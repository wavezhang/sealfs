// Copyright 2022 labring. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    callback::CallbackPool,
    connection::ClientConnection,
    protocol::{ResponseHeader, CONNECTION_RETRY_TIMES, SEND_RETRY_TIMES},
};
use crate::common::errors::{
    CONNECTION_ERROR, DATABASE_ERROR, INVALID_CLUSTER_STATUS, SERIALIZATION_ERROR,
};
use async_trait::async_trait;
use dashmap::DashMap;
use log::{error, info, warn};
use std::{marker::PhantomData, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Upper bound for a status value carried in a response header. Real statuses are
/// 0, -1 or a small errno, so anything above this is a protocol violation.
const MAX_RESPONSE_STATUS: i32 = 4096;

#[async_trait]
pub trait StreamCreator<
    R: AsyncReadExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
    W: AsyncWriteExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
>
{
    async fn create_stream(server_address: &str) -> Result<(R, W), String>;
}

pub struct TcpStreamCreator;

#[async_trait]
impl StreamCreator<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>
    for TcpStreamCreator
{
    async fn create_stream(
        server_address: &str,
    ) -> Result<
        (
            tokio::net::tcp::OwnedReadHalf,
            tokio::net::tcp::OwnedWriteHalf,
        ),
        String,
    > {
        let stream = match tokio::net::TcpStream::connect(server_address).await {
            Ok(stream) => stream,
            Err(e) => {
                return Err(format!("connect to {} error: {}", server_address, e));
            }
        };
        Ok(stream.into_split())
    }
}

pub struct UnixStreamCreator;

#[async_trait]
impl StreamCreator<tokio::net::unix::OwnedReadHalf, tokio::net::unix::OwnedWriteHalf>
    for UnixStreamCreator
{
    async fn create_stream(
        server_address: &str,
    ) -> Result<
        (
            tokio::net::unix::OwnedReadHalf,
            tokio::net::unix::OwnedWriteHalf,
        ),
        String,
    > {
        let stream = match tokio::net::UnixStream::connect(server_address).await {
            Ok(stream) => stream,
            Err(e) => {
                return Err(format!("connect to {} error: {}", server_address, e));
            }
        };
        Ok(stream.into_split())
    }
}

pub struct RpcClient<
    R: AsyncReadExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
    W: AsyncWriteExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
    S: StreamCreator<R, W>,
> {
    connections: DashMap<String, Arc<ClientConnection<W, R>>>,
    pool: Arc<CallbackPool>,
    stream_creator: PhantomData<S>,
}

impl<
        R: AsyncReadExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
        W: AsyncWriteExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
        S: StreamCreator<R, W>,
    > Default for RpcClient<R, W, S>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        R: AsyncReadExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
        W: AsyncWriteExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
        S: StreamCreator<R, W>,
    > RpcClient<R, W, S>
{
    pub fn new() -> Self {
        let mut pool = CallbackPool::new();
        pool.init();
        let pool = Arc::new(pool);
        Self {
            connections: DashMap::new(),
            pool,
            stream_creator: PhantomData,
        }
    }

    pub fn close(&self) {
        self.pool.free();
    }

    pub async fn add_connection(&self, server_address: &str) -> Result<(), String> {
        for _ in 0..CONNECTION_RETRY_TIMES {
            match S::create_stream(server_address).await {
                Ok((read_stream, write_stream)) => {
                    if self.connections.contains_key(server_address) {
                        warn!("connection already exists: {}", server_address);
                        return Ok(());
                    }
                    let connection = Arc::new(ClientConnection::new(server_address, write_stream));
                    tokio::spawn(parse_response(
                        read_stream,
                        connection.clone(),
                        self.pool.clone(),
                    ));
                    self.connections
                        .insert(server_address.to_string(), connection);
                    info!("add connection to {} success", server_address);
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "connect to {} failed: {}, wait for a while",
                        server_address, e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Err(format!(
            "connect to {} error: connection retry times exceed",
            server_address
        ))
    }

    async fn reconnect(&self, server_address: &str) -> Result<(), String> {
        info!("reconnect to {}", server_address);
        match self.connections.get(server_address) {
            Some(connection) => {
                if connection.is_connected() {
                    info!("connection already exists: {}", server_address);
                    return Ok(());
                }
                match S::create_stream(server_address).await {
                    Ok((read_stream, write_stream)) => {
                        tokio::spawn(parse_response(
                            read_stream,
                            connection.clone(),
                            self.pool.clone(),
                        ));
                        connection.value().reset_connection(write_stream).await;
                        info!("reconnect to {} success", server_address);
                        Ok(())
                    }
                    Err(e) => {
                        warn!(
                            "reconnect to {} failed: {}, wait for a while",
                            server_address, e
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok(())
                    }
                }
            }
            None => Err(format!("connection not exists: {}", server_address)),
        }
    }

    pub fn remove_connection(&self, server_address: &str) {
        self.connections.remove(server_address);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn call_remote(
        &self,
        server_address: &str,
        operation_type: u32,
        req_flags: u32,
        path: &str,
        send_meta_data: &[u8],
        send_data: &[u8],
        status: &mut i32,
        rsp_flags: &mut u32,
        recv_meta_data_length: &mut usize,
        recv_data_length: &mut usize,
        recv_meta_data: &mut [u8],
        recv_data: &mut [u8],
        timeout: Duration,
    ) -> Result<(), String> {
        for _ in 0..SEND_RETRY_TIMES {
            let connection = match self.connections.get(server_address) {
                Some(connection) => connection,
                None => {
                    error!("connection not exists: {}", server_address);
                    return Err(format!("connection not exists: {}", server_address));
                }
            };
            let (batch, id) = self
                .pool
                .register_callback(recv_meta_data, recv_data)
                .await?; // TODO: unregister callback when error

            if let Err(e) = connection
                .send_request(
                    batch,
                    id,
                    operation_type,
                    req_flags,
                    path,
                    send_meta_data,
                    send_data,
                )
                .await
            {
                error!("send request to {} failed: {}", server_address, e);
                connection.disconnect();
                let _lock = connection.get_reconnecting_lock().await;
                warn!("connection to {} disconnected", server_address);
                match self.reconnect(server_address).await {
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        error!("reconnect to {} failed: {}", server_address, e);
                        return Err(format!("reconnect to {} failed: {}", server_address, e));
                    }
                }
            }
            match self.pool.wait_for_callback(id, timeout).await {
                Ok((s, f, meta_data_length, data_length)) => {
                    *status = s;
                    *rsp_flags = f;
                    *recv_meta_data_length = meta_data_length;
                    *recv_data_length = data_length;
                    return Ok(());
                }
                Err(e) => {
                    error!("wait for callback failed: {}, batch: {}, id {}, operation type: {}, path: {}", e, batch, id, operation_type, path);
                    continue;
                }
            }
        }
        Err(format!(
            "send request to {} error: send retry times exceed",
            server_address
        ))
    }
}

// parse_response
// try to get response from sequence of connections and write to callbacks
//
// Every field of the response header is chosen by the peer, so it is validated
// before it is used: the two body lengths must add up to `total_length` and must
// fit into the buffers registered for this callback (checked again by
// `CallbackPool::get_data_ref`/`get_meta_data_ref`), and `status`/`flags` must be
// in their valid ranges. A header that does not pass these checks is treated as
// a protocol error and the connection is dropped.
pub async fn parse_response<W: AsyncWriteExt + Unpin, R: AsyncReadExt + Unpin>(
    mut read_stream: R,
    connection: Arc<ClientConnection<W, R>>,
    pool: Arc<CallbackPool>,
) {
    loop {
        if !connection.is_connected() {
            break;
        }
        let header = match connection.receive_response_header(&mut read_stream).await {
            Ok(header) => header,
            Err(e) => {
                if e == "early eof" || e == "Connection reset by peer (os error 104)" {
                    warn!("{:?} disconnected: {}", connection.server_address, e);
                    break;
                }
                error!(
                    "parse_response header from {:?} error: {}",
                    connection.server_address, e
                );
                break;
            }
        };
        let batch = header.batch;
        let id = header.id;
        let total_length = header.total_length;
        let meta_data_length = header.meta_data_length as usize;
        let data_length = header.data_length as usize;

        if let Some(error) = validate_response_header(&header) {
            error!(
                "parse_response invalid header from {:?}: {}, batch: {}, id: {}",
                connection.server_address, error, batch, id
            );
            break;
        }

        let result = {
            match pool.lock_if_not_timeout(batch, id) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        };
        match result {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "parse_response lock timeout: {}, batch: {}, id: {}",
                    e, batch, id
                );
                let result = connection
                    .clean_response(&mut read_stream, total_length)
                    .await;
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        error!("parse_response clean_response error: {}", e);
                        break;
                    }
                }
                continue;
            }
        }

        let meta_data = match pool.get_meta_data_ref(id, meta_data_length) {
            Ok(meta_data) => meta_data,
            Err(e) => {
                error!(
                    "parse_response invalid meta data length from {:?}: {}, batch: {}, id: {}",
                    connection.server_address, e, batch, id
                );
                break;
            }
        };
        let data = match pool.get_data_ref(id, data_length) {
            Ok(data) => data,
            Err(e) => {
                error!(
                    "parse_response invalid data length from {:?}: {}, batch: {}, id: {}",
                    connection.server_address, e, batch, id
                );
                break;
            }
        };

        if let Err(e) = connection
            .receive_response(&mut read_stream, meta_data, data)
            .await
        {
            error!("Error receiving response: {}", e);
            break;
        };
        if let Err(e) = pool
            .response(
                id,
                header.status,
                header.flags,
                meta_data_length,
                data_length,
            )
            .await
        {
            error!("Error writing response back: {}", e);
            break;
        };
    }
}

/// Check the fields of a response header that come straight from the peer.
fn validate_response_header(header: &ResponseHeader) -> Option<String> {
    let meta_data_length = header.meta_data_length as usize;
    let data_length = header.data_length as usize;
    match meta_data_length.checked_add(data_length) {
        Some(total) if total == header.total_length as usize => {}
        Some(total) => {
            return Some(format!(
                "total_length {} does not match meta_data_length {} + data_length {}",
                header.total_length, meta_data_length, data_length
            ));
        }
        None => return Some("response body length overflow".to_string()),
    }
    // `flags` is reserved by the protocol and the server always sends 0.
    if header.flags != 0 {
        return Some(format!("unexpected flags: {}", header.flags));
    }
    if !is_valid_response_status(header.status) {
        return Some(format!("invalid status: {}", header.status));
    }
    None
}

/// Response statuses are 0, -1 (unknown operation), an errno, or one of the
/// internal sealfs error codes.
fn is_valid_response_status(status: i32) -> bool {
    (-1..=MAX_RESPONSE_STATUS).contains(&status)
        || matches!(
            status,
            CONNECTION_ERROR | INVALID_CLUSTER_STATUS | DATABASE_ERROR | SERIALIZATION_ERROR
        )
}

#[cfg(test)]
mod tests {
    use super::{validate_response_header, MAX_RESPONSE_STATUS};
    use crate::common::errors::{CONNECTION_ERROR, DATABASE_ERROR};
    use crate::rpc::protocol::ResponseHeader;

    fn header(status: i32, flags: u32, total: u32, meta: u32, data: u32) -> ResponseHeader {
        ResponseHeader {
            batch: 1,
            id: 0,
            status,
            flags,
            total_length: total,
            meta_data_length: meta,
            data_length: data,
        }
    }

    #[test]
    fn test_validate_response_header_accepts_valid_headers() {
        assert!(validate_response_header(&header(0, 0, 24, 24, 0)).is_none());
        assert!(validate_response_header(&header(libc::ENOENT, 0, 8, 0, 8)).is_none());
        assert!(validate_response_header(&header(-1, 0, 0, 0, 0)).is_none());
        // internal sealfs error codes are forwardable statuses too
        assert!(validate_response_header(&header(DATABASE_ERROR, 0, 0, 0, 0)).is_none());
        assert!(validate_response_header(&header(CONNECTION_ERROR, 0, 0, 0, 0)).is_none());
    }

    #[test]
    fn test_validate_response_header_rejects_inconsistent_lengths() {
        // total_length does not match meta_data_length + data_length
        assert!(validate_response_header(&header(0, 0, 25, 24, 0)).is_some());
        assert!(validate_response_header(&header(0, 0, 0, 1, 1)).is_some());
        // a huge advertised total_length must not be accepted either
        assert!(validate_response_header(&header(0, 0, u32::MAX, u32::MAX, 1)).is_some());
    }

    #[test]
    fn test_validate_response_header_rejects_invalid_status_and_flags() {
        // flags is reserved and always 0 from the server
        assert!(validate_response_header(&header(0, 1, 0, 0, 0)).is_some());
        assert!(validate_response_header(&header(MAX_RESPONSE_STATUS + 1, 0, 0, 0, 0)).is_some());
        assert!(validate_response_header(&header(i32::MIN, 0, 0, 0, 0)).is_some());
        assert!(validate_response_header(&header(-2, 0, 0, 0, 0)).is_some());
        // below the first internal sealfs error code, above the errno range
        assert!(validate_response_header(&header(10_000, 0, 0, 0, 0)).is_some());
    }
}
