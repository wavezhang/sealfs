// Copyright 2022 labring. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
};

use super::{
    auth::{is_loopback_address, AuthState, AUTH_FRAME_SIZE, AUTH_HANDSHAKE_TIMEOUT_SECS},
    connection::ServerConnection,
    protocol::RequestHeader,
};

#[async_trait]
pub trait Handler {
    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        &self,
        id: u32,
        operation_type: u32,
        flags: u32,
        path: Vec<u8>,
        data: Vec<u8>,
        metadata: Vec<u8>,
        authenticated: bool,
    ) -> anyhow::Result<(i32, u32, usize, usize, Vec<u8>, Vec<u8>)>;
}

pub async fn handle<
    H: Handler + std::marker::Sync + std::marker::Send + 'static,
    W: AsyncWriteExt + Unpin,
    R: AsyncReadExt + Unpin,
>(
    handler: Arc<H>,
    connection: Arc<ServerConnection<W, R>>,
    header: RequestHeader,
    path: Vec<u8>,
    data: Vec<u8>,
    metadata: Vec<u8>,
    authenticated: bool,
) {
    let response = handler
        .dispatch(
            connection.id,
            header.r#type,
            header.flags,
            path.clone(),
            data,
            metadata,
            authenticated,
        )
        .await;
    match response {
        Ok(response) => {
            if let Err(e) = connection
                .send_response(
                    header.batch,
                    header.id,
                    response.0,
                    response.1,
                    &response.4[0..response.2],
                    &response.5[0..response.3],
                )
                .await
            {
                error!("handle connection: {} , send response error: {}, batch: {}, id: {}, operation_type: {}, flags: {}, path: {:?}", connection.id, e, header.batch, header.id, header.r#type, header.flags, std::str::from_utf8(&path));
                let _ = connection.close().await;
            }
        }
        Err(e) => {
            error!(
                "handle connection: {} , dispatch error: {}",
                connection.id, e
            );
        }
    }
}

async fn authenticate<W: AsyncWriteExt + Unpin, R: AsyncReadExt + Unpin>(
    auth: &AuthState,
    connection: &ServerConnection<W, R>,
    read_stream: &mut R,
) -> Result<(), String> {
    let mut frame = [0u8; AUTH_FRAME_SIZE];
    let result = tokio::time::timeout(
        Duration::from_secs(AUTH_HANDSHAKE_TIMEOUT_SECS),
        read_stream.read_exact(&mut frame),
    )
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("authentication handshake timed out".to_string()),
    }
    match auth.verify_frame(&frame) {
        Ok(()) => connection.send_response(0, 0, 0, 0, &[], &[]).await,
        Err(e) => {
            let _ = connection
                .send_response(0, 0, libc::EACCES, 0, &[], &[])
                .await;
            Err(e.to_string())
        }
    }
}

pub async fn receive<
    H: Handler + std::marker::Sync + std::marker::Send + 'static,
    W: AsyncWriteExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
    R: AsyncReadExt + Unpin + std::marker::Sync + std::marker::Send + 'static,
>(
    handler: Arc<H>,
    connection: Arc<ServerConnection<W, R>>,
    mut read_stream: R,
    auth: Option<Arc<AuthState>>,
) {
    let mut authenticated = false;
    if let Some(auth) = auth.as_ref() {
        match authenticate(auth, &connection, &mut read_stream).await {
            Ok(()) => {
                authenticated = true;
                info!("connection {} authenticated", connection.id);
            }
            Err(e) => {
                warn!(
                    "connection {} rejected: authentication failed: {}",
                    connection.id, e
                );
                let _ = connection.close().await;
                return;
            }
        }
    }
    loop {
        {
            let id = connection.name_id();
            let header = match connection.receive_request_header(&mut read_stream).await {
                Ok(header) => header,
                Err(e) => {
                    if e == "early eof" || e == "Connection reset by peer (os error 104)" {
                        warn!("{:?} receive, connection closed", id);
                        break;
                    }
                    panic!("{:?} parse_request, header error: {}", id, e);
                }
            };
            let data_result = connection.receive_request(&mut read_stream, &header).await;
            let (path, data, metadata) = match data_result {
                Ok(data) => data,
                Err(e) => {
                    panic!("{:?} parse_request, data error: {}", id, e);
                }
            };
            let handler = handler.clone();
            let connection = connection.clone();
            tokio::spawn(handle(
                handler,
                connection,
                header,
                path,
                data,
                metadata,
                authenticated,
            ));
        }
    }
}

pub struct RpcServer<H: Handler + std::marker::Sync + std::marker::Send + 'static> {
    // listener: TcpListener,
    bind_address: String,
    handler: Arc<H>,
}

impl<H: Handler + std::marker::Sync + std::marker::Send> RpcServer<H> {
    pub fn new(handler: Arc<H>, bind_address: &str) -> Self {
        Self {
            handler,
            bind_address: String::from(bind_address),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let auth = AuthState::from_env();
        if auth.is_none() && !is_loopback_address(&self.bind_address) {
            return Err(anyhow::anyhow!(
                "refusing to bind {} without {}: set the token or bind to a loopback address",
                self.bind_address,
                super::auth::AUTH_TOKEN_ENV
            ));
        }
        if auth.is_some() {
            info!("RPC authentication enabled for {}", self.bind_address);
        }
        let auth = auth.map(Arc::new);
        info!("Listening on {:?}", self.bind_address);
        let listener = TcpListener::bind(&self.bind_address).await?;
        let mut id = 1u32;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let (read_stream, write_stream) = stream.into_split();
                    info!("Connection {id} accepted");
                    let handler = Arc::clone(&self.handler);
                    let name_id = format!("{},{}", self.bind_address, id);
                    let connection = Arc::new(ServerConnection::new(write_stream, name_id, id));
                    let auth = auth.clone();
                    tokio::spawn(async move {
                        receive(handler, connection, read_stream, auth).await;
                    });
                    id += 1;
                }
                Err(e) => {
                    panic!("Failed to create tcp stream, error is {}", e)
                }
            }
        }
    }

    pub async fn run_unix_stream(&self) -> anyhow::Result<()> {
        info!("Listening on {:?}", self.bind_address);
        let listener = match UnixListener::bind(&self.bind_address) {
            Ok(listener) => listener,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to create unix stream at {:?}, error is {}",
                    self.bind_address,
                    e
                ));
            }
        };
        let mut id = 1u32;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let (read_stream, write_stream) = stream.into_split();
                    info!("Connection {id} accepted");
                    let handler = Arc::clone(&self.handler);
                    let name_id = format!("{},{}", self.bind_address, id);
                    let connection = Arc::new(ServerConnection::new(write_stream, name_id, id));
                    tokio::spawn(async move {
                        receive(handler, connection, read_stream, None).await;
                    });
                    id += 1;
                }
                Err(e) => {
                    panic!("Failed to create tcp stream, error is {}", e)
                }
            }
        }
    }
}
