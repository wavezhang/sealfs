// Copyright 2022 labring. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use crate::{
    common::serialization::{
        AddNodesSendMetaData, ClusterStatus, DeleteNodesSendMetaData, GetClusterStatusRecvMetaData,
        GetHashRingInfoRecvMetaData, ManagerOperationType, ServerStatus,
    },
    rpc::server::Handler,
};

use super::core::Manager;

use async_trait::async_trait;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

pub struct ManagerService {
    pub manager: Arc<Manager>,
}

#[derive(Serialize, Deserialize)]
pub struct SendHeartRequest {
    pub address: String,
    pub flags: u32,
    pub lifetime: String,
}

#[derive(Serialize, Deserialize)]
pub struct MetadataRequest {
    pub flags: u32,
}

#[derive(Default, Serialize, Deserialize)]
pub struct MetadataResponse {
    pub instances: Vec<String>,
}

pub async fn update_server_status(manager: Arc<Manager>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if manager.closed.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let status = *manager.cluster_status.lock().unwrap();
        debug!("current cluster status is {:?}", status);
        match status {
            ClusterStatus::Idle => {}
            ClusterStatus::NodesStarting => {
                // if all servers is ready, change the cluster status to SyncNewHashRing
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::Finished);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::SyncNewHashRing;
                    info!("all servers is ready, change the cluster status to SyncNewHashRing");
                };
            }
            ClusterStatus::SyncNewHashRing => {
                // if all servers is ready, change the cluster status to PreTransfer
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::PreTransfer);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::PreTransfer;
                    info!("all servers is ready, change the cluster status to PreTransfer");
                }
            }
            ClusterStatus::PreTransfer => {
                // if all servers is ready, change the cluster status to Transferring
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::Transferring);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::Transferring;
                    info!("all servers is ready, change the cluster status to Transferring");
                }
            }
            ClusterStatus::Transferring => {
                // if all servers is ready, change the cluster status to PreFinish
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::PreFinish);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::PreFinish;
                    info!("all servers is ready, change the cluster status to PreFinish");
                }
            }
            ClusterStatus::PreFinish => {
                // if all servers is ready, change the cluster status to Finishing
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::Finishing);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let _ = manager
                        .hashring
                        .write()
                        .unwrap()
                        .replace(manager.new_hashring.read().unwrap().clone().unwrap());
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::Finishing;
                    info!("all servers is ready, change the cluster status to Finishing");
                }
            }
            ClusterStatus::Finishing => {
                // if all servers is ready, change the cluster status to Idle
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::Finished);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let mut new_hashring = manager.new_hashring.write().unwrap();
                    manager
                        .servers
                        .lock()
                        .unwrap()
                        .retain(|k, _| new_hashring.as_ref().unwrap().contains(k));
                    // move new_hashring to hashring
                    let _ = new_hashring.take().unwrap();
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::Idle;
                    info!("all servers is ready, change the cluster status to Idle");
                }
            }
            ClusterStatus::Initializing => {
                // if all servers is ready, change the cluster status to Idle
                let flag = manager
                    .servers
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kv| kv.1.status == ServerStatus::Finished);
                if flag {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    *manager.cluster_status.lock().unwrap() = ClusterStatus::Idle;
                    info!("all servers is ready, change the cluster status to Idle");
                }
            }
            s => panic!("update server status failed, invalid cluster status: {}", s),
        }
    }
}

impl ManagerService {
    pub fn new(servers: Vec<(String, usize)>) -> Self {
        let manager = Arc::new(Manager::new(servers));
        ManagerService { manager }
    }
}

#[async_trait]
impl Handler for ManagerService {
    async fn dispatch(
        &self,
        id: u32,
        operation_type: u32,
        _flags: u32,
        path: Vec<u8>,
        _data: Vec<u8>,
        metadata: Vec<u8>,
        authenticated: bool,
    ) -> anyhow::Result<(i32, u32, usize, usize, Vec<u8>, Vec<u8>)> {
        let r#type = match ManagerOperationType::try_from(operation_type) {
            Ok(value) => value,
            Err(e) => {
                error!(
                    "connection {} sent invalid manager operation type {}: {:?}",
                    id, operation_type, e
                );
                return Ok((libc::EINVAL, 0, 0, 0, Vec::new(), Vec::new()));
            }
        };
        match r#type {
            ManagerOperationType::GetClusterStatus => {
                let status = self.manager.get_cluster_status();
                let response_meta_data =
                    bincode::serialize(&GetClusterStatusRecvMetaData { status }).unwrap();

                debug!("connection {} get cluster status: {:?}", id, status);

                Ok((
                    0,
                    0,
                    response_meta_data.len(),
                    0,
                    response_meta_data,
                    Vec::new(),
                ))
            }
            ManagerOperationType::GetHashRing => {
                let hash_ring_info = self.manager.get_hash_ring_info();

                info!("connection {} get hash ring: {:?}", id, hash_ring_info);

                let response_meta_data =
                    bincode::serialize(&GetHashRingInfoRecvMetaData { hash_ring_info }).unwrap();
                Ok((
                    0,
                    0,
                    response_meta_data.len(),
                    0,
                    response_meta_data,
                    Vec::new(),
                ))
            }
            ManagerOperationType::GetNewHashRing => match self.manager.get_new_hash_ring_info() {
                Ok(hash_ring_info) => {
                    info!("connection {} get new hash ring: {:?}", id, hash_ring_info);
                    let response_meta_data =
                        bincode::serialize(&GetHashRingInfoRecvMetaData { hash_ring_info })
                            .unwrap();
                    Ok((
                        0,
                        0,
                        response_meta_data.len(),
                        0,
                        response_meta_data,
                        Vec::new(),
                    ))
                }
                Err(e) => {
                    error!("get new hash ring error: {}", e);
                    Ok((libc::ENOENT, 0, 0, 0, Vec::new(), Vec::new()))
                }
            },
            ManagerOperationType::AddNodes => {
                if !authenticated {
                    error!(
                        "connection {} rejected unauthenticated AddNodes request",
                        id
                    );
                    return Ok((libc::EACCES, 0, 0, 0, Vec::new(), Vec::new()));
                }
                let new_servers_info = match bincode::deserialize::<AddNodesSendMetaData>(&metadata)
                {
                    Ok(value) => value.new_servers_info,
                    Err(e) => {
                        error!("connection {} sent malformed AddNodes metadata: {}", id, e);
                        return Ok((libc::EINVAL, 0, 0, 0, Vec::new(), Vec::new()));
                    }
                };
                info!("connection {} add nodes: {:?}", id, new_servers_info);
                match self.manager.add_nodes(new_servers_info) {
                    None => Ok((0, 0, 0, 0, Vec::new(), Vec::new())),
                    Some(e) => {
                        error!("add nodes error: {}", e);
                        Ok((libc::EIO, 0, 0, 0, Vec::new(), Vec::new()))
                    }
                }
            }
            ManagerOperationType::RemoveNodes => {
                if !authenticated {
                    error!(
                        "connection {} rejected unauthenticated RemoveNodes request",
                        id
                    );
                    return Ok((libc::EACCES, 0, 0, 0, Vec::new(), Vec::new()));
                }
                let deleted_servers_info =
                    match bincode::deserialize::<DeleteNodesSendMetaData>(&metadata) {
                        Ok(value) => value.deleted_servers_info,
                        Err(e) => {
                            error!(
                                "connection {} sent malformed RemoveNodes metadata: {}",
                                id, e
                            );
                            return Ok((libc::EINVAL, 0, 0, 0, Vec::new(), Vec::new()));
                        }
                    };
                info!("connection {} remove nodes: {:?}", id, deleted_servers_info);
                match self.manager.delete_nodes(deleted_servers_info) {
                    None => Ok((0, 0, 0, 0, Vec::new(), Vec::new())),
                    Some(e) => {
                        error!("remove nodes error: {}", e);
                        Ok((libc::EIO, 0, 0, 0, Vec::new(), Vec::new()))
                    }
                }
            }
            ManagerOperationType::UpdateServerStatus => {
                info!("connection {} update server status", id);
                let server_address = match String::from_utf8(path) {
                    Ok(value) => value,
                    Err(e) => {
                        error!("connection {} sent invalid server address: {}", id, e);
                        return Ok((libc::EINVAL, 0, 0, 0, Vec::new(), Vec::new()));
                    }
                };
                let status = match bincode::deserialize(&metadata) {
                    Ok(value) => value,
                    Err(e) => {
                        error!(
                            "connection {} sent malformed server status metadata: {}",
                            id, e
                        );
                        return Ok((libc::EINVAL, 0, 0, 0, Vec::new(), Vec::new()));
                    }
                };
                match self.manager.set_server_status(server_address, status) {
                    None => Ok((0, 0, 0, 0, Vec::new(), Vec::new())),
                    Some(e) => {
                        error!("update server status error: {}", e);
                        Ok((libc::EIO, 0, 0, 0, Vec::new(), Vec::new()))
                    }
                }
            }
            _ => {
                error!(
                    "connection {} sent unsupported manager operation type: {}",
                    id, operation_type
                );
                Ok((libc::ENOSYS, 0, 0, 0, Vec::new(), Vec::new()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::server::Handler;

    fn add_nodes_metadata() -> Vec<u8> {
        bincode::serialize(&AddNodesSendMetaData {
            new_servers_info: vec![("127.0.0.1:9000".to_string(), 100)],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn unauthenticated_add_nodes_is_rejected() {
        let service = ManagerService::new(vec![]);
        let response = service
            .dispatch(
                1,
                106,
                0,
                Vec::new(),
                Vec::new(),
                add_nodes_metadata(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(response.0, libc::EACCES);
    }

    #[tokio::test]
    async fn unauthenticated_remove_nodes_is_rejected() {
        let service = ManagerService::new(vec![]);
        let metadata = bincode::serialize(&DeleteNodesSendMetaData {
            deleted_servers_info: vec!["127.0.0.1:9000".to_string()],
        })
        .unwrap();
        let response = service
            .dispatch(1, 107, 0, Vec::new(), Vec::new(), metadata, false)
            .await
            .unwrap();
        assert_eq!(response.0, libc::EACCES);
    }

    #[tokio::test]
    async fn unknown_operation_type_is_rejected_without_panic() {
        let service = ManagerService::new(vec![]);
        let response = service
            .dispatch(1, 999, 0, Vec::new(), Vec::new(), Vec::new(), true)
            .await
            .unwrap();
        assert_eq!(response.0, libc::EINVAL);
    }

    #[tokio::test]
    async fn malformed_add_nodes_metadata_is_rejected_without_panic() {
        let service = ManagerService::new(vec![]);
        let response = service
            .dispatch(1, 106, 0, Vec::new(), Vec::new(), vec![0xff, 0x00], true)
            .await
            .unwrap();
        assert_eq!(response.0, libc::EINVAL);
    }
}
