use redis_cluster_async::{redis::Cmd, Client};
use std::net::SocketAddr;

use crate::storage::Storage;

pub struct RedisClusterClient {
    client: Client,
}

impl RedisClusterClient {
    /// Create a new [`RedisClusterClient`] by connecting to a node in the cluster at the given ip
    /// and port.
    ///
    /// # Panics
    ///
    /// This function will panic if an invalid configuration is passed
    pub fn new(addr: SocketAddr) -> Self {
        RedisClusterClient {
            client: Client::open(vec![format!("redis://{}", addr)]).expect("Clusterclient created"),
        }
    }

    /// Test the client, to see if it can actually connect to the given node. If this fails, the
    /// client should be discarded as future operations will likely also fails.
    pub async fn test(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut con = self.client.get_connection().await?;
        Ok(Cmd::new().arg("PING").query_async(&mut con).await?)
    }
}

#[async_trait::async_trait]
impl Storage for RedisClusterClient {
    async fn zones(
        &self,
    ) -> Result<
        Vec<trust_dns_server::client::rr::LowerName>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        unimplemented!();
    }

    async fn lookup_records(
        &self,
        name: &trust_dns_server::client::rr::LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Vec<crate::storage::StoredRecord>, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!();
    }
}
