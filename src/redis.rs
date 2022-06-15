use futures_util::StreamExt;
use redis_cluster_async::{
    redis::{AsyncCommands, Cmd},
    Client,
};
use serde::Deserialize;
use trust_dns_server::client::rr::LowerName;

use std::{fmt::Display, net::SocketAddr, str::FromStr};

use crate::storage::{Storage, StorageRecord};

pub struct RedisClusterClient {
    client: Client,
}

#[derive(Debug, Deserialize)]
pub struct ClusterConnectionInfo {
    pub user: Option<String>,
    pub password: Option<String>,
    pub address: SocketAddr,
}

impl Display for ClusterConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "redis://{}:{}@{}",
            if let Some(ref user) = self.user {
                user.as_ref()
            } else {
                ""
            },
            if let Some(ref pass) = self.password {
                pass.as_ref()
            } else {
                ""
            },
            self.address
        )
    }
}

impl RedisClusterClient {
    /// Create a new [`RedisClusterClient`] by connecting to a node in the cluster at the given ip
    /// and port.
    ///
    /// # Panics
    ///
    /// This function will panic if an invalid configuration is passed
    pub fn new(addrs: &[&ClusterConnectionInfo]) -> Self {
        let connection_strings = addrs.iter().map(|ci| ci.to_string()).collect();
        log::trace!("Connection strings: {:?}", connection_strings);
        RedisClusterClient {
            client: Client::open(connection_strings).expect("Clusterclient created"),
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
        let mut con = self.client.get_connection().await?;
        Ok(con
            .scan_match("zone:*")
            .await?
            .filter_map(|key: String| async move {
                LowerName::from_str(key.trim_start_matches("zone:")).ok()
            })
            .collect::<Vec<LowerName>>()
            .await)
    }

    async fn lookup_records(
        &self,
        name: &trust_dns_server::client::rr::LowerName,
        zone: &trust_dns_server::client::rr::LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Option<Vec<crate::storage::StorageRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let mut con = self.client.get_connection().await?;
        let data = con
            .hget::<_, &str, Vec<u8>>(format!("resource:{}:{}", zone, name), rtype.into())
            .await?;

        Ok(Some(serde_json::from_slice(&data)?))
    }

    async fn add_zone(
        &self,
        zone: &LowerName,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut con = self.client.get_connection().await?;
        Ok(con.set(format!("zone:{}", zone), "").await?)
    }

    async fn add_record(
        &self,
        zone: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let record_name = LowerName::from(record.record.name());
        let record_type = record.record.record_type();
        let mut con = self.client.get_connection().await?;

        let mut record_set = self
            .lookup_records(zone, &record_name, record_type)
            .await?
            .unwrap_or(vec![]);

        // Add new record to the set
        record_set.push(record);
        let new_record_set = serde_json::to_vec(&record_set)?;

        Ok(con
            .hset::<_, &str, _, _>(
                format!("resource:{}:{}", zone, record_name),
                record_type.into(),
                new_record_set,
            )
            .await?)
    }
}
