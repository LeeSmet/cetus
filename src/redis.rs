use futures_util::{join, stream, StreamExt};
// use redis_cluster_async::{
//     redis::{self, AsyncCommands},
//     Client,
// };
use fred::{
    pool::RedisPool,
    prelude::*,
    types::{BackpressureConfig, PerformanceConfig, RespVersion, ScanType},
};
use serde::Deserialize;
use trust_dns_server::client::rr::LowerName;

use std::{net::SocketAddr, str::FromStr};

use crate::storage::{Storage, StorageRecord};

pub struct RedisClusterClient {
    client: RedisPool,
}

impl RedisClusterClient {
    /// Create a new [`RedisClusterClient`] by connecting to a node in the cluster at the given ip
    /// and port.
    ///
    /// # Panics
    ///
    /// This function will panic if an invalid configuration is passed
    pub fn new(username: Option<String>, password: Option<String>, addrs: &[SocketAddr]) -> Self {
        let mut conf = RedisConfig::default();
        conf.username = username;
        conf.password = password;
        conf.server = ServerConfig::Clustered {
            hosts: addrs
                .into_iter()
                .map(|sa| (sa.ip().to_string(), sa.port()))
                .collect(),
        };
        conf.version = RespVersion::RESP2;
        let mut perf = PerformanceConfig::default();
        perf.cluster_cache_update_delay_ms = 10;
        perf.max_command_attempts = 20;
        perf.backpressure = BackpressureConfig {
            disable_auto_backpressure: false,
            disable_backpressure_scaling: false,
            min_sleep_duration_ms: 10,
            max_in_flight_commands: 5000,
        };
        let client = RedisPool::new(conf, 10).expect("Valid pool config");
        let reconnect = ReconnectPolicy::new_constant(1_000, 10);
        let conn_task = client.connect(Some(reconnect));
        //tokio::spawn(conn_task);
        RedisClusterClient { client }
    }

    /// Test the client, to see if it can actually connect to the given node. If this fails, the
    /// client should be discarded as future operations will likely also fails.
    pub async fn test(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::trace!("Testing cluster connection");
        self.client.wait_for_connect().await?;
        log::trace!("Client connected - try to ping");
        self.client.ping().await?;
        log::trace!("Cluster connection OK");
        Ok(())
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
        log::trace!("Getting zones from redis cluster");
        let mut scan_stream = self
            .client
            .scan_cluster("zone:*", Some(10), Some(ScanType::String));
        // TODO: simplify this
        Ok(scan_stream
            .filter_map(|result| async move {
                let mut page = match result {
                    Ok(page) => page,
                    Err(e) => {
                        log::error!("Could not get zone scan entry: {}", e);
                        return None;
                    }
                };
                if let Some(keys) = page.take_results() {
                    return Some(
                        keys.into_iter()
                            .filter_map(|key| {
                                let key = match key.into_string() {
                                    Some(key) => key,
                                    None => {
                                        log::error!("Could not convert key to string");
                                        return None;
                                    }
                                };
                                match LowerName::from_str(key.trim_start_matches("zone:")) {
                                    Ok(ln) => Some(ln),
                                    Err(e) => {
                                        log::error!("Ignoring invalid zone {:?}: {}", key, e);
                                        None
                                    }
                                }
                            })
                            .collect(),
                    );
                };
                None
            })
            .collect::<Vec<Vec<LowerName>>>()
            .await
            .into_iter()
            .flatten()
            .collect())
    }

    async fn lookup_records(
        &self,
        name: &trust_dns_server::client::rr::LowerName,
        zone: &trust_dns_server::client::rr::LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Option<Vec<crate::storage::StorageRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let data = self
            .client
            .hget::<Vec<_>, _, &str>(format!("resource:{}:{}", zone, name), rtype.into())
            .await?;

        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_slice(&data)?))
        }
    }

    async fn add_zone(
        &self,
        zone: &LowerName,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .client
            .set(format!("zone:{}", zone), "", None, None, false)
            .await?)
    }

    async fn add_record(
        &self,
        zone: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("Adding record {:?}", record);
        let record_name = LowerName::from(record.record.name());
        let record_type = record.record.record_type();

        let mut record_set = self
            .lookup_records(zone, &record_name, record_type)
            .await?
            .unwrap_or(vec![]);

        // Add new record to the set
        record_set.push(record);
        let new_record_set = serde_json::to_vec(&record_set)?;

        log::trace!("record set: {:?}", new_record_set);
        Ok(self
            .client
            .hset::<_, _, (&str, &[u8])>(
                format!("resource:{}:{}", zone, record_name),
                (record_type.into(), &new_record_set),
            )
            .await?)
    }
}
