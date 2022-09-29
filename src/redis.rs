use fred::{
    pool::RedisPool,
    prelude::*,
    types::{BackpressureConfig, PerformanceConfig, RespVersion, ScanType},
};
use futures_util::StreamExt;
use log::error;
use trust_dns_server::client::rr::LowerName;

use std::{collections::HashMap, net::SocketAddr, str::FromStr};

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
        let performance = PerformanceConfig {
            cluster_cache_update_delay_ms: 10,
            max_command_attempts: 20,
            backpressure: BackpressureConfig {
                disable_auto_backpressure: false,
                disable_backpressure_scaling: false,
                min_sleep_duration_ms: 10,
                max_in_flight_commands: 5000,
            },
            ..Default::default()
        };
        let conf = RedisConfig {
            username,
            password,
            performance,
            version: RespVersion::RESP2,
            server: ServerConfig::Clustered {
                hosts: addrs
                    .iter()
                    .map(|sa| (sa.ip().to_string(), sa.port()))
                    .collect(),
            },
            ..Default::default()
        };
        let client = RedisPool::new(conf, 10).expect("Valid pool config");
        let reconnect = ReconnectPolicy::new_constant(1_000, 10);
        let _conn_task = client.connect(Some(reconnect));
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
        let scan_stream = self
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
        domain: &LowerName,
        zone: &LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Option<Vec<crate::storage::StorageRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        // Use HGETALL here and then manually find the correct value instead of using HGET + key.
        // This way we at least properly return data if an entry for the domain exists but is not
        // of the correct type. Note that this is bad design, as business logic is now encoded in
        // the storge layer.
        let data = self
            .client
            .hgetall::<Vec<Vec<_>>, _>(format!("resource:{}:{}", zone, domain))
            .await?;

        if data.is_empty() {
            Ok(None)
        } else if data.len() % 2 != 0 {
            error!("HGETAL response size is not a multiple of 2");
            Ok(None)
        } else {
            for chunk in data.chunks_exact(2) {
                // TODO: take ownership here so we can get rid of the clone
                if String::from_utf8(chunk[0].clone())? == rtype.to_string() {
                    return Ok(Some(serde_json::from_slice(&chunk[1])?));
                }
            }
            Ok(Some(vec![]))
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
        domain: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let record_type = record.record.record_type();

        let mut record_set = self
            .lookup_records(domain, zone, record_type)
            .await?
            .unwrap_or_default();

        // Add new record to the set
        record_set.push(record);
        let new_record_set = serde_json::to_vec(&record_set)?;

        Ok(self
            .client
            .hset::<_, _, (&str, &[u8])>(
                format!("resource:{}:{}", zone, domain),
                (record_type.into(), &new_record_set),
            )
            .await?)
    }

    async fn list_records(
        &self,
        zone: &LowerName,
        domain: &LowerName,
    ) -> Result<Vec<StorageRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let encoded_records = self
            .client
            .hgetall::<HashMap<String, Vec<u8>>, _>(format!("resource:{}:{}", zone, domain))
            .await?;

        Ok(encoded_records
            .into_values()
            .filter_map::<Vec<_>, _>(|jv| serde_json::from_slice(&jv).ok())
            .flatten()
            .collect())
    }

    async fn list_domains(
        &self,
        zone: &LowerName,
    ) -> Result<Vec<LowerName>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .client
            .scan_cluster(
                format!("resource:{}:*", zone),
                Some(10),
                Some(ScanType::Hash),
            )
            .filter_map(|scan_entry| async {
                if let Ok(mut entry) = scan_entry {
                    if let Some(results) = entry.take_results() {
                        return Some(
                            results
                                .into_iter()
                                .filter_map(|re| {
                                    if let Some(raw_key) = re.as_str() {
                                        if let Some(domain) = raw_key.split(':').nth(2) {
                                            LowerName::from_str(domain).ok()
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                })
                                .collect(),
                        );
                    }
                }
                None
            })
            .collect::<Vec<Vec<_>>>()
            .await
            .into_iter()
            .flatten()
            .collect())
    }
}
