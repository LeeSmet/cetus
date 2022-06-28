use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub instance_name: String,

    // TCP address for the api HTTP server
    pub api_listener: Option<SocketAddr>,

    pub metric_listener: Option<SocketAddr>,

    pub geoip_db_location: PathBuf,

    pub redis_config: RedisConnectionConfig,

    #[serde(default = "Vec::new")]
    pub udp_sockets: Vec<SocketAddr>,
    #[serde(default = "Vec::new")]
    pub tcp_listeners: Vec<TcpListenerConfig>,
}

#[derive(Deserialize)]
pub struct TcpListenerConfig {
    pub address: SocketAddr,
    pub timeout_millis: u64,
}

#[derive(Deserialize)]
pub struct RedisConnectionConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "Vec::new")]
    pub node_addresses: Vec<SocketAddr>,
}
