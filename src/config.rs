use std::{net::SocketAddr, time::Duration};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub instance_name: String,

    pub metric_listener: Option<SocketAddr>,

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
