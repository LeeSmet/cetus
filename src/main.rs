use log::error;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod api;
mod config;
mod fs;
mod geo;
mod handle;
mod memory;
mod metrics;
mod redis;
mod storage;

fn main() {
    pretty_env_logger::init();

    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./cetus_cfg.toml".to_string());

    let cfg =
        toml::from_slice::<config::Config>(&std::fs::read(cfg_path).expect("Can read config file"))
            .expect("Can decode config file");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("cetus-runtime")
        .build()
        .unwrap();

    rt.block_on(async {
        let mut base_path = PathBuf::new();
        base_path.push("dns_storage");
        let storage = redis::RedisClusterClient::new(
            cfg.redis_config.username,
            cfg.redis_config.password,
            &cfg.redis_config.node_addresses,
        );
        storage.test().await.unwrap();
        let storage = Arc::new(storage);
        if let Some(api_address) = cfg.api_listener {
            api::listen(storage.clone(), api_address);
        }
        let geoip_db = geo::GeoLocator::new(cfg.geoip_db_location).unwrap();
        let handler =
            handle::DnsHandler::new(cfg.instance_name, cfg.metric_listener, geoip_db, storage);
        let mut fut = ServerFuture::new(handler);
        log::trace!("Setup server future");
        for sock_addr in cfg.udp_sockets {
            match UdpSocket::bind(sock_addr).await {
                Ok(socket) => fut.register_socket(socket),
                Err(e) => error!("Could not bind udp socket {}: {}", sock_addr, e),
            };
        }
        for tcp_cfg in cfg.tcp_listeners {
            match TcpListener::bind(tcp_cfg.address).await {
                Ok(listener) => {
                    fut.register_listener(listener, Duration::from_millis(tcp_cfg.timeout_millis))
                }
                Err(e) => error!("Could not bind tcp listener {}: {}", tcp_cfg.address, e),
            }
        }

        fut.block_until_done().await.unwrap();
    })
}
