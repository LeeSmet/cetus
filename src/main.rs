use std::{path::PathBuf, time::Duration};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod fs;
mod handle;
mod memory;
mod metrics;
mod redis;
mod storage;

fn main() {
    pretty_env_logger::init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("cetus-runtime")
        .build()
        .unwrap();

    rt.block_on(async {
        let udp_socket = UdpSocket::bind("[::]:5353").await.unwrap();
        let tcp_listener = TcpListener::bind("[::]:5353").await.unwrap();
        let mut base_path = PathBuf::new();
        base_path.push("dns_storage");
        let storage = fs::FSStorage::new(base_path);
        // let handler = handle::DNS::new(MemoryStorage::new());
        let handler = handle::DnsHandler::new("cetus primary".to_string(), storage);
        let mut fut = ServerFuture::new(handler);
        fut.register_socket(udp_socket);
        fut.register_listener(tcp_listener, Duration::from_secs(2));

        fut.block_until_done().await.unwrap();
    })
}
