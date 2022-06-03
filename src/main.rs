use std::path::PathBuf;
use tokio::net::UdpSocket;
use trust_dns_server::ServerFuture;

mod fs;
mod handle;
mod memory;
mod storage;

fn main() {
    pretty_env_logger::init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("cetus-runtime")
        .build()
        .unwrap();

    rt.block_on(async {
        let udp_listener = UdpSocket::bind("[::]:5353").await.unwrap();
        let mut base_path = PathBuf::new();
        base_path.push("dns_storage");
        let storage = fs::FSStorage::new(base_path);
        // let handler = handle::DNS::new(MemoryStorage::new());
        let handler = handle::DnsHandler::new(storage);
        handler.load_zones().await.expect("can load zones");
        let mut fut = ServerFuture::new(handler);
        fut.register_socket(udp_listener);
        fut.block_until_done().await.unwrap();
    })
}
