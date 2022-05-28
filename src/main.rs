use memory::MemoryStorage;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_server::client::rr::rdata::SOA;
use trust_dns_server::client::rr::{LowerName, Name, RecordSet, RrKey};
use trust_dns_server::store::in_memory::InMemoryAuthority;
use trust_dns_server::{authority::Catalog, client::rr::Record, ServerFuture};

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
        // let mut catalog = Catalog::new();
        // let name = Name::from_str("ava.tf").unwrap();
        // let mut records = BTreeMap::new();
        // let mut rs = RecordSet::new(&name, trust_dns_server::client::rr::RecordType::A, 1);
        // let mut rs2 = RecordSet::new(&name, trust_dns_server::client::rr::RecordType::SOA, 1);
        // let mut record = Record::new();
        // record
        //     .set_name(name.clone())
        //     .set_rr_type(trust_dns_server::client::rr::RecordType::A)
        //     .set_ttl(300)
        //     .set_data(Some(trust_dns_server::client::rr::RData::A(
        //         [1, 1, 1, 1].into(),
        //     )));
        // let mut record2 = Record::new();
        // record2
        //     .set_name(name.clone())
        //     .set_rr_type(trust_dns_server::client::rr::RecordType::SOA)
        //     .set_ttl(3600 * 24 * 7)
        //     .set_data(Some(trust_dns_server::client::rr::RData::SOA(SOA::new(
        //         Name::from_str("ns1.test.grid.tf").unwrap(),
        //         Name::from_str("info.threefold.tech").unwrap(),
        //         2,
        //         3600,
        //         300,
        //         600,
        //         300,
        //     ))));
        // rs.insert(record, 2);
        // rs2.insert(record2, 2);
        // records.insert(
        //     RrKey {
        //         name: LowerName::from(&name),
        //         record_type: trust_dns_server::client::rr::RecordType::A,
        //     },
        //     rs,
        // );
        // records.insert(
        //     RrKey {
        //         name: LowerName::from(&name),
        //         record_type: trust_dns_server::client::rr::RecordType::SOA,
        //     },
        //     rs2,
        // );
        // let authority = InMemoryAuthority::new(
        //     name.clone(),
        //     records,
        //     trust_dns_server::authority::ZoneType::Primary,
        //     false,
        // )
        // .unwrap();
        // catalog.upsert(LowerName::new(&name), Box::new(Arc::new(authority)));
        //let mut fut = ServerFuture::new(catalog);
        let handler = handle::DNS::new(MemoryStorage::new());
        let mut fut = ServerFuture::new(handler);
        fut.register_socket(udp_listener);
        fut.block_until_done().await.unwrap();
    })
}
