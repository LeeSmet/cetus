use crate::storage::{Storage, StorageRecord};

pub struct MemoryStorage {}

impl MemoryStorage {
    #[allow(dead_code)]
    pub fn new() -> Self {
        MemoryStorage {}
    }
}

#[async_trait::async_trait]
impl Storage for MemoryStorage {
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
        _domain: &trust_dns_server::client::rr::LowerName,
        _zone: &trust_dns_server::client::rr::LowerName,
        _rtype: trust_dns_server::proto::rr::RecordType,
    ) -> Result<Option<Vec<crate::storage::StorageRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        unimplemented!();
    }

    async fn add_zone(
        &self,
        _zone: &trust_dns_server::client::rr::LowerName,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!();
    }

    async fn add_record(
        &self,
        _zone: &trust_dns_server::client::rr::LowerName,
        _domain: &trust_dns_server::client::rr::LowerName,
        _record: StorageRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!();
    }

    async fn list_records(
        &self,
        _zone: &trust_dns_server::client::rr::LowerName,
        _domain: &trust_dns_server::client::rr::LowerName,
    ) -> Result<Vec<StorageRecord>, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!();
    }

    async fn list_domains(
        &self,
        _zone: &trust_dns_server::client::rr::LowerName,
    ) -> Result<
        Vec<trust_dns_server::client::rr::LowerName>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        unimplemented!();
    }
}
