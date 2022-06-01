use crate::storage::Storage;

pub struct MemoryStorage {}

impl MemoryStorage {
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
        name: &trust_dns_server::client::rr::LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Vec<crate::storage::StoredRecord>, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!();
    }
}