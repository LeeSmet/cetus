use std::error::Error;
use trust_dns_proto::rr::RecordType;
use trust_dns_server::{client::rr::LowerName, proto::rr::Record};

pub struct StoredRecord {
    record: Record,
    // TODO
}

#[async_trait::async_trait]
pub trait Storage {
    /// Get a list of all zones served by the server. These are only the names - not the actual SOA
    /// records.
    async fn zones(&self) -> Result<Vec<LowerName>, Box<dyn Error + Send + Sync>>;
    /// Look up the records for a fqdn in the data store. It is possible that no records exist for
    /// the given name of the given type. It is also possible that more than 1 record exists for
    /// the given name and type.
    async fn lookup_records(
        &self,
        name: &LowerName,
        rtype: RecordType,
    ) -> Result<Vec<StoredRecord>, Box<dyn Error + Send + Sync>>;
}
