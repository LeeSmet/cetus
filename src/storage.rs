use serde::{Deserialize, Serialize};
use std::error::Error;
use trust_dns_proto::rr::{rdata::SOA, RecordType};
use trust_dns_server::{client::rr::LowerName, proto::rr::Record};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct StoredRecord {
    pub record: Record,
    // TODO
}

impl StoredRecord {
    /// Get access to the actual record.
    pub fn as_record(&self) -> &Record {
        &self.record
    }

    /// Get mutable access to the actual record.
    pub fn as_mut_record(&mut self) -> &mut Record {
        &mut self.record
    }
}

#[async_trait::async_trait]
pub trait Storage {
    /// Get a list of all zones served by the server. These are only the names - not the actual SOA
    /// records.
    async fn zones(&self) -> Result<Vec<(LowerName, SOA)>, Box<dyn Error + Send + Sync>>;

    /// Look up the records for a fqdn in the data store. It is possible that no records exist for
    /// the given name of the given type. It is also possible that more than 1 record exists for
    /// the given name and type.
    ///
    /// # Returns
    ///
    /// This method should return [`Option::None`] if the domain does not exist at all. Conversely,
    /// if the domain exists, but there are no entries for the given [`RecordType`], the return
    /// type must be [`Option::Some`] of an empty [`Vec`].
    async fn lookup_records(
        &self,
        name: &LowerName,
        zone: &LowerName,
        rtype: RecordType,
    ) -> Result<Option<Vec<StoredRecord>>, Box<dyn Error + Send + Sync>>;
}
