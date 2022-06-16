use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::{error::Error, sync::Arc};
use trust_dns_proto::rr::RecordType;
use trust_dns_server::{client::rr::LowerName, proto::rr::Record};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct StorageRecord {
    pub record: Record,
    // TODO
}

impl StorageRecord {
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
    async fn zones(&self) -> Result<Vec<LowerName>, Box<dyn Error + Send + Sync>>;

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
    ) -> Result<Option<Vec<StorageRecord>>, Box<dyn Error + Send + Sync>>;

    /// Add a new zone to the server. This only sets a marker in storage to indicate that the
    /// server is indeed authoritative for the zone, but importantly the SOA and NS records will
    /// need to be added manually after this.
    async fn add_zone(&self, zone: &LowerName) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Store a record in a zone. Callers should always verify that the zone exists before
    /// submitting a record.
    async fn add_record(
        &self,
        zone: &LowerName,
        name: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

#[async_trait::async_trait]
impl<S> Storage for Arc<S>
where
    S: Storage + Send + Sync,
{
    async fn zones(&self) -> Result<Vec<LowerName>, Box<dyn Error + Send + Sync>> {
        self.deref().zones().await
    }

    async fn lookup_records(
        &self,
        name: &LowerName,
        zone: &LowerName,
        rtype: RecordType,
    ) -> Result<Option<Vec<StorageRecord>>, Box<dyn Error + Send + Sync>> {
        self.deref().lookup_records(name, zone, rtype).await
    }

    async fn add_zone(&self, zone: &LowerName) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.deref().add_zone(zone).await
    }

    async fn add_record(
        &self,
        zone: &LowerName,
        name: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.deref().add_record(zone, name, record).await
    }
}
