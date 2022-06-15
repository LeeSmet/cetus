use log::{debug, error, trace};
use std::{path::PathBuf, str::FromStr};
use tokio::fs;
use trust_dns_server::client::rr::LowerName;

use crate::storage::{Storage, StorageRecord};

/// An implementation of record storage on the filesystem.
pub struct FSStorage {
    base: PathBuf,
}

impl FSStorage {
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }
}

#[async_trait::async_trait]
impl Storage for FSStorage {
    async fn zones(&self) -> Result<Vec<LowerName>, Box<dyn std::error::Error + Send + Sync>> {
        trace!("Reading zones from {:?}", self.base);
        let mut zones = Vec::new();
        let mut dir_reader = fs::read_dir(&self.base).await?;
        while let Some(entry) = dir_reader.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }

            // we have a dir, load name
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => {
                    error!("could not convert dir name to String");
                    continue;
                }
            };

            let name = LowerName::from_str(&name)?;

            zones.push(name);
        }

        debug!("Found {} zones in filesystem", zones.len());

        Ok(zones)
    }

    async fn lookup_records(
        &self,
        name: &LowerName,
        zone: &LowerName,
        rtype: trust_dns_proto::rr::RecordType,
    ) -> Result<Option<Vec<crate::storage::StorageRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let mut path = self.base.clone();
        path.push(zone.to_string());
        path.push(name.to_string());

        // First check if the dir exists, per the contract of this function we should return
        // Ok(None) if it does not.
        if fs::metadata(&path).await.is_err() {
            return Ok(None);
        }

        path.push(rtype.to_string());

        // Check if the path for the record type exists to avoid returning an error later as this
        // is a valid setup.
        if fs::metadata(&path).await.is_err() {
            return Ok(Some(vec![]));
        }

        let data = fs::read(&path).await?;
        Ok(Some(serde_json::from_slice(&data)?))
    }

    async fn add_zone(
        &self,
        zone: &LowerName,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        todo!();
    }

    async fn add_record(
        &self,
        zone: &LowerName,
        record: StorageRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        todo!();
    }
}
