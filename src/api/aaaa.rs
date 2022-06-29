use std::net::Ipv6Addr;

use super::State;
use crate::storage::StorageRecord;
use axum::{extract, http::StatusCode, response, Extension};
use log::error;
use serde::Deserialize;
use trust_dns_proto::rr::{Name, RData, Record};
use trust_dns_server::client::rr::LowerName;

#[derive(Deserialize)]
pub struct AddARecord {
    data: Ipv6Addr,
    ttl: u32,
}

pub async fn add_record(
    extract::Path((zone, domain)): extract::Path<(Name, Name)>,
    extract::Json(data): extract::Json<AddARecord>,
    Extension(state): Extension<State>,
) -> response::Result<StatusCode> {
    if !zone.is_fqdn() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Can only add records for fqdn zones",
        )
            .into());
    }

    if !domain.is_fqdn() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Can only add records for fqdn domains",
        )
            .into());
    }

    let record = Record::from_rdata(domain.clone(), data.ttl, RData::AAAA(data.data));

    state
        .storage
        .add_record(
            &LowerName::from(zone),
            &LowerName::from(domain),
            StorageRecord { record },
        )
        .await
        .map_err(|err| {
            error!("Failed to insert AAAA record: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::CREATED)
}
