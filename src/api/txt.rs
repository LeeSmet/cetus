use super::State;
use crate::storage::StorageRecord;
use axum::{extract, http::StatusCode, response, Extension};
use log::error;
use serde::Deserialize;
use trust_dns_proto::rr::{rdata::TXT, Name, RData, Record};
use trust_dns_server::client::rr::LowerName;

const MAX_TXT_SECTION_LENGTH: usize = 255;

#[derive(Deserialize)]
pub struct AddARecord {
    data: Vec<String>,
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

    let mut decoded_sections = Vec::with_capacity(data.data.len());
    for section in data.data {
        // Input must be hex encoded
        if section.len() > MAX_TXT_SECTION_LENGTH * 2 {
            return Err((
                StatusCode::BAD_REQUEST,
                "TXT section length is limited to 255 characters (510 hex characters)",
            )
                .into());
        }
        let mut dst = Vec::with_capacity(section.len() / 2);
        faster_hex::hex_decode(section.as_bytes(), &mut dst)
            .map_err(|_| (StatusCode::BAD_REQUEST, "TXT section must be valid hex"))?;
        decoded_sections.push(dst);
    }
    let txt = TXT::from_bytes(decoded_sections.iter().map(|s| s.as_slice()).collect());

    let record = Record::from_rdata(domain.clone(), data.ttl, RData::TXT(txt));

    state
        .storage
        .add_record(
            &LowerName::from(zone),
            &LowerName::from(domain),
            StorageRecord { record },
        )
        .await
        .map_err(|err| {
            error!("Failed to insert CNAME record: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::CREATED)
}
