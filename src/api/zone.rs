use super::State;
use crate::storage::{Storage, StorageRecord};
use axum::{extract, http::StatusCode, response, Extension};
use log::{error, trace};
use trust_dns_proto::rr::{rdata::SOA, Name, RData, Record};
use trust_dns_server::client::rr::LowerName;

use serde::Deserialize;
#[derive(Deserialize)]
pub struct AddZone {
    // primary dns name
    mname: Name,
    // mailbox domain
    rname: Name,
    // serial, not really used by cetus.
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
    ttl: u32,
    nameservers: Vec<NS>,
}

#[derive(Deserialize)]
struct NS {
    name: Name,
    ttl: u32,
}

/// Load all existing zones from the server.
pub async fn list_zones(
    Extension(state): Extension<State>,
) -> response::Result<response::Json<Vec<String>>> {
    trace!("Loading zones through API");
    Ok(response::Json(
        state
            .storage
            .zones()
            .await
            .map_err(|err| {
                error!("Failed to load zones in API: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .into_iter()
            .map(|ln| ln.to_string())
            .collect(),
    ))
}

/// Add a new zone to the server
pub async fn add_zone(
    extract::Path(zone): extract::Path<Name>,
    extract::Json(data): extract::Json<AddZone>,
    Extension(state): Extension<State>,
) -> response::Result<StatusCode> {
    let existing_zones = state.storage.zones().await.map_err(|err| {
        error!("Failed to load zones in API: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let zone_name = LowerName::from(zone.clone());

    if !zone_name.is_fqdn() {
        log::debug!("Refusing to add zone which is not an fqdn ({})", zone_name);
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
    }

    if existing_zones.contains(&zone_name) {
        // Zone already exists
        return Err(StatusCode::CONFLICT.into());
    }

    let soa = SOA::new(
        data.mname,
        data.rname,
        data.serial,
        data.refresh,
        data.retry,
        data.expire,
        data.minimum,
    );

    let soa_record = Record::from_rdata(zone, data.ttl, RData::SOA(soa));

    let ns_records = data
        .nameservers
        .into_iter()
        .map(|ns| {
            let rdata = RData::NS(ns.name.clone());
            Record::from_rdata(ns.name, ns.ttl, rdata)
        })
        .collect::<Vec<_>>();

    log::trace!("NS records {:?}", ns_records);

    // Insert the zone first, otherwise the records will get rejected
    state.storage.add_zone(&zone_name).await.map_err(|err| {
        error!("Failed to add zone: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Now insert the SOA record
    state
        .storage
        .add_record(&zone_name, &zone_name, StorageRecord { record: soa_record })
        .await
        .map_err(|err| {
            error!("Failed to insert zone SOA: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Finally insert the NS records
    for ns_record in ns_records {
        state
            .storage
            .add_record(&zone_name, &zone_name, StorageRecord { record: ns_record })
            .await
            .map_err(|err| {
                error!("Failed to insert NS record: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    Ok(StatusCode::CREATED)
}