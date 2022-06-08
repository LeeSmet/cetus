use std::{
    collections::HashMap,
    error::Error,
    future::{ready, Future},
    net::SocketAddr,
};

use axum::{routing::get, Router};
use chashmap::CHashMap;
use prometheus::{
    labels, opts, register_int_counter_vec_with_registry, Encoder, IntCounterVec, Registry,
    TextEncoder,
};
use trust_dns_proto::{op::ResponseCode, rr::RecordType};
use trust_dns_server::{client::rr::LowerName, server::Protocol};

/// &str representation of ipv4
const IPV4: &str = "IPv4";
/// &str representation of ipv6
const IPV6: &str = "IPv6";

/// Metrics for the dns server.
pub struct Metrics {
    registry: Registry,
    zone_metrics: CHashMap<LowerName, ZoneMetrics>,
}

/// Metrics for a specific zone
pub struct ZoneMetrics {
    record_types: IntCounterVec,
    connection_types: IntCounterVec,
    response_codes: IntCounterVec,
}

impl Metrics {
    /// Create a new Metrics instance. The metrics won't have any zone info, these need to be added
    /// manually after creating the instance.
    pub fn new(instance_name: String) -> Metrics {
        let mut labels = HashMap::new();
        labels.insert("instance_name".to_string(), instance_name);
        let registry = Registry::new_custom(Some("cetus".to_string()), Some(labels))
            .expect("can create a new registry");
        let zone_metrics = CHashMap::new();
        Metrics {
            registry,
            zone_metrics,
        }
    }

    /// Register a new zone in the metrics, so that they are exposed and can be updated.
    pub fn register_zone(&self, zone: LowerName) {
        // Needed because labels! moves the value.
        let zone_name = zone.to_string();

        let response_codes = register_int_counter_vec_with_registry!(
            opts!(
                "response_code",
                "response codes returned by queries to zones in the given authority.",
                labels! {"zone" => &zone_name}
            ),
            &["code"],
            self.registry
        )
        .expect("Can register response code counters");
        // pre fill all response codes, though only the ones we use
        response_codes.with_label_values(&[ResponseCode::NoError.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NotImp.to_str()]);
        response_codes.with_label_values(&[ResponseCode::ServFail.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NXDomain.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NotImp.to_str()]);
        response_codes.with_label_values(&[ResponseCode::Refused.to_str()]);

        let record_types = register_int_counter_vec_with_registry!(
            opts!(
                "query_type",
                "the record type requested by the query.",
                labels! {"zone" => &zone_name}
            ),
            &["record"],
            self.registry
        )
        .expect("Can register query type counter vec");

        // pre fill all record types.
        record_types.with_label_values(&[RecordType::A.into()]);
        record_types.with_label_values(&[RecordType::AAAA.into()]);
        record_types.with_label_values(&[RecordType::ANAME.into()]);
        record_types.with_label_values(&[RecordType::ANY.into()]);
        record_types.with_label_values(&[RecordType::AXFR.into()]);
        record_types.with_label_values(&[RecordType::CAA.into()]);
        record_types.with_label_values(&[RecordType::CDS.into()]);
        record_types.with_label_values(&[RecordType::CDNSKEY.into()]);
        record_types.with_label_values(&[RecordType::CNAME.into()]);
        record_types.with_label_values(&[RecordType::CSYNC.into()]);
        record_types.with_label_values(&[RecordType::DNSKEY.into()]);
        record_types.with_label_values(&[RecordType::DS.into()]);
        record_types.with_label_values(&[RecordType::HINFO.into()]);
        record_types.with_label_values(&[RecordType::HTTPS.into()]);
        record_types.with_label_values(&[RecordType::IXFR.into()]);
        record_types.with_label_values(&[RecordType::KEY.into()]);
        record_types.with_label_values(&[RecordType::MX.into()]);
        record_types.with_label_values(&[RecordType::NAPTR.into()]);
        record_types.with_label_values(&[RecordType::NS.into()]);
        record_types.with_label_values(&[RecordType::NSEC.into()]);
        record_types.with_label_values(&[RecordType::NSEC3.into()]);
        record_types.with_label_values(&[RecordType::NSEC3PARAM.into()]);
        record_types.with_label_values(&[RecordType::NULL.into()]);
        record_types.with_label_values(&[RecordType::OPENPGPKEY.into()]);
        record_types.with_label_values(&[RecordType::OPT.into()]);
        record_types.with_label_values(&[RecordType::PTR.into()]);
        record_types.with_label_values(&[RecordType::RRSIG.into()]);
        record_types.with_label_values(&[RecordType::SIG.into()]);
        record_types.with_label_values(&[RecordType::SOA.into()]);
        record_types.with_label_values(&[RecordType::SRV.into()]);
        record_types.with_label_values(&[RecordType::SSHFP.into()]);
        record_types.with_label_values(&[RecordType::SVCB.into()]);
        record_types.with_label_values(&[RecordType::TLSA.into()]);
        record_types.with_label_values(&[RecordType::TSIG.into()]);
        record_types.with_label_values(&[RecordType::TXT.into()]);

        let connection_types = register_int_counter_vec_with_registry!(
            opts!(
                "connection_types",
                "The type of connection used for the query to the zone",
                labels! {"zone" => &zone_name}
            ),
            &["ip_version", "protocol"],
            self.registry
        )
        .expect("Can register connection type counter vec");

        // pre fill connection types.
        // NOTE: currently only UDP and TCP are able to be used.
        connection_types.with_label_values(&[IPV4, &Protocol::Udp.to_string()]);
        connection_types.with_label_values(&[IPV4, &Protocol::Tcp.to_string()]);
        // connection_types.with_label_values(&[IPV4, &Protocol::Dtls.to_string()]);
        // connection_types.with_label_values(&[IPV4, &Protocol::Tls.to_string()]);
        // connection_types.with_label_values(&[IPV4, &Protocol::Https.to_string()]);
        connection_types.with_label_values(&[IPV6, &Protocol::Udp.to_string()]);
        connection_types.with_label_values(&[IPV6, &Protocol::Tcp.to_string()]);
        // connection_types.with_label_values(&[IPV6, &Protocol::Dtls.to_string()]);
        // connection_types.with_label_values(&[IPV6, &Protocol::Tls.to_string()]);
        // connection_types.with_label_values(&[IPV6, &Protocol::Https.to_string()]);

        let zone_metrics = ZoneMetrics {
            record_types,
            connection_types,
            response_codes,
        };

        self.zone_metrics.insert(zone, zone_metrics);
    }

    /// Unregister an existing zone from the metrics, so that metrics are no longer exposed. They
    /// will also not be available anymore to update.
    pub fn unregister_zone(&self, zone: &LowerName) {
        unimplemented!();
    }

    /// Increment the query count for a zone.
    pub fn increment_zone_record_type(&self, zone: &LowerName, query_type: RecordType) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .record_types
                .with_label_values(&[query_type.into()])
                .inc();
        };
    }

    /// Increment the response code count for a zone.
    pub fn increment_response_code(&self, zone: &LowerName, response_code: ResponseCode) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .response_codes
                .with_label_values(&[response_code.to_str()])
                .inc();
        }
    }

    pub fn increment_connection_type(
        &self,
        zone: &LowerName,
        remote: &SocketAddr,
        proto: Protocol,
    ) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .connection_types
                .with_label_values(&[
                    if remote.is_ipv4() { IPV4 } else { IPV6 },
                    &proto.to_string(),
                ])
                .inc();
        }
    }

    /// Set up the metric server and bind it to the given socket address. The server won't start
    /// until the future returned by this function is awaited.
    pub fn server_future(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>> {
        let registry = self.registry.clone();

        async move {
            let app = Router::new().route(
                "/metrics",
                get(move || {
                    ready({
                        let encoder = TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = vec![];
                        encoder.encode(&metric_families, &mut buffer).unwrap();

                        buffer
                    })
                }),
            );

            Ok(axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
                .map(|_| ())?)
        }
    }
}
