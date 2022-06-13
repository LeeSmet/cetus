use std::{
    collections::HashMap,
    error::Error,
    future::{ready, Future},
    net::SocketAddr,
    ops::Deref,
    sync::Arc,
};

use axum::{routing::get, Router};
use chashmap::CHashMap;
use log::debug;
use prometheus::{
    labels, opts, register_int_counter_vec_with_registry, Encoder, IntCounterVec, Registry,
    TextEncoder,
};
use trust_dns_proto::{
    op::ResponseCode,
    rr::{DNSClass, RecordType},
};
use trust_dns_server::{client::rr::LowerName, server::Protocol};

/// &str representation of ipv4
const IPV4: &str = "IPv4";
/// &str representation of ipv6
const IPV6: &str = "IPv6";

/// Metrics for the dns server. These can be cheaply cloned to share between multiple
/// tasks/threads.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

impl Deref for Metrics {
    type Target = MetricsInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Actual implementation of the metrics.
pub struct MetricsInner {
    registry: Registry,
    zone_metrics: CHashMap<LowerName, ZoneMetrics>,
    /// metrics used if a query is not in the zone
    unknown_zone_metrics: ZoneMetrics,
}

/// Metrics for a specific zone
pub struct ZoneMetrics {
    registry: Registry,
    query_class: IntCounterVec,
    record_types: IntCounterVec,
    connection_types: IntCounterVec,
    response_codes: IntCounterVec,
    country_queries: IntCounterVec,
}

impl ZoneMetrics {
    fn register(zone: Option<&LowerName>, registry: Registry) -> ZoneMetrics {
        let zone_name = if let Some(ref zone) = zone {
            zone.to_string()
        } else {
            "UNKNOWN".to_string()
        };

        let response_codes = register_int_counter_vec_with_registry!(
            opts!(
                "response_code",
                "response codes returned by queries to zones in the given authority.",
                labels! {"zone" => &zone_name}
            ),
            &["code"],
            registry
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
            registry
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

        let query_class = register_int_counter_vec_with_registry!(
            opts!(
                "query_class",
                "The class in the query",
                labels! {"zone" => &zone_name}
            ),
            &["class"],
            registry
        )
        .expect("Can register query class counter vec");

        // pre fill query types.
        query_class.with_label_values(&[&DNSClass::IN.to_string()]);
        query_class.with_label_values(&[&DNSClass::CH.to_string()]);
        query_class.with_label_values(&[&DNSClass::HS.to_string()]);
        query_class.with_label_values(&[&DNSClass::NONE.to_string()]);
        query_class.with_label_values(&[&DNSClass::ANY.to_string()]);

        let connection_types = register_int_counter_vec_with_registry!(
            opts!(
                "connection_types",
                "The type of connection used for the query to the zone",
                labels! {"zone" => &zone_name}
            ),
            &["ip_version", "protocol"],
            registry
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

        // We don't prefill this vec
        let country_queries = register_int_counter_vec_with_registry!(
            opts!(
                "country_queries",
                "The assumed country a query originates from",
                labels! {"zone" => &zone_name}
            ),
            &["country"],
            registry
        )
        .expect("Can register query class counter vec");

        ZoneMetrics {
            registry,
            query_class,
            record_types,
            connection_types,
            response_codes,
            country_queries,
        }
    }

    /// Remove existing metrics from a register, making the item inaccessible.
    fn unregister(self) {
        // This unwrap is safe as self.registry is the registry used to add the metrics
        self.registry
            .unregister(Box::new(self.response_codes))
            .unwrap();
        // This unwrap is safe as self.registry is the registry used to add the metrics
        self.registry
            .unregister(Box::new(self.connection_types))
            .unwrap();
        // This unwrap is safe as self.registry is the registry used to add the metrics
        self.registry
            .unregister(Box::new(self.record_types))
            .unwrap();
    }
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
        let unknown_zone_metrics = ZoneMetrics::register(None, registry.clone());
        Metrics {
            inner: Arc::new(MetricsInner {
                registry,
                zone_metrics,
                unknown_zone_metrics,
            }),
        }
    }

    /// Register a new zone in the metrics, so that they are exposed and can be updated.
    pub fn register_zone(&self, zone: LowerName) {
        debug!("Registering metrics for zone {}", zone);

        let zone_metrics = ZoneMetrics::register(Some(&zone), self.registry.clone());
        self.zone_metrics.insert(zone, zone_metrics);
    }

    /// Unregister an existing zone from the metrics, so that metrics are no longer exposed. They
    /// will also not be available anymore to update.
    pub fn unregister_zone(&self, zone: &LowerName) {
        debug!("Unregistering metrics for zone {}", zone);

        if let Some(zone_metrics) = self.zone_metrics.remove(zone) {
            zone_metrics.unregister();
        }
    }

    /// Increment the query record type for a zone.
    pub fn increment_zone_record_type(&self, zone: &LowerName, record_type: RecordType) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .record_types
                .with_label_values(&[record_type.into()])
                .inc();
        };
    }

    /// Increment the query record type for the unknown zone.
    pub fn increment_unknown_zone_record_type(&self, record_type: RecordType) {
        self.unknown_zone_metrics
            .record_types
            .with_label_values(&[record_type.into()])
            .inc();
    }

    /// Increment the response code count for a zone.
    pub fn increment_zone_response_code(&self, zone: &LowerName, response_code: ResponseCode) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .response_codes
                .with_label_values(&[response_code.to_str()])
                .inc();
        }
    }

    /// Increment the response code count for the unknown zone.
    pub fn increment_unknown_zone_response_code(&self, response_code: ResponseCode) {
        self.unknown_zone_metrics
            .response_codes
            .with_label_values(&[response_code.to_str()])
            .inc();
    }

    /// Increment the connection type info for a zone.
    pub fn increment_zone_connection_type(
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

    /// Increment the connection type info for the unknown zone.
    pub fn increment_unknown_zone_connection_type(&self, remote: &SocketAddr, proto: Protocol) {
        self.unknown_zone_metrics
            .connection_types
            .with_label_values(&[
                if remote.is_ipv4() { IPV4 } else { IPV6 },
                &proto.to_string(),
            ])
            .inc();
    }

    /// Increment the class queried in the zone.
    pub fn increment_zone_query_class(&self, zone: &LowerName, class: DNSClass) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics
                .query_class
                .with_label_values(&[&class.to_string()])
                .inc();
        }
    }

    /// Increment the class queried for the unknown zone.
    pub fn increment_unknown_zone_query_class(&self, class: DNSClass) {
        self.unknown_zone_metrics
            .query_class
            .with_label_values(&[&class.to_string()])
            .inc();
    }

    /// Increment the query lookup source.
    pub fn increment_zone_country_query(&self, zone: &LowerName, country: &str) {
        debug!("Incrementing source '{}' for zone {}", country, zone);
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics.country_queries.with_label_values(&[country]).inc();
        }
    }

    /// Increment the query lookup source for the unknown zone.
    pub fn increment_unknown_zone_country_query(&self, country: &str) {
        debug!("Incrementing source '{}' for zone UNKNOWN", country);
        self.unknown_zone_metrics
            .country_queries
            .with_label_values(&[country])
            .inc();
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
