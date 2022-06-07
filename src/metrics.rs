use std::{
    collections::HashMap,
    error::Error,
    future::{ready, Future},
    net::SocketAddr,
};

use axum::{routing::get, Router};
use chashmap::CHashMap;
use prometheus::{
    labels, opts, register_int_counter_vec_with_registry, register_int_counter_with_registry,
    Encoder, IntCounter, IntCounterVec, Registry, TextEncoder,
};
use trust_dns_proto::op::ResponseCode;
use trust_dns_server::client::rr::LowerName;

/// Metrics for the dns server.
pub struct Metrics {
    registry: Registry,
    zone_metrics: CHashMap<LowerName, ZoneMetrics>,
}

/// Metrics for a specific zone
pub struct ZoneMetrics {
    query_count: IntCounter,
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

        let response_code_opts = opts!(
            "response_code",
            "response codes returned by queries to zones in the given authority.",
            labels! {"zone" => &zone_name}
        );

        let response_codes =
            register_int_counter_vec_with_registry!(response_code_opts, &["code"], self.registry)
                .expect("Can register response code counters");
        // pre fill all response codes, though only the ones we use
        response_codes.with_label_values(&[ResponseCode::NoError.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NotImp.to_str()]);
        response_codes.with_label_values(&[ResponseCode::ServFail.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NXDomain.to_str()]);
        response_codes.with_label_values(&[ResponseCode::NotImp.to_str()]);
        response_codes.with_label_values(&[ResponseCode::Refused.to_str()]);

        let query_count = register_int_counter_with_registry!(
            opts!(
                "total_queries",
                "total queries in this zone.",
                labels! {"zone" => &zone_name}
            ),
            self.registry
        )
        .expect("Can register query counter vec");

        let zone_metrics = ZoneMetrics {
            response_codes,
            query_count,
        };

        self.zone_metrics.insert(zone, zone_metrics);
    }

    /// Unregister an existing zone from the metrics, so that metrics are no longer exposed. They
    /// will also not be available anymore to update.
    pub fn unregister_zone(&self, zone: &LowerName) {
        unimplemented!();
    }

    /// Increment the query count for a zone.
    pub fn increment_zone_query_count(&self, zone: &LowerName) {
        if let Some(metrics) = self.zone_metrics.get(zone) {
            metrics.query_count.inc();
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
