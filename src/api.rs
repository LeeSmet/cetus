use crate::storage::Storage;
use axum::{
    routing::{get, put},
    Extension, Router,
};
use std::{net::SocketAddr, sync::Arc};

mod zone;

/// State for all API handlers.
#[derive(Clone)]
pub struct State {
    storage: Arc<dyn Storage + Send + Sync>,
}

/// Create a new API instance with the given storage, and starts listening on the provided address
pub fn listen<S>(storage: Arc<S>, listen_address: SocketAddr)
where
    S: Storage + Send + Sync + 'static,
{
    log::trace!("Setting up API");
    // TODO: shutdown
    let shared_state = State { storage };
    let app = Router::new()
        .route("/zones", get(zone::list_zones))
        .route("/zones/:zone", get(zone::list_zone_domains))
        .route("/zones/:zone", put(zone::add_zone))
        .route("/zones/:zone/:domain", get(zone::list_domain_records))
        .layer(Extension(shared_state));
    tokio::spawn(async move {
        axum::Server::bind(&listen_address)
            .serve(app.into_make_service())
            .await
    });
    log::trace!("API set up");
}
