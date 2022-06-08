use std::{
    future::Future,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use trust_dns_proto::rr::DNSClass;
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::{
        op::{LowerQuery, MessageType, OpCode, ResponseCode},
        rr::LowerName,
    },
    server::{RequestHandler, ResponseInfo},
};

use crate::{metrics::Metrics, storage::Storage};

/// We don't expect frequent updates of the Zone list, so use an [AtomicPtr] here. The idea is that
/// we will create a new [Arc] if there is a new list, and an atomic operation is used to swap the
/// old list with the new list. Note that the [Arc] is not part of the type signature, for more
/// info see [Arc::into_raw] and [Arc::from_raw].
// TODO: vetting
type ZoneCache = AtomicPtr<Vec<LowerName>>;

pub struct DnsHandler<S> {
    // list of all known zones, this allows us to verify if we are an authority without hitting the
    // database.
    // TODO: check if there is a better way to spawn the refresh loop.
    zone_cache: Arc<ZoneCache>,
    storage: Arc<S>,
    metrics: Metrics,
}

impl<S> DnsHandler<S>
where
    S: Storage + Send + Sync + Unpin + 'static,
{
    /// Create a new DNS handler with the given [`Storage`].
    ///
    /// # Panics
    ///
    /// This function will panic if called outside the context of a `[tokio]` runtime.
    pub fn new(instance_name: String, storage: S) -> Self {
        // TODO: inject metric addr
        let metric_addr = "[::]:9000"
            .parse()
            .expect("Can parse static socket address");
        let zones = Arc::new(Vec::<LowerName>::new());
        let zone_cache = Arc::new(AtomicPtr::new(Arc::into_raw(zones) as *mut _));
        let storage = Arc::new(storage);
        let metrics = Metrics::new(instance_name);
        // Start the metric server forever
        tokio::spawn(metrics.server_future(metric_addr));

        let handler = DnsHandler {
            zone_cache,
            storage,
            metrics,
        };

        // Start permanently loading zones
        tokio::spawn(handler.zone_loader());

        handler
    }
}

#[async_trait::async_trait]
impl<S> RequestHandler for DnsHandler<S>
where
    S: Storage + Send + Sync + Unpin + 'static,
{
    async fn handle_request<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        response_handle: R,
    ) -> ResponseInfo {
        // We only support query types - outright reject responses
        match request.message_type() {
            MessageType::Query => {}
            MessageType::Response => {
                return self
                    .reply_error(request, response_handle, ResponseCode::NotImp)
                    .await;
            }
        };

        match request.op_code() {
            OpCode::Query => self.query(request, response_handle).await,
            OpCode::Status | OpCode::Notify | OpCode::Update => {
                return self
                    .reply_error(request, response_handle, ResponseCode::NotImp)
                    .await;
            }
        }
    }
}

impl<S> DnsHandler<S>
where
    S: Storage + Send + Sync + Unpin,
{
    /// Handle a request query. This function does the following:
    ///
    /// 1. Check if the class is `IN`. We only serve these (for now), outright reject other
    ///    classes.
    /// 2. Check the zone cache to see if the request is a (child of) a known zone, if it is not
    ///    outright reject the query.
    /// 3. Handle the query for the domain in the known zone.
    async fn query<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();

        // First verify this is the IN class
        if query.query_class() != DNSClass::IN {
            // Refuse to answer anything for these
            return self
                .reply_error(request, response_handle, ResponseCode::Refused)
                .await;
        }

        // Next check if we are authorized for the zone.
        let zone = self.find_authority(query);
        if let Some(zone_name) = zone {
            self.query_zone(request, &zone_name, response_handle).await
        } else {
            self.query_unknown_zone(request, response_handle).await
        }
    }

    /// Handle a query in a zone. At this point, validation of the zone is assumed to already have
    /// happened, i.e. we are certain that we are an authority for this zone.
    async fn query_zone<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        zone_name: &LowerName,
        mut response_handle: R,
    ) -> ResponseInfo {
        self.metrics
            .increment_zone_connection_type(zone_name, &request.src(), request.protocol());
        let query = request.query();
        self.metrics
            .increment_zone_record_type(zone_name, query.query_type());

        trace!("Getting zone SOA for {}", zone_name);
        let soas = match self
            .storage
            .lookup_records(zone_name, zone_name, trust_dns_proto::rr::RecordType::SOA)
            .await
        {
            Err(e) => {
                error!("Failed to fetch SOA record for {}: {}", zone_name, e);
                self.metrics
                    .increment_zone_response_code(zone_name, ResponseCode::ServFail);
                return self
                    .reply_error(request, response_handle, ResponseCode::ServFail)
                    .await;
            }
            Ok(records) => records.expect("SOA record is always present if the zone exists"),
        };

        // Now get potential records
        trace!(
            "Fetching records for {} {}",
            query.name(),
            query.query_type()
        );

        let mut records = match self
            .storage
            .lookup_records(query.name(), zone_name, query.query_type())
            .await
        {
            Err(e) => {
                error!(
                    "Failed to fetch records for {} of type {}: {}",
                    query.name(),
                    query.query_type(),
                    e
                );
                self.metrics
                    .increment_zone_response_code(zone_name, ResponseCode::ServFail);
                return self
                    .reply_error(request, response_handle, ResponseCode::ServFail)
                    .await;
            }
            Ok(records) => records,
        };

        // Set edns according to the request.
        let mut response_builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = request.edns() {
            response_builder.edns(edns.clone());
        };

        // Set NXDOMAIN if there domain is not found.
        let mut header = *request.header();
        if records.is_none() {
            header.set_response_code(ResponseCode::NXDomain);
        };

        let required_soas = if match records {
            None => true,
            Some(ref records) => records.is_empty(),
        } {
            &soas[..]
        } else {
            &[][..]
        };

        let msg = response_builder.build(
            header,
            if let Some(ref mut records) = records {
                &mut records[..]
            } else {
                &mut [][..]
            }
            .iter_mut()
            .map(|sr| {
                {
                    // Preserve original casing in request.
                    sr.as_mut_record().set_name(query.original().name().clone());
                }
                sr.as_record()
            }),
            [],
            required_soas
                .iter()
                .map(|stored_soa| stored_soa.as_record()),
            [],
        );

        self.metrics
            .increment_zone_response_code(zone_name, msg.header().response_code());
        match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(ioe) => {
                warn!(
                    "Failed to send reply to message with response type: {}",
                    ioe
                );
                ResponseInfo::from(*request.header())
            }
        }
    }

    async fn query_unknown_zone<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.metrics
            .increment_unknown_zone_connection_type(&request.src(), request.protocol());
        self.metrics
            .increment_unknown_zone_record_type(request.query().query_type());
        self.metrics
            .increment_unknown_zoneresponse_code(ResponseCode::Refused);
        // We aren't an authority for this query, therefore it is refused.
        self.reply_error(request, response_handle, ResponseCode::Refused)
            .await
    }

    /// Send a generic error response. If sending the response fails, a new [ResponseInfo] object is
    /// created from a clone of the request header.
    async fn reply_error<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let response_builder = MessageResponseBuilder::from_message_request(request);
        let msg = response_builder.error_msg(request.header(), code);
        return match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(ioe) => {
                warn!(
                    "Failed to send reply to message with response code {}: {}",
                    code, ioe
                );
                ResponseInfo::from(*request.header())
            }
        };
    }

    /// Gets the authority zone for the query if it is present.
    ///
    /// TODO: Currently this just returns the first match, but does not account for zone in zones.
    fn find_authority(&self, query: &LowerQuery) -> Option<LowerName> {
        let name = query.name();
        let zones = self.zone_list();
        trace!("zone cache ref count {}", Arc::strong_count(&zones));
        for zone in zones.iter() {
            if zone.zone_of(name) {
                debug!("query {} in known zone {}", name, zone);
                return Some(zone.clone());
            }
        }
        None
    }

    /// Get the current zone list.
    fn zone_list(&self) -> Arc<Vec<LowerName>> {
        trace!("Loading zone cache");

        let ptr = self.zone_cache.load(Ordering::Relaxed);
        // SAFETY: These methods are safe if performed on *const T acquired by calling
        // Arc::into_raw(), which is always the case here. Furthermore, we guarantee manually that
        // the refcount is correct and accounts for the decrement once the reconstructed Arc gets
        // dropped.
        unsafe {
            // Reconstructing the Arc from a pointer in step 2 does not increment the strong
            // refcount, though it will be decremented once that goes out of scope. Hence, manually
            // increment it first.
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }

    /// Generates a future which continuously loads all know zones and caches them. This removes
    /// previously stored zones.
    fn zone_loader(&self) -> impl Future<Output = ()> {
        let storage = self.storage.clone();
        let zone_cache = self.zone_cache.clone();
        let metrics = self.metrics.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        async move {
            loop {
                interval.tick().await;
                // Create the new zone mapping;
                let zones = match storage.zones().await {
                    Ok(zones) => zones,
                    Err(e) => {
                        error!("Failed to load zones: {}", e);
                        continue;
                    }
                };

                // TODO: properly add and remove zones.
                for zone in &zones {
                    metrics.register_zone(zone.clone());
                }

                info!("Loaded {} zones in zone cache", zones.len());
                let zones = Arc::new(zones);

                // Get the pointer to store
                let ptr = Arc::into_raw(zones) as *mut _;
                let old_ptr = zone_cache.swap(ptr, Ordering::AcqRel);

                // Create the arc from the raw pointer. Don't increment refcount first. This will trigger
                // proper cleanup of the Arc and it's associated data once the last one goes out of scope.
                // SAFETY: this is safe since regular loads of the pointer always increment refcount first,
                // so the pointer is always valid.
                unsafe { Arc::from_raw(old_ptr) };
            }
        }
    }
}
