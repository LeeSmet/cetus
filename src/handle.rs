use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
};

use log::{debug, error, info, trace, warn};
use trust_dns_proto::rr::{rdata::SOA, DNSClass};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::{
        op::{LowerQuery, MessageType, OpCode, ResponseCode},
        rr::{LowerName, Name, RData},
    },
    server::{RequestHandler, ResponseInfo},
};

use crate::storage::Storage;

/// We don't expect frequent updates of the Zone list, so use an [AtomicPtr] here. The idea is that
/// we will create a new [Arc] if there is a new list, and an atomic operation is used to swap the
/// old list with the new list. Note that the [Arc] is not part of the type signature, for more
/// info see [Arc::into_raw] and [Arc::from_raw].
// TODO: vetting
type ZoneCache = AtomicPtr<HashMap<LowerName, SOA>>;

pub struct DnsHandler<S> {
    // list of all known zones, this allows us to verify if we are an authority without hitting the
    // database.
    zone_list: ZoneCache,
    storage: S,
}

impl<S> DnsHandler<S> {
    /// Create a new DNS handler with the given [`Storage`].
    pub fn new(storage: S) -> Self {
        let zones = Arc::new(HashMap::<LowerName, SOA>::new());
        let zone_list = AtomicPtr::new(Arc::into_raw(zones) as *mut _);
        DnsHandler { zone_list, storage }
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
    /// 3. Look up the record(s) in the database.
    ///
    /// The response is then attempted to be served to the client.
    async fn query<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        mut response_handle: R,
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
        let zone = self.query_zone(query);
        if zone.is_none() {
            // We aren't an authority for this query, therefore it is refused.
            return self
                .reply_error(request, response_handle, ResponseCode::Refused)
                .await;
        }
        // unwrap is safe as we just checked the none case and returned.
        let (zone_name, soa) = zone.unwrap();

        // Now get potential records
        trace!(
            "Fetching records for {} {}",
            query.name(),
            query.query_type()
        );
        let mut records = match self
            .storage
            .lookup_records(query.name(), &zone_name, query.query_type())
            .await
        {
            Err(e) => {
                error!(
                    "Failed to fetch records for {} of type {}: {}",
                    query.name(),
                    query.query_type(),
                    e
                );
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

        let soa_records = if records.is_none() {
            // this unwrap is safe because we already checked that zone is not none.
            let soa_rdata = RData::SOA(soa);
            vec![trust_dns_server::proto::rr::Record::from_rdata(
                Name::from(zone_name),
                // TODO: SOA TTL
                300,
                soa_rdata,
            )]
        } else {
            vec![]
        };

        // TODO: lifetime workaround;
        let mut empty_vec = vec![];
        let msg = response_builder.build(
            header,
            if let Some(ref mut records) = records {
                records
            } else {
                &mut empty_vec
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
            &soa_records,
            [],
        );

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
    fn query_zone(&self, query: &LowerQuery) -> Option<(LowerName, SOA)> {
        let name = query.name();
        let zones = self.zone_list();
        trace!("zone cache ref count {}", Arc::strong_count(&zones));
        for (zone, soa) in zones.iter() {
            if zone.zone_of(name) {
                debug!("query {} in known zone {}", name, zone);
                return Some((zone.clone(), soa.clone()));
            }
        }
        None
    }

    /// Get the current zone list.
    fn zone_list(&self) -> Arc<HashMap<LowerName, SOA>> {
        trace!("Loading zone cache");

        let ptr = self.zone_list.load(Ordering::Relaxed);
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

    /// Load all known zones from storage and cache them. This removes previously stored zones.
    pub async fn load_zones(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create the new zone mapping;
        let zones = self.storage.zones().await?;
        let mut zone_map = HashMap::new();
        for (zone, soa) in zones {
            zone_map.insert(zone, soa);
        }
        info!("Loaded {} zones in zone cache", zone_map.len());
        let zone_map = Arc::new(zone_map);
        // Get the pointer to store
        let ptr = Arc::into_raw(zone_map) as *mut _;
        let old_ptr = self.zone_list.swap(ptr, Ordering::AcqRel);

        // Create the arc from the raw pointer. Don't increment refcount first. This will trigger
        // proper cleanup of the Arc and it's associated data once the last one goes out of scope.
        // SAFETY: this is safe since regular loads of the pointer always increment refcount first,
        // so the pointer is always valid.
        unsafe { Arc::from_raw(old_ptr) };

        Ok(())
    }
}
