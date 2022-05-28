use std::{
    mem,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
};

use log::warn;
use trust_dns_server::{
    authority::{MessageResponse, MessageResponseBuilder},
    client::{
        op::{MessageType, OpCode, ResponseCode},
        rr::LowerName,
    },
    server::{RequestHandler, ResponseInfo},
};

use crate::storage::Storage;

/// We don't expect frequent updates of the Zone list, so use an [AtomicPtr] here. The idea is that
/// we will create a new [Arc] if there is a new list, and an atomic operation is used to swap the
/// old list with the new list.
type ZoneCache = AtomicPtr<Arc<Vec<LowerName>>>;

pub struct DNS<S> {
    // list of all known zones, this allows us to verify if we are an authority without hitting the
    // database.
    zone_list: ZoneCache,
    storage: S,
}

impl<S> DNS<S> {
    pub fn new(storage: S) -> Self {
        let mut zones = Arc::new(Vec::<LowerName>::new());
        let zone_list = AtomicPtr::new(&mut zones as *mut _);
        DNS { zone_list, storage }
    }
}

#[async_trait::async_trait]
impl<S> RequestHandler for DNS<S>
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
                return self.reply_not_implemented(request, response_handle).await;
            }
        };

        match request.op_code() {
            OpCode::Query => self.query(request, response_handle).await,
            // TODO: proper not impl
            OpCode::Status | OpCode::Notify | OpCode::Update => unimplemented!(),
        }
    }
}

impl<S> DNS<S>
where
    S: Storage + Send + Sync + Unpin,
{
    /// Handle a request query. This function does the following:
    ///
    /// 1. Check the zone cache to see if the request is a (child of) a known zone, if it is not
    ///    outright reject the query.
    /// 2. Look up the record(s) in the database.
    ///
    /// The response is then attempted to be served to the client.
    async fn query<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        response_handle: R,
    ) -> ResponseInfo {
        unimplemented!()
    }

    /// Send a generic "Not Implemented" response. If sending the response fails, a new
    /// [ResponseInfo] object is created from a clone of the request header.
    async fn reply_not_implemented<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let response_builder = MessageResponseBuilder::from_message_request(request);
        let msg = response_builder.error_msg(request.header(), ResponseCode::NotImp);
        return match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(ioe) => {
                warn!(
                    "Failed to send reply to message with response type: {}",
                    ioe
                );
                ResponseInfo::from(request.header().clone())
            }
        };
    }

    /// Get the current zone list.
    fn zone_list(&self) -> Arc<Vec<LowerName>> {
        // TODO: vet
        // let base = unsafe { &*(self.zone_list.load(Ordering::Relaxed)) };
        // let copy = base.clone();
        // mem::forget(base);
        // copy
        unsafe { &*(self.zone_list.load(Ordering::Relaxed)) }.clone()
    }
}
