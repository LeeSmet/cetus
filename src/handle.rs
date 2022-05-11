use trust_dns_server::{client::op::OpCode, server::RequestHandler};

pub struct DNS {}

impl DNS {
    pub fn new() -> Self {
        DNS {}
    }
}

#[async_trait::async_trait]
impl RequestHandler for DNS {
    async fn handle_request<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        response_handle: R,
    ) -> trust_dns_server::server::ResponseInfo {
        log::warn!("request EDNS: {:?}", request.edns());
        match request.op_code() {
            OpCode::Query => unimplemented!(),
            OpCode::Status => unimplemented!(),
            OpCode::Notify => unimplemented!(),
            OpCode::Update => unimplemented!(),
        };
        unimplemented!();
    }
}
