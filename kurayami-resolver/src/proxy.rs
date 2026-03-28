//! DNS proxy — local UDP listener that forwards queries through a backend.

use std::net::SocketAddr;

use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, MX, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kurayami_core::{DnsBackend, DnsFilter, DnsQuery, DnsRecord, DnsResponse, QueryType, RecordData, Result};

/// Map a hickory `RecordType` to the kurayami `QueryType`.
#[must_use]
pub fn hickory_to_query_type(rt: RecordType) -> QueryType {
    match rt {
        RecordType::A => QueryType::A,
        RecordType::AAAA => QueryType::AAAA,
        RecordType::CNAME => QueryType::CNAME,
        RecordType::MX => QueryType::MX,
        RecordType::TXT => QueryType::TXT,
        RecordType::NS => QueryType::NS,
        RecordType::SOA => QueryType::SOA,
        RecordType::PTR => QueryType::PTR,
        RecordType::SRV => QueryType::SRV,
        _ => QueryType::ANY,
    }
}

/// Map a kurayami `QueryType` to hickory `RecordType`.
#[must_use]
pub fn query_type_to_hickory(qt: &QueryType) -> RecordType {
    match qt {
        QueryType::A => RecordType::A,
        QueryType::AAAA => RecordType::AAAA,
        QueryType::CNAME => RecordType::CNAME,
        QueryType::MX => RecordType::MX,
        QueryType::TXT => RecordType::TXT,
        QueryType::NS => RecordType::NS,
        QueryType::SOA => RecordType::SOA,
        QueryType::PTR => RecordType::PTR,
        QueryType::SRV => RecordType::SRV,
        QueryType::ANY => RecordType::ANY,
    }
}

/// Build a DNS response message from kurayami records.
#[must_use]
pub fn build_response(request: &Message, dns_response: &DnsResponse) -> Message {
    let mut msg = Message::new();

    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(dns_response.authoritative);
    header.set_truncated(dns_response.truncated);
    header.set_response_code(ResponseCode::NoError);
    msg.set_header(header);

    // Copy the question section from the request.
    for q in request.queries() {
        msg.add_query(q.clone());
    }

    for record in &dns_response.answers {
        if let Some(rr) = dns_record_to_hickory(record) {
            msg.add_answer(rr);
        }
    }

    msg
}

/// Build an NXDOMAIN response for a blocked query.
#[must_use]
pub fn build_nxdomain(request: &Message) -> Message {
    let mut msg = Message::new();

    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::NXDomain);
    header.set_authoritative(false);
    msg.set_header(header);

    for q in request.queries() {
        msg.add_query(q.clone());
    }

    msg
}

/// Convert a kurayami `DnsRecord` to a hickory `Record`.
fn dns_record_to_hickory(record: &DnsRecord) -> Option<Record> {
    let name = Name::from_ascii(&record.name).ok()?;
    let rdata = match &record.data {
        RecordData::A(addr) => RData::A((*addr).into()),
        RecordData::AAAA(addr) => RData::AAAA((*addr).into()),
        RecordData::CNAME(s) => {
            let cname = Name::from_ascii(s).ok()?;
            RData::CNAME(CNAME(cname))
        }
        RecordData::MX { priority, exchange } => {
            let exchange_name = Name::from_ascii(exchange).ok()?;
            RData::MX(MX::new(*priority, exchange_name))
        }
        RecordData::TXT(s) => RData::TXT(TXT::new(vec![s.clone()])),
        RecordData::Other(_) => return None,
    };

    let mut rr = Record::from_rdata(name, record.ttl, rdata);
    rr.set_dns_class(DNSClass::IN);
    Some(rr)
}

/// A local DNS proxy that binds a UDP socket and forwards queries to a
/// configured [`DnsBackend`], applying [`DnsFilter`]s before resolution.
pub struct DnsProxy {
    listen_addr: SocketAddr,
    backend: Box<dyn DnsBackend>,
    filters: Vec<Box<dyn DnsFilter>>,
}

impl DnsProxy {
    /// Create a new proxy with the given listen address and backend.
    pub fn new(listen_addr: SocketAddr, backend: Box<dyn DnsBackend>) -> Self {
        Self {
            listen_addr,
            backend,
            filters: Vec::new(),
        }
    }

    /// Add a domain filter to the proxy.
    pub fn add_filter(&mut self, filter: Box<dyn DnsFilter>) {
        self.filters.push(filter);
    }

    /// Return the configured listen address.
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Return a reference to the backend.
    #[must_use]
    pub fn backend(&self) -> &dyn DnsBackend {
        self.backend.as_ref()
    }

    /// Number of active filters.
    #[must_use]
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }

    /// Check whether any filter blocks the given domain.
    fn is_blocked(&self, domain: &str) -> bool {
        self.filters.iter().any(|f| f.should_block(domain))
    }

    /// Start the proxy event loop.
    ///
    /// Binds a UDP socket on [`Self::listen_addr`] and processes incoming
    /// DNS queries until the task is cancelled.
    pub async fn run(&self) -> Result<()> {
        let socket = tokio::net::UdpSocket::bind(self.listen_addr).await?;
        tracing::info!(
            addr = %self.listen_addr,
            backend = self.backend.name(),
            filters = self.filters.len(),
            "kurayami DNS proxy listening"
        );

        let mut buf = [0u8; 4096];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            tracing::debug!(bytes = len, src = %src, "received UDP packet");

            let request = match Message::from_vec(&buf[..len]) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::warn!(src = %src, error = %e, "failed to parse DNS message");
                    continue;
                }
            };

            // Extract the first question from the DNS message.
            let question = match request.queries().first() {
                Some(q) => q,
                None => {
                    tracing::warn!(src = %src, "DNS message has no questions");
                    continue;
                }
            };

            let domain = question.name().to_ascii();
            let query_type = hickory_to_query_type(question.query_type());

            tracing::debug!(domain = %domain, query_type = ?query_type, "processing query");

            // Check filters — return NXDOMAIN if blocked.
            if self.is_blocked(&domain) {
                tracing::info!(domain = %domain, "blocked by filter");
                let nxdomain = build_nxdomain(&request);
                if let Ok(bytes) = nxdomain.to_vec() {
                    let _ = socket.send_to(&bytes, src).await;
                }
                continue;
            }

            // Forward to backend.
            let query = DnsQuery {
                name: domain.clone(),
                query_type,
                source_addr: Some(src),
            };

            let response_msg = match self.backend.resolve(&query).await {
                Ok(dns_response) => build_response(&request, &dns_response),
                Err(e) => {
                    tracing::warn!(domain = %domain, error = %e, "backend resolve failed");
                    // Return SERVFAIL on backend error.
                    let mut msg = Message::new();
                    let mut header = Header::response_from_request(request.header());
                    header.set_response_code(ResponseCode::ServFail);
                    msg.set_header(header);
                    for q in request.queries() {
                        msg.add_query(q.clone());
                    }
                    msg
                }
            };

            match response_msg.to_vec() {
                Ok(bytes) => {
                    let _ = socket.send_to(&bytes, src).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize DNS response");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::system::SystemBackend;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use kurayami_core::{DnsRecord, DnsResponse, RecordData};

    fn default_addr() -> SocketAddr {
        "127.0.0.1:5353".parse().unwrap()
    }

    #[test]
    fn creates_proxy() {
        let proxy = DnsProxy::new(default_addr(), Box::new(SystemBackend::new()));
        assert_eq!(proxy.listen_addr(), default_addr());
        assert_eq!(proxy.backend().name(), "system");
        assert_eq!(proxy.filter_count(), 0);
    }

    #[test]
    fn default_listen_addr() {
        let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let proxy = DnsProxy::new(addr, Box::new(SystemBackend::new()));
        assert_eq!(proxy.listen_addr().port(), 5353);
    }

    #[test]
    fn add_filter_increments_count() {
        let mut proxy = DnsProxy::new(default_addr(), Box::new(SystemBackend::new()));
        let filter = crate::filter::BlocklistFilter::new(["ads.com"]);
        proxy.add_filter(Box::new(filter));
        assert_eq!(proxy.filter_count(), 1);
    }

    /// Build a minimal DNS query message for testing.
    fn make_dns_query_message(domain: &str, record_type: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);

        let name = Name::from_ascii(domain).unwrap();
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(record_type);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);

        msg
    }

    #[test]
    fn parse_dns_query_message() {
        let msg = make_dns_query_message("example.com.", RecordType::A);
        let bytes = msg.to_vec().unwrap();

        // Parse it back from wire format.
        let parsed = Message::from_vec(&bytes).unwrap();
        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.message_type(), MessageType::Query);
        assert_eq!(parsed.queries().len(), 1);

        let q = &parsed.queries()[0];
        assert_eq!(q.name().to_ascii(), "example.com.");
        assert_eq!(q.query_type(), RecordType::A);
    }

    #[test]
    fn build_nxdomain_response() {
        let request = make_dns_query_message("blocked.com.", RecordType::A);
        let nxdomain = build_nxdomain(&request);

        assert_eq!(nxdomain.id(), request.id());
        assert_eq!(nxdomain.message_type(), MessageType::Response);
        assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
        assert!(nxdomain.answers().is_empty());
        assert_eq!(nxdomain.queries().len(), 1);
    }

    #[test]
    fn hickory_type_mapping() {
        // Round-trip: hickory -> kurayami -> hickory
        let types = [
            (RecordType::A, QueryType::A),
            (RecordType::AAAA, QueryType::AAAA),
            (RecordType::CNAME, QueryType::CNAME),
            (RecordType::MX, QueryType::MX),
            (RecordType::TXT, QueryType::TXT),
            (RecordType::NS, QueryType::NS),
            (RecordType::SOA, QueryType::SOA),
            (RecordType::PTR, QueryType::PTR),
            (RecordType::SRV, QueryType::SRV),
        ];

        for (hickory_type, expected_qt) in types {
            let qt = hickory_to_query_type(hickory_type);
            assert_eq!(qt, expected_qt, "hickory_to_query_type failed for {hickory_type:?}");

            let rt = query_type_to_hickory(&qt);
            assert_eq!(rt, hickory_type, "query_type_to_hickory failed for {qt:?}");
        }
    }

    #[test]
    fn build_response_with_a_record() {
        let request = make_dns_query_message("example.com.", RecordType::A);
        let dns_response = DnsResponse {
            answers: vec![DnsRecord {
                name: "example.com.".to_string(),
                record_type: QueryType::A,
                ttl: 300,
                data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
            }],
            authoritative: false,
            truncated: false,
        };

        let response = build_response(&request, &dns_response);
        assert_eq!(response.id(), request.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let answer = &response.answers()[0];
        assert_eq!(answer.record_type(), RecordType::A);
        assert_eq!(answer.ttl(), 300);
    }

    #[test]
    fn build_response_roundtrip_wire_format() {
        let request = make_dns_query_message("example.com.", RecordType::A);
        let dns_response = DnsResponse {
            answers: vec![DnsRecord {
                name: "example.com.".to_string(),
                record_type: QueryType::A,
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(127, 0, 0, 1)),
            }],
            authoritative: false,
            truncated: false,
        };

        let response = build_response(&request, &dns_response);
        let bytes = response.to_vec().unwrap();
        let parsed = Message::from_vec(&bytes).unwrap();

        assert_eq!(parsed.id(), request.id());
        assert_eq!(parsed.answers().len(), 1);
    }
}
