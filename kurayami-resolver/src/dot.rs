//! DNS-over-TLS (DoT) backend — resolves via an encrypted TLS connection.
//!
//! Uses `hickory-resolver` with the `tls-ring` feature to connect
//! to a DoT-capable upstream resolver on port 853.

use std::net::{Ipv4Addr, SocketAddr};

use async_trait::async_trait;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use kurayami_core::{
    DnsBackend, DnsQuery, DnsRecord, DnsResponse, Error, QueryType, RecordData, Result,
};

/// DNS-over-TLS backend.
#[derive(Debug)]
pub struct DotBackend {
    server_addr: SocketAddr,
    tls_name: String,
}

impl DotBackend {
    /// Create a new DoT backend targeting the given server.
    #[must_use]
    pub fn new(server_addr: SocketAddr, tls_name: String) -> Self {
        Self {
            server_addr,
            tls_name,
        }
    }

    /// Pre-configured Cloudflare DoT backend (`1.1.1.1:853`).
    #[must_use]
    pub fn cloudflare() -> Self {
        Self::new(
            SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 853),
            "cloudflare-dns.com".to_string(),
        )
    }

    /// Pre-configured Google DoT backend (`8.8.8.8:853`).
    #[must_use]
    pub fn google() -> Self {
        Self::new(
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 853),
            "dns.google".to_string(),
        )
    }

    /// Return the configured server address.
    #[must_use]
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Return the TLS server name.
    #[must_use]
    pub fn tls_name(&self) -> &str {
        &self.tls_name
    }

    /// Build a hickory resolver configured for DoT to our server.
    fn build_resolver(&self) -> TokioResolver {
        let mut ns = NameServerConfig::new(self.server_addr, Protocol::Tls);
        ns.tls_dns_name = Some(self.tls_name.clone());

        let mut config = ResolverConfig::new();
        config.add_name_server(ns);

        let builder = TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        );

        builder.build()
    }
}

/// Map a hickory `RecordType` to kurayami `QueryType`.
fn hickory_to_query_type(rt: hickory_proto::rr::RecordType) -> QueryType {
    match rt {
        hickory_proto::rr::RecordType::A => QueryType::A,
        hickory_proto::rr::RecordType::AAAA => QueryType::AAAA,
        hickory_proto::rr::RecordType::CNAME => QueryType::CNAME,
        hickory_proto::rr::RecordType::MX => QueryType::MX,
        hickory_proto::rr::RecordType::TXT => QueryType::TXT,
        hickory_proto::rr::RecordType::NS => QueryType::NS,
        hickory_proto::rr::RecordType::SOA => QueryType::SOA,
        hickory_proto::rr::RecordType::PTR => QueryType::PTR,
        hickory_proto::rr::RecordType::SRV => QueryType::SRV,
        _ => QueryType::ANY,
    }
}

/// Convert a hickory `RData` to kurayami `RecordData`.
fn rdata_to_record_data(rdata: &hickory_proto::rr::RData) -> RecordData {
    use hickory_proto::rr::RData;
    match rdata {
        RData::A(a) => RecordData::A((*a).into()),
        RData::AAAA(aaaa) => RecordData::AAAA((*aaaa).into()),
        RData::CNAME(cname) => RecordData::CNAME(cname.0.to_ascii()),
        RData::MX(mx) => RecordData::MX {
            priority: mx.preference(),
            exchange: mx.exchange().to_ascii(),
        },
        RData::TXT(txt) => {
            let joined: String = txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join("");
            RecordData::TXT(joined)
        }
        other => RecordData::Other(format!("{other:?}")),
    }
}

#[async_trait]
impl DnsBackend for DotBackend {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
        let resolver = self.build_resolver();
        let name = &query.name;

        let lookup = resolver
            .lookup(
                name.as_str(),
                crate::proxy::query_type_to_hickory(&query.query_type),
            )
            .await
            .map_err(|e| Error::ResolveFailed(format!("DoT resolve {name}: {e}")))?;

        let answers = lookup
            .record_iter()
            .map(|r| DnsRecord {
                name: r.name().to_ascii(),
                record_type: hickory_to_query_type(r.record_type()),
                ttl: r.ttl(),
                data: rdata_to_record_data(r.data()),
            })
            .collect();

        Ok(DnsResponse {
            answers,
            authoritative: false,
            truncated: false,
        })
    }

    fn name(&self) -> &str {
        "dot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_dot() {
        let backend = DotBackend::cloudflare();
        assert_eq!(backend.name(), "dot");
    }

    #[test]
    fn config_cloudflare() {
        let backend = DotBackend::cloudflare();
        assert_eq!(backend.server_addr().port(), 853);
        assert_eq!(
            backend.server_addr().ip(),
            Ipv4Addr::new(1, 1, 1, 1)
        );
        assert_eq!(backend.tls_name(), "cloudflare-dns.com");
    }

    #[test]
    fn config_google() {
        let backend = DotBackend::google();
        assert_eq!(backend.server_addr().port(), 853);
        assert_eq!(
            backend.server_addr().ip(),
            Ipv4Addr::new(8, 8, 8, 8)
        );
        assert_eq!(backend.tls_name(), "dns.google");
    }

    #[test]
    fn custom_config() {
        let addr: SocketAddr = "9.9.9.9:853".parse().unwrap();
        let backend = DotBackend::new(addr, "dns.quad9.net".to_string());
        assert_eq!(backend.server_addr(), addr);
        assert_eq!(backend.tls_name(), "dns.quad9.net");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_a_record_via_cloudflare_dot() {
        let backend = DotBackend::cloudflare();
        let query = DnsQuery {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let response = backend.resolve(&query).await.unwrap();
        assert!(!response.answers.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_a_record_via_google_dot() {
        let backend = DotBackend::google();
        let query = DnsQuery {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let response = backend.resolve(&query).await.unwrap();
        assert!(!response.answers.is_empty());
    }
}
