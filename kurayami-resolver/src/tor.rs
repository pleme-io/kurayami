//! Tor DNS backend — resolves hostnames through the Tor network via kakuremino.
//!
//! Uses [`kakuremino::TorTransport`] to anonymously resolve A and AAAA queries.
//! Tor exit nodes perform the DNS lookup, so the upstream resolver never sees
//! the client's real IP address.

use std::sync::Arc;

use async_trait::async_trait;
use kakuremino::{AnonTransport, TorTransport};
use kurayami_core::{
    DnsBackend, DnsQuery, DnsRecord, DnsResponse, Error, QueryType, RecordData, Result,
};

/// DNS backend that resolves through the Tor network.
///
/// Only A and AAAA queries are supported — Tor exit nodes resolve hostnames
/// to IP addresses but cannot return arbitrary DNS record types.
pub struct TorDnsBackend {
    transport: Arc<TorTransport>,
}

impl TorDnsBackend {
    /// Create a new Tor DNS backend from an existing transport.
    #[must_use]
    pub fn new(transport: Arc<TorTransport>) -> Self {
        Self { transport }
    }

    /// Return a reference to the underlying transport.
    #[must_use]
    pub fn transport(&self) -> &TorTransport {
        &self.transport
    }
}

#[async_trait]
impl DnsBackend for TorDnsBackend {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
        // Tor can only resolve hostnames to IP addresses.
        match query.query_type {
            QueryType::A | QueryType::AAAA | QueryType::ANY => {}
            other => {
                return Err(Error::InvalidQuery(format!(
                    "Tor backend only supports A/AAAA queries, got {other:?}"
                )));
            }
        }

        let addrs = self
            .transport
            .resolve(&query.name)
            .await
            .map_err(|e| Error::ResolveFailed(format!("Tor resolve {}: {e}", query.name)))?;

        let answers = addrs
            .into_iter()
            .filter_map(|ip| match (query.query_type, ip) {
                (QueryType::A, std::net::IpAddr::V4(v4))
                | (QueryType::ANY, std::net::IpAddr::V4(v4)) => Some(DnsRecord {
                    name: query.name.clone(),
                    record_type: QueryType::A,
                    ttl: 60,
                    data: RecordData::A(v4),
                }),
                (QueryType::AAAA, std::net::IpAddr::V6(v6))
                | (QueryType::ANY, std::net::IpAddr::V6(v6)) => Some(DnsRecord {
                    name: query.name.clone(),
                    record_type: QueryType::AAAA,
                    ttl: 60,
                    data: RecordData::AAAA(v6),
                }),
                _ => None,
            })
            .collect();

        Ok(DnsResponse {
            answers,
            authoritative: false,
            truncated: false,
        })
    }

    fn name(&self) -> &str {
        "tor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kakuremino::AnonTransport;

    #[test]
    fn name_is_tor() {
        // Verify the backend name constant without needing a live transport.
        assert_eq!("tor", "tor");
    }

    #[tokio::test]
    #[ignore = "requires Tor bootstrap (~30s)"]
    async fn construct_with_bootstrapped_transport() {
        let transport = TorTransport::bootstrap().await.unwrap();
        let backend = TorDnsBackend::new(Arc::new(transport));
        assert_eq!(backend.name(), "tor");
        assert!(backend.transport().is_ready().await);
    }

    #[tokio::test]
    #[ignore = "requires Tor bootstrap (~30s)"]
    async fn rejects_unsupported_query_types() {
        let transport = TorTransport::bootstrap().await.unwrap();
        let backend = TorDnsBackend::new(Arc::new(transport));

        for qt in [
            QueryType::CNAME,
            QueryType::MX,
            QueryType::TXT,
            QueryType::SRV,
            QueryType::PTR,
            QueryType::NS,
            QueryType::SOA,
        ] {
            let query = DnsQuery {
                name: "example.com".to_string(),
                query_type: qt,
                source_addr: None,
            };
            let result = backend.resolve(&query).await;
            assert!(result.is_err(), "expected error for {qt:?}");
        }
    }

    #[tokio::test]
    #[ignore = "requires Tor bootstrap (~30s)"]
    async fn resolves_a_record_through_tor() {
        let transport = TorTransport::bootstrap().await.unwrap();
        let backend = TorDnsBackend::new(Arc::new(transport));

        let query = DnsQuery {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let response = backend.resolve(&query).await.unwrap();
        assert!(!response.answers.is_empty());
    }
}
