//! System DNS backend — resolves via the OS resolver (`tokio::net::lookup_host`).

use async_trait::async_trait;
use kurayami_core::{DnsBackend, DnsQuery, DnsRecord, DnsResponse, Error, QueryType, RecordData, Result};

/// Backend that delegates to the operating system's built-in resolver.
#[derive(Debug, Default)]
pub struct SystemBackend;

impl SystemBackend {
    /// Create a new system backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DnsBackend for SystemBackend {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
        let lookup_addr = format!("{}:0", query.name);

        let addrs = tokio::net::lookup_host(&lookup_addr)
            .await
            .map_err(|e| Error::ResolveFailed(format!("{}: {e}", query.name)))?;

        let mut answers = Vec::new();

        for addr in addrs {
            let record = match (query.query_type, addr.ip()) {
                (QueryType::A, std::net::IpAddr::V4(v4)) | (QueryType::ANY, std::net::IpAddr::V4(v4)) => {
                    Some(DnsRecord {
                        name: query.name.clone(),
                        record_type: QueryType::A,
                        ttl: 60,
                        data: RecordData::A(v4),
                    })
                }
                (QueryType::AAAA, std::net::IpAddr::V6(v6)) | (QueryType::ANY, std::net::IpAddr::V6(v6)) => {
                    Some(DnsRecord {
                        name: query.name.clone(),
                        record_type: QueryType::AAAA,
                        ttl: 60,
                        data: RecordData::AAAA(v6),
                    })
                }
                _ => None,
            };

            if let Some(r) = record {
                answers.push(r);
            }
        }

        Ok(DnsResponse {
            answers,
            authoritative: false,
            truncated: false,
        })
    }

    fn name(&self) -> &str {
        "system"
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn name_is_system() {
        let backend = SystemBackend::new();
        assert_eq!(backend.name(), "system");
    }

    #[tokio::test]
    async fn resolves_localhost() {
        let backend = SystemBackend::new();
        let query = DnsQuery {
            name: "localhost".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };

        let response = backend.resolve(&query).await;
        assert!(response.is_ok());

        let resp = response.unwrap();
        // localhost should resolve to 127.0.0.1 on every platform
        let has_loopback = resp.answers.iter().any(|r| {
            matches!(&r.data, RecordData::A(addr) if *addr == Ipv4Addr::LOCALHOST)
        });
        assert!(has_loopback, "expected 127.0.0.1 in answers: {resp:?}");
    }

    #[tokio::test]
    async fn handles_invalid_domain() {
        let backend = SystemBackend::new();
        let query = DnsQuery {
            name: "this.domain.definitely.does.not.exist.invalid".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };

        let result = backend.resolve(&query).await;
        assert!(result.is_err());
    }

    #[test]
    fn default_creates_backend() {
        let _backend = SystemBackend::default();
    }
}
