//! DNS-over-HTTPS (DoH) backend — stub implementation.
//!
//! The structure is in place for a full DoH client that constructs wireformat
//! DNS queries and sends them via HTTPS POST to a compliant resolver.

use async_trait::async_trait;
use kurayami_core::{DnsBackend, DnsQuery, DnsResponse, Error, Result};

/// Default upstream for Cloudflare DoH.
pub const DEFAULT_DOH_UPSTREAM: &str = "https://cloudflare-dns.com/dns-query";

/// DNS-over-HTTPS backend.
#[derive(Debug, Clone)]
pub struct DohBackend {
    /// The DoH endpoint URL.
    upstream: String,
}

impl DohBackend {
    /// Create a new DoH backend targeting the given upstream URL.
    #[must_use]
    pub fn new(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
        }
    }

    /// Return the configured upstream URL.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
}

impl Default for DohBackend {
    fn default() -> Self {
        Self::new(DEFAULT_DOH_UPSTREAM)
    }
}

#[async_trait]
impl DnsBackend for DohBackend {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResponse> {
        // TODO: construct wireformat DNS query, POST to upstream, parse response
        Err(Error::BackendUnavailable(format!(
            "DoH backend ({}) not yet implemented",
            self.upstream
        )))
    }

    fn name(&self) -> &str {
        "doh"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_doh() {
        let backend = DohBackend::default();
        assert_eq!(backend.name(), "doh");
    }

    #[test]
    fn default_upstream() {
        let backend = DohBackend::default();
        assert_eq!(backend.upstream(), DEFAULT_DOH_UPSTREAM);
    }

    #[test]
    fn custom_upstream() {
        let backend = DohBackend::new("https://dns.google/dns-query");
        assert_eq!(backend.upstream(), "https://dns.google/dns-query");
    }

    #[tokio::test]
    async fn resolve_returns_not_implemented() {
        let backend = DohBackend::default();
        let query = kurayami_core::DnsQuery {
            name: "example.com".to_string(),
            query_type: kurayami_core::QueryType::A,
            source_addr: None,
        };
        let result = backend.resolve(&query).await;
        assert!(result.is_err());
    }
}
