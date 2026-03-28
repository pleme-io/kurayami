//! DNS-over-HTTPS (DoH) backend — resolves via the Cloudflare JSON DNS API.
//!
//! Makes HTTPS GET requests to a DoH-compatible resolver using the JSON wire
//! format (`application/dns-json`). The default upstream is Cloudflare's
//! `1.1.1.1` resolver.

use async_trait::async_trait;
use kurayami_core::{
    DnsBackend, DnsQuery, DnsRecord, DnsResponse, Error, QueryType, RecordData, Result,
};
use serde::Deserialize;

/// Default upstream for Cloudflare DoH (JSON API).
pub const DEFAULT_DOH_UPSTREAM: &str = "https://cloudflare-dns.com/dns-query";

/// DNS-over-HTTPS backend using the JSON wire format.
#[derive(Debug, Clone)]
pub struct DohBackend {
    /// The DoH endpoint URL.
    upstream: String,
    /// HTTP client (connection pooled).
    client: reqwest::Client,
}

impl DohBackend {
    /// Create a new DoH backend targeting the given upstream URL.
    #[must_use]
    pub fn new(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
            client: reqwest::Client::new(),
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

/// Map a numeric DNS type back to our `QueryType`.
fn number_to_query_type(n: u16) -> QueryType {
    match n {
        1 => QueryType::A,
        28 => QueryType::AAAA,
        5 => QueryType::CNAME,
        15 => QueryType::MX,
        16 => QueryType::TXT,
        33 => QueryType::SRV,
        12 => QueryType::PTR,
        2 => QueryType::NS,
        6 => QueryType::SOA,
        _ => QueryType::ANY,
    }
}

/// Query type string for the DoH JSON API `type` parameter.
fn query_type_to_str(qt: QueryType) -> &'static str {
    match qt {
        QueryType::A => "A",
        QueryType::AAAA => "AAAA",
        QueryType::CNAME => "CNAME",
        QueryType::MX => "MX",
        QueryType::TXT => "TXT",
        QueryType::SRV => "SRV",
        QueryType::PTR => "PTR",
        QueryType::NS => "NS",
        QueryType::SOA => "SOA",
        QueryType::ANY => "ANY",
    }
}

// ---- JSON response structures from Cloudflare DoH API ----

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

/// Parse the `data` field from a DoH JSON answer into our [`RecordData`].
fn parse_record_data(record_type: u16, data: &str) -> RecordData {
    match record_type {
        // A record
        1 => data
            .parse()
            .map(RecordData::A)
            .unwrap_or_else(|_| RecordData::Other(data.to_string())),
        // AAAA record
        28 => data
            .parse()
            .map(RecordData::AAAA)
            .unwrap_or_else(|_| RecordData::Other(data.to_string())),
        // CNAME record
        5 => RecordData::CNAME(data.to_string()),
        // TXT record — Cloudflare wraps in quotes
        16 => RecordData::TXT(data.trim_matches('"').to_string()),
        // MX record — "priority exchange"
        15 => {
            let parts: Vec<&str> = data.splitn(2, ' ').collect();
            if parts.len() == 2 {
                if let Ok(priority) = parts[0].parse::<u16>() {
                    return RecordData::MX {
                        priority,
                        exchange: parts[1].to_string(),
                    };
                }
            }
            RecordData::Other(data.to_string())
        }
        _ => RecordData::Other(data.to_string()),
    }
}

#[async_trait]
impl DnsBackend for DohBackend {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
        let type_str = query_type_to_str(query.query_type);

        let response = self
            .client
            .get(&self.upstream)
            .header("Accept", "application/dns-json")
            .query(&[("name", query.name.as_str()), ("type", type_str)])
            .send()
            .await
            .map_err(|e| Error::BackendUnavailable(format!("DoH request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::ResolveFailed(format!(
                "DoH upstream returned HTTP {}",
                response.status()
            )));
        }

        let json: DohJsonResponse = response
            .json()
            .await
            .map_err(|e| Error::ResolveFailed(format!("DoH JSON parse error: {e}")))?;

        let answers = json
            .answer
            .into_iter()
            .map(|a| DnsRecord {
                name: a.name,
                record_type: number_to_query_type(a.record_type),
                ttl: a.ttl,
                data: parse_record_data(a.record_type, &a.data),
            })
            .collect();

        Ok(DnsResponse {
            answers,
            authoritative: false,
            truncated: false,
        })
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

    #[test]
    fn number_to_query_type_mapping() {
        assert_eq!(number_to_query_type(1), QueryType::A);
        assert_eq!(number_to_query_type(28), QueryType::AAAA);
        assert_eq!(number_to_query_type(5), QueryType::CNAME);
        assert_eq!(number_to_query_type(15), QueryType::MX);
        assert_eq!(number_to_query_type(16), QueryType::TXT);
    }

    #[test]
    fn parse_a_record() {
        let data = parse_record_data(1, "93.184.216.34");
        assert!(matches!(data, RecordData::A(addr) if addr.to_string() == "93.184.216.34"));
    }

    #[test]
    fn parse_aaaa_record() {
        let data = parse_record_data(28, "2606:2800:220:1:248:1893:25c8:1946");
        assert!(matches!(data, RecordData::AAAA(_)));
    }

    #[test]
    fn parse_cname_record() {
        let data = parse_record_data(5, "www.example.com.");
        assert!(matches!(data, RecordData::CNAME(ref s) if s == "www.example.com."));
    }

    #[test]
    fn parse_mx_record() {
        let data = parse_record_data(15, "10 mail.example.com.");
        assert!(
            matches!(data, RecordData::MX { priority, ref exchange } if priority == 10 && exchange == "mail.example.com.")
        );
    }

    #[test]
    fn parse_txt_record() {
        let data = parse_record_data(16, "\"v=spf1 include:example.com ~all\"");
        assert!(
            matches!(data, RecordData::TXT(ref s) if s == "v=spf1 include:example.com ~all")
        );
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolves_a_record_via_cloudflare() {
        let backend = DohBackend::default();
        let query = DnsQuery {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let response = backend.resolve(&query).await.unwrap();
        assert!(!response.answers.is_empty());
    }
}
