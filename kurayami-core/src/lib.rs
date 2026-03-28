//! Core types and traits for the kurayami privacy DNS resolver.
//!
//! Provides the foundational abstractions: [`DnsBackend`] for pluggable
//! resolution strategies, [`DnsFilter`] for domain-level content filtering,
//! and the wire types shared across all crates in the workspace.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by kurayami components.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Upstream resolution failed.
    #[error("resolve failed: {0}")]
    ResolveFailed(String),

    /// The selected backend is not reachable.
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Resolution exceeded the configured timeout.
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// The query is malformed or unsupported.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// An I/O error occurred.
    #[error("io: {0}")]
    Io(String),

    /// Configuration error.
    #[error("config: {0}")]
    Config(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl Error {
    /// Whether this error is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ResolveFailed(_)
                | Self::BackendUnavailable(_)
                | Self::Timeout(_)
                | Self::Io(_)
        )
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Query / Response types
// ---------------------------------------------------------------------------

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    SRV,
    PTR,
    NS,
    SOA,
    ANY,
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::SRV => write!(f, "SRV"),
            Self::PTR => write!(f, "PTR"),
            Self::NS => write!(f, "NS"),
            Self::SOA => write!(f, "SOA"),
            Self::ANY => write!(f, "ANY"),
        }
    }
}

/// An incoming DNS query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    /// The domain name being queried.
    pub name: String,
    /// Requested record type.
    pub query_type: QueryType,
    /// The socket address of the client, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_addr: Option<SocketAddr>,
}

/// A complete DNS response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsResponse {
    /// Answer records.
    pub answers: Vec<DnsRecord>,
    /// Whether the response is authoritative.
    pub authoritative: bool,
    /// Whether the response was truncated.
    pub truncated: bool,
}

/// A single DNS resource record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Owner name of the record.
    pub name: String,
    /// Record type.
    pub record_type: QueryType,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Record payload.
    pub data: RecordData,
}

/// Typed record data variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecordData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    AAAA(Ipv6Addr),
    /// Canonical name.
    CNAME(String),
    /// Mail exchange.
    MX {
        /// Priority (lower is preferred).
        priority: u16,
        /// Mail server hostname.
        exchange: String,
    },
    /// Text record.
    TXT(String),
    /// Catch-all for record types without a dedicated variant.
    Other(String),
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            Self::AAAA(addr) => write!(f, "{addr}"),
            Self::CNAME(name) => write!(f, "{name}"),
            Self::MX { priority, exchange } => write!(f, "{priority} {exchange}"),
            Self::TXT(txt) => write!(f, "\"{txt}\""),
            Self::Other(raw) => write!(f, "{raw}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Filter types
// ---------------------------------------------------------------------------

/// The action a filter decides for a given domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow the query to proceed.
    Allow,
    /// Block the query entirely.
    Block,
    /// Redirect the query to the given address.
    Redirect(IpAddr),
}

impl fmt::Display for FilterAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Block => write!(f, "block"),
            Self::Redirect(addr) => write!(f, "redirect({addr})"),
        }
    }
}

// ---------------------------------------------------------------------------
// DNS protocol
// ---------------------------------------------------------------------------

/// DNS transport protocol.
///
/// Covers the spectrum from plain-text UDP/TCP through encrypted transports
/// (DoT, DoH, DoQ, DnsCrypt) to privacy-maximizing protocols (ODoH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    /// Plain UDP (RFC 1035).
    #[default]
    PlainUdp,
    /// Plain TCP (RFC 1035).
    PlainTcp,
    /// DNS over TLS (RFC 7858).
    DoT,
    /// DNS over HTTPS (RFC 8484).
    DoH,
    /// DNS over QUIC (RFC 9250).
    DoQ,
    /// DNSCrypt encrypted protocol.
    DnsCrypt,
    /// Oblivious DNS over HTTPS (RFC 9230).
    ODoH,
}

impl DnsProtocol {
    /// Whether this protocol encrypts DNS traffic in transit.
    ///
    /// Returns `true` for all protocols except `PlainUdp` and `PlainTcp`.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, Self::PlainUdp | Self::PlainTcp)
    }
}

impl fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainUdp => write!(f, "PlainUDP"),
            Self::PlainTcp => write!(f, "PlainTCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::DoQ => write!(f, "DoQ"),
            Self::DnsCrypt => write!(f, "DNSCrypt"),
            Self::ODoH => write!(f, "ODoH"),
        }
    }
}

// ---------------------------------------------------------------------------
// Privacy level
// ---------------------------------------------------------------------------

/// Privacy level for DNS resolution.
///
/// Inspired by dnscrypt-proxy's anonymization tiers: from standard
/// (no special measures) through encrypted transport to fully anonymized
/// relay configurations and maximum-privacy ODoH/Tor routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLevel {
    /// No special privacy measures.
    #[default]
    Standard,
    /// Encrypted transport (DoT/DoH/DoQ).
    Encrypted,
    /// Anonymized relay (identity hidden from resolver).
    Anonymized,
    /// Maximum privacy (ODoH or Tor-routed).
    Maximum,
}

impl fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "Standard"),
            Self::Encrypted => write!(f, "Encrypted"),
            Self::Anonymized => write!(f, "Anonymized"),
            Self::Maximum => write!(f, "Maximum"),
        }
    }
}

// ---------------------------------------------------------------------------
// Cache policy
// ---------------------------------------------------------------------------

/// Declarative cache policy for DNS responses.
///
/// Modelled after hickory-dns caching behaviour with support for negative
/// caching (caching NXDOMAIN / NODATA responses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicy {
    /// Whether caching is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of cached entries.
    #[serde(default = "default_cache_size")]
    pub max_entries: u32,
    /// Minimum TTL in seconds (overrides record TTL if lower).
    #[serde(default = "default_ttl")]
    pub min_ttl_secs: u64,
    /// Maximum TTL in seconds (caps record TTL if higher).
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u64,
    /// Whether to cache negative responses (NXDOMAIN / NODATA).
    #[serde(default)]
    pub negative_cache: bool,
}

fn default_true() -> bool {
    true
}

fn default_cache_size() -> u32 {
    10_000
}

fn default_ttl() -> u64 {
    60
}

fn default_max_ttl() -> u64 {
    86_400
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_entries: default_cache_size(),
            min_ttl_secs: default_ttl(),
            max_ttl_secs: default_max_ttl(),
            negative_cache: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Upstream resolver
// ---------------------------------------------------------------------------

/// Configuration for a single upstream DNS resolver.
///
/// Modelled after dnscrypt-proxy's resolver list with weighted load
/// balancing and optional DNSSEC validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamResolver {
    /// The upstream server address (IP:port or URL depending on protocol).
    pub address: String,
    /// Transport protocol used to reach this resolver.
    pub protocol: DnsProtocol,
    /// Human-readable name for this resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Weight for load-balancing (higher = more traffic).
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Whether to perform DNSSEC validation on responses.
    #[serde(default)]
    pub dnssec_validation: bool,
}

fn default_weight() -> u32 {
    100
}

// ---------------------------------------------------------------------------
// Backend configuration
// ---------------------------------------------------------------------------

/// Declarative configuration for a single DNS backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend identifier (e.g. `"system"`, `"doh"`, `"dot"`, `"tor"`).
    pub backend_type: String,
    /// Upstream server URL or address.
    pub upstream: String,
    /// Backend-specific options.
    pub options: HashMap<String, String>,
}

impl BackendConfig {
    /// Create a new backend configuration.
    #[must_use]
    pub fn new(backend_type: impl Into<String>, upstream: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            upstream: upstream.into(),
            options: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// A pluggable DNS resolution backend.
#[async_trait]
pub trait DnsBackend: Send + Sync {
    /// Resolve a DNS query through this backend.
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse>;

    /// Human-readable name of the backend.
    fn name(&self) -> &str;
}

/// A domain-level filter that decides whether a query should be allowed.
pub trait DnsFilter: Send + Sync {
    /// Return `true` if the domain should be **blocked**.
    fn should_block(&self, domain: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_type_display() {
        assert_eq!(QueryType::A.to_string(), "A");
        assert_eq!(QueryType::AAAA.to_string(), "AAAA");
        assert_eq!(QueryType::CNAME.to_string(), "CNAME");
        assert_eq!(QueryType::MX.to_string(), "MX");
        assert_eq!(QueryType::TXT.to_string(), "TXT");
        assert_eq!(QueryType::SRV.to_string(), "SRV");
        assert_eq!(QueryType::PTR.to_string(), "PTR");
        assert_eq!(QueryType::NS.to_string(), "NS");
        assert_eq!(QueryType::SOA.to_string(), "SOA");
        assert_eq!(QueryType::ANY.to_string(), "ANY");
    }

    #[test]
    fn record_data_display() {
        assert_eq!(
            RecordData::A(Ipv4Addr::new(1, 2, 3, 4)).to_string(),
            "1.2.3.4"
        );
        assert_eq!(RecordData::CNAME("example.com".into()).to_string(), "example.com");
        assert_eq!(
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".into()
            }
            .to_string(),
            "10 mail.example.com"
        );
        assert_eq!(RecordData::TXT("hello".into()).to_string(), "\"hello\"");
        assert_eq!(RecordData::Other("raw".into()).to_string(), "raw");
    }

    #[test]
    fn filter_action_display() {
        assert_eq!(FilterAction::Allow.to_string(), "allow");
        assert_eq!(FilterAction::Block.to_string(), "block");
        assert_eq!(
            FilterAction::Redirect(IpAddr::V4(Ipv4Addr::LOCALHOST)).to_string(),
            "redirect(127.0.0.1)"
        );
    }

    #[test]
    fn error_is_retryable() {
        assert!(Error::ResolveFailed("test".into()).is_retryable());
        assert!(Error::BackendUnavailable("test".into()).is_retryable());
        assert!(Error::Timeout(100).is_retryable());
        assert!(Error::Io("test".into()).is_retryable());
        assert!(!Error::InvalidQuery("test".into()).is_retryable());
        assert!(!Error::Config("test".into()).is_retryable());
    }

    #[test]
    fn error_partial_eq() {
        assert_eq!(
            Error::ResolveFailed("a".into()),
            Error::ResolveFailed("a".into())
        );
        assert_ne!(
            Error::ResolveFailed("a".into()),
            Error::BackendUnavailable("a".into())
        );
    }

    #[test]
    fn backend_config_new() {
        let config = BackendConfig::new("doh", "https://dns.example.com");
        assert_eq!(config.backend_type, "doh");
        assert_eq!(config.upstream, "https://dns.example.com");
        assert!(config.options.is_empty());
    }

    #[test]
    fn dns_query_serde_roundtrip() {
        let query = DnsQuery {
            name: "example.com".into(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let json = serde_json::to_string(&query).unwrap();
        let back: DnsQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, back);
    }

    #[test]
    fn dns_response_serde_roundtrip() {
        let response = DnsResponse {
            answers: vec![DnsRecord {
                name: "example.com".into(),
                record_type: QueryType::A,
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            authoritative: false,
            truncated: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: DnsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, back);
    }

    #[test]
    fn backend_config_serde_roundtrip() {
        let config = BackendConfig::new("system", "localhost");
        let json = serde_json::to_string(&config).unwrap();
        let back: BackendConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn dns_query_skip_none_source_addr() {
        let query = DnsQuery {
            name: "example.com".into(),
            query_type: QueryType::A,
            source_addr: None,
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(!json.contains("source_addr"));
    }

    // -----------------------------------------------------------------------
    // DnsProtocol tests
    // -----------------------------------------------------------------------

    #[test]
    fn dns_protocol_default_is_plain_udp() {
        assert_eq!(DnsProtocol::default(), DnsProtocol::PlainUdp);
    }

    #[test]
    fn dns_protocol_is_encrypted() {
        assert!(!DnsProtocol::PlainUdp.is_encrypted());
        assert!(!DnsProtocol::PlainTcp.is_encrypted());
        assert!(DnsProtocol::DoT.is_encrypted());
        assert!(DnsProtocol::DoH.is_encrypted());
        assert!(DnsProtocol::DoQ.is_encrypted());
        assert!(DnsProtocol::DnsCrypt.is_encrypted());
        assert!(DnsProtocol::ODoH.is_encrypted());
    }

    #[test]
    fn dns_protocol_display() {
        assert_eq!(DnsProtocol::PlainUdp.to_string(), "PlainUDP");
        assert_eq!(DnsProtocol::PlainTcp.to_string(), "PlainTCP");
        assert_eq!(DnsProtocol::DoT.to_string(), "DoT");
        assert_eq!(DnsProtocol::DoH.to_string(), "DoH");
        assert_eq!(DnsProtocol::DoQ.to_string(), "DoQ");
        assert_eq!(DnsProtocol::DnsCrypt.to_string(), "DNSCrypt");
        assert_eq!(DnsProtocol::ODoH.to_string(), "ODoH");
    }

    #[test]
    fn dns_protocol_serde_roundtrip() {
        let protocols = [
            DnsProtocol::PlainUdp,
            DnsProtocol::PlainTcp,
            DnsProtocol::DoT,
            DnsProtocol::DoH,
            DnsProtocol::DoQ,
            DnsProtocol::DnsCrypt,
            DnsProtocol::ODoH,
        ];
        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let back: DnsProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, back);
        }
    }

    #[test]
    fn dns_protocol_hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DnsProtocol::DoH);
        set.insert(DnsProtocol::DoT);
        set.insert(DnsProtocol::DoH); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // PrivacyLevel tests
    // -----------------------------------------------------------------------

    #[test]
    fn privacy_level_default_is_standard() {
        assert_eq!(PrivacyLevel::default(), PrivacyLevel::Standard);
    }

    #[test]
    fn privacy_level_display() {
        assert_eq!(PrivacyLevel::Standard.to_string(), "Standard");
        assert_eq!(PrivacyLevel::Encrypted.to_string(), "Encrypted");
        assert_eq!(PrivacyLevel::Anonymized.to_string(), "Anonymized");
        assert_eq!(PrivacyLevel::Maximum.to_string(), "Maximum");
    }

    #[test]
    fn privacy_level_serde_roundtrip() {
        let levels = [
            PrivacyLevel::Standard,
            PrivacyLevel::Encrypted,
            PrivacyLevel::Anonymized,
            PrivacyLevel::Maximum,
        ];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let back: PrivacyLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn privacy_level_equality() {
        assert_eq!(PrivacyLevel::Maximum, PrivacyLevel::Maximum);
        assert_ne!(PrivacyLevel::Standard, PrivacyLevel::Encrypted);
    }

    // -----------------------------------------------------------------------
    // CachePolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn cache_policy_default() {
        let policy = CachePolicy::default();
        assert!(policy.enabled);
        assert_eq!(policy.max_entries, 10_000);
        assert_eq!(policy.min_ttl_secs, 60);
        assert_eq!(policy.max_ttl_secs, 86_400);
        assert!(!policy.negative_cache);
    }

    #[test]
    fn cache_policy_serde_roundtrip() {
        let policy = CachePolicy {
            enabled: true,
            max_entries: 5000,
            min_ttl_secs: 30,
            max_ttl_secs: 3600,
            negative_cache: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: CachePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn cache_policy_serde_uses_defaults() {
        let json = r#"{}"#;
        let policy: CachePolicy = serde_json::from_str(json).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.max_entries, 10_000);
        assert_eq!(policy.min_ttl_secs, 60);
        assert_eq!(policy.max_ttl_secs, 86_400);
        assert!(!policy.negative_cache);
    }

    // -----------------------------------------------------------------------
    // UpstreamResolver tests
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_resolver_serde_roundtrip() {
        let resolver = UpstreamResolver {
            address: "1.1.1.1:853".into(),
            protocol: DnsProtocol::DoT,
            name: Some("Cloudflare DoT".into()),
            weight: 200,
            dnssec_validation: true,
        };
        let json = serde_json::to_string(&resolver).unwrap();
        let back: UpstreamResolver = serde_json::from_str(&json).unwrap();
        assert_eq!(resolver, back);
    }

    #[test]
    fn upstream_resolver_skip_none_name() {
        let resolver = UpstreamResolver {
            address: "8.8.8.8:53".into(),
            protocol: DnsProtocol::PlainUdp,
            name: None,
            weight: 100,
            dnssec_validation: false,
        };
        let json = serde_json::to_string(&resolver).unwrap();
        assert!(!json.contains("name"));
    }

    #[test]
    fn upstream_resolver_default_weight() {
        let json = r#"{"address":"1.1.1.1:53","protocol":"plain_udp"}"#;
        let resolver: UpstreamResolver = serde_json::from_str(json).unwrap();
        assert_eq!(resolver.weight, 100);
        assert!(!resolver.dnssec_validation);
    }

    #[test]
    fn upstream_resolver_equality() {
        let a = UpstreamResolver {
            address: "1.1.1.1:853".into(),
            protocol: DnsProtocol::DoT,
            name: None,
            weight: 100,
            dnssec_validation: false,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
