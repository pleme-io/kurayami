//! Core types and traits for the kurayami privacy DNS resolver.
//!
//! Provides the foundational abstractions: [`DnsBackend`] for pluggable
//! resolution strategies, [`DnsFilter`] for domain-level content filtering,
//! and the wire types shared across all crates in the workspace.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by kurayami components.
#[derive(Debug, thiserror::Error)]
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
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("config: {0}")]
    Config(String),
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

/// An incoming DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// The domain name being queried.
    pub name: String,
    /// Requested record type.
    pub query_type: QueryType,
    /// The socket address of the client, if known.
    pub source_addr: Option<SocketAddr>,
}

/// A complete DNS response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    /// Answer records.
    pub answers: Vec<DnsRecord>,
    /// Whether the response is authoritative.
    pub authoritative: bool,
    /// Whether the response was truncated.
    pub truncated: bool,
}

/// A single DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// Backend configuration
// ---------------------------------------------------------------------------

/// Declarative configuration for a single DNS backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend identifier (e.g. `"system"`, `"doh"`, `"dot"`, `"tor"`).
    pub backend_type: String,
    /// Upstream server URL or address.
    pub upstream: String,
    /// Backend-specific options.
    pub options: HashMap<String, String>,
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
