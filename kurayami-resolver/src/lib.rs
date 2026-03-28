//! DNS backends and filters for the kurayami privacy DNS resolver.
//!
//! This crate provides concrete implementations of [`kurayami_core::DnsBackend`]
//! and [`kurayami_core::DnsFilter`], plus the [`DnsProxy`](proxy::DnsProxy)
//! that wires them together as a local DNS listener.

pub mod cache;
pub mod doh;
pub mod dot;
pub mod filter;
pub mod proxy;
pub mod system;
pub mod tor;

pub use cache::{CachedBackend, DnsCache};
pub use doh::DohBackend;
pub use dot::DotBackend;
pub use filter::{BlocklistFilter, CompositeFilter, RegexFilter};
pub use proxy::DnsProxy;
pub use system::SystemBackend;
pub use tor::TorDnsBackend;
