//! DNS backends and filters for the kurayami privacy DNS resolver.
//!
//! This crate provides concrete implementations of [`kurayami_core::DnsBackend`]
//! and [`kurayami_core::DnsFilter`], plus the [`DnsProxy`](proxy::DnsProxy)
//! that wires them together as a local DNS listener.

pub mod doh;
pub mod filter;
pub mod proxy;
pub mod system;

pub use doh::DohBackend;
pub use filter::{BlocklistFilter, CompositeFilter, RegexFilter};
pub use proxy::DnsProxy;
pub use system::SystemBackend;
