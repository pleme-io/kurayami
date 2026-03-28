//! DNS proxy — local UDP listener that forwards queries through a backend.

use std::net::SocketAddr;

use kurayami_core::{DnsBackend, DnsFilter, Result};

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

        let mut buf = [0u8; 512];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            tracing::debug!(bytes = len, src = %src, "received UDP packet");
            // TODO: parse DNS wire format, apply filters, resolve, reply
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::SystemBackend;

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
}
