//! DNS cache layer — wraps any [`DnsBackend`] with an in-memory TTL cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kurayami_core::{DnsBackend, DnsQuery, DnsResponse, QueryType, Result};
use tokio::sync::RwLock;

/// Default time-to-live for cached entries (5 minutes).
const DEFAULT_TTL_SECS: u64 = 300;

/// Default maximum number of cached entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// A single cached DNS response with expiry metadata.
struct CacheEntry {
    response: DnsResponse,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    /// Whether this entry has expired.
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }
}

/// In-memory DNS response cache keyed by (domain, query type).
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<(String, QueryType), CacheEntry>>>,
    default_ttl: Duration,
    max_entries: usize,
}

impl DnsCache {
    /// Create a new cache with the given default TTL and maximum entry count.
    #[must_use]
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            max_entries,
        }
    }

    /// Look up a cached response. Returns `None` on miss or if the entry has expired.
    pub async fn get(&self, name: &str, query_type: &QueryType) -> Option<DnsResponse> {
        let entries = self.entries.read().await;
        let key = (name.to_string(), *query_type);
        match entries.get(&key) {
            Some(entry) if !entry.is_expired() => Some(entry.response.clone()),
            _ => None,
        }
    }

    /// Insert a response into the cache. If the cache is at capacity, expired
    /// entries are evicted first; if still full the oldest entry is removed.
    pub async fn put(&self, name: &str, query_type: &QueryType, response: DnsResponse) {
        let mut entries = self.entries.write().await;

        // Determine the TTL: use the minimum of the record TTL and the cache
        // default. If no records have a positive TTL, fall back to the default.
        let record_ttl = response
            .answers
            .iter()
            .map(|r| r.ttl)
            .filter(|t| *t > 0)
            .min()
            .map(|t| Duration::from_secs(u64::from(t)));

        let ttl = match record_ttl {
            Some(rt) => rt.min(self.default_ttl),
            None => self.default_ttl,
        };

        // Evict expired entries first.
        if entries.len() >= self.max_entries {
            entries.retain(|_, v| !v.is_expired());
        }

        // If still at capacity, evict the oldest entry.
        if entries.len() >= self.max_entries {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, v)| v.inserted_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        let key = (name.to_string(), *query_type);
        entries.insert(
            key,
            CacheEntry {
                response,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Remove all entries from the cache.
    pub async fn flush(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    /// Return the number of entries currently in the cache (including expired).
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Whether the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// A caching wrapper around any [`DnsBackend`].
///
/// On cache hit (and not expired), returns the cached response without
/// contacting the upstream. On miss or expiry, resolves through the inner
/// backend and caches the result.
pub struct CachedBackend<B: DnsBackend> {
    inner: B,
    cache: DnsCache,
}

impl<B: DnsBackend> CachedBackend<B> {
    /// Create a cached backend with an explicit cache instance.
    #[must_use]
    pub fn new(backend: B, cache: DnsCache) -> Self {
        Self {
            inner: backend,
            cache,
        }
    }

    /// Create a cached backend with sensible defaults (5 min TTL, 10 000 max entries).
    #[must_use]
    pub fn with_default_cache(backend: B) -> Self {
        Self::new(
            backend,
            DnsCache::new(Duration::from_secs(DEFAULT_TTL_SECS), DEFAULT_MAX_ENTRIES),
        )
    }

    /// Return a reference to the underlying cache.
    #[must_use]
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// Return a reference to the inner backend.
    #[must_use]
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

#[async_trait]
impl<B: DnsBackend> DnsBackend for CachedBackend<B> {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
        // Check cache first.
        if let Some(cached) = self.cache.get(&query.name, &query.query_type).await {
            tracing::debug!(name = %query.name, "cache hit");
            return Ok(cached);
        }

        // Miss — resolve through inner backend.
        let response = self.inner.resolve(query).await?;

        // Cache the result.
        self.cache
            .put(&query.name, &query.query_type, response.clone())
            .await;

        Ok(response)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kurayami_core::{DnsRecord, RecordData};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock backend that counts how many times `resolve` is called.
    struct CountingBackend {
        call_count: Arc<AtomicUsize>,
    }

    impl CountingBackend {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: Arc::clone(&count),
                },
                count,
            )
        }
    }

    #[async_trait]
    impl DnsBackend for CountingBackend {
        async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(DnsResponse {
                answers: vec![DnsRecord {
                    name: query.name.clone(),
                    record_type: QueryType::A,
                    ttl: 60,
                    data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
                }],
                authoritative: false,
                truncated: false,
            })
        }

        fn name(&self) -> &str {
            "counting"
        }
    }

    fn make_query(name: &str) -> DnsQuery {
        DnsQuery {
            name: name.to_string(),
            query_type: QueryType::A,
            source_addr: None,
        }
    }

    #[tokio::test]
    async fn cache_miss_resolves() {
        let (backend, count) = CountingBackend::new();
        let cached = CachedBackend::with_default_cache(backend);

        let query = make_query("example.com");
        let response = cached.resolve(&query).await.unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(response.answers.len(), 1);
    }

    #[tokio::test]
    async fn cache_hit_returns_cached() {
        let (backend, count) = CountingBackend::new();
        let cached = CachedBackend::with_default_cache(backend);

        let query = make_query("example.com");

        // First call: miss → resolves.
        cached.resolve(&query).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second call: hit → does not resolve again.
        let response = cached.resolve(&query).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(response.answers.len(), 1);
    }

    #[tokio::test]
    async fn cache_ttl_expiry() {
        let (backend, count) = CountingBackend::new();
        let cache = DnsCache::new(Duration::from_millis(50), 100);
        let cached = CachedBackend::new(backend, cache);

        let query = make_query("example.com");

        // First resolve populates cache.
        cached.resolve(&query).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be a miss now — resolves again.
        cached.resolve(&query).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_flush() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);

        let response = DnsResponse {
            answers: vec![],
            authoritative: false,
            truncated: false,
        };

        cache.put("a.com", &QueryType::A, response.clone()).await;
        cache.put("b.com", &QueryType::A, response).await;
        assert_eq!(cache.len().await, 2);

        cache.flush().await;
        assert_eq!(cache.len().await, 0);
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn cache_max_entries_eviction() {
        let cache = DnsCache::new(Duration::from_secs(300), 3);

        for i in 0..3 {
            let response = DnsResponse {
                answers: vec![],
                authoritative: false,
                truncated: false,
            };
            cache
                .put(&format!("{i}.com"), &QueryType::A, response)
                .await;
        }
        assert_eq!(cache.len().await, 3);

        // Inserting a 4th entry should evict the oldest.
        let response = DnsResponse {
            answers: vec![],
            authoritative: false,
            truncated: false,
        };
        cache.put("new.com", &QueryType::A, response).await;
        assert_eq!(cache.len().await, 3);

        // The new entry should be present.
        assert!(cache.get("new.com", &QueryType::A).await.is_some());
    }

    #[tokio::test]
    async fn different_query_types_cached_separately() {
        let cache = DnsCache::new(Duration::from_secs(300), 100);

        let response_a = DnsResponse {
            answers: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: QueryType::A,
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            authoritative: false,
            truncated: false,
        };

        let response_aaaa = DnsResponse {
            answers: vec![],
            authoritative: false,
            truncated: false,
        };

        cache
            .put("example.com", &QueryType::A, response_a)
            .await;
        cache
            .put("example.com", &QueryType::AAAA, response_aaaa)
            .await;

        let hit_a = cache.get("example.com", &QueryType::A).await.unwrap();
        assert_eq!(hit_a.answers.len(), 1);

        let hit_aaaa = cache.get("example.com", &QueryType::AAAA).await.unwrap();
        assert!(hit_aaaa.answers.is_empty());
    }
}
