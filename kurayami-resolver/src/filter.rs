//! Domain filters — blocklists, regex patterns, and composite chains.

use std::collections::HashSet;

use kurayami_core::DnsFilter;
use regex::Regex;

/// Exact-match domain blocklist filter.
#[derive(Debug, Default)]
pub struct BlocklistFilter {
    blocked: HashSet<String>,
}

impl BlocklistFilter {
    /// Create a new blocklist filter from the given domains.
    #[must_use]
    pub fn new(domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            blocked: domains.into_iter().map(Into::into).collect(),
        }
    }

    /// Add a domain to the blocklist.
    pub fn add(&mut self, domain: impl Into<String>) {
        self.blocked.insert(domain.into());
    }

    /// Number of blocked domains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// Whether the blocklist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }
}

impl DnsFilter for BlocklistFilter {
    fn should_block(&self, domain: &str) -> bool {
        self.blocked.contains(domain)
    }
}

/// Regex-based domain filter.
#[derive(Debug)]
pub struct RegexFilter {
    patterns: Vec<Regex>,
}

impl RegexFilter {
    /// Create a new regex filter from compiled patterns.
    #[must_use]
    pub fn new(patterns: Vec<Regex>) -> Self {
        Self { patterns }
    }

    /// Create a regex filter from pattern strings.
    ///
    /// # Errors
    ///
    /// Returns an error if any pattern fails to compile.
    pub fn from_patterns(patterns: &[&str]) -> std::result::Result<Self, regex::Error> {
        let compiled = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self::new(compiled))
    }
}

impl DnsFilter for RegexFilter {
    fn should_block(&self, domain: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(domain))
    }
}

/// Composite filter that chains multiple filters — blocks if **any** child blocks.
#[derive(Default)]
pub struct CompositeFilter {
    filters: Vec<Box<dyn DnsFilter>>,
}

impl CompositeFilter {
    /// Create an empty composite filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter to the chain.
    pub fn add(&mut self, filter: Box<dyn DnsFilter>) {
        self.filters.push(filter);
    }

    /// Number of child filters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the composite has no child filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

impl DnsFilter for CompositeFilter {
    fn should_block(&self, domain: &str) -> bool {
        self.filters.iter().any(|f| f.should_block(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_exact_match_blocks() {
        let filter = BlocklistFilter::new(["ads.example.com", "tracker.example.com"]);
        assert!(filter.should_block("ads.example.com"));
    }

    #[test]
    fn blocklist_non_match_allows() {
        let filter = BlocklistFilter::new(["ads.example.com"]);
        assert!(!filter.should_block("safe.example.com"));
    }

    #[test]
    fn regex_pattern_blocks() {
        let filter = RegexFilter::from_patterns(&[r"^ads\.", r"tracker"]).unwrap();
        assert!(filter.should_block("ads.example.com"));
        assert!(filter.should_block("my-tracker.example.com"));
        assert!(!filter.should_block("safe.example.com"));
    }

    #[test]
    fn composite_blocks_if_any_child_blocks() {
        let blocklist = BlocklistFilter::new(["blocked.com"]);
        let regex = RegexFilter::from_patterns(&[r"^ads\."]).unwrap();

        let mut composite = CompositeFilter::new();
        composite.add(Box::new(blocklist));
        composite.add(Box::new(regex));

        assert!(composite.should_block("blocked.com"));
        assert!(composite.should_block("ads.other.com"));
        assert!(!composite.should_block("safe.com"));
    }

    #[test]
    fn empty_filter_allows_all() {
        let composite = CompositeFilter::new();
        assert!(!composite.should_block("anything.com"));
        assert!(composite.is_empty());
    }

    #[test]
    fn blocklist_add_and_len() {
        let mut filter = BlocklistFilter::default();
        assert!(filter.is_empty());
        filter.add("example.com");
        assert_eq!(filter.len(), 1);
        assert!(filter.should_block("example.com"));
    }
}
