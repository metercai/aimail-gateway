//! # Whitelist System Constraints
//!
//! ## 1. Address-level
//! All whitelist entries are per-individual-address.
//! `domain_addr` is always a full email address (e.g. `"alice@domain.com"`).
//! No bare-domain whitelist entries exist. Wildcards in `value` are supported.
//!
//! ## 2. Mandatory protection
//! Every registered email address MUST have whitelist entries.
//! "No matching entries → reject" is the system-enforced behavior.
//! There is NO open-policy fallback.
//!
//! ## 3. Directional
//! - `to`:  subject(`domain_addr`) is allowed to SEND TO object(`value`)
//! - `from`: subject(`domain_addr`) is allowed to RECEIVE FROM object(`value`)
//! - `all`: bidirectional
//!
//! ## Whitelist entry semantics
//! ```text
//! { domain_addr: "alice@domain.com",    ← subject
//!   direction:   "to",                  ← direction
//!   value:       "bob@other.com" }      ← object
//! ```
//! Means: Alice allows Bob as a recipient (Alice can send TO Bob).
//!
//! ## Check paths
//! - HTTP send (outbound): `check_whitelisted(sender, recipient, "to")`
//! - SMTP receive (inbound): `check_whitelisted(recipient_email, sender, "from")`
//! - P0 gate before each: `count_whitelist_entries(addr, [directions])`
//!   Returns 0 → reject immediately (no whitelist protection).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use regex::Regex;

use crate::core::errors::{AppError, AppResult};
use crate::core::storage::Database;
use crate::core::strategy::WhitelistKeyResolver;

/// Maximum length for a whitelist pattern value.
const MAX_PATTERN_LEN: usize = 128;

/// Time-to-live for cached compiled regex patterns.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// Compile a whitelist pattern value into a regex.
///
/// Rules:
/// - Maximum 128 characters
/// - First `*` only is treated as a wildcard, replaced with `.*`
/// - Pattern is anchored with `^...$`
/// - Case-insensitive matching
/// - Other regex metacharacters are escaped
pub fn compile_whitelist_pattern(value: &str) -> AppResult<Regex> {
    if value.len() > MAX_PATTERN_LEN {
        return Err(AppError::Validation(format!(
            "Whitelist pattern too long: {} chars (max {})",
            value.len(),
            MAX_PATTERN_LEN
        )));
    }

    // Escape all regex metacharacters, then replace the escaped wildcard.
    let escaped = regex::escape(value);
    // regex::escape produces `\*` for `*` — replace with the unescaped `.*`
    let pattern = escaped.replace("\\*", ".*");
    let anchored = format!("^{}$", pattern);

    Regex::new(&format!("(?i){}", anchored))
        .map_err(|e| AppError::Validation(format!("Invalid whitelist pattern '{}': {}", value, e)))
}

/// In-memory cache for compiled whitelist regex patterns.
///
/// Stores compiled regex patterns with a 30-second TTL to balance
/// performance with pattern freshness.
pub struct WhitelistCache {
    inner: RwLock<HashMap<String, (Regex, Instant)>>,
}

impl WhitelistCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Get a compiled regex for the given pattern value.
    ///
    /// Returns a cached regex if available and not expired, otherwise
    /// compiles a new one and stores it in the cache.
    pub fn get_or_compile(&self, value: &str) -> AppResult<Regex> {
        // Fast path: read lock to check cache
        {
            let cache = self.inner.read().unwrap();
            if let Some((regex, created)) = cache.get(value) {
                if created.elapsed() < CACHE_TTL {
                    return Ok(regex.clone());
                }
            }
        }

        // Slow path: compile and cache
        let regex = compile_whitelist_pattern(value)?;

        {
            let mut cache = self.inner.write().unwrap();
            // Clean expired entries while we're here
            cache.retain(|_, (_, created)| created.elapsed() < CACHE_TTL);
            cache.insert(value.to_string(), (regex.clone(), Instant::now()));
        }

        Ok(regex)
    }

    /// Remove a specific pattern from the cache, forcing recompilation on next lookup.
    pub fn invalidate(&self, value: &str) {
        let mut cache = self.inner.write().unwrap();
        cache.remove(value);
    }

    /// Clear all cached entries.
    pub fn invalidate_all(&self) {
        let mut cache = self.inner.write().unwrap();
        cache.clear();
    }
}

impl Default for WhitelistCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if `target` matches any of the whitelist `values` using wildcard matching.
///
/// Returns `true` if `target` matches at least one value pattern.
/// Returns `false` if no values match or the values list is empty.
pub fn is_whitelisted_wildcard(values: &[String], target: &str, cache: &WhitelistCache) -> bool {
    values
        .iter()
        .any(|value| match cache.get_or_compile(value) {
            Ok(regex) => regex.is_match(target),
            Err(_) => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let re = compile_whitelist_pattern("user@example.com").unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(!re.is_match("other@example.com"));
    }

    #[test]
    fn prefix_wildcard() {
        let re = compile_whitelist_pattern("*@example.com").unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("admin@example.com"));
        assert!(!re.is_match("user@other.com"));
    }

    #[test]
    fn suffix_wildcard() {
        let re = compile_whitelist_pattern("admin@*").unwrap();
        assert!(re.is_match("admin@example.com"));
        assert!(re.is_match("admin@other.org"));
        assert!(!re.is_match("user@example.com"));
    }

    #[test]
    fn infix_wildcard() {
        let re = compile_whitelist_pattern("user@*.com").unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("user@other.com"));
        assert!(!re.is_match("user@example.org"));
    }

    #[test]
    fn bare_wildcard() {
        let re = compile_whitelist_pattern("*").unwrap();
        assert!(re.is_match("anything@anywhere.com"));
    }

    #[test]
    fn case_insensitive() {
        let re = compile_whitelist_pattern("User@Example.COM").unwrap();
        assert!(re.is_match("user@example.com"));
        assert!(re.is_match("USER@EXAMPLE.COM"));
    }

    #[test]
    fn max_length_enforced() {
        let long = "a".repeat(129);
        assert!(compile_whitelist_pattern(&long).is_err());
    }

    #[test]
    fn exactly_max_length_ok() {
        let ok = "a".repeat(128);
        assert!(compile_whitelist_pattern(&ok).is_ok());
    }

    #[test]
    fn regex_metacharacters_escaped() {
        // "." should not match arbitrary characters
        let re = compile_whitelist_pattern("user.example.com").unwrap();
        assert!(re.is_match("user.example.com"));
        assert!(!re.is_match("userXexampleXcom"));
    }

    #[test]
    fn cache_basic_operation() {
        let cache = WhitelistCache::new();
        let re1 = cache.get_or_compile("test@example.com").unwrap();
        let re2 = cache.get_or_compile("test@example.com").unwrap();
        // Same pattern should return cached version
        assert_eq!(re1.as_str(), re2.as_str());
    }

    #[test]
    fn is_whitelisted_wildcard_tests() {
        let cache = WhitelistCache::new();
        let patterns: Vec<String> = vec!["*@example.com".to_string(), "admin@*".to_string()];

        assert!(is_whitelisted_wildcard(
            &patterns,
            "user@example.com",
            &cache
        ));
        assert!(is_whitelisted_wildcard(
            &patterns,
            "admin@other.org",
            &cache
        ));
        assert!(!is_whitelisted_wildcard(
            &patterns,
            "user@other.com",
            &cache
        ));
    }

    #[test]
    fn empty_patterns_returns_false() {
        let cache = WhitelistCache::new();
        let empty: Vec<String> = vec![];
        assert!(!is_whitelisted_wildcard(
            &empty,
            "anything@example.com",
            &cache
        ));
    }
}

/// Default resolver: single exact match (address-level only).
pub struct ExactKeyResolver;
#[async_trait]
impl WhitelistKeyResolver for ExactKeyResolver {
    async fn resolve(&self, db: &Database, addr: &str) -> AppResult<Vec<(String, String)>> {
        let record = db
            .get_system_domain_by_name(addr)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("domain not found: {}", addr)))?;
        Ok(vec![(record.system_id, addr.to_string())])
    }
}
