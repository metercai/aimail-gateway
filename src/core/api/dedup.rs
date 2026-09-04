//! Outbound send deduplication (gateway-level, client-agnostic).
//!
//! Intercepts duplicate sends at the gateway API — regardless of which
//! client made the call (send_mail tool, direct API, scripts) — so an
//! agent that works around its own tooling is still blocked from
//! re-sending an identical email.
//!
//! Key: (sender, to, cc, subject, sha256(body)). The body digest is
//! required: to/cc/subject alone cannot distinguish a retry of a
//! partially-edited draft from a genuine resend. The sender is required
//! because identical content from DIFFERENT agents is legitimate
//! (e.g. two agents notifying a shared manager).
//!
//! Storage: in-process LRU + TTL. No DB schema change, no cross-restart
//! persistence — a gateway restart clears the window. Dedup is a
//! storm-suppression guard, not a correctness invariant, so the
//! blast radius of a restart is acceptable (one re-send window).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// In-memory duplicate-send detector with TTL + LRU eviction.
#[derive(Clone)]
pub struct SendDeduper {
    inner: Arc<Mutex<DedupInner>>,
    window: Duration,
    capacity: usize,
}

struct DedupInner {
    /// key → (seen_at, insertion_order)
    entries: HashMap<u64, (Instant, u64)>,
    /// monotonically increasing insertion counter (LRU ordering)
    seq: u64,
}

impl Default for SendDeduper {
    fn default() -> Self {
        Self::new(Duration::from_secs(600), 4096)
    }
}

impl SendDeduper {
    pub fn new(window: Duration, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DedupInner {
                entries: HashMap::new(),
                seq: 0,
            })),
            window,
            capacity,
        }
    }

    fn hash_key(sender: &str, to: &[String], cc: &[String], subject: &str, body: &str) -> u64 {
        // FNV-1a over the full key components — 64-bit is ample for an
        // in-process guard (a collision only suppresses one legitimate
        // identical-content send from the same sender in the window).
        // to/cc are sorted so recipient order does not change identity.
        let mut h: u64 = 0xcbf29ce484222325;
        let mix = |h: &mut u64, bytes: &[u8]| {
            for &b in bytes {
                *h ^= b as u64;
                *h = h.wrapping_mul(0x100000001b3);
            }
        };
        mix(&mut h, sender.as_bytes());
        mix(&mut h, &[0]);
        for list in [&to, &cc] {
            let mut sorted: Vec<&String> = list.iter().collect();
            sorted.sort();
            for addr in sorted {
                mix(&mut h, addr.as_bytes());
                mix(&mut h, &[0]);
            }
            mix(&mut h, &[0]);
        }
        mix(&mut h, subject.as_bytes());
        mix(&mut h, &[0]);
        let digest = Sha256::digest(body.as_bytes());
        mix(&mut h, &digest);
        h
    }

    /// Returns true if this exact (sender, to, cc, subject, body) was
    /// already seen within the window. Does NOT record the key.
    pub fn is_duplicate(&self, sender: &str, to: &[String], cc: &[String], subject: &str, body: &str) -> bool {
        let key = Self::hash_key(sender, to, cc, subject, body);
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        // Lazy TTL purge of expired entries while we hold the lock.
        g.entries.retain(|_, (t, _)| now.duration_since(*t) < self.window);
        g.entries.contains_key(&key)
    }

    /// Record a successful send so subsequent identical sends in the
    /// window are suppressed. Call ONLY after the DB insert succeeded —
    /// a failed insert must not poison the key.
    pub fn mark(
        &self,
        sender: &str,
        to: &[String],
        cc: &[String],
        subject: &str,
        body: &str,
    ) {
        let key = Self::hash_key(sender, to, cc, subject, body);
        let mut g = self.inner.lock().unwrap();
        g.seq = g.seq.wrapping_add(1);
        let seq = g.seq;
        // Evict oldest (lowest seq) when at capacity.
        if g.entries.len() >= self.capacity {
            let oldest = g
                .entries
                .iter()
                .min_by_key(|(_, (_, s))| *s)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                g.entries.remove(&k);
            }
        }
        g.entries.insert(key, (Instant::now(), seq));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_cc() -> (Vec<String>, Vec<String>) {
        (vec!["bob@x.com".to_string()], vec!["mgr@x.com".to_string()])
    }

    #[test]
    fn duplicate_detected_within_window() {
        let d = SendDeduper::new(Duration::from_secs(60), 100);
        let (to, cc) = to_cc();
        assert!(!d.is_duplicate("alice@x.com", &to, &cc, "Hi", "body"));
        d.mark("alice@x.com", &to, &cc, "Hi", "body");
        assert!(d.is_duplicate("alice@x.com", &to, &cc, "Hi", "body"));
    }

    #[test]
    fn different_body_not_duplicate() {
        let d = SendDeduper::new(Duration::from_secs(60), 100);
        let (to, cc) = to_cc();
        d.mark("alice@x.com", &to, &cc, "Hi", "body v1");
        assert!(!d.is_duplicate("alice@x.com", &to, &cc, "Hi", "body v2"));
    }

    #[test]
    fn different_sender_not_duplicate() {
        let d = SendDeduper::new(Duration::from_secs(60), 100);
        let (to, cc) = to_cc();
        d.mark("alice@x.com", &to, &cc, "Hi", "body");
        assert!(!d.is_duplicate("carol@x.com", &to, &cc, "Hi", "body"));
    }

    #[test]
    fn cc_order_normalized_not_duplicate_of_reordered() {
        // mark with cc=[a,b]; query with cc=[b,a] — same set, must match
        let d = SendDeduper::new(Duration::from_secs(60), 100);
        let to = vec!["bob@x.com".to_string()];
        let cc1 = vec!["a@x.com".to_string(), "b@x.com".to_string()];
        let cc2 = vec!["b@x.com".to_string(), "a@x.com".to_string()];
        d.mark("alice@x.com", &to, &cc1, "Hi", "body");
        assert!(d.is_duplicate("alice@x.com", &to, &cc2, "Hi", "body"));
    }

    #[test]
    fn expired_entry_allows_resend() {
        let d = SendDeduper::new(Duration::from_secs(0), 100);
        let (to, cc) = to_cc();
        d.mark("alice@x.com", &to, &cc, "Hi", "body");
        // window=0 → everything expires immediately
        std::thread::sleep(Duration::from_millis(1));
        assert!(!d.is_duplicate("alice@x.com", &to, &cc, "Hi", "body"));
    }

    #[test]
    fn lru_eviction_keeps_capacity() {
        let d = SendDeduper::new(Duration::from_secs(60), 2);
        let (to, cc) = to_cc();
        d.mark("a@x.com", &to, &cc, "1", "b");
        d.mark("b@x.com", &to, &cc, "2", "b");
        d.mark("c@x.com", &to, &cc, "3", "b"); // evicts "a"
        assert!(!d.is_duplicate("a@x.com", &to, &cc, "1", "b"));
        assert!(d.is_duplicate("b@x.com", &to, &cc, "2", "b"));
        assert!(d.is_duplicate("c@x.com", &to, &cc, "3", "b"));
    }

    #[test]
    fn concurrent_mark_is_duplicate() {
        let d = Arc::new(SendDeduper::new(Duration::from_secs(60), 100));
        let (to, cc) = to_cc();
        let mut handles = Vec::new();
        for i in 0..8 {
            let d = d.clone();
            let to = to.clone();
            let cc = cc.clone();
            handles.push(std::thread::spawn(move || {
                d.mark(format!("s{}@x.com", i).as_str(), &to, &cc, "Hi", "body");
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 8 distinct senders, all recorded
        for i in 0..8 {
            assert!(d.is_duplicate(&format!("s{}@x.com", i), &to, &cc, "Hi", "body"));
        }
    }
}
