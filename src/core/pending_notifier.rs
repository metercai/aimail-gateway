//! Process-local wake-up for pending-delivery waiters (long-pull + SSE).
//!
//! Single-process premise: the writer (webhook insert, `core/api/webhook.rs`)
//! and the waiters (pull handlers, SSE streams) share one process and one
//! SQLite file — the process embedding this library keeps exactly one writer
//! task and any number of waiter tasks.
//! An in-process signal is sufficient; no DB polling, no PG LISTEN, no
//! Redis. (Multi-instance deployments are not the current shape; if they
//! arrive, this module's backend changes — the waiter protocol below does
//! not.)
//!
//! # Waiter protocol
//! 1. `let since = n.snapshot(key);` — BEFORE querying the store.
//! 2. Query the store. Non-empty ⇒ return it (done, no wait).
//! 3. `n.wait_since(key, since, hold).await`:
//!    - `Woke` ⇒ re-query (double-check) and return whatever it yields;
//!    - `Timeout` ⇒ return empty.
//!
//! # Correctness
//! A writer must call `notify_*` only AFTER the insert has committed.
//! Then, for a notify at time T and a snapshot at time S:
//! when T < S the row is durable before S, so the step-2 query sees it;
//! when T > S, `gen > since` becomes true (either before `wait_since` is
//! called, or via the waker) and the re-query sees it. No ordering loses a
//! row. The double-check is the source of truth; the wake-up is only a
//! latency optimization. A spurious `Woke` costs one extra query.
//!
//! # Cancellation
//! Waiters hold no per-waiter state: a slot is a shared `Notify` plus a
//! generation counter. When axum drops the handler task on disconnect, the
//! `select!` future is dropped with it — zero cleanup. The slot map is
//! bounded by the key space (one entry per system + one per (system,
//! lowercased email)).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::sync::Notify;

/// Wake-up key — must match the storage filter exactly (scope IS the range).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NotifyKey {
    /// system/bridge-scope waiters (storage filter: `system_id`).
    System(String),
    /// agent-scope waiters (storage filter: `system_id` + lowercased email).
    Email { system_id: String, email: String },
}

struct PendingSlot {
    notify: Notify,
    gen: AtomicU64,
}

/// In-process wake-up registry for pending-delivery waiters.
pub struct PendingNotifier {
    map: RwLock<HashMap<NotifyKey, Arc<PendingSlot>>>,
}

/// Result of a bounded wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// A notify landed after the snapshot — re-query the store.
    Woke,
    /// The hold elapsed with no relevant notify — return what you have.
    Timeout,
}

impl Default for PendingNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingNotifier {
    /// Fresh registry (tests). Production code uses [`PendingNotifier::global`].
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Process-wide singleton: writer and all waiters must share ONE
    /// instance for wake-ups to work.
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<PendingNotifier> = OnceLock::new();
        INSTANCE.get_or_init(Self::new)
    }

    fn slot(&self, key: &NotifyKey) -> Arc<PendingSlot> {
        {
            let map = self.map.read().unwrap();
            if let Some(s) = map.get(key) {
                return Arc::clone(s);
            }
        }
        let mut map = self.map.write().unwrap();
        map.entry(key.clone())
            .or_insert_with(|| {
                Arc::new(PendingSlot {
                    notify: Notify::new(),
                    gen: AtomicU64::new(0),
                })
            })
            .clone()
    }

    /// Baseline for the waiter protocol — call BEFORE the store query.
    pub fn snapshot(&self, key: &NotifyKey) -> u64 {
        self.slot(key).gen.load(Ordering::SeqCst)
    }

    /// Wake every waiter on the system key. Call AFTER the insert commits.
    pub fn notify_system(&self, system_id: &str) {
        let key = NotifyKey::System(system_id.to_string());
        let slot = self.slot(&key);
        slot.gen.fetch_add(1, Ordering::SeqCst);
        slot.notify.notify_waiters();
    }

    /// Wake every waiter on the (system, lowercased-email) key.
    /// Call AFTER the insert commits.
    pub fn notify_email(&self, system_id: &str, email_lower: &str) {
        let key = NotifyKey::Email {
            system_id: system_id.to_string(),
            email: email_lower.to_string(),
        };
        let slot = self.slot(&key);
        slot.gen.fetch_add(1, Ordering::SeqCst);
        slot.notify.notify_waiters();
    }

    /// Wait up to `timeout` for a notify that landed after `since`.
    ///
    /// Returns `Woke` as soon as `gen > since` is observable — either on
    /// entry (notify already happened), or via the waker. Spurious waker
    /// completions re-check `gen` and re-arm; they can only delay a real
    /// wake by one re-arm, never mask it (`gen` is monotonic and the
    /// compare is against the fixed `since`, not a re-read baseline).
    pub async fn wait_since(&self, key: &NotifyKey, since: u64, timeout: Duration) -> WaitOutcome {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let slot = self.slot(key);
            if slot.gen.load(Ordering::SeqCst) > since {
                return WaitOutcome::Woke;
            }
            let notified = slot.notify.notified();
            tokio::select! {
                _ = notified => {
                    // Woken (or spurious) — the loop top re-checks `gen`.
                }
                _ = tokio::time::sleep_until(deadline) => {
                    // A notify may have landed in the window before the
                    // waker's first poll armed it: `notify_waiters` then
                    // found no armed waiter and the one-shot signal is
                    // lost. `gen` is persistent, so re-reading it closes
                    // that window before we may return `Timeout`.
                    if self.slot(key).gen.load(Ordering::SeqCst) > since {
                        return WaitOutcome::Woke;
                    }
                    return WaitOutcome::Timeout;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notify_after_wait_start_wakes_quickly() {
        let n = Arc::new(PendingNotifier::new());
        let k = NotifyKey::System("s".into());
        let since = n.snapshot(&k);

        let n2 = n.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            n2.notify_system("s");
        });
        let t0 = std::time::Instant::now();
        let out = n.wait_since(&k, since, Duration::from_millis(500)).await;
        let elapsed = t0.elapsed();
        writer.await.unwrap();
        assert_eq!(out, WaitOutcome::Woke);
        assert!(
            elapsed < Duration::from_millis(100),
            "wake took {elapsed:?}, expected <100ms"
        );
    }

    #[tokio::test]
    async fn no_notify_times_out() {
        let n = PendingNotifier::new();
        let k = NotifyKey::System("s".into());
        let since = n.snapshot(&k);
        let t0 = std::time::Instant::now();
        let out = n.wait_since(&k, since, Duration::from_millis(150)).await;
        let elapsed = t0.elapsed();
        assert_eq!(out, WaitOutcome::Timeout);
        assert!(elapsed >= Duration::from_millis(140), "elapsed {elapsed:?}");
    }

    #[tokio::test]
    async fn ten_waiters_on_same_key_all_wake() {
        let n = Arc::new(PendingNotifier::new());
        let k = NotifyKey::System("s".into());
        let since = n.snapshot(&k);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let n2 = n.clone();
            let k2 = k.clone();
            handles.push(tokio::spawn(async move {
                n2.wait_since(&k2, since, Duration::from_secs(2)).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await; // let all arm
        n.notify_system("s");
        for h in handles {
            assert_eq!(h.await.unwrap(), WaitOutcome::Woke);
        }
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let n = Arc::new(PendingNotifier::new());
        let sys = NotifyKey::System("A".into());
        let since = n.snapshot(&sys);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let n2 = n.clone();
        let sys_key = sys.clone();
        let sys_waiter = tokio::spawn(async move {
            let out = n2
                .wait_since(&sys_key, since, Duration::from_millis(200))
                .await;
            let _ = tx.send(out);
            out
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Email-scoped notify must NOT wake the system waiter.
        n.notify_email("A", "x@t.test");
        let out = rx.await.unwrap();
        assert_eq!(out, WaitOutcome::Timeout, "email notify woke system key");

        // System-scoped notify wakes the system key.
        let n3 = n.clone();
        let t2 = tokio::spawn(async move {
            n3.wait_since(&sys, n3.snapshot(&sys), Duration::from_millis(200))
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        n.notify_system("A");
        assert_eq!(t2.await.unwrap(), WaitOutcome::Woke);
        assert_eq!(sys_waiter.await.unwrap(), WaitOutcome::Timeout);
    }

    #[tokio::test]
    async fn notify_between_snapshot_and_wait_wakes_immediately() {
        // Protocol mapping: snapshot = start of the wait protocol (it is
        // taken before the store query). A notify landing after the
        // snapshot — whenever before `wait_since` — must be observed.
        let n = PendingNotifier::new();
        let k = NotifyKey::Email {
            system_id: "s".into(),
            email: "a@t.test".into(),
        };
        let since = n.snapshot(&k); // 0
        n.notify_email("s", "a@t.test"); // insert+notify "between query and wait"
        let t0 = std::time::Instant::now();
        let out = n.wait_since(&k, since, Duration::from_millis(500)).await;
        assert_eq!(out, WaitOutcome::Woke);
        assert!(t0.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn dropped_wait_task_leaves_notifier_functional() {
        let n = Arc::new(PendingNotifier::new());
        let k = NotifyKey::System("s".into());
        let n2 = n.clone();
        let doomed_key = k.clone();
        let doomed =
            tokio::spawn(
                async move { n2.wait_since(&doomed_key, 0, Duration::from_secs(5)).await },
            );
        tokio::time::sleep(Duration::from_millis(20)).await;
        doomed.abort(); // axum disconnect = task drop
        tokio::task::yield_now().await;

        // Notifier still wakes fresh waiters after the drop.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let n3 = n.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            n3.notify_system("s");
            let _ = tx.send(());
        });
        assert_eq!(
            n.wait_since(&k, 0, Duration::from_millis(300)).await,
            WaitOutcome::Woke
        );
        rx.await.unwrap();
    }
}
