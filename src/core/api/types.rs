//! Shared HTTP state and request/response types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::core::api::dedup::SendDeduper;
use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::MailFactories;
use crate::core::storage::{ApiKeyRecord, SystemDomainRecord, SystemRecord, WhitelistRecord};
use crate::core::strategy::ExtensionProviders;
use hickory_resolver::TokioAsyncResolver;

// ── Pull / stream contract (single source of truth) ────────────────

/// Max server-side hold for a long-pull (`timeout_ms` is clamped to this).
/// 50s < the 60s read timeout a reverse proxy would typically impose, so a
/// held response always completes before the proxy gives up. Production has
/// no proxy today; the margin is kept as defensive headroom.
pub const PULL_HOLD_MAX_MS: u64 = 50_000;

/// SSE heartbeat cadence (comment line `: ping`). 15s x 3 = 45s < the
/// client's 90s stream read timeout: three missed pings mean the link is
/// dead or buffered.
pub const SSE_HEARTBEAT_SECS: u64 = 15;

/// Max lifetime of one SSE stream before the server closes it. The client
/// reconnects (at-least-once: unacked rows are re-sent). Bounds one
/// connection's resources.
pub const SSE_MAX_LIFE_SECS: u64 = 300;

// ── Single-slot mailbox lock (one client per key) ──────────────────
//
// At most ONE client may hold a key's mailbox at any instant, across BOTH
// transports (SSE stream + long-poll). First connection wins; a second,
// different client gets 409 "occupied" until the holder's slot frees.
//
// Identity is the client's `X-Aimail-Client` id (stable per process,
// UUID v4): a reconnect (same id) always re-acquires; a different id is
// rejected while the slot is live or in its post-release grace window.
//
// Slot lifecycle:
//   * stream: acquired on connect; released when the stream ends — with the
//     post-release grace (`SLOT_GRACE_SECS`) on a max-life rotation (so the
//     reconnecting client is not raced by a stranger) and zero grace on an
//     abrupt disconnect (second-level release);
//   * poll: acquired per request with a lease (`SLOT_POLL_LEASE_SECS`); a
//     dead holder's lease expires and the next client takes over. No
//     explicit release (requests are stateless).

/// Post-release grace after a max-life stream rotation: a DIFFERENT client
/// gets 409 for this window; the same client re-acquires immediately.
pub const SLOT_GRACE_SECS: u64 = 60;

/// Long-poll slot lease: a poll holder's claim auto-expires this long after
/// its last acquire (holder crash ⇒ the slot frees without any release).
pub const SLOT_POLL_LEASE_SECS: u64 = 120;

/// Stream slot lease: longer than the max stream life, so a live stream can
/// never expire mid-stream; release happens via the guard (drop / rotation).
pub const SLOT_STREAM_LEASE_SECS: u64 = 600;

/// One key's slot: which client holds it and until when.
#[derive(Debug)]
pub struct SlotHolder {
    pub client_id: String,
    /// Active-lease deadline (poll holders; streams use a long lease).
    pub expires_at: std::time::Instant,
    /// Set when the holder released (stream end): `None` = actively held.
    /// While set, only the same client re-acquires until this instant.
    pub grace_until: Option<std::time::Instant>,
}

/// Per-gateway single-slot lock, keyed by API key id.
///
/// Cheap to share across `HttpState` clones: the map sits behind an `Arc`.
#[derive(Debug)]
pub struct SingleSlotLock(Arc<Mutex<HashMap<i64, SlotHolder>>>);

impl SingleSlotLock {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Try to take (or keep) the slot for `key_id` as `client_id`.
    ///
    /// `true` when the slot is now ours: it was empty, ours (refreshed —
    /// a refresh never shortens an existing deadline), expired, or in our
    /// own grace window. `false` = 409: another live client holds it.
    pub fn try_acquire(&self, key_id: i64, client_id: &str, lease: std::time::Duration) -> bool {
        let mut slots = self.0.lock().unwrap();
        let now = std::time::Instant::now();
        let deadline = now + lease;
        match slots.get_mut(&key_id) {
            Some(h) if h.grace_until.is_none() => {
                if h.client_id == client_id {
                    if deadline > h.expires_at {
                        h.expires_at = deadline;
                    }
                    true
                } else if h.expires_at <= now {
                    *h = SlotHolder {
                        client_id: client_id.to_string(),
                        expires_at: deadline,
                        grace_until: None,
                    };
                    true
                } else {
                    false
                }
            }
            Some(h) => {
                let grace_over = h.grace_until.is_none_or(|g| g <= now);
                if h.client_id == client_id || grace_over {
                    *h = SlotHolder {
                        client_id: client_id.to_string(),
                        expires_at: deadline,
                        grace_until: None,
                    };
                    true
                } else {
                    false
                }
            }
            None => {
                slots.insert(
                    key_id,
                    SlotHolder {
                        client_id: client_id.to_string(),
                        expires_at: deadline,
                        grace_until: None,
                    },
                );
                true
            }
        }
    }

    /// Release `key_id` as `client_id`: the slot enters a grace window
    /// (`grace`) during which only the same client re-acquires. No-op when
    /// the slot is not actively held by us (idempotent across the
    /// explicit-rotation-release + drop-guard double path).
    pub fn release(&self, key_id: i64, client_id: &str, grace: std::time::Duration) {
        let mut slots = self.0.lock().unwrap();
        if let Some(h) = slots.get_mut(&key_id) {
            if h.client_id == client_id && h.grace_until.is_none() {
                h.grace_until = Some(std::time::Instant::now() + grace);
            }
        }
    }
}

impl Clone for SingleSlotLock {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Default for SingleSlotLock {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII slot holder for a live SSE stream: releasing on drop covers abrupt
/// disconnects (the axum future is cancelled ⇒ the stream state drops).
#[derive(Debug)]
pub struct SlotGuard {
    lock: SingleSlotLock,
    key_id: i64,
    client_id: String,
}

impl SlotGuard {
    pub fn new(lock: SingleSlotLock, key_id: i64, client_id: &str) -> Self {
        Self {
            lock,
            key_id,
            client_id: client_id.to_string(),
        }
    }

    /// Max-life rotation: release with the grace window (called explicitly
    /// from the stream step; the subsequent drop then no-ops).
    pub fn release_on_rotation(&self) {
        self.lock.release(
            self.key_id,
            &self.client_id,
            std::time::Duration::from_secs(SLOT_GRACE_SECS),
        );
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Abrupt disconnect (or the no-op after a rotation release): zero
        // grace — a stranger may take over at once; the owner re-acquires
        // regardless.
        self.lock
            .release(self.key_id, &self.client_id, std::time::Duration::ZERO);
    }
}

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    pub factories: MailFactories,
    pub metrics: Arc<Metrics>,
    pub config: Config,
    pub trigger_tx: mpsc::Sender<String>,
    pub extensions: Arc<ExtensionProviders>,
    pub dns_resolver: Option<Arc<TokioAsyncResolver>>,
    /// Gateway-level duplicate-send suppression (sender+to+cc+subject+body
    /// within a configurable window). Shared across all API handlers.
    pub send_deduper: SendDeduper,
    /// Single-slot mailbox lock: one client per key across the stream +
    /// long-poll paths (409 occupied otherwise). Shared across handler
    /// clones (Arc-backed).
    pub delivery_slot: SingleSlotLock,
}

// ── First-delivery dispatch (single authority) ──────────────────────

/// Fire the first-delivery trigger for an email whose payload is COMPLETE.
///
/// Every email is born `readying` (`core/storage.rs`) and the scheduler's
/// periodic tick reads `ready` only — this trigger is the *only* first-delivery
/// claimant (`core/scheduler/entry.rs`). A caller that queues an email and
/// forgets this call leaves it structurally invisible to the tick until Flow 0
/// (`core/scheduler/batch.rs::sweep_stuck_readying`) flips it, i.e. after
/// `retry.readying_stuck_secs` (default 30s) **plus** up to one
/// `retry.poll_interval_secs` (default 5s).
///
/// Call it AFTER the payload is complete. For an email with attachments that
/// means after the attachment write loop — firing earlier delivers an empty
/// attachment set, which is the entire reason the `readying` state exists.
/// Attachment-less emails (API notifications, codes, notices) are complete the
/// moment `create_outbound`/`create_inbound` returns.
///
/// A full channel is a supported degradation, not an error path: the email is
/// already durable and the sweep picks it up (at the cost of the delay above).
pub fn dispatch_first_delivery(
    trigger_tx: &mpsc::Sender<String>,
    metrics: &Metrics,
    email_id: &str,
) {
    if let Err(e) = trigger_tx.try_send(email_id.to_string()) {
        metrics.inc_trigger_dropped();
        tracing::warn!(
            operation = "dispatch_trigger_dropped",
            email_id = %email_id,
            error = %e,
            "First-delivery trigger dropped (channel full) — the readying sweep will pick this email up"
        );
    }
}

impl HttpState {
    /// [`dispatch_first_delivery`] for callers holding the HTTP state.
    pub fn dispatch_first_delivery(&self, email_id: &str) {
        dispatch_first_delivery(&self.trigger_tx, &self.metrics, email_id);
    }
}

// ── Request/Response types ──

/// Request body for creating an API key.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub system_id: String,
    pub email_address: String,
    /// Scope(s) granted to this key. Single string treated as a one-element collection.
    #[serde(default = "default_scope")]
    pub scopes: Vec<String>,
    /// Optional ISO-8601 expiration timestamp.
    pub expires_at: Option<String>,
    /// Category of the key: "platform", "system", or "agent". Defaults to "system".
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_scope() -> Vec<String> {
    vec!["agent".to_string()]
}

fn default_category() -> String {
    "system".to_string()
}

/// Request body for updating an API key.
#[derive(Debug, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub scopes: Option<Vec<String>>,
    pub is_active: Option<bool>,
    pub expires_at: Option<String>,
    /// If true, rotate the key (generate new hash). Agent-only operation.
    pub rotate: Option<bool>,
}

/// Response for an API key.
/// `raw_key` is only populated on creation; subsequent reads return `null`.
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: i64,
    pub system_id: String,
    pub email_address: String,
    pub key_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_key: Option<String>,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub category: String,
}

/// Reference to an uploaded attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
}

/// Request body for POST /api/v1/send.
#[derive(Debug, Deserialize)]
pub struct SendEmailRequest {
    /// Sender address — must exactly match the API key's email_address.
    pub sender: Option<String>,
    /// Primary recipient(s), comma-separated or single address.
    pub to: String,
    /// Optional CC recipients.
    pub cc: Option<Vec<String>>,
    /// Optional email subject.
    pub subject: Option<String>,
    /// Markdown content — will be converted to HTML for MIME delivery.
    pub markdown: String,
    /// Optional attachment references from prior uploads.
    pub attachments: Option<Vec<AttachmentRef>>,
    /// Optional custom headers to include in the outbound email.
    pub headers: Option<HashMap<String, String>>,
}

/// Response for a successful send request.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendEmailResponse {
    pub email_id: String,
    pub status: String,
}

/// Generic error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub detail: Option<String>,
}

/// Owner information for health check endpoint.
#[derive(Debug, Serialize)]
pub struct OwnerResponse {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Response returned after a successful attachment upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadAttachmentResponse {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
}

// ── System management types ──

#[derive(Debug, Deserialize)]
pub struct CreateSystemRequest {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemRequest {
    pub admin_email: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SystemResponse {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,
    pub is_active: bool,
    pub created_at: String,
}

// ── System domain management types ──

#[derive(Debug, Deserialize)]
pub struct CreateSystemDomainRequest {
    pub id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAddressRequest {
    pub id: String,
    pub email: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub manager_address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemDomainRequest {
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub is_active: Option<bool>,
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemDomainResponse {
    pub id: String,
    pub system_id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub manager_address: String,
    pub agent_signature: String,
    pub agent_persona: String,
}

// ── Whitelist management types ──

#[derive(Debug, Deserialize)]
pub struct CreateWhitelistRequest {
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWhitelistRequest {
    pub is_active: Option<bool>,
    pub direction: Option<String>,
}

/// Request body for PUT /api/v1/admin/agent-meta/:email
#[derive(Debug, Deserialize)]
pub struct UpdateAgentMetaRequest {
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WhitelistResponse {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub category: String,
}

// ── From conversions ──

impl From<ApiKeyRecord> for ApiKeyResponse {
    fn from(record: ApiKeyRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            email_address: record.email_address,
            key_prefix: record.key_prefix,
            raw_key: None, // never exposed from stored records
            scopes: record.scopes,
            is_active: record.is_active,
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            category: record.category,
        }
    }
}

impl From<SystemRecord> for SystemResponse {
    fn from(record: SystemRecord) -> Self {
        Self {
            id: record.id,
            admin_email: record.admin_email,
            limits_config: record.limits_config,
            is_active: record.is_active,
            created_at: record.created_at,
        }
    }
}

impl From<SystemDomainRecord> for SystemDomainResponse {
    fn from(record: SystemDomainRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            domain: record.domain,
            webhook_url: record.webhook_url,
            is_active: record.is_active,
            created_at: record.created_at,
            manager_address: String::new(),
            agent_signature: String::new(),
            agent_persona: String::new(),
        }
    }
}

impl From<WhitelistRecord> for WhitelistResponse {
    fn from(record: WhitelistRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            domain_addr: record.domain_addr,
            direction: record.direction,
            value: record.value,
            description: record.description,
            is_active: record.is_active,
            created_at: record.created_at,
            category: record.category,
        }
    }
}

// ── Agent State ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentStatePutRequest {
    pub value: String,
}

// ── Contacts (semantic profile + name index) ──────────────────

#[derive(Debug, Deserialize)]
pub struct ContactProfileRequest {
    pub profile: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactsByNameQuery {
    #[serde(default)]
    pub name: Option<String>,
    /// Comma-separated address list for batch profile lookup
    /// (e.g. `?addresses=alice@x.com,bob@x.com`).
    #[serde(default)]
    pub addresses: Option<String>,
}

// ── Probe Webhook ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProbeWebhookRequest {
    /// host:port to probe (e.g. "192.168.1.100:38080")
    pub addr: String,
}

// ── Single-slot lock unit tests ────────────────────────────────────

#[cfg(test)]
mod slot_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn slot_fresh_acquire_and_refresh_never_shortens() {
        let lock = SingleSlotLock::new();
        assert!(lock.try_acquire(1, "a", Duration::from_secs(60)));
        // Same client refreshes with a shorter lease: deadline unchanged.
        assert!(lock.try_acquire(1, "a", Duration::from_secs(30)));
        // Different client is rejected while the slot is live.
        assert!(!lock.try_acquire(1, "b", Duration::from_secs(60)));
    }

    #[test]
    fn slot_lease_expiry_takeover() {
        let lock = SingleSlotLock::new();
        assert!(lock.try_acquire(2, "a", Duration::from_millis(30)));
        assert!(!lock.try_acquire(2, "b", Duration::from_secs(60)));
        std::thread::sleep(Duration::from_millis(80));
        assert!(lock.try_acquire(2, "b", Duration::from_secs(60)));
    }

    #[test]
    fn slot_rotation_grace_same_client_only() {
        let lock = SingleSlotLock::new();
        assert!(lock.try_acquire(3, "a", Duration::from_secs(600)));
        let guard = SlotGuard::new(lock.clone(), 3, "a");
        guard.release_on_rotation();
        // Same client re-acquires during grace (clears it, goes active).
        assert!(lock.try_acquire(3, "a", Duration::from_secs(60)));
        // Now actively held again ⇒ a different client is 409.
        assert!(!lock.try_acquire(3, "b", Duration::from_secs(60)));
    }

    #[test]
    fn slot_rotation_grace_blocks_stranger_until_expiry() {
        let lock = SingleSlotLock::new();
        assert!(lock.try_acquire(4, "a", Duration::from_secs(600)));
        // Direct release with a 40ms grace (the handler uses SLOT_GRACE_SECS;
        // this exercises the same path on a short window).
        lock.release(4, "a", Duration::from_millis(40));
        assert!(
            !lock.try_acquire(4, "b", Duration::from_secs(60)),
            "stranger must be 409 during the grace window"
        );
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            lock.try_acquire(4, "b", Duration::from_secs(60)),
            "stranger takes over after the grace expires"
        );
    }

    #[test]
    fn slot_drop_zero_grace_immediate_takeover() {
        let lock = SingleSlotLock::new();
        {
            let _guard = SlotGuard::new(lock.clone(), 5, "a");
        } // drop ⇒ release with zero grace
        assert!(lock.try_acquire(5, "b", Duration::from_secs(60)));
    }
}
