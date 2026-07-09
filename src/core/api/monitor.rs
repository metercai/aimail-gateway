//! Monitor endpoints.

use axum::response::Json;

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

use crate::core::api::types::HttpState;

/// GET /health — Service health check.
pub async fn health_check(state: axum::extract::State<HttpState>) -> Json<HealthStatus> {
    Json(HealthStatus {
        status: "ok",
        uptime_secs: state.metrics.uptime_secs(),
        version: state.metrics.version(),
        owner_email: state.config.admin.email.clone(),
    })
}

/// In-process counters for webhook delivery metrics.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Debug)]
struct MetricsInner {
    started_at: Instant,
    version: &'static str,
    webhook_sent: AtomicU64,
    webhook_failed: AtomicU64,
    webhook_retried: AtomicU64,
    webhook_exhausted: AtomicU64,
    auto_reply_sent: AtomicU64,
    relay_sent: AtomicU64,
    relay_failed: AtomicU64,
    relay_retried: AtomicU64,
    rate_limited: AtomicU64,
    whitelist_matches: AtomicU64,
    ip_blacklist_hits: AtomicU64,
    ip_whitelist_rescues: AtomicU64,
    trigger_dropped: AtomicU64,
    smtp_connections_rejected: AtomicU64,
    emails_received_smtp: AtomicU64,
    emails_queued_api: AtomicU64,
    attachments_uploaded: AtomicU64,
    attachments_downloaded: AtomicU64,
    attachment_unauthorized_access: AtomicU64,
    attachment_expired_deleted: AtomicU64,
    scheduler_pending_count: AtomicI64,
    storage_attachments_bytes: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::with_version("base")
    }

    pub fn with_version(version: &'static str) -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                started_at: Instant::now(),
                version,
                webhook_sent: AtomicU64::new(0),
                webhook_failed: AtomicU64::new(0),
                webhook_retried: AtomicU64::new(0),
                webhook_exhausted: AtomicU64::new(0),
                auto_reply_sent: AtomicU64::new(0),
                relay_sent: AtomicU64::new(0),
                relay_failed: AtomicU64::new(0),
                relay_retried: AtomicU64::new(0),
                rate_limited: AtomicU64::new(0),
                whitelist_matches: AtomicU64::new(0),
                ip_blacklist_hits: AtomicU64::new(0),
                ip_whitelist_rescues: AtomicU64::new(0),
                trigger_dropped: AtomicU64::new(0),
                smtp_connections_rejected: AtomicU64::new(0),
                emails_received_smtp: AtomicU64::new(0),
                emails_queued_api: AtomicU64::new(0),
                attachments_uploaded: AtomicU64::new(0),
                attachments_downloaded: AtomicU64::new(0),
                attachment_unauthorized_access: AtomicU64::new(0),
                attachment_expired_deleted: AtomicU64::new(0),
                scheduler_pending_count: AtomicI64::new(0),
                storage_attachments_bytes: AtomicI64::new(0),
            }),
        }
    }

    pub fn inc_webhook_sent(&self) {
        self.inner.webhook_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_failed(&self) {
        self.inner.webhook_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_retried(&self) {
        self.inner.webhook_retried.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_exhausted(&self) {
        self.inner.webhook_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auto_reply_sent(&self) {
        self.inner.auto_reply_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_sent(&self) {
        self.inner.relay_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_failed(&self) {
        self.inner.relay_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_retried(&self) {
        self.inner.relay_retried.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limited(&self) {
        self.inner.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_whitelist_matches(&self) {
        self.inner.whitelist_matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ip_blacklist_hits(&self) {
        self.inner.ip_blacklist_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ip_whitelist_rescues(&self) {
        self.inner
            .ip_whitelist_rescues
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_trigger_dropped(&self) {
        self.inner.trigger_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_smtp_connections_rejected(&self) {
        self.inner
            .smtp_connections_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_emails_received_smtp(&self) {
        self.inner
            .emails_received_smtp
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_emails_queued_api(&self) {
        self.inner.emails_queued_api.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_attachments_uploaded(&self) {
        self.inner
            .attachments_uploaded
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_attachments_downloaded(&self) {
        self.inner
            .attachments_downloaded
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_attachment_unauthorized_access(&self) {
        self.inner
            .attachment_unauthorized_access
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_attachment_expired_deleted(&self) {
        self.inner
            .attachment_expired_deleted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Set the scheduler pending count to an absolute value.
    pub fn set_scheduler_pending_count(&self, value: i64) {
        self.inner
            .scheduler_pending_count
            .store(value, Ordering::Release);
    }

    /// Add (or subtract) bytes to the storage attachment gauge.
    pub fn add_storage_attachments_bytes(&self, delta: i64) {
        self.inner
            .storage_attachments_bytes
            .fetch_add(delta, Ordering::AcqRel);
    }

    /// Return server uptime in seconds since Metrics creation.
    pub fn uptime_secs(&self) -> u64 {
        self.inner.started_at.elapsed().as_secs()
    }

    /// Return the version string (e.g. "advanced-4457df2").
    pub fn version(&self) -> &'static str {
        self.inner.version
    }

    /// Snapshot all counters as a JSON-serializable struct.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            webhook_sent: self.inner.webhook_sent.load(Ordering::Relaxed),
            webhook_failed: self.inner.webhook_failed.load(Ordering::Relaxed),
            webhook_retried: self.inner.webhook_retried.load(Ordering::Relaxed),
            webhook_exhausted: self.inner.webhook_exhausted.load(Ordering::Relaxed),
            auto_reply_sent: self.inner.auto_reply_sent.load(Ordering::Relaxed),
            relay_sent: self.inner.relay_sent.load(Ordering::Relaxed),
            relay_failed: self.inner.relay_failed.load(Ordering::Relaxed),
            rate_limited: self.inner.rate_limited.load(Ordering::Relaxed),
            whitelist_matches: self.inner.whitelist_matches.load(Ordering::Relaxed),
            ip_blacklist_hits: self.inner.ip_blacklist_hits.load(Ordering::Relaxed),
            ip_whitelist_rescues: self.inner.ip_whitelist_rescues.load(Ordering::Relaxed),
            smtp_connections_rejected: self.inner.smtp_connections_rejected.load(Ordering::Relaxed),
            emails_received_smtp: self.inner.emails_received_smtp.load(Ordering::Relaxed),
            emails_queued_api: self.inner.emails_queued_api.load(Ordering::Relaxed),
            attachments_uploaded: self.inner.attachments_uploaded.load(Ordering::Relaxed),
            attachments_downloaded: self.inner.attachments_downloaded.load(Ordering::Relaxed),
            attachment_unauthorized_access: self
                .inner
                .attachment_unauthorized_access
                .load(Ordering::Relaxed),
            attachment_expired_deleted: self
                .inner
                .attachment_expired_deleted
                .load(Ordering::Relaxed),
            scheduler_pending_count: self.inner.scheduler_pending_count.load(Ordering::Relaxed),
            storage_attachments_bytes: self.inner.storage_attachments_bytes.load(Ordering::Relaxed),
        }
    }
}

// ── JSON snapshot ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub webhook_sent: u64,
    pub webhook_failed: u64,
    pub webhook_retried: u64,
    pub webhook_exhausted: u64,
    pub auto_reply_sent: u64,
    pub relay_sent: u64,
    pub relay_failed: u64,
    pub rate_limited: u64,
    pub whitelist_matches: u64,
    pub ip_blacklist_hits: u64,
    pub ip_whitelist_rescues: u64,
    pub smtp_connections_rejected: u64,
    pub emails_received_smtp: u64,
    pub emails_queued_api: u64,
    pub attachments_uploaded: u64,
    pub attachments_downloaded: u64,
    pub attachment_unauthorized_access: u64,
    pub attachment_expired_deleted: u64,
    pub scheduler_pending_count: i64,
    pub storage_attachments_bytes: i64,
}

// ── Health check response ────────────────────────────────────────────

/// Health status response.
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_email: Option<String>,
}
