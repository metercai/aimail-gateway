use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::smtp::sender::SmtpRelay;

use super::deliver::cleanup_completed_email;

use super::flows::{handle_overlimit, periodic_inspection, process_expired_attachments};

/// In-flight email IDs currently being processed by the trigger path.
/// The interval batch skips these to avoid duplicate concurrent delivery.
pub type InflightSet = Arc<Mutex<std::collections::HashSet<String>>>;

/// Create an empty inflight set.
pub fn new_inflight_set() -> InflightSet {
    Arc::new(Mutex::new(std::collections::HashSet::new()))
}

// ── Main scheduler loop ────────────────────────────────────────────

/// Run all flows in one batch cycle: overlimit, retry, attachment expiry, expired delivered.
pub(crate) async fn process_batch(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    http_client: &reqwest::Client,
    smtp_relay: &Option<SmtpRelay>,
    metrics: &Metrics,
    batch_size: i32,
    inflight: &InflightSet,
) {
    // ── Flow 1: Overlimit handling ──
    match email_factory.get_overlimit(batch_size).await {
        Ok(records) if !records.is_empty() => {
            info!(
                operation = "overlimit_batch",
                count = records.len(),
                "Overlimit batch — sending auto-replies"
            );
            for record in &records {
                handle_overlimit(email_factory, attachment_factory, config, record, metrics).await;
            }
        }
        Ok(_) => { /* no overlimit emails */ }
        Err(e) => {
            error!(operation="fetch_overlimit_failed", %e, "Failed to fetch overlimit emails")
        }
    }

    // ── Flow 2: Periodic retry inspection ──
    match email_factory.get_pending_retry(batch_size).await {
        Ok(records) if !records.is_empty() => {
            info!(
                operation = "retry_batch",
                count = records.len(),
                "Retry batch — periodic inspection"
            );
            // Build a snapshot of inflight IDs once, to avoid holding the lock
            // per-record (reduces lock contention).
            let inflight_ids: std::collections::HashSet<String> = inflight.lock().await.clone();
            for record in &records {
                let record_id = record.id.trim();
                if inflight_ids.contains(record_id) {
                    debug!(email_id = %record.id, "Skipping inflight email (trigger path active)");
                    continue;
                }
                periodic_inspection(
                    email_factory,
                    attachment_factory,
                    config,
                    http_client,
                    smtp_relay,
                    record,
                    metrics,
                )
                .await;
            }
        }
        Ok(_) => { /* no retry-due emails */ }
        Err(e) => {
            error!(operation="fetch_retry_failed", %e, "Failed to fetch pending retry emails")
        }
    }

    // ── Flow 3: Attachment expiry scan ──
    process_expired_attachments(
        attachment_factory,
        email_factory,
        config,
        metrics,
        batch_size,
    )
    .await;

    // ── Flow 4: Expired delivered emails (MX direct mode) ──
    // Emails in "delivered" status past the NDR window get finalized to
    // "completed" and cleaned up (same as relay-mode post-delivery).
    let cutoff = chrono::Utc::now()
        .checked_sub_signed(chrono::Duration::seconds(
            config.relay.delivery_window_secs as i64,
        ))
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default();
    if !cutoff.is_empty() {
        match email_factory
            .get_expired_delivered(&cutoff, batch_size)
            .await
        {
            Ok(records) if !records.is_empty() => {
                info!(
                    operation = "expired_delivered_batch",
                    count = records.len(),
                    "Expired delivered batch — finalizing to completed"
                );
                for record in &records {
                    if let Err(e) = email_factory.complete(&record.id).await {
                        error!(operation="finalize_expired_failed", email_id = %record.id, %e, "Failed to finalize expired delivered email");
                    } else {
                        cleanup_completed_email(attachment_factory, email_factory, config, record)
                            .await;
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                error!(operation="fetch_expired_delivered_failed", %e, "Failed to fetch expired delivered emails")
            }
        }
    }

    // ── Flow 5: Board lifecycle management ──
    crate::board::sweeper::board_sweeper_flow(config);
}
