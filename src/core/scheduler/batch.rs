use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::smtp::sender::SmtpRelay;

use super::deliver::{cascade_delete_attachment, cleanup_completed_email};

use super::flows::{handle_overlimit, periodic_inspection, process_expired_attachments};

/// In-flight email IDs currently being processed by the trigger path.
/// The interval batch skips these to avoid duplicate concurrent delivery.
pub type InflightSet = Arc<Mutex<std::collections::HashSet<String>>>;

/// Create an empty inflight set.
pub fn new_inflight_set() -> InflightSet {
    Arc::new(Mutex::new(std::collections::HashSet::new()))
}

/// How long an email may sit in `readying` before Flow 0 treats it as a
/// crash orphan (process died between insert and trigger claim, or the
/// trigger was dropped by a full channel).
///
/// The legitimate preparation window is ~50-100ms (attachment save loop for
/// SMTP inbound; a few local DB ops for API paths), so 30s is a 300x margin.
/// Lowering it risks sweeping an in-flight SMTP attachment save (which would
/// re-introduce the early-delivery race the state machine eliminates).
const READYING_STUCK_SECS: i64 = 30;

// ── Main scheduler loop ────────────────────────────────────────────

/// Run all flows in one batch cycle: readying-sweep, overlimit, retry,
/// attachment expiry, expired delivered.
pub(crate) async fn process_batch(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    http_client: &reqwest::Client,
    smtp_relay: &Option<SmtpRelay>,
    metrics: &Metrics,
    batch_size: i32,
    inflight: &InflightSet,
    trigger: &tokio::sync::mpsc::Sender<String>,
) {
    // ── Flow 0: Stuck-`readying` crash recovery ──
    sweep_stuck_readying(email_factory, attachment_factory, config, batch_size).await;

    // ── Flow 1: Overlimit handling ──
    match email_factory.get_overlimit(batch_size).await {
        Ok(records) if !records.is_empty() => {
            info!(
                operation = "overlimit_batch",
                count = records.len(),
                "Overlimit batch — sending auto-replies"
            );
            for record in &records {
                handle_overlimit(email_factory, attachment_factory, config, record, metrics, Some(trigger)).await;
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
                    Some(trigger),
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
                        cleanup_completed_email(attachment_factory, email_factory, record)
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

// ── Flow 0: Stuck-`readying` crash recovery ────────────────────────

/// Recover emails stuck in `readying` past the stuck threshold.
///
/// Every email is born `readying` and is claimed by its first-delivery
/// trigger before the tick can see it. If the process dies between insert
/// and claim — or the trigger is dropped by a full channel — the email would
/// otherwise sit in `readying` forever (the tick only reads `ready`).
///
/// Three-branch data discriminator (zero-loss where possible):
/// - **A: attachments JSON written** → payload complete (the save loop ended
///   or the path never wrote attachments after insert). Flip to `ready`;
///   the next tick delivers it. Covers: trigger dropped, crash after the
///   attachments UPDATE, all API/notification paths.
/// - **B: attachments JSON missing but attachment meta rows reference this
///   email** → the save loop was interrupted mid-way: partial files/metadata
///   on disk, incomplete payload. Discard: cascade-delete the partial
///   attachments, then delete the email row. We never deliver a broken
///   attachment set.
/// - **C: attachments JSON missing, no meta rows** → attachment-less email
///   (or crash within the first nanoseconds of the save loop). Flip to
///   `ready`.
async fn sweep_stuck_readying(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    _config: &Config,
    batch_size: i32,
) {
    let cutoff = chrono::Utc::now()
        .checked_sub_signed(chrono::Duration::seconds(READYING_STUCK_SECS))
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let records = match email_factory.get_stuck_readying(&cutoff, batch_size).await {
        Ok(r) => r,
        Err(e) => {
            error!(operation="fetch_stuck_readying_failed", %e, "Failed to fetch stuck readying emails");
            return;
        }
    };
    if records.is_empty() {
        return;
    }

    for record in &records {
        // Branch discriminator. The attachments JSON (record.attachments) is
        // the single UPDATE that closes the preparation phase, so:
        //   JSON present  → preparation completed (or path never wrote after
        //                   insert) → payload complete.
        //   JSON missing  → look at attachment_meta rows referencing this
        //                   email: present → save loop was interrupted
        //                   mid-way (partial files/meta on disk) → discard.
        let json_complete = record.attachments.as_deref().map_or(false, |s| !s.is_empty());
        let meta_ids: Vec<String> = if json_complete {
            // Delivery reads the JSON, not the meta rows; use JSON ids.
            record.attachment_ids()
        } else {
            attachment_factory
                .list_by_mail_id(&record.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.id.clone())
                .collect()
        };

        if !json_complete && !meta_ids.is_empty() {
            // Branch B: partial save in progress — never deliver a broken set.
            warn!(
                operation = "stuck_readying_discarded",
                email_id = %record.id,
                attachment_count = meta_ids.len(),
                "Discarding partially-prepared email (crash mid-attachment-save)"
            );
            discard_partial_email(email_factory, attachment_factory, record, &meta_ids).await;
            continue;
        }

        // Branch A (JSON complete) or C (no attachments, no meta): flip to
        // ready and let the next tick deliver. The CAS flip is a no-op if a
        // trigger claimed the email in the meantime.
        match email_factory.flip_readying_to_ready(&record.id).await {
            Ok(true) => {
                warn!(
                    operation = "stuck_readying_recovered",
                    email_id = %record.id,
                    branch = if json_complete { "A_complete" } else { "C_no_attachments" },
                    "Recovering stuck readying email → ready (tick will deliver)"
                );
            }
            Ok(false) => {
                debug!(email_id = %record.id, "Stuck readying email already claimed (trigger won the race)");
            }
            Err(e) => {
                error!(operation="stuck_readying_flip_failed", email_id = %record.id, %e, "Failed to flip stuck readying email");
            }
        }
    }
}

/// Branch B cleanup: cascade-delete the partial attachments, then delete the
/// email row. Reuses the shared cascade so file/MIME/permission/meta removal
/// matches the normal completion path.
async fn discard_partial_email(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    record: &crate::core::email::storage::EmailRecord,
    attachment_ids: &[String],
) {
    for attachment_id in attachment_ids {
        let extension = attachment_factory
            .get_meta(attachment_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.file_extension().to_string())
            .unwrap_or_else(|| "bin".to_string());
        let perm_count = attachment_factory.count_permissions(attachment_id).await.unwrap_or(0);
        let mail_count = attachment_factory.count_mail_ids(attachment_id).await.unwrap_or(0);
        cascade_delete_attachment(
            attachment_factory,
            email_factory,
            attachment_id,
            &extension,
            &record.sender,
            perm_count,
            mail_count,
            &record.id,
        )
        .await;
    }
    if let Err(e) = email_factory.delete(&record.id).await {
        error!(
            operation = "stuck_readying_delete_failed",
            email_id = %record.id,
            %e,
            "Failed to delete partially-prepared email row"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::strategy::BaseSystemStore;
    use crate::core::config::Config;
    use crate::core::storage::Database;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Ctx {
        db: Database,
        ef: EmailFactory,
        af: AttachmentFactory,
    }

    fn temp_ctx() -> Ctx {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("amailgw-sweep-{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(&dir.join("aimail.db"), 4, None).unwrap();
        db.init_global();
        let arc = std::sync::Arc::new(db.clone());
        let att_dir = dir.join("attachments");
        std::fs::create_dir_all(&att_dir).unwrap();
        let ef = EmailFactory::new(arc.clone(), att_dir.clone(), Arc::new(BaseSystemStore));
        let af = AttachmentFactory::new(arc, att_dir);
        Ctx { db, ef, af }
    }

    /// Backdate an email's created_at so it is older than the 30s stuck
    /// threshold (the sweep only touches old rows — a fresh `readying` email
    /// mid-save must never be swept).
    async fn backdate(db: &Database, id: &str) {
        let id = id.to_string();
        db.call(move |conn| {
            conn.execute(
                "UPDATE emails SET created_at = datetime('now', '-60 seconds') WHERE id = ?1",
                rusqlite::params![id],
            )?;
            Ok(())
        }).await.unwrap();
    }

    async fn insert_readying(ef: &EmailFactory, id: &str) {
        ef.create_inbound(id, "sys1", "ext@ext.com",
            r#"{"to":["a@x.com"],"cc":[],"rcpt":["a@x.com"]}"#,
            "s", "b", None, None, None, 3).await.unwrap();
    }

    #[tokio::test]
    async fn sweep_branch_a_complete_json_flips_to_ready() {
        // Branch A: attachments JSON written → payload complete → flip ready.
        let ctx = temp_ctx();
        insert_readying(&ctx.ef, "sa").await;
        backdate(&ctx.db, "sa").await;
        // The save loop finished: attachments JSON is present.
        ctx.ef.update_email_attachments("sa", r#"[{"attachment_id":"att1","filename":"a.txt","content_type":"text/plain"}]"#)
            .await.unwrap();

        sweep_stuck_readying(&ctx.ef, &ctx.af, &Config::default(), 10).await;

        let rec = ctx.ef.get("sa").await.unwrap().unwrap();
        assert_eq!(rec.status, "ready", "branch A: complete payload flips to ready");
    }

    #[tokio::test]
    async fn sweep_branch_b_partial_meta_discards() {
        // Branch B: JSON missing but attachment meta rows reference the
        // email → crash mid-save → discard the email and the partial meta.
        let ctx = temp_ctx();
        insert_readying(&ctx.ef, "sb").await;
        backdate(&ctx.db, "sb").await;
        // A meta row was written but the attachments JSON never landed.
        ctx.db.insert_attachment_meta("att-b", "b.txt", Some("text/plain"),
            "ext@ext.com", Some(&["sb".to_string()])).await.unwrap();

        sweep_stuck_readying(&ctx.ef, &ctx.af, &Config::default(), 10).await;

        assert!(ctx.ef.get("sb").await.unwrap().is_none(),
            "branch B: partial email is deleted");
        assert!(ctx.db.get_attachment_meta("att-b").await.unwrap().is_none(),
            "branch B: partial attachment meta is cascade-deleted");
    }

    #[tokio::test]
    async fn sweep_branch_c_no_attachments_flips_to_ready() {
        // Branch C: no JSON, no meta rows → attachment-less email → flip ready.
        let ctx = temp_ctx();
        insert_readying(&ctx.ef, "sc").await;
        backdate(&ctx.db, "sc").await;

        sweep_stuck_readying(&ctx.ef, &ctx.af, &Config::default(), 10).await;

        let rec = ctx.ef.get("sc").await.unwrap().unwrap();
        assert_eq!(rec.status, "ready", "branch C: attachment-less flips to ready");
    }

    #[tokio::test]
    async fn sweep_ignores_fresh_readying() {
        // A `readying` email still within the legitimate preparation window
        // (created < 30s ago) must NOT be swept — sweeping it mid-save would
        // re-introduce the early-delivery race.
        let ctx = temp_ctx();
        insert_readying(&ctx.ef, "sf").await;
        // No backdate: created_at = now.

        sweep_stuck_readying(&ctx.ef, &ctx.af, &Config::default(), 10).await;

        let rec = ctx.ef.get("sf").await.unwrap().unwrap();
        assert_eq!(rec.status, "readying", "fresh readying email is untouched");
    }
}
