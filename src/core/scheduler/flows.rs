use tracing::{debug, error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::email::storage::EmailRecord;
use crate::core::smtp::sender::SmtpRelay;

use super::backoff::{calculate_backoff, detect_delivery_type};

use super::deliver::{cleanup_completed_email, deliver_smtp, deliver_webhook};

use super::exhaustion::{insert_exhaustion_auto_reply, insert_exhaustion_notification};

// ── Post-delivery finalization ──────────────────────────────────────

/// After a successful SMTP delivery, decide whether to keep the record for
/// NDR bounce correlation (MX direct mode) or finalize immediately (relay mode).
///
/// - **MX direct mode** (no relay configured): marks as "delivered" — the record
///   stays in the DB for `delivery_window_secs` so incoming bounce/NDR emails
///   can be matched. The expired_delivered batch in `batch.rs` finalizes them later.
/// - **Relay mode** (upstream SMTP configured): immediately completes + cleans up,
///   since the relay handles bounces on its own.
async fn finalize_after_delivery(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    record: &EmailRecord,
    delivery_type: &str,
) {
    let direct_delivery = config
        .relay
        .smtp_server
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true);
    if direct_delivery && delivery_type != "webhook" {
        if let Err(e) = email_factory.mark_delivered(&record.id).await {
            error!(email_id = %record.id, %e, "Failed to mark delivered");
        }
    } else {
        if let Err(e) = email_factory.complete(&record.id).await {
            error!(email_id = %record.id, %e, "Failed to mark completed");
        } else {
            cleanup_completed_email(attachment_factory, email_factory, record).await;
        }
    }
}

// ── Shared exhaustion path ─────────────────────────────────────────

/// Exhaust an email: record final send_count, insert auto-reply/notification,
/// record metrics, then complete + cleanup. Shared by handle_overlimit,
/// periodic_inspection and immediate_forward (AUDIT-1 P2-8 de-duplication).
pub(crate) async fn exhaust_email(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    record: &EmailRecord,
    metrics: &Metrics,
    delivery_type: &str,
    final_send_count: Option<i32>,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
) {
    if let Some(count) = final_send_count {
        let _ = email_factory.update_send_count(&record.id, count).await;
    }
    if record.direction == "inbound" {
        insert_exhaustion_auto_reply(config, email_factory, record, metrics, trigger).await;
    } else if record.direction == "outbound" {
        insert_exhaustion_notification(email_factory, attachment_factory, config, record, trigger).await;
    }
    match delivery_type {
        "webhook" => metrics.inc_webhook_exhausted(),
        _ => metrics.inc_relay_failed(),
    }
    match email_factory.complete(&record.id).await {
        Ok(Some(_)) => {
            info!(email_id = %record.id, "Exhausted email marked completed");
            cleanup_completed_email(attachment_factory, email_factory, record).await;
        }
        Ok(None) => warn!(email_id = %record.id, "Exhausted email not found (already processed?)"),
        Err(e) => error!(email_id = %record.id, %e, "Failed to mark exhausted email as completed"),
    }
}

// ── Flow 1: Overlimit handling ─────────────────────────────────────

/// Process an exhausted email: send auto-reply and mark completed.
pub(crate) async fn handle_overlimit(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    record: &EmailRecord,
    metrics: &Metrics,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
) {
    let delivery_type = detect_delivery_type(record);

    info!(
        operation="email_exhausted",
        email_id = %record.id,
        attempts = record.send_count,
        max_attempts = record.max_attempts,
        delivery_type,
        "Email exhausted — sending auto-reply and marking completed"
    );

    exhaust_email(
        email_factory,
        attachment_factory,
        config,
        record,
        metrics,
        delivery_type,
        None,
        trigger,
    )
    .await;
}

// ── Flow 2: Periodic retry inspection ──────────────────────────────

/// Process a retry-due email: attempt delivery, reschedule with backoff or promote to overlimit.
pub(crate) async fn periodic_inspection(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    http_client: &reqwest::Client,
    smtp_relay: &Option<SmtpRelay>,
    record: &EmailRecord,
    metrics: &Metrics,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
) {
    let delivery_type = detect_delivery_type(record);
    let new_send_count = record.send_count + 1;
    let will_exhaust = new_send_count >= record.max_attempts;

    info!(
        email_id = %record.id,
        attempts = record.send_count,
        next_count = new_send_count,
        max_attempts = record.max_attempts,
        delivery_type,
        "Periodic retry inspection"
    );

    // Attempt delivery
    let last_error = match delivery_type {
        "webhook" => deliver_webhook(email_factory, http_client, config, record, metrics).await,
        _ => deliver_smtp(smtp_relay, record, metrics, config, email_factory).await,
    };

    // Success → mark completed or delivered
    if last_error.is_none() {
        info!(email_id = %record.id, "Retry delivery succeeded, marking completed");
        finalize_after_delivery(email_factory, attachment_factory, config, record, delivery_type).await;
        return;
    }

    // Failure
    if will_exhaust {
        info!(
            email_id = %record.id,
            "Retry delivery failed and attempts exhausted — promoting to overlimit"
        );
        exhaust_email(
            email_factory,
            attachment_factory,
            config,
            record,
            metrics,
            delivery_type,
            Some(new_send_count),
            trigger,
        )
        .await;
        return;
    }

    // Schedule next retry with exponential backoff
    match delivery_type {
        "webhook" => metrics.inc_webhook_retried(),
        _ => metrics.inc_relay_retried(),
    }
    let backoff_secs = calculate_backoff(
        new_send_count as u64,
        config.retry.initial_backoff_secs,
        config.retry.multiplier,
        config.retry.max_backoff_secs,
    );

    let next_retry = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(backoff_secs as i64))
        .unwrap_or_else(|| chrono::Utc::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    if let Err(e) = email_factory
        .ready_retry(&record.id, new_send_count, &next_retry)
        .await
    {
        // Fallback: compute a minimal backoff to prevent tight retry loop
        error!(email_id = %record.id, %e, "Failed to schedule retry, applying fallback backoff");
        let fallback_next = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(60))
            .unwrap_or_else(|| chrono::Utc::now())
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Err(e2) = email_factory
            .ready_retry(&record.id, record.send_count, &fallback_next)
            .await
        {
            error!(email_id = %record.id, %e2, "Fallback retry scheduling also failed, giving up");
        }
    } else {
        info!(
            email_id = %record.id,
            attempts = new_send_count,
            next_retry_in_secs = backoff_secs,
            "Retry scheduled"
        );
    }
}

// ── Flow 3: Immediate forward ──────────────────────────────────────

/// Deliver a new email immediately. On success → completed/delivered. On failure → enter retry cycle.
pub(crate) async fn immediate_forward(
    email_factory: &EmailFactory,
    attachment_factory: &AttachmentFactory,
    config: &Config,
    http_client: &reqwest::Client,
    smtp_relay: &Option<SmtpRelay>,
    record: &EmailRecord,
    metrics: &Metrics,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
) {
    let delivery_type = detect_delivery_type(record);

    info!(
        email_id = %record.id,
        delivery_type,
        "Immediate forward (first attempt)"
    );

    // Attempt delivery
    let last_error = match delivery_type {
        "webhook" => deliver_webhook(email_factory, http_client, config, record, metrics).await,
        _ => deliver_smtp(smtp_relay, record, metrics, config, email_factory).await,
    };

    if last_error.is_none() {
        debug!(email_id = %record.id, "Immediate forward succeeded, marking completed");
        finalize_after_delivery(email_factory, attachment_factory, config, record, delivery_type).await;
        return;
    }

    // First attempt failed — enter retry cycle
    let new_send_count = 1; // First attempt just failed
    let will_exhaust = new_send_count >= record.max_attempts;

    if will_exhaust {
        info!(
            email_id = %record.id,
            "Immediate forward failed and max_attempts=1 — marking completed"
        );
        exhaust_email(
            email_factory,
            attachment_factory,
            config,
            record,
            metrics,
            delivery_type,
            Some(new_send_count),
            trigger,
        )
        .await;
        return;
    }

    // Schedule first retry with backoff
    match delivery_type {
        "webhook" => metrics.inc_webhook_retried(),
        _ => metrics.inc_relay_retried(),
    }
    let backoff_secs = calculate_backoff(
        new_send_count as u64,
        config.retry.initial_backoff_secs,
        config.retry.multiplier,
        config.retry.max_backoff_secs,
    );

    let next_retry = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(backoff_secs as i64))
        .unwrap_or_else(|| chrono::Utc::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    if let Err(e) = email_factory
        .ready_retry(&record.id, new_send_count, &next_retry)
        .await
    {
        error!(email_id = %record.id, %e, "Failed to schedule initial retry");
    } else {
        info!(
            email_id = %record.id,
            attempts = 1,
            next_retry_in_secs = backoff_secs,
            "Initial failure — retry scheduled"
        );
    }
}

// ── Flow 4: Attachment expiry scan ─────────────────────────────────

/// Delete expired attachment files, MIME copies, permissions, and metadata.
/// Shared attachments: only the mail_id reference is removed (file stays for other emails).
/// After cleanup, cascades to parent email cleanup if no attachments remain.
pub(crate) async fn process_expired_attachments(
    attachment_factory: &AttachmentFactory,
    email_factory: &EmailFactory,
    config: &Config,
    metrics: &Metrics,
    batch_size: i32,
) {
    // Calculate expiry cutoff
    let lifetime = chrono::Duration::hours(config.storage.attachment_lifetime_hours as i64);
    let expiry_cutoff = chrono::Utc::now()
        .checked_sub_signed(lifetime)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let expired = match attachment_factory
        .list_expired_before(&expiry_cutoff, batch_size as i64)
        .await
    {
        Ok(records) => records,
        Err(e) => {
            error!(%e, "Failed to fetch expired attachments for cleanup");
            return;
        }
    };

    if expired.is_empty() {
        return;
    }

    info!(
        count = expired.len(),
        cutoff = %expiry_cutoff,
        "Attachment expiry scan — cleaning up expired attachments"
    );

    let mut touched_mail_ids: Vec<String> = Vec::new();

    for attachment in &expired {
        // Compute hash prefix from sender email
        let extension = attachment.file_extension();

        // ── Check if this attachment is shared across multiple emails ──
        let mail_count = attachment_factory
            .count_mail_ids(&attachment.id)
            .await
            .unwrap_or(1);
        let perm_count = attachment_factory
            .count_permissions(&attachment.id)
            .await
            .unwrap_or(0);

        // Collect mail_ids referenced by this attachment for later cascade
        if let Some(ref mail_ids) = attachment.mail_id {
            for mid in mail_ids {
                if !touched_mail_ids.contains(mid) {
                    touched_mail_ids.push(mid.clone());
                }
            }
        }

        if perm_count == 0 && mail_count <= 1 {
            // ── Full cascade: no other references ──
            // Track file size before deletion for metrics
            let full_path =
                attachment_factory.file_path(&attachment.sender_email, &attachment.id, &extension);
            let file_size = tokio::task::spawn_blocking(move || {
                std::fs::metadata(&full_path).map(|m| m.len()).unwrap_or(0)
            })
            .await
            .unwrap_or(0);

            super::deliver::cascade_delete_attachment(
                attachment_factory,
                email_factory,
                &attachment.id,
                &extension,
                &attachment.sender_email,
                perm_count,
                mail_count,
                &attachment.id,
            )
            .await;

            // Update metrics
            metrics.inc_attachment_expired_deleted();
            metrics.add_storage_attachments_bytes(-(file_size as i64));

            info!(
                attachment_id = %attachment.id,
                filename = %attachment.filename,
                created_at = %attachment.created_at,
                "Expired attachment fully cleaned up"
            );
        } else {
            // ── Shared attachment: only remove expired mail_id references ──
            info!(
                attachment_id = %attachment.id,
                perm_count,
                mail_count,
                "Attachment still shared — removing mail_id references only"
            );
            if let Some(ref mail_ids) = attachment.mail_id {
                for mid in mail_ids {
                    if let Err(e) = attachment_factory.remove_mail_id(&attachment.id, mid).await {
                        warn!(
                            attachment_id = %attachment.id,
                            mail_id = %mid,
                            %e,
                            "Failed to remove shared mail_id reference during expiry (non-fatal)"
                        );
                    }
                }
            }
        }
    }

    // ── Cascade: clean up parent emails with no remaining attachments ──
    for mail_id in &touched_mail_ids {
        // Check if this email still has any live attachments
        match attachment_factory.list_by_mail_id(mail_id).await {
            Ok(remaining) if remaining.is_empty() => {
                // No attachments left — do full email cascade cleanup
                info!(
                    %mail_id,
                    "No attachments remain after expiry — cascading email cleanup"
                );
                match email_factory.get(mail_id).await {
                    Ok(Some(email_record)) => {
                        cleanup_completed_email(
                            attachment_factory,
                            email_factory,
                            &email_record,
                        )
                        .await;
                    }
                    Ok(None) => {
                        debug!(%mail_id, "Email already deleted, skipping cascade");
                    }
                    Err(e) => {
                        warn!(%mail_id, %e, "Failed to fetch email for cascade cleanup");
                    }
                }
            }
            Ok(remaining) => {
                debug!(
                    %mail_id,
                    remaining_count = remaining.len(),
                    "Email still has live attachments — skipping email cascade"
                );
            }
            Err(e) => {
                warn!(%mail_id, %e, "Failed to check remaining attachments for cascade");
            }
        }
    }
}
