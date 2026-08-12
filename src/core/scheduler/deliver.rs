use tracing::{debug, error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::email::storage::EmailRecord;
use crate::core::smtp::sender::SmtpRelay;

// ── Webhook URL resolution ─────────────────────────────────────────

/// Resolve the webhook URL for outbound delivery by sender address.
pub(crate) async fn resolve_webhook_url(
    email_factory: &EmailFactory,
    sender: &str,
) -> Option<String> {
    email_factory.env_factory.resolve_webhook_url(sender).await
}

// ── Delivery helpers ───────────────────────────────────────────────

/// Deliver email via SMTP relay. Returns None on success, Some(error) on failure.
pub(crate) async fn deliver_smtp(
    smtp_relay: &Option<SmtpRelay>,
    record: &EmailRecord,
    metrics: &Metrics,
    config: &Config,
    email_factory: &EmailFactory,
) -> Option<String> {
    let relay = match smtp_relay {
        Some(r) => r,
        None => {
            let msg = "SmtpRelay not configured".to_string();
            warn!(operation = "delivery_failed", email_id = %record.id, error = %msg, "SmtpRelay not configured");
            metrics.inc_relay_failed();
            return Some(msg);
        }
    };

    let attachment_data = load_attachment_data(record, config, email_factory).await;

    match relay.send_email(record, attachment_data.as_deref()).await {
        Ok(()) => {
            metrics.inc_relay_sent();
            None
        }
        Err(e) => {
            error!(operation = "delivery_retry", email_id = %record.id, error = %e, "SMTP delivery failed");
            metrics.inc_relay_failed();
            Some(format!("smtp error: {}", e))
        }
    }
}

/// Parse attachments JSON, load files from disk, return (filename, content_type, data) tuples.
pub(crate) async fn load_attachment_data(
    record: &EmailRecord,
    _config: &Config,
    email_factory: &EmailFactory,
) -> Option<Vec<(String, String, Vec<u8>)>> {
    let attachments_json = record.attachments.as_ref()?;
    let list: Vec<serde_json::Value> = serde_json::from_str(attachments_json).ok()?;
    if list.is_empty() {
        return None;
    }

    let base_dir = email_factory.attachment_hash_dir(&record.sender);

    let mut result: Vec<(String, String, Vec<u8>)> = Vec::new();
    for item in &list {
        let attachment_id = item.get("attachment_id")?.as_str()?;
        let filename = item.get("filename")?.as_str()?;
        let content_type = item.get("content_type")?.as_str()?;

        // Derive file extension from stored filename — uses Path::extension()
        // to match the save-side logic (receiver.rs save_attachment).
        let ext = std::path::Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");

        let filepath = base_dir.join(format!("{}.{}", attachment_id, ext));
        let fp_display = filepath.clone();
        match tokio::task::spawn_blocking(move || std::fs::read(&filepath)).await {
            Ok(Ok(data)) => {
                result.push((filename.to_string(), content_type.to_string(), data));
            }
            Ok(Err(e)) => {
                warn!(
                    operation = "attachment_load_failed",
                    email_id = %record.id,
                    attachment_id,
                    path = %fp_display.display(),
                    error = %e,
                    "Failed to load attachment file for outbound SMTP"
                );
            }
            Err(e) => {
                warn!(
                    operation = "attachment_load_failed",
                    email_id = %record.id,
                    attachment_id,
                    error = %e,
                    "spawn_blocking panicked while reading attachment"
                );
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Deliver email via webhook with DB-driven endpoint traversal.
/// Returns None if all endpoints succeed, Some(error) otherwise.
pub(crate) async fn deliver_webhook(
    email_factory: &EmailFactory,
    client: &reqwest::Client,
    config: &Config,
    record: &EmailRecord,
    metrics: &Metrics,
) -> Option<String> {
    let all_succeeded = crate::core::api::webhook::process_email_webhook(
        &email_factory.env_factory,
        email_factory,
        config,
        client,
        record,
    )
    .await;
    if all_succeeded {
        metrics.inc_webhook_sent();
        None
    } else {
        metrics.inc_webhook_failed();
        Some("multi-endpoint webhook delivery incomplete".to_string())
    }
}

// ── Shared attachment cascade ──────────────────────────────────────

/// Cascade-delete one attachment: file, MIME copy, permissions, metadata, empty dirs.
///
/// This is the shared helper used by both `cleanup_completed_email` and
/// `process_expired_attachments` to avoid duplicated cleanup logic.
///
/// - When `perm_count == 0 && mail_count <= 1`: full cascade (no other references).
/// - Otherwise: shared attachment — only remove this `mail_id` reference.
pub(crate) async fn cascade_delete_attachment(
    attachment_factory: &AttachmentFactory,
    email_factory: &EmailFactory,
    attachment_id: &str,
    extension: &str,
    sender_email: &str,
    perm_count: i64,
    mail_count: i64,
    mail_id: &str,
) {
    if perm_count == 0 && mail_count <= 1 {
        // ── Full cascade: no other references ──

        // 1. Delete the attachment file from disk
        let full_path = attachment_factory.file_path(sender_email, attachment_id, extension);
        let full_path_for_log = full_path.clone();
        match tokio::task::spawn_blocking(move || std::fs::remove_file(&full_path)).await {
            Ok(Ok(())) => {
                debug!(attachment_id, path = %full_path_for_log.display(), "Deleted attachment file");
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(Err(e)) => {
                warn!(attachment_id, %e, "Failed to delete attachment file (non-fatal)");
            }
            Err(join_err) => {
                warn!(attachment_id, error = %join_err, "spawn_blocking panicked during file deletion (non-fatal)");
            }
        }

        // 2. Delete the MIME copy
        let mime_path = email_factory
            .attachment_hash_dir(sender_email)
            .join("mime")
            .join(attachment_id);
        match tokio::task::spawn_blocking(move || std::fs::remove_file(&mime_path)).await {
            Ok(Ok(())) => {
                debug!(attachment_id, "Deleted MIME copy");
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(Err(e)) => {
                warn!(attachment_id, %e, "Failed to delete MIME copy (non-fatal)");
            }
            Err(join_err) => {
                warn!(attachment_id, error = %join_err, "spawn_blocking panicked during MIME deletion (non-fatal)");
            }
        }

        // 3. Revoke download permissions
        if let Err(e) = attachment_factory.revoke_all(attachment_id).await {
            warn!(attachment_id, %e, "Failed to revoke permissions (non-fatal)");
        }

        // 4. Delete attachment metadata
        if let Err(e) = attachment_factory.delete_meta(attachment_id).await {
            warn!(attachment_id, %e, "Failed to delete metadata (non-fatal)");
        }

        // 5. Clean up empty hash-prefix directories
        let hash_dir = email_factory.attachment_hash_dir(sender_email);
        let mime_dir = hash_dir.join("mime");
        let _ = tokio::task::spawn_blocking(move || {
            if std::fs::metadata(&mime_dir).is_ok() {
                let _ = std::fs::remove_dir(&mime_dir);
            }
            if std::fs::metadata(&hash_dir).is_ok() {
                let _ = std::fs::remove_dir(&hash_dir);
            }
        })
        .await;
    } else {
        // ── Shared attachment: only remove this mail_id reference ──
        info!(
            attachment_id, perm_count, mail_count,
            "Attachment shared — removing mail_id reference only"
        );
        if let Err(e) = attachment_factory
            .remove_mail_id(attachment_id, mail_id)
            .await
        {
            warn!(attachment_id, mail_id, %e,
                  "Failed to remove mail_id reference (non-fatal)");
        }
    }
}

// ── Post-completion cleanup ────────────────────────────────────────

/// Cascade-delete email and all associated data after completion: revoke permissions,
/// delete attachment files, MIME copies, metadata, and the email record itself.
/// Shared attachments: only the mail_id reference is removed (file stays for other emails).
/// Delete an email together with its attachments (files, MIME copies,
/// references) using the shared cascade logic. Also deletes the email
/// record itself.
///
/// Public so the advanced edition's product-release path reuses the base
/// deletion semantics instead of re-implementing them.
pub async fn cleanup_completed_email(
    attachment_factory: &AttachmentFactory,
    email_factory: &EmailFactory,
    record: &EmailRecord,
) {
    // Parse attachment IDs from the record's JSON field
    let attachment_ids = record.attachment_ids();
    for attachment_id in &attachment_ids {
        // Determine file extension from attachment metadata
        let extension = attachment_factory
            .get_meta(attachment_id)
            .await
            .ok()
            .flatten()
            .map(|m| m.file_extension().to_string())
            .unwrap_or_else(|| "bin".to_string());

        let perm_count = attachment_factory
            .count_permissions(attachment_id)
            .await
            .unwrap_or(0);
        let mail_count = attachment_factory
            .count_mail_ids(attachment_id)
            .await
            .unwrap_or(0);

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

    // Delete the email record itself
    if let Err(e) = email_factory.delete(&record.id).await {
        error!(
            operation = "cleanup_failed",
            email_id = %record.id,
            error = %e,
            "Failed to delete email during cleanup"
        );
    } else {
        debug!(
            operation = "cleanup_completed",
            email_id = %record.id,
            "Email and associated attachments cleaned up (full cascade)"
        );
    }
}
