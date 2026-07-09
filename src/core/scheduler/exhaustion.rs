use tracing::{error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{EmailFactory, AttachmentFactory};
use crate::core::email::storage::EmailRecord;

use super::deliver::resolve_webhook_url;

// ── Exhaustion helpers ───────────────────────────────────────────────

/// Insert an auto-reply email record for an exhausted inbound email.
pub(crate) async fn insert_exhaustion_auto_reply(
    config: &Config,
    email_factory: &EmailFactory,
    record: &EmailRecord,
    metrics: &Metrics,
) {
    let orig_message_id = record.message_id_from_headers();

    // Guard: prevent infinite cascade — system-generated records
    // (notifications, auto-replies) should not recursively create
    // more auto-replies when they themselves exhaust.
    if record.id.starts_with("ar-")
        || record.id.starts_with("wn-")
        || record.subject.contains("[Overlimit]")
        || record.subject.contains("[AmailGW]")
    {
        info!(email_id = %record.id, "Suppressing recursive auto-reply — system-generated record");
        return;
    }

    let auto_reply_from = config
        .relay
        .auto_reply_from
        .as_deref()
        .or(config.admin.email.as_deref())
        .unwrap_or("noreply@localhost");

    if auto_reply_from.is_empty() {
        warn!(operation="auto_reply_from_empty", email_id = %record.id, "auto_reply_from is empty — skipping auto-reply record");
        return;
    }

    let auto_reply_id = format!("ar-{}", uuid::Uuid::new_v4());
    let auto_reply_body = config.relay.auto_reply_body.as_deref().unwrap_or(
        "Your request could not be processed after multiple attempts. Please try again later.",
    );
    let auto_reply_subject = format!(
        "{}{}",
        config.relay.auto_reply_subject_prefix, record.subject
    );

    let auto_reply_headers = match orig_message_id {
        Some(ref mid) => serde_json::json!({
            "In-Reply-To": mid,
            "References": mid,
            "X-AMRelay-AutoReply": "1"
        })
        .to_string(),
        None => serde_json::json!({
            "X-AMRelay-AutoReply": "1"
        })
        .to_string(),
    };

    // Build proper recipients JSON: {"to":[sender],"cc":[]}
    let recipients_json = crate::core::email::storage::Recipients {
        to: vec![record.sender.clone()],
        cc: vec![],
    }
    .to_json();

    if let Err(e) = email_factory
        .create_outbound(
            &auto_reply_id,
            &record.system_id,
            auto_reply_from,
            &recipients_json,
            &auto_reply_subject,
            auto_reply_body,
            None,
            None,
            Some(&auto_reply_headers),
            config.retry.max_attempts as i32,
        )
        .await
    {
        error!(operation="auto_reply_insert_failed", email_id = %record.id, %e, "Failed to insert auto-reply email record");
    } else {
        info!(operation="auto_reply_inserted", email_id = %record.id, auto_reply_id = %auto_reply_id, "Auto-reply email record inserted");
        metrics.inc_auto_reply_sent();
    }
}

/// Insert a webhook notification record for an exhausted outbound email.
/// Guards against recursive cascade (system-generated records don't create more notifications).
///
/// Semantics: the system notifies the agent that their outbound email delivery exhausted.
///   FROM: system (auto_reply_from → admin.email → "noreply@localhost")
///   TO:   agent (record.sender)
///   Subject: {auto_reply_subject_prefix}[Overlimit] {original_subject}
///   Body: markdown (auto_reply_body + detail + original body + attachment filenames)
pub(crate) async fn insert_exhaustion_notification(
    email_factory: &EmailFactory,
    _attachment_factory: &AttachmentFactory,
    config: &Config,
    record: &EmailRecord,
) {
    // Guard: prevent infinite cascade — system-generated notifications
    // (auto-replies, filtered notifications) should not recursively create
    // more notifications when they themselves exhaust.
    if record.subject.contains("[Overlimit]")
        || record.subject.contains("[AmailGW]")
        || record.id.starts_with("wn-")
    {
        info!(email_id = %record.id, "Suppressing recursive exhaustion notification");
        return;
    }

    // Determine system FROM address
    let auto_reply_from = config
        .relay
        .auto_reply_from
        .as_deref()
        .or(config.admin.email.as_deref())
        .unwrap_or("noreply@localhost");

    if auto_reply_from.is_empty() {
        warn!(email_id = %record.id, "auto_reply_from and admin.email both empty — skipping notification");
        return;
    }

    let webhook_url = resolve_webhook_url(email_factory, &record.sender).await;
    let Some(url) = webhook_url else {
        warn!(operation="no_webhook_url", email_id = %record.id, system_id = %record.system_id, sender = %record.sender, "No webhook URL resolved for outbound overlimit notification — skipping");
        return;
    };

    let notification_id = format!("wn-{}", uuid::Uuid::new_v4());

    // Build endpoints JSON for webhook delivery to the agent
    let endpoints_json = serde_json::json!({
        "notification": {
            "url": url,
            "status": "pending"
        }
    })
    .to_string();

    // Resolve attachment filenames for display
    let attachment_ids: Vec<String> = record
        .attachments
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let attachment_display = if attachment_ids.is_empty() {
        String::new()
    } else {
        let filenames = email_factory.attachment_display_list(&attachment_ids).await;
        if filenames.is_empty() {
            String::new()
        } else {
            format!(
                "\n**Attachments**: {}\n",
                filenames.join(", ")
            )
        }
    };

    // Build human-readable markdown body
    let auto_reply_body = config.relay.auto_reply_body.as_deref().unwrap_or(
        "This is an automated message from the amail system. \
         The delivery could not be completed after all retry attempts.",
    );
    let notification_body = format!(
        "{}\n\n---\n\n\
         **Event**: delivery_exhausted\n\
         **Email ID**: {}\n\
         **Original Subject**: {}\n\
         **Original Recipients**: {}\n\
         **Attempts**: {}/{}\n\
         {}\
         ---\n\n\
         **Original Message**:\n\n\
         {}",
        auto_reply_body,
        record.id,
        record.subject,
        record.recipients,
        record.send_count, record.max_attempts,
        attachment_display,
        record.body,
    );

    // Build subject with dual prefix
    let auto_reply_subject = format!(
        "{}[Overlimit] {}",
        config.relay.auto_reply_subject_prefix, record.subject
    );

    // Build recipients: notify only the agent who sent the original email
    let recipients_json = crate::core::email::storage::Recipients {
        to: vec![record.sender.clone()],
        cc: vec![],
    }
    .to_json();

    // Build In-Reply-To / References headers for correlation
    let orig_message_id = record.message_id_from_headers();
    let auto_reply_headers = match orig_message_id {
        Some(ref mid) => serde_json::json!({
            "In-Reply-To": mid,
            "References": mid,
            "X-AMRelay-AutoReply": "1"
        })
        .to_string(),
        None => serde_json::json!({
            "X-AMRelay-AutoReply": "1"
        })
        .to_string(),
    };

    // Create inbound email: system → agent, delivered via webhook
    match email_factory
        .create_inbound(
            &notification_id,
            &record.system_id,
            auto_reply_from,
            &recipients_json,
            &auto_reply_subject,
            &notification_body,
            Some(&endpoints_json),
            None, // attachments
            Some(&auto_reply_headers),
            config.retry.max_attempts as i32,
        )
        .await
    {
        Err(e) => {
            error!(operation="overlimit_notification_insert_failed", email_id = %record.id, %e, "Failed to insert overlimit webhook notification record");
        }
        Ok(_) => {
            info!(operation="overlimit_notification_inserted", email_id = %record.id, notification_id = %notification_id, "Overlimit webhook notification record inserted");
        }
    }
}
