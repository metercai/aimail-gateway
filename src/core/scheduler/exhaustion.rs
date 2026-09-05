use tracing::{error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::email::storage::EmailRecord;

use super::deliver::resolve_webhook_url;

/// Wake the scheduler for a freshly-inserted auto-reply/notification
/// (born `readying`; only the trigger claims it for first delivery).
fn trigger_first_delivery(
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
    email_id: &str,
    operation: &str,
) {
    if let Some(tx) = trigger {
        if let Err(e) = tx.try_send(email_id.to_string()) {
            warn!(
                operation,
                error = %e,
                email_id,
                "Failed to trigger dispatch; will be picked up by the readying sweep"
            );
        }
    }
}

// ── Exhaustion helpers ───────────────────────────────────────────────

/// Insert an auto-reply email record for an exhausted inbound email.
pub(crate) async fn insert_exhaustion_auto_reply(
    config: &Config,
    email_factory: &EmailFactory,
    record: &EmailRecord,
    metrics: &Metrics,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
) {
    let orig_message_id = record.message_id_from_headers();

    // Guard: prevent infinite cascade — system-generated records
    // (notifications, auto-replies) should not recursively create
    // more auto-replies when they themselves exhaust.
    if record.id.starts_with("ar-")
        || record.id.starts_with("wn-")
        || record.id.starts_with("bn-")
        || record.id.starts_with("sr-")
        || record.subject.contains("[Overlimit]")
        || record.subject.contains("[AmailGW]")
        || record.subject.starts_with("__amail_pong__:")
        || record.id.starts_with("exp-")
    {
        info!(email_id = %record.id, "Suppressing recursive auto-reply — system-generated record");
        return;
    }

    // System FROM address (fixed: noreply@{smtp.hostname})
    let auto_reply_from = config.system_sender();

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
            "X-AIMail-AutoReply": "1"
        })
        .to_string(),
        None => serde_json::json!({
            "X-AIMail-AutoReply": "1"
        })
        .to_string(),
    };

    // Build proper recipients JSON: {"to":[sender],"cc":[],"rcpt":[sender]}
    let recipients_json = crate::core::email::storage::Recipients {
        to: vec![record.sender.clone()],
        cc: vec![],
        rcpt: vec![record.sender.clone()],
    }
    .to_json();

    if let Err(e) = email_factory
        .create_outbound(
            &auto_reply_id,
            &record.system_id,
            auto_reply_from.as_str(),
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
        trigger_first_delivery(trigger, &auto_reply_id, "auto_reply_trigger_failed");
    }
}

/// Insert a webhook notification record for an exhausted outbound email.
/// Guards against recursive cascade (system-generated records don't create more notifications).
///
/// Semantics: the system notifies the agent that their outbound email delivery exhausted.
///   FROM: system (fixed: noreply@{smtp.hostname} via config.system_sender())
///   TO:   agent (record.sender)
///   Subject: {auto_reply_subject_prefix}[Overlimit] {original_subject}
///   Body: markdown (auto_reply_body + detail + original body + attachment filenames)
pub(crate) async fn insert_exhaustion_notification(
    email_factory: &EmailFactory,
    _attachment_factory: &AttachmentFactory,
    config: &Config,
    record: &EmailRecord,
    trigger: Option<&tokio::sync::mpsc::Sender<String>>,
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

    // System FROM address (fixed: noreply@{smtp.hostname})
    let auto_reply_from = config.system_sender();

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
            format!("\n**Attachments**: {}\n", filenames.join(", "))
        }
    };

    // Build human-readable markdown body
    let auto_reply_body = config.relay.auto_reply_body.as_deref().unwrap_or(
        "This is an automated message from the aimail system. \
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
        record.send_count,
        record.max_attempts,
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
        rcpt: vec![record.sender.clone()],
    }
    .to_json();

    // Build In-Reply-To / References headers for correlation
    let orig_message_id = record.message_id_from_headers();
    let auto_reply_headers = match orig_message_id {
        Some(ref mid) => serde_json::json!({
            "In-Reply-To": mid,
            "References": mid,
            "X-AIMail-AutoReply": "1"
        })
        .to_string(),
        None => serde_json::json!({
            "X-AIMail-AutoReply": "1"
        })
        .to_string(),
    };

    // Create inbound email: system → agent, delivered via webhook
    match email_factory
        .create_inbound(
            &notification_id,
            &record.system_id,
            auto_reply_from.as_str(),
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
            trigger_first_delivery(trigger, &notification_id, "notification_trigger_failed");
        }
    }
}
