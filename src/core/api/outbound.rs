//! Shared "outbound mail enqueue" helper (extracted 2026-09-22).
//!
//! Motive: the welcome endpoint inlined a chunk of outbound enqueue logic (record + endpoints + metrics + trigger);
//! the gateway's new "safety-officer command confirmation mail" needs the same set of actions => per "shared logic must be extracted into a common implementation" it moves here,
//! avoiding a second copy (the pull_intercept signature-verification copy already caused one missed fix because of duplication).
//!
//! Dependencies are deliberately **injected on demand** (config / email_factory / metrics?/ trigger_tx?) instead of taking `HttpState`:
//! confirmation mails happen on the delivery path (deliver.rs), where there is no HttpState.

use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::EmailFactory;
use tokio::sync::mpsc::Sender;

/// Enqueue a **single-recipient, attachment-free** outbound mail and wake the scheduler when a trigger handle is available.
///
/// Returns `email_id`; failures return `Err(reason)`. A confirmation-mail failure **must not** affect the command's own execution result,
/// so callers handle it as a warn.
#[allow(clippy::too_many_arguments)] // explicit parameter list is deliberate: internal constructor/handler API
pub async fn enqueue_outbound_simple(
    cfg: &Config,
    email_factory: &EmailFactory,
    metrics: Option<&Metrics>,
    trigger_tx: Option<&Sender<String>>,
    system_id: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, String> {
    let email_id = Uuid::new_v4().to_string();
    let recipients_json = json!({ "to": [to] }).to_string();

    // Endpoint resolution (2026-09-23, demonstrated by S4 e2e): the original helper
    // hardcoded `protocol: mx`, so confirmations to INTERNAL recipients
    // (registered on this gateway) were dropped by loopback prevention in the
    // SMTP sender and swept away — the ack never reached same-host managers.
    // Resolve the webhook endpoint like the welcome endpoint does; fall back
    // to the MX envelope only when the recipient has no webhook (external).
    let endpoints_str = {
        let internal = email_factory
            .env_factory
            .build_endpoints_for_recipients(&[to.to_string()])
            .await;
        if internal == "{}" || internal.is_empty() {
            let mut eps = serde_json::Map::new();
            eps.insert(
                to.to_lowercase(),
                json!({ "status": "pending", "protocol": "mx" }),
            );
            serde_json::to_string(&eps).unwrap_or_default()
        } else {
            internal
        }
    };

    // Delivery-type routing (2026-09-23): for outbound records
    // `detect_delivery_type` only consults the explicit header override
    // (body present ⇒ SMTP). An internal recipient must go through the
    // webhook processor (which consumes the endpoints above), otherwise the
    // SMTP sender's loopback prevention silently drops the mail.
    let headers_json = {
        let is_internal = endpoints_str.contains("\"url\"");
        let mut h = serde_json::Map::new();
        if is_internal {
            h.insert("delivery_type".to_string(), json!("webhook"));
        }
        let domain = from.split('@').nth(1).unwrap_or("aimail-relay");
        // Lowercase key: internal headers map convention (inbound normalizes
        // to lowercase; webhook/SMTP read sites all read "message_id").
        h.insert(
            "message_id".to_string(),
            json!(format!("<{}@{}>", Uuid::new_v4(), domain)),
        );
        serde_json::to_string(&h).unwrap_or_default()
    };
    let max_attempts = cfg.retry.max_attempts as i32;

    match email_factory
        .create_outbound(
            &email_id,
            system_id,
            from,
            &recipients_json,
            subject,
            body,
            Some(&endpoints_str),
            None,
            Some(&headers_json),
            max_attempts,
        )
        .await
    {
        Ok(record) => {
            if let Some(m) = metrics {
                m.inc_emails_queued_api();
            }
            info!(
                operation = "outbound_queued",
                email_id = %record.id,
                sender = %from,
                to = %to,
                "outbound mail queued"
            );
            if let Some(tx) = trigger_tx {
                if let Err(e) = tx.try_send(record.id.clone()) {
                    if let Some(m) = metrics {
                        m.inc_trigger_dropped();
                    }
                    warn!(
                        operation = "outbound_trigger_failed",
                        error = %e,
                        email_id = %record.id,
                        "failed to trigger outbound dispatch"
                    );
                }
            }
            Ok(record.id.clone())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Context needed by confirmation mails - the delivery path (deliver.rs) has no `HttpState`, so these are injected on demand.
/// Copy: one command may produce two confirmation mails (agent closed loop + safety-officer ack); the borrowed context must not be moved by the first
/// call.
#[derive(Clone, Copy)]
pub struct AckCtx<'a> {
    pub cfg: &'a Config,
    pub email_factory: &'a EmailFactory,
    pub metrics: Option<&'a Metrics>,
    pub trigger_tx: Option<&'a Sender<String>>,
}

/// Failure confirmation context for command handling (2026-09-23): every command gets a reply => **a non-manager sender must also receive**
/// the "Command failed" confirmation mail; otherwise a non-manager's command fails silently and the sender can never notice.
/// sender = the command mail's sender (failure-confirmation recipient); system_id = the owning system of the target address (for routing);
/// to_agent (the command target address) differs per hit, so it is passed as a parameter at the call site, not stored in the struct.
pub struct FailedCommandAck<'a> {
    pub cfg: &'a Config,
    pub email_factory: &'a EmailFactory,
    pub metrics: Option<&'a Metrics>,
    pub trigger_tx: Option<&'a Sender<String>>,
    pub sender: &'a str,
    pub system_id: &'a str,
}
