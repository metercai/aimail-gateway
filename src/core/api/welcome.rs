//! System welcome mail endpoint (POST /api/v1/system/welcome).
//!
//! Single parameter: `to` (agent address). Everything else is fixed in
//! code:
//!   from     = postman@{smtp.hostname} (system sender, fixed)
//!   subject  = "Welcome to AIMail world!"
//!   body     = fixed text (reply-all instructions + project homepage)
//!   cc       = reverse-looked-up from the agent's manager_address
//!
//! cc reverse lookup + auto routing (no forced path):
//!   manager empty                                        -> no cc
//!   manager's domain not registered on this gateway      -> cc, external MX
//!   manager's domain registered, address registered+active -> cc, internal webhook
//!   manager's domain registered, address NOT registered  -> invalid address,
//!                                                         excluded from cc
//!
//! Recipient semantics (rcpt/to/cc model):
//!   to   = agent address(es) — must be registered + active, else 400
//!   cc   = resolved manager address(es)
//!   rcpt = actual delivery targets per direction record
//!
//! The agent is expected to reply-all (body instruction), so the manager
//! receives both the original welcome (as cc) and the agent's reply — two
//! threaded mails.
//!
//! Storm safety: replies addressed back to the system sender (postman@)
//! are absorbed by the system-sink bucket in `send.rs` — no
//! unregistered-address notification, no re-delivery.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Json,
};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::core::api::auth::require_scope_any;
use crate::core::api::types::*;
use crate::core::email::storage::Recipients;
use crate::core::storage::ApiKeyRecord;

#[derive(Debug, Deserialize)]
pub struct WelcomeRequest {
    /// Registered agent address(es) to welcome. The ONLY parameter.
    pub to: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct WelcomeResponse {
    pub email_id: String,
    pub message_id: String,
    pub status: String,
    /// cc resolved from the agent's manager_address (reverse lookup).
    /// Empty when no manager is configured or it was invalid.
    pub cc: Vec<String>,
}

const WELCOME_SUBJECT: &str = "Welcome to AIMail world!";

/// Fixed welcome body template. Placeholders:
///   {domain}    — gateway domain (system sender's domain)
///   {timestamp} — server time at send (UTC RFC3339)
const WELCOME_BODY: &str = r#"Welcome to the AIMail world!

Your AIMail address has been activated. This is the first welcome email
automatically sent by the system, to confirm that your address is now active.

To verify that the full delivery path is working end to end, please
**reply-all** to this email and include:
- Your current status
- The current server time

Thank you for joining the AIMail world. For the latest updates, visit the
project homepage:
https://github.com/metercai/aimail

Best regards,
Postman@{domain}
{timestamp}
"#;

/// POST /api/v1/system/welcome — send a system welcome mail (from postman@).
pub async fn send_welcome(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Json(req): Json<WelcomeRequest>,
) -> Result<(StatusCode, Json<WelcomeResponse>), (StatusCode, Json<ErrorResponse>)> {
    // ── 1. Scope: system-level admin only ──
    require_scope_any(&api_key, &["platform", "system", "agent_admin"])?;

    let env = &state.factories.email.env_factory;

    // ── 2. Validate `to`: registered, active agent address(es) ──
    if req.to.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No recipients provided".to_string(),
                detail: Some("The 'to' field must contain at least one agent address".to_string()),
            }),
        ));
    }
    let mut internal: Vec<(String, String)> = Vec::new(); // (email, system_id)
    for addr in &req.to {
        let a = addr.trim().to_lowercase();
        if a.is_empty() {
            continue;
        }
        match env.lookup_domain_addr(&a).await {
            Ok(Some(rec)) if rec.is_active => internal.push((a, rec.system_id.clone())),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Welcome recipient not registered".to_string(),
                        detail: Some(format!(
                            "'{}' is not a registered active address — welcome mail is for agent addresses",
                            a
                        )),
                    }),
                ));
            }
        }
    }
    if internal.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid recipients".to_string(),
                detail: Some("All 'to' entries were empty".to_string()),
            }),
        ));
    }

    // ── 3. cc: reverse-lookup manager_address, auto-route internal/external ──
    let mut ext_cc: Vec<String> = Vec::new();   // external (MX)
    let mut int_cc: Vec<String> = Vec::new();   // internal (webhook)
    for (agent, _) in &internal {
        if let Ok(Some(meta)) = env.db.get_domain_addr_meta(agent).await {
            let m = meta.manager_address.trim().to_lowercase();
            if m.is_empty() {
                continue;
            }
            let m_domain = match m.rsplit('@').next() {
                Some(d) if !d.is_empty() => d.to_string(),
                _ => continue,
            };
            // Exact-address match (no domain fallback): registered+active
            // agent address on this gateway — aligned with send.rs Type 1
            // internal routing (address row active, domain row is the
            // registration anchor).
            let (addr_res, domain_res) = (
                env.db.get_system_domain_by_domain(&m).await,
                env.db.get_system_domain_by_domain(&m_domain).await,
            );
            let (addr_rec, domain_rec) = match (addr_res, domain_res) {
                (Ok(a), Ok(d)) => (a, d),
                (Err(e), _) | (_, Err(e)) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Manager lookup failed".to_string(),
                            detail: Some(e.to_string()),
                        }),
                    ));
                }
            };
            match (addr_rec, domain_rec) {
                (Some(a), _) if a.is_active && a.domain == m => {
                    // Address registered + active → internal webhook.
                    if !int_cc.contains(&m) {
                        int_cc.push(m);
                    }
                }
                (_, Some(_)) => {
                    // Domain registered but address not registered (or
                    // inactive) → invalid address: excluded from cc
                    // (user rule, 2026-08-24).
                    info!(
                        operation = "welcome_cc_invalid",
                        agent = %agent,
                        manager = %m,
                        "Manager address on a registered domain but not registered — excluded from cc"
                    );
                }
                _ => {
                    // Domain not registered on this gateway → external MX.
                    if !ext_cc.contains(&m) {
                        ext_cc.push(m);
                    }
                }
            }
        }
    }
    let full_cc: Vec<String> = int_cc.iter().cloned().chain(ext_cc.iter().cloned()).collect();

    // ── 4. Headers: welcome marker + Message-ID (thread root) ──
    let from = state.config.system_sender();
    let domain = state
        .config
        .smtp
        .hostname
        .as_deref()
        .or_else(|| state.config.http.hostname.as_deref())
        .unwrap_or("amail-relay");
    let message_id = format!("<{}@{}>", Uuid::new_v4(), domain);
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut headers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    headers.insert("Message-ID".into(), message_id.clone());
    headers.insert("X-AIMail-Welcome".into(), "1".into());
    let headers_json = serde_json::to_string(&headers).unwrap_or_default();

    let subject = WELCOME_SUBJECT;
    let body = WELCOME_BODY
        .replace("{domain}", domain)
        .replace("{timestamp}", &timestamp);

    // ── 5. Records (rcpt/to/cc model) ──
    let full_to: Vec<String> = internal.iter().map(|(e, _)| e.clone()).collect();
    let attachments_json: Option<String> = None;
    let max_attempts = state.config.retry.max_attempts as i32;
    let mut created_ids: Vec<String> = Vec::new();

    // 5a. Outbound record for external cc targets (MX delivery).
    if !ext_cc.is_empty() {
        let email_id = Uuid::new_v4().to_string();
        let recipients_json = Recipients {
            to: full_to.clone(),
            cc: full_cc.clone(),
            rcpt: ext_cc.clone(),
        }
        .to_json();

        let mut eps = serde_json::Map::new();
        for addr in &ext_cc {
            eps.insert(
                addr.to_lowercase(),
                serde_json::json!({"status": "pending", "protocol": "mx"}),
            );
        }
        let endpoints_str = serde_json::to_string(&eps).unwrap_or_default();

        match state
            .factories
            .email
            .create_outbound(
                &email_id,
                &api_key.system_id,
                &from,
                &recipients_json,
                subject,
                &body,
                Some(&endpoints_str),
                attachments_json.as_deref(),
                Some(&headers_json),
                max_attempts,
            )
            .await
        {
            Ok(record) => {
                state.metrics.inc_emails_queued_api();
                info!(
                    operation = "welcome_queued",
                    email_id = %record.id,
                    sender = %from,
                    external_cc = ext_cc.len(),
                    "Welcome mail queued for external cc recipients"
                );
                created_ids.push(record.id.clone());
                if let Err(e) = state.trigger_tx.try_send(record.id.clone()) {
                    state.metrics.inc_trigger_dropped();
                    tracing::warn!(
                        operation = "welcome_dispatch_trigger_failed",
                        error = %e,
                        email_id = %record.id,
                        "Failed to trigger outbound dispatch for welcome cc record"
                    );
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to queue welcome cc record".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        }
    }

    // 5b. Inbound record(s) for internal targets (webhook delivery).
    //     agent targets are always internal (validated in step 2); internal
    //     cc targets join the same record when present.
    {
        let internal_targets: Vec<String> = {
            let mut v: Vec<String> = internal.iter().map(|(e, _)| e.clone()).collect();
            for c in &int_cc {
                if !v.contains(c) {
                    v.push(c.clone());
                }
            }
            v
        };
        let email_id = Uuid::new_v4().to_string();
        let recipients_json = Recipients {
            to: full_to.clone(),
            cc: full_cc.clone(),
            rcpt: internal_targets.clone(),
        }
        .to_json();

        let endpoints_str = state
            .factories
            .email
            .build_endpoints_for_recipients(&internal_targets)
            .await;
        let endpoints = if endpoints_str == "{}" || endpoints_str.is_empty() {
            None
        } else {
            Some(endpoints_str)
        };

        // Attribute the record to the agent's owning system (shared-domain
        // addresses may belong to a different system).
        let record_system = internal[0].1.clone();

        match state
            .factories
            .email
            .create_inbound(
                &email_id,
                &record_system,
                &from,
                &recipients_json,
                subject,
                &body,
                endpoints.as_deref(),
                attachments_json.as_deref(),
                Some(&headers_json),
                max_attempts,
            )
            .await
        {
            Ok(record) => {
                info!(
                    operation = "welcome_queued",
                    email_id = %record.id,
                    sender = %from,
                    internal_targets = internal_targets.len(),
                    "Welcome mail record created for internal delivery"
                );
                created_ids.push(record.id.clone());
                // Trigger immediate webhook delivery (CAS in the scheduler
                // guards against double delivery with the periodic sweep).
                if let Err(e) = state.trigger_tx.try_send(record.id.clone()) {
                    state.metrics.inc_trigger_dropped();
                    tracing::warn!(
                        operation = "welcome_dispatch_trigger_failed",
                        error = %e,
                        email_id = %record.id,
                        "Failed to trigger inbound delivery for welcome record"
                    );
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to queue welcome internal record".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        }
    }

    if created_ids.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Welcome mail was not queued".to_string(),
                detail: None,
            }),
        ));
    }

    Ok((
        StatusCode::OK,
        Json(WelcomeResponse {
            email_id: created_ids[0].clone(),
            message_id,
            status: "welcome_queued".to_string(),
            cc: full_cc,
        }),
    ))
}
