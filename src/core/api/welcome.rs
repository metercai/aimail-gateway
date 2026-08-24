//! System welcome mail endpoint (POST /api/v1/system/welcome).
//!
//! Sends a welcome mail on behalf of the FIXED system sender
//! (`postman@{smtp.hostname}`) to a registered agent address, cc'ing the
//! agent's manager/admin address (external). System-generated mail — like
//! unregistered/filtered/bounce notifications — bypasses the whitelist:
//! the system sender is not a registered mailbox and owns no whitelist
//! rules.
//!
//! Recipient semantics (rcpt/to/cc model):
//!   to   = agent address(es) — must be registered + active (internal)
//!   cc   = manager/admin address(es) — external (MX delivery)
//!   rcpt = actual delivery targets per direction record
//!
//! The agent is expected to reply-all, so the manager receives both the
//! original welcome (as cc) and the agent's reply (cc'd on the reply) —
//! two threaded mails, less abrupt than a lone reply.
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
    /// Registered agent address(es) to welcome (internal delivery).
    pub to: Vec<String>,
    /// Manager/admin address(es) to cc (external MX delivery).
    #[serde(default)]
    pub cc: Vec<String>,
    /// Optional subject override.
    #[serde(default)]
    pub subject: Option<String>,
    /// Optional markdown body override.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct WelcomeResponse {
    pub email_id: String,
    pub message_id: String,
    pub status: String,
}

const DEFAULT_SUBJECT: &str = "Welcome to AgentMail";

const DEFAULT_BODY: &str = r#"Welcome! Your AgentMail address has been set up and is now active.

This is a system message from your mail relay — it is sent by the fixed
system sender `postman@` and is not a registered mailbox.

To confirm your mailbox is fully operational (inbound delivery, LLM
processing, and outbound reply), please **reply-all** to this email with a
short confirmation (e.g. your server's current time). Keep all original
recipients in the reply (To + Cc).
"#;

/// POST /api/v1/system/welcome — send a system welcome mail (from postman@).
pub async fn send_welcome(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Json(req): Json<WelcomeRequest>,
) -> Result<(StatusCode, Json<WelcomeResponse>), (StatusCode, Json<ErrorResponse>)> {
    // ── 1. Scope: system-level admin only ──
    require_scope_any(&api_key, &["platform", "system", "agent_admin"])?;

    // ── 2. Validate recipients ──
    let env = &state.factories.email.env_factory;
    if req.to.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No recipients provided".to_string(),
                detail: Some("The 'to' field must contain at least one agent address".to_string()),
            }),
        ));
    }

    // Each `to` must be a registered, active address (internal delivery).
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

    // `cc` entries: external delivery (MX). No registration required.
    let external: Vec<String> = req
        .cc
        .iter()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();

    // ── 3. Headers: welcome marker + Message-ID (thread root) ──
    let from = state.config.system_sender();
    let domain = state
        .config
        .smtp
        .hostname
        .as_deref()
        .or_else(|| state.config.http.hostname.as_deref())
        .unwrap_or("amail-relay");
    let message_id = format!("<{}@{}>", Uuid::new_v4(), domain);
    let mut headers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    headers.insert("Message-ID".into(), message_id.clone());
    headers.insert("X-AMMail-Welcome".into(), "1".into());
    let headers_json = serde_json::to_string(&headers).unwrap_or_default();

    let subject = req.subject.as_deref().unwrap_or(DEFAULT_SUBJECT);
    let body = req.body.as_deref().unwrap_or(DEFAULT_BODY);

    // ── 4. Build full display lists (to/cc = what recipients see) ──
    let full_to: Vec<String> = internal.iter().map(|(e, _)| e.clone()).collect();
    let full_cc: Vec<String> = external.iter().cloned().collect();

    let attachments_json: Option<String> = None;
    let max_attempts = state.config.retry.max_attempts as i32;
    let mut created_ids: Vec<String> = Vec::new();

    // 4a. Outbound record for external cc targets (MX delivery).
    //     rcpt = external only; to/cc = full lists.
    if !external.is_empty() {
        let email_id = Uuid::new_v4().to_string();
        let recipients_json = Recipients {
            to: full_to.clone(),
            cc: full_cc.clone(),
            rcpt: external.clone(),
        }
        .to_json();

        let mut eps = serde_json::Map::new();
        for addr in &external {
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
                body,
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
                    external_cc = external.len(),
                    "Welcome mail queued for external cc recipients"
                );
                created_ids.push(record.id.clone());
                if let Err(e) = state.trigger_tx.try_send(record.id.clone()) {
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

    // 4b. Inbound record for the agent target(s) (webhook delivery).
    //     rcpt = internal targets; to/cc = full lists.
    {
        let email_id = Uuid::new_v4().to_string();
        let internal_emails: Vec<String> = internal.iter().map(|(e, _)| e.clone()).collect();
        let recipients_json = Recipients {
            to: full_to.clone(),
            cc: full_cc.clone(),
            rcpt: internal_emails.clone(),
        }
        .to_json();

        let endpoints_str = state
            .factories
            .email
            .build_endpoints_for_recipients(&internal_emails)
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
                body,
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
                    agent_count = internal_emails.len(),
                    "Welcome mail record created for agent delivery"
                );
                created_ids.push(record.id.clone());
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to queue welcome agent record".to_string(),
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
        }),
    ))
}
