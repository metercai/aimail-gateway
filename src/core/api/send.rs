//! Outbound email send API endpoint.

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Json,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::core::api::auth::{domain_from_email, require_scope};
use crate::core::api::types::*;
use crate::core::email::storage::Recipients;
use crate::core::email::utils::strip_persona;
use crate::core::storage::ApiKeyRecord;

/// POST /api/v1/send — Create an outbound email record via API.
pub async fn send_email(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Json(req): Json<SendEmailRequest>,
) -> Result<(StatusCode, Json<SendEmailResponse>), (StatusCode, Json<ErrorResponse>)> {
    // ── 1. Scope check ──
    require_scope(&api_key, "agent")?;

    // ── 1a. Bare-domain API keys cannot send emails ──
    // A key with a bare domain (no @) is a domain-level admin key,
    // not an address-bound key. Sending requires a valid email address.
    if !api_key.email_address.contains('@') {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Sender mismatch".to_string(),
                detail: Some(format!(
                    "Domain-level key '{}' cannot send — use an address-level key with a valid email",
                    api_key.email_address
                )),
            }),
        ));
    }

    // ── 1b. Daily email quota (emails_per_day from system plans) ──
    {
        let system_id = api_key.system_id.as_str();
        let _system = match state
            .factories
            .email
            .env_factory
            .resolve_system(system_id)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "System not found".to_string(),
                        detail: None,
                    }),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Database error".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        };
        // Delegate quota check to QuotaChecker trait
        state
            .extensions
            .quota_checker
            .check_send_quota(system_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: "rate_limited".to_string(),
                        detail: Some(e.to_string()),
                    }),
                )
            })?;
    }

    // ── 1a. Per-system rate limit ──
    {
        let system_id = api_key.system_id.as_str();
        match state.extensions.rate_limiter.check(system_id) {
            Ok(()) => { /* allowed */ }
            Err(wait) => {
                state.metrics.inc_rate_limited();
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: "Rate limit exceeded".to_string(),
                        detail: Some(format!(
                            "Too many requests for system '{}'. Retry after {:.0}s",
                            system_id,
                            wait.as_secs_f64()
                        )),
                    }),
                ));
            }
        }
    }

    // ── 2. Validate sender matches API key (persona-aware) ──
    let sender_raw = req.sender.as_deref().unwrap_or(&api_key.email_address);
    // Strip persona prefix for comparison — sender may be "support.alice@agent.com"
    // but api_key.email_address is "alice@agent.com"
    let (sender_base, sender_persona) = strip_persona(sender_raw);
    if sender_base != api_key.email_address {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Sender mismatch".to_string(),
                detail: Some(format!(
                    "The sender '{}' must match the API key email '{}'",
                    sender_raw, api_key.email_address
                )),
            }),
        ));
    }
    // Use base address for all subsequent internal matching (whitelist, domain, etc.)
    let sender = sender_base.as_str();

    // ── 2b. Append agent signature if configured ──
    let mut markdown_body = req.markdown.clone();
    if let Ok(Some(meta)) = state
        .factories
        .email
        .env_factory
        .resolve_domain_addr_meta(sender)
        .await
    {
        if !meta.agent_signature.is_empty() {
            let signature_block = format!("\n\n-- \n{}", meta.agent_signature);
            markdown_body = format!("{}{}", markdown_body, signature_block);
        }
    }

    // ── 3. Parse recipients, preserving to/cc distinction ──
    // Support "Name <email>" and bare "email" formats.
    // Helper: parse "Name <email>" → (name, email); bare "email" → ("", email)
    let parse_one = |s: &str| -> (String, String) {
        let s = s.trim();
        if s.is_empty() {
            return (String::new(), String::new());
        }
        if let Some(pos) = s.find('<') {
            let name = s[..pos].trim().to_string();
            let email = if let Some(end) = s.find('>') {
                s[pos + 1..end].trim().to_string()
            } else {
                s[pos + 1..].trim().to_string()
            };
            (name, email.to_lowercase())
        } else {
            (String::new(), s.to_lowercase())
        }
    };
    let fmt_display = |name: &str, email: &str| -> String {
        if name.is_empty() {
            email.to_string()
        } else {
            format!("{} <{}>", name, email)
        }
    };

    // Parse to addresses — strip persona prefix at entry point.
    // Persona-prefixed addresses (support.bob@agent.com) are reduced to base
    // (bob@agent.com) for all internal matching; the _persona header carries
    // the role. Full addresses are reconstructed from persona_map for display
    // and SMTP envelope delivery.
    let mut persona_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let to_raw: Vec<(String, String)> = req
        .to
        .split(',')
        .map(|s| parse_one(s))
        .filter(|(_, e)| !e.is_empty())
        .map(|(name, email)| {
            let (base, persona) = strip_persona(&email);
            if !persona.is_empty() {
                persona_map.entry(base.clone()).or_insert(persona);
            }
            (name, base)
        })
        .collect();
    let to_set: std::collections::HashSet<String> = to_raw.iter().map(|(_, e)| e.clone()).collect();

    // Parse cc addresses (with persona stripping)
    let mut cc_raw: Vec<(String, String)> = Vec::new();
    if let Some(cc_list) = &req.cc {
        for addr in cc_list {
            let (name, raw_email) = parse_one(addr);
            if !raw_email.is_empty() {
                let (base, persona) = strip_persona(&raw_email);
                if !persona.is_empty() {
                    persona_map.entry(base.clone()).or_insert(persona);
                }
                if !to_set.contains(&base) {
                    cc_raw.push((name, base));
                }
            }
        }
    }
    let cc_set: std::collections::HashSet<String> = cc_raw.iter().map(|(_, e)| e.clone()).collect();

    // For bare emails (no display name), try whitelist description; fall back to email local-part.
    // Collect unique bare emails to resolve names in batch.
    let mut bare_emails: Vec<String> = Vec::new();
    for (n, e) in to_raw.iter().chain(cc_raw.iter()) {
        if n.is_empty() && !bare_emails.contains(&e) {
            bare_emails.push(e.clone());
        }
    }
    let mut name_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Batch name resolution: fetch whitelist entries once per sender domain
    if !bare_emails.is_empty() {
        let domain = domain_from_email(&bare_emails[0]);
        let all_entries = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(domain)
            .await
            .unwrap_or_default();
        for email in &bare_emails {
            let name = all_entries
                .iter()
                .find(|e| e.value == *email)
                .and_then(|e| e.description.as_ref())
                .and_then(|desc| serde_json::from_str::<serde_json::Value>(desc).ok())
                .and_then(|v| {
                    v.get("name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| email.split('@').next().unwrap_or(email).to_string());
            name_map.insert(email.clone(), name);
        }
    }

    // Helper: reconstruct full persona address from base.
    // External addresses that happen to match "x.y@domain" also pass
    // through here — persona_map always maps back to the original.
    let full_addr = |e: &str| -> String {
        persona_map
            .get(e)
            .map_or_else(|| e.to_string(), |p| format!("{}.{}", p, e))
    };

    let to_named: Vec<(String, String)> = to_raw
        .into_iter()
        .map(|(n, e)| {
            let addr = full_addr(&e);
            (
                if n.is_empty() {
                    name_map
                        .get(&e)
                        .cloned()
                        .unwrap_or_else(|| e.split('@').next().unwrap_or(&e).to_string())
                } else {
                    n
                },
                addr,
            )
        })
        .collect();
    let cc_named: Vec<(String, String)> = cc_raw
        .into_iter()
        .map(|(n, e)| {
            let addr = full_addr(&e);
            (
                if n.is_empty() {
                    name_map
                        .get(&e)
                        .cloned()
                        .unwrap_or_else(|| e.split('@').next().unwrap_or(&e).to_string())
                } else {
                    n
                },
                addr,
            )
        })
        .collect();

    // Build display-name headers for SMTP sender and internal-webhook preprocessor
    let mut display_headers = std::collections::HashMap::new();
    if !to_named.is_empty() {
        let to_str: Vec<String> = to_named.iter().map(|(n, e)| fmt_display(n, e)).collect();
        display_headers.insert("to".to_string(), to_str.join(", "));
    }
    if !cc_named.is_empty() {
        let cc_str: Vec<String> = cc_named.iter().map(|(n, e)| fmt_display(n, e)).collect();
        display_headers.insert("cc".to_string(), cc_str.join(", "));
    }
    // Sender display: use raw (persona-preserving) address, fall back to base
    let sender_display = if !sender_persona.is_empty() {
        sender_raw
    } else {
        sender
    };
    let sender_name = name_map
        .get(sender)
        .cloned()
        .unwrap_or_else(|| sender.split('@').next().unwrap_or(sender).to_string());
    display_headers.insert(
        "from".to_string(),
        fmt_display(&sender_name, sender_display),
    );

    // Merge display-name headers into existing request headers (if any)
    let mut merged_headers = req.headers.clone().unwrap_or_default();
    for (k, v) in display_headers {
        merged_headers.insert(k, v);
    }
    // Inject _persona entries for persona-aware recipients — the webhook
    // preprocessor extracts these to set my_role on the receiving agent.
    for (base, persona) in &persona_map {
        let key = format!("_persona.{}", base);
        merged_headers.entry(key).or_insert_with(|| persona.clone());
    }

    // ── a2a_board: 会话流检测（出站） ──
    // 检查 CC 中是否包含 board 地址，若是则注入 board 身份 headers
    if let Some(ref cc_list) = req.cc {
        for cc_addr in cc_list {
            let (cc_base, _) = strip_persona(cc_addr);
            if let Some((_sid, board_id, _domain)) =
                crate::board::models::parse_board_email(&cc_base)
            {
                use crate::board::db;
                if let Ok(conn) =
                    db::open_board_db(state.config.storage.path.to_str().unwrap_or(""), &board_id)
                {
                    // Sender = API key's email address
                    let sender = sender_base.as_str();
                    // TO = first primary recipient (for board_role)
                    let to_addr = to_set.iter().next().map(|s| s.as_str()).unwrap_or("");
                    let from_member = db::get_member(&conn, &board_id, sender).ok().flatten();
                    let to_member = db::get_member(&conn, &board_id, to_addr).ok().flatten();
                    if from_member.is_some() && to_member.is_some() {
                        merged_headers.insert("X-Board-ID".to_string(), board_id.clone());
                        merged_headers.insert("X-Board-Role".to_string(), to_member.unwrap().role);
                        merged_headers.insert("X-From-Role".to_string(), from_member.unwrap().role);
                    }
                }
                break; // Only process the first matching board
            }
        }
    }

    // ── [P0] Auto-generate Message-ID if missing ──────────────────
    // Every outbound email needs a Message-ID header for snapshot
    // tracking and thread correlation. If the caller didn't provide one,
    // generate it from the gateway's hostname.
    if !merged_headers.contains_key("Message-ID")
        && !merged_headers.contains_key("message-id")
        && !merged_headers.contains_key("message_id")
    {
        let domain = state
            .config
            .smtp
            .hostname
            .as_deref()
            .or_else(|| state.config.http.hostname.as_deref())
            .unwrap_or("amail.local");
        let msg_id = format!("<{}@{}>", Uuid::new_v4(), domain);
        merged_headers.insert("Message-ID".into(), msg_id);
    }

    let recipients: Vec<String> = to_set
        .iter()
        .cloned()
        .chain(cc_set.iter().cloned())
        .collect();

    if recipients.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No valid recipients provided".to_string(),
                detail: Some(
                    "The 'to' field must contain at least one valid email address".to_string(),
                ),
            }),
        ));
    }

    // ── 3a. P0: Empty whitelist → 403 ──
    let whitelist_count = match state
        .factories
        .email
        .env_factory
        .count_whitelist_entries(sender, &["to", "all"])
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };
    if whitelist_count == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Sending disabled".to_string(),
                detail: Some(
                    "No outbound whitelist entries configured for this system/domain".to_string(),
                ),
            }),
        ));
    }

    // ── 4. Outbound whitelist: filter recipients against sender's "to"/"all" rules ──
    let mut filtered: Vec<String> = Vec::new();
    let mut valid_recipients: Vec<String> = Vec::new();

    for recipient in &recipients {
        match state
            .factories
            .email
            .env_factory
            .check_whitelisted(sender, recipient, "to")
            .await
        {
            Ok(true) => {
                state.metrics.inc_whitelist_matches();
                valid_recipients.push(recipient.clone());
            }
            _ => filtered.push(recipient.clone()),
        }
    }

    // ── 5. Split valid recipients into internal (same system) and external ──
    let mut internal: Vec<(String, String, Option<String>, Option<String>)> = Vec::new();
    // (email, domain, webhook_url, webhook_secret)
    let mut external: Vec<String> = Vec::new();
    let mut unregistered: Vec<String> = Vec::new(); // Type 2 hit but Type 1 miss

    for recipient in &valid_recipients {
        let env = &state.factories.email.env_factory;
        // Type 1: exact match on full address
        match env.lookup_domain_addr(recipient).await {
            Ok(Some(ref inner)) if inner.is_active && inner.system_id == api_key.system_id => {
                internal.push((
                    recipient.clone(),
                    inner.domain.clone(),
                    inner.webhook_url.clone(),
                    inner.webhook_secret.clone(),
                ));
            }
            _ => {
                // Type 2: fallback to domain-level match
                let domain = recipient.rsplit('@').next().unwrap_or(recipient);
                match env.lookup_domain_addr(domain).await {
                    Ok(Some(ref inner))
                        if inner.is_active && inner.system_id == api_key.system_id =>
                    {
                        // Domain exists but address not registered — auto-reply
                        unregistered.push(recipient.clone());
                    }
                    _ => {
                        external.push(recipient.clone());
                    }
                }
            }
        }
    }

    // ── 6. Inbound whitelist: for internal recipients, verify sender against their "from"/"all" rules ──
    let mut final_internal: Vec<(String, String, Option<String>, Option<String>)> = Vec::new();
    for (recipient, domain, webhook_url, webhook_secret) in internal {
        match state
            .factories
            .email
            .env_factory
            .check_whitelisted(&recipient, sender, "from")
            .await
        {
            Ok(true) => {
                state.metrics.inc_whitelist_matches();
                final_internal.push((recipient, domain, webhook_url, webhook_secret));
            }
            _ => filtered.push(recipient),
        }
    }

    // ── 7. Generate DB records ──
    let mut created_ids: Vec<String> = Vec::new();
    let attachments_json: Option<String> = req
        .attachments
        .as_ref()
        .map(|a| serde_json::to_string(a).unwrap_or_default());
    let headers_json: Option<String> =
        Some(serde_json::to_string(&merged_headers).unwrap_or_default());

    let subject = req.subject.as_deref().unwrap_or("");

    // ── Stranger detection for universal commands ──
    // For internal delivery, headers are read by StrangerInterceptor
    {
        let stranger_commands = ["[WHOAMI]"];
        let subj_upper = subject.to_uppercase();
        for cmd in &stranger_commands {
            if subj_upper.starts_with(cmd) {
                if !merged_headers.contains_key("x-mail-stranger") {
                    merged_headers.insert("x-mail-stranger".into(), "true".into());
                }
                let cmd_name = cmd
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_lowercase();
                merged_headers.insert("x-mail-command".into(), cmd_name);
                break;
            }
        }
    }

    // ── [P0] Ping-pong interception ────────────────────────────
    // When send_mail sends a pong, redirect as inbound instead of
    // creating an outbound record for external SMTP delivery.
    if subject.starts_with("__amail_pong__:") && !external.is_empty() {
        let new_id = Uuid::new_v4().to_string();
        let new_sender = external[0].clone();
        let new_recipient = sender.to_string();
        let new_recipients_json = serde_json::json!({"to": [new_recipient], "cc": []}).to_string();

        info!(
            operation = "pong_intercepted",
            email_id = %new_id,
            from = %new_sender,
            to = %new_recipient,
            subject = %subject,
            "Pong intercepted at HTTP API — redirecting as inbound"
        );

        state
            .factories
            .email
            .create_inbound(
                &new_id,
                &api_key.system_id,
                &new_sender,
                &new_recipients_json,
                subject,
                &markdown_body,
                None, // endpoints
                None, // attachments
                headers_json.as_deref(),
                0, // max_retries
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Pong redirect failed".to_string(),
                        detail: Some(e.to_string()),
                    }),
                )
            })?;

        let _ = state.trigger_tx.try_send(new_id.clone());
        return Ok((
            StatusCode::OK,
            Json(SendEmailResponse {
                email_id: new_id,
                status: "pong_redirected".to_string(),
            }),
        ));
    }

    // 7a. Outbound: one record for all external recipients
    if !external.is_empty() {
        let email_id = Uuid::new_v4().to_string();
        let external_to: Vec<String> = external
            .iter()
            .filter(|e| to_set.contains(*e))
            .map(|e| full_addr(e))
            .collect();
        let external_cc: Vec<String> = external
            .iter()
            .filter(|e| cc_set.contains(*e))
            .map(|e| full_addr(e))
            .collect();
        let recipients_json = Recipients {
            to: external_to,
            cc: external_cc,
        }
        .to_json();
        match state
            .factories
            .email
            .create_outbound(
                &email_id,
                &api_key.system_id,
                sender,
                &recipients_json,
                subject,
                &markdown_body,
                None, // no webhook endpoints for outbound
                attachments_json.as_deref(),
                headers_json.as_deref(), // headers
                state.config.retry.max_attempts as i32,
            )
            .await
        {
            Ok(record) => {
                state.metrics.inc_emails_queued_api();
                info!(
                    operation = "email_queued",
                    email_id = %record.id,
                    external_count = external.len(),
                    "Outbound email queued for external recipients"
                );
                created_ids.push(record.id.clone());

                // Register this email on every attachment BEFORE triggering
                // the scheduler, so cleanup sees the mail_id reference.
                if let Some(ref attachments) = req.attachments {
                    for att in attachments {
                        if let Err(e) = state
                            .factories
                            .attachment
                            .add_mail_id(&att.attachment_id, &record.id)
                            .await
                        {
                            warn!(operation="attachment_registration_failed", error=%e, attachment_id=%att.attachment_id,
                                email_id=%record.id,
                                "Failed to register mail_id on attachment");
                        }
                    }
                }

                // Trigger immediate outbound dispatch via async channel
                if let Err(e) = state.trigger_tx.try_send(record.id.clone()) {
                    warn!(
                        operation = "dispatch_trigger_failed",
                        error = %e,
                        email_id = %record.id,
                        "Failed to trigger outbound dispatch; will be picked up by periodic sweep"
                    );
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to queue outbound email".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        }
    }

    // 7b. Inbound: one shared record for all internal recipients
    if !final_internal.is_empty() {
        let email_id = Uuid::new_v4().to_string();

        // Collect all internal recipient emails, preserving to/cc membership
        let internal_emails: Vec<String> = final_internal
            .iter()
            .map(|(email, _, _, _)| email.clone())
            .collect();
        let internal_to: Vec<String> = internal_emails
            .iter()
            .filter(|e| to_set.contains(*e))
            .cloned()
            .collect();
        let internal_cc: Vec<String> = internal_emails
            .iter()
            .filter(|e| cc_set.contains(*e))
            .cloned()
            .collect();
        let recipients_json = Recipients {
            to: internal_to,
            cc: internal_cc,
        }
        .to_json();

        // Build webhook endpoints: per-recipient → domain fallback
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

        match state
            .factories
            .email
            .create_inbound(
                &email_id,
                &api_key.system_id,
                sender,
                &recipients_json,
                subject,
                &markdown_body,
                endpoints.as_deref(),
                attachments_json.as_deref(),
                headers_json.as_deref(),
                state.config.retry.max_attempts as i32,
            )
            .await
        {
            Ok(record) => {
                // Insert attachment_permissions per internal recipient (granularity unchanged)
                for (recipient, _, _, _) in &final_internal {
                    if let Some(attachments) = &req.attachments {
                        for att in attachments {
                            if let Err(e) = state
                                .factories
                                .attachment
                                .create_permission(&att.attachment_id, recipient)
                                .await
                            {
                                warn!(operation="permission_creation_failed", error=%e, attachment_id=%att.attachment_id,
                                    recipient=%recipient,
                                    "Failed to create download permission");
                            }
                        }
                    }
                }

                info!(
                    operation = "email_queued",
                    email_id = %record.id,
                    internal_count = final_internal.len(),
                    "Inbound email record created for internal delivery"
                );
                created_ids.push(record.id.clone());

                // Register this email on every attachment
                if let Some(ref attachments) = req.attachments {
                    for att in attachments {
                        if let Err(e) = state
                            .factories
                            .attachment
                            .add_mail_id(&att.attachment_id, &record.id)
                            .await
                        {
                            warn!(operation="attachment_registration_failed", error=%e, attachment_id=%att.attachment_id,
                                email_id=%record.id,
                                "Failed to register mail_id on attachment");
                        }
                    }
                }
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to queue internal email".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        }
    }

    // ── 8. Auto-reply if any recipients were filtered ──
    send_filtered_notification(
        &state.factories.email,
        &state.config,
        &api_key.system_id,
        sender,
        &filtered,
    )
    .await;

    // ── 8b. Auto-reply for unregistered addresses (domain exists but address not registered) ──
    send_unregistered_notification(
        &state.factories.email,
        &state.config,
        &api_key.system_id,
        sender,
        &unregistered,
    )
    .await;

    let status = if created_ids.is_empty() {
        // All recipients were filtered — no emails created
        info!(
            operation = "email_rejected",
            sender = %sender,
            filtered_count = filtered.len(),
            "All recipients were filtered; no email records created"
        );
        "filtered"
    } else {
        "queued"
    };

    Ok((
        StatusCode::CREATED,
        Json(SendEmailResponse {
            email_id: created_ids.first().cloned().unwrap_or_default(),
            status: status.to_string(),
        }),
    ))
}

/// Log filtered recipients and insert notification for the sender.
/// Uses auto_reply_* config fields for consistent system messaging.
async fn send_filtered_notification(
    email_factory: &crate::core::email::factory::EmailFactory,
    config: &crate::core::config::Config,
    system_id: &str,
    sender: &str,
    filtered: &[String],
) {
    if filtered.is_empty() {
        return;
    }

    info!(
        operation = "recipients_filtered",
        sender = %sender,
        filtered_count = filtered.len(),
        filtered_recipients = ?filtered,
        "Some recipients were filtered by whitelist"
    );

    // Determine system FROM address
    let auto_reply_from = config
        .relay
        .auto_reply_from
        .as_deref()
        .or(config.admin.email.as_deref())
        .unwrap_or("noreply@localhost");

    if auto_reply_from.is_empty() {
        warn!(sender = %sender, "auto_reply_from and admin.email both empty — skipping filtered notification");
        return;
    }

    // Build markdown body
    let auto_reply_body = config
        .relay
        .auto_reply_body
        .as_deref()
        .unwrap_or("This is an automated message from the amail system.");
    let body = format!(
        "{}\n\n---\n\n\
         **Filtered Recipients** (not in whitelist or blocked by policy):\n\n\
         {}\n\n\
         These recipients will NOT receive your message. \
         Please verify the addresses or contact your administrator to update whitelist settings.",
        auto_reply_body,
        filtered
            .iter()
            .map(|a| format!("  • {}", a))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let subject = format!(
        "{}[AmailGW] Filtered recipients: {} recipient(s) not delivered",
        config.relay.auto_reply_subject_prefix,
        filtered.len()
    );

    // Insert into the database so the scheduler picks it up for SMTP delivery
    let email_id = Uuid::new_v4().to_string();

    // Build proper recipients JSON: {"to":[sender],"cc":[]}
    let recipients_json = crate::core::email::storage::Recipients {
        to: vec![sender.to_string()],
        cc: vec![],
    }
    .to_json();

    if let Err(e) = email_factory
        .create_outbound(
            &email_id,
            system_id,
            auto_reply_from,
            &recipients_json,
            &subject,
            &body,
            None, // endpoints
            None, // attachments
            None, // headers
            1,    // max_attempts: notification emails need only 1 attempt
        )
        .await
    {
        warn!(operation = "notification_insert_failed", error = %e, "Failed to insert filtered-recipient email into database");
    }
}

/// Log unregistered recipients and insert notification for the sender.
/// Uses auto_reply_* config fields for consistent system messaging.
async fn send_unregistered_notification(
    email_factory: &crate::core::email::factory::EmailFactory,
    config: &crate::core::config::Config,
    system_id: &str,
    sender: &str,
    unregistered: &[String],
) {
    if unregistered.is_empty() {
        return;
    }

    info!(
        operation = "unregistered_addresses",
        sender = %sender,
        count = unregistered.len(),
        recipients = ?unregistered,
        "Recipients matched domain but address not registered — auto-reply sent"
    );

    let auto_reply_from = config
        .relay
        .auto_reply_from
        .as_deref()
        .or(config.admin.email.as_deref())
        .unwrap_or("noreply@localhost");

    if auto_reply_from.is_empty() {
        warn!(sender = %sender, "auto_reply_from and admin.email both empty — skipping unregistered notification");
        return;
    }

    let body = format!(
        "{}\n\n---\n\n\
         **Unregistered Addresses** (domain exists but address not created):\n\n\
         {}\n\n\
         These addresses belong to your domain but have not been registered. \
         Please create them via the Agent integration or contact your administrator to register these addresses.",
        config.relay.auto_reply_body.as_deref().unwrap_or(
            "This is an automated message from the amail system."
        ),
        unregistered.iter().map(|a| format!("  • {}", a)).collect::<Vec<_>>().join("\n")
    );

    let subject = format!(
        "{}[AmailGW] Unregistered addresses: {} address(es) not deliverable",
        config.relay.auto_reply_subject_prefix,
        unregistered.len()
    );

    let email_id = Uuid::new_v4().to_string();
    let recipients_json = crate::core::email::storage::Recipients {
        to: vec![sender.to_string()],
        cc: vec![],
    }
    .to_json();

    if let Err(e) = email_factory
        .create_outbound(
            &email_id,
            system_id,
            auto_reply_from,
            &recipients_json,
            &subject,
            &body,
            None, // endpoints
            None, // attachments
            None, // headers
            1,
        )
        .await
    {
        warn!(operation = "unregistered_insert_failed", error = %e, "Failed to insert unregistered-address notification");
    }
}
