//! Webhook delivery handlers.

use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::core::email::utils::sign_payload;

/// Send a single webhook POST request.
///
/// Headers: X-Webhook-Signature, X-AIMail-Timestamp.
async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    payload_bytes: &[u8],
    hmac_secret: &[u8],
    email: &str,
    timeout_secs: u64,
) -> (Option<i64>, Option<String>) {
    let (signature, timestamp_ms) = sign_payload(hmac_secret, payload_bytes);

    let request_builder = client
        .post(url)
        .body(axum::body::Bytes::copy_from_slice(payload_bytes))
        .header("content-type", "application/json")
        .header("X-AIMail-Email", email)
        .header("X-Webhook-Signature", &signature)
        .header("X-AIMail-Timestamp", timestamp_ms.to_string())
        .timeout(std::time::Duration::from_secs(timeout_secs));

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16() as i64;
            if response.status().is_success() {
                debug!(%url, %status, "Webhook delivered successfully");
                (Some(status), None)
            } else {
                let error_msg = format!("HTTP {}", status);
                warn!(operation="webhook_non_2xx", %url, %status, "Webhook returned non-2xx");
                (Some(status), Some(error_msg))
            }
        }
        Err(e) => {
            error!(operation="webhook_request_failed", %url, %e, "Webhook request failed");
            (None, Some(format!("request error: {}", e)))
        }
    }
}

/// Send a batched webhook: multiple recipients → one POST with shared body.
async fn send_batch_webhook(
    client: &reqwest::Client,
    url: &str,
    payload: &serde_json::Value,
    entries: &[(String, String)], // (email, signature_header_json)
    timeout_secs: u64,
) -> (Option<i64>, Option<String>) {
    let entry_list: Vec<serde_json::Value> = entries.iter().map(|(email, sig)| {
        let sig_val: serde_json::Value = match serde_json::from_str(sig) {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, email=%email, "batch webhook: malformed signature JSON, sending unsigned");
                serde_json::Value::default()
            }
        };
        serde_json::json!({
            "email": email,
            "signature": sig_val["X-Webhook-Signature"],
            "timestamp": sig_val["X-AIMail-Timestamp"],
        })
    }).collect();

    let mut body = payload.clone();
    body["signatures"] = serde_json::json!(entry_list);

    let request_builder = client
        .post(url)
        .json(&body)
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(timeout_secs));

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16() as i64;
            if response.status().is_success() {
                info!(%url, %status, count = entries.len(), "Batch webhook delivered successfully");
                (Some(status), None)
            } else {
                let error_msg = format!("HTTP {}", status);
                warn!(operation="batch_webhook_non_2xx", %url, %status, "Batch webhook returned non-2xx");
                (Some(status), Some(error_msg))
            }
        }
        Err(e) => {
            error!(operation="batch_webhook_request_failed", %url, %e, "Batch webhook request failed");
            (None, Some(format!("request error: {}", e)))
        }
    }
}

/// Build a webhook JSON payload from an EmailRecord.
pub fn build_webhook_payload_from_record(
    record: &crate::core::email::storage::EmailRecord,
    forwarder: &str,
    sender_signature_cache: Option<&str>,
) -> serde_json::Value {
    record.to_webhook_payload(forwarder, sender_signature_cache)
}

/// Process webhook delivery for a single email record by traversing its endpoints.
pub async fn process_email_webhook(
    env_factory: &crate::core::factory::EnvFactory,
    email_factory: &crate::core::email::factory::EmailFactory,
    config: &crate::core::config::Config,
    client: &reqwest::Client,
    record: &crate::core::email::storage::EmailRecord,
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    // 2026-09-23 (方案 §6.3): 非 manager 发件人的失败确认信上下文; None = 静默(单测/flows)。
    // sender 取 record.sender(收件人=发件人自己), to_agent 在消费点按命中地址覆盖。
    failed_ack: Option<crate::core::api::outbound::FailedCommandAck<'_>>,
) -> bool {
    // ── 0. Handle manager commands ────────────────────────────
    if handle_manager_commands(record, env_factory, email_factory, ack, failed_ack).await {
        return true; // Email processed by command, don't deliver
    }

    // Parse recipients once — used by the pull block below
    let recipients = record.recipients_parsed();

    // ── 1. Parse endpoints ──────────────────────────────────────────
    let endpoints_map: serde_json::Map<String, serde_json::Value> =
        record.endpoints_parsed().unwrap_or_default();

    // ── 2. Build payload once (same for all endpoints) ──────────────
    // Forwarder address: use relay.username if set (the mailbox that
    // actually relays outbound mail), otherwise a fixed local placeholder.
    // (The system auto-reply sender is noreply@{domain} via
    // config.system_sender(); it is not a relay identity.)
    let forwarder = config
        .relay
        .username
        .as_deref()
        .unwrap_or("relay@aimail-relay.local");

    let mut payload =
        build_webhook_payload_from_record(record, forwarder, record.sender_signature.as_deref());

    // ── Inbound interceptor chain ──
    let interceptors_snapshot = env_factory
        .get_interceptors()
        .read()
        .ok()
        .map(|guard| guard.iter().map(Arc::clone).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut intercepted = false;
    for interceptor in &interceptors_snapshot {
        match interceptor.intercept(record, &mut payload).await {
            crate::core::strategy::InterceptorDecision::Handled => {
                tracing::info!(
                    operation = "interceptor_handled",
                    interceptor = %interceptor.name(),
                    email_id = %record.id,
                    "Interceptor handled email; skipping webhook"
                );
                intercepted = true;
                break;
            }
            crate::core::strategy::InterceptorDecision::PassThrough => {}
        }
    }
    if intercepted {
        return true;
    }

    // Save cleaned body + extracted signature atomically (first time only)
    if record.sender_signature.is_none() {
        let cleaned_body = payload["body"].as_str().unwrap_or(&record.body);
        let sig = payload
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Err(e) = email_factory
            .update_email_body_and_signature(&record.id, cleaned_body, sig)
            .await
        {
            tracing::warn!(
                operation = "save_cleaned_body_failed",
                email_id = %record.id,
                error = %e,
                "Failed to persist cleaned body/signature — will re-process on retry"
            );
        }
    }

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let body_len = payload
        .get("body")
        .and_then(|v| v.as_str())
        .map_or(0, |s| s.len());
    let subject = payload
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    tracing::info!(
        operation = "webhook_payload_built",
        email_id = %record.id,
        body_len = body_len,
        subject = subject,
        "Webhook payload built; inserting pending delivery"
    );

    // ── 2.5 Pull-mode: sign enriched payload, insert pending ────────
    // Pre-scan recipients for pull-mode domains.  Pull recipients are
    // stored in pending_deliveries (signed, enriched payload) instead
    // of POSTed via webhook.  Other recipients proceed through the
    // normal endpoint loop below.
    let mut any_endpoint = false;
    // AUDIT-1 P1-2: track whether we attempted pull-mode insertion at all.
    // When pull recipients exist but EVERY insert_pending_delivery fails,
    // we must NOT report success (email would be completed + deleted =
    // silent loss). Only a clean "nothing to deliver" path returns true.
    let mut pull_attempted = false;
    let mut pull_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    let payload_json = String::from_utf8(payload_bytes.clone()).unwrap_or_default();
    {
        // Delivery targets only (rcpt) — to/cc is now the full post-filter
        // list and may include external (MX) addresses that have no webhook.
        for addr in recipients.delivery() {
            // Resolve address with domain-level fallback (Type 3)
            let d = env_factory
                .resolve_domain_from_address(addr)
                .await
                .unwrap_or(None);
            if let Some(ref d) = d {
                let is_pull = d.webhook_url.as_deref().is_none_or(|u| u.trim().is_empty());
                if is_pull {
                    // Determine the correct key for the endpoints map.
                    let ep_key: String = if endpoints_map.contains_key(addr) {
                        addr.to_string()
                    } else if endpoints_map.contains_key(&d.domain) {
                        d.domain.clone()
                    } else {
                        // Pull domain with no endpoint key — use bare domain
                        d.domain.clone()
                    };

                    // Skip if already delivered (retry of mixed pull+webhook email)
                    let already_done = endpoints_map
                        .get(&ep_key)
                        .and_then(|ep| ep.get("status"))
                        .and_then(|s| s.as_str())
                        .map(|s| s == "success" || s == "delivered")
                        .unwrap_or(false);
                    if already_done {
                        pull_domains.insert(ep_key.clone());
                        continue;
                    }
                    // Sign with address-level webhook_secret, fall back to domain-level
                    // resolve_domain_from_address handles both tiers in one call
                    let ws_secret: Option<String> = env_factory
                        .resolve_domain_from_address(addr)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|rec| rec.webhook_secret);

                    let sig = if let Some(ref secret) = ws_secret {
                        let (signature, ts_ms) = sign_payload(secret.as_bytes(), &payload_bytes);
                        serde_json::json!({
                            "X-Webhook-Signature": signature,
                            "X-AIMail-Timestamp": ts_ms.to_string(),
                        })
                    } else {
                        warn!(email_id = %record.id, domain = %d.domain,
                              "No webhook_secret for pull domain — unsigned delivery");
                        serde_json::json!({
                            "X-Webhook-Signature": "",
                        })
                    };
                    let headers_json = serde_json::to_string(&serde_json::json!({
                        "X-AIMail-Email": addr,
                        "X-Webhook-Signature": sig["X-Webhook-Signature"],
                        "X-AIMail-Timestamp": sig["X-AIMail-Timestamp"],
                        "content-type": "application/json",
                    }))
                    .unwrap_or_default();
                    // payload_json computed once before the loop (same for all pull recipients)

                    if let Err(e) = env_factory
                        .db
                        .insert_pending_delivery(
                            &d.system_id,
                            &ep_key,
                            addr,
                            &headers_json,
                            &payload_json,
                        )
                        .await
                    {
                        pull_attempted = true;
                        warn!(email_id = %record.id, domain = %d.domain, error = %e,
                              "Failed to insert pending delivery");
                    } else {
                        any_endpoint = true;
                        info!(email_id = %record.id, domain = %d.domain, recipient = %addr,
                              "Inserted pending delivery (pull mode)");
                        // Mark endpoint success so check_all_endpoints_completed
                        // passes for mixed pull+webhook scenarios.
                        if let Err(e) = email_factory
                            .update_endpoint_status(&record.id, &ep_key, "success")
                            .await
                        {
                            warn!(email_id = %record.id, domain = %d.domain, error = %e,
                                  "Failed to mark endpoint success for pull domain");
                        }
                        pull_domains.insert(ep_key);
                    }
                }
            }
        }
    }

    // ── 3. Group push endpoints by URL, batch-dispatch ───────────────
    // Endpoints sharing the same URL (i.e. same bridge) are batched into
    // a single POST with one shared body and per-recipient signatures.
    let timeout_secs = config.webhook.timeout_secs;
    let mut all_succeeded = true;

    // First pass: collect non-pull pending endpoints, grouped by URL
    let mut url_groups: std::collections::HashMap<String, Vec<(String, String, String)>> =
        std::collections::HashMap::new();
    // value = Vec<(domain, secret, email)>

    for (domain, endpoint_obj) in &endpoints_map {
        if pull_domains.contains(domain.as_str()) {
            continue;
        }
        any_endpoint = true;

        let status = endpoint_obj
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if status != "pending" {
            continue;
        }

        let url = endpoint_obj
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if url.is_empty() {
            warn!(email_id = %record.id, %domain, "Endpoint has no URL — skipping");
            continue;
        }

        // Extract secret (same logic as before)
        let secret: String;
        let endpoint_secret = endpoint_obj
            .get("secret")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(s) = endpoint_secret {
            secret = s;
        } else {
            match env_factory.lookup_domain_addr(domain).await {
                Ok(Some(domain_record)) => {
                    match env_factory.resolve_webhook_for_domain(&domain_record).await {
                        Ok((_domain_url, domain_secret)) => {
                            secret = domain_secret;
                        }
                        Err(e) => {
                            warn!(email_id = %record.id, %domain, error = %e,
                                  "Failed to resolve webhook — unsigned");
                            secret = String::new();
                        }
                    }
                }
                _ => {
                    secret = String::new();
                }
            }
        }

        let email_for_header: String = if domain.contains('@') {
            domain.to_string()
        } else {
            recipients
                .to
                .iter()
                .chain(recipients.cc.iter())
                .find(|r| r.rsplit('@').next() == Some(domain.as_str()))
                .cloned()
                .unwrap_or_else(|| domain.to_string())
        };

        url_groups.entry(url.to_string()).or_default().push((
            domain.to_string(),
            secret,
            email_for_header,
        ));
    }

    if !any_endpoint {
        if pull_attempted {
            // AUDIT-1 P1-2: every pull insertion failed — report failure so
            // the scheduler retries instead of completing+deleting the email.
            warn!(
                email_id = %record.id,
                "Pull-mode pending insertion failed for all recipients — scheduling retry"
            );
            return false;
        }
        info!(operation="pull_mode", email_id = %record.id, "Pull mode — no webhook push endpoint, email queued for bridge");
        return true;
    }

    // Second pass: dispatch (batched if >1 recipient per URL)
    for (url, entries) in url_groups {
        if entries.len() > 1 {
            // Batch: sign each entry, send one POST
            let signed: Vec<(String, String)> = entries
                .iter()
                .map(|(_domain, secret, email)| {
                    let sig = if secret.is_empty() {
                        serde_json::json!({"X-Webhook-Signature": "", "X-AIMail-Timestamp": ""})
                    } else {
                        let (signature, ts_ms) = sign_payload(secret.as_bytes(), &payload_bytes);
                        serde_json::json!({
                            "X-Webhook-Signature": signature,
                            "X-AIMail-Timestamp": ts_ms.to_string(),
                        })
                    };
                    (email.clone(), sig.to_string())
                })
                .collect();

            let (response_code, last_error) =
                send_batch_webhook(client, &url, &payload, &signed, timeout_secs).await;

            for (domain, _secret, _email) in &entries {
                if last_error.is_none() {
                    if let Err(e) = email_factory
                        .update_endpoint_status(&record.id, domain, "success")
                        .await
                    {
                        error!(operation="endpoint_status_update_failed", email_id = %record.id, %domain, error = %e,
                               "Failed to update endpoint status to 'success'");
                        all_succeeded = false;
                    } else {
                        info!(operation="batch_delivery_success", email_id = %record.id, %domain, %url,
                              response_code = ?response_code, "Batch endpoint delivered");
                    }
                } else {
                    warn!(operation="batch_delivery_failed", email_id = %record.id, %domain, %url,
                          response_code = ?response_code, error = ?last_error, "Batch delivery failed");
                    all_succeeded = false;
                }
            }
        } else {
            // Single endpoint — existing behavior
            let (domain, secret, email) = &entries[0];
            let (response_code, last_error) = send_webhook(
                client,
                &url,
                &payload_bytes,
                secret.as_bytes(),
                email,
                timeout_secs,
            )
            .await;

            if last_error.is_none() {
                if let Err(e) = email_factory
                    .update_endpoint_status(&record.id, domain, "success")
                    .await
                {
                    error!(operation="endpoint_status_update_failed", email_id = %record.id, %domain, error = %e,
                           "Failed to update endpoint status to 'success'");
                    all_succeeded = false;
                } else {
                    info!(operation="webhook_delivery_success", email_id = %record.id, %domain, %url,
                          response_code = ?response_code, "Webhook endpoint delivered successfully");
                }
            } else {
                warn!(operation="webhook_delivery_failed", email_id = %record.id, %domain, %url,
                      response_code = ?response_code, error = ?last_error, "Webhook endpoint delivery failed");
                all_succeeded = false;
            }
        }
    }

    match email_factory
        .check_all_endpoints_completed(&record.id)
        .await
    {
        Ok(all_completed) => {
            if all_completed {
                debug!(operation="all_endpoints_completed", email_id = %record.id, "All endpoints completed successfully");
            } else {
                warn!(
                    operation="endpoints_not_all_completed",
                    email_id = %record.id,
                    "Not all endpoints completed — some deliveries failed"
                );
            }
            all_succeeded && all_completed
        }
        Err(e) => {
            error!(
                operation="check_endpoints_failed",
                email_id = %record.id,
                error = %e,
                "Failed to check all endpoints completed"
            );
            false
        }
    }
}

/// Manager commands parsed from manager's email.
enum ManagerCommand {
    /// Composite approval: updates persona and/or signature in one upsert.
    PersonaApproval {
        persona: String,
        signature: String,
    },
    AddContact(String, Option<String>), // email to add, optional description
    RemoveContact(String),              // email to remove
}

/// Is this line a marker that ends a persona-approval payload section?
///
/// The approval is a **command block**: `persona:` / `signature:` lines plus
/// their immediate continuation lines. Anything a mail client appends after it
/// — the quoted thread, the RFC 3676 signature divider (`-- `), a reply
/// attribution, or trailing draft boilerplate — must not leak into the stored
/// values. Observed 2026-09-21 on a real approval: the stored signature came
/// back as `"<sig line>\n---\n<draft note>\n--\n<placeholder>"`.
fn payload_terminator(line: &str) -> bool {
    if line.is_empty() {
        return true; // blank line ends the command block (quoted thread follows)
    }
    let lower = line.to_lowercase();
    // Quote prefix
    if line.starts_with('>') {
        return true;
    }
    // RFC 3676 signature delimiter (`-- ` / `--`)
    if line == "--" || line.starts_with("-- ") {
        return true;
    }
    // A rule made only of dashes/underscores (`---`, `—`, `––`, `____`)
    if line
        .chars()
        .all(|c| matches!(c, '-' | '—' | '–' | '_' | ' '))
    {
        return true;
    }
    // Reply attributions / quoted-message headers
    if lower.contains("original message") {
        return true;
    }
    if lower.starts_with("on ") && lower.contains("wrote:") {
        return true;
    }
    if lower.contains("写道:") || lower.contains("写道：") {
        return true;
    }
    if lower.starts_with("from:") || lower.starts_with("发件人") || lower.starts_with("sent:") {
        return true;
    }
    false
}

/// A line that is nothing but a `<...>` placeholder (e.g. `<出站邮件签名>`):
/// draft boilerplate, never real content.
fn is_placeholder_line(line: &str) -> bool {
    line.len() >= 2 && line.starts_with('<') && line.ends_with('>')
}

fn push_capture(target: &mut String, line: &str) {
    if !target.is_empty() {
        target.push('\n');
    }
    target.push_str(line);
}

/// Parse the persona/signature payload out of an approval email body.
///
/// Tightened 2026-09-21: capture stops at the first `payload_terminator` **after
/// a section started** (markers before the first `persona:`/`signature:` line are
/// just skipped, so a reply that quotes the original above the command still
/// parses). `<...>` placeholder lines are dropped.
fn parse_persona_approval(body: &str) -> Option<(String, String)> {
    let mut persona = String::new();
    let mut signature = String::new();
    let mut section = 0usize; // 0 = preamble, 1 = persona, 2 = signature
    for line in body.lines() {
        let trimmed = line.trim();
        if section != 0 && payload_terminator(trimmed) {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("persona:") {
            section = 1;
            persona = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("signature:") {
            section = 2;
            signature = rest.trim().to_string();
        } else if section == 1 && !trimmed.is_empty() {
            if !is_placeholder_line(trimmed) {
                push_capture(&mut persona, trimmed);
            }
        } else if section == 2 && !trimmed.is_empty() && !is_placeholder_line(trimmed) {
            push_capture(&mut signature, trimmed);
        }
    }
    if persona.is_empty() && signature.is_empty() {
        None
    } else {
        Some((persona, signature))
    }
}

/// Parse email body for manager commands.
fn parse_manager_command(body: &str) -> Option<ManagerCommand> {
    let lower = body.to_lowercase();

    // Persona approval (composite) — checked first so its body text
    // cannot be misparsed as a contact command.
    for trigger in &["approve persona", "批准角色"] {
        if lower.find(trigger).is_some() {
            if let Some((persona, signature)) = parse_persona_approval(body) {
                return Some(ManagerCommand::PersonaApproval { persona, signature });
            }
        }
    }

    // Add contact
    for prefix in &["add ", "添加 ", "加入 "] {
        if let Some(pos) = lower.find(prefix) {
            let rest = &body[pos + prefix.len()..];
            // Look for keywords indicating contact management
            if let Some(end_pos) = rest.to_lowercase().find(" to my contacts") {
                let email = rest[..end_pos].trim().to_string();
                if !email.is_empty() && email.contains('@') {
                    let add_email = email.clone();
                    let desc = extract_description_from_body(body);
                    return Some(ManagerCommand::AddContact(add_email, desc));
                }
            }
            if let Some(end_pos) = rest.to_lowercase().find(" to contacts") {
                let email = rest[..end_pos].trim().to_string();
                if !email.is_empty() && email.contains('@') {
                    let add_email = email.clone();
                    let desc = extract_description_from_body(body);
                    return Some(ManagerCommand::AddContact(add_email, desc));
                }
            }
        }
    }

    // Remove contact
    for prefix in &["remove ", "delete ", "移除 ", "删除 "] {
        if let Some(pos) = lower.find(prefix) {
            let rest = &body[pos + prefix.len()..];
            if let Some(end_pos) = rest.to_lowercase().find(" from my contacts") {
                let email = rest[..end_pos].trim().to_string();
                if !email.is_empty() && email.contains('@') {
                    return Some(ManagerCommand::RemoveContact(email));
                }
            }
            if let Some(end_pos) = rest.to_lowercase().find(" from contacts") {
                let email = rest[..end_pos].trim().to_string();
                if !email.is_empty() && email.contains('@') {
                    return Some(ManagerCommand::RemoveContact(email));
                }
            }
        }
    }

    None
}

/// Process manager commands from email. Returns true if email was consumed by a command.
async fn handle_manager_commands(
    record: &crate::core::email::storage::EmailRecord,
    env_factory: &crate::core::factory::EnvFactory,
    _email_factory: &crate::core::email::factory::EmailFactory,
    // 2026-09-22: 指令确认信需要入队+触发投递 ⇒ 需要 HttpState; 单测无 state 时传 None
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    // 2026-09-23 (方案 §6.3"指令必有回复"): 非 manager 发件人的失败确认信上下文。
    // 两路都传 None = 行为与 2026-09-22 之前完全一致(静默); 只有命令路径会同时给两路。
    failed_ack: Option<crate::core::api::outbound::FailedCommandAck<'_>>,
) -> bool {
    let body = &record.body;
    if body.is_empty() {
        return false;
    }

    let cmd = match parse_manager_command(body) {
        Some(c) => c,
        None => return false,
    };

    // Find matching agent address, verify sender is manager.
    // Use delivery targets (rcpt, base addresses) — recipients.to holds the
    // full persona addresses, which would miss the base-keyed meta lookup
    // when the manager addresses a persona-prefixed recipient.
    let recipients = record.recipients_parsed();
    for to_addr in recipients.delivery() {
        let agent_meta = match env_factory.resolve_domain_addr_meta(to_addr).await {
            Ok(Some(m)) => m,
            _ => continue,
        };
        if agent_meta.manager_address.is_empty() || record.sender != agent_meta.manager_address {
            // 2026-09-23 (方案 §6.3"指令必有回复"): 非 manager 发的指令邮件不消费、不投 agent
            // (原行为保留), 但**必须回失败确认信** —— 否则发件方完全无反馈。meta 不动。
            if let Some(ref fa) = failed_ack {
                send_failed_command_ack(
                    fa,
                    to_addr,
                    &format!("sender {} is not the manager of {}", record.sender, to_addr),
                )
                .await;
            }
            continue;
        }

        match &cmd {
            ManagerCommand::PersonaApproval { persona, signature } => {
                // Omitted sections (empty string) must keep the existing
                // value — the meta upsert overwrites every column, so passing
                // an empty string would wipe the stored signature/persona.
                let sig = if signature.is_empty() {
                    agent_meta.agent_signature.as_str()
                } else {
                    signature.as_str()
                };
                let per = if persona.is_empty() {
                    agent_meta.agent_persona.as_str()
                } else {
                    persona.as_str()
                };
                if let Err(e) = env_factory
                    .upsert_domain_addr_meta(
                        to_addr,
                        &agent_meta.system_id,
                        Some(&agent_meta.manager_address),
                        Some(sig),
                        Some(per),
                    )
                    .await
                {
                    warn!(operation="manager_persona_approval_failed", error = %e, "Failed to apply persona approval");
                    send_command_ack(
                        ack,
                        to_addr,
                        &record.sender,
                        &agent_meta.system_id,
                        "approve persona",
                        "",
                        Some(&e.to_string()),
                    )
                    .await;
                    return false;
                }
                info!(operation="manager_persona_approved", agent = %to_addr, "Manager command: persona and/or signature approved");
                let applied = format!(
                    "persona = {per}\n          signature = {sig}{}",
                    if persona.is_empty() || signature.is_empty() {
                        "\n          (unchanged: omitted section keeps its previous value)"
                    } else {
                        ""
                    }
                );
                send_command_ack(
                    ack,
                    to_addr,
                    &record.sender,
                    &agent_meta.system_id,
                    "approve persona",
                    &applied,
                    None,
                )
                .await;
                return true;
            }
            ManagerCommand::AddContact(email, description) => {
                // Add to whitelist (direction=all) so agent can both send and receive
                if let Err(e) = env_factory
                    .create_whitelist_entry(to_addr, "all", email, description.as_deref())
                    .await
                {
                    warn!(operation="manager_add_contact_failed", error = %e, "Failed to add contact");
                    send_command_ack(
                        ack,
                        to_addr,
                        &record.sender,
                        &agent_meta.system_id,
                        "add contact",
                        "",
                        Some(&e.to_string()),
                    )
                    .await;
                    return false;
                }
                info!(operation="manager_contact_added", domain = %to_addr, email = %email, "Manager command: contact added");
                send_command_ack(
                    ack,
                    to_addr,
                    &record.sender,
                    &agent_meta.system_id,
                    "add contact",
                    &format!("{email} added to your contacts (direction: all)"),
                    None,
                )
                .await;
                return true;
            }
            ManagerCommand::RemoveContact(email) => {
                if let Err(e) = env_factory
                    .delete_whitelist_entry_by_value(to_addr, email)
                    .await
                {
                    warn!(operation="manager_remove_contact_failed", error = %e, "Failed to remove contact");
                    send_command_ack(
                        ack,
                        to_addr,
                        &record.sender,
                        &agent_meta.system_id,
                        "remove contact",
                        "",
                        Some(&e.to_string()),
                    )
                    .await;
                    return false;
                }
                info!(operation="manager_contact_removed", domain = %to_addr, email = %email, "Manager command: contact removed");
                send_command_ack(
                    ack,
                    to_addr,
                    &record.sender,
                    &agent_meta.system_id,
                    "remove contact",
                    &format!("{email} removed from your contacts"),
                    None,
                )
                .await;
                return true;
            }
        }
    }
    false
}

/// 非 manager 发件人的失败确认信(2026-09-23, 方案 §6.3"失败场景 ⇒ 收到失败确认信")。
/// 与成功确认信同一发出方(`noreply@{domain}`)与同一正文骨架, Result 段固定 FAILED。
/// 入队失败只 warn —— 确认信失败不影响指令处理路径本身。
async fn send_failed_command_ack(
    fa: &crate::core::api::outbound::FailedCommandAck<'_>,
    to_agent: &str,
    reason: &str,
) {
    let from = fa.cfg.system_sender();
    let ts = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string();
    let subject = "[AIMail] Command failed: not authorized".to_string();
    let body = format!(
        "Your command email for {to_agent} was received but NOT applied.\n\n\
         Command : (manager command detected)\n\
         Result  : FAILED - {reason}\n\
         Time    : {ts}\n\n\
         Only the address manager may issue manager commands for this agent.\n\
         --\n\
         Automated confirmation from {from}; do not reply.\n",
    );
    if let Err(e) = crate::core::api::outbound::enqueue_outbound_simple(
        fa.cfg,
        fa.email_factory,
        fa.metrics,
        fa.trigger_tx,
        fa.system_id,
        &from,
        fa.sender,
        &subject,
        &body,
    )
    .await
    {
        warn!(
            operation = "command_ack_enqueue_failed",
            error = %e,
            to = %fa.sender,
            "failed to enqueue failed-command confirmation mail"
        );
    }
}

/// 安全员指令确认信 —— 2026-09-22 用户要求"**指令邮件必有回复**": 成功与失败都回一封。
///
/// from `noreply@{domain}`(系统发件人) ⇒ 不满足网关的消费条件(sender == meta.manager_address)
/// ⇒ 不会把确认信当成新指令消费, 无自激回环。失败也回信: 否则静默失败无从发现。
async fn send_command_ack(
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    to_agent: &str,
    sender: &str,
    system_id: &str,
    command: &str,
    applied: &str,
    error: Option<&str>,
) {
    let Some(ack) = ack else { return };
    let from = ack.cfg.system_sender();
    let subject = match error {
        None => format!("[AIMail] Command applied: {command}"),
        Some(_) => format!("[AIMail] Command failed: {command}"),
    };
    let ts = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string();
    let body = match error {
        None => format!(
            "Your command email for {to_agent} has been received and applied.\n\n\
             Command : {command}\n\
             Result  : OK\n\
             Applied : {applied}\n\
             Time    : {ts}\n\n\
             --\n\
             Automated confirmation from {from}; do not reply.\n"
        ),
        Some(e) => format!(
            "Your command email for {to_agent} was received but NOT applied.\n\n\
             Command : {command}\n\
             Result  : FAILED - {e}\n\
             Time    : {ts}\n\n\
             --\n\
             Automated confirmation from {from}; do not reply.\n"
        ),
    };
    if let Err(e) = crate::core::api::outbound::enqueue_outbound_simple(
        ack.cfg,
        ack.email_factory,
        ack.metrics,
        ack.trigger_tx,
        system_id,
        &from,
        sender,
        &subject,
        &body,
    )
    .await
    {
        warn!(
            operation = "command_ack_enqueue_failed",
            error = %e,
            to = %sender,
            "failed to enqueue command confirmation mail"
        );
    }
}

/// Extract description from email body (line after 'description:' or 'desc:').
fn extract_description_from_body(body: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("description:") {
            let val = rest.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("desc:") {
            let val = rest.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::core::email::utils::html_to_markdown;
    use crate::core::email::utils::sign_payload;

    // ─── manager command parsing tests ───

    #[test]
    fn test_parse_persona_approval_both_sections() {
        let body =
            "approve persona\npersona: I am an email assistant.\nsignature: Best regards\nBob";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "I am an email assistant.");
                assert_eq!(signature, "Best regards\nBob");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_multiline_persona() {
        let body = "approve persona\npersona: Line one\nLine two\nsignature: sig";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "Line one\nLine two");
                assert_eq!(signature, "sig");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_chinese_trigger() {
        let body = "批准角色\npersona: 我是助手\nsignature: 此致敬礼";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "我是助手");
                assert_eq!(signature, "此致敬礼");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_only_signature() {
        let body = "approve persona\nsignature: New sig";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert!(persona.is_empty());
                assert_eq!(signature, "New sig");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_trigger_without_sections_is_not_command() {
        // Trigger present but no sections → not a command (falls through).
        assert!(super::parse_manager_command("approve persona, please see attached").is_none());
    }

    // 2026-09-21 生产实测: 真实批准回信的表体形如
    //   approve persona / persona: … / signature: <sig> / 空行 / --- / 说明 / -- / <占位符>
    // 修复前 signature 被贪婪吞下 "---"、说明行与占位符。
    #[test]
    fn test_parse_persona_approval_stops_at_blank_line() {
        let body = "approve persona\npersona: 我是 pi\nsignature: — pi · AI Agent\n\n---\n\
                    以上为 persona 与 signature 草案。审阅后回复 approve persona 即可确认生效。\n\n--\n<出站邮件签名>";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "我是 pi");
                assert_eq!(signature, "— pi · AI Agent");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_quoted_thread_not_captured() {
        let body = "approve persona\npersona: p\nsignature: s\n> quoted original\n> more";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "p");
                assert_eq!(signature, "s");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_parse_persona_approval_placeholder_and_attribution_dropped() {
        let body = "approve persona\npersona: p1\nsignature: s1\n<出站邮件签名>\nOn 2026-09-21, pi wrote:\nold";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "p1");
                assert_eq!(signature, "s1");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    // 以破折号开头的**值**要保留(如 "— pi · AI Agent"), 只有整行破折号才是分隔符。
    #[test]
    fn test_parse_persona_approval_dash_value_kept() {
        let body = "approve persona\npersona: p\nsignature:\n— pi · AI Agent\n---\nnote";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "p");
                assert_eq!(signature, "— pi · AI Agent");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    // 回信把原信引在**上方**时仍要解析出指令(终止符只在进入 section 后生效)。
    #[test]
    fn test_parse_persona_approval_quote_above_command_still_parses() {
        let body = "> On 2026-09-21, pi wrote:\n> persona: old\n\napprove persona\npersona: new p\nsignature: new s";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "new p");
                assert_eq!(signature, "new s");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn test_legacy_role_signature_triggers_are_dead() {
        // Removed triggers must no longer parse as commands.
        assert!(super::parse_manager_command("set my role to assistant").is_none());
        assert!(super::parse_manager_command("set signature to bye").is_none());
        assert!(super::parse_manager_command("签名设为 再见").is_none());
    }

    #[test]
    fn test_parse_add_contact_still_works() {
        let body = "please add bob@example.com to my contacts\ndescription: Bob";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::AddContact(email, desc)) => {
                assert_eq!(email, "bob@example.com");
                assert_eq!(desc.as_deref(), Some("Bob"));
            }
            _ => panic!("expected AddContact"),
        }
    }

    #[test]
    fn test_parse_remove_contact_still_works() {
        let body = "remove bob@example.com from my contacts";
        match super::parse_manager_command(body) {
            Some(super::ManagerCommand::RemoveContact(email)) => {
                assert_eq!(email, "bob@example.com")
            }
            _ => panic!("expected RemoveContact"),
        }
    }

    // ─── html_to_markdown tests ───

    #[test]
    fn test_html_to_markdown_headings() {
        let html = "<h1>Heading 1</h1><h2>Heading 2</h2><h3>Heading 3</h3>";
        let md = html_to_markdown(html);
        assert!(md.contains("# Heading 1"));
        assert!(md.contains("## Heading 2"));
        assert!(md.contains("### Heading 3"));
    }

    #[test]
    fn test_html_to_markdown_paragraphs() {
        let html = "<p>First</p><p>Second</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("First"));
        assert!(md.contains("Second"));
    }

    #[test]
    fn test_html_to_markdown_bold_italic() {
        let html = "<b>Bold</b><i>Italic</i>";
        let md = html_to_markdown(html);
        assert!(md.contains("**Bold**"));
        assert!(md.contains("*Italic*"));
    }

    #[test]
    fn test_html_to_markdown_links() {
        let html = "<a href=\"https://example.com\">Link</a>";
        let md = html_to_markdown(html);
        assert!(md.contains("[Link](https://example.com)"));
    }

    #[test]
    fn test_html_to_markdown_lists() {
        let html = "<ul><li>Item 1</li><li>Item 2</li></ul>";
        let md = html_to_markdown(html);
        assert!(md.contains("- Item 1"));
        assert!(md.contains("- Item 2"));
    }

    #[test]
    fn test_html_to_markdown_code() {
        let html = "<code>fn main() {}</code>";
        let md = html_to_markdown(html);
        assert!(md.contains("`fn main() {}`"));
    }

    #[test]
    fn test_html_to_markdown_empty() {
        let md = html_to_markdown("");
        assert_eq!(md, "");
    }

    #[test]
    fn test_html_to_markdown_nested_tags() {
        let html = "<p>This is <b>bold</b> and <i>italic</i></p>";
        let md = html_to_markdown(html);
        assert!(md.contains("This is"));
        assert!(md.contains("**bold**"));
        assert!(md.contains("*italic*"));
    }

    #[test]
    fn test_html_to_markdown_line_breaks() {
        let html = "<p>Line 1</p>\n<p>Line 2</p>";
        let md = html_to_markdown(html);
        assert!(md.contains("Line 1"));
        assert!(md.contains("Line 2"));
    }

    // ─── sign_payload tests ───

    #[test]
    fn test_sign_payload_produces_hex_signature() {
        let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
        let (signature, timestamp) = sign_payload(b"test-secret", &body);
        // No v1= prefix — raw hex HMAC-SHA256
        assert!(!signature.starts_with("v1="));
        assert!(timestamp > 0);
        assert_eq!(signature.len(), 64); // 64 hex chars
    }

    #[test]
    fn test_sign_payload_deterministic_for_same_input() {
        let secret = b"test-hmac-secret";
        let body = b"fixed-body";
        let (sig1, _) = sign_payload(secret, body);
        let (sig2, _) = sign_payload(secret, body);
        assert_eq!(sig1, sig2);
    }

    // ─── P2-1: approve persona merge semantics (integration) ───

    use crate::base::strategy::BaseSystemStore;
    use crate::core::email::factory::EmailFactory;
    use crate::core::email::storage::EmailRecord;
    use crate::core::factory::EnvFactory;

    fn approval_env() -> (EnvFactory, EmailFactory) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-wb-approval-{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::core::storage::Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let arc = std::sync::Arc::new(db);
        let env = EnvFactory::new(arc.clone(), std::sync::Arc::new(BaseSystemStore));
        let ef = EmailFactory::new(
            arc,
            std::path::PathBuf::from("/tmp/aimailgw-wb-att"),
            std::sync::Arc::new(BaseSystemStore),
        );
        (env, ef)
    }

    fn approval_record(body: &str) -> EmailRecord {
        EmailRecord {
            id: "t1".to_string(),
            status: "pending".to_string(),
            system_id: "sys1".to_string(),
            direction: "inbound".to_string(),
            sender: "mgr@ext.com".to_string(),
            recipients: r#"{"to":["agent@test.com"],"cc":[],"rcpt":["agent@test.com"]}"#
                .to_string(),
            endpoints: None,
            subject: "approve persona".to_string(),
            body: body.to_string(),
            headers: None,
            attachments: None,
            send_count: 0,
            last_sent_at: String::new(),
            next_retry_at: None,
            max_attempts: 3,
            created_at: String::new(),
            sender_signature: None,
        }
    }

    async fn seed_agent(env: &EnvFactory) {
        env.create_domain(
            "d1",
            "sys1",
            "agent@test.com",
            Some("http://hook"),
            None,
            Some("mgr@ext.com"),
        )
        .await
        .unwrap();
        env.upsert_domain_addr_meta(
            "agent@test.com",
            "sys1",
            Some("mgr@ext.com"),
            Some("old sig"),
            Some("old persona"),
        )
        .await
        .unwrap();
    }

    // P2-1: persona-only approval must NOT wipe the existing signature.
    #[tokio::test]
    async fn persona_approval_only_persona_keeps_signature() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let rec = approval_record("approve persona\npersona: new persona only");
        assert!(
            super::handle_manager_commands(&rec, &env, &ef, None, None).await,
            "approval must be consumed"
        );
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.agent_persona, "new persona only");
        assert_eq!(
            meta.agent_signature, "old sig",
            "signature must be preserved"
        );
        assert_eq!(meta.manager_address, "mgr@ext.com");
    }

    // P2-1: signature-only approval must NOT wipe the existing persona.
    #[tokio::test]
    async fn persona_approval_only_signature_keeps_persona() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let rec = approval_record("approve persona\nsignature: new sig only");
        assert!(super::handle_manager_commands(&rec, &env, &ef, None, None).await);
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.agent_signature, "new sig only");
        assert_eq!(
            meta.agent_persona, "old persona",
            "persona must be preserved"
        );
    }

    // P2-1: both sections replace both values.
    #[tokio::test]
    async fn persona_approval_both_sections_replaces_both() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let rec = approval_record("approve persona\npersona: p2\nsignature: s2");
        assert!(super::handle_manager_commands(&rec, &env, &ef, None, None).await);
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.agent_persona, "p2");
        assert_eq!(meta.agent_signature, "s2");
    }

    // ── 2026-09-23 (方案 §6.3"指令必有回复"): 非 manager 发件人也必须收到失败确认信 ──

    /// 构造带 ack 能力的 Config(Default + smtp.hostname)。
    fn ack_cfg() -> crate::core::config::Config {
        let mut c = crate::core::config::Config::default();
        c.smtp.hostname = Some("e2e.local".to_string());
        c
    }

    // 非 manager 发指令 ⇒ 不消费(false, 邮件照常投递), 但发件人收到
    // "Command failed: not authorized" 失败确认信; meta 两个值都不被改写。
    #[tokio::test]
    async fn non_manager_command_gets_failed_ack_and_meta_untouched() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        // approval_record 固定 sender=mgr@ext.com(= manager);非 manager 场景换发件人。
        let mut rec =
            approval_record("approve persona\npersona: rogue persona\nsignature: rogue sig");
        rec.sender = "stranger@ext.com".to_string();
        let fa = Some(crate::core::api::outbound::FailedCommandAck {
            cfg: &cfg,
            email_factory: &ef,
            metrics: None,
            trigger_tx: None,
            sender: &rec.sender,
            system_id: &rec.system_id,
        });
        assert!(
            !super::handle_manager_commands(&rec, &env, &ef, None, fa).await,
            "non-manager command must NOT be consumed"
        );
        // meta 未被改写
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            meta.agent_persona, "old persona",
            "meta must stay untouched"
        );
        assert_eq!(meta.agent_signature, "old sig", "meta must stay untouched");
        // 失败确认信已入队: from noreply@e2e.local → to stranger@ext.com, Command failed
        let acks = env.db.list_emails(50).await.unwrap();
        let ack = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] Command failed"));
        let ack = ack.expect("non-manager command must get a failed confirmation mail");
        assert_eq!(ack.sender, "noreply@e2e.local");
        assert!(
            ack.recipients.contains("stranger@ext.com"),
            "ack must go to the command sender"
        );
        assert!(ack.body.contains("Result  : FAILED"));
        assert!(ack.body.contains("is not the manager of agent@test.com"));
    }

    // 无 failed_ack 上下文(如 flows 路径)⇒ 行为与旧版一致: 不消费、无确认信、meta 不动。
    #[tokio::test]
    async fn non_manager_command_without_failed_ack_ctx_stays_silent() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let mut rec =
            approval_record("approve persona\npersona: rogue persona\nsignature: rogue sig");
        rec.sender = "stranger@ext.com".to_string();
        assert!(!super::handle_manager_commands(&rec, &env, &ef, None, None).await);
        let acks = env.db.list_emails(50).await.unwrap();
        assert!(
            !acks.iter().any(|m| m.subject.contains("Command")),
            "no ack may be enqueued when failed_ack is None"
        );
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.agent_persona, "old persona");
        assert_eq!(meta.agent_signature, "old sig");
    }
}
