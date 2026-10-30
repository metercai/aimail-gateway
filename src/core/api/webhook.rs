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
    // 2026-09-23 (plan §6.3): failure-confirmation context for a non-manager sender; None = silent (unit tests / flows).
    // sender comes from record.sender (recipient = the sender themselves); to_agent is overridden at the consumption point per hit address.
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
                        // Wake long-pull / SSE waiters. The insert is already
                        // committed (the `.call` above resolved), so both the
                        // system key (bridge/system-scope waiters) and the
                        // per-address key (agent-scope waiters) are safe to
                        // signal. Each waiter re-queries under its OWN filter,
                        // so waking both is always correct: a waiter whose key
                        // does not match this row simply sees nothing new.
                        let notifier = crate::core::pending_notifier::PendingNotifier::global();
                        notifier.notify_system(&d.system_id);
                        notifier.notify_email(&d.system_id, &addr.to_lowercase());
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
            // 2-tier resolve (full address → bare domain), matching the pull
            // pre-scan; a bare-domain registration with an address-keyed
            // endpoint must still sign.
            match env_factory.resolve_domain_from_address(domain).await {
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

/// Manager commands parsed from a `[CMD]`-subjected mail.
#[derive(Debug)]
enum ManagerCommand {
    /// Composite approval: updates persona and/or signature in one upsert.
    PersonaApproval {
        persona: String,
        signature: String,
    },
    AddContact(String, Option<String>), // email to add, optional description
    RemoveContact(String),              // email to remove
    /// Transfer the address manager: `new_manager` is the new safety-officer
    /// address (from `to`), `agent` is the managed agent address (from `cc`).
    TransferManager {
        new_manager: String,
        agent: String,
    },
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

/// The four manager-command kinds, keyed by their subject trigger.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CommandKind {
    ApprovePersona,
    AddContact,
    RemoveContact,
    ChangeManager,
}

/// Canonical (English) command name used in confirmation-mail subjects.
fn kind_name(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::ApprovePersona => "approve persona",
        CommandKind::AddContact => "add contact",
        CommandKind::RemoveContact => "remove contact",
        CommandKind::ChangeManager => "change manager",
    }
}

/// Stage 1 — detect a manager command from the mail **subject**.
///
/// A command mail's subject must **start with** the `[CMD]` marker
/// (case-insensitive), followed by one of the known command names at a word
/// boundary. This is a strict prefix match: a reply subject such as
/// `Re: [CMD] approve persona` is NOT a command — the welcome mail instructs
/// the manager to *set* the subject to exactly `[CMD] <command>`, not merely
/// keep it. Unknown command names (e.g. `[CMD] foo`) are not commands.
///
/// Returns `None` when the subject is not a recognized trigger — the mail then
/// falls through to normal delivery.
fn detect_command(subject: &str) -> Option<CommandKind> {
    let s = subject.trim_start().to_lowercase();
    let rest = s.strip_prefix("[cmd]")?.trim_start();
    const TRIGGERS: [(&str, CommandKind); 6] = [
        ("approve persona", CommandKind::ApprovePersona),
        ("批准角色", CommandKind::ApprovePersona),
        ("add contact", CommandKind::AddContact),
        ("remove contact", CommandKind::RemoveContact),
        ("change manager", CommandKind::ChangeManager),
        ("更换安全员", CommandKind::ChangeManager),
    ];
    for (name, kind) in TRIGGERS {
        if matches_name(rest, name) {
            return Some(kind);
        }
    }
    None
}

/// `rest` starts with `name` and the match ends at a word boundary (end of
/// string, whitespace, or ':'). Both arguments are already lowercased.
fn matches_name(rest: &str, name: &str) -> bool {
    let Some(after) = rest.strip_prefix(name) else {
        return false;
    };
    after.is_empty() || after.starts_with(|c: char| c.is_whitespace()) || after.starts_with(':')
}

/// Stage 2 — validate the body/headers against a detected command's payload
/// rules. Returns the fully-populated `ManagerCommand` on success, or the
/// specific unmet condition on failure (surfaced verbatim in the failed ack).
fn match_payload(
    kind: CommandKind,
    record: &crate::core::email::storage::EmailRecord,
) -> Result<ManagerCommand, String> {
    let body = &record.body;
    match kind {
        CommandKind::ApprovePersona => parse_persona_approval(body)
            .map(|(persona, signature)| ManagerCommand::PersonaApproval { persona, signature })
            .ok_or_else(|| {
                "no 'persona:' and/or 'signature:' section found in the body".to_string()
            }),
        CommandKind::AddContact => parse_add_contact_body(body)
            .ok_or_else(|| "body must be of the form 'add <email> to my contacts'".to_string()),
        CommandKind::RemoveContact => parse_remove_contact_body(body).ok_or_else(|| {
            "body must be of the form 'remove <email> from my contacts'".to_string()
        }),
        CommandKind::ChangeManager => {
            let recipients = record.recipients_parsed();
            let to = &recipients.to;
            let cc = &recipients.cc;
            if to.len() != 1 {
                return Err(format!(
                    "exactly one recipient in To: is required (the new manager); found {}",
                    to.len()
                ));
            }
            if cc.len() != 1 {
                return Err(format!(
                    "exactly one recipient in Cc: is required (the managed agent); found {}",
                    cc.len()
                ));
            }
            let new_manager = to[0].trim().to_string();
            let agent = cc[0].trim().to_string();
            if !new_manager.contains('@') {
                return Err(format!("To: address '{new_manager}' is not a valid email"));
            }
            if !agent.contains('@') {
                return Err(format!("Cc: address '{agent}' is not a valid email"));
            }
            // Head/body cross-consistency: the body must name both the new
            // manager (To) and the managed agent (Cc).
            let body_lc = body.to_lowercase();
            let nm_lc = new_manager.to_lowercase();
            let ag_lc = agent.to_lowercase();
            if !body_lc.contains(&nm_lc) {
                return Err(format!("body must name the new manager ({new_manager})"));
            }
            if !body_lc.contains(&ag_lc) {
                return Err(format!("body must name the managed agent ({agent})"));
            }
            if !body_lc.contains("change manager") && !body_lc.contains("更换安全员") {
                return Err("body must contain 'change manager' (or '更换安全员')".to_string());
            }
            Ok(ManagerCommand::TransferManager { new_manager, agent })
        }
    }
}

/// Body payload for `add contact`: `add <email> to my contacts` (or `to
/// contacts`), with an optional `description:` line. Extracted verbatim from
/// the former body-trigger parser.
fn parse_add_contact_body(body: &str) -> Option<ManagerCommand> {
    let lower = body.to_lowercase();
    for prefix in &["add ", "添加 ", "加入 "] {
        if let Some(pos) = lower.find(prefix) {
            let rest = &body[pos + prefix.len()..];
            let rest_lc = rest.to_lowercase();
            for kw in &[" to my contacts", " to contacts"] {
                if let Some(end_pos) = rest_lc.find(kw) {
                    let email = rest[..end_pos].trim().to_string();
                    if !email.is_empty() && email.contains('@') {
                        let desc = extract_description_from_body(body);
                        return Some(ManagerCommand::AddContact(email, desc));
                    }
                }
            }
        }
    }
    None
}

/// Body payload for `remove contact`: `remove <email> from my contacts` (or
/// `from contacts`). Extracted verbatim from the former body-trigger parser.
fn parse_remove_contact_body(body: &str) -> Option<ManagerCommand> {
    let lower = body.to_lowercase();
    for prefix in &["remove ", "delete ", "移除 ", "删除 "] {
        if let Some(pos) = lower.find(prefix) {
            let rest = &body[pos + prefix.len()..];
            let rest_lc = rest.to_lowercase();
            for kw in &[" from my contacts", " from contacts"] {
                if let Some(end_pos) = rest_lc.find(kw) {
                    let email = rest[..end_pos].trim().to_string();
                    if !email.is_empty() && email.contains('@') {
                        return Some(ManagerCommand::RemoveContact(email));
                    }
                }
            }
        }
    }
    None
}

/// Process manager commands from a `[CMD]`-subjected mail.
///
/// Four-stage isomorphic pipeline, shared by all four command kinds. Stage 1
/// **detect** reads the subject trigger; if it is not a trigger the mail is
/// not a command and gets normal delivery (return false). Stage 2 **payload**
/// validates the body/headers per kind; a trigger hit with an incomplete
/// payload triggers D3: a failed ack, with no consumption and no delivery
/// (return true). Stage 3 **execute** resolves the managed agent, checks
/// auth (sender == current manager), and applies the change to the DB. Stage
/// 4 **ack** sends one confirmation mail per outcome (applied / failed).
///
/// Returns true when the mail was consumed by a command (do not deliver it).
async fn handle_manager_commands(
    record: &crate::core::email::storage::EmailRecord,
    env_factory: &crate::core::factory::EnvFactory,
    _email_factory: &crate::core::email::factory::EmailFactory,
    // 2026-09-22: the command confirmation mail needs enqueue + delivery trigger => requires HttpState; pass None in unit tests without state
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    // 2026-09-23 (plan §6.3 "every command gets a reply"): failure-confirmation context for a non-manager sender.
    // both routes None = behavior identical to before 2026-09-22 (silent); only the command path supplies both routes.
    failed_ack: Option<crate::core::api::outbound::FailedCommandAck<'_>>,
) -> bool {
    // ── Stage 1: subject trigger ─────────────────────────────────
    let kind = match detect_command(&record.subject) {
        Some(k) => k,
        None => return false, // not a command → normal delivery
    };
    let name = kind_name(kind);

    // The managed agent: the `change manager` kind identifies it from the Cc
    // header (its payload), the other three from the delivery target (rcpt /
    // base address — recipients.to may hold persona-prefixed addresses that
    // would miss the base-keyed meta lookup).
    match kind {
        CommandKind::ChangeManager => {
            handle_change_manager(record, env_factory, ack, failed_ack, name).await
        }
        other => handle_regular_command(other, record, env_factory, ack, failed_ack, name).await,
    }
}

/// The three contact/persona command kinds: the managed agent is the mail's
/// delivery target (a command mail addresses a single agent).
async fn handle_regular_command(
    kind: CommandKind,
    record: &crate::core::email::storage::EmailRecord,
    env_factory: &crate::core::factory::EnvFactory,
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    failed_ack: Option<crate::core::api::outbound::FailedCommandAck<'_>>,
    name: &str,
) -> bool {
    // Managed agent = the first delivery target. A command mail addresses a
    // single agent, so there is exactly one.
    let recipients = record.recipients_parsed();
    let Some(agent) = recipients.delivery().next() else {
        return false; // no delivery target → normal delivery
    };
    // If the target is not a registered agent on this gateway we cannot
    // confirm this is a command → deliver normally (never swallow a mail whose
    // target we cannot identify).
    let meta = match env_factory.resolve_domain_addr_meta(agent).await {
        Ok(Some(m)) => m,
        _ => return false,
    };

    // ── Stage 2: payload match ───────────────────────────────────
    match match_payload(kind, record) {
        Err(reason) => {
            // D3: the target is a real managed agent and the subject triggered,
            // so this is a (malformed) command → failed ack, do not deliver.
            if let Some(fa) = &failed_ack {
                send_failed_command_ack(fa, agent, name, &reason).await;
            }
            true
        }
        Ok(cmd) => {
            // ── Stage 3: auth + execute ──────────────────────────
            if meta.manager_address.is_empty() || record.sender != meta.manager_address {
                // unauthorized: failed ack, mail is delivered as usual (the
                // agent does not auto-execute commands; only the gateway applies).
                if let Some(fa) = &failed_ack {
                    send_failed_command_ack(
                        fa,
                        agent,
                        name,
                        &format!("sender {} is not the manager of {}", record.sender, agent),
                    )
                    .await;
                }
                return false;
            }
            let applied = match execute_regular(kind, &cmd, agent, &meta, env_factory, ack).await {
                Ok(a) => a,
                Err(e) => {
                    // exec error: failed ack, mail delivered as usual (preserved).
                    send_command_ack(
                        ack,
                        agent,
                        &record.sender,
                        &meta.system_id,
                        name,
                        "",
                        Some(&e),
                    )
                    .await;
                    return false;
                }
            };
            // ── Stage 4: success ack to the manager ──────────────
            send_command_ack(
                ack,
                agent,
                &record.sender,
                &meta.system_id,
                name,
                &applied,
                None,
            )
            .await;
            true
        }
    }
}

/// The `change manager` kind: the managed agent is the Cc address and the new
/// manager is the To address, both validated by the payload. On success the
/// old manager gets the applied ack (a) and the new manager gets the
/// "you are now the manager" notice (c); the agent itself is not notified (b).
async fn handle_change_manager(
    record: &crate::core::email::storage::EmailRecord,
    env_factory: &crate::core::factory::EnvFactory,
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    failed_ack: Option<crate::core::api::outbound::FailedCommandAck<'_>>,
    name: &str,
) -> bool {
    // ── Stage 2: payload match (identifies new_manager=To, agent=Cc) ──
    match match_payload(CommandKind::ChangeManager, record) {
        Err(reason) => {
            // D3 — but only swallow when the managed agent (Cc) is a real
            // registered agent; otherwise deliver normally.
            let label = record
                .recipients_parsed()
                .cc
                .first()
                .cloned()
                .unwrap_or_default();
            if !label.is_empty() && agent_is_registered(env_factory, &label).await {
                if let Some(fa) = &failed_ack {
                    send_failed_command_ack(fa, &label, name, &reason).await;
                }
                return true;
            }
            false
        }
        Ok(ManagerCommand::TransferManager { new_manager, agent }) => {
            // The managed agent must be registered on this gateway.
            let meta = match env_factory.resolve_domain_addr_meta(&agent).await {
                Ok(Some(m)) => m,
                _ => return false, // deliver normally
            };
            // ── Stage 3: auth + execute ──────────────────────────
            if meta.manager_address.is_empty() || record.sender != meta.manager_address {
                if let Some(fa) = &failed_ack {
                    send_failed_command_ack(
                        fa,
                        &agent,
                        name,
                        &format!("sender {} is not the manager of {}", record.sender, agent),
                    )
                    .await;
                }
                return false; // unauthorized: delivered as usual (preserved)
            }
            // The meta upsert overwrites every column, so pass the existing
            // persona/signature back verbatim — only manager_address changes.
            let sig = meta.agent_signature.clone();
            let per = meta.agent_persona.clone();
            if let Err(e) = env_factory
                .upsert_domain_addr_meta(
                    &agent,
                    &meta.system_id,
                    Some(&new_manager),
                    Some(&sig),
                    Some(&per),
                )
                .await
            {
                send_command_ack(
                    ack,
                    &agent,
                    &record.sender,
                    &meta.system_id,
                    name,
                    "",
                    Some(&e.to_string()),
                )
                .await;
                return false; // exec error: delivered as usual (preserved)
            }
            info!(operation="manager_transferred", agent=%agent, new_manager=%new_manager, "Manager command: manager transferred");
            // (a) applied ack to the old manager (the sender).
            let applied = format!(
                "manager of {agent} changed: {} → {new_manager}",
                record.sender
            );
            send_command_ack(
                ack,
                &agent,
                &record.sender,
                &meta.system_id,
                name,
                &applied,
                None,
            )
            .await;
            // (c) notice to the new manager.
            notify_new_manager(ack, &new_manager, &agent, &meta.system_id).await;
            true
        }
        _ => false, // unreachable: ChangeManager payload always yields TransferManager
    }
}

/// Apply the DB change for the three contact/persona kinds and return the
/// "applied" description. For persona approval this also sends the closed-loop
/// "now effective" mail to the agent itself.
async fn execute_regular(
    kind: CommandKind,
    cmd: &ManagerCommand,
    agent: &str,
    meta: &crate::core::storage::DomainAddrMetaRecord,
    env_factory: &crate::core::factory::EnvFactory,
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
) -> Result<String, String> {
    match (kind, cmd) {
        (CommandKind::ApprovePersona, ManagerCommand::PersonaApproval { persona, signature }) => {
            // Omitted sections (empty) keep the existing value — the meta
            // upsert overwrites every column, so an empty string would wipe it.
            let sig = if signature.is_empty() {
                meta.agent_signature.as_str()
            } else {
                signature.as_str()
            };
            let per = if persona.is_empty() {
                meta.agent_persona.as_str()
            } else {
                persona.as_str()
            };
            env_factory
                .upsert_domain_addr_meta(
                    agent,
                    &meta.system_id,
                    Some(&meta.manager_address),
                    Some(sig),
                    Some(per),
                )
                .await
                .map_err(|e| e.to_string())?;
            info!(operation="manager_persona_approved", agent=%agent, "Manager command: persona and/or signature approved");
            let applied = format!(
                "persona = {per}\n          signature = {sig}{}",
                if persona.is_empty() || signature.is_empty() {
                    "\n          (unchanged: omitted section keeps its previous value)"
                } else {
                    ""
                }
            );
            // Closed loop: the agent first receives the "now effective" mail
            // (in pull mode it has no other way to know it may speak as the persona).
            notify_agent_persona_applied(ack, agent, &meta.system_id, per, sig).await;
            Ok(applied)
        }
        (CommandKind::AddContact, ManagerCommand::AddContact(email, description)) => {
            // Add to whitelist (direction=all) so agent can both send and receive
            env_factory
                .create_whitelist_entry(agent, "all", email, description.as_deref())
                .await
                .map_err(|e| e.to_string())?;
            info!(operation="manager_contact_added", domain=%agent, email=%email, "Manager command: contact added");
            Ok(format!("{email} added to your contacts (direction: all)"))
        }
        (CommandKind::RemoveContact, ManagerCommand::RemoveContact(email)) => {
            env_factory
                .delete_whitelist_entry_by_value(agent, email)
                .await
                .map_err(|e| e.to_string())?;
            info!(operation="manager_contact_removed", domain=%agent, email=%email, "Manager command: contact removed");
            Ok(format!("{email} removed from your contacts"))
        }
        _ => Err("internal: command kind does not match payload".to_string()),
    }
}

/// Is `addr` a registered agent on this gateway (has an addr-meta row)?
async fn agent_is_registered(env_factory: &crate::core::factory::EnvFactory, addr: &str) -> bool {
    matches!(
        env_factory.resolve_domain_addr_meta(addr).await,
        Ok(Some(_))
    )
}

/// (c) "You are now the manager" notice — sent to the **new** manager after a
/// successful transfer. Mirrors `notify_agent_persona_applied`: an internal
/// recipient (same gateway domain) uses `create_inbound` so it goes through the
/// webhook/pull chain; an external recipient uses `create_outbound` (MX).
async fn notify_new_manager(
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    new_manager: &str,
    agent: &str,
    system_id: &str,
) {
    let Some(ack) = ack else { return };
    let from = ack.cfg.system_sender();
    let subject = format!("[AIMail] You are now the manager of {agent}");
    let body = format!(
        "You are now the manager (safety officer) of {agent}.\n\n\
         To issue a manager command for this agent, send a mail whose subject\n\
         is set to exactly [CMD] <command> (for example [CMD] approve persona),\n\
         with the command details in the body.\n\n\
         --\n\
         Automated confirmation from {from}; do not reply.\n"
    );
    let email_id = format!("sys_manager_{}", uuid::Uuid::new_v4());
    let domain = from.split('@').nth(1).unwrap_or("").to_lowercase();
    let is_internal = new_manager.to_lowercase().ends_with(&format!("@{domain}"));
    let headers = serde_json::json!({
        "message_id": format!("<{}@{}>", uuid::Uuid::new_v4(), domain),
    })
    .to_string();
    let res = if is_internal {
        // Push-mode internal recipients need the webhook endpoint attached,
        // otherwise process_email_webhook sees an empty endpoints_map and
        // completes + deletes the mail silently. Pull-mode recipients resolve
        // to no endpoint ("{}") and stay covered by the recipients pre-scan.
        let eps = ack
            .email_factory
            .env_factory
            .build_endpoints_for_recipients(&[new_manager.to_string()])
            .await;
        let eps = (eps != "{}").then_some(eps);
        ack.email_factory
            .create_inbound(
                &email_id,
                system_id,
                &from,
                new_manager,
                &subject,
                &body,
                eps.as_deref(),
                None,
                Some(headers.as_str()),
                3,
            )
            .await
    } else {
        let recipients = serde_json::json!({ "to": [new_manager] }).to_string();
        ack.email_factory
            .create_outbound(
                &email_id,
                system_id,
                &from,
                &recipients,
                &subject,
                &body,
                None,
                None,
                Some(headers.as_str()),
                3,
            )
            .await
    };
    match res {
        Ok(_) => {
            if let Some(tx) = ack.trigger_tx {
                if let Err(e) = tx.try_send(email_id.clone()) {
                    warn!(
                        operation = "manager_notify_trigger_dropped",
                        error = %e,
                        to = %new_manager,
                        "new-manager notification queued but the trigger was dropped; the sweep will pick it up"
                    );
                }
            }
        }
        Err(e) => warn!(
            operation = "manager_notify_failed",
            error = %e,
            to = %new_manager,
            "failed to queue the new-manager notification mail"
        ),
    }
}

/// Failure confirmation mail for any command that was NOT applied (incomplete
/// payload, unauthorized sender, or execution error). Same sender
/// (`noreply@{domain}`) and same body skeleton as the success confirmation
/// mail; the Result section is fixed to FAILED and names the specific unmet
/// condition. An enqueue failure only warns - a confirmation-mail failure does
/// not affect the command-handling path itself.
async fn send_failed_command_ack(
    fa: &crate::core::api::outbound::FailedCommandAck<'_>,
    to_agent: &str,
    command: &str,
    reason: &str,
) {
    let from = fa.cfg.system_sender();
    let ts = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string();
    let subject = format!("[AIMail] Command failed: {command}");
    let body = format!(
        "Your command email for {to_agent} was received but NOT applied.\n\n\
         Command : {command}\n\
         Result  : FAILED - {reason}\n\
         Time    : {ts}\n\n\
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

/// Safety-officer command confirmation mail - 2026-09-22 user requirement "**every command mail gets a reply**": one mail for success and for failure alike.
///
/// from `noreply@{domain}` (system sender) => it does not meet the gateway's consumption condition (sender == meta.manager_address)
/// => the confirmation mail is never consumed as a new command; no self-excitation loopback. Failures get a reply too: otherwise silent failures go unnoticed.
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

/// "Persona now effective" closed-loop mail - sent to the agent itself. The safety-officer ack only reaches the officer; in pull mode
/// the agent has no other way to learn that it may already speak as the persona.
///
/// A recipient **inside** the same gateway **cannot** use `enqueue_outbound_simple`: pull-mode addresses have no
/// webhook endpoint => the helper falls back to MX => the SMTP sender's loopback prevention drops it outright
/// (observed in server.log: `loopback_skip recipient=...`). Internal recipients use the same approach as board notifications:
/// create an inbound record (`create_inbound`), which then goes through the webhook/pull delivery chain.
async fn notify_agent_persona_applied(
    ack: Option<crate::core::api::outbound::AckCtx<'_>>,
    to_agent: &str,
    system_id: &str,
    persona: &str,
    signature: &str,
) {
    let Some(ack) = ack else { return };
    let from = ack.cfg.system_sender();
    let body = persona_applied_body(to_agent, persona, signature, &from);
    let subject = "[AIMail] Persona applied";
    let email_id = format!("sys_persona_{}", uuid::Uuid::new_v4());
    let domain = from.split('@').nth(1).unwrap_or("").to_lowercase();
    let is_internal = to_agent.to_lowercase().ends_with(&format!("@{}", domain));
    // a proper notice needs its own message_id (threading/dedup/host display all read it).
    let headers = serde_json::json!({
        "message_id": format!("<{}@{}>", uuid::Uuid::new_v4(), domain),
    })
    .to_string();
    let res = if is_internal {
        // Push-mode internal recipients need the webhook endpoint attached,
        // otherwise process_email_webhook sees an empty endpoints_map and
        // completes + deletes the mail silently. Pull-mode recipients resolve
        // to no endpoint ("{}") and stay covered by the recipients pre-scan.
        let eps = ack
            .email_factory
            .env_factory
            .build_endpoints_for_recipients(&[to_agent.to_string()])
            .await;
        let eps = (eps != "{}").then_some(eps);
        ack.email_factory
            .create_inbound(
                &email_id,
                system_id,
                &from,
                to_agent,
                subject,
                &body,
                eps.as_deref(),
                None,
                Some(headers.as_str()),
                3,
            )
            .await
    } else {
        let recipients = serde_json::json!({ "to": [to_agent] }).to_string();
        ack.email_factory
            .create_outbound(
                &email_id,
                system_id,
                &from,
                &recipients,
                subject,
                &body,
                None,
                None,
                Some(headers.as_str()),
                3,
            )
            .await
    };
    match res {
        Ok(_) => {
            if let Some(tx) = ack.trigger_tx {
                if let Err(e) = tx.try_send(email_id.clone()) {
                    warn!(
                        operation = "persona_applied_ack_trigger_dropped",
                        error = %e,
                        to = %to_agent,
                        "persona-applied confirmation queued but the trigger was dropped; the sweep will pick it up"
                    );
                }
            }
        }
        Err(e) => warn!(
            operation = "persona_applied_ack_failed",
            error = %e,
            to = %to_agent,
            "failed to queue the persona-applied confirmation mail"
        ),
    }
}

fn persona_applied_body(to_agent: &str, persona: &str, signature: &str, from: &str) -> String {
    format!(
        "Your persona and signature are now active on {to_agent}.

persona    : {persona}
signature  : {signature}
my_profile : injected into every inbound message from now on

Nothing else is required — this closes the activation.

--
Automated confirmation from {from}; do not reply.
"
    )
}

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
    use super::persona_applied_body;
    use crate::core::email::utils::html_to_markdown;
    use crate::core::email::utils::sign_payload;

    // ─── subject-trigger (stage 1) detection tests ───

    #[test]
    fn detect_command_recognizes_all_triggers() {
        assert_eq!(
            super::detect_command("[CMD] approve persona"),
            Some(super::CommandKind::ApprovePersona)
        );
        assert_eq!(
            super::detect_command("[CMD] 批准角色"),
            Some(super::CommandKind::ApprovePersona)
        );
        assert_eq!(
            super::detect_command("[CMD] add contact"),
            Some(super::CommandKind::AddContact)
        );
        assert_eq!(
            super::detect_command("[CMD] remove contact"),
            Some(super::CommandKind::RemoveContact)
        );
        assert_eq!(
            super::detect_command("[CMD] change manager"),
            Some(super::CommandKind::ChangeManager)
        );
        assert_eq!(
            super::detect_command("[CMD] 更换安全员"),
            Some(super::CommandKind::ChangeManager)
        );
    }

    #[test]
    fn detect_command_is_case_insensitive_and_tolerates_missing_space() {
        assert_eq!(
            super::detect_command("  [cmd] Approve Persona"),
            Some(super::CommandKind::ApprovePersona)
        );
        assert_eq!(
            super::detect_command("[CMD]approve persona"),
            Some(super::CommandKind::ApprovePersona)
        );
    }

    #[test]
    fn detect_command_rejects_reply_prefix_unknown_and_non_boundary() {
        // A reply prefix (Re: ...) is NOT a command — the manager must set the
        // subject to exactly `[CMD] <command>` (welcome-mail contract).
        assert_eq!(super::detect_command("Re: [CMD] approve persona"), None);
        assert_eq!(super::detect_command("[CMD] foo"), None);
        assert_eq!(super::detect_command("[CMD] add contactx"), None);
        assert_eq!(super::detect_command("approve persona"), None); // no [CMD] marker
        assert_eq!(super::detect_command(""), None);
        assert_eq!(
            super::detect_command("[AIMail] Command applied: approve persona"),
            None
        );
    }

    // ─── body-payload (stage 2) match tests ───

    fn payload_record(subject: &str, body: &str) -> crate::core::email::storage::EmailRecord {
        crate::core::email::storage::EmailRecord {
            id: "t1".to_string(),
            status: "pending".to_string(),
            system_id: "sys1".to_string(),
            direction: "inbound".to_string(),
            sender: "mgr@ext.com".to_string(),
            recipients: r#"{"to":["agent@test.com"],"cc":[],"rcpt":["agent@test.com"]}"#
                .to_string(),
            endpoints: None,
            subject: subject.to_string(),
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

    #[test]
    fn match_payload_approve_persona_both_sections() {
        let rec = payload_record(
            "[CMD] approve persona",
            "approve persona\npersona: I am an email assistant.\nsignature: Best regards\nBob",
        );
        match super::match_payload(super::CommandKind::ApprovePersona, &rec) {
            Ok(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert_eq!(persona, "I am an email assistant.");
                assert_eq!(signature, "Best regards\nBob");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn match_payload_approve_persona_only_signature() {
        let rec = payload_record(
            "[CMD] approve persona",
            "approve persona\nsignature: New sig",
        );
        match super::match_payload(super::CommandKind::ApprovePersona, &rec) {
            Ok(super::ManagerCommand::PersonaApproval { persona, signature }) => {
                assert!(persona.is_empty());
                assert_eq!(signature, "New sig");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    // D3: subject triggered but no payload sections => the match fails (the
    // caller then sends a failed ack and does not deliver).
    #[test]
    fn match_payload_approve_persona_missing_sections_is_err() {
        let rec = payload_record(
            "[CMD] approve persona",
            "approve persona, please see attached",
        );
        assert!(super::match_payload(super::CommandKind::ApprovePersona, &rec).is_err());
    }

    // 2026-09-21 production observation: a real approval reply body looks like
    //   approve persona / persona: ... / signature: <sig> / blank line / --- / description / -- / <placeholder>
    // before the fix, signature greedily swallowed the "---", the description line and the placeholder.
    #[test]
    fn parse_persona_approval_stops_at_blank_line() {
        let body = "approve persona\npersona: 我是 pi\nsignature: — pi · AI Agent\n\n---\n\
                    以上为 persona 与 signature 草案。审阅后回复 approve persona 即可确认生效。\n\n--\n<出站邮件签名>";
        match super::parse_persona_approval(body) {
            Some((persona, signature)) => {
                assert_eq!(persona, "我是 pi");
                assert_eq!(signature, "— pi · AI Agent");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn parse_persona_approval_quoted_thread_not_captured() {
        let body = "approve persona\npersona: p\nsignature: s\n> quoted original\n> more";
        match super::parse_persona_approval(body) {
            Some((persona, signature)) => {
                assert_eq!(persona, "p");
                assert_eq!(signature, "s");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn parse_persona_approval_placeholder_and_attribution_dropped() {
        let body = "approve persona\npersona: p1\nsignature: s1\n<出站邮件签名>\nOn 2026-09-21, pi wrote:\nold";
        match super::parse_persona_approval(body) {
            Some((persona, signature)) => {
                assert_eq!(persona, "p1");
                assert_eq!(signature, "s1");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    // a **value** starting with a dash must be kept (e.g. "— pi · AI Agent"); only an all-dash line is a separator.
    #[test]
    fn parse_persona_approval_dash_value_kept() {
        let body = "approve persona\npersona: p\nsignature:\n— pi · AI Agent\n---\nnote";
        match super::parse_persona_approval(body) {
            Some((persona, signature)) => {
                assert_eq!(persona, "p");
                assert_eq!(signature, "— pi · AI Agent");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    // when a reply quotes the original mail **above**, the command must still be parsed (terminators only take effect once inside a section).
    #[test]
    fn parse_persona_approval_quote_above_command_still_parses() {
        let body = "> On 2026-09-21, pi wrote:\n> persona: old\n\napprove persona\npersona: new p\nsignature: new s";
        match super::parse_persona_approval(body) {
            Some((persona, signature)) => {
                assert_eq!(persona, "new p");
                assert_eq!(signature, "new s");
            }
            _ => panic!("expected PersonaApproval"),
        }
    }

    #[test]
    fn match_payload_add_contact_still_works() {
        let rec = payload_record(
            "[CMD] add contact",
            "please add bob@example.com to my contacts\ndescription: Bob",
        );
        match super::match_payload(super::CommandKind::AddContact, &rec) {
            Ok(super::ManagerCommand::AddContact(email, desc)) => {
                assert_eq!(email, "bob@example.com");
                assert_eq!(desc.as_deref(), Some("Bob"));
            }
            _ => panic!("expected AddContact"),
        }
    }

    #[test]
    fn match_payload_add_contact_missing_email_is_err() {
        let rec = payload_record("[CMD] add contact", "please add bob to my contacts");
        assert!(super::match_payload(super::CommandKind::AddContact, &rec).is_err());
    }

    #[test]
    fn match_payload_remove_contact_still_works() {
        let rec = payload_record(
            "[CMD] remove contact",
            "remove bob@example.com from my contacts",
        );
        match super::match_payload(super::CommandKind::RemoveContact, &rec) {
            Ok(super::ManagerCommand::RemoveContact(email)) => {
                assert_eq!(email, "bob@example.com")
            }
            _ => panic!("expected RemoveContact"),
        }
    }

    // ─── change manager (transfer) payload tests ───

    fn transfer_record(
        to: &[&str],
        cc: &[&str],
        body: &str,
    ) -> crate::core::email::storage::EmailRecord {
        let recipients = format!(
            r#"{{"to":[{}],"cc":[{}]}}"#,
            to.iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(","),
            cc.iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        crate::core::email::storage::EmailRecord {
            id: "t1".to_string(),
            status: "pending".to_string(),
            system_id: "sys1".to_string(),
            direction: "inbound".to_string(),
            sender: "oldmgr@ext.com".to_string(),
            recipients,
            endpoints: None,
            subject: "[CMD] change manager".to_string(),
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

    #[test]
    fn match_payload_transfer_complete_is_ok() {
        let rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com for agent@test.com",
        );
        match super::match_payload(super::CommandKind::ChangeManager, &rec) {
            Ok(super::ManagerCommand::TransferManager { new_manager, agent }) => {
                assert_eq!(new_manager, "newmgr@ext.com");
                assert_eq!(agent, "agent@test.com");
            }
            e => panic!("expected TransferManager, got {e:?}"),
        }
    }

    #[test]
    fn match_payload_transfer_chinese_alias_is_ok() {
        let mut rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "更换安全员 to newmgr@ext.com for agent@test.com",
        );
        rec.subject = "[CMD] 更换安全员".to_string();
        match super::match_payload(super::CommandKind::ChangeManager, &rec) {
            Ok(super::ManagerCommand::TransferManager { new_manager, .. }) => {
                assert_eq!(new_manager, "newmgr@ext.com");
            }
            e => panic!("expected TransferManager, got {e:?}"),
        }
    }

    #[test]
    fn match_payload_transfer_two_to_is_err() {
        let rec = transfer_record(
            &["newmgr@ext.com", "extra@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com for agent@test.com",
        );
        assert!(super::match_payload(super::CommandKind::ChangeManager, &rec).is_err());
    }

    #[test]
    fn match_payload_transfer_no_cc_is_err() {
        let rec = transfer_record(
            &["newmgr@ext.com"],
            &[],
            "change manager to newmgr@ext.com for agent@test.com",
        );
        assert!(super::match_payload(super::CommandKind::ChangeManager, &rec).is_err());
    }

    #[test]
    fn match_payload_transfer_body_missing_new_manager_is_err() {
        let rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "change manager to somebody for agent@test.com",
        );
        assert!(super::match_payload(super::CommandKind::ChangeManager, &rec).is_err());
    }

    #[test]
    fn match_payload_transfer_body_missing_agent_is_err() {
        let rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com",
        );
        assert!(super::match_payload(super::CommandKind::ChangeManager, &rec).is_err());
    }

    #[test]
    fn match_payload_transfer_body_missing_semantic_is_err() {
        // body names both addresses but lacks the 'change manager'/'更换安全员' marker
        let rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "please forward newmgr@ext.com and agent@test.com",
        );
        assert!(super::match_payload(super::CommandKind::ChangeManager, &rec).is_err());
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
            subject: "[CMD] approve persona".to_string(),
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
    #[test]
    fn persona_applied_body_carries_the_applied_values() {
        let body = persona_applied_body("a@x.test", "I am A.", "-- A", "noreply@x.test");
        assert!(body.contains("a@x.test"), "{body}");
        assert!(body.contains("I am A."), "{body}");
        assert!(body.contains("-- A"), "{body}");
        assert!(body.contains("do not reply"), "{body}");
    }

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

    // ── 2026-09-23 (plan §6.3 "every command gets a reply"): a non-manager sender must also receive a failure confirmation mail ──

    /// Build a Config with ack capability (Default + smtp.hostname).
    fn ack_cfg() -> crate::core::config::Config {
        let mut c = crate::core::config::Config::default();
        c.smtp.hostname = Some("e2e.local".to_string());
        c
    }

    // a non-manager sends a command => not consumed (false, the mail is delivered as usual), but the sender receives
    // a "Command failed: not authorized" failure confirmation mail; neither of the two meta values is rewritten.
    #[tokio::test]
    async fn non_manager_command_gets_failed_ack_and_meta_untouched() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        // approval_record has sender=mgr@ext.com (= manager) fixed; the non-manager scenario swaps the sender.
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
        // meta not rewritten
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
        // the failure confirmation mail is enqueued: from noreply@e2e.local -> to stranger@ext.com, Command failed
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

    // no failed_ack context (e.g. the flows path) => behavior matches the old version: not consumed, no confirmation mail, meta untouched.
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

    // ── D3 family invariant: trigger hit + incomplete payload => failed ack, consumed (not delivered), meta untouched ──

    #[tokio::test]
    async fn incomplete_payload_gets_failed_ack_and_is_consumed() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        // subject triggers approve persona, but the body has no persona:/signature: sections
        let rec = approval_record("please see attached for the details");
        let fa = Some(crate::core::api::outbound::FailedCommandAck {
            cfg: &cfg,
            email_factory: &ef,
            metrics: None,
            trigger_tx: None,
            sender: &rec.sender,
            system_id: &rec.system_id,
        });
        assert!(
            super::handle_manager_commands(&rec, &env, &ef, None, fa).await,
            "D3: a triggered mail with an incomplete payload must be CONSUMED (never delivered)"
        );
        // meta untouched
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.agent_persona, "old persona");
        assert_eq!(meta.agent_signature, "old sig");
        // failed ack enqueued, naming the unmet condition
        let acks = env.db.list_emails(50).await.unwrap();
        let ack = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] Command failed"));
        let ack = ack.expect("incomplete payload must get a failed confirmation mail");
        assert_eq!(ack.sender, "noreply@e2e.local");
        assert!(
            ack.recipients.contains("mgr@ext.com"),
            "ack goes to the sender"
        );
        assert!(
            ack.body.contains("persona:"),
            "reason must name the unmet condition"
        );
    }

    // ── transfer manager (change manager) integration ──

    #[tokio::test]
    async fn transfer_manager_happy_path_applies_and_notifies() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        // current manager (seeded as mgr@ext.com) sends: To: new manager, Cc: the managed agent
        let mut rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com for agent@test.com",
        );
        rec.sender = "mgr@ext.com".to_string();
        rec.system_id = "sys1".to_string();
        let ack = Some(crate::core::api::outbound::AckCtx {
            cfg: &cfg,
            email_factory: &ef,
            metrics: None,
            trigger_tx: None,
        });
        assert!(
            super::handle_manager_commands(&rec, &env, &ef, ack, None).await,
            "transfer must be consumed"
        );
        // manager_address changed; persona/signature preserved verbatim
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.manager_address, "newmgr@ext.com");
        assert_eq!(meta.agent_persona, "old persona");
        assert_eq!(meta.agent_signature, "old sig");
        let acks = env.db.list_emails(50).await.unwrap();
        // (a) applied ack to the old manager (the sender)
        let applied = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] Command applied"))
            .expect("old manager must receive the applied ack");
        assert!(applied.recipients.contains("mgr@ext.com"));
        assert!(applied.body.contains("newmgr@ext.com"));
        // (c) the new manager receives the "you are now the manager" notice
        let notice = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] You are now the manager"))
            .expect("new manager must receive the notice");
        assert!(notice.recipients.contains("newmgr@ext.com"));
        assert!(notice.body.contains("agent@test.com"));
    }

    #[tokio::test]
    async fn transfer_manager_from_non_manager_sender_fails_and_meta_untouched() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        let mut rec = transfer_record(
            &["newmgr@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com for agent@test.com",
        );
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
            "unauthorized transfer is delivered as usual"
        );
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.manager_address, "mgr@ext.com");
        let acks = env.db.list_emails(50).await.unwrap();
        let ack = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] Command failed"));
        let ack = ack.expect("unauthorized transfer must get a failed ack");
        assert!(ack.recipients.contains("stranger@ext.com"));
        assert!(ack.body.contains("is not the manager of agent@test.com"));
    }

    // D3 for transfer: the Cc agent is registered but the payload is incomplete
    // (two To: recipients) => failed ack + consumed, meta untouched.
    #[tokio::test]
    async fn transfer_manager_incomplete_payload_is_consumed_with_failed_ack() {
        let (env, ef) = approval_env();
        seed_agent(&env).await;
        let cfg = ack_cfg();
        let rec = transfer_record(
            &["newmgr@ext.com", "extra@ext.com"],
            &["agent@test.com"],
            "change manager to newmgr@ext.com for agent@test.com",
        );
        let fa = Some(crate::core::api::outbound::FailedCommandAck {
            cfg: &cfg,
            email_factory: &ef,
            metrics: None,
            trigger_tx: None,
            sender: &rec.sender,
            system_id: &rec.system_id,
        });
        assert!(
            super::handle_manager_commands(&rec, &env, &ef, None, fa).await,
            "D3: incomplete transfer payload must be consumed"
        );
        let meta = env
            .resolve_domain_addr_meta("agent@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.manager_address, "mgr@ext.com");
        let acks = env.db.list_emails(50).await.unwrap();
        let ack = acks
            .iter()
            .find(|m| m.subject.starts_with("[AIMail] Command failed"))
            .expect("incomplete transfer must get a failed ack");
        assert!(ack.body.contains("To:"));
    }

    // ─── P1-2 path b: internal notification records must carry push endpoints ───

    // A push-mode internal recipient (webhook-registered) gets the endpoint
    // attached — without it process_email_webhook sees an empty endpoints_map
    // and completes + deletes the mail silently.
    #[tokio::test]
    async fn new_manager_notice_internal_push_recipient_carries_endpoint() {
        let (env, ef) = approval_env();
        let cfg = ack_cfg();
        // New manager registered on THIS gateway with a push webhook.
        env.create_domain(
            "d2",
            "sys1",
            "newmgr@e2e.local",
            Some("http://hook/2"),
            None,
            None,
        )
        .await
        .unwrap();

        super::notify_new_manager(
            Some(crate::core::api::outbound::AckCtx {
                cfg: &cfg,
                email_factory: &ef,
                metrics: None,
                trigger_tx: None,
            }),
            "newmgr@e2e.local",
            "agent@test.com",
            "sys1",
        )
        .await;
        let rec = ef
            .list(10)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.subject.starts_with("[AIMail] You are now the manager"))
            .expect("notice must be enqueued");
        assert_eq!(
            rec.direction, "inbound",
            "internal recipient stays on the inbound chain"
        );
        let eps = rec
            .endpoints
            .as_deref()
            .expect("push-mode internal recipient must carry the webhook endpoint");
        assert!(
            eps.contains("http://hook/2"),
            "endpoint must hold the webhook url: {eps}"
        );
        assert!(
            eps.contains("newmgr@e2e.local"),
            "endpoint key must be the recipient: {eps}"
        );
    }

    // The persona-applied closed-loop mail (sent to the agent itself) carries
    // the same push endpoint.
    #[tokio::test]
    async fn persona_applied_notice_internal_push_agent_carries_endpoint() {
        let (env, ef) = approval_env();
        let cfg = ack_cfg();
        // system_sender = noreply@e2e.local (ack_cfg), so an internal agent
        // must sit in the e2e.local domain.
        env.create_domain(
            "d1",
            "sys1",
            "agent@e2e.local",
            Some("http://hook/1"),
            None,
            Some("mgr@ext.com"),
        )
        .await
        .unwrap();

        super::notify_agent_persona_applied(
            Some(crate::core::api::outbound::AckCtx {
                cfg: &cfg,
                email_factory: &ef,
                metrics: None,
                trigger_tx: None,
            }),
            "agent@e2e.local",
            "sys1",
            "persona-x",
            "sig-x",
        )
        .await;
        let rec = ef
            .list(10)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.subject.starts_with("[AIMail] Persona applied"))
            .expect("persona notice must be enqueued");
        let eps = rec
            .endpoints
            .as_deref()
            .expect("push-mode internal agent must carry the webhook endpoint");
        assert!(
            eps.contains("http://hook/1"),
            "endpoint must hold the webhook url: {eps}"
        );
    }

    // Pull-mode internal recipients resolve to no endpoint — the record stays
    // endpoint-less and the recipients pre-scan covers delivery.
    #[tokio::test]
    async fn new_manager_notice_pull_recipient_stays_without_endpoint() {
        let (env, ef) = approval_env();
        let cfg = ack_cfg();
        // Registered with NO webhook url => pull mode.
        env.create_domain("d3", "sys1", "pullmgr@e2e.local", None, None, None)
            .await
            .unwrap();

        super::notify_new_manager(
            Some(crate::core::api::outbound::AckCtx {
                cfg: &cfg,
                email_factory: &ef,
                metrics: None,
                trigger_tx: None,
            }),
            "pullmgr@e2e.local",
            "agent@test.com",
            "sys1",
        )
        .await;
        let rec = ef
            .list(10)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.subject.starts_with("[AIMail] You are now the manager"))
            .expect("notice must be enqueued");
        // Pull-mode recipient: no webhook url resolves to no endpoint — the
        // record stays endpoint-less (delivery is covered by the recipients
        // pre-scan), so a push endpoint must NOT be fabricated.
        assert!(
            rec.endpoints
                .as_deref()
                .map(str::trim)
                .map_or(true, |e| e == "{}" || e.is_empty()),
            "pull-mode recipient must not carry a fake push endpoint: {:?}",
            rec.endpoints
        );
        assert!(
            rec.endpoints
                .as_deref()
                .map_or(true, |e| !e.contains("http://")),
            "pull-mode endpoint must not contain a url: {:?}",
            rec.endpoints
        );
    }

    // ─── P1-2 path b + B4: push loop resolves the secret via 2-tier lookup ───

    /// One-shot raw HTTP capture: read the full request (headers + body per
    /// Content-Length), reply 200. Returns a receiver that yields the complete
    /// raw request bytes once the POST arrives — the caller must `recv` AFTER
    /// triggering delivery (recv-ing here would deadlock, since the URL is
    /// only known to the caller after this returns).
    fn raw_http_capture() -> (std::sync::mpsc::Receiver<Vec<u8>>, std::net::SocketAddr) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 4096];
            // Read until the header block is complete.
            let head_end = loop {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
                    break Some(pos + 4);
                }
                if buf.len() > 65536 {
                    break None;
                }
            };
            let head_end = match head_end {
                Some(p) => p,
                None => {
                    let _ = tx.send(buf);
                    return;
                }
            };
            // Read the body per Content-Length.
            let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
            let content_len = head
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            while buf.len() < head_end + content_len {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let _ = tx.send(buf);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        (rx, addr)
    }

    /// Index of the first occurrence of `needle` in `hay` (bytes).
    fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || hay.len() < needle.len() {
            return None;
        }
        (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
    }

    // B4: an address-keyed endpoint whose domain is registered as a BARE
    // domain must still be signed — the push loop resolves full address →
    // bare domain (same strength as the pull pre-scan).
    #[tokio::test]
    async fn push_loop_signs_bare_domain_registration_with_address_keyed_endpoint() {
        let (env, ef) = approval_env();
        // Bare-domain registration (type 4): "corp.local" holds the secret.
        env.create_domain(
            "d4",
            "sys1",
            "corp.local",
            Some("http://hook/corp"),
            Some("bare-secret-42"),
            None,
        )
        .await
        .unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (cap_rx, addr) = raw_http_capture();
        let url = format!("http://{addr}/hook");
        let rec = ef
            .create_inbound(
                "wb-sign-test-1",
                "sys1",
                "noreply@e2e.local",
                "alice@corp.local",
                "hello",
                "body",
                Some(
                    &serde_json::json!({
                        "alice@corp.local": { "url": url, "status": "pending" }
                    })
                    .to_string(),
                ),
                None,
                None,
                3,
            )
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let ok = super::process_email_webhook(
            &env,
            &ef,
            &ack_cfg(),
            &client,
            &rec,
            Some(crate::core::api::outbound::AckCtx {
                cfg: &ack_cfg(),
                email_factory: &ef,
                metrics: None,
                trigger_tx: Some(&tx),
            }),
            None,
        )
        .await;
        assert!(ok, "push delivery must report success");

        // The capture thread sends the raw request once the POST arrives.
        let raw = cap_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("POST must reach the capture server within 10s");

        // Split the captured request into head and body.
        let head_end = find_bytes(&raw, b"\r\n\r\n").expect("request must have a header block");
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let body = &raw[head_end + 4..];
        assert!(!body.is_empty(), "POST must carry the webhook payload body");

        let header_val = |name: &str| -> Option<String> {
            head.lines().find_map(|l| {
                let lower = l.to_lowercase();
                lower
                    .strip_prefix(name)
                    .map(|v| v.trim().trim_start_matches(':').trim().to_string())
            })
        };
        let got_sig = header_val("x-webhook-signature:")
            .filter(|s| !s.is_empty())
            .expect("POST must carry a non-empty signature header: {head}");

        // The signature must be the HMAC over the BARE-DOMAIN secret — an
        // empty-secret (unsigned) HMAC is a different value, so this also
        // proves the 2-tier resolve found the secret.
        let (expected_sig, _ts) = sign_payload(b"bare-secret-42", body);
        assert_eq!(
            got_sig, expected_sig,
            "signature must be HMAC over the bare-domain secret (2-tier resolve), not the empty secret"
        );

        assert_eq!(
            header_val("x-aimail-email:"),
            Some("alice@corp.local".to_string()),
            "X-AIMail-Email must carry the real recipient address: {head}"
        );
    }
}
