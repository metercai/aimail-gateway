//! Webhook delivery handlers.

use std::sync::Arc;
use tracing::{error, debug, info, warn};

use crate::core::email::utils::sign_payload;

/// Send a single webhook POST request.
///
/// Headers: X-MailRelay-Signature, X-MailRelay-Timestamp.
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
        .header("X-Amail-Email", email)
        .header("X-Webhook-Signature", &signature)
        .header("X-Mailrelay-Timestamp", timestamp_ms.to_string())
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
            "timestamp": sig_val["X-Mailrelay-Timestamp"],
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
) -> bool {
    // ── 0. Handle manager commands ────────────────────────────
    if handle_manager_commands(record, env_factory, email_factory).await {
        return true; // Email processed by command, don't deliver
    }

    // Parse recipients once — used by enrichment, pull block, and my_role injection
    let recipients = record.recipients_parsed();

    // ── 0b. Pre-populate agent_state for thread metadata ──────────
    // For EACH recipient (to + cc), resolve persona-prefixed address
    // and write msg:{message_id} → agent_state. This lets every agent
    // read thread info without calling back to the gateway.
    for addr in recipients.to.iter().chain(recipients.cc.iter()) {
        if let Ok(Some(meta)) = env_factory.resolve_domain_addr_meta(addr).await {
            let agent_addr = if !meta.agent_persona.is_empty() {
                if let Some((base, domain)) = addr.split_once('@') {
                    format!("{}.{}@{}", meta.agent_persona, base, domain)
                } else {
                    addr.to_string()
                }
            } else {
                addr.to_string()
            };
            let _ = email_factory.put_msg_metadata(record, &agent_addr).await;
        } else {
            let _ = email_factory.put_msg_metadata(record, addr).await;
        }
    }

    // ── 1. Parse endpoints ──────────────────────────────────────────
    let endpoints_map: serde_json::Map<String, serde_json::Value> =
        record.endpoints_parsed().unwrap_or_default();

    // ── 2. Build payload once (same for all endpoints) ──────────────
    // Forwarder address: use relay.username if set, otherwise auto_reply_from,
    // falling back to a sensible default.
    let forwarder = config
        .relay
        .username
        .as_deref()
        .or(config.relay.auto_reply_from.as_deref())
        .unwrap_or("relay@amail-relay.local");

    let mut payload =
        build_webhook_payload_from_record(record, forwarder, record.sender_signature.as_deref());

    // ── Inbound interceptor chain ──
    let interceptors_snapshot = env_factory
        .get_interceptors()
        .read()
        .ok()
        .map(|guard| guard.iter().map(|i| Arc::clone(i)).collect::<Vec<_>>())
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
        email_factory
            .update_email_body_and_signature(&record.id, cleaned_body, sig)
            .await
            .ok();
    }

    // Enrich with contact info from whitelist
    if let Err(e) = record.enrich_with_contacts(&mut payload, env_factory).await {
        warn!(operation="enrich_contacts_failed", error = %e, "Failed to enrich contacts");
    }

    // Inject my_role from the target agent's persona (from domain_addr_meta)
    {
        let target_addr = recipients.to.first().or(recipients.cc.first());
        if let Some(addr) = target_addr {
            match env_factory.resolve_domain_addr_meta(addr).await {
                Ok(Some(meta)) => {
                    if !meta.agent_persona.is_empty() {
                        payload["my_role"] = serde_json::json!(meta.agent_persona);
                    }
                }
                _ => {}
            }
        }
    }

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let body_len = payload.get("body").and_then(|v| v.as_str()).map_or(0, |s| s.len());
    let subject = payload.get("subject").and_then(|v| v.as_str()).unwrap_or("N/A");
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
    let mut pull_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    let payload_json = String::from_utf8(payload_bytes.clone()).unwrap_or_default();
    {
        for addr in recipients.to.iter().chain(recipients.cc.iter()) {
            // Resolve address with domain-level fallback (Type 3)
            let d = env_factory.resolve_domain_from_address(addr).await
                .unwrap_or(None);
            if let Some(ref d) = d {
                let is_pull = d.webhook_url
                    .as_deref()
                    .map_or(true, |u| u.trim().is_empty());
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
                            "X-Mailrelay-Timestamp": ts_ms.to_string(),
                        })
                    } else {
                        warn!(email_id = %record.id, domain = %d.domain,
                              "No webhook_secret for pull domain — unsigned delivery");
                        serde_json::json!({
                            "X-Webhook-Signature": "",
                        })
                    };
                    let headers_json = serde_json::to_string(&serde_json::json!({
                        "X-Amail-Email": addr,
                        "X-Webhook-Signature": sig["X-Webhook-Signature"],
                        "X-Mailrelay-Timestamp": sig["X-Mailrelay-Timestamp"],
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
                    }
                    pull_domains.insert(ep_key);
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
                .find(|r| r.rsplit('@').next().map_or(false, |d| d == domain.as_str()))
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
                        serde_json::json!({"X-Webhook-Signature": "", "X-Mailrelay-Timestamp": ""})
                    } else {
                        let (signature, ts_ms) = sign_payload(secret.as_bytes(), &payload_bytes);
                        serde_json::json!({
                            "X-Webhook-Signature": signature,
                            "X-Mailrelay-Timestamp": ts_ms.to_string(),
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
                        .update_endpoint_status(&record.id, &domain, "success")
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
    SignatureUpdate(String),
    RoleUpdate(String),
    AddContact(String, Option<String>), // email to add, optional description
    RemoveContact(String),              // email to remove
}

/// Parse email body for manager commands.
fn parse_manager_command(body: &str) -> Option<ManagerCommand> {
    let lower = body.to_lowercase();

    // Signature update
    for prefix in &[
        "set signature to",
        "change signature to",
        "update signature to",
        "set signature as",
        "change signature as",
        "set my signature to",
        "set your signature to",
        "签名设为",
        "署名设为",
    ] {
        if let Some(pos) = lower.find(prefix) {
            let val = body[pos + prefix.len()..].trim().to_string();
            if !val.is_empty() {
                return Some(ManagerCommand::SignatureUpdate(val));
            }
        }
    }

    // Role/Persona update
    for prefix in &[
        "set my role to",
        "update my role to",
        "change my role to",
        "set your role to",
        "update your role to",
        "change your role to",
        "角色设为",
        "职责设为",
    ] {
        if let Some(pos) = lower.find(prefix) {
            let val = body[pos + prefix.len()..].trim().to_string();
            if !val.is_empty() {
                return Some(ManagerCommand::RoleUpdate(val));
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
) -> bool {
    let body = &record.body;
    if body.is_empty() {
        return false;
    }

    let cmd = match parse_manager_command(body) {
        Some(c) => c,
        None => return false,
    };

    // Find matching domain by recipient address, verify sender is manager
    let recipients = record.recipients_parsed();
    for to_addr in &recipients.to {
        let agent_meta = match env_factory.resolve_domain_addr_meta(to_addr).await {
            Ok(Some(m)) => m,
            _ => continue,
        };
        if agent_meta.manager_address.is_empty() || record.sender != agent_meta.manager_address {
            continue;
        }

        match &cmd {
            ManagerCommand::SignatureUpdate(sig) => {
                if let Err(e) = env_factory
                    .upsert_domain_addr_meta(
                        to_addr,
                        &agent_meta.system_id,
                        Some(&agent_meta.manager_address),
                        Some(sig),
                        Some(&agent_meta.agent_persona),
                    )
                    .await
                {
                    warn!(operation="manager_signature_update_failed", error = %e, "Failed to update signature");
                    return false;
                }
                info!(operation="manager_signature_updated", agent = %to_addr, "Manager command: signature updated");
                return true;
            }
            ManagerCommand::RoleUpdate(role) => {
                if let Err(e) = env_factory
                    .upsert_domain_addr_meta(
                        to_addr,
                        &agent_meta.system_id,
                        Some(&agent_meta.manager_address),
                        Some(&agent_meta.agent_signature),
                        Some(role),
                    )
                    .await
                {
                    warn!(operation="manager_role_update_failed", error = %e, "Failed to update persona");
                    return false;
                }
                info!(operation="manager_role_updated", agent = %to_addr, "Manager command: role updated");
                return true;
            }
            ManagerCommand::AddContact(email, description) => {
                // Add to whitelist (direction=all) so agent can both send and receive
                if let Err(e) = env_factory
                    .create_whitelist_entry(to_addr, "all", email, description.as_deref())
                    .await
                {
                    warn!(operation="manager_add_contact_failed", error = %e, "Failed to add contact");
                    return false;
                }
                info!(operation="manager_contact_added", domain = %to_addr, email = %email, "Manager command: contact added");
                return true;
            }
            ManagerCommand::RemoveContact(email) => {
                if let Err(e) = env_factory
                    .delete_whitelist_entry_by_value(to_addr, email)
                    .await
                {
                    warn!(operation="manager_remove_contact_failed", error = %e, "Failed to remove contact");
                    return false;
                }
                info!(operation="manager_contact_removed", domain = %to_addr, email = %email, "Manager command: contact removed");
                return true;
            }
        }
    }
    false
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
    use crate::core::config::Config;
    use crate::core::email::utils::sign_payload;
    use crate::core::email::utils::{html_to_markdown, parse_headers};

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

    // ─── parse_headers tests ───

    #[test]
    fn test_parse_headers_basic() {
        let raw = "Content-Type: text/plain\r\nSubject: Test\r\n";
        let headers = parse_headers(raw);
        assert_eq!(headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(headers.get("subject").unwrap(), "Test");
    }

    #[test]
    fn test_parse_headers_empty() {
        let headers = parse_headers("");
        assert!(headers.is_empty());
    }

    #[test]
    fn test_parse_headers_case_insensitive_keys() {
        let raw = "Content-Type: multipart/alternative\r\n";
        let headers = parse_headers(raw);
        assert_eq!(
            headers.get("content-type").unwrap(),
            "multipart/alternative"
        );
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
}
