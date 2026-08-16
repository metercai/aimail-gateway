//! SMTP receiver — accepts inbound email via the mailin protocol.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{trace, warn};

use mailin::{Handler, Response};
use mailparse;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::email::storage::Recipients;
use crate::core::email::utils::strip_persona;
use crate::core::errors::AppResult;
use crate::core::strategy::{InboundSecurity, QuotaChecker, RateLimitChecker};

/// SMTP response helpers matching mailin 0.6 `Response::custom` API.
/// SMTP codes: 250=OK, 451=local-error/temp-fail, 550=perm-fail/rejected.
const OK: &str = "OK";

fn ok() -> Response {
    Response::custom(250, OK.to_string())
}

fn perm_fail(msg: &str) -> Response {
    Response::custom(550, msg.to_string())
}

fn temp_fail(msg: &str) -> Response {
    Response::custom(451, msg.to_string())
}

/// SMTP receiver that processes inbound emails directly within handler callbacks.
///
/// `ConnectionHandler` (impl `mailin::Handler`) is instantiated per connection
/// and borrows shared `Config` and a scheduler `trigger_tx`.
pub struct ConnectionHandler {
    config: Arc<Config>,
    email_factory: Arc<EmailFactory>,
    attachment_factory: Arc<AttachmentFactory>,
    inbound_security: Arc<dyn InboundSecurity>,
    rate_limiter: Arc<dyn RateLimitChecker>,
    quota_checker: Arc<dyn QuotaChecker>,
    trigger_tx: mpsc::Sender<String>,
    metrics: Arc<Metrics>,
    // ── per-SMTP-session state ────────────────────────────────────
    peer_addr: Option<IpAddr>,
    sender: Option<String>,
    recipients: Vec<String>,
    message_data: Vec<u8>,
    domain: Option<String>,
    system_id: Option<String>,
    persona: Option<String>,
    sender_whitelisted: bool,
}

impl ConnectionHandler {
    /// Create a new per-connection handler.
    /// No longer creates a dedicated runtime — uses the parent tokio runtime
    /// via `Handle::current().block_on()` to bridge sync→async.  The SMTP
    /// handler runs inside `spawn_blocking`, so the blocking thread pool
    /// thread is owned by the parent runtime and `Handle::current()` works.
    pub fn new(
        config: Arc<Config>,
        email_factory: Arc<EmailFactory>,
        attachment_factory: Arc<AttachmentFactory>,
        inbound_security: Arc<dyn InboundSecurity>,
        rate_limiter: Arc<dyn RateLimitChecker>,
        quota_checker: Arc<dyn QuotaChecker>,
        trigger_tx: mpsc::Sender<String>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            config,
            email_factory,
            attachment_factory,
            inbound_security,
            rate_limiter,
            quota_checker,
            trigger_tx,
            metrics,
            peer_addr: None,
            sender: None,
            recipients: Vec::new(),
            message_data: Vec::new(),
            domain: None,
            system_id: None,
            persona: None,
            sender_whitelisted: true,
        }
    }

    /// Execute an async future from a synchronous context.
    ///
    /// Uses `Handle::current().block_on()` to bridge sync→async.  The caller
    /// (SMTP handler) runs inside `spawn_blocking`, which executes on the
    /// blocking thread pool — NOT on an async worker thread.  `block_on` on
    /// the current handle runs the future on this blocking thread without
    /// consuming a worker, so there is no deadlock risk on a multi-threaded
    /// runtime.
    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        tokio::runtime::Handle::current().block_on(future)
    }

    /// Save attachment to disk; returns the storage-relative path.
    /// The `uuid` must match the attachment's metadata ID so the download
    /// handler can locate the file on disk by looking up attachments_meta.
    fn save_attachment(
        &self,
        data: &[u8],
        sender: &str,
        original_filename: &str,
        uuid: &str,
    ) -> AppResult<String> {
        let extension = Path::new(original_filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("bin");
        let full = self.attachment_factory.file_path(sender, uuid, extension);
        let relative = full.to_string_lossy().to_string();

        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&full, data)?;
        Ok(relative)
    }
}

// ── DSN / Bounce parsing ──────────────────────────────────────────────

/// Fields extracted from a DSN (Delivery Status Notification) MIME message.
struct BounceDsn {
    /// Original sender address (From header of the original email).
    original_from: String,
    /// Original recipient address (To header of the original email).
    original_to: String,
    /// Original subject line.
    original_subject: String,
    /// Original Message-ID.
    orig_message_id: String,
    /// DSN status code (e.g. "5.1.1", "4.4.7").
    dsn_status: String,
    /// DSN diagnostic code (e.g. "550 5.1.1 User unknown").
    dsn_diagnostic: String,
}

/// Recursively find a MIME sub-part by content type.
fn find_mime_part<'a>(
    part: &'a mailparse::ParsedMail<'a>,
    mime_type: &str,
) -> Option<&'a mailparse::ParsedMail<'a>> {
    if part.ctype.mimetype == mime_type {
        return Some(part);
    }
    for sub in &part.subparts {
        if let Some(found) = find_mime_part(sub, mime_type) {
            return Some(found);
        }
    }
    None
}

/// Extract a header value (case-insensitive).
fn get_header_value(part: &mailparse::ParsedMail, name: &str) -> String {
    part.headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case(name))
        .map(|h| h.get_value())
        .unwrap_or_default()
}

/// Parse a raw bounce/NDR email to extract DSN fields.
fn parse_bounce_dsn(raw: &[u8]) -> Option<BounceDsn> {
    let parsed = mailparse::parse_mail(raw).ok()?;

    let dsn_part = find_mime_part(&parsed, "message/delivery-status")?;
    let dsn_body = String::from_utf8(dsn_part.get_body().ok()?.into_bytes()).ok()?;

    let mut dsn_status = String::new();
    let mut dsn_diagnostic = String::new();
    for line in dsn_body.lines() {
        if let Some(val) = line.strip_prefix("Status: ") {
            dsn_status = val.to_string();
        }
        if let Some(val) = line.strip_prefix("Diagnostic-Code: ") {
            dsn_diagnostic = val.to_string();
        }
    }

    // ── message/rfc822 (original email) ──
    let orig_part = find_mime_part(&parsed, "message/rfc822")?;

    Some(BounceDsn {
        original_from: get_header_value(orig_part, "from"),
        original_to: get_header_value(orig_part, "to"),
        original_subject: get_header_value(orig_part, "subject"),
        orig_message_id: get_header_value(orig_part, "message-id"),
        dsn_status,
        dsn_diagnostic,
    })
}

// ── mailin::Handler implementation ──────────────────────────────────────

impl Handler for ConnectionHandler {
    fn mail(&mut self, ip: IpAddr, domain: &str, from: &str) -> Response {
        // 1. IP blacklist check (highest priority — reject known bad IPs immediately)
        let ip_str = ip.to_string();
        if self.inbound_security.check_ip_blacklisted(&ip_str) {
            self.metrics.inc_ip_blacklist_hits();
            tracing::warn!(
                operation="ip_blacklisted",
                ip = %ip_str,
                from = %from,
                "Rejected inbound connection from blacklisted IP"
            );
            return perm_fail("IP address is blacklisted");
        }

        self.peer_addr = Some(ip);
        self.sender = Some(from.to_string());

        // 2. Resolve sender — advanced edition may decode auth address
        if let Some(real) = self.inbound_security.resolve_sender(from) {
            self.sender = Some(real.clone());
            // Authenticated session: resolve_sender validated the key,
            // and check_inbound (including SPF) is bypassed intentionally.
        } else {
            // Skip inbound security for null-sender (bounce/NDR, RFC 5321)
            if !from.is_empty() {
                if let Err(e) = self.inbound_security.check_inbound(ip, from, domain) {
                    tracing::warn!(operation="inbound_rejected", ip=%ip_str, from=%from, reason=e, "Inbound check failed");
                    return perm_fail(e);
                }
            }
        }

        // 3. Anti-loop detection — check if sender domain is registered
        let sender_domain = from.rsplit('@').next().unwrap_or(from);
        match self.block_on(
            self.email_factory
                .env_factory
                .lookup_domain_addr(sender_domain),
        ) {
            Ok(Some(_rec)) => {
                tracing::warn!(operation="inbound_anti_loop", ip=%ip_str, sender=%from,
                    "Internal sender address rejected on inbound path");
                perm_fail("Internal sender address rejected on inbound path")
            }
            Ok(None) => {
                // External sender → accept; system resolved in rcpt()
                ok()
            }
            Err(_) => temp_fail("Database error during domain lookup"),
        }
    }

    fn rcpt(&mut self, to: &str) -> Response {
        // ── Resolve system / domain from recipient address ────────────
        // Try exact match first (shared domain: ql-biopharm.tow@amail.token.tm
        // IS the domain record).  Fall back to persona-stripped base address
        // (non-shared domain: sales.bob@company.com → bob@company.com).
        let full_lower = to.to_lowercase();

        let (lookup_addr, persona) = match self.block_on(
            self.email_factory
                .env_factory
                .lookup_domain_addr(&full_lower),
        ) {
            Ok(Some(rec)) => {
                // Exact match — full address is the domain record.
                // Shared-domain system anchor (system_name@domain, 0-dot
                // local) is a system-level mailbox, not a deliverable
                // agent address — reject it at RCPT time.
                let local_part = full_lower.split('@').next().unwrap_or("");
                if rec.system_id.starts_with("shared-") && !local_part.contains('.') {
                    return perm_fail("Recipient does not exist");
                }
                // Registered addresses carry no persona of their own —
                // persona prefixes only appear on unregistered dynamic
                // forms resolved via the fallback path below.
                self.system_id = match self.system_id.take() {
                    None => Some(rec.system_id.clone()),
                    Some(prev) if prev == rec.system_id => Some(prev),
                    Some(prev) => Some(format!("{}|{}", prev, rec.system_id)),
                };
                self.domain = Some(rec.domain.clone());
                (full_lower, String::new())
            }
            Ok(None) => {
                // Exact match failed — try stripping persona prefix
                let (base_addr, p) = strip_persona(to);
                let base_lower = base_addr.to_lowercase();
                if base_lower != full_lower {
                    match self.block_on(
                        self.email_factory
                            .env_factory
                            .lookup_domain_addr(&base_lower),
                    ) {
                        Ok(Some(rec)) => {
                            // Same system-anchor guard on the fallback path:
                            // an unregistered shared-domain agent address
                            // (1-dot) strips down to the 0-dot anchor and
                            // must be rejected, not delivered to the system.
                            let local_part = base_lower.split('@').next().unwrap_or("");
                            if rec.system_id.starts_with("shared-") && !local_part.contains('.') {
                                return perm_fail("Recipient does not exist");
                            }
                            self.system_id = match self.system_id.take() {
                                None => Some(rec.system_id.clone()),
                                Some(prev) if prev == rec.system_id => Some(prev),
                                Some(prev) => Some(format!("{}|{}", prev, rec.system_id)),
                            };
                            self.domain = Some(rec.domain.clone());
                            (base_lower, p)
                        }
                        Ok(None) => return perm_fail("Recipient domain not found"),
                        Err(_) => return temp_fail("Database error during domain lookup"),
                    }
                } else {
                    return perm_fail("Recipient domain not found");
                }
            }
            Err(_) => return temp_fail("Database error during domain lookup"),
        };

        if !persona.is_empty() {
            self.persona = Some(persona);
        }

        // ── Whitelist check (inbound) ────────────────────────────────
        if let Some(ref sender) = self.sender {
            let allowed = self.block_on(self.email_factory.env_factory.check_whitelisted(
                &lookup_addr,
                sender,
                "from",
            ));
            match allowed {
                Ok(true) => {
                    self.sender_whitelisted = true;
                    self.metrics.inc_whitelist_matches();
                }
                Ok(false) => {
                    self.sender_whitelisted = false;
                    tracing::info!(
                        operation = "smtp_sender_not_whitelisted",
                        domain = %self.domain.as_deref().unwrap_or(""),
                        sender = %sender,
                        recipient = %lookup_addr,
                        "Sender not in recipient's from whitelist — deferred to data_end"
                    );
                    // Defer rejection to data_end() for stranger-command detection
                }
                Err(_) => return temp_fail("Whitelist check failed"),
            }
        }
        self.recipients.push(lookup_addr);
        ok()
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        ok()
    }

    fn data(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        // 4. Enforce message size limit (checks total accumulated size)
        if self.message_data.len() + data.len() > self.config.smtp.max_message_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        self.message_data.extend_from_slice(data);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        let sender = match self.sender.take() {
            Some(s) => s,
            None => return temp_fail("No sender"),
        };
        let recipients = std::mem::take(&mut self.recipients);
        if recipients.is_empty() {
            return perm_fail("No recipients");
        }
        let system_id = match self.system_id.as_ref() {
            Some(t) => t.clone(),
            None => return temp_fail("No system"),
        };
        // Validate domain was captured during MAIL FROM
        if self.domain.is_none() {
            return temp_fail("No domain");
        }

        // ── Deferred whitelist rejection ─────────────────────────
        // Senders not in any recipient's "from" whitelist were deferred
        // from rcpt().  Allow stranger commands ([WHOAMI] etc.) through;
        // reject everything else before wasting time on full MIME parse.
        if !self.sender_whitelisted {
            let is_stranger_cmd = match mailparse::parse_headers(&self.message_data) {
                Ok((headers, _)) => {
                    let subject = headers
                        .iter()
                        .find(|h| h.get_key().eq_ignore_ascii_case("subject"))
                        .map(|h| h.get_value())
                        .unwrap_or_default();
                    ["[WHOAMI]"]
                        .iter()
                        .any(|cmd| subject.to_uppercase().starts_with(cmd))
                }
                Err(_) => false,
            };
            if !is_stranger_cmd {
                return perm_fail("Sender not whitelisted");
            }
        }

        // ── Rate limit check ──────────────────────────────────────
        // Per-system inbound rate limiting.  When recipients span multiple
        // systems (pipe-delimited system_id), check each individually.
        let mut rate_limited_sid = None;
        let mut rate_limited_wait = std::time::Duration::ZERO;
        for sid in system_id.split('|') {
            match self.rate_limiter.check(sid) {
                Ok(()) => {}
                Err(wait) => {
                    if wait > rate_limited_wait {
                        rate_limited_wait = wait;
                        rate_limited_sid = Some(sid.to_string());
                    }
                }
            }
        }
        if let Some(sid) = rate_limited_sid {
            self.metrics.inc_rate_limited();
            tracing::warn!(
                operation = "smtp_rate_limited",
                system_id = %sid,
                wait_secs = rate_limited_wait.as_secs_f64(),
                "SMTP rate limit exceeded"
            );
            return temp_fail(&format!(
                "Rate limit exceeded for system {}. Retry after {:.0}s",
                sid,
                rate_limited_wait.as_secs_f64()
            ));
        }

        let raw_data = std::mem::take(&mut self.message_data);

        // ── Post-DATA message security (DKIM/DMARC) ────────────────
        // Base edition: no-op. Advanced edition verifies the full raw
        // message per its dkim/dmarc policies. Null-sender (bounce) is
        // exempted inside implementations (RFC 5321).
        if !sender.is_empty() {
            if let Err(e) = self.inbound_security.check_inbound_message(&sender, &raw_data) {
                tracing::warn!(
                    operation = "inbound_message_rejected",
                    sender = %sender,
                    reason = %e,
                    "Inbound message security check failed"
                );
                return perm_fail(&e);
            }
        }

        // ── Bounce / NDR pre-verification ─────────────────────────
        // MAIL FROM:<> with an internal RCPT TO → potential bounce.
        // Parse the DSN to verify legitimacy before storing anything.
        if sender.is_empty() && !recipients.is_empty() {
            let bounce_for = recipients[0].clone();
            match parse_bounce_dsn(&raw_data) {
                Some(dsn) => {
                    // Found DSN fields → candidate. Verify against our outbound records.
                    let matched_id = self.block_on(self.verify_bounce(&dsn));
                    if let Some(original_id) = matched_id {
                        // Generate a structured notification inbound email.
                        // We complete+delete the original delivered email and create
                        // a clean notification for the sender's webhook pipeline.
                        let notification_id = self.block_on(self.create_bounce_notification(
                            &dsn,
                            &system_id,
                            &bounce_for,
                            &original_id,
                        ));
                        if let Some(nid) = notification_id {
                            if let Err(e) = self.trigger_tx.try_send(nid.clone()) {
                                self.metrics.inc_trigger_dropped();
                                tracing::warn!(operation="trigger_channel_full", error = %e, mail_id = %nid, "Trigger channel full, notification dropped");
                            }
                        }
                        tracing::info!(
                            operation="bounce_verified",
                            bounce_recipient = %bounce_for,
                            original_message_id = %dsn.orig_message_id,
                            dsn_status = %dsn.dsn_status,
                            "Verified bounce processed — delivered notification for original email"
                        );
                    } else {
                        tracing::warn!(
                            operation="bounce_unverified",
                            bounce_recipient = %bounce_for,
                            "Unverified bounce (no matching delivered email within NDR window) — silently discarded"
                        );
                    }
                    // In both cases: do NOT store the raw bounce email.
                    return ok();
                }
                None => {
                    // MAIL FROM empty but not a valid DSN format → suspicious/spam.
                    // Silently discard to avoid backscatter amplification.
                    tracing::warn!(
                        operation="bounce_non_dsn",
                        bounce_recipient = %bounce_for,
                        "Bounce with empty MAIL FROM but non-DSN format — silently discarded"
                    );
                    return ok();
                }
            }
        }

        // ── Normal inbound processing (below) ─────────────────────
        // Only reaches here when sender is NOT empty (regular inbound email).

        // Parse MIME → (body, attachments, to_emails, cc_emails, in_reply_to, references, message_id, subject)
        let parsed = match mailparse::parse_mail(&raw_data) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(operation="mime_parse_error", error = %e, "Failed to parse MIME message");
                return temp_fail("MIME parse error");
            }
        };
        let (body, attachments, to_emails, cc_emails, in_reply_to, references, message_id, subject) =
            match EmailFactory::parse_mime_detailed_from_parsed(&parsed) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(operation="mime_parse_error", error = %e, "Failed to parse MIME message");
                    return temp_fail("MIME parse error");
                }
            };

        // ── Attachment limit enforcement ───────────────────────────
        // Per-system limits from quota_checker override global config

        let att_cfg = &self.config.storage;
        let system_id_opt = self.system_id.as_deref();

        let per_system_max_count = match system_id_opt {
            Some(sid) => self.block_on(self.quota_checker.get_max_attachments(sid)),
            None => None,
        };
        let per_system_max_size = match system_id_opt {
            Some(sid) => self.block_on(self.quota_checker.get_max_attachment_size(sid)),
            None => None,
        };

        if let Err(e) = EmailFactory::validate_attachments(
            att_cfg,
            &attachments,
            per_system_max_count,
            per_system_max_size,
        ) {
            return perm_fail(&e.to_string());
        }

        // ── Recipient filtering ────────────────────────────────────

        // Build an envelope-whitelist set from the RCPT TO addresses
        // that already passed the per-rcpt whitelist check.
        // These are base addresses (persona already stripped).
        let envelope_set: std::collections::HashSet<String> =
            recipients.iter().map(|s| s.to_lowercase()).collect();

        // Filter MIME To / CC headers against the envelope set.
        // MIME headers may contain persona-prefixed addresses or
        // "Name <email>" format — extract the bare email and strip
        // persona before comparing.
        // Preserve the original header order so downstream systems
        // see recipients in the positions the sender intended.
        fn extract_email_for_envelope(
            raw: &str,
            envelope: &std::collections::HashSet<String>,
        ) -> bool {
            // Extract the email part from "Name <email>" or bare "email"
            let email = if let Some(start) = raw.rfind('<') {
                if let Some(end) = raw.rfind('>') {
                    &raw[start + 1..end]
                } else {
                    raw
                }
            } else {
                raw
            }
            .trim()
            .to_lowercase();
            // Check exact match first, then try base address (strip persona)
            if envelope.contains(&email) {
                return true;
            }
            // Try base address: sales.inbound-test@agent.com → inbound-test@agent.com
            if let Some((_persona, rest)) = email.split_once('.') {
                if rest.contains('@') {
                    return envelope.contains(rest);
                }
            }
            false
        }

        /// Strip MIME display name: "Name <email>" → "email".
        fn strip_mime_display(raw: &str) -> String {
            if let Some(start) = raw.rfind('<') {
                if let Some(end) = raw.rfind('>') {
                    raw[start + 1..end].trim().to_string()
                } else {
                    raw.to_string()
                }
            } else {
                raw.to_string()
            }
        }

        let filtered_to: Vec<String> = to_emails
            .iter()
            .filter(|e| extract_email_for_envelope(e, &envelope_set))
            .map(|e| strip_mime_display(e))
            .collect();

        let filtered_cc: Vec<String> = cc_emails
            .iter()
            .filter(|e| extract_email_for_envelope(e, &envelope_set))
            .map(|e| strip_mime_display(e))
            .collect();

        if filtered_to.is_empty() && filtered_cc.is_empty() {
            return perm_fail("No recipients match between envelope and email headers");
        }

        tracing::debug!(
            operation="recipients_filtered",
            sender = ?self.sender,
            email_to = ?filtered_to,
            email_cc = ?filtered_cc,
            envelope_count = recipients.len(),
            "RCPT TO filtering completed"
        );

        // Flatten for per-recipient operations (attachment perms, etc.)
        let filtered_recipients: Vec<String> = filtered_to
            .iter()
            .chain(filtered_cc.iter())
            .cloned()
            .collect();

        // ── Board group-whitelist learning (all delivery modes) ──────────
        // Notifications from a board address carry
        //   X-Board-Members: {board_email};{member_csv}
        // Recipient gateways verify From == header board address, then update
        // the local board-keyed group whitelist so members auto-pass SMTP /
        // HTTP whitelist checks (no per-member whitelist storm). Learnt here,
        // at receive time, so both push (webhook) and pull (pending) modes
        // build the list.
        if sender.contains(".a2a@") && subject.starts_with("[A2A]") {
            let raw_text = String::from_utf8_lossy(&raw_data);
            let header_val = raw_text.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("X-Board-Members:")
                    .map(|v| v.trim().to_string())
            });
            if let Some(hval) = header_val {
                let parts: Vec<&str> = hval.splitn(2, ';').collect();
                if parts.len() == 2 && parts[0].trim().eq_ignore_ascii_case(&sender) {
                    let members: Vec<String> = parts[1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !members.is_empty() {
                        match self
                            .block_on(
                                self.email_factory
                                    .env_factory
                                    .db
                                    .replace_board_members(parts[0].trim(), &members),
                            ) {

                            Ok(_) => tracing::info!(
                                operation = "board_group_whitelist",
                                board_email = parts[0].trim(),
                                members = members.len(),
                                "board group whitelist learnt from inbound notification"
                            ),
                            Err(e) => tracing::warn!(
                                operation = "board_group_whitelist",
                                error = %e,
                                "failed to learn board group whitelist"
                            ),
                        }
                    }
                } else {
                    tracing::warn!(
                        operation = "board_group_whitelist",
                        "member notification rejected: From != header board address"
                    );
                }
            }
        }

        let mail_uuid = Uuid::new_v4().to_string();

        // ── Build JSON payloads for insert_email ───────────────────

        // Build recipients JSON with to/cc distinction — order is
        // inherited from the MIME headers, which the sender authored.
        let recipients_json = Recipients {
            to: filtered_to,
            cc: filtered_cc,
        }
        .to_json();

        // Generate attachment UUIDs upfront so they can be included in both
        // the attachments JSON and the attachments_meta table.
        let attachment_uuids: Vec<String> = (0..attachments.len())
            .map(|_| Uuid::new_v4().to_string())
            .collect();

        // Build webhook endpoints: per-recipient → domain fallback
        let endpoints_json = self.block_on(
            self.email_factory
                .build_endpoints_for_recipients(&filtered_recipients),
        );
        // Build JSON with threading headers (Message-ID, In-Reply-To, References)
        let mut headers_map = serde_json::Map::new();
        if !message_id.is_empty() {
            headers_map.insert(
                "message_id".to_string(),
                serde_json::Value::String(message_id.clone()),
            );
        }
        if !in_reply_to.is_empty() {
            headers_map.insert(
                "in_reply_to".to_string(),
                serde_json::Value::String(in_reply_to.clone()),
            );
        }
        if !references.is_empty() {
            headers_map.insert(
                "references".to_string(),
                serde_json::Value::String(references.clone()),
            );
        }

        // Preserve raw MIME To/Cc/From header values so the preprocessor
        // can extract display names (e.g. "Alice <alice@c.com>").
        // Reuse `parsed` from the MIME parse above — no redundant re-parse.
        for h in &parsed.headers {
            let key = h.get_key();
            if key.eq_ignore_ascii_case("to")
                || key.eq_ignore_ascii_case("cc")
                || key.eq_ignore_ascii_case("from")
            {
                let val = h.get_value();
                if !val.is_empty() && !headers_map.contains_key(&key.to_lowercase()) {
                    headers_map.insert(key.to_lowercase(), serde_json::Value::String(val));
                }
            }
        }

        // Store persona extracted from RCPT TO address
        // (restored in webhook payload / outbound SMTP as needed)
        if let Some(ref persona) = self.persona {
            headers_map.insert(
                "_persona".to_string(),
                serde_json::Value::String(persona.clone()),
            );
        }
        // ── Stranger detection: inject X-Mail-* headers for universal commands ──
        let stranger_commands = ["[WHOAMI]"];
        let subject_upper = subject.to_uppercase();
        for cmd in &stranger_commands {
            if subject_upper.starts_with(cmd) {
                if !self.sender_whitelisted {
                    headers_map.insert(
                        "x-mail-stranger".to_string(),
                        serde_json::Value::String("true".to_string()),
                    );
                }
                let cmd_name = cmd
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_lowercase();
                headers_map.insert(
                    "x-mail-command".to_string(),
                    serde_json::Value::String(cmd_name),
                );
                break;
            }
        }

        let headers_json = serde_json::Value::Object(headers_map).to_string();

        // ── Insert email record ────────────────────────────────────
        // When recipients span multiple systems, attribute to the first one
        let primary_system = system_id.split('|').next().unwrap_or(&system_id);

        let mail_id = match self.block_on(self.email_factory.create_inbound(
            &mail_uuid,
            primary_system,
            &sender,
            &recipients_json,
            &subject,
            &body,
            Some(&endpoints_json),
            None, // attachments JSON updated after save loop below
            Some(&headers_json),
            self.config.retry.max_attempts as i32,
        )) {
            Ok(rec) => {
                self.metrics.inc_emails_received_smtp();
                tracing::info!(
                    operation="email_received",
                    email_id = %rec.id,
                    sender = %sender,
                    subject = %subject,
                    recipients = %recipients_json,
                    "Email received and stored via SMTP"
                );
                rec.id
            }
            Err(_) => return temp_fail("Database insert failed"),
        };

        // ── Save attachments + metadata + permission rows ──────────

        let mut saved_entries: Vec<serde_json::Value> = Vec::new();
        for ((filename, content_type, data, _content_id), attachment_uuid) in
            attachments.iter().zip(attachment_uuids.iter())
        {
            let _ = match self.save_attachment(&data, &sender, &filename, attachment_uuid) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(operation="attachment_save_failed", attachment_id = %attachment_uuid, filename = %filename, error = %e, "Failed to save attachment file");
                    continue;
                }
            };
            saved_entries.push(serde_json::json!({
                "attachment_id": attachment_uuid,
                "filename": filename,
                "content_type": content_type,
                "size": data.len()
            }));
            if let Err(e) = self.block_on(self.attachment_factory.create_meta(
                attachment_uuid,
                &filename,
                Some(&content_type),
                &sender,
                Some(&[mail_id.clone()]),
            )) {
                tracing::warn!(operation="attachment_meta_failed", attachment_id = %attachment_uuid, error = %e, "Failed to create attachment metadata");
            }
            // Grant download permission to every confirmed recipient
            for user_email in &filtered_recipients {
                if let Err(e) = self.block_on(
                    self.attachment_factory
                        .create_permission(attachment_uuid, user_email),
                ) {
                    tracing::warn!(operation="attachment_perm_failed", attachment_id = %attachment_uuid, user = %user_email, error = %e, "Failed to create attachment permission");
                }
            }
        }

        // Update the email record with the actual saved attachments JSON
        if !saved_entries.is_empty() {
            let attachments_json =
                serde_json::to_string(&saved_entries).unwrap_or_else(|_| "[]".to_string());
            let _ = self.block_on(
                self.email_factory
                    .update_email_attachments(&mail_id, &attachments_json),
            );
        }

        // ── Trigger scheduler (wake-up signal) ────────────────────

        if let Err(e) = self.trigger_tx.try_send(mail_id.clone()) {
            self.metrics.inc_trigger_dropped();
            tracing::warn!(operation="trigger_channel_full", error = %e, mail_id = %mail_id, "Trigger channel full, notification dropped");
        }

        ok()
    }
}

// ── Bounce verification helpers (async, called via block_on) ─────────

impl ConnectionHandler {
    /// Verify a bounce is legitimate by finding the original outbound email.
    ///
    /// Checks:
    /// 1. An outbound email exists with matching sender address
    /// 2. Status is "delivered" (within NDR window)
    /// 3. Subject matches the original email's subject
    /// 4. Message-ID from the bounce matches the original email's stored headers
    /// 5. Last delivery was within the configured NDR window
    ///
    /// Returns the original email's ID if verified, None otherwise.
    async fn verify_bounce(&self, dsn: &BounceDsn) -> Option<String> {
        // 1. Find outbound emails by sender (the original From address)
        let matches = match self
            .email_factory
            .find_outbound_by_sender(&dsn.original_from, 10)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(operation="bounce_db_error", error = %e, "Bounce verification: DB error searching outbound emails");
                return None;
            }
        };

        if matches.is_empty() {
            tracing::debug!(
                original_from = %dsn.original_from,
                "Bounce verification: no outbound emails found for this sender"
            );
            return None;
        }

        let window_secs = self.config.relay.delivery_window_secs;
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window_secs as i64);

        // 2-5. Find one that matches all criteria
        for rec in &matches {
            if rec.status != "delivered" {
                continue;
            }
            // Time window check — last_sent_at must be within NDR window
            if let Ok(sent_at) = chrono::DateTime::parse_from_rfc3339(&rec.last_sent_at) {
                if sent_at < cutoff {
                    continue;
                }
            }
            // Subject match (trimmed, case-insensitive)
            let rec_subject = rec.subject.trim().to_lowercase();
            let dsn_subject = dsn.original_subject.trim().to_lowercase();
            if rec_subject != dsn_subject {
                continue;
            }
            // Message-ID match
            let rec_msg_id = rec.message_id_from_headers().unwrap_or_default();
            let dsn_msg_id = dsn.orig_message_id.trim();
            if rec_msg_id == dsn_msg_id {
                // All criteria met — this is a verified bounce
                tracing::info!(
                    operation="bounce_matched",
                    email_id = %rec.id,
                    original_from = %dsn.original_from,
                    dsn_status = %dsn.dsn_status,
                    "Bounce verified: matching delivered email found"
                );
                return Some(rec.id.clone());
            }
        }

        tracing::warn!(
            operation="bounce_no_match",
            original_from = %dsn.original_from,
            "Bounce verification: found outbound emails but none matched (status/subject/message-id/window)"
        );
        None
    }

    /// Generate a structured notification inbound email for a verified bounce.
    ///
    /// Returns the notification email ID if created successfully.
    async fn create_bounce_notification(
        &self,
        dsn: &BounceDsn,
        system_id: &str,
        bounce_recipient: &str,
        original_id: &str,
    ) -> Option<String> {
        let notif_id = format!("bn-{}", Uuid::new_v4());

        // Determine system FROM address (auto_reply_from → admin.email → noreply@localhost)
        let auto_reply_from = self
            .config
            .relay
            .auto_reply_from
            .as_deref()
            .or(self.config.admin.email.as_deref())
            .unwrap_or("noreply@localhost");

        let body_prefix = self
            .config
            .relay
            .auto_reply_body
            .as_deref()
            .unwrap_or("Your message could not be delivered.");

        let notification_body = format!(
            "{}\n---\n\
             From: {}\n\
             To: {}\n\
             Subject: {}\n\
             Status: {}\n\
             Diagnostic: {}",
            body_prefix,
            dsn.original_from,
            dsn.original_to,
            dsn.original_subject,
            dsn.dsn_status,
            dsn.dsn_diagnostic,
        );

        // Build recipients JSON
        let recipients = Recipients {
            to: vec![bounce_recipient.to_string()],
            cc: vec![],
        };
        let recipients_json = recipients.to_json();

        // Build endpoints (webhook URL for the bounce recipient's domain)
        let endpoints_json = self
            .email_factory
            .build_endpoints_for_recipients(&[bounce_recipient.to_string()])
            .await;

        // Build headers with Original-Message-ID for correlation
        let headers_json = serde_json::json!({
            "message_id": notif_id,
            "original_message_id": dsn.orig_message_id,
            "bounce_status": dsn.dsn_status,
            "bounce_diagnostic": dsn.dsn_diagnostic,
        })
        .to_string();

        // Store as inbound email (will be webhook-delivered to the domain)
        match self
            .email_factory
            .create_inbound(
                &notif_id,
                system_id,
                auto_reply_from,
                &recipients_json,
                "Mail delivery failed",
                &notification_body,
                Some(&endpoints_json),
                None, // no attachments
                Some(&headers_json),
                self.config.retry.max_attempts as i32,
            )
            .await
        {
            Ok(rec) => {
                // Complete + delete the original delivered email (best-effort)
                let _ = self.email_factory.complete(original_id).await;
                let _ = self.email_factory.delete(original_id).await;
                Some(rec.id)
            }
            Err(e) => {
                tracing::warn!(operation="bounce_notification_failed", error = %e, "Failed to create bounce notification email");
                None
            }
        }
    }
}
pub fn handle_smtp_session_blocking(
    mut stream: std::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    email_factory: Arc<EmailFactory>,
    attachment_factory: Arc<AttachmentFactory>,
    arc_config: Arc<Config>,
    inbound_security: Arc<dyn InboundSecurity>,
    trigger_tx: mpsc::Sender<String>,
    metrics: Arc<Metrics>,
    rate_limiter: Arc<dyn RateLimitChecker>,
    quota_checker: Arc<dyn QuotaChecker>,
) {
    use std::io::{BufRead, BufReader, Write};

    // Keep original Arc references for potential TLS re-handshake;
    // clone for the first ConnectionHandler.
    let cfg_orig = arc_config;
    let emf_orig = email_factory;
    let af_orig = attachment_factory;
    let r_orig = inbound_security;
    let rl_orig = rate_limiter;
    let qc_orig = quota_checker;
    let tt_orig = trigger_tx;
    let m_orig = metrics;

    let peer_ip = peer_addr.ip();
    let handler = ConnectionHandler::new(
        cfg_orig.clone(),
        emf_orig.clone(),
        af_orig.clone(),
        r_orig.clone(),
        rl_orig.clone(),
        qc_orig.clone(),
        tt_orig.clone(),
        m_orig.clone(),
    );
    let banner_hostname = cfg_orig.smtp.hostname.as_deref().unwrap_or("amail-relay");
    let session_builder = crate::SessionBuilder::new(banner_hostname);
    let mut session = session_builder.build(peer_ip, handler);

    let mut reader = BufReader::new(stream.try_clone().expect("failed to clone TcpStream"));
    // Use &mut stream directly instead of a long-lived `writer` borrow,
    // so we can take ownership of `stream` for TLS upgrade.

    // Send greeting
    let greeting = session.greeting();
    match greeting.buffer() {
        Ok(greeting_buf) => {
            if let Err(e) = stream.write_all(&greeting_buf) {
                trace!(?e, "Failed to write greeting");
                return;
            }
            if let Err(e) = stream.flush() {
                trace!(?e, "Failed to flush greeting");
                return;
            }
        }
        Err(e) => {
            warn!(%e, "Failed to build SMTP greeting");
            return;
        }
    }

    let mut line = String::new();
    let mut in_data_phase = false;
    let mut data_bytes_total: usize = 0;
    let max_msg_size = cfg_orig.smtp.max_message_size;
    let mut declared_size: Option<u64> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                // ── Pre-flight size check during DATA phase ──────────
                // Accumulate total bytes received so far and reject the
                // email immediately if it exceeds max_message_size.
                // This avoids buffering the entire oversized message
                // in memory and wastes no time on MIME parsing / DB
                // writes for a message that will be rejected anyway.
                if in_data_phase {
                    // Skip the dot-stuffing de-escaping for counting —
                    // receiving side just counts raw bytes.
                    data_bytes_total += line.len();
                    if data_bytes_total > max_msg_size {
                        tracing::warn!(
                            operation="oversized_email",
                            peer_addr = %peer_addr,
                            total_bytes = data_bytes_total,
                            max = max_msg_size,
                            "Rejecting oversized email during DATA phase"
                        );
                        let _ = write_response_blocking(
                            &mut stream,
                            &crate::Response::custom(
                                552,
                                format!("Message exceeds maximum size of {} bytes", max_msg_size),
                            ),
                        );
                        break;
                    }
                }

                // ── Mail FROM SIZE interception ─────────────────────────
                // Parse SIZE declaration from the raw SMTP line and store
                // locally.  Check it when DATA arrives so we can reject
                // oversized emails before any data transfer.
                if line.len() > 6 && line[..6].eq_ignore_ascii_case("MAIL FR") {
                    tracing::info!(
                        operation = "smtp_raw_mail_from",
                        line = %line.trim(),
                        "Raw MAIL FROM received"
                    );
                    declared_size = None; // reset on new MAIL FROM
                    if let Some(pos) = line.to_uppercase().find(" SIZE=") {
                        let rest = &line[pos + 6..];
                        let num_str: String =
                            rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if let Ok(s) = num_str.parse::<u64>() {
                            declared_size = Some(s);
                        }
                    }
                }

                // ── Early rejection via SIZE ──────────────────────────
                if !in_data_phase && declared_size.is_some() {
                    let trimmed = line.trim();
                    if trimmed.len() == 4 && trimmed.eq_ignore_ascii_case("data") {
                        if let Some(s) = declared_size.take() {
                            if s > max_msg_size as u64 {
                                tracing::info!(
                                    operation = "declared_size_exceeded",
                                    declared_size = s,
                                    max = max_msg_size,
                                    "Rejected oversized email before DATA phase"
                                );
                                let resp = crate::Response::custom(
                                    552,
                                    format!(
                                        "Message size {} exceeds maximum allowed {}",
                                        s, max_msg_size
                                    ),
                                );
                                let _ = write_response_blocking(&mut stream, &resp);
                                continue; // FSM stays in RCPT state; client should RSET/QUIT
                            }
                        }
                    }
                }

                let response = session.process(line.as_bytes());
                // ── Detect DATA phase end ─────────────────────────────
                if in_data_phase && response.code == 250 {
                    declared_size = None; // consumed
                }
                // mailin returns 354 to signal "Start mail input".
                if response.code == 354 {
                    in_data_phase = true;
                    data_bytes_total = 0;
                }
                match response.action {
                    crate::Action::Close => {
                        let _ = write_response_blocking(&mut stream, &response);
                        break;
                    }
                    crate::Action::Reply => {
                        if write_response_blocking(&mut stream, &response).is_err() {
                            break;
                        }
                    }
                    crate::Action::NoReply => {}
                    crate::Action::UpgradeTls => {
                        // STARTTLS not available in base edition — TLS migrated
                        // to advanced. Respond 454 (TLS not available) and keep
                        // the connection alive instead of dropping it
                        // (AUDIT-1 P2-9: hard-close confused SMTP clients).
                        let resp = crate::Response::custom(
                            454,
                            "TLS not available".to_string(),
                        );
                        if write_response_blocking(&mut stream, &resp).is_err() {
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                warn!(%e, "Error reading SMTP line from {}", peer_addr);
                break;
            }
        }
    }
}
fn write_response_blocking(
    writer: &mut impl std::io::Write,
    response: &mailin::Response,
) -> Result<(), std::io::Error> {
    let buf = response.buffer()?;
    writer.write_all(&buf)?;
    writer.flush()
}
