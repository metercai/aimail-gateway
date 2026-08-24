//! Outbound SMTP relay.

use std::sync::Arc;

use lettre::address::Address;
use lettre::address::Envelope;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message, MultiPart, SinglePart};
use lettre::AsyncTransport;
use lettre::Tokio1Executor;
use tracing::{error, info, warn};

use crate::core::config::RelayConfig;
use crate::core::email::factory::EmailFactory;
use crate::core::email::storage::EmailRecord;
use crate::core::email::utils::markdown_to_html;
use crate::core::errors::{AppError, AppResult};
use crate::core::smtp::mime::{build_with_attachments, parse_address};
use crate::core::smtp::mx_deliverer::MxDelivererImpl;
use crate::core::smtp::transport::{build_transport, SmtpTransportMode};
use crate::core::strategy::MessageSigner;

// ── SmtpRelay ─────────────────────────────────────────────────────

/// Outbound SMTP relay — supports both upstream relay and direct MX modes.
pub struct SmtpRelay {
    transport: SmtpTransportMode,
    email_factory: Arc<EmailFactory>,
    dkim_signer: Option<Arc<dyn MessageSigner>>,
    /// Fixed system auto-reply sender (postman@{gateway domain}). The system
    /// sender is never a deliverable mailbox — if it ever appears as a
    /// recipient (e.g. a reply-all to a welcome mail), it is excluded from
    /// SMTP envelope delivery unconditionally: when the gateway domain's MX
    /// points back at this gateway, envelope-delivering to it would bounce
    /// the mail straight back in (a storm vector).
    system_sender: String,
}

/// Resolve the effective sender address, preferring the persona-aware
/// address stored in headers["from"] over record.sender.
fn resolve_sender(record: &EmailRecord) -> AppResult<Address> {
    let headers = record.headers_parsed();
    if let Some(from_header) = headers.get("from").and_then(|v| v.as_str()) {
        if let Some(pos) = from_header.rfind('<') {
            let end = from_header.rfind('>').unwrap_or(from_header.len());
            let email = from_header[pos + 1..end].trim();
            if !email.is_empty() && email.contains('@') {
                return parse_address(email);
            }
        }
    }
    parse_address(&record.sender)
}

impl SmtpRelay {
    /// Build an SMTP relay from config.
    ///
    /// When `relay.smtp_server` is set → relay mode (original, upstream SMTP).
    /// When `relay.smtp_server` is empty or None → direct MX delivery mode.
    pub fn from_config(
        config: &RelayConfig,
        email_factory: Arc<EmailFactory>,
        hostname: Option<&str>,
        dkim_signer: Option<Arc<dyn MessageSigner>>,
        dns_resolver: Option<Arc<hickory_resolver::TokioAsyncResolver>>,
    ) -> AppResult<Self> {
        let has_relay = config
            .smtp_server
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        let transport = if has_relay {
            SmtpTransportMode::Relay(build_transport(config, hostname)?)
        } else if let Some(resolver) = dns_resolver {
            let mx_overrides = config.mx_dns_override.clone().unwrap_or_default();
            SmtpTransportMode::DirectMx(Arc::new(MxDelivererImpl::new(resolver, mx_overrides)))
        } else {
            return Err(AppError::Config(
                "No relay config — set relay.smtp_server for SMTP relay delivery".into(),
            ));
        };

        Ok(SmtpRelay {
            transport,
            email_factory,
            dkim_signer,
            system_sender: format!("postman@{}", hostname.unwrap_or("amail-relay")),
        })
    }

    /// Send an email — dispatches to relay or direct MX mode.
    pub async fn send_email(
        &self,
        record: &EmailRecord,
        attachment_data: Option<&[(String, String, Vec<u8>)]>,
    ) -> AppResult<()> {
        let html_body = if record.body.is_empty() {
            String::new()
        } else {
            markdown_to_html(&record.body)
        };
        let plain_body = record.body.clone();
        // Resolve sender with persona: prefer the full address from headers["from"]
        // (which preserves the persona prefix), fall back to record.sender.
        let from_addr = resolve_sender(record)?;

        let plain_part = SinglePart::builder()
            .header(ContentType::TEXT_PLAIN)
            .body(plain_body);
        let html_part = SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(html_body);
        let alt_part = MultiPart::alternative()
            .singlepart(plain_part)
            .singlepart(html_part);
        let email_body = match attachment_data {
            Some(att) if !att.is_empty() => build_with_attachments(alt_part, att),
            _ => alt_part,
        };

        let recipients = record.recipients_parsed();
        // Envelope (RCPT TO) = external recipients only — internal
        // recipients are delivered via webhook, never over SMTP.
        let external = self.filter_external_recipients(&recipients).await?;

        if external.is_empty() {
            info!(
                operation = "loopback_all",
                email_id = %record.id,
                "All recipients internal — no external delivery needed"
            );
            return Ok(());
        }

        // To/Cc headers = the full post-filter recipient list (external ∪
        // internal) so the final recipient sees every address, with the
        // to/cc slot distinction preserved.
        let header_to: Vec<Address> = recipients
            .to
            .iter()
            .filter_map(|r| parse_address(r).ok())
            .collect();
        let header_cc: Vec<Address> = recipients
            .cc
            .iter()
            .filter_map(|r| parse_address(r).ok())
            .collect();
        // If everything landed in Cc, the message still needs a To header —
        // fall back to the external set so the mail is well-formed.
        let header_to: Vec<Address> = if header_to.is_empty() {
            external.clone()
        } else {
            header_to
        };

        match &self.transport {
            SmtpTransportMode::Relay(transport) => {
                self.send_via_relay(
                    transport,
                    &from_addr,
                    &external,
                    &header_to,
                    &header_cc,
                    &email_body,
                    record,
                )
                .await
            }
            SmtpTransportMode::DirectMx(deliverer) => {
                deliverer
                    .deliver_via_mx(
                        &self.dkim_signer,
                        &from_addr,
                        &external,
                        &header_to,
                        &header_cc,
                        &email_body,
                        record,
                        &self.email_factory.as_ref(),
                    )
                    .await
            }
        }
    }

    /// Build display-name map from headers.to/cc ("Name <email>, ...").
    fn name_map_from_headers(
        headers: &serde_json::Value,
    ) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        for key in &["to", "cc"] {
            if let Some(val) = headers.get(key).and_then(|v| v.as_str()) {
                for part in val.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some(pos) = part.find('<') {
                        let name = part[..pos].trim().to_string();
                        let email = if let Some(end) = part.find('>') {
                            part[pos + 1..end].trim().to_lowercase()
                        } else {
                            continue;
                        };
                        if !name.is_empty() && !email.is_empty() {
                            map.insert(email, name);
                        }
                    }
                }
            }
        }
        map
    }

    /// Relay mode: all recipients via a single upstream SMTP.
    async fn send_via_relay(
        &self,
        transport: &lettre::AsyncSmtpTransport<Tokio1Executor>,
        from_addr: &Address,
        envelope: &[Address],
        header_to: &[Address],
        header_cc: &[Address],
        email_body: &MultiPart,
        record: &EmailRecord,
    ) -> AppResult<()> {
        let subject = if record.subject.is_empty() {
            "(no subject)".to_string()
        } else {
            record.subject.clone()
        };
        let headers_val = record.headers_parsed();
        let name_map = Self::name_map_from_headers(&serde_json::Value::Object(headers_val.clone()));

        let from_name: Option<String> =
            headers_val
                .get("from")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    if let Some(pos) = s.find('<') {
                        let n = s[..pos].trim().to_string();
                        if n.is_empty() {
                            None
                        } else {
                            Some(n)
                        }
                    } else {
                        None
                    }
                });

        let mut builder = Message::builder()
            .from(Mailbox::new(from_name, from_addr.clone()))
            .subject(subject);
        for addr in header_to {
            let display = name_map.get(&addr.to_string().to_lowercase()).cloned();
            builder = builder.to(Mailbox::new(display, addr.clone()));
        }
        for addr in header_cc {
            let display = name_map.get(&addr.to_string().to_lowercase()).cloned();
            builder = builder.cc(Mailbox::new(display, addr.clone()));
        }
        if let Some(v) = headers_val
            .get("message_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            builder = builder.header(lettre::message::header::MessageId::from(v.to_string()));
        }
        if let Some(v) = headers_val
            .get("in_reply_to")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            builder = builder.header(lettre::message::header::InReplyTo::from(v.to_string()));
        }
        if let Some(v) = headers_val
            .get("references")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            builder = builder.header(lettre::message::header::References::from(v.to_string()));
        }
        // ── Custom header passthrough (outbound-only whitelist) ──────────
        // X-Agentmail-Agent / X-Board-Members / X-AMRelay-AutoReply are
        // forwarded verbatim (same whitelist as mx_deliverer). All other
        // record headers are internal (webhook-only).
        for hname in crate::core::smtp::mx_deliverer::OUTBOUND_PASSTHROUGH_HEADERS {
            if let Some(v) = headers_val
                .get(*hname)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                builder = builder.header(crate::core::smtp::mime::PassthroughHeader {
                    name: hname.to_string(),
                    value: v.to_string(),
                });
            }
        }
        // Envelope (RCPT TO) carries external recipients only; the To/Cc
        // headers above carry the full post-filter list.
        let envelope_obj = Envelope::new(Some(from_addr.clone()), envelope.to_vec())
            .map_err(|e| AppError::Smtp(format!("failed to build envelope: {}", e)))?;
        let email = builder
            .envelope(envelope_obj.clone())
            .multipart(email_body.clone())
            .map_err(|e| AppError::Smtp(format!("failed to build MIME message: {}", e)))?;
        let raw = email.formatted();
        let raw_to_send = match &self.dkim_signer {
            Some(signer) => signer.apply_sign(&raw, &record.id).await,
            None => std::borrow::Cow::Borrowed(raw.as_slice()),
        };

        match transport.send_raw(&envelope_obj, &*raw_to_send).await {
            Ok(response) => {
                info!(operation="smtp_delivery_success", email_id = %record.id, sender = %record.sender, subject = %record.subject, status_code = %response.code(), "SMTP delivery successful");
                Ok(())
            }
            Err(e) => {
                error!(operation="smtp_delivery_failed", email_id = %record.id, sender = %record.sender, subject = %record.subject, error = %e, "SMTP delivery failed");
                Err(AppError::Smtp(format!("SMTP send error: {}", e)))
            }
        }
    }

    /// Filter recipients through loopback prevention.
    async fn filter_external_recipients(
        &self,
        recipients: &crate::core::email::storage::Recipients,
    ) -> AppResult<Vec<Address>> {
        let mut external = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for r in recipients.to.iter().chain(recipients.cc.iter()) {
            let lower = r.to_lowercase();
            if !seen.insert(lower.clone()) {
                continue;
            }
            // System sender (postman@{domain}) as a recipient is a sink,
            // never deliverable — exclude from the envelope unconditionally
            // (see `system_sender` field docs for the storm rationale).
            if lower == self.system_sender {
                info!(operation="system_sender_sink", recipient = %r,
                      "System sender as recipient — excluded from SMTP envelope");
                continue;
            }
            let addr = match parse_address(r) {
                Ok(a) => a,
                Err(_) => continue,
            };
            match self
                .email_factory
                .env_factory
                .lookup_domain_addr(r.rsplit('@').next().unwrap_or(r))
                .await
            {
                Ok(Some(_)) => {
                    info!(operation="loopback_skip", recipient = %r, "Loopback prevention: skipping internal-domain recipient")
                }
                Ok(None) => external.push(addr),
                Err(e) => {
                    warn!(operation="loopback_db_error", recipient = %r, error = %e, "Database error during loopback lookup, skipping")
                }
            }
        }
        Ok(external)
    }
}
