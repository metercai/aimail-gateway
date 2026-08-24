//! MX direct delivery — per-recipient endpoint tracking with internal re-resolve retry.

use std::collections::HashMap;
use std::sync::Arc;

use lettre::message::MultiPart;
use lettre::{Address, AsyncTransport};
use tracing::{info, warn};

use crate::core::email::factory::EmailFactory;
use crate::core::email::storage::EmailRecord;
use crate::core::errors::{AppError, AppResult};
use crate::core::smtp::mx::{resolve_mx, MxTransportPool};
use crate::core::strategy::MessageSigner;

/// Custom headers that must be forwarded verbatim onto outbound SMTP mail.
/// These are consumed by the receiving side from the raw message:
///   - X-Agentmail-Agent: agent platform/version identity (agent-side tools)
///   - X-Board-Members:   board member set for cross-gateway whitelist sync
///   - X-AMRelay-AutoReply: system-generated auto-reply marker
/// Everything else in the record headers is internal (webhook-only) and
/// must NOT leak into external mail.
pub const OUTBOUND_PASSTHROUGH_HEADERS: &[&str] = &[
    "X-Agentmail-Agent",
    "X-Board-Members",
    "X-AMRelay-AutoReply",
];

/// MX direct deliverer — resolves MX per domain and delivers directly.
pub struct MxDelivererImpl {
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    pool: MxTransportPool,
    mx_overrides: HashMap<String, String>,
}

impl MxDelivererImpl {
    pub fn new(
        resolver: Arc<hickory_resolver::TokioAsyncResolver>,
        mx_overrides: HashMap<String, String>,
    ) -> Self {
        Self {
            resolver,
            pool: MxTransportPool::new(std::time::Duration::from_secs(300)),
            mx_overrides,
        }
    }

    /// Deliver via MX with per-recipient endpoint tracking.
    ///
    /// - Reads `record.endpoints` to skip already-success recipients (retry path).
    /// - For pending recipients: resolve MX → try all hosts → re-resolve once → retry.
    /// - Marks individual recipients as "success" on delivery.
    /// - Returns Ok when all pending recipients delivered, Err otherwise.
    pub async fn deliver_via_mx(
        &self,
        dkim_signer: &Option<Arc<dyn MessageSigner>>,
        from_addr: &Address,
        recipients: &[Address],
        header_to: &[Address],
        header_cc: &[Address],
        email_body: &MultiPart,
        record: &EmailRecord,
        email_factory: &EmailFactory,
    ) -> AppResult<()> {
        let endpoints = record.endpoints_parsed().unwrap_or_default();

        // ── Phase 1: group pending recipients by domain ──
        let mut domain_groups: HashMap<String, Vec<Address>> = HashMap::new();
        for addr in recipients {
            let key = addr.to_string().to_lowercase();
            if endpoints
                .get(&key)
                .and_then(|v| v.get("status"))
                .and_then(|s| s.as_str())
                == Some("success")
            {
                continue;
            }
            domain_groups
                .entry(addr.domain().to_lowercase())
                .or_default()
                .push(addr.clone());
        }

        if domain_groups.is_empty() {
            return Ok(());
        }

        // Build message once (all recipients share same body/headers)
        let raw_to_send = build_mx_message(
            dkim_signer,
            from_addr,
            header_to,
            header_cc,
            email_body,
            record,
        )
        .await?;

        let mut any_failed = false;

        // ── Phase 2: per-domain resolve + send ──
        for (domain, addrs) in &domain_groups {
            let envelope = lettre::address::Envelope::new(
                Some(from_addr.clone()),
                addrs.iter().cloned().collect(),
            )
            .map_err(|_| AppError::Smtp("bad envelope".into()))?;

            let delivered = self
                .try_deliver_domain(
                    domain,
                    &envelope,
                    &raw_to_send,
                    from_addr,
                    dkim_signer,
                    record,
                )
                .await;

            for addr in addrs {
                let key = addr.to_string().to_lowercase();
                if delivered {
                    let _ = email_factory
                        .update_endpoint_status(&record.id, &key, "success")
                        .await;
                } else {
                    any_failed = true;
                }
            }
        }

        if any_failed {
            Err(AppError::Smtp("partial MX delivery failure".into()))
        } else {
            Ok(())
        }
    }

    /// Resolve MX for a domain → try all hosts → re-resolve once → retry.
    async fn try_deliver_domain(
        &self,
        domain: &str,
        envelope: &lettre::address::Envelope,
        raw_to_send: &[u8],
        _from_addr: &Address,
        _dkim_signer: &Option<Arc<dyn MessageSigner>>,
        _record: &EmailRecord,
    ) -> bool {
        // Resolve MX
        let mx_hosts = match resolve_mx(domain, &self.mx_overrides, &self.resolver).await {
            Ok(h) if !h.is_empty() => h.into_iter().map(|r| r.exchange).collect::<Vec<_>>(),
            _ => {
                warn!(domain = %domain, "MX: initial resolve failed");
                return false;
            }
        };

        // Try all MX hosts in priority order
        if self.try_mx_hosts(&mx_hosts, envelope, raw_to_send).await {
            return true;
        }

        // Re-resolve once (catch DNS flap / MX switch) and retry
        warn!(domain = %domain, "MX: all hosts failed, re-resolving");
        let mx_hosts2 = match resolve_mx(domain, &self.mx_overrides, &self.resolver).await {
            Ok(h) if !h.is_empty() => h.into_iter().map(|r| r.exchange).collect::<Vec<_>>(),
            _ => return false,
        };
        self.try_mx_hosts(&mx_hosts2, envelope, raw_to_send).await
    }

    /// Try each MX host in priority order. Returns true on first success.
    async fn try_mx_hosts(
        &self,
        hosts: &[String],
        envelope: &lettre::address::Envelope,
        raw_to_send: &[u8],
    ) -> bool {
        for host in hosts {
            match self.pool.get_or_create(host.as_str(), None).await {
                Ok(transport) => match transport.send_raw(envelope, raw_to_send).await {
                    Ok(_) => {
                        info!(mx = %host, "MX delivery OK");
                        return true;
                    }
                    Err(e) => {
                        warn!(mx = %host, error = %e, "MX send failed");
                    }
                },
                Err(e) => {
                    warn!(mx = %host, error = %e, "MX pool fail");
                }
            }
        }
        false
    }
}

/// Build a signed MIME message for MX delivery (shared across domains).
async fn build_mx_message(
    dkim_signer: &Option<Arc<dyn MessageSigner>>,
    from_addr: &Address,
    header_to: &[Address],
    header_cc: &[Address],
    email_body: &MultiPart,
    record: &EmailRecord,
) -> AppResult<Vec<u8>> {
    let subject = if record.subject.is_empty() {
        "(no subject)"
    } else {
        record.subject.as_str()
    };
    let headers_val = record.headers_parsed();
    let name_map = name_map_from_headers(&serde_json::Value::Object(headers_val.clone()));
    let from_name: Option<String> =
        headers_val
            .get("from")
            .and_then(|v| v.as_str())
            .and_then(|s| {
                if let Some(pos) = s.find('<') {
                    let n = s[..pos].trim().to_string();
                    if n.is_empty() { None } else { Some(n) }
                } else {
                    None
                }
            });

    let mut builder = lettre::Message::builder()
        .from(lettre::message::Mailbox::new(from_name, from_addr.clone()))
        .subject(subject);
    for addr in header_to {
        let display = name_map
            .get(&addr.to_string().to_lowercase())
            .cloned();
        builder = builder.to(lettre::message::Mailbox::new(display, addr.clone()));
    }
    for addr in header_cc {
        let display = name_map
            .get(&addr.to_string().to_lowercase())
            .cloned();
        builder = builder.cc(lettre::message::Mailbox::new(display, addr.clone()));
    }
    if let Some(v) = headers_val.get("message_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        builder = builder.header(lettre::message::header::MessageId::from(v.to_string()));
    }
    if let Some(v) = headers_val.get("in_reply_to").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        builder = builder.header(lettre::message::header::InReplyTo::from(v.to_string()));
    }
    if let Some(v) = headers_val.get("references").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        builder = builder.header(lettre::message::header::References::from(v.to_string()));
    }
    // ── Custom header passthrough (outbound-only whitelist) ──────────
    // X-Agentmail-Agent / X-Board-Members / X-AMRelay-AutoReply are
    // forwarded verbatim. All other record headers are internal
    // (webhook-only) and must not leak into external mail.
    for hname in OUTBOUND_PASSTHROUGH_HEADERS {
        if let Some(v) = headers_val.get(*hname).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
            builder = builder.header(crate::core::smtp::mime::PassthroughHeader {
                name: hname.to_string(),
                value: v.to_string(),
            });
        }
    }
    let email = builder
        .multipart(email_body.clone())
        .map_err(|e| AppError::Smtp(format!("build MIME: {}", e)))?;
    let raw = email.formatted();
    let raw_to_send = match dkim_signer {
        Some(signer) => signer.apply_sign(&raw, &record.id).await,
        None => std::borrow::Cow::Borrowed(raw.as_slice()),
    };
    Ok(raw_to_send.into_owned())
}

fn name_map_from_headers(headers: &serde_json::Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for key in &["to", "cc"] {
        if let Some(val) = headers.get(key).and_then(|v| v.as_str()) {
            for part in val.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some(pos) = part.find('<') {
                    let name = part[..pos].trim().to_string();
                    if let Some(end) = part.find('>') {
                        let email = part[pos + 1..end].trim().to_lowercase();
                        if !name.is_empty() && !email.is_empty() {
                            map.insert(email, name);
                        }
                    }
                }
            }
        }
    }
    map
}
