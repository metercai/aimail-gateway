//! MX direct delivery — domain-grouped SMTP with built-in DNS resolution.

use std::collections::HashMap;
use std::sync::Arc;

use lettre::{Address, AsyncTransport};
use lettre::message::MultiPart;
use tracing::{info, warn};

use crate::core::email::storage::EmailRecord;
use crate::core::errors::{AppError, AppResult};
use crate::core::smtp::mx::{resolve_mx, MxTransportPool};
use crate::core::strategy::MessageSigner;

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

    /// Deliver an email directly to MX hosts, grouped by recipient domain.
    pub async fn deliver_via_mx(
        &self,
        dkim_signer: &Option<Arc<dyn MessageSigner>>,
        from_addr: &Address,
        recipients: &[Address],
        email_body: &MultiPart,
        record: &EmailRecord,
    ) -> AppResult<()> {
        let mut domain_groups: HashMap<String, (Vec<String>, Vec<Address>)> = HashMap::new();
        let mut dropped_count = 0usize;

        for addr in recipients {
            let domain = addr.domain().to_lowercase();
            if let Some(group) = domain_groups.get_mut(&domain) {
                group.1.push(addr.clone());
                continue;
            }
            let mx_hosts: Vec<String> = match resolve_mx(&domain, &self.mx_overrides, &self.resolver).await {
                Ok(hosts) if !hosts.is_empty() => hosts.into_iter().map(|r| r.exchange).collect(),
                Ok(_) => { dropped_count += 1; warn!(domain=%domain, "MX: no records, dropping"); continue; }
                Err(e) => { dropped_count += 1; warn!(domain=%domain, error=%e, "MX: lookup failed"); continue; }
            };
            domain_groups.insert(domain, (mx_hosts, vec![addr.clone()]));
        }

        if domain_groups.is_empty() {
            return Err(AppError::Smtp(format!("no MX hosts found ({} dropped)", dropped_count)));
        }
        if dropped_count > 0 {
            warn!(operation="mx_dropped", dropped=dropped_count, total=recipients.len());
        }

        let subject = if record.subject.is_empty() { "(no subject)" } else { record.subject.as_str() };
        let headers_val = record.headers_parsed();
        let name_map = name_map_from_headers(&serde_json::Value::Object(headers_val.clone()));
        let from_name: Option<String> = headers_val.get("from").and_then(|v| v.as_str())
            .and_then(|s| {
                if let Some(pos) = s.find('<') {
                    let n = s[..pos].trim().to_string();
                    if n.is_empty() { None } else { Some(n) }
                } else { None }
            });

        let mut builder = lettre::Message::builder()
            .from(lettre::message::Mailbox::new(from_name, from_addr.clone()))
            .subject(subject);
        for addr in recipients {
            let display = name_map.get(&addr.to_string().to_lowercase()).cloned();
            builder = builder.to(lettre::message::Mailbox::new(display, addr.clone()));
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
        let email = builder.multipart(email_body.clone())
            .map_err(|e| AppError::Smtp(format!("build MIME: {}", e)))?;
        let raw = email.formatted();
        let raw_to_send = match dkim_signer {
            Some(signer) => signer.apply_sign(&raw, &record.id).await,
            None => std::borrow::Cow::Borrowed(raw.as_slice()),
        };

        let mut last_error = None;
        for (_domain, (mx_hosts, domain_recipients)) in &domain_groups {
            let envelope = lettre::address::Envelope::new(
                Some(from_addr.clone()),
                domain_recipients.iter().cloned().collect(),
            ).map_err(|_| AppError::Smtp("bad envelope".into()))?;

            let mut delivered = false;
            for host in mx_hosts {
                match self.pool.get_or_create(host.as_str(), None).await {
                    Ok(transport) => {
                        match transport.send_raw(&envelope, &*raw_to_send).await {
                            Ok(_) => { info!(mx=%host, "MX delivery OK"); delivered = true; break; }
                            Err(e) => { last_error = Some(AppError::Smtp(format!("{}: {}", host, e))); }
                        }
                    }
                    Err(e) => { last_error = Some(e); }
                }
            }
            if !delivered {
                return Err(last_error.unwrap_or_else(|| AppError::Smtp("no MX transport available".into())));
            }
        }
        Ok(())
    }
}

fn name_map_from_headers(headers: &serde_json::Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for key in &["to", "cc"] {
        if let Some(val) = headers.get(key).and_then(|v| v.as_str()) {
            for part in val.split(',') {
                let part = part.trim();
                if part.is_empty() { continue; }
                if let Some(pos) = part.find('<') {
                    let name = part[..pos].trim().to_string();
                    if let Some(end) = part.find('>') {
                        let email = part[pos+1..end].trim().to_lowercase();
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
