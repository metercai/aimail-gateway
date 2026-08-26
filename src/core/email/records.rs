// Encapsulated accessors for EmailRecord and AttachmentMetaRecord JSON fields.

use crate::core::email::storage::{AttachmentMetaRecord, EmailRecord, Recipients};

// ═══════════════════════════════════════════════════════════════════════
//  EmailRecord helpers
// ═══════════════════════════════════════════════════════════════════════

impl EmailRecord {
    // ── Direction checks ─────────────────────────────────────────────

    pub fn is_inbound(&self) -> bool {
        self.direction == "inbound"
    }

    pub fn is_outbound(&self) -> bool {
        self.direction == "outbound"
    }

    // ── Status checks ────────────────────────────────────────────────

    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }

    pub fn is_completed(&self) -> bool {
        self.status == "completed"
    }

    pub fn is_overlimit(&self) -> bool {
        self.send_count >= self.max_attempts
    }

    // ── Recipients ───────────────────────────────────────────────────

    /// Parse `self.recipients` (JSON) into a typed `Recipients` struct.
    pub fn recipients_parsed(&self) -> Recipients {
        Recipients::from_json(&self.recipients)
    }

    // ── Headers ──────────────────────────────────────────────────────

    /// Parse `self.headers` (JSON object), returning the parsed map or empty.
    pub fn headers_parsed(&self) -> serde_json::Map<String, serde_json::Value> {
        self.headers
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    /// Extract the `delivery_type` from parsed headers (e.g. "smtp", "webhook").
    pub fn delivery_type_from_headers(&self) -> Option<String> {
        self.headers_parsed()
            .get("delivery_type")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Extract the `message_id` from parsed headers.
    pub fn message_id_from_headers(&self) -> Option<String> {
        self.headers_parsed()
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Extract the `in_reply_to` from parsed headers.
    pub fn in_reply_to_from_headers(&self) -> Option<String> {
        self.headers_parsed()
            .get("in_reply_to")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Extract the `references` from parsed headers.
    pub fn references_from_headers(&self) -> Option<String> {
        self.headers_parsed()
            .get("references")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    // ── Attachments ──────────────────────────────────────────────────

    /// Parse `self.attachments` (JSON) for webhook payloads.
    pub fn attachments_parsed(&self) -> Vec<serde_json::Value> {
        self.attachments
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    /// Extract raw attachment IDs from `self.attachments` JSON. Used for cleanup.
    pub fn attachment_ids(&self) -> Vec<String> {
        let json_str = match self.attachments.as_deref() {
            Some(s) => s,
            None => return Vec::new(),
        };
        // First try plain array of strings
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(json_str) {
            return ids;
        }
        // Fall back: array of objects with "attachment_id" key
        let arr: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap_or_default();
        arr.iter()
            .filter_map(|v| v.get("attachment_id").and_then(|id| id.as_str()))
            .map(String::from)
            .collect()
    }

    /// Whether this email has any attachments.
    pub fn has_attachments(&self) -> bool {
        self.attachments
            .as_deref()
            .map(|s| !s.is_empty() && s != "[]")
            .unwrap_or(false)
    }

    // ── Endpoints ────────────────────────────────────────────────────

    /// Parse `self.endpoints` (JSON map of `{domain: {url, status}}`).
    pub fn endpoints_parsed(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        self.endpoints
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    /// Whether this email has any endpoints configured.
    pub fn has_endpoints(&self) -> bool {
        self.endpoints
            .as_deref()
            .map(|s| !s.is_empty() && s != "{}")
            .unwrap_or(false)
    }

    // ── Timestamp ────────────────────────────────────────────────────

    /// Parse `self.created_at` into a `chrono::DateTime<Utc>`.
    pub fn created_at_datetime(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }

    // ── Sender helpers ───────────────────────────────────────────────

    /// Return the domain part of `self.sender` (everything after the last '@').
    pub fn sender_domain(&self) -> Option<&str> {
        self.sender.rsplit('@').next().filter(|d| !d.is_empty())
    }

    // ── Serialisation helpers ────────────────────────────────────────

    /// Build a complete JSON payload for webhook delivery.
    pub fn to_webhook_payload(
        &self,
        forwarder: &str,
        sender_signature_cache: Option<&str>,
    ) -> serde_json::Value {
        let recipients = self.recipients_parsed();

        // Use the new body processing pipeline:
        // decomposition → per-layer signature → assembly with quote markers.
        // If the body looks like HTML (starts with <), run HTML→Markdown conversion.
        tracing::debug!(operation="body_before_proc", id=%self.id, len=self.body.len(), preview=%self.body.chars().take(80).collect::<String>());
        let is_html = self.body.trim_start().starts_with('<')
            || self.body.trim_start().starts_with("<!DOCTYPE")
            || self.body.trim_start().starts_with("<html");
        let processed = crate::core::email::bodyproc::process_email_body(&self.body, is_html);
        tracing::debug!(operation="body_after_proc", id=%self.id, len=processed.body.len(), preview=%processed.body.chars().take(80).collect::<String>());
        let (body, signature) = match sender_signature_cache {
            None => {
                // Only emit sender signature if confidence ≥ 0.65.
                // Rule 4 (bare name, 0.40) is too noisy for machine use.
                let sig = processed
                    .signature
                    .filter(|s| s.confidence >= 0.65)
                    .map(|s| s.raw);
                (processed.body, sig)
            }
            Some(cached_sig) if cached_sig.is_empty() => (self.body.clone(), None),
            Some(cached_sig) => (self.body.clone(), Some(cached_sig.to_string())),
        };

        let headers_map = self.headers_parsed();
        let message_id = headers_map
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let references: Vec<String> = headers_map
            .get("references")
            .and_then(|v| v.as_str())
            .map(|r| r.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let mut payload = serde_json::json!({
            "mail_id": self.id,
            "from": self.sender,
            "to": recipients.to,
            "cc": recipients.cc,
            "subject": self.subject,
            "body": body,
            "signature": signature,
            "headers": headers_map,
            "attachments": self.attachments_parsed(),
            "created_at": self.created_at,
            "forwarder": forwarder,
            "forward_at": chrono::Utc::now().to_rfc3339(),
        });

        if let Some(msg_id) = message_id {
            payload["message_id"] = serde_json::Value::String(msg_id);
        }
        if !references.is_empty() {
            payload["references"] = serde_json::Value::Array(
                references
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }

        if let Some(sig) = signature {
            payload["signature"] = serde_json::Value::String(sig);
        }
        payload
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AttachmentMetaRecord helpers
// ═══════════════════════════════════════════════════════════════════════

impl AttachmentMetaRecord {
    /// Parse `self.mail_id` (JSON array) into a `Vec<String>`.
    pub fn mail_ids(&self) -> Vec<String> {
        self.mail_id.clone().unwrap_or_default()
    }

    /// Whether any mail IDs reference this attachment.
    pub fn has_mail_ids(&self) -> bool {
        self.mail_id
            .as_ref()
            .map(|ids| !ids.is_empty())
            .unwrap_or(false)
    }

    /// How many email records reference this attachment.
    pub fn mail_id_count(&self) -> usize {
        self.mail_id.as_ref().map(|ids| ids.len()).unwrap_or(0)
    }

    /// Return the file extension for this attachment, defaulting to "bin".
    /// Delegates to the single derivation entry point so save/load/download/
    /// cleanup all agree on the on-disk extension.
    pub fn file_extension(&self) -> &str {
        crate::core::email::factory::AttachmentFactory::extension_for(&self.filename)
    }
}
