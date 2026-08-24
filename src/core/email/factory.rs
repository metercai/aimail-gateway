use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailparse::ParsedMail;
use sha2::{Digest, Sha256};

use crate::core::config::StorageConfig;
use crate::core::errors::{AppError, AppResult};
use crate::core::factory::EnvFactory;
use crate::core::storage::Database;
use crate::core::storage::SystemDomainRecord;
use crate::core::strategy::SystemStore;

use crate::core::email::storage::{
    AttachmentMetaRecord, AttachmentPermissionRecord, EmailRecord, Recipients,
};

/// Email CRUD factory backed by `Arc<Database>`.
#[derive(Clone)]
pub struct EmailFactory {
    db: Arc<Database>,
    pub env_factory: EnvFactory,
    attachments_dir: PathBuf,
}

/// Parsed attachment extracted from a MIME part.
#[derive(Debug, Clone)]
pub struct MimeAttachment {
    pub content: Vec<u8>,
    pub content_type: Option<String>,
    pub filename: Option<String>,
}

/// Result of parsing an inbound MIME message.
#[derive(Debug, Clone)]
pub struct ParsedInbound {
    pub body: String,
    pub attachments: Vec<MimeAttachment>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub headers: BTreeMap<String, String>,
}

impl EmailFactory {
    pub fn new(
        db: Arc<Database>,
        attachments_dir: PathBuf,
        system_store: Arc<dyn SystemStore>,
    ) -> Self {
        EmailFactory {
            env_factory: EnvFactory::new(
                db.clone(),
                system_store,
                Arc::new(crate::core::whitelist::ExactKeyResolver),
            ),
            db,
            attachments_dir,
        }
    }

    /// On-disk hash-prefix directory: `{attachments_dir}/{sender_hash16}/`.
    pub fn attachment_hash_dir(&self, sender_email: &str) -> PathBuf {
        let hash = sha2::Sha256::digest(sender_email.as_bytes());
        let hash_hex = hex::encode(hash);
        let sender_dir = &hash_hex[..16];
        self.attachments_dir.join(sender_dir)
    }

    // ── Create ────────────────────────────────────────────────────────

    /// Create an email record (inbound or outbound) and return the inserted row.
    async fn create_email(
        &self,
        direction: &str,
        id: &str,
        system_id: &str,
        sender: &str,
        recipients: &str,
        subject: &str,
        body: &str,
        endpoints: Option<&str>,
        attachments: Option<&str>,
        headers: Option<&str>,
        max_attempts: i32,
    ) -> AppResult<EmailRecord> {
        self.db
            .insert_email(id, system_id, direction, sender, recipients, subject, body, endpoints, attachments, headers, max_attempts)
            .await
    }

    /// Create an inbound email record.
    pub async fn create_inbound(
        &self, id: &str, system_id: &str, sender: &str, recipients: &str,
        subject: &str, body: &str, endpoints: Option<&str>,
        attachments: Option<&str>, headers: Option<&str>, max_attempts: i32,
    ) -> AppResult<EmailRecord> {
        self.create_email("inbound", id, system_id, sender, recipients, subject, body, endpoints, attachments, headers, max_attempts).await
    }

    /// Create an outbound email record.
    pub async fn create_outbound(
        &self, id: &str, system_id: &str, sender: &str, recipients: &str,
        subject: &str, body: &str, endpoints: Option<&str>,
        attachments: Option<&str>, headers: Option<&str>, max_attempts: i32,
    ) -> AppResult<EmailRecord> {
        self.create_email("outbound", id, system_id, sender, recipients, subject, body, endpoints, attachments, headers, max_attempts).await
    }

    // ── Status transitions ────────────────────────────────────────────

    /// Transition an email to `completed` and return the updated record.
    pub async fn complete(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        self.db.update_email_completed(id).await
    }

    /// Mark email as ready for next retry (after failed delivery attempt).
    pub async fn ready_retry(
        &self,
        id: &str,
        send_count: i32,
        next_retry_at: &str,
    ) -> AppResult<Option<EmailRecord>> {
        self.db
            .update_email_ready_retry(id, send_count, next_retry_at)
            .await
    }

    // ── Queries ───────────────────────────────────────────────────────

    /// Get a single email by ID.
    pub async fn get(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        self.db.get_email(id).await
    }

    /// CAS claim: atomically transition status `ready` → `sending`.
    /// Returns `Some(record)` if the claim succeeded, `None` if already consumed.
    pub async fn claim_ready(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        self.db.claim_ready(id).await
    }

    /// Get emails ready for delivery.
    pub async fn get_pending_retry(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.db.get_pending_retry_emails(limit).await
    }

    /// Get overlimit emails.
    pub async fn get_overlimit(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.db.get_overlimit_emails(limit).await
    }

    /// List emails by system.
    pub async fn list_by_system(&self, system_id: &str, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.db.list_emails_by_system(system_id, limit).await
    }

    /// List emails by status.
    pub async fn list_by_status(&self, status: &str, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.db.list_emails_by_status(status, limit).await
    }

    /// Count emails by status.
    pub async fn count_by_status(&self, status: &str) -> AppResult<i64> {
        self.db.count_emails_by_status(status).await
    }

    /// Count emails by system.
    pub async fn count_by_system(&self, system_id: &str) -> AppResult<i64> {
        self.db.count_emails_by_system(system_id).await
    }

    /// Search outbound emails by sender address (for NDR correlation).
    pub async fn find_outbound_by_sender(
        &self,
        sender: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        self.db
            .find_emails_by_sender_direction(sender, "outbound", limit)
            .await
    }

    /// Mark an outbound email as delivered (MX accepted, waiting for NDR window).
    pub async fn mark_delivered(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        self.db.update_email_delivered(id).await
    }

    /// Update only send_count without changing status.
    /// Used by exhaustion paths to record the final attempt before marking completed.
    pub async fn update_send_count(&self, id: &str, send_count: i32) -> AppResult<()> {
        self.db.update_email_send_count(id, send_count).await
    }

    /// Fetch delivered emails past their NDR window.
    pub async fn get_expired_delivered(
        &self,
        cutoff: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        self.db.get_delivered_expired_before(cutoff, limit).await
    }

    /// List all emails.
    pub async fn list(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.db.list_emails(limit).await
    }

    /// Delete an email.
    pub async fn delete(&self, id: &str) -> AppResult<()> {
        self.db.delete_email(id).await
    }

    /// Update a single endpoint's status within the endpoints JSON.
    pub async fn update_endpoint_status(
        &self,
        email_id: &str,
        domain: &str,
        new_status: &str,
    ) -> AppResult<bool> {
        self.db
            .update_email_endpoint_status(email_id, domain, new_status)
            .await
    }

    /// Check whether all endpoints are completed.
    pub async fn check_all_endpoints_completed(&self, email_id: &str) -> AppResult<bool> {
        self.db.check_all_endpoints_completed(email_id).await
    }

    /// Update the email body (used when body was preprocessed for the first time).
    /// Atomically update both cleaned body and sender_signature cache.
    pub async fn update_email_body_and_signature(
        &self,
        id: &str,
        body: &str,
        signature: &str,
    ) -> AppResult<()> {
        self.db
            .update_email_body_and_signature(id, body, signature)
            .await
    }

    /// Update attachments JSON after attachments have been saved to disk.
    pub async fn update_email_attachments(&self, id: &str, attachments: &str) -> AppResult<()> {
        self.db.update_email_attachments(id, attachments).await
    }

    /// Check if the sender's domain belongs to a registered system domain.
    pub async fn is_internal_sender(&self, sender: &str) -> AppResult<bool> {
        self.db.is_internal_sender(sender).await
    }

    /// Parse the attachments JSON string from an email record to get attachment IDs.
    pub async fn get_attachment_ids(&self, email_id: &str) -> AppResult<Vec<String>> {
        self.db.get_email_attachment_ids(email_id).await
    }

    /// Resolve attachment IDs to human-readable "filename (type)" strings.
    /// Used for notification body display — not for file access.
    /// Uses batch lookup (single DB call) instead of N+1 queries.
    pub async fn attachment_display_list(&self, ids: &[String]) -> Vec<String> {
        if ids.is_empty() {
            return Vec::new();
        }
        let metas = self.db.get_attachment_meta_batch(ids).await.unwrap_or_default();
        let mut map: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for meta in &metas {
            map.insert(meta.id.as_str(), meta.filename.as_str());
        }
        ids.iter()
            .map(|id| match map.get(id.as_str()) {
                Some(filename) => format!("{} ({})", filename,
                    metas.iter().find(|m| m.id == *id).and_then(|m| m.content_type.as_deref()).unwrap_or("unknown")),
                None => format!("{} (deleted)", id),
            })
            .collect()
    }

    // ── Recipient resolution ──────────────────────────────────────────

    /// Build a Recipients struct from a JSON string.
    pub fn parse_recipients(json: &str) -> Recipients {
        Recipients::from_json(json)
    }

    /// Serialize Recipients to JSON string.
    pub fn recipients_to_json(recipients: &Recipients) -> String {
        recipients.to_json()
    }

    /// Resolve the domain registration for an email address.
    /// Delegates to EnvFactory::resolve_domain_from_address for consistent two-step logic.
    pub async fn resolve_domain_from_address(
        &self,
        address: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        self.env_factory.resolve_domain_from_address(address).await
    }

    /// Build endpoints JSON for a list of recipient email addresses.
    /// Delegates to `EnvFactory::build_endpoints_for_recipients`.
    pub async fn build_endpoints_for_recipients(&self, recipients: &[String]) -> String {
        self.env_factory
            .build_endpoints_for_recipients(recipients)
            .await
    }

    /// Validate attachments against config limits: count, size per attachment, MIME types.
    pub fn validate_attachments(
        config: &StorageConfig,
        attachments: &[(String, String, Vec<u8>, Option<String>)],
        per_system_max_count: Option<usize>,
        per_system_max_size: Option<usize>,
    ) -> AppResult<()> {
        let max_count = per_system_max_count.unwrap_or(config.attachment_max_attachments);
        let max_size = per_system_max_size.unwrap_or(config.attachment_max_size);

        // 1. Count check
        if attachments.len() > max_count {
            return Err(AppError::Validation(format!(
                "Too many attachments ({}) — max allowed: {}",
                attachments.len(),
                max_count
            )));
        }

        // 2. Size check per attachment
        for (filename, _, data, _) in attachments {
            if data.len() > max_size {
                return Err(AppError::Validation(format!(
                    "Attachment '{}' exceeds max size of {} bytes",
                    filename, max_size
                )));
            }
        }

        // 3. Type check (only when allowed_types is non-empty)
        if !config.attachment_allowed_types.is_empty() {
            for (filename, content_type, _, _) in attachments {
                let allowed = config.attachment_allowed_types.iter().any(|t| {
                    if t.ends_with("/*") {
                        let prefix = &t[..t.len() - 1]; // e.g. "image/"
                        content_type.starts_with(prefix)
                    } else {
                        t == content_type
                    }
                });
                if !allowed {
                    return Err(AppError::Validation(format!(
                        "Attachment '{}' has disallowed MIME type: {}",
                        filename, content_type
                    )));
                }
            }
        }

        Ok(())
    }

    // ── MIME parsing ──────────────────────────────────────────────────

    /// Parse an inbound MIME message body: body text, attachments, to/cc, threading headers.
    pub fn parse_mime(
        raw: &[u8],
    ) -> AppResult<(
        String,
        Vec<MimeAttachment>,
        Vec<String>,
        Vec<String>,
        BTreeMap<String, String>,
    )> {
        let parsed = mailparse::parse_mail(raw)
            .map_err(|e| AppError::Parse(format!("MIME parse failed: {}", e)))?;

        let mut body = String::new();
        let mut attachments: Vec<MimeAttachment> = Vec::new();

        // Walk MIME parts recursively
        EmailFactory::walk_mime_parts(&parsed, &mut body, &mut attachments);

        // Extract To/Cc headers
        let to_emails = parsed
            .headers
            .iter()
            .filter(|h| h.get_key().eq_ignore_ascii_case("to"))
            .flat_map(|h| {
                let val = h.get_value();
                val.split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();

        let cc_emails = parsed
            .headers
            .iter()
            .filter(|h| h.get_key().eq_ignore_ascii_case("cc"))
            .flat_map(|h| {
                let val = h.get_value();
                val.split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();

        // Extract threading headers
        let mut threading_headers = BTreeMap::new();
        for h in &parsed.headers {
            if h.get_key().eq_ignore_ascii_case("references") {
                threading_headers.insert("references".to_string(), h.get_value().to_string());
            } else if h.get_key().eq_ignore_ascii_case("in-reply-to") {
                threading_headers.insert("in-reply-to".to_string(), h.get_value().to_string());
            }
        }

        // Convert HTML body to plain text if needed
        if body.starts_with("<") {
            let before_len = body.len();
            body = EmailFactory::html_to_text(&body);
            tracing::info!(
                operation = "html_to_text_applied",
                before_len = before_len,
                after_len = body.len(),
                after_preview = %body.chars().take(80).collect::<String>(),
                "HTML-to-text conversion applied"
            );
        }

        Ok((body, attachments, to_emails, cc_emails, threading_headers))
    }

    /// Parse MIME with full header extraction: subject, message_id, in-reply-to, references.
    /// Returns an 8-tuple for SMTP receiver usage.
    pub fn parse_mime_detailed(
        raw: &[u8],
    ) -> AppResult<(
        String,
        Vec<(String, String, Vec<u8>, Option<String>)>,
        Vec<String>,
        Vec<String>,
        String,
        String,
        String,
        String,
    )> {
        let parsed = mailparse::parse_mail(raw)
            .map_err(|e| AppError::Parse(format!("MIME parse failed: {}", e)))?;
        Self::parse_mime_detailed_from_parsed(&parsed)
    }

    /// Same as parse_mime_detailed but reuses an already-parsed ParsedMail.
    /// Callers that need access to raw headers after parsing can parse once and
    /// pass the result here, avoiding a redundant full MIME parse.
    pub fn parse_mime_detailed_from_parsed(
        parsed: &mailparse::ParsedMail,
    ) -> AppResult<(
        String,
        Vec<(String, String, Vec<u8>, Option<String>)>,
        Vec<String>,
        Vec<String>,
        String,
        String,
        String,
        String,
    )> {
        let mut body = String::new();
        let mut attachments: Vec<MimeAttachment> = Vec::new();
        EmailFactory::walk_mime_parts(parsed, &mut body, &mut attachments);

        // Fallback: non-MIME messages have no subparts — use main body directly
        if body.is_empty() {
            let main_body = parsed.get_body_raw().unwrap_or_default();
            let text = Self::decode_text_body(&main_body, &parsed.ctype);
            if !text.is_empty() {
                body = text;
            }
        }

        // Extract To/Cc headers
        let to_emails: Vec<String> = parsed
            .headers
            .iter()
            .filter(|h| h.get_key().eq_ignore_ascii_case("to"))
            .flat_map(|h| {
                h.get_value()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();

        let cc_emails: Vec<String> = parsed
            .headers
            .iter()
            .filter(|h| h.get_key().eq_ignore_ascii_case("cc"))
            .flat_map(|h| {
                h.get_value()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .collect();

        // Extract threading headers + subject + message_id
        let mut in_reply_to = String::new();
        let mut references = String::new();
        let mut message_id = String::new();
        let mut subject = String::new();
        for h in &parsed.headers {
            let key = h.get_key();
            if key.eq_ignore_ascii_case("in-reply-to") {
                in_reply_to = h.get_value().to_string();
            } else if key.eq_ignore_ascii_case("references") {
                references = h.get_value().to_string();
            } else if key.eq_ignore_ascii_case("message-id") {
                message_id = h.get_value().to_string();
            } else if key.eq_ignore_ascii_case("subject") {
                subject = h.get_value().to_string();
            }
        }

        // Convert HTML body to plain text if needed
        if body.starts_with("<") {
            let before_len = body.len();
            body = EmailFactory::html_to_text(&body);
            tracing::debug!(
                operation = "html_to_text_applied",
                before_len = before_len,
                after_len = body.len(),
                after_preview = %body.chars().take(80).collect::<String>(),
                "HTML-to-text conversion applied"
            );
        }

        // Convert MimeAttachment vec to tuple vec
        let attachment_tuples: Vec<(String, String, Vec<u8>, Option<String>)> = attachments
            .into_iter()
            .map(|a| {
                let filename = a.filename.unwrap_or_else(|| "attachment.dat".to_string());
                let content_type = a
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                (filename, content_type, a.content, None)
            })
            .collect();

        Ok((
            body,
            attachment_tuples,
            to_emails,
            cc_emails,
            in_reply_to,
            references,
            message_id,
            subject,
        ))
    }

    /// Recursively walk MIME parts, collecting body text and attachments.
    fn walk_mime_parts(
        parsed: &ParsedMail,
        body: &mut String,
        attachments: &mut Vec<MimeAttachment>,
    ) {
        for sub in &parsed.subparts {
            let cdisp = sub.get_content_disposition();

            // Check if this part is an attachment
            // Skip if explicitly marked as inline (e.g., inline images with CID)
            if cdisp.disposition != mailparse::DispositionType::Inline {
                if let Some(filename) = cdisp.params.get("filename") {
                    if !filename.is_empty() {
                        let content_type = sub.ctype.mimetype.to_lowercase();
                        let data = sub.get_body_raw().unwrap_or_default();
                        attachments.push(MimeAttachment {
                            content: data,
                            content_type: Some(content_type),
                            filename: Some(filename.clone()),
                        });
                        continue;
                    }
                }
            }

            // Check content type for body text
            let (content_type, sub_subtype) =
                if let Some((a, b)) = sub.ctype.mimetype.split_once('/') {
                    (a.to_lowercase(), b.to_lowercase())
                } else {
                    (sub.ctype.mimetype.to_lowercase(), String::new())
                };

            if content_type == "text" {
                let body_raw = sub.get_body_raw().unwrap_or_default();
                let text = Self::decode_text_body(&body_raw, &sub.ctype);
                tracing::debug!(
                    operation = "mime_part_text",
                    mime_type = %sub.ctype.mimetype,
                    charset = %sub.ctype.params.get("charset").map(|s| s.as_str()).unwrap_or(""),
                    raw_len = body_raw.len(),
                    decoded_len = text.len(),
                    decoded_preview = %text.chars().take(80).collect::<String>(),
                    "MIME text part decoded"
                );
                if !text.is_empty() {
                    if sub_subtype == "plain" {
                        body.clear();
                        body.push_str(&text);
                    } else if body.is_empty() && sub_subtype == "html" {
                        body.push_str(&text);
                    } else if body.is_empty() {
                        body.push_str(&text);
                    }
                }
            }

            // Recurse into nested parts
            if !sub.subparts.is_empty() {
                EmailFactory::walk_mime_parts(sub, body, attachments);
            }
        }
    }

    /// Decode a MIME text body part according to its charset parameter.
    /// Falls back to UTF-8 lossy if the charset is unknown or decoding fails.
    fn decode_text_body(raw: &[u8], ctype: &mailparse::ParsedContentType) -> String {
        let charset = ctype
            .params
            .get("charset")
            .map(|s| s.as_str())
            .unwrap_or("");
        if charset.is_empty() {
            return String::from_utf8_lossy(raw).into_owned();
        }
        match encoding_rs::Encoding::for_label_no_replacement(charset.as_bytes()) {
            Some(enc) => {
                let (cow, _enc, had_errors) = enc.decode(raw);
                if had_errors {
                    tracing::warn!(
                        operation = "charset_decode_errors",
                        charset = %charset,
                        "Non-fatal decoding errors during charset conversion"
                    );
                }
                cow.into_owned()
            }
            None => {
                tracing::warn!(
                    operation = "unknown_charset",
                    charset = %charset,
                    "Unknown charset — falling back to UTF-8 lossy"
                );
                String::from_utf8_lossy(raw).into_owned()
            }
        }
    }

    /// Simple HTML-to-text: strip tags, collapse whitespace.
    pub fn html_to_text(html: &str) -> String {
        let mut result = String::with_capacity(html.len());
        let mut in_tag = false;

        for c in html.chars() {
            if c == '<' {
                in_tag = true;
                result.push(' ');
            } else if c == '>' {
                in_tag = false;
            } else if !in_tag {
                match c {
                    '&' => {
                        result.push('&');
                    }
                    _ => {
                        result.push(c);
                    }
                }
            }
        }

        // Collapse multiple spaces/newlines
        result.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── MIME construction for outbound ────────────────────────────────

    /// Build a MIME message for outbound delivery with attachments.
    pub fn build_with_attachments(
        body: &str,
        attachments: &[(Vec<u8>, String, String)],
    ) -> AppResult<Vec<u8>> {
        if attachments.is_empty() {
            return Ok(body.as_bytes().to_vec());
        }

        let boundary = format!(
            "----=_Part_{}.{}",
            uuid::Uuid::new_v4(),
            chrono::Utc::now().timestamp()
        );
        let mut mime = String::new();

        // Write body part
        mime.push_str(&format!("--{}\r\n", boundary));
        mime.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        mime.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        mime.push_str(&EmailFactory::base64_encode_wrapped(body.as_bytes()));
        mime.push_str("\r\n");

        // Write attachment parts
        for (content, filename, content_type) in attachments {
            mime.push_str(&format!("--{}\r\n", boundary));
            mime.push_str(&format!(
                "Content-Type: {}; name=\"{}\"\r\n",
                content_type, filename
            ));
            mime.push_str(&format!(
                "Content-Disposition: attachment; filename=\"{}\"\r\n",
                filename
            ));
            mime.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            mime.push_str(&EmailFactory::base64_encode_wrapped(content));
            mime.push_str("\r\n");
        }

        // Close boundary
        mime.push_str(&format!("--{}--\r\n", boundary));

        Ok(mime.into_bytes())
    }

    /// Base64-encode bytes with 76-character line wrapping (RFC 2045).
    pub fn base64_encode_wrapped(data: &[u8]) -> String {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        encoded
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 76 == 0 {
                    Some('\n')
                } else {
                    None
                }
                .into_iter()
                .chain(std::iter::once(c))
            })
            .collect()
    }
}

/// Factory for attachment CRUD and permission operations.
#[derive(Clone)]
pub struct AttachmentFactory {
    db: Arc<Database>,
    attachments_dir: PathBuf,
}

/// Bundle of both factories, always used together — stores Arcs internally
/// so HttpState clone and per-connection SMTP cloning are both O(1).
#[derive(Clone)]
pub struct MailFactories {
    pub email: Arc<EmailFactory>,
    pub attachment: Arc<AttachmentFactory>,
}

impl MailFactories {
    /// Create both factories from shared dependencies.
    /// `storage_path` is the base storage directory; attachments dir is derived internally.
    /// Also loads the board address registry from `a2a_board/` and attaches it
    /// to the env factory (RCPT substantive check for `.a2a@` addresses).
    pub fn new(
        db: Arc<Database>,
        storage_path: &std::path::Path,
        system_store: Arc<dyn SystemStore>,
    ) -> Self {
        let attachments_dir = storage_path.join("attachments");
        let board_registry = Arc::new(crate::board::registry::BoardRegistry::new());
        board_registry.load(&storage_path.to_string_lossy());
        let mut email_factory = EmailFactory::new(
            db.clone(),
            attachments_dir.clone(),
            system_store,
        );
        email_factory.env_factory = email_factory
            .env_factory
            .with_board_registry(board_registry);
        Self {
            email: Arc::new(email_factory),
            attachment: Arc::new(AttachmentFactory::new(db, attachments_dir)),
        }
    }
}

impl AttachmentFactory {
    pub fn new(db: Arc<Database>, attachments_dir: PathBuf) -> Self {
        AttachmentFactory {
            db,
            attachments_dir,
        }
    }

    // ── Metadata CRUD ─────────────────────────────────────────────────

    /// Create attachment metadata after writing file to disk.
    pub async fn create_meta(
        &self,
        id: &str,
        filename: &str,
        content_type: Option<&str>,
        sender_email: &str,
        mail_id: Option<&[String]>,
    ) -> AppResult<AttachmentMetaRecord> {
        self.db
            .insert_attachment_meta(id, filename, content_type, sender_email, mail_id)
            .await
    }

    /// Get attachment metadata by ID.
    pub async fn get_meta(&self, id: &str) -> AppResult<Option<AttachmentMetaRecord>> {
        self.db.get_attachment_meta(id).await
    }

    /// List attachments by mail_id.
    pub async fn list_by_mail_id(&self, mail_id: &str) -> AppResult<Vec<AttachmentMetaRecord>> {
        self.db.get_attachments_by_mail_id(mail_id).await
    }

    /// Find expired attachments (older than `before`).
    pub async fn list_expired_before(
        &self,
        before: &str,
        limit: i64,
    ) -> AppResult<Vec<AttachmentMetaRecord>> {
        self.db.get_attachments_expired_before(before, limit).await
    }

    /// Delete attachment metadata.
    pub async fn delete_meta(&self, id: &str) -> AppResult<()> {
        self.db.delete_attachment_meta_v2(id).await
    }

    // ── Permission CRUD ───────────────────────────────────────────────

    /// Grant download permission to a user.
    pub async fn create_permission(
        &self,
        attachment_id: &str,
        user_email: &str,
    ) -> AppResult<AttachmentPermissionRecord> {
        self.db
            .insert_attachment_permission(attachment_id, user_email)
            .await
    }

    /// List all permissions for an attachment.
    pub async fn list_permissions(
        &self,
        attachment_id: &str,
    ) -> AppResult<Vec<AttachmentPermissionRecord>> {
        self.db.list_attachment_permissions(attachment_id).await
    }

    /// Revoke a specific user's permission.
    pub async fn revoke_permission(&self, attachment_id: &str, user_email: &str) -> AppResult<()> {
        self.db
            .delete_attachment_permission_by_user(attachment_id, user_email)
            .await
    }

    /// Delete all permissions for an attachment.
    pub async fn revoke_all(&self, attachment_id: &str) -> AppResult<()> {
        self.db
            .delete_attachment_permissions_by_attachment_id(attachment_id)
            .await
    }

    /// Delete a single permission by row ID.
    pub async fn delete_permission(&self, id: i64) -> AppResult<()> {
        self.db.delete_attachment_permission(id).await
    }

    /// Count remaining permissions for an attachment.
    pub async fn count_permissions(&self, attachment_id: &str) -> AppResult<i64> {
        self.db.count_attachment_permissions(attachment_id).await
    }

    /// Count mail_ids referencing an attachment.
    pub async fn count_mail_ids(&self, attachment_id: &str) -> AppResult<i64> {
        self.db.count_attachment_mail_ids(attachment_id).await
    }

    /// Remove a mail_id from the attachment's mail_id array.
    pub async fn remove_mail_id(&self, attachment_id: &str, mail_id: &str) -> AppResult<()> {
        self.db
            .remove_mail_id_from_attachment_meta(attachment_id, mail_id)
            .await
    }

    /// Register a mail_id reference on attachment metadata for cleanup cascade.
    pub async fn add_mail_id(&self, attachment_id: &str, mail_id: &str) -> AppResult<()> {
        self.db
            .add_mail_id_to_attachment_meta(attachment_id, mail_id)
            .await
    }

    // ── File I/O operations ───────────────────────────────────────────

    /// Compute file path for an attachment: `{attach_dir}/{sender_hash16}/{id}.{ext}`.
    pub fn file_path(&self, sender_email: &str, attachment_id: &str, ext: &str) -> PathBuf {
        let hash = Sha256::digest(sender_email.as_bytes());
        let hash_hex = hex::encode(hash);
        let sender_dir = &hash_hex[..16];

        self.attachments_dir
            .join(sender_dir)
            .join(format!("{}.{}", attachment_id, ext))
    }

    /// Save attachment to disk: validate → write file → create metadata → grant permission.
    pub async fn save_attachment(
        &self,
        config: &StorageConfig,
        sender_email: &str,
        attachment_id: &str,
        filename: &str,
        content_type: &str,
        content: &[u8],
        mail_id: &str,
        recipient_email: &str,
    ) -> AppResult<AttachmentMetaRecord> {
        // Validate size
        if !Self::is_size_allowed(config, content.len()) {
            return Err(AppError::Validation(format!(
                "attachment {} exceeds max size {} bytes (actual: {})",
                filename,
                config.attachment_max_size,
                content.len()
            )));
        }

        // Validate content type
        if !Self::is_content_type_allowed(config, content_type) {
            return Err(AppError::Validation(format!(
                "attachment content type {} is not allowed",
                content_type
            )));
        }

        // Extract extension — uses Path::extension() to match load side
        let ext = std::path::Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin");

        // Build file path
        let file_path = self.file_path(sender_email, attachment_id, ext);

        // Create directory
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(format!("failed to create attachment directory: {}", e))
            })?;
        }

        // Write file asynchronously
        tokio::fs::write(&file_path, content).await.map_err(|e| {
            AppError::Internal(format!("failed to write attachment {}: {}", filename, e))
        })?;

        // Create metadata
        let meta = self
            .db
            .insert_attachment_meta(
                attachment_id,
                filename,
                Some(content_type),
                sender_email,
                Some(&[mail_id.to_string()]),
            )
            .await?;

        // Grant permission
        self.db
            .insert_attachment_permission(attachment_id, recipient_email)
            .await?;

        Ok(meta)
    }

    /// Load attachment content from disk.
    pub async fn load_attachment(file_path: &Path) -> AppResult<Vec<u8>> {
        tokio::fs::read(file_path)
            .await
            .map_err(|e| AppError::Internal(format!("failed to read attachment: {}", e)))
    }

    /// Open an attachment file for streaming download.
    pub async fn open_attachment(file_path: &Path) -> AppResult<tokio::fs::File> {
        tokio::fs::File::open(file_path)
            .await
            .map_err(|e| AppError::Internal(format!("failed to open attachment: {}", e)))
    }

    /// Delete attachment file from disk.
    pub async fn delete_attachment(file_path: &Path) -> AppResult<()> {
        tokio::fs::remove_file(file_path)
            .await
            .map_err(|e| AppError::Internal(format!("failed to delete attachment: {}", e)))?;
        Ok(())
    }

    /// Check if a user has download permission for an attachment.
    pub async fn check_permission(&self, attachment_id: &str, user_email: &str) -> AppResult<bool> {
        let perms = self.list_permissions(attachment_id).await?;
        Ok(perms.iter().any(|p| p.user_email == user_email))
    }

    /// Consume a one-time download: check permission, then revoke it.
    pub async fn consume_download(&self, attachment_id: &str, user_email: &str) -> AppResult<()> {
        let has = self.check_permission(attachment_id, user_email).await?;
        if !has {
            return Err(AppError::Forbidden(format!(
                "user {} does not have permission to download attachment {}",
                user_email, attachment_id
            )));
        }
        self.revoke_permission(attachment_id, user_email).await
    }

    // ── Attachment config helpers ─────────────────────────────────────

    /// Check if the content type is allowed by the config.
    /// Supports wildcard patterns like "image/*" (matches "image/png", etc.).
    pub fn is_content_type_allowed(config: &StorageConfig, content_type: &str) -> bool {
        if config.attachment_allowed_types.is_empty() {
            true
        } else {
            config
                .attachment_allowed_types
                .iter()
                .any(|t| Self::wildcard_type_match(t, content_type))
        }
    }

    /// Match a content type pattern against an actual content type.
    /// "image/*" matches "image/png", exact match otherwise.
    fn wildcard_type_match(pattern: &str, content_type: &str) -> bool {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 1];
            content_type.starts_with(prefix)
        } else {
            pattern == content_type
        }
    }

    /// Check if the attachment size is within the limit.
    pub fn is_size_allowed(config: &StorageConfig, size: usize) -> bool {
        size <= config.attachment_max_size
    }
}
