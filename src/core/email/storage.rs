//! Email-related database tables: emails, attachment_permissions, attachments_meta.
//! All DB methods are async, wrapping pool operations in `tokio::task::spawn_blocking`.

use rusqlite::{params, OptionalExtension};

use crate::core::errors::AppResult;
use crate::core::storage::Database;

#[derive(Debug, Clone)]
pub struct AttachmentPermissionRecord {
    pub id: i64,
    pub attachment_id: String,
    pub user_email: String,
    pub created_at: String,
}

fn attachment_permission_row(r: &rusqlite::Row) -> rusqlite::Result<AttachmentPermissionRecord> {
    Ok(AttachmentPermissionRecord {
        id: r.get(0)?,
        attachment_id: r.get(1)?,
        user_email: r.get(2)?,
        created_at: r.get(3)?,
    })
}

/// Record returned by attachments_meta CRUD helpers.
#[derive(Debug, Clone)]
pub struct AttachmentMetaRecord {
    pub id: String,
    pub filename: String,
    pub content_type: Option<String>,
    pub sender_email: String,
    pub mail_id: Option<Vec<String>>,
    pub created_at: String,
}

fn attachment_meta_row(r: &rusqlite::Row) -> rusqlite::Result<AttachmentMetaRecord> {
    Ok(AttachmentMetaRecord {
        id: r.get(0)?,
        filename: r.get(1)?,
        content_type: r.get(2)?,
        sender_email: r.get(3)?,
        mail_id: {
            let raw: Option<String> = r.get(4)?;
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        created_at: r.get(5)?,
    })
}

impl Database {
    pub async fn insert_attachment_permission(
        &self,
        attachment_id: &str,
        user_email: &str,
    ) -> AppResult<AttachmentPermissionRecord> {
        let (attachment_id, user_email) = (attachment_id.to_string(), user_email.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO attachment_permissions (attachment_id, user_email, created_at) VALUES (?1, ?2, ?3)",
                params![attachment_id, user_email, now],
            )?;
            let id = conn.last_insert_rowid();
            Ok(AttachmentPermissionRecord {
                id, attachment_id, user_email, created_at: now,
            })
        }).await
    }

    pub async fn list_attachment_permissions(
        &self,
        attachment_id: &str,
    ) -> AppResult<Vec<AttachmentPermissionRecord>> {
        let attachment_id = attachment_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, attachment_id, user_email, created_at FROM attachment_permissions WHERE attachment_id = ?1",
            )?;
            let rows = stmt.query_map(params![attachment_id], attachment_permission_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn delete_attachment_permission(&self, id: i64) -> AppResult<()> {
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM attachment_permissions WHERE id = ?1",
                params![id],
            )?;
            Ok(())
        })
        .await
    }

    /// P3: Delete a specific user's permission on an attachment (by compound key).
    pub async fn delete_attachment_permission_by_user(
        &self,
        attachment_id: &str,
        user_email: &str,
    ) -> AppResult<()> {
        let (attachment_id, user_email) = (attachment_id.to_string(), user_email.to_string());
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM attachment_permissions WHERE attachment_id = ?1 AND user_email = ?2",
                params![attachment_id, user_email],
            )?;
            Ok(())
        })
        .await
    }

    /// P3: Delete all permissions for a given attachment (bulk cleanup).
    pub async fn delete_attachment_permissions_by_attachment_id(
        &self,
        attachment_id: &str,
    ) -> AppResult<()> {
        let attachment_id = attachment_id.to_string();
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM attachment_permissions WHERE attachment_id = ?1",
                params![attachment_id],
            )?;
            Ok(())
        })
        .await
    }

    /// P3: Count remaining permissions for an attachment (used in download-permission cleanup flow).
    pub async fn count_attachment_permissions(&self, attachment_id: &str) -> AppResult<i64> {
        let attachment_id = attachment_id.to_string();
        self.call(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM attachment_permissions WHERE attachment_id = ?1",
                params![attachment_id],
                |r| r.get(0),
            )?;
            Ok(count)
        })
        .await
    }

    // ── Attachment Metadata helpers ──────────────────────────────────

    /// Insert attachment metadata after writing file to disk.
    /// `mail_id` is stored as a JSON array string.
    pub async fn insert_attachment_meta(
        &self,
        id: &str,
        filename: &str,
        content_type: Option<&str>,
        sender_email: &str,
        mail_id: Option<&[String]>,
    ) -> AppResult<AttachmentMetaRecord> {
        let (id, filename, sender_email) = (
            id.to_string(),
            filename.to_string(),
            sender_email.to_string(),
        );
        let (content_type,) = (content_type.map(String::from),);
        let mail_id_json = mail_id.map(|ids| serde_json::to_string(ids).unwrap_or_default());
        let mail_id_vec = mail_id.map(|ids| ids.to_vec());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO attachments_meta (id, filename, content_type, sender_email, mail_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, filename, content_type, sender_email, mail_id_json, now],
            )?;
            Ok(AttachmentMetaRecord {
                id, filename, content_type, sender_email, mail_id: mail_id_vec, created_at: now,
            })
        }).await
    }

    /// Look up a single attachment by ID.
    pub async fn get_attachment_meta(&self, id: &str) -> AppResult<Option<AttachmentMetaRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, filename, content_type, sender_email, mail_id, created_at FROM attachments_meta WHERE id = ?1",
                params![id],
                attachment_meta_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Batch lookup: fetch multiple attachments in a single DB call.
    /// Uses `WHERE id IN (...)` with one spawn_blocking instead of N.
    pub async fn get_attachment_meta_batch(
        &self,
        ids: &[String],
    ) -> AppResult<Vec<AttachmentMetaRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // Build dynamic IN (...) clause; parameter count is bounded by caller
        let placeholders: Vec<String> = ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
        let sql = format!(
            "SELECT id, filename, content_type, sender_email, mail_id, created_at FROM attachments_meta WHERE id IN ({})",
            placeholders.join(", ")
        );
        let ids = ids.to_vec();
        self.call(move |conn| {
            let params: Vec<&dyn rusqlite::types::ToSql> = ids.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params.as_slice(), attachment_meta_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        }).await
    }

    /// List attachments associated with a given mail_id.
    /// Uses json_each for exact match inside the JSON array stored in mail_id column.
    pub async fn get_attachments_by_mail_id(
        &self,
        mail_id: &str,
    ) -> AppResult<Vec<AttachmentMetaRecord>> {
        let mail_id = mail_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, filename, content_type, sender_email, mail_id, created_at \
                 FROM attachments_meta \
                 WHERE EXISTS (SELECT 1 FROM json_each(mail_id) WHERE value = ?1)",
            )?;
            let rows = stmt.query_map(params![mail_id], attachment_meta_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await
    }

    /// Find attachments older than `before` (RFC3339)-limited to `limit` rows for batch processing.
    pub async fn get_attachments_expired_before(
        &self,
        before: &str,
        limit: i64,
    ) -> AppResult<Vec<AttachmentMetaRecord>> {
        let before = before.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, filename, content_type, sender_email, mail_id, created_at FROM attachments_meta WHERE created_at < ?1 ORDER BY created_at ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![before, limit], attachment_meta_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Delete attachment metadata (after file is removed from disk).
    pub async fn delete_attachment_meta_v2(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        self.call(move |conn| {
            conn.execute("DELETE FROM attachments_meta WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }
}

/// Structured recipients with to/cc/rcpt distinction.
///
/// - `to` / `cc`: the complete post-filter recipient list (union of the
///   external and internal directions). This is what final recipients should
///   see in the To/Cc headers; both direction records carry identical values.
/// - `rcpt`: the addresses this specific record actually delivers to
///   (outbound record → MX targets; inbound internal record → webhook
///   targets). Board addresses may appear in to/cc without being in rcpt,
///   since they are not final delivery targets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Recipients {
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rcpt: Vec<String>,
}

impl Recipients {
    /// Full recipient list (to + cc) — display/metadata semantics.
    pub fn all(&self) -> impl Iterator<Item = &str> {
        self.to.iter().chain(self.cc.iter()).map(|s| s.as_str())
    }

    /// Actual delivery targets of this record: `rcpt` when present,
    /// falling back to to + cc for records written before `rcpt` existed.
    pub fn delivery(&self) -> Box<dyn Iterator<Item = &str> + Send + '_> {
        if self.rcpt.is_empty() {
            Box::new(self.to.iter().chain(self.cc.iter()).map(|s| s.as_str()))
        } else {
            Box::new(self.rcpt.iter().map(|s| s.as_str()))
        }
    }

    /// Parse from a JSON string stored in the emails.recipients column.
    /// Format: `{"to":[...],"cc":[...],"rcpt":[...]}` (cc/rcpt optional).
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str::<Recipients>(json)
            .unwrap_or_else(|_| Recipients {
                to: vec![json.to_string()],
                cc: vec![],
                rcpt: vec![],
            })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct EmailRecord {
    pub id: String,
    pub status: String,
    pub system_id: String,
    pub direction: String,
    pub sender: String,
    pub recipients: String,
    pub endpoints: Option<String>,
    pub subject: String,
    pub body: String,
    pub headers: Option<String>,
    pub attachments: Option<String>,
    pub send_count: i32,
    pub last_sent_at: String,
    pub next_retry_at: Option<String>,
    pub max_attempts: i32,
    pub created_at: String,
    pub sender_signature: Option<String>,
}

fn email_row(r: &rusqlite::Row) -> rusqlite::Result<EmailRecord> {
    Ok(EmailRecord {
        id: r.get(0)?,
        status: r.get(1)?,
        system_id: r.get(2)?,
        direction: r.get(3)?,
        sender: r.get(4)?,
        recipients: r.get(5)?,
        endpoints: r.get(6)?,
        subject: r.get(7)?,
        body: r.get(8)?,
        headers: r.get(9)?,
        attachments: r.get(10)?,
        send_count: r.get(11)?,
        last_sent_at: r.get(12)?,
        next_retry_at: r.get(13)?,
        max_attempts: r.get(14)?,
        created_at: r.get(15)?,
        sender_signature: r.get(16)?,
    })
}

const EMAIL_SELECT: &str =
    "SELECT id, status, system_id, direction, sender, recipients, endpoints, subject, body, headers, attachments, send_count, last_sent_at, next_retry_at, max_attempts, created_at, sender_signature FROM emails";

impl Database {
    pub async fn insert_email(
        &self,
        id: &str,
        system_id: &str,
        direction: &str,
        sender: &str,
        recipients: &str,
        subject: &str,
        body: &str,
        endpoints: Option<&str>,
        attachments: Option<&str>,
        headers: Option<&str>,
        max_attempts: i32,
    ) -> AppResult<EmailRecord> {
        let (id, system_id, direction, sender, recipients) = (
            id.to_string(),
            system_id.to_string(),
            direction.to_string(),
            sender.to_string(),
            recipients.to_string(),
        );
        let subject_owned = subject.to_string();
        let body_owned = body.to_string();
        let endpoints_owned = endpoints.map(String::from);
        let attachments_owned = attachments.map(String::from);
        let headers_owned = headers.map(String::from);
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO emails (id, status, system_id, direction, sender, recipients, endpoints, subject, body, headers, attachments, send_count, max_attempts, last_sent_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14)",
                // Every email is born 'readying' (preparing). The trigger path
                // claims it readying→sending for first delivery; the tick never
                // sees 'readying', so a half-prepared payload can never be
                // delivered early. Crash recovery (batch Flow 0) flips
                // complete 'readying' rows to 'ready' or discards partial ones.
                params![id, "readying", system_id, direction, sender, recipients, endpoints_owned, subject_owned, body_owned, headers_owned, attachments_owned, max_attempts, now.clone(), now],
            )?;
            Ok(EmailRecord {
                id, status: "readying".into(), system_id, direction, sender, recipients, subject: subject_owned,
                endpoints: endpoints_owned, body: body_owned, headers: headers_owned, attachments: attachments_owned,
                send_count: 0, last_sent_at: now.clone(), next_retry_at: None, max_attempts,
                created_at: now,
                sender_signature: None,
            })
        }).await
    }

    pub async fn get_email(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let row = conn
                .query_row(
                    &format!("{} WHERE id = ?1", EMAIL_SELECT),
                    params![id],
                    email_row,
                )
                .optional()?;
            Ok(row)
        })
        .await
    }

    /// CAS (Compare-And-Swap) claim: atomically transition status
    /// `readying`/`ready` → `sending`.
    /// Returns `Some(record)` if the claim succeeded, `None` if already consumed by another path.
    /// This prevents concurrent delivery from trigger + interval batch.
    ///
    /// State machine:
    /// - `readying` — preparing (born state; only the first-delivery trigger may claim it)
    /// - `ready`    — payload-complete and retryable (only the tick may claim it;
    ///                first-delivery emails are claimed from `readying` via trigger)
    /// - `sending`  — in flight
    pub async fn claim_ready(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        let id = id.to_string();
        self.call_tx(move |tx| {
            // Atomic CAS: update only if current status is 'readying' or 'ready'
            // Wrapped in a transaction so UPDATE + SELECT are atomic —
            // prevents orphaned 'sending' state if SELECT fails.
            let rows = tx.execute(
                "UPDATE emails SET status = 'sending', last_sent_at = (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) WHERE id = ?1 AND status IN ('readying', 'ready')",
                params![id],
            )?;
            if rows == 0 {
                return Ok(None);
            }
            // Read the updated record within the same transaction
            let result = tx.query_row(
                &format!("{} WHERE id = ?1", EMAIL_SELECT),
                params![id],
                email_row,
            ).optional()?;
            Ok(result)
        }).await
    }

    pub async fn list_emails_by_system(
        &self,
        system_id: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "{} WHERE system_id = ?1 ORDER BY created_at DESC LIMIT ?2",
                EMAIL_SELECT
            ))?;
            let rows = stmt.query_map(params![system_id, limit], email_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await
    }

    pub async fn list_emails_by_status(
        &self,
        status: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        let status = status.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "{} WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2",
                EMAIL_SELECT
            ))?;
            let rows = stmt.query_map(params![status, limit], email_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await
    }

    pub async fn count_emails_by_status(&self, status: &str) -> AppResult<i64> {
        let status = status.to_string();
        self.call(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM emails WHERE status = ?1",
                params![status],
                |r| r.get(0),
            )?;
            Ok(count)
        })
        .await
    }

    /// Count emails awaiting delivery: `ready` (retryable) + `readying`
    /// (preparing, about to be trigger-delivered). Drives the pending gauge
    /// so in-preparation emails aren't invisible while their trigger is in flight.
    pub async fn count_pending_emails(&self) -> AppResult<i64> {
        self.call(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM emails WHERE status IN ('ready', 'readying')",
                params![],
                |r| r.get(0),
            )?;
            Ok(count)
        })
        .await
    }

    /// Find emails by sender address and direction (for NDR bounce correlation).
    pub async fn find_emails_by_sender_direction(
        &self,
        sender: &str,
        direction: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        let (sender, direction) = (sender.to_string(), direction.to_string());
        self.call(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "{} WHERE sender = ?1 AND direction = ?2 ORDER BY created_at DESC LIMIT ?3",
                EMAIL_SELECT
            ))?;
            let rows = stmt.query_map(params![sender, direction, limit], email_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await
    }

    pub async fn count_emails_by_system(&self, system_id: &str) -> AppResult<i64> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM emails WHERE system_id = ?1",
                params![system_id],
                |r| r.get(0),
            )?;
            Ok(count)
        })
        .await
    }

    /// Fetch `readying` emails older than `cutoff` (RFC3339).
    /// These are crash orphans: the process died between insert and trigger
    /// claim (or the trigger was dropped by a full channel). Flow 0 sweeps
    /// them: complete ones flip to `ready` (or are trigger-delivered),
    /// partially-prepared ones are discarded.
    pub async fn get_stuck_readying_emails(
        &self,
        cutoff: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        let cutoff = cutoff.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "{} WHERE status = 'readying' AND created_at < ?1 ORDER BY created_at ASC LIMIT ?2",
                EMAIL_SELECT
            ))?;
            let rows = stmt.query_map(params![cutoff, limit], email_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// CAS flip `readying` → `ready` (crash recovery: payload verified complete).
    /// Returns true if this call performed the flip, false if the row is no
    /// longer `readying` (e.g. a trigger claimed it in the meantime).
    pub async fn flip_readying_to_ready(&self, id: &str) -> AppResult<bool> {
        let id = id.to_string();
        self.call(move |conn| {
            let rows = conn.execute(
                "UPDATE emails SET status = 'ready' WHERE id = ?1 AND status = 'readying'",
                params![id],
            )?;
            Ok(rows > 0)
        }).await
    }

    // ── Scheduler v1.0: periodic inspection queries ──────────────────

    /// Fetch emails ready for delivery: status='ready', send_count < max_attempts,
    /// (next_retry_at IS NULL OR next_retry_at <= now).
    pub async fn get_pending_retry_emails(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                // Compare next_retry_at at second-level granularity.
                // next_retry_at is stored as RFC 3339 with milliseconds (e.g. "2026-07-23T10:00:00.123Z").
                // strftime('%Y-%m-%dT%H:%M:%SZ', 'now') truncates to seconds, and 'Z' > '.'
                // in ASCII, so "2026-07-23T10:00:00Z" > "2026-07-23T10:00:00.999Z" — misses retries.
                // Fix: append '.999Z' to include all milliseconds within the current second.
                &format!("{} WHERE status = 'ready' AND send_count < max_attempts AND (next_retry_at IS NULL OR next_retry_at <= strftime('%Y-%m-%dT%H:%M:%S.', 'now') || '999Z') ORDER BY next_retry_at ASC LIMIT ?1", EMAIL_SELECT),
            )?;
            let rows = stmt.query_map(params![limit], email_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Fetch over-limit emails: status='ready', send_count >= max_attempts.
    pub async fn get_overlimit_emails(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                &format!("{} WHERE status = 'ready' AND send_count >= max_attempts ORDER BY last_sent_at ASC LIMIT ?1", EMAIL_SELECT),
            )?;
            let rows = stmt.query_map(params![limit], email_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Mark email as ready for next retry (after failed delivery attempt).
    pub async fn update_email_ready_retry(
        &self,
        id: &str,
        send_count: i32,
        next_retry_at: &str,
    ) -> AppResult<Option<EmailRecord>> {
        let id = id.to_string();
        let next_retry_at = next_retry_at.to_string();
        self.call(move |conn| {
            let current = conn.query_row(
                &format!("{} WHERE id = ?1", EMAIL_SELECT),
                params![id],
                email_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            record.status = "ready".into();
            record.send_count = send_count;
            record.next_retry_at = Some(next_retry_at.clone());
            record.last_sent_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            conn.execute(
                "UPDATE emails SET status = 'ready', send_count = ?1, next_retry_at = ?2, last_sent_at = ?3 WHERE id = ?4",
                params![send_count, next_retry_at, record.last_sent_at, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    /// Update only send_count without changing status.
    /// Used by exhaustion paths to record the final attempt before marking completed.
    pub async fn update_email_send_count(
        &self,
        id: &str,
        send_count: i32,
    ) -> AppResult<()> {
        let id = id.to_string();
        self.call(move |conn| {
            conn.execute(
                "UPDATE emails SET send_count = ?1 WHERE id = ?2",
                params![send_count, id],
            )?;
            Ok(())
        })
        .await
    }

    /// Mark email as successfully completed.
    pub async fn update_email_completed(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let current = conn
                .query_row(
                    &format!("{} WHERE id = ?1", EMAIL_SELECT),
                    params![id],
                    email_row,
                )
                .optional()?;
            let mut record = match current {
                Some(r) => r,
                None => return Ok(None),
            };
            record.status = "completed".into();
            record.last_sent_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            conn.execute(
                "UPDATE emails SET status = 'completed', last_sent_at = ?1 WHERE id = ?2",
                params![record.last_sent_at, record.id],
            )?;
            Ok(Some(record))
        })
        .await
    }

    /// Mark an email as delivered (MX accepted, waiting for NDR window).
    pub async fn update_email_delivered(&self, id: &str) -> AppResult<Option<EmailRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let current = conn
                .query_row(
                    &format!("{} WHERE id = ?1", EMAIL_SELECT),
                    params![id],
                    email_row,
                )
                .optional()?;
            let mut record = match current {
                Some(r) => r,
                None => return Ok(None),
            };
            record.status = "delivered".into();
            record.last_sent_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            conn.execute(
                "UPDATE emails SET status = 'delivered', last_sent_at = ?1 WHERE id = ?2",
                params![record.last_sent_at, record.id],
            )?;
            Ok(Some(record))
        })
        .await
    }

    /// Fetch delivered emails whose last_sent_at is before the cutoff.
    /// Used by the scheduler to finalize emails past the NDR window.
    pub async fn get_delivered_expired_before(
        &self,
        cutoff: &str,
        limit: i32,
    ) -> AppResult<Vec<EmailRecord>> {
        let (cutoff, limit) = (cutoff.to_string(), limit);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                &format!("{} WHERE status = 'delivered' AND last_sent_at < ?1 ORDER BY last_sent_at ASC LIMIT ?2", EMAIL_SELECT),
            )?;
            let rows = stmt.query_map(params![cutoff, limit], email_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Parse the attachments JSON string from an email record to get attachment IDs.
    pub async fn get_email_attachment_ids(&self, id: &str) -> AppResult<Vec<String>> {
        let id = id.to_string();
        self.call(move |conn| {
            let attachments_json: Option<String> = conn
                .query_row(
                    "SELECT attachments FROM emails WHERE id = ?1",
                    params![id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            match &attachments_json {
                Some(json_str) => {
                    let ids: Vec<String> = serde_json::from_str(json_str).unwrap_or_default();
                    Ok(ids)
                }
                None => Ok(Vec::new()),
            }
        })
        .await
    }

    /// Check if the sender's domain belongs to a registered system domain (internal sender).
    pub async fn is_internal_sender(&self, sender: &str) -> AppResult<bool> {
        // Extract domain from email: "user@example.com" → "example.com"
        let domain = sender.rsplit('@').next().unwrap_or("");
        if domain.is_empty() {
            return Ok(false);
        }
        let domain = domain.to_string();
        self.call(move |conn| {
            let row: Option<String> = conn.query_row(
                "SELECT id FROM system_domains WHERE domain_addr = ?1 AND is_active = 1 LIMIT 1",
                params![domain],
                |r| r.get(0),
            ).optional()?;
            Ok(row.is_some())
        })
        .await
    }

    /// Count mail_ids in attachment_meta for an attachment (check if other emails still reference it).
    pub async fn count_attachment_mail_ids(&self, attachment_id: &str) -> AppResult<i64> {
        let attachment_id = attachment_id.to_string();
        self.call(move |conn| {
            let mail_id_json: Option<String> = conn
                .query_row(
                    "SELECT mail_id FROM attachments_meta WHERE id = ?1",
                    params![attachment_id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            match &mail_id_json {
                Some(json_str) => {
                    let ids: Vec<String> = serde_json::from_str(json_str).unwrap_or_default();
                    Ok(ids.len() as i64)
                }
                None => Ok(0),
            }
        })
        .await
    }

    /// Add a mail_id to the JSON array in attachments_meta.
    /// If the mail_id already exists, it is not duplicated.
    pub async fn add_mail_id_to_attachment_meta(
        &self,
        attachment_id: &str,
        mail_id: &str,
    ) -> AppResult<()> {
        let attachment_id = attachment_id.to_string();
        let mail_id = mail_id.to_string();
        self.call(move |conn| {
            let current_json: Option<String> = conn
                .query_row(
                    "SELECT mail_id FROM attachments_meta WHERE id = ?1",
                    params![attachment_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();

            let mut ids: Vec<String> = match current_json {
                Some(ref json_str) if !json_str.is_empty() => {
                    serde_json::from_str(json_str).unwrap_or_default()
                }
                _ => Vec::new(),
            };

            if !ids.contains(&mail_id) {
                ids.push(mail_id);
                let new_json = serde_json::to_string(&ids).unwrap_or_default();
                conn.execute(
                    "UPDATE attachments_meta SET mail_id = ?1 WHERE id = ?2",
                    params![new_json, attachment_id],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// Remove a single mail_id from the JSON array in attachments_meta.
    pub async fn remove_mail_id_from_attachment_meta(
        &self,
        attachment_id: &str,
        mail_id: &str,
    ) -> AppResult<()> {
        let attachment_id = attachment_id.to_string();
        let mail_id = mail_id.to_string();
        self.call(move |conn| {
            let current_json: Option<String> = conn
                .query_row(
                    "SELECT mail_id FROM attachments_meta WHERE id = ?1",
                    params![attachment_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();

            match current_json {
                Some(ref json_str) if !json_str.is_empty() => {
                    let mut ids: Vec<String> = serde_json::from_str(json_str).unwrap_or_default();
                    ids.retain(|id| id != &mail_id);
                    let new_json = serde_json::to_string(&ids).unwrap_or_default();
                    if ids.is_empty() {
                        conn.execute(
                            "UPDATE attachments_meta SET mail_id = NULL WHERE id = ?1",
                            params![attachment_id],
                        )?;
                    } else {
                        conn.execute(
                            "UPDATE attachments_meta SET mail_id = ?1 WHERE id = ?2",
                            params![new_json, attachment_id],
                        )?;
                    }
                }
                _ => { /* no mail_ids to remove */ }
            }
            Ok(())
        })
        .await
    }
}

impl Database {
    // ── Scheduler / worker methods ───────────────────────────────────

    pub async fn delete_email(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        self.call(move |conn| {
            conn.execute("DELETE FROM emails WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }

    // ── List all emails (no filter) ──────────────────────────────────

    pub async fn list_emails(&self, limit: i32) -> AppResult<Vec<EmailRecord>> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "{} ORDER BY created_at DESC LIMIT ?1",
                EMAIL_SELECT
            ))?;
            let rows = stmt.query_map(params![limit], email_row)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await
    }

    // ── Endpoint status helpers ──────────────────────────────────────

    /// Atomically update a single endpoint's status within the `endpoints` JSON.
    /// Returns `true` on success, `false` if endpoint not found or email doesn't exist.
    ///
    /// `COALESCE(endpoints, '{}')` is required: emails delivered to pull-mode
    /// (bridge) domains have no pre-built endpoint key, so `endpoints` is NULL
    /// at insert time. SQLite `json_set(NULL, ...)` returns NULL — the success
    /// mark would be lost, `check_all_endpoints_completed` would report
    /// "not completed", and the scheduler would treat the successful delivery
    /// as a failure and retry to `max_attempts`, re-inserting a pending
    /// delivery on every pass (the 3x delivery storm).
    pub async fn update_email_endpoint_status(
        &self,
        email_id: &str,
        domain: &str,
        new_status: &str,
    ) -> AppResult<bool> {
        let (email_id, domain, new_status) = (
            email_id.to_string(),
            domain.to_string(),
            new_status.to_string(),
        );
        self.call(move |conn| {
            let changes = conn.execute(
                "UPDATE emails SET endpoints = json_set(COALESCE(endpoints, '{}'), '$.\"' || ?2 || '\".status', ?3) WHERE id = ?1",
                params![email_id, domain, new_status],
            )?;
            let updated = changes == 1;
            if updated {
                tracing::debug!(
                    operation="endpoint_status_updated",
                    email_id = %email_id,
                    domain = %domain,
                    new_status = %new_status,
                    "Updated endpoint status"
                );
            } else {
                tracing::warn!(
                    operation="endpoint_status_no_match",
                    email_id = %email_id,
                    domain = %domain,
                    new_status = %new_status,
                    "Endpoint status update did not match any row (endpoint missing or email not found)"
                );
            }
            Ok(updated)
        }).await
    }

    /// Check whether every endpoint in the email has status `"success"`.
    /// Returns `true` when all are completed, `false` otherwise.
    pub async fn check_all_endpoints_completed(&self, email_id: &str) -> AppResult<bool> {
        let email_id = email_id.to_string();
        self.call(move |conn| {
            let all_completed: Option<bool> = conn
                .query_row(
                    "SELECT CASE WHEN endpoints IS NULL OR endpoints = '{}' THEN 0 WHEN NOT EXISTS (SELECT 1 FROM json_each(endpoints) WHERE json_extract(value, '$.status') != 'success') THEN 1 ELSE 0 END as all_completed FROM emails WHERE id = ?1",
                    params![email_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();

            match all_completed {
                Some(true) => {
                    tracing::debug!(operation="endpoints_all_completed", email_id = %email_id, "All endpoints completed successfully");
                    Ok(true)
                }
                Some(false) | None => {
                    tracing::debug!(email_id = %email_id, "Not all endpoints completed (or email not found)");
                    Ok(false)
                }
            }
        }).await
    }

    /// Atomically update both cleaned body and sender_signature cache.
    pub async fn update_email_body_and_signature(
        &self,
        id: &str,
        body: &str,
        signature: &str,
    ) -> AppResult<()> {
        let (id, body, signature) = (id.to_string(), body.to_string(), signature.to_string());
        self.call(move |conn| {
            conn.execute(
                "UPDATE emails SET body = ?1, sender_signature = ?2 WHERE id = ?3",
                params![body, signature, id],
            )?;
            Ok(())
        })
        .await
    }

    /// Update the attachments JSON for an email after attachments have been saved.
    pub async fn update_email_attachments(&self, id: &str, attachments: &str) -> AppResult<()> {
        let (id, attachments) = (id.to_string(), attachments.to_string());
        self.call(move |conn| {
            conn.execute(
                "UPDATE emails SET attachments = ?1 WHERE id = ?2",
                params![attachments, id],
            )?;
            Ok(())
        })
        .await
    }
}
