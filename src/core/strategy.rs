// Strategy traits for edition-specific behavior injection.
//
// Advanced edition adds: SPF+PTR, DKIM, MX direct delivery, GCRA rate
// limiting, DB-backed quotas, and extra HTTP routes (/metrics etc).

use crate::core::email::storage::EmailRecord;
use crate::core::errors::AppResult;
use async_trait::async_trait;
use std::sync::Arc;

use crate::board::quota::BoardQuotaChecker;
use crate::core::storage::Database;

// ── MessageSigner ─────────────────────────────────────────────────────

/// Signs outbound email messages.
#[async_trait]
pub trait MessageSigner: Send + Sync {
    /// Produce a signed version of `raw`. Returns `None` when signing is unavailable.
    async fn sign(&self, raw: &[u8], email_id: &str) -> Option<Vec<u8>>;

    /// Sign if configured, otherwise return the input unchanged.
    async fn apply_sign<'a>(&self, raw: &'a [u8], email_id: &str) -> std::borrow::Cow<'a, [u8]> {
        match self.sign(raw, email_id).await {
            Some(signed) => std::borrow::Cow::Owned(signed),
            None => std::borrow::Cow::Borrowed(raw),
        }
    }
}

// ── QuotaChecker ──────────────────────────────────────────────────────

/// Per-system quota checks for emails, domains, and API keys.
#[async_trait]
pub trait QuotaChecker: Send + Sync {
    async fn check_send_quota(&self, system_id: &str) -> Result<(), crate::core::errors::AppError>;
    async fn check_domain_quota(
        &self,
        system_id: &str,
    ) -> Result<(), crate::core::errors::AppError>;
    async fn check_address_quota(&self, system_id: &str) -> Result<(), crate::core::errors::AppError>;
    async fn get_max_attachments(&self, _system_id: &str) -> Option<usize> {
        None
    }
    async fn get_max_attachment_size(&self, _system_id: &str) -> Option<usize> {
        None
    }
}

// ── RouterHook ────────────────────────────────────────────────────────

/// Hooks into router construction to add edition-specific HTTP routes.
pub trait RouterHook: Send + Sync {
    fn mount(&self, router: axum::Router) -> axum::Router;
}

// ── InboundInterceptor ─────────────────────────────────────────────────

/// Intercepts inbound emails BEFORE webhook delivery.
/// Allows edition-specific handling (e.g. a2a_board commands).
pub enum InterceptorDecision {
    /// Email was handled — skip webhook delivery entirely.
    Handled,
    /// Email not handled — continue to next interceptor or webhook.
    PassThrough,
}

#[async_trait]
pub trait InboundInterceptor: Send + Sync {
    /// Interceptor name for logging.
    fn name(&self) -> &str;

    /// Priority (lower runs first). 5=suspend/stranger, 20=a2a.
    /// Manager commands are NOT an interceptor — they run as step 0 in
    /// `process_email_webhook` (webhook.rs) before the chain.
    fn priority(&self) -> u32;

    /// Intercept an inbound email. Return Handled to skip webhook delivery.
    /// The payload is the JSON that would be sent via webhook.
    async fn intercept(
        &self,
        record: &EmailRecord,
        payload: &mut serde_json::Value,
    ) -> InterceptorDecision;
}

// ── SystemStore ───────────────────────────────────────────────────────

/// Resolves a system record by ID.
#[async_trait]
pub trait SystemStore: Send + Sync {
    async fn resolve_system(
        &self,
        id: &str,
    ) -> crate::core::errors::AppResult<Option<crate::core::storage::SystemRecord>>;
}

/// Resolves a sender/receiver address into whitelist lookup keys.
/// Both editions use `ExactKeyResolver` (exact address match).
#[async_trait]
pub trait WhitelistKeyResolver: Send + Sync {
    async fn resolve(&self, db: &Database, addr: &str) -> AppResult<Vec<(String, String)>>;
}

// ── ExtensionProviders ─────────────────────────────────────────────

/// Bundle of edition-specific extension points.
/// Base edition: all fields default to no-op implementations.
/// Advanced edition: each field can be replaced individually.
pub struct ExtensionProviders {
    pub quota_checker: Arc<dyn QuotaChecker>,
    pub dkim_signer: Arc<dyn MessageSigner>,
    pub board_quota: Arc<dyn BoardQuotaChecker>,
}
