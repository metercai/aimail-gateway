//! Shared HTTP state and request/response types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::MailFactories;
use crate::core::storage::{ApiKeyRecord, SystemDomainRecord, SystemRecord, WhitelistRecord};
use crate::core::strategy::ExtensionProviders;

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    pub factories: MailFactories,
    pub metrics: Arc<Metrics>,
    pub config: Config,
    pub trigger_tx: mpsc::Sender<String>,
    pub extensions: Arc<ExtensionProviders>,
}

// ── Request/Response types ──

/// Request body for creating an API key.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub system_id: String,
    pub email_address: String,
    /// Scope(s) granted to this key. Single string treated as a one-element collection.
    #[serde(default = "default_scope")]
    pub scopes: Vec<String>,
    /// Optional ISO-8601 expiration timestamp.
    pub expires_at: Option<String>,
    /// Category of the key: "platform", "system", or "agent". Defaults to "system".
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_scope() -> Vec<String> {
    vec!["agent".to_string()]
}

fn default_category() -> String {
    "system".to_string()
}

/// Request body for updating an API key.
#[derive(Debug, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub scopes: Option<Vec<String>>,
    pub is_active: Option<bool>,
    pub expires_at: Option<String>,
    /// If true, rotate the key (generate new hash). Agent-only operation.
    pub rotate: Option<bool>,
}

/// Response for an API key.
/// `raw_key` is only populated on creation; subsequent reads return `null`.
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: i64,
    pub system_id: String,
    pub email_address: String,
    pub key_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_key: Option<String>,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub category: String,
}

/// Reference to an uploaded attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
}

/// Request body for POST /api/v1/send.
#[derive(Debug, Deserialize)]
pub struct SendEmailRequest {
    /// Sender address — must exactly match the API key's email_address.
    pub sender: Option<String>,
    /// Primary recipient(s), comma-separated or single address.
    pub to: String,
    /// Optional CC recipients.
    pub cc: Option<Vec<String>>,
    /// Optional email subject.
    pub subject: Option<String>,
    /// Markdown content — will be converted to HTML for MIME delivery.
    pub markdown: String,
    /// Optional attachment references from prior uploads.
    pub attachments: Option<Vec<AttachmentRef>>,
    /// Optional custom headers to include in the outbound email.
    pub headers: Option<HashMap<String, String>>,
}

/// Response for a successful send request.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendEmailResponse {
    pub email_id: String,
    pub status: String,
}

/// Generic error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub detail: Option<String>,
}

/// Owner information for health check endpoint.
#[derive(Debug, Serialize)]
pub struct OwnerResponse {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Response returned after a successful attachment upload.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadAttachmentResponse {
    pub attachment_id: String,
    pub filename: String,
    pub content_type: String,
}

// ── System management types ──

#[derive(Debug, Deserialize)]
pub struct CreateSystemRequest {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemRequest {
    pub admin_email: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SystemResponse {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,
    pub is_active: bool,
    pub created_at: String,
}

// ── System domain management types ──

#[derive(Debug, Deserialize)]
pub struct CreateSystemDomainRequest {
    pub id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAddressRequest {
    pub id: String,
    pub email: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub manager_address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemDomainRequest {
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub is_active: Option<bool>,
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemDomainResponse {
    pub id: String,
    pub system_id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub manager_address: String,
    pub agent_signature: String,
    pub agent_persona: String,
}

// ── Whitelist management types ──

#[derive(Debug, Deserialize)]
pub struct CreateWhitelistRequest {
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWhitelistRequest {
    pub is_active: Option<bool>,
    pub direction: Option<String>,
}

/// Request body for PUT /api/v1/admin/agent-meta/:email
#[derive(Debug, Deserialize)]
pub struct UpdateAgentMetaRequest {
    pub manager_address: Option<String>,
    pub agent_signature: Option<String>,
    pub agent_persona: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WhitelistResponse {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub category: String,
}

// ── From conversions ──

impl From<ApiKeyRecord> for ApiKeyResponse {
    fn from(record: ApiKeyRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            email_address: record.email_address,
            key_prefix: record.key_prefix,
            raw_key: None, // never exposed from stored records
            scopes: record.scopes,
            is_active: record.is_active,
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            category: record.category,
        }
    }
}

impl From<SystemRecord> for SystemResponse {
    fn from(record: SystemRecord) -> Self {
        Self {
            id: record.id,
            admin_email: record.admin_email,
            limits_config: record.limits_config,
            is_active: record.is_active,
            created_at: record.created_at,
        }
    }
}

impl From<SystemDomainRecord> for SystemDomainResponse {
    fn from(record: SystemDomainRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            domain: record.domain,
            webhook_url: record.webhook_url,
            is_active: record.is_active,
            created_at: record.created_at,
            manager_address: String::new(),
            agent_signature: String::new(),
            agent_persona: String::new(),
        }
    }
}

impl From<WhitelistRecord> for WhitelistResponse {
    fn from(record: WhitelistRecord) -> Self {
        Self {
            id: record.id,
            system_id: record.system_id,
            domain_addr: record.domain_addr,
            direction: record.direction,
            value: record.value,
            description: record.description,
            is_active: record.is_active,
            created_at: record.created_at,
            category: record.category,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ActivateAddressRequest {
    pub code: String,
    pub email_address: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ActivateAddressResponse {
    pub status: String,
    pub raw_key: String,
    pub email_address: String,
    pub system_id: String,
    pub scopes: Vec<String>,
}

// ── Agent State ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentStatePutRequest {
    pub value: String,
}

// ── Contacts (semantic profile + name index) ──────────────────

#[derive(Debug, Deserialize)]
pub struct ContactProfileRequest {
    pub profile: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactsByNameQuery {
    pub name: String,
}

// ── Thread Summary ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ThreadSummaryRequest {
    pub summary: String,
}

// ── Probe Webhook ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProbeWebhookRequest {
    /// host:port to probe (e.g. "192.168.1.100:38080")
    pub addr: String,
}
