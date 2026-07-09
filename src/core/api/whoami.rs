//! Authenticated key identity endpoint.

use axum::{
    extract::{Extension, State},
    response::Json,
};

use crate::core::api::types::HttpState;
use crate::core::scope::Scope;
use crate::core::storage::ApiKeyRecord;

/// GET /api/v1/whoami — Return information about the authenticated API key.
pub async fn whoami(
    Extension(key): Extension<ApiKeyRecord>,
    State(state): State<HttpState>,
) -> Json<serde_json::Value> {
    let scope_name = key
        .scopes
        .first()
        .and_then(|s| Scope::from_str(s).map(|scope| scope.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    // Look up agent metadata from domain_addr_meta (keyed by email_address).
    let (manager_address, agent_signature, agent_persona) = if !key.email_address.is_empty() {
        match state
            .email_factory
            .env_factory
            .resolve_domain_addr_meta(&key.email_address)
            .await
        {
            Ok(Some(meta)) => (
                meta.manager_address,
                meta.agent_signature,
                meta.agent_persona,
            ),
            _ => (String::new(), String::new(), String::new()),
        }
    } else {
        (String::new(), String::new(), String::new())
    };

    Json(serde_json::json!({
        "scope": scope_name,
        "system_id": key.system_id,
        "email": key.email_address,
        "key_prefix": key.key_prefix,
        "category": key.category,
        "manager_address": manager_address,
        "agent_signature": agent_signature,
        "agent_persona": agent_persona,
    }))
}
