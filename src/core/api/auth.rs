//! Authentication middleware and scope guard utilities.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Json, Response},
};

use sha2::{Digest, Sha256};

use crate::core::api::types::ErrorResponse;
use crate::core::factory::EnvFactory;
use crate::core::scope::Scope;
use crate::core::storage::ApiKeyRecord;

// ── AuthLayer Middleware ──

/// Middleware: Verify API key from X-Api-Key header against database.
///
/// Returns 401 if key is missing, invalid, or deactivated.
pub async fn auth_layer(env_factory: EnvFactory, mut req: Request, next: Next) -> Response {
    let api_key = req
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(api_key) = api_key else {
        let err_body = serde_json::to_string(&ErrorResponse {
            error: "Missing X-Api-Key header".to_string(),
            detail: None,
        })
        .unwrap_or_default();
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(err_body))
            .unwrap();
    };

    let key_hash = sha256_hex(&api_key);

    let record = match env_factory.verify_api_key(&key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let err_body = serde_json::to_string(&ErrorResponse {
                error: "Invalid or deactivated API key".to_string(),
                detail: None,
            })
            .unwrap_or_default();
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(err_body))
                .unwrap();
        }
        Err(e) => {
            tracing::error!(%e, "auth_layer: DB error during API key verification");
            let err_body = serde_json::to_string(&ErrorResponse {
                error: "Authentication error".to_string(),
                detail: None,
            })
            .unwrap_or_default();
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(err_body))
                .unwrap();
        }
    };

    // Attach verified key info to request extensions for downstream handlers
    req.extensions_mut().insert(record);

    next.run(req).await
}

/// Scope guard: verify API key has required scope.
pub fn require_scope(
    key: &ApiKeyRecord,
    required_scope: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Map the required string to a Scope
    let required = match required_scope {
        "platform" => Scope::PlatformAdmin,
        "system" => Scope::SystemAdmin,
        "agent_admin" => Scope::AgentAdmin,
        "agent" => Scope::Agent,
        "bridge" => Scope::Bridge,
        _ => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Unknown scope: {}", required_scope),
                    detail: None,
                }),
            ));
        }
    };

    // Check if any of the key's scopes map to the required scope
    let has_scope = key
        .scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == required));

    if !has_scope {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Insufficient scope: {}", required_scope),
                detail: Some(format!(
                    "Key '{}' has scopes: {:?}",
                    key.key_prefix, key.scopes
                )),
            }),
        ));
    }
    Ok(())
}

/// Internal: check API key's domain/address match against target email.
/// Used by `require_domain_match` and `require_agent_match` — logic is identical,
/// only the error message label differs.
fn check_domain_access(
    key: &ApiKeyRecord,
    target: &str,
    role_label: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Admin system bypass — AUDIT-1 P2-1: decided by SCOPE, not by the
    // system_id prefix. Platform/System admin keys may manage any address.
    // ("admin" is the legacy default-system name kept for compatibility.)
    if is_platform_admin_scope(key) || is_system_admin_scope(key) || key.system_id == "admin" {
        return Ok(());
    }
    // System-level key (empty email) — unrestricted
    if key.email_address.is_empty() {
        return Ok(());
    }
    // Domain-level: bare domain matches target's domain suffix
    if !key.email_address.contains('@') {
        let target_domain = target.rsplit('@').next().unwrap_or("");
        if key.email_address == target_domain {
            return Ok(());
        }
    }
    // Address-level: exact email match
    if key.email_address == target {
        return Ok(());
    }
    Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
        error: "forbidden".into(),
        detail: Some(format!(
            "{} email '{}' does not match target '{}' — cross-address access denied",
            role_label, key.email_address, target
        )),
    })))
}

/// Verify target email matches API key's email_address.
pub fn require_domain_match(
    key: &ApiKeyRecord,
    target_email: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_domain_access(key, target_email, "API key")
}

/// Verify agent-level access: exact email match or system-level bypass.
pub fn require_agent_match(
    key: &ApiKeyRecord,
    target_email: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_domain_access(key, target_email, "AgentAdmin")
}

/// Check whitelist access: admin keys get full pass; AgentAdmin gets domain suffix match; Agent gets own email.
pub fn check_whitelist_access(
    key: &ApiKeyRecord,
    domain_addr: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // ── Admin-level: PlatformAdmin + SystemAdmin → full pass ──
    if is_platform_admin_scope(key) || is_system_admin_scope(key) {
        return Ok(());
    }

    // ── AgentAdmin: domain suffix match ──
    if is_agent_admin_scope(key) {
        let domain_suffix = format!(
            "@{}",
            key.email_address
                .rsplit('@')
                .next()
                .unwrap_or(&key.email_address)
        );
        if domain_addr.ends_with(&domain_suffix) {
            return Ok(());
        }
    }

    // ── Agent: own email only ──
    if is_agent_scope(key) && key.email_address == domain_addr {
        return Ok(());
    }

    Err((
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".into(),
            detail: Some("Insufficient scope or email mismatch for whitelist operation".into()),
        }),
    ))
}

/// Check if the API key has Agent scope.
pub fn is_agent_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == Scope::Agent))
}

/// Check if the API key has SystemAdmin scope.
pub fn is_system_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == Scope::SystemAdmin))
}

/// Check if the API key has AgentAdmin scope.
pub fn is_agent_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == Scope::AgentAdmin))
}

/// Check if the API key has PlatformAdmin scope.
pub fn is_platform_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == Scope::PlatformAdmin))
}

/// Check if the API key has any admin scope (PlatformAdmin, SystemAdmin, or AgentAdmin).
pub fn is_admin_scope(key: &ApiKeyRecord) -> bool {
    is_platform_admin_scope(key) || is_system_admin_scope(key) || is_agent_admin_scope(key)
}

/// Check if the API key has Bridge scope (pending deliveries only).
pub fn is_bridge_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::from_str(s).map_or(false, |scope| scope == Scope::Bridge))
}

/// Scope guard: verify API key has at least one of the given scopes.
pub fn require_scope_any(
    key: &ApiKeyRecord,
    required_scopes: &[&str],
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if required_scopes.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "No valid scopes specified".to_string(),
                detail: Some("require_scope_any called with empty scope list".to_string()),
            }),
        ));
    }
    for s in required_scopes {
        if require_scope(key, s).is_ok() {
            return Ok(());
        }
    }
    // return error for first scope
    require_scope(key, required_scopes[0])
}

/// Compute SHA-256 hash of a string and return as hex.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Extract the domain part from an email address (e.g. "user@example.com" → "example.com").
/// Falls back to the input unchanged if no '@' is present.
pub fn domain_from_email(address: &str) -> &str {
    address.split('@').nth(1).unwrap_or(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::ApiKeyRecord;

    fn key(system_id: &str, email: &str, scopes: &[&str]) -> ApiKeyRecord {
        ApiKeyRecord {
            id: 1,
            system_id: system_id.to_string(),
            email_address: email.to_string(),
            key_hash: "h".into(),
            key_prefix: "p".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            is_active: true,
            created_at: String::new(),
            expires_at: None,
            last_used_at: None,
            category: "agent".into(),
            activation_code_hash: None,
            activation_expires_at: None,
            claimed_at: None,
        }
    }

    #[test]
    fn domain_access_agent_key_on_bootstrap_system_is_scoped() {
        // AUDIT-1 P2-1: an agent-scope key must NOT bypass domain checks even
        // when its system_id looks like a bootstrap system (system-*).
        let k = key("system-abc", "alice@example.com", &["agent"]);
        assert!(check_domain_access(&k, "bob@other.com", "API key").is_err());
        // own address still allowed
        assert!(check_domain_access(&k, "alice@example.com", "API key").is_ok());
    }

    #[test]
    fn domain_access_platform_admin_bypasses() {
        let k = key("system-abc", "", &["platform"]);
        assert!(check_domain_access(&k, "anyone@anywhere.com", "API key").is_ok());
    }

    #[test]
    fn domain_access_system_admin_bypasses() {
        let k = key("shared-token-1", "", &["system"]);
        assert!(check_domain_access(&k, "anyone@anywhere.com", "API key").is_ok());
    }

    #[test]
    fn domain_access_agent_cannot_cross_address() {
        let k = key("shared-token-1", "alice@example.com", &["agent"]);
        assert!(check_domain_access(&k, "bob@example.com", "API key").is_err());
    }
}
