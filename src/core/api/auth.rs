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
            let err_body = serde_json::to_string(&ErrorResponse {
                error: "Authentication error".to_string(),
                detail: Some(e.to_string()),
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

/// Verify target email/system matches API key's email_address.
pub fn require_domain_match(
    key: &ApiKeyRecord,
    target_email: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // System admin (admin system) may operate across all
    if key.system_id == "admin" {
        return Ok(());
    }
    // System-level key (email_address == "") can manage any address-level key in the same system
    if key.email_address.is_empty() {
        return Ok(());
    }
    // Domain-level admin: email_address is a bare domain, matches target's domain
    if !key.email_address.contains('@') {
        let target_domain = target_email.rsplit('@').next().unwrap_or("");
        if key.email_address == target_domain {
            return Ok(());
        }
    }
    if key.email_address == target_email {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "API key email '{}' does not match target email '{}' — cross-address access denied",
                    key.email_address, target_email
                )),
            }),
        ))
    }
}

/// Verify agent-level access: exact email match or system-level bypass.
pub fn require_agent_match(
    key: &ApiKeyRecord,
    target_email: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Admin system bypass
    if key.system_id == "admin" {
        return Ok(());
    }
    // System-level key (empty email) — unrestricted
    if key.email_address.is_empty() {
        return Ok(());
    }
    // Domain-level: bare domain matches target's domain
    if !key.email_address.contains('@') {
        let target_domain = target_email.rsplit('@').next().unwrap_or("");
        if key.email_address == target_domain {
            return Ok(());
        }
    }
    // Address-level: exact email match only
    if key.email_address == target_email {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "AgentAdmin email '{}' does not match target '{}'",
                    key.email_address, target_email
                )),
            }),
        ))
    }
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
