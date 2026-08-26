//! Authentication middleware and scope guard utilities.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Json, Response},
};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::api::types::ErrorResponse;
use crate::core::factory::EnvFactory;
use crate::core::scope::Scope;
use crate::core::storage::ApiKeyRecord;

// ── AuthLayer Middleware ──

/// Freshness window for `X-Api-Timestamp` (±5 minutes).
const SIGNATURE_FRESHNESS_MS: u64 = 300_000;
/// Cap on candidate keys tried per request (bounds the empty-identity path).
const MAX_SIGNATURE_CANDIDATES: usize = 64;
/// Base cap on the request body buffered for signature verification (30 MB).
const MAX_SIGNATURE_BODY_BYTES: u64 = 30 * 1024 * 1024;

/// Effective body cap: at least the base cap, but never below the configured
/// max attachment size (+1 MB margin for MIME framing). A configured
/// attachment limit above the base cap would otherwise 413 at the auth layer
/// before the upload handler could even see the body.
pub fn signature_body_cap(configured_attachment_max: u64) -> u64 {
    configured_attachment_max.max(MAX_SIGNATURE_BODY_BYTES) + 1024 * 1024
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unauthorized(err: &str) -> Response {
    let err_body = serde_json::to_string(&ErrorResponse {
        error: err.to_string(),
        detail: None,
    })
    .unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .body(Body::from(err_body))
        .unwrap()
}

/// Canonical v1 API signature base string:
/// `METHOD\npath_and_query\ntimestamp\nsha256_hex(body)` (no trailing newline).
fn signature_base(method: &str, path: &str, timestamp: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());
    format!("{method}\n{path}\n{timestamp}\n{body_hash}")
}

/// Compute the v1 API request signature (spec: docs/API-SIGNATURE-PROTOCOL.md).
///
/// `sig = hex(HMAC-SHA256(key = key_hash bytes, msg = signature_base bytes))`
///
/// `key_hash` is `sha256(raw_key)` — the value stored in `api_keys.key_hash`.
/// Clients derive it offline from the raw key, so the raw key never crosses
/// the wire.
pub fn compute_api_signature(
    key_hash: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key_hash.as_bytes()).expect("HMAC can take key of any size");
    mac.update(signature_base(method, path, timestamp, body).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Middleware: verify the v1 API signature
/// (`X-Api-Identity` + `X-Api-Timestamp` + `X-Api-Signature`) against the
/// database.
///
/// The raw API key never crosses the wire: the client signs with
/// `sha256(raw_key)` (= the DB `key_hash`), and the server re-computes the
/// HMAC for each candidate key of the claimed identity, comparing in
/// constant time. A 5-minute freshness window on the (signed) timestamp
/// bounds replay. Returns 401 if any header is missing, the signature does
/// not match, or the timestamp is stale.
pub async fn auth_layer(env_factory: EnvFactory, req: Request, next: Next, body_cap: u64) -> Response {
    // `X-Api-Identity` is optional: curl drops empty-valued headers on the
    // wire, so a *missing* header must mean the same as an empty one
    // (empty-identity fallback — the signature itself selects the key).
    let identity = req
        .headers()
        .get("X-Api-Identity")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let timestamp = req
        .headers()
        .get("X-Api-Timestamp")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let signature = req
        .headers()
        .get("X-Api-Signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return unauthorized("Missing X-Api-Timestamp or X-Api-Signature header");
    };

    let ts_ms: u64 = match timestamp.parse() {
        Ok(v) => v,
        Err(_) => return unauthorized("Invalid X-Api-Timestamp"),
    };
    if ts_ms.abs_diff(now_ms()) > SIGNATURE_FRESHNESS_MS {
        return unauthorized("Stale X-Api-Timestamp (outside ±5 min window)");
    }

    let provided_sig = match hex::decode(&signature) {
        Ok(v) => v,
        Err(_) => return unauthorized("Invalid X-Api-Signature"),
    };

    // Buffer the body so it can be hashed, then forwarded unchanged.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, body_cap as usize).await {
        Ok(b) => b,
        Err(e) => {
            // Body exceeded the cap or could not be read — reject (fail closed).
            tracing::debug!(%e, "auth_layer: failed to buffer request body");
            let err_body = serde_json::to_string(&ErrorResponse {
                error: "Payload too large or unreadable".to_string(),
                detail: None,
            })
            .unwrap_or_default();
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("Content-Type", "application/json")
                .body(Body::from(err_body))
                .unwrap();
        }
    };

    let method = parts.method.to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());

    let candidates = match env_factory.list_api_keys_by_identity(&identity).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%e, "auth_layer: DB error during signature verification");
            return unauthorized("Authentication error");
        }
    };

    let base = signature_base(&method, &path, &timestamp, &bytes);
    let mut record: Option<ApiKeyRecord> = None;
    for rec in candidates.iter().take(MAX_SIGNATURE_CANDIDATES) {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(rec.key_hash.as_bytes())
                .expect("HMAC can take key of any size");
        mac.update(base.as_bytes());
        if mac.verify_slice(&provided_sig).is_ok() {
            record = Some(rec.clone());
            break;
        }
    }

    let Some(record) = record else {
        return unauthorized("Invalid X-Api-Signature");
    };

    // Best-effort last_used_at (observability only).
    if let Err(e) = env_factory.touch_api_key_last_used(record.id).await {
        tracing::debug!(%e, "auth_layer: failed to update last_used_at");
    }

    // Reassemble the request with the buffered body for downstream handlers.
    let mut req = Request::from_parts(parts, Body::from(bytes));
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

/// Canonical v1 signature vector (docs/API-SIGNATURE-PROTOCOL.md).
/// Rust / Python / TS clients MUST all produce this exact value.
#[test]
fn api_signature_matches_canonical_vector() {
    let raw_key = "0123456789abcdef0123456789abcdef";
    let key_hash = sha256_hex(raw_key);
    assert_eq!(
        key_hash,
        "3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9"
    );

    let method = "POST";
    let path = "/api/v1/whitelists?domain=alice%40x.com&value=%40mx-a.test";
    let timestamp = "1756000000000";
    let body = b"{\"direction\":\"to\"}";

    let sig = compute_api_signature(&key_hash, method, path, timestamp, body);
    assert_eq!(
        sig,
        "cabf840e1d1a8dd9d6885762beae087f422dbd4d6d20c9ca404896120a45bcbd"
    );

    // Empty-body (GET) case.
    let sig_empty =
        compute_api_signature(&key_hash, "GET", "/api/v1/whoami", timestamp, b"");
    assert_eq!(
        sig_empty,
        "1aac75c79bea9c60efb3280a384900ce649c346c3da5cc124361fc5070e55c74"
    );
}

/// Tampering any part of the request must change the signature.
#[test]
fn api_signature_is_tamper_sensitive() {
    let key_hash = sha256_hex("0123456789abcdef0123456789abcdef");
    let method = "POST";
    let path = "/api/v1/whitelists?domain=alice%40x.com";
    let timestamp = "1756000000000";
    let body = b"{\"direction\":\"to\"}";
    let base = compute_api_signature(&key_hash, method, path, timestamp, body);

    assert_ne!(
        compute_api_signature(&key_hash, method, path, timestamp, b"{\"direction\":\"from\"}"),
        base
    );
    assert_ne!(
        compute_api_signature(&key_hash, method, path, "1756000000001", body),
        base
    );
    assert_ne!(
        compute_api_signature(&key_hash, "GET", path, timestamp, body),
        base
    );
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

    // ─── P2-2: signature body cap ───

    #[test]
    fn signature_body_cap_tracks_attachment_config() {
        use super::signature_body_cap;
        use super::MAX_SIGNATURE_BODY_BYTES;
        // Below base cap → base cap + 1 MB margin.
        assert_eq!(signature_body_cap(0), MAX_SIGNATURE_BODY_BYTES + 1024 * 1024);
        assert_eq!(
            signature_body_cap(20 * 1024 * 1024),
            MAX_SIGNATURE_BODY_BYTES + 1024 * 1024
        );
        // Above base cap → configured value + 1 MB margin.
        assert_eq!(
            signature_body_cap(40 * 1024 * 1024),
            40 * 1024 * 1024 + 1024 * 1024
        );
    }
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
