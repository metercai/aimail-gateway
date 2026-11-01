//! Authentication middleware and scope guard utilities.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Json, Response},
};
use futures_util::StreamExt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::api::types::ErrorResponse;
use crate::core::factory::EnvFactory;
use crate::core::scope::Scope;
use crate::core::storage::ApiKeyRecord;

// ── AuthLayer Middleware ──

/// D9: default freshness window for `X-Api-Timestamp` (±120 s). Configurable
/// via `[api] signature_window_secs`; client and server clocks must agree
/// within ±window (keep both NTP-synchronized, or every request 401s).
pub const DEFAULT_SIGNATURE_WINDOW_MS: u64 = 120_000;
/// D6: body cap for regular (JSON) API routes — 1 MB. The auth layer streams
/// the body (incremental SHA-256) and stops at the cap, so memory per request
/// is bounded by the route's cap instead of the previous fixed 30 MB whole-body
/// buffer.
pub const REGULAR_API_BODY_CAP: u64 = 1024 * 1024;

/// D6: per-route body caps for the auth layer's streaming read.
#[derive(Debug, Clone, Copy)]
pub struct BodyCaps {
    /// Regular JSON API routes (default 1 MB).
    pub regular: u64,
    /// Attachment upload endpoint (configured: attachment_max_size + 1 MB
    /// margin for MIME framing).
    pub attachment: u64,
}

impl BodyCaps {
    /// Cap for a request path: only the upload endpoint may exceed the
    /// regular cap (its multipart body carries the file bytes).
    pub fn for_path(&self, path: &str) -> u64 {
        if path.starts_with("/api/v1/upload") {
            self.attachment
        } else {
            self.regular
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// D9: a signed timestamp is outside the freshness window when its
/// distance from now exceeds ±window_ms. Pure (testable without a factory).
fn window_expired(ts_ms: u64, now_ms: u64, window_ms: u64) -> bool {
    ts_ms.abs_diff(now_ms) > window_ms
}

/// D1: cap on candidate keys for the **degraded** empty-identity fallback
/// (`[api] allow_unidentified_keys = true`). Enforced in SQL
/// (storage `list_api_keys_by_identity`), so the full table never enters
/// memory. The normal identity branch is uncapped — a caller with a valid
/// identity must be able to reach every one of its keys.
pub const EMPTY_IDENTITY_CANDIDATE_CAP: usize = 64;

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
///
/// **Single implementation**: every request path (inline middleware and the pull
/// intercept) must call it; no re-implementations (on 2026-09-22 a second copy
/// missed one spot of a sealing refactor and the agent's own pull stopped working).
pub fn signature_base(method: &str, path: &str, timestamp: &str, body: &[u8]) -> String {
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

/// Request signature verification: **single implementation** (shared by the inline
/// middleware and the pull intercept; no re-implementations).
///
/// Iterate candidate records: stored material may be sealed (`v1:`) => first unseal it via `seal::signing_material` back to
/// `sha256(raw_key)`, then compare against `signature_base(...)` with a constant-time HMAC; on a hit return that record
/// (including scopes/category, for the caller's authorization decision). A failed unseal only skips that candidate => final 401 (fail closed).
pub fn verify_request_signature(
    candidates: &[crate::core::storage::ApiKeyRecord],
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
    provided_sig: &[u8],
) -> Option<crate::core::storage::ApiKeyRecord> {
    let base = signature_base(method, path, timestamp, body);
    for rec in candidates.iter() {
        let material = match crate::core::api::seal::signing_material_env(&rec.key_hash) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    operation = "sealed_credential_open_failed",
                    error = %e,
                    key_prefix = %rec.key_prefix,
                    "skipping candidate key"
                );
                continue;
            }
        };
        let mut mac = match Hmac::<Sha256>::new_from_slice(material.as_bytes()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        mac.update(base.as_bytes());
        if mac.verify_slice(provided_sig).is_ok() {
            return Some(rec.clone());
        }
    }
    None
}

/// Middleware: verify the v1 API signature
/// (`X-Api-Identity` + `X-Api-Timestamp` + `X-Api-Signature`) against the
/// database.
///
/// The raw API key never crosses the wire: the client signs with
/// `sha256(raw_key)` (= the DB `key_hash`), and the server re-computes the
/// HMAC for each candidate key of the claimed identity, comparing in
/// constant time. A configurable freshness window (default ±120 s, `[api]
/// signature_window_secs`) on the (signed) timestamp bounds replay; with
/// `[api] replay_protection` an already-verified request re-sent inside the
/// window is rejected with 409 `replayed`. Returns 401 if any header is
/// missing, the signature does not match, or the timestamp is stale.
pub async fn auth_layer(
    env_factory: EnvFactory,
    req: Request,
    next: Next,
    caps: BodyCaps,
) -> Response {
    // `X-Api-Identity` is optional: curl drops empty-valued headers on the
    // wire, so a *missing* header must mean the same as an empty one
    // (empty-identity fallback — the signature itself selects the key).
    let identity = req
        .headers()
        .get("X-Api-Identity")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    // D1: an empty identity (missing or empty `X-Api-Identity`) used to fall
    // back to a full-table scan of every API key. That is a scan proportional
    // to total keys (not the caller's own), and it made the 65th key of a
    // bulk-issued batch permanently unauthenticatable. Refuse it before
    // touching the body or the database — 401 `identity_required` — unless
    // the operator explicitly enabled the degraded mode.
    if identity.is_empty() && !env_factory.allows_unidentified_keys() {
        return unauthorized("identity_required: X-Api-Identity must name a system or address");
    }

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
    let window_ms = env_factory.signature_window_ms();
    if window_expired(ts_ms, now_ms(), window_ms) {
        return unauthorized(&format!(
            "Stale X-Api-Timestamp (outside ±{} s window)",
            window_ms / 1000
        ));
    }

    let provided_sig = match hex::decode(&signature) {
        Ok(v) => v,
        Err(_) => return unauthorized("Invalid X-Api-Signature"),
    };

    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let cap = caps.for_path(&path);

    // D6: stream the body — incremental SHA-256, bounded buffer. The buffer
    // holds at most `cap` + one chunk, so memory per request is bounded by
    // the route's cap (a 30 MB body on a regular route 413s after ~1 MB of
    // buffering, not after 30 MB).
    let (parts, body) = req.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = body.into_data_stream();
    let mut read_error: Option<String> = None;
    let mut over_cap = false;
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(chunk) => {
                let bytes = chunk.to_vec();
                if !over_cap {
                    buf.extend(bytes);
                    if buf.len() > cap as usize {
                        // Over the route cap — stop reading (do not consume
                        // the rest of the stream), free the buffer, 413.
                        over_cap = true;
                        buf.clear();
                        break;
                    }
                }
            }
            Err(e) => {
                read_error = Some(e.to_string());
                break;
            }
        }
    }
    if over_cap {
        tracing::debug!(
            path = %path,
            cap_bytes = cap,
            "auth_layer: body exceeds route cap"
        );
        let err_body = serde_json::to_string(&ErrorResponse {
            error: "payload_too_large".to_string(),
            detail: Some(format!("body exceeds the {} byte cap for this route", cap)),
        })
        .unwrap_or_default();
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("Content-Type", "application/json")
            .body(Body::from(err_body))
            .unwrap();
    }
    if let Some(read_error) = read_error {
        // Body could not be read — reject (fail closed).
        tracing::debug!(%read_error, "auth_layer: failed to read request body");
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

    let bytes = buf;

    let candidates = match env_factory.list_api_keys_by_identity(&identity).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%e, "auth_layer: DB error during signature verification");
            return unauthorized("Authentication error");
        }
    };

    // Signature verification goes through the **shared single implementation**
    // (per-candidate unseal + constant-time HMAC comparison). It re-hashes the
    // buffered bytes — the streamed SHA-256 above bounded the read; the
    // protocol's body-hash semantics are unchanged (see the protocol doc).
    let record: Option<ApiKeyRecord> = verify_request_signature(
        &candidates,
        &method,
        &path,
        &timestamp,
        &bytes,
        &provided_sig,
    );

    let Some(record) = record else {
        return unauthorized("Invalid X-Api-Signature");
    };

    // D9: replay check (optional, `[api] replay_protection`). The nonce key
    // binds identity + timestamp + method + path — the full replay surface of
    // the signature base (method is included because it is part of the signed
    // base string; two different methods with the same timestamp are
    // different requests, not replays of each other).
    let nonce_key = format!("{}\n{}\n{}\n{}", identity, timestamp, method, path);
    if let Some(first_seen_ms) = env_factory.check_and_record_signature(&nonce_key) {
        let err_body = serde_json::to_string(&ErrorResponse {
            error: "replayed".to_string(),
            detail: Some(format!(
                "signature already verified at {first_seen_ms} ms — re-sends inside the window are rejected"
            )),
        })
        .unwrap_or_default();
        return Response::builder()
            .status(StatusCode::CONFLICT)
            .header("Content-Type", "application/json")
            .body(Body::from(err_body))
            .unwrap();
    }

    // D5: last_used_at is an in-memory note (observability only) — the
    // background flush task batch-writes it, at most once per interval.
    env_factory.note_api_key_last_used(record.id);

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
        .any(|s| Scope::parse_db(s).is_some_and(|scope| scope == required));

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
///
/// Access is decided by SCOPE, never by the key's system_id value. A
/// platform/system-scope key may manage any address; an agent-scope key is
/// bound to its own address regardless of which system issued it.
fn check_domain_access(
    key: &ApiKeyRecord,
    target: &str,
    role_label: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // SCOPE-based bypass only. The legacy `key.system_id == "admin"` clause is
    // gone (D2): it let an agent-scope key of the default system read any
    // address. "admin" is just the default system's id — not a privilege.
    if is_platform_admin_scope(key) || is_system_admin_scope(key) {
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
    Err((
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".into(),
            detail: Some(format!(
                "{} email '{}' does not match target '{}' — cross-address access denied",
                role_label, key.email_address, target
            )),
        }),
    ))
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
    target_system: Option<&str>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // ── Admin-level: PlatformAdmin + SystemAdmin → full pass ──
    if is_platform_admin_scope(key) || is_system_admin_scope(key) {
        return Ok(());
    }

    // ── AgentAdmin: agents inside one's own system (the authorization object is the agent, independent of domain/shared domain) ──
    if is_agent_admin_scope(key) && target_system == Some(key.system_id.as_str()) {
        return Ok(());
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
        .any(|s| Scope::parse_db(s).is_some_and(|scope| scope == Scope::Agent))
}

/// Check if the API key has SystemAdmin scope.
pub fn is_system_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::parse_db(s).is_some_and(|scope| scope == Scope::SystemAdmin))
}

/// Check if the API key has AgentAdmin scope.
pub fn is_agent_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::parse_db(s).is_some_and(|scope| scope == Scope::AgentAdmin))
}

/// Check if the API key has PlatformAdmin scope.
pub fn is_platform_admin_scope(key: &ApiKeyRecord) -> bool {
    key.scopes
        .iter()
        .any(|s| Scope::parse_db(s).is_some_and(|scope| scope == Scope::PlatformAdmin))
}

/// Check if the API key has any admin scope (PlatformAdmin, SystemAdmin, or AgentAdmin).
pub fn is_admin_scope(key: &ApiKeyRecord) -> bool {
    is_platform_admin_scope(key) || is_system_admin_scope(key) || is_agent_admin_scope(key)
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
    let sig_empty = compute_api_signature(&key_hash, "GET", "/api/v1/whoami", timestamp, b"");
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
        compute_api_signature(
            &key_hash,
            method,
            path,
            timestamp,
            b"{\"direction\":\"from\"}"
        ),
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

    // ── D6: per-route body caps ──

    #[test]
    fn d6_body_caps_per_route() {
        let caps = BodyCaps {
            regular: REGULAR_API_BODY_CAP,
            attachment: 20 * 1024 * 1024 + 1024 * 1024,
        };
        // Only the upload endpoint gets the attachment cap.
        assert_eq!(
            caps.for_path("/api/v1/upload"),
            20 * 1024 * 1024 + 1024 * 1024
        );
        assert_eq!(
            caps.for_path("/api/v1/upload?x=1"),
            20 * 1024 * 1024 + 1024 * 1024
        );
        // Everything else is the regular 1 MB cap.
        assert_eq!(caps.for_path("/api/v1/send"), REGULAR_API_BODY_CAP);
        assert_eq!(caps.for_path("/api/v1/whoami"), REGULAR_API_BODY_CAP);
        assert_eq!(
            caps.for_path("/api/v1/attachments/abc"),
            REGULAR_API_BODY_CAP
        );
        assert_eq!(REGULAR_API_BODY_CAP, 1024 * 1024);
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

    // ── D2: the system_id == "admin" bypass is gone ─────────────────────────
    #[test]
    fn d2_agent_key_of_default_system_cannot_read_other_addresses() {
        // The original repro: an agent-scope key issued by the default system
        // (system_id == "admin") reading someone else's data.
        let k = key("admin", "alice@example.com", &["agent"]);
        assert!(
            check_domain_access(&k, "someone-else@another-domain", "API key").is_err(),
            "agent key of the 'admin' system must NOT bypass the address check"
        );
        // ...but its own address still works.
        assert!(check_domain_access(&k, "alice@example.com", "API key").is_ok());
    }

    #[test]
    fn d2_system_scope_key_of_default_system_still_manages_own_domain() {
        // A system-scope key of the default system keeps its scope-based
        // authority (this is scope, not the removed id-based bypass).
        let k = key("admin", "", &["system"]);
        assert!(check_domain_access(&k, "anyone@anywhere.com", "API key").is_ok());
    }

    #[test]
    fn d2_platform_scope_unaffected() {
        let k = key("admin", "", &["platform"]);
        assert!(check_domain_access(&k, "anyone@anywhere.com", "API key").is_ok());
        let k2 = key("system-abc", "", &["platform"]);
        assert!(check_domain_access(&k2, "anyone@anywhere.com", "API key").is_ok());
    }

    #[test]
    fn d2_non_default_system_agent_key_unchanged() {
        // Regression guard: systems whose id is not "admin" already behaved
        // correctly; make sure the removal did not change them either way.
        let k = key("system-abc", "alice@example.com", &["agent"]);
        assert!(check_domain_access(&k, "bob@example.com", "API key").is_err());
        assert!(check_domain_access(&k, "alice@example.com", "API key").is_ok());
    }

    #[test]
    fn domain_access_agent_cannot_cross_address() {
        let k = key("shared-token-1", "alice@example.com", &["agent"]);
        assert!(check_domain_access(&k, "bob@example.com", "API key").is_err());
    }

    // ── D9: configurable freshness window + optional replay cache ──

    #[test]
    fn d9_window_expired_boundaries() {
        assert!(!window_expired(1000, 1100, 200)); // diff 100 ≤ 200
        assert!(!window_expired(1000, 700, 300)); // diff 300 ≤ 300 (boundary inside)
        assert!(window_expired(1000, 1301, 300)); // diff 301 > 300
        assert!(window_expired(1000, 700, 299)); // diff 300 > 299
    }

    #[test]
    fn d9_signature_cache_hit_ttl_and_eviction() {
        use crate::core::factory::SignatureCache;
        let c = SignatureCache::new(3).with_ttl(60_000);
        // Fresh insert → miss (None), re-send → hit.
        assert_eq!(c.check_and_record("a"), None);
        assert_eq!(
            c.check_and_record("a").unwrap(),
            c.check_and_record("a").unwrap()
        );
        // Distinct keys coexist up to the cap.
        assert_eq!(c.check_and_record("b"), None);
        assert_eq!(c.check_and_record("c"), None);
        // Cap is 3 — inserting "d" evicts the oldest-inserted ("a").
        assert_eq!(c.check_and_record("d"), None);
        assert_eq!(c.check_and_record("a"), None); // evicted → re-accepted
        assert!(c.check_and_record("c").is_some()); // still cached

        // TTL: an entry older than the TTL is treated as absent.
        let short = SignatureCache::new(2).with_ttl(30);
        assert_eq!(short.check_and_record("x"), None);
        std::thread::sleep(std::time::Duration::from_millis(40));
        assert_eq!(short.check_and_record("x"), None); // expired → re-accepted
    }

    #[tokio::test]
    async fn d9_auth_layer_window_and_replay() {
        use crate::base::strategy::BaseSystemStore;
        use crate::core::storage::Database;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("aimailgw-d9-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let arc = std::sync::Arc::new(db);

        // A key the client signs with.
        let key_hash = "a".repeat(64);
        arc.insert_api_key(
            "sys1",
            "agent@test.com",
            &key_hash,
            "abcd",
            &["agent".to_string()],
            None,
            "agent",
        )
        .await
        .unwrap();

        // X-Api-Timestamp is epoch **milliseconds** (see the protocol doc).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ts = (now_ms - 60_000).to_string(); // 60 s back — inside the 120 s window
        let path = "/api/v1/whoami";
        let sig = compute_api_signature(&key_hash, "GET", path, &ts, b"");

        async fn ok_handler(_req: Request) -> Response {
            Response::new(Body::from("ok"))
        }

        // One signed request through `auth_layer` mounted as middleware on a
        // real router — the exact production wiring (http.rs route_layer
        // pattern; axum 0.7's `Next` has no public constructor, so the
        // middleware can only be exercised through the framework).
        async fn one(
            ef: &crate::core::factory::EnvFactory,
            identity: &str,
            ts: &str,
            sig: &str,
            req_path: &str,
        ) -> (StatusCode, String) {
            use axum::routing::get;
            let ef_state = ef.clone();
            let app = axum::Router::new()
                .route("/api/v1/whoami", get(ok_handler))
                .route("/api/v1/key/rotate", get(ok_handler))
                .route_layer(axum::middleware::from_fn(move |req, next| {
                    let ef = ef_state.clone();
                    let caps = BodyCaps {
                        regular: 1024,
                        attachment: 1024,
                    };
                    async move { auth_layer(ef, req, next, caps).await }
                }));
            let req = Request::builder()
                .method("GET")
                .uri(req_path)
                .header("X-Api-Identity", identity)
                .header("X-Api-Timestamp", ts)
                .header("X-Api-Signature", sig)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).to_string())
        }

        // (a) Replay protection OFF: two identical sends both pass (pre-D9
        // behaviour, only the window tightened).
        let ef_off = crate::core::factory::EnvFactory::new(
            arc.clone(),
            std::sync::Arc::new(BaseSystemStore),
        )
        .with_signature_auth(120, false);
        let (s1, body1) = one(&ef_off, "agent@test.com", &ts, &sig, path).await;
        assert_eq!(s1, StatusCode::OK, "body: {body1}");
        let (s2, _) = one(&ef_off, "agent@test.com", &ts, &sig, path).await;
        assert_eq!(s2, StatusCode::OK); // no cache → not a replay

        // (b) Replay protection ON: first passes, identical re-send → 409.
        let ef_on = crate::core::factory::EnvFactory::new(
            arc.clone(),
            std::sync::Arc::new(BaseSystemStore),
        )
        .with_signature_auth(120, true);
        let (s1, _) = one(&ef_on, "agent@test.com", &ts, &sig, path).await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, body2) = one(&ef_on, "agent@test.com", &ts, &sig, path).await;
        assert_eq!(s2, StatusCode::CONFLICT);
        assert!(body2.contains("replayed"), "body: {body2}");

        // (c) A different path with the same timestamp is a different
        // request, not a replay.
        let ts2 = ts.clone();
        let sig2 = compute_api_signature(&key_hash, "GET", "/api/v1/key/rotate", &ts2, b"");
        let (s3, _) = one(&ef_on, "agent@test.com", &ts2, &sig2, "/api/v1/key/rotate").await;
        assert_eq!(s3, StatusCode::OK);

        // (d) Concurrent identical sends: exactly one wins, the other 409s.
        let ts3 = (now_ms - 10_000).to_string();
        let sig3 = compute_api_signature(&key_hash, "GET", path, &ts3, b"");
        let (ra, rb) = tokio::join!(
            one(&ef_on, "agent@test.com", &ts3, &sig3, path),
            one(&ef_on, "agent@test.com", &ts3, &sig3, path),
        );
        let codes = [ra.0, rb.0]
            .iter()
            .map(|s| *s == StatusCode::OK)
            .filter(|b| *b)
            .count();
        assert_eq!(codes, 1, "exactly one of the concurrent twins may pass");
        assert!(
            [ra.0, rb.0].contains(&StatusCode::CONFLICT),
            "the loser must be a 409 replay, got {ra:?} {rb:?}"
        );

        // (e) Window: a timestamp 180 s in the past is outside the default
        // 120 s window → 401 regardless of replay protection.
        let ef_window = crate::core::factory::EnvFactory::new(
            arc.clone(),
            std::sync::Arc::new(BaseSystemStore),
        )
        .with_signature_auth(120, false);
        let ts_stale = (now_ms - 180_000).to_string();
        let sig_stale = compute_api_signature(&key_hash, "GET", path, &ts_stale, b"");
        let (s5, body5) = one(&ef_window, "agent@test.com", &ts_stale, &sig_stale, path).await;
        assert_eq!(s5, StatusCode::UNAUTHORIZED);
        assert!(body5.contains("window"), "body: {body5}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── D6: streaming body read + per-route caps → 413 ──

    #[tokio::test]
    async fn d6_oversized_body_413s_before_signature_undersized_passes() {
        use crate::base::strategy::BaseSystemStore;
        use crate::core::storage::Database;
        use axum::routing::post;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("aimailgw-d6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = std::sync::Arc::new(Database::open(dir.join("aimail.db"), 4, None).unwrap());

        let key_hash = "b".repeat(64);
        db.insert_api_key(
            "sys1",
            "agent@test.com",
            &key_hash,
            "abcd",
            &["agent".to_string()],
            None,
            "agent",
        )
        .await
        .unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ts = (now_ms - 1000).to_string();

        async fn ok_handler(_req: Request) -> Response {
            Response::new(Body::from("ok"))
        }

        let ef =
            crate::core::factory::EnvFactory::new(db.clone(), std::sync::Arc::new(BaseSystemStore));
        let caps = BodyCaps {
            regular: 1024 * 1024,         // 1 MB
            attachment: 21 * 1024 * 1024, // 20 MB + 1 MB margin
        };

        async fn post_one(
            ef: &crate::core::factory::EnvFactory,
            caps: BodyCaps,
            path: &str,
            ts: &str,
            sig: &str,
            body: Vec<u8>,
        ) -> StatusCode {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header("X-Api-Identity", "agent@test.com")
                .header("X-Api-Timestamp", ts)
                .header("X-Api-Signature", sig)
                .body(Body::from(body))
                .unwrap();
            let ef_state = ef.clone();
            let app = axum::Router::new()
                .route("/api/v1/send", post(ok_handler))
                .route("/api/v1/upload", post(ok_handler))
                .route_layer(axum::middleware::from_fn(move |req, next| {
                    let ef = ef_state.clone();
                    let c = caps;
                    async move { auth_layer(ef, req, next, c).await }
                }));
            app.clone().oneshot(req).await.unwrap().status()
        }

        // 1) Oversized body on a REGULAR route → 413 (size short-circuits
        //    before signature verification, so no valid sig needed).
        let big = vec![0u8; 2 * 1024 * 1024]; // 2 MB > 1 MB cap
        let s = post_one(&ef, caps, "/api/v1/send", &ts, "deadbeef", big).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "2 MB on /send must 413");

        // 2) Small body on a regular route with a valid signature → reaches
        //    the handler (OK), proving it is NOT 413.
        let small = b"{\"to\":\"a@b.c\"}".to_vec();
        let sig_small = compute_api_signature(&key_hash, "POST", "/api/v1/send", &ts, &small);
        let s = post_one(&ef, caps, "/api/v1/send", &ts, &sig_small, small).await;
        assert_eq!(s, StatusCode::OK, "small valid body on /send must pass");

        // 3) Oversized body on the UPLOAD route → 413 (25 MB > 21 MB cap).
        let big_up = vec![0u8; 25 * 1024 * 1024];
        let s = post_one(&ef, caps, "/api/v1/upload", &ts, "deadbeef", big_up).await;
        assert_eq!(
            s,
            StatusCode::PAYLOAD_TOO_LARGE,
            "25 MB on /upload must 413"
        );

        // 4) Body under the attachment cap with a valid signature → reaches
        //    the handler (OK), proving the upload route still accepts large
        //    bodies (20 MB upload regression).
        let mid = vec![0u8; 5 * 1024 * 1024]; // 5 MB < 21 MB
        let sig_mid = compute_api_signature(&key_hash, "POST", "/api/v1/upload", &ts, &mid);
        let s = post_one(&ef, caps, "/api/v1/upload", &ts, &sig_mid, mid).await;
        assert_eq!(s, StatusCode::OK, "5 MB valid body on /upload must pass");

        let _ = std::fs::remove_dir_all(&dir);
    }
    // ── D1: identity_required + allow_unidentified_keys + LIMIT 64 ──

    #[tokio::test]
    async fn d1_empty_identity_refused_without_db_or_body() {
        use crate::base::strategy::BaseSystemStore;
        use crate::core::storage::Database;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("aimailgw-d1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let arc = std::sync::Arc::new(db);

        // Seed one key so the "would-have-matched" path is real.
        let key_hash = "b".repeat(64);
        arc.insert_api_key(
            "sys1",
            "agent@test.com",
            &key_hash,
            "abcd",
            &["agent".to_string()],
            None,
            "agent",
        )
        .await
        .unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ts = now_ms.to_string();
        let path = "/api/v1/whoami";
        let sig = compute_api_signature(&key_hash, "GET", path, &ts, b"");

        async fn ok_handler(_req: Request) -> Response {
            Response::new(Body::from("ok"))
        }

        // (a) Default (allow_unidentified_keys = false): empty identity is
        //     refused with 401 identity_required — before any DB access.
        let ef = crate::core::factory::EnvFactory::new(
            arc.clone(),
            std::sync::Arc::new(BaseSystemStore),
        );
        let ef_state = ef.clone();
        let app = axum::Router::new()
            .route("/api/v1/whoami", axum::routing::get(ok_handler))
            .route_layer(axum::middleware::from_fn(move |req, next| {
                let ef = ef_state.clone();
                let caps = BodyCaps {
                    regular: 1024,
                    attachment: 1024,
                };
                async move { auth_layer(ef, req, next, caps).await }
            }));

        // Missing header entirely…
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", &sig)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "body: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("identity_required"));

        // …and an explicitly empty header value (curl semantics).
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("X-Api-Identity", "")
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", &sig)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // (b) The valid-identity path still works (the gate is identity-scoped).
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("X-Api-Identity", "agent@test.com")
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", &sig)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn d1_degraded_mode_scans_capped_and_valid_identity_reaches_key_100() {
        use crate::core::storage::Database;

        let dir = std::env::temp_dir().join(format!("aimailgw-d1b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let arc = std::sync::Arc::new(db);

        // (a) Degraded mode: the SQL cap is 64 — seeding 70 active keys must
        //     return exactly 64 candidates, not 70. (Each key needs its own
        //     (system_id, domain_addr) — the table's unique constraint.)
        for i in 0..70u32 {
            let kh = format!("{:064x}", i);
            arc.insert_api_key(
                &format!("bulk{i}"),
                &format!("bulk{i}@t.com"),
                &kh,
                &format!("p{i:04}"),
                &["agent".to_string()],
                None,
                "agent",
            )
            .await
            .unwrap();
        }
        let all = arc.list_api_keys_by_identity("").await.unwrap();
        assert_eq!(all.len(), 64, "degraded scan must be SQL-capped at 64");

        // (b) Normal identity: all 100 keys of one identity must be
        //     reachable (no silent .take(64) drop).
        for i in 0..100u32 {
            let kh = format!("{:064x}", 1000 + i);
            arc.insert_api_key(
                &format!("sys100{i}"),
                "batch@t.com",
                &kh,
                &format!("q{i:04}"),
                &["agent".to_string()],
                None,
                "agent",
            )
            .await
            .unwrap();
        }
        let cands = arc.list_api_keys_by_identity("batch@t.com").await.unwrap();
        assert_eq!(cands.len(), 100, "valid identity must reach all 100 keys");

        // And the last one (index 99) verifies through the real signature path.
        let last = &cands[99];
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ts = now_ms.to_string();
        let path = "/api/v1/whoami";
        let sig = compute_api_signature(&last.key_hash, "GET", path, &ts, b"");
        let hit =
            verify_request_signature(&cands, "GET", path, &ts, b"", &hex::decode(&sig).unwrap());
        assert!(
            hit.is_some(),
            "key #100 of a 100-key batch must authenticate"
        );
        assert_eq!(hit.as_ref().unwrap().id, last.id);
    }
}
