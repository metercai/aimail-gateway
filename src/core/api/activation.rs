//! Activation code handlers (core).

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// System activation codes expire after 7 days; address codes are a 24-hour
/// application window (same as advanced shared-domain defaults).
const ACTIVATION_CODE_TTL_DAYS: i64 = 7;
const ADDRESS_CODE_TTL_HOURS: i64 = 24;

use crate::core::api::auth::require_scope_any;
use crate::core::api::types::{ErrorResponse, HttpState};
use crate::core::storage::{ApiKeyParams, ApiKeyRecord};

// ── Address activation helpers ──

/// Generate address activation codes. Writes into activation_codes table.
pub async fn generate_activation_codes(
    db: &crate::core::storage::Database,
    system_id: &str,
    domain: &str,
    email_address: Option<&str>,
    count: u32,
) -> crate::core::errors::AppResult<Vec<String>> {
    let email = email_address.unwrap_or("");
    let expires = {
        let future = chrono::Utc::now() + chrono::Duration::hours(ADDRESS_CODE_TTL_HOURS);
        Some(future.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    };
    let mut codes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let code = random_code("addr");
        let hash = crate::core::api::auth::sha256_hex(&code);
        db.insert_activation_code(
            &hash,
            &code,
            "address",
            system_id,
            domain,
            email,
            expires.as_deref(),
        )
        .await?;
        codes.push(code);
    }
    Ok(codes)
}

/// Redeem an address activation code → creates an agent-scope API key.
///
/// The endpoint is unauthenticated (the code is the only credential), so
/// caller-supplied scopes are ignored and the bound address is enforced.
pub async fn activate_address_code(
    db: &crate::core::storage::Database,
    code: &str,
    email_address: &str,
    factory: &crate::core::factory::EnvFactory,
) -> crate::core::errors::AppResult<(String, i64)> {
    let hash = crate::core::api::auth::sha256_hex(code);
    let (system_id, bound_email) = db.lookup_activation_code(&hash).await?.ok_or_else(|| {
        crate::core::errors::AppError::ActivationCodeGone(
            "invalid or expired activation code".into(),
        )
    })?;
    // Codes generated for a specific address (register_address) are bound to it.
    // Batch codes (platform/system) carry an empty binding and accept any address.
    if !bound_email.is_empty() && !email_address.eq_ignore_ascii_case(&bound_email) {
        return Err(crate::core::errors::AppError::Forbidden(
            "activation code is bound to a different address".into(),
        ));
    }
    // Atomically claim the code (UPDATE ... WHERE claimed = 0) so concurrent
    // redemptions of the same code cannot both create keys.
    let claimed = db
        .claim_activation_code(&hash, email_address)
        .await
        .map_err(|e| crate::core::errors::AppError::Internal(format!("claim code: {e}")))?;
    if !claimed {
        return Err(crate::core::errors::AppError::ActivationCodeGone(
            "activation code already redeemed".into(),
        ));
    }

    let (raw_key, key_hash, key_prefix) = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let raw_bytes: [u8; 32] = rng.gen();
        let raw_key = hex::encode(raw_bytes);
        let hash = crate::core::api::auth::sha256_hex(&raw_key);
        let prefix = raw_key[..8].to_string();
        (raw_key, hash, prefix)
    };

    // Address activation codes always produce an agent-scope key.
    let actual_scopes: Vec<String> = vec!["agent".to_string()];

    let key_id = factory
        .upsert_api_key(ApiKeyParams::new(
            &system_id,
            email_address,
            &key_hash,
            &key_prefix,
            &actual_scopes,
            None,
            "agent",
        ))
        .await
        .map_err(|e| crate::core::errors::AppError::Internal(format!("create key: {e}")))?;

    db.ensure_agent_address_domain(&system_id, email_address)
        .await?;
    db.delete_activation_code(&hash).await?;
    Ok((raw_key, key_id))
}

// ── Rate limiter for public activation endpoint ──────────────────

static ACTIVATION_ATTEMPTS: std::sync::LazyLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const ACTIVATION_MAX_FAILURES: u32 = 10;
const ACTIVATION_BLOCK_SECS: u64 = 300;

fn check_activation_limit(ip: IpAddr) -> bool {
    let mut map = ACTIVATION_ATTEMPTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Prune entries whose block window has fully elapsed. Without this, an IP
    // that accumulates failures and later cools off would keep its stale
    // (count, since) entry forever (unbounded map growth).
    map.retain(|_, (_, since)| since.elapsed() < Duration::from_secs(ACTIVATION_BLOCK_SECS));
    if let Some((count, since)) = map.get(&ip) {
        if *count >= ACTIVATION_MAX_FAILURES
            && since.elapsed() < Duration::from_secs(ACTIVATION_BLOCK_SECS)
        {
            return false;
        }
    }
    true
}

fn record_activation_failure(ip: IpAddr) {
    let mut map = ACTIVATION_ATTEMPTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let entry = map.entry(ip).or_insert((0, Instant::now()));
    entry.0 += 1;
}

fn clear_activation_limit(ip: IpAddr) {
    ACTIVATION_ATTEMPTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&ip);
}

// ── Handlers ──────────────────────────────────────────────────────

/// D12: parse the `count` field of a batch-code request. `None` field ->
/// default 1; out of `[1, MAX_CODE_BATCH]` (or not fitting u32 on narrow
/// targets) -> `None` so the caller rejects with 400 instead of silently
/// narrowing.
const MAX_CODE_BATCH: u64 = 10_000;

fn parse_code_count(v: Option<&serde_json::Value>) -> Option<u32> {
    let c = v.and_then(|x| x.as_u64())?;
    // MAX_CODE_BATCH (10_000) is far below u32::MAX, so fitting the range
    // also guarantees the narrowing to u32 is lossless on any target.
    (1..=MAX_CODE_BATCH).contains(&c).then_some(c as u32)
}

pub async fn batch_generate_codes(
    State(state): State<HttpState>,
    Extension(api_key): Extension<ApiKeyRecord>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["platform", "system"])?;
    let code_type = body
        .get("code_type")
        .and_then(|v| v.as_str())
        .unwrap_or("address");
    if code_type != "address" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Only code_type=address is supported".to_string(),
                detail: None,
            }),
        ));
    }
    let system_id = body.get("system_id").and_then(|v| v.as_str()).unwrap_or("");
    let domain = body.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let email = body.get("email_address").and_then(|v| v.as_str());
    // D12: `count` arrives as u64 (JSON number) and is narrowed to u32 —
    // validated in parse_code_count (no silent truncation, bounded batch).
    // Field absent keeps the original default of 1.
    let count = match body.get("count") {
        None => 1,
        Some(v) => match parse_code_count(Some(v)) {
            Some(c) => c,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "count must be in [1, 10000]".to_string(),
                        detail: None,
                    }),
                ))
            }
        },
    };

    if let Some(email) = email {
        let record = state
            .factories
            .email
            .env_factory
            .lookup_domain_addr(email)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Database error".to_string(),
                        detail: Some(e.to_string()),
                    }),
                )
            })?;
        match record {
            None => return Err((StatusCode::PRECONDITION_FAILED, Json(ErrorResponse {
                error: "Cannot generate activation code: email address not registered. Register first via POST /api/v1/admin/systems/{sid}/domains".to_string(),
                detail: None,
            }))),
            Some(ref r) if !r.is_active => return Err((StatusCode::PRECONDITION_FAILED, Json(ErrorResponse {
                error: "Cannot generate activation code: domain registration is inactive".to_string(),
                detail: None,
            }))),
            Some(ref r) if r.webhook_url.as_deref().unwrap_or("").is_empty() => return Err((StatusCode::PRECONDITION_FAILED, Json(ErrorResponse {
                error: "Cannot generate activation code: address has no webhook routing configured".to_string(),
                detail: None,
            }))),
            _ => {}
        }
    }

    let raw_codes = generate_activation_codes(
        &state.factories.email.env_factory.db,
        system_id,
        domain,
        email,
        count.clamp(1, 100),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate codes".to_string(),
                detail: Some(e.to_string()),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({ "raw_codes": raw_codes })))
}

pub async fn activate_address_handler(
    State(state): State<HttpState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let ip = addr.ip();

    // Rate limit check
    if !check_activation_limit(ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many activation attempts. Please try again later.".to_string(),
                detail: None,
            }),
        ));
    }

    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let email = body
        .get("email_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let email_domain = email.rsplit('@').next().unwrap_or("");
    if !email_domain.is_empty() {
        // Domain-anchor lookup mirrors register_address: non-shared keys
        // resolve on the bare domain; shared-domain systems resolve on
        // their system anchor (system_name@email_domain) — same table,
        // same lookup, only the key differs.
        let code_hash = crate::core::api::auth::sha256_hex(code);
        let sys_id = state
            .factories
            .email
            .env_factory
            .db
            .lookup_activation_code(&code_hash)
            .await
            .ok()
            .flatten()
            .map(|(sid, _)| sid)
            .unwrap_or_default();
        let lookup_key = if sys_id.starts_with("shared-") {
            let sys_name = email
                .split('@')
                .next()
                .unwrap_or("")
                .rsplit('.')
                .next()
                .unwrap_or("");
            format!("{}@{}", sys_name, email_domain)
        } else {
            email_domain.to_string()
        };
        let has_domain = state
            .factories
            .email
            .env_factory
            .lookup_domain_addr(&lookup_key)
            .await
            .map(|r| r.is_some())
            .unwrap_or(false);
        if !has_domain {
            record_activation_failure(ip);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Domain not registered".to_string(),
                    detail: Some(format!(
                        "Domain '{}' has not been added. Register it first via POST /api/v1/admin/systems/{{sid}}/domains",
                        email_domain
                    )),
                }),
            ));
        }
    }

    let (raw_key, api_key_id) = activate_address_code(
        &state.factories.email.env_factory.db,
        code,
        email,
        &state.factories.email.env_factory,
    )
    .await
    .map_err(|e| {
        record_activation_failure(ip);
        let code = e.status(); // D4: variant → status (single exit)
        (
            code,
            Json(ErrorResponse {
                error: "Activation failed".to_string(),
                detail: Some(e.to_string()),
            }),
        )
    })?;

    clear_activation_limit(ip);

    let body = Json(serde_json::json!({
        "status": "activated", "raw_key": raw_key, "api_key_id": api_key_id, "email_address": email,
    }));
    Ok((StatusCode::OK, body))
}

// ── Base standalone activation API (not mounted by advanced) ─────────
//
// These handlers are composed only by the base binary (`src/server.rs`).
// Advanced depends on the library and mounts its own activation routes, so
// there is no duplicate-route risk and no shared policy layer.

fn activation_error(
    status: StatusCode,
    error: &str,
    detail: Option<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            detail,
        }),
    )
}

fn is_expired(expires_at: Option<&str>) -> bool {
    let Some(raw) = expires_at else { return false };
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(t) => t.with_timezone(&chrono::Utc) <= chrono::Utc::now(),
        Err(_) => false,
    }
}

/// POST /api/v1/public/activation-code/preflight {code}
/// Returns code metadata WITHOUT consuming the code.
pub async fn preflight_activation_code_handler(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if code.is_empty() {
        return Json(serde_json::json!({"valid": false, "error": "code is required"}));
    }
    let hash = crate::core::api::auth::sha256_hex(code);
    let meta = state
        .factories
        .email
        .env_factory
        .db
        .lookup_activation_code_meta(&hash)
        .await
        .ok()
        .flatten();
    let Some((code_type, system_id, domain, email, claimed, expires_at, frozen)) = meta else {
        return Json(serde_json::json!({"valid": false, "error": "unknown activation code"}));
    };
    let expired = is_expired(expires_at.as_deref());
    let scope = if system_id.starts_with("shared-") || system_id.starts_with("shared_") {
        "shared"
    } else {
        "system"
    };
    Json(serde_json::json!({
        "valid": !claimed && !frozen && !expired,
        "code_type": code_type,
        "scope": scope,
        "system_id": system_id,
        "domain": domain,
        "system_name": "",
        "email_address": email,
        "claimed": claimed,
        "is_frozen": frozen,
        "expires_at": expires_at,
        "error": if claimed { "already claimed" } else if frozen { "frozen" } else if expired { "expired" } else { "" },
    }))
}

/// POST /api/v1/activate-system {code, system_name?, domain?, manager?}
/// Base is single-system: the code names the existing system/domain; activation
/// mints an agent-side system key for it. No product/quota layer.
pub async fn activate_system_handler(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if code.is_empty() {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "code is required",
            None,
        ));
    }
    let hash = crate::core::api::auth::sha256_hex(code);
    let meta = state
        .factories
        .email
        .env_factory
        .db
        .lookup_activation_code_meta(&hash)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?
        .ok_or_else(|| {
            activation_error(StatusCode::GONE, "invalid or expired activation code", None)
        })?;
    let (code_type, meta_sid, meta_domain, _email, claimed, expires_at, frozen) = meta;
    if code_type != "product" && code_type != "system" {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "this is not a system activation code",
            None,
        ));
    }
    if claimed || frozen || is_expired(expires_at.as_deref()) {
        return Err(activation_error(
            StatusCode::GONE,
            "activation code is not redeemable",
            None,
        ));
    }
    let req_domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !meta_domain.is_empty() && !req_domain.is_empty() && meta_domain.to_lowercase() != req_domain
    {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "activation code is bound to a different domain",
            Some(meta_domain),
        ));
    }
    let domain = if !req_domain.is_empty() {
        req_domain
    } else {
        meta_domain.to_lowercase()
    };
    let sid = if meta_sid.is_empty() {
        "admin".to_string()
    } else {
        meta_sid
    };
    let manager = body
        .get("manager")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let claimed_ok = state
        .factories
        .email
        .env_factory
        .db
        .claim_activation_code(&hash, if manager.is_empty() { &sid } else { &manager })
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "claim failed",
                Some(e.to_string()),
            )
        })?;
    if !claimed_ok {
        return Err(activation_error(
            StatusCode::CONFLICT,
            "activation code already redeemed",
            None,
        ));
    }

    let (raw_key, key_hash, key_prefix) = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let raw_bytes: [u8; 32] = rng.gen();
        let raw_key = hex::encode(raw_bytes);
        let hash = crate::core::api::auth::sha256_hex(&raw_key);
        let prefix = raw_key[..8].to_string();
        (raw_key, hash, prefix)
    };
    state
        .factories
        .email
        .env_factory
        .upsert_api_key(ApiKeyParams::new(
            &sid,
            "",
            &key_hash,
            &key_prefix,
            &["system".to_string()],
            None,
            "system",
        ))
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key creation failed",
                Some(e.to_string()),
            )
        })?;

    let domains = state
        .factories
        .email
        .env_factory
        .list_domains_by_system(&sid)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|d| d.domain)
                .filter(|d| !d.contains('@'))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let domains = if domains.is_empty() && !domain.is_empty() {
        vec![domain.clone()]
    } else {
        domains
    };

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "status": "activated",
            "raw_key": raw_key,
            "system_id": sid,
            "domain": domain,
            "domains": domains,
            "system_name": body.get("system_name").and_then(|v| v.as_str()).unwrap_or(""),
            "manager_address": manager,
            "kind": "new",
        })),
    ))
}

/// POST /api/v1/activate-address-code {code, email_address}
/// Same credential as /activate-address, but returns the system binding and
/// kind so a client can route/renew without a second lookup.
pub async fn activate_address_code_compat_handler(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let email = body
        .get("email_address")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if code.is_empty() || !email.contains('@') {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "code and email_address are required",
            None,
        ));
    }
    let hash = crate::core::api::auth::sha256_hex(code);
    let meta = state
        .factories
        .email
        .env_factory
        .db
        .lookup_activation_code_meta(&hash)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?
        .ok_or_else(|| {
            activation_error(StatusCode::GONE, "invalid or expired activation code", None)
        })?;
    let (_code_type, sid, _domain, _bound, claimed, expires_at, frozen) = meta;
    if claimed || frozen || is_expired(expires_at.as_deref()) {
        return Err(activation_error(
            StatusCode::GONE,
            "activation code is not redeemable",
            None,
        ));
    }
    // A live agent key for the same address means this redemption rotates it.
    let already_active = state
        .factories
        .email
        .env_factory
        .db
        .get_api_key_by_email(&email)
        .await
        .ok()
        .flatten()
        .is_some();
    let (raw_key, _key_id) = activate_address_code(
        &state.factories.email.env_factory.db,
        code,
        &email,
        &state.factories.email.env_factory,
    )
    .await
    .map_err(|e| activation_error(e.status(), "activation failed", Some(e.to_string())))?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "status": "activated",
            "raw_key": raw_key,
            "system_id": sid,
            "email_address": email,
            "kind": if already_active { "rotation" } else { "new" },
            "expires_at": expires_at,
        })),
    ))
}

// ── Public self-service apply (base pilot) ────────────────────────
//
// The gateway has no external SMTP sender on the public path, so the pilot
// simulates the recipient mailbox: verification and activation codes are
// appended to `mock_inbox` and the /apply webapp/API reads them back. The
// production replacement is SMTP delivery; the API shape stays the same.

fn random_six_digits() -> String {
    use rand::Rng;
    format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32))
}

fn random_code(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let parts: Vec<String> = (0..6)
        .map(|_| format!("{:04x}", rng.gen_range(0..0x10000u32) as u16))
        .collect();
    format!("{}-{}", prefix, parts.join("-"))
}

fn verification_email_body(code: &str) -> String {
    format!(
        "Hello,\n\nYour AIMail verification code is:\n\n  {code}\n\nIt expires in 10 minutes. If you did not request this mail, please ignore it.\n\nBest regards,\nAIMail Team\n"
    )
}

/// POST /api/v1/public/email-verify/send {email}
pub async fn apply_email_verify_send(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !email.contains('@') {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "valid email is required",
            None,
        ));
    }
    let code = random_six_digits();
    let hash = crate::core::api::auth::sha256_hex(&code);
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let db = &state.factories.email.env_factory.db;
    db.upsert_email_verification(&email, &hash, &expires)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    if let Err(e) = enqueue_apply_email(
        &state,
        &email,
        "AIMail verification code",
        &verification_email_body(&code),
    )
    .await
    {
        db.clear_email_verification(&email).await.ok();
        return Err(e);
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "sent",
            "email": email,
            "expires_at": expires,
            "mock_inbox": format!("/api/v1/public/mock-inbox?email={}", urlencoding(&email)),
        })),
    ))
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '@' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

/// Queue an application email through the real outbound pipeline (the
/// advanced gateway's pattern): create_outbound + first-delivery trigger.
/// The pilot's simulated inbox reads these queued rows back by recipient.
async fn enqueue_apply_email(
    state: &HttpState,
    to_email: &str,
    subject: &str,
    body: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let from = state.config.system_sender();
    let recipients = serde_json::json!({ "to": [to_email], "cc": [] }).to_string();
    let id = format!("apply-{}", uuid::Uuid::new_v4());
    state
        .factories
        .email
        .create_outbound(
            &id,
            "admin",
            &from,
            &recipients,
            subject,
            body,
            None,
            None,
            None,
            state.config.retry.max_attempts as i32,
        )
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::BAD_GATEWAY,
                "failed to queue email",
                Some(e.to_string()),
            )
        })?;
    state.dispatch_first_delivery(&id);
    Ok(())
}

/// POST /api/v1/public/email-verify/check {email, code}
pub async fn apply_email_verify_check(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !email.contains('@') || code.is_empty() {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "email and code are required",
            None,
        ));
    }
    let db = &state.factories.email.env_factory.db;
    let row = db
        .get_email_verification(&email)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?
        .ok_or_else(|| {
            activation_error(
                StatusCode::BAD_REQUEST,
                "no verification request for this email",
                None,
            )
        })?;
    let (hash, expires, _verified) = row;
    if is_expired(Some(&expires)) {
        return Err(activation_error(
            StatusCode::GONE,
            "verification code expired",
            None,
        ));
    }
    if crate::core::api::auth::sha256_hex(code) != hash {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "verification code mismatch",
            None,
        ));
    }
    db.mark_email_verified(&email).await.map_err(|e| {
        activation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error",
            Some(e.to_string()),
        )
    })?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "verified", "email": email})),
    ))
}

/// GET /api/v1/public/mock-inbox?email=...
pub async fn apply_mock_inbox(
    State(state): State<HttpState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let email = q
        .get("email")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if !email.contains('@') {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "email is required",
            None,
        ));
    }
    let mail = state
        .factories
        .email
        .env_factory
        .db
        .list_outbound_for_recipient(&email, 20)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    let items: Vec<serde_json::Value> = mail
        .into_iter()
        .map(|(id, subject, body, created_at)| {
            serde_json::json!({
                "id": id, "subject": subject, "body": body, "created_at": created_at
            })
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"email": email, "messages": items})),
    ))
}

/// GET /api/v1/public/system/domains — current single system's bare domains.
pub async fn apply_system_domains(
    State(state): State<HttpState>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let rows = state
        .factories
        .email
        .env_factory
        .db
        .current_system_domains()
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    let domains: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(sid, domain)| {
            serde_json::json!({
                "system_id": sid, "domain": domain
            })
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"domains": domains})),
    ))
}

async fn require_verified(
    state: &HttpState,
    email: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let row = state
        .factories
        .email
        .env_factory
        .db
        .get_email_verification(email)
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?
        .ok_or_else(|| activation_error(StatusCode::BAD_REQUEST, "verify the email first", None))?;
    let (_, expires, verified) = row;
    if !verified {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "email is not verified",
            None,
        ));
    }
    if is_expired(Some(&expires)) {
        return Err(activation_error(
            StatusCode::GONE,
            "email verification expired; verify again",
            None,
        ));
    }
    Ok(())
}

fn system_activation_email(name: &str, domain: &str, code: &str, gateway_url: &str) -> String {
    let greeting = if name.is_empty() {
        "Hello,".to_string()
    } else {
        format!("Hello {name},")
    };
    format!(
        "{greeting}\n\nAn AIMail system is ready for your agent:\n\n  system: {domain}\n\nPlease activate it within 7 days.\n\nCopy the message below into your agent's conversation and let the agent activate the system:\n\nActivate my AIMail system {domain} using the activation code {code}. AIMail gateway is at {gateway_url}. Follow the step-by-step instructions at https://raw.githubusercontent.com/metercai/aimail/main/docs/agent-self-setup.md\n\nThis code is sent only once - please keep this email.\nPlease do not reply to this email - it is sent automatically.\n\nBest regards,\nAIMail Team\n"
    )
}

fn address_activation_email(
    name: &str,
    address: &str,
    code: &str,
    manager: &str,
    gateway_url: &str,
) -> String {
    let greeting = if name.is_empty() {
        "Hello,".to_string()
    } else {
        format!("Hello {name},")
    };
    format!(
        "{greeting}\n\nAn AIMail mailbox is ready for your agent:\n\n  address: {address}\n\nPlease activate it within 24 hours.\n\nCopy the message below into your agent's conversation and let the agent bind the address:\n\nActivate my AIMail mailbox {address} using the activation code {code}. My safety officer (manager) is {manager}. AIMail gateway is at {gateway_url}. Follow the step-by-step instructions at https://raw.githubusercontent.com/metercai/aimail/main/docs/agent-self-setup.md\n\nThis code is sent only once - please keep this email.\nPlease do not reply to this email - it is sent automatically.\n\nBest regards,\nAIMail Team\n"
    )
}

/// POST /api/v1/public/apply-system {email, name, domain}
pub async fn apply_system_public(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !email.contains('@') || domain.is_empty() {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "email and domain are required",
            None,
        ));
    }
    require_verified(&state, &email).await?;
    let domains = state
        .factories
        .email
        .env_factory
        .db
        .current_system_domains()
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    let Some((sid, _)) = domains
        .into_iter()
        .find(|(_, d)| d.eq_ignore_ascii_case(&domain))
    else {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "domain is not offered by this gateway",
            None,
        ));
    };
    let code = random_code("sys");
    let hash = crate::core::api::auth::sha256_hex(&code);
    let expires = (chrono::Utc::now() + chrono::Duration::days(ACTIVATION_CODE_TTL_DAYS))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let db = &state.factories.email.env_factory.db;
    db.insert_activation_code(&hash, &code, "product", &sid, &domain, "", Some(&expires))
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    let gateway_url = crate::core::server::api_endpoint_url(&state.config);
    let body = system_activation_email(name, &domain, &code, &gateway_url);
    if let Err(e) =
        enqueue_apply_email(&state, &email, "Your AIMail system activation code", &body).await
    {
        db.delete_activation_code(&hash).await.ok();
        return Err(e);
    }
    db.clear_email_verification(&email).await.ok();
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created", "email": email, "system_id": sid, "domain": domain, "activation_code": code,
            "mock_inbox": format!("/api/v1/public/mock-inbox?email={}", urlencoding(&email)),
        })),
    ))
}

/// POST /api/v1/public/apply-address {email, name, agentname, domain}
pub async fn apply_address_public(
    State(state): State<HttpState>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let agentname = body
        .get("agentname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let domain = body
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if !email.contains('@') || agentname.is_empty() || domain.is_empty() {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "email, agentname and domain are required",
            None,
        ));
    }
    if !agentname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "invalid agentname",
            None,
        ));
    }
    require_verified(&state, &email).await?;
    let domains = state
        .factories
        .email
        .env_factory
        .db
        .current_system_domains()
        .await
        .map_err(|e| {
            activation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
                Some(e.to_string()),
            )
        })?;
    let Some((sid, _)) = domains
        .into_iter()
        .find(|(_, d)| d.eq_ignore_ascii_case(&domain))
    else {
        return Err(activation_error(
            StatusCode::BAD_REQUEST,
            "domain is not offered by this gateway",
            None,
        ));
    };
    let address = format!("{}@{}", agentname, domain);
    let db = &state.factories.email.env_factory.db;
    let codes = crate::core::api::activation::generate_activation_codes(
        db,
        &sid,
        &domain,
        Some(&address),
        1,
    )
    .await
    .map_err(|e| {
        activation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error",
            Some(e.to_string()),
        )
    })?;
    let code = codes.into_iter().next().unwrap_or_default();
    let gateway_url = crate::core::server::api_endpoint_url(&state.config);
    let body = address_activation_email(name, &address, &code, &email, &gateway_url);
    if let Err(e) = enqueue_apply_email(
        &state,
        &email,
        &format!("AIMail address activation code for {address}"),
        &body,
    )
    .await
    {
        db.delete_activation_code(&crate::core::api::auth::sha256_hex(&code))
            .await
            .ok();
        return Err(e);
    }
    db.clear_email_verification(&email).await.ok();
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "created", "email": email, "system_id": sid, "domain": domain, "address": address, "activation_code": code,
            "mock_inbox": format!("/api/v1/public/mock-inbox?email={}", urlencoding(&email)),
        })),
    ))
}

/// GET /apply — pilot SPA (system/address claim + mock inbox).
pub async fn apply_page() -> Html<&'static str> {
    Html(APPLY_PAGE)
}

const APPLY_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claim Activation Code - AIMail</title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--border:#2d3143;--primary:#5b6af0;--primary-hover:#4a58d4;--text:#e4e6eb;--label:#8b8fa3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,sans-serif}
main{max-width:440px;margin:56px auto;padding:0 16px}h1{font-size:20px;margin:0 0 8px}
p.lead{color:var(--label);font-size:13px;margin:0 0 20px}
section{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;margin:14px 0}
h2{font-size:14px;margin:0 0 12px}label{display:block;color:var(--label);font-size:13px;margin:10px 0 5px}
input,select{width:100%;padding:10px;background:#11141d;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px}
.row{display:flex;gap:8px}.row>*{flex:1}
button{padding:10px 14px;border:0;border-radius:8px;background:var(--primary);color:#fff;font-size:13px;cursor:pointer}
button:hover{background:var(--primary-hover)}button.secondary{background:#252938;color:var(--text)}
pre{background:#11141d;border:1px solid var(--border);border-radius:8px;padding:10px;white-space:pre-wrap;font-size:12px;color:var(--text)}
#msg{font-size:13px;color:#6ee7a8;margin-top:10px}#msg.err{color:#f28b82}.muted{color:var(--label);font-size:12px}
</style></head><body><main>
<h1>Claim Activation Code</h1>
<p class="lead">Verify your email, then claim a system or address activation code. Codes are also delivered to the simulated inbox.</p>
<section><h2>1. Email verification</h2>
<label for="email">Email</label><input id="email" placeholder="you@example.com" autocomplete="email">
<div class="row"><button onclick="sendCode()">Send code</button><button class="secondary" onclick="checkCode()">Verify</button></div>
<label for="vcode">Verification code</label><input id="vcode" placeholder="6-digit code" inputmode="numeric">
<div id="msg"></div><button class="secondary" onclick="showInbox()">Open simulated inbox</button><pre id="inbox"></pre>
</section>
<section><h2>2. Claim system code</h2>
<div class="row"><label for="sname">Name<input id="sname"></label><label for="sdomain">Domain<select id="sdomain"></select></label></div>
<button onclick="applySystem()">Claim system activation code</button></section>
<section><h2>3. Claim address code</h2>
<div class="row"><label for="aname">Name<input id="aname"></label><label for="agentname">Agent name<input id="agentname" placeholder="alice"></label><label for="adomain">Domain<select id="adomain"></select></label></div>
<button onclick="applyAddress()">Claim address activation code</button></section>
<section><h2>Result</h2><pre id="out"></pre><p class="muted">Codes are single-use. Keep the email.</p></section>
</main>
<script>
const $=id=>document.getElementById(id);const msg=(t,e)=>{$('msg').textContent=t;$('msg').className=e?'err':''};
async function j(url,opt){const r=await fetch(url,opt);const t=await r.text();let v;try{v=JSON.parse(t)}catch{v={raw:t}}if(!r.ok)throw new Error(v.error||v.detail||t);return v}
async function loadDomains(){try{const v=await j('/api/v1/public/system/domains');for(const sel of ['sdomain','adomain']){$(sel).innerHTML=v.domains.map(d=>`<option value="${d.domain}">${d.domain}</option>`).join('')}}catch(e){msg(e.message,1)}}
async function sendCode(){try{await j('/api/v1/public/email-verify/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:$('email').value})});$('out').textContent='Verification code sent to the simulated inbox.';showInbox()}catch(e){msg(e.message,1)}}
async function checkCode(){try{await j('/api/v1/public/email-verify/check',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:$('email').value,code:$('vcode').value})});msg('Email verified.',0)}catch(e){msg(e.message,1)}}
async function showInbox(){try{const v=await j('/api/v1/public/mock-inbox?email='+encodeURIComponent($('email').value));$('inbox').textContent=v.messages.map(m=>`#${m.id} ${m.subject}\n${m.body}`).join('\n---\n')}catch(e){$('inbox').textContent=e.message}}
async function applySystem(){try{const v=await j('/api/v1/public/apply-system',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:$('email').value,name:$('sname').value,domain:$('sdomain').value})});$('out').textContent=JSON.stringify(v,null,2);showInbox()}catch(e){msg(e.message,1)}}
async function applyAddress(){try{const v=await j('/api/v1/public/apply-address',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:$('email').value,name:$('aname').value,agentname:$('agentname').value,domain:$('adomain').value})});$('out').textContent=JSON.stringify(v,null,2);showInbox()}catch(e){msg(e.message,1)}}
loadDomains();
</script></body></html>"#;

/// Base-only activation router (composed by src/server.rs, never by advanced).
pub fn base_activation_router(state: HttpState) -> Router {
    Router::new()
        .route(
            "/api/v1/public/activation-code/preflight",
            post(preflight_activation_code_handler),
        )
        .route("/api/v1/activate-system", post(activate_system_handler))
        .route(
            "/api/v1/activate-address-code",
            post(activate_address_code_compat_handler),
        )
        .route(
            "/api/v1/public/email-verify/send",
            post(apply_email_verify_send),
        )
        .route(
            "/api/v1/public/email-verify/check",
            post(apply_email_verify_check),
        )
        .route("/api/v1/public/mock-inbox", get(apply_mock_inbox))
        .route("/api/v1/public/system/domains", get(apply_system_domains))
        .route("/api/v1/public/apply-system", post(apply_system_public))
        .route("/api/v1/public/apply-address", post(apply_address_public))
        .route("/apply", get(apply_page))
        .with_state(state)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::strategy::BaseSystemStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_env_factory() -> (
        crate::core::storage::Database,
        crate::core::factory::EnvFactory,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-act-test-{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::core::storage::Database::open(dir.join("aimail.db"), 4, None).unwrap();
        let factory = crate::core::factory::EnvFactory::new(
            std::sync::Arc::new(db.clone()),
            std::sync::Arc::new(BaseSystemStore),
        );
        (db, factory)
    }

    async fn insert_code(db: &crate::core::storage::Database, code: &str, email: &str) {
        let hash = crate::core::api::auth::sha256_hex(code);
        db.insert_activation_code(&hash, code, "address", "sys-test", "test.com", email, None)
            .await
            .unwrap();
    }

    // P1-1: activation codes must never yield non-agent scopes.
    #[tokio::test]
    async fn activate_code_produces_agent_scope_key() {
        let (db, factory) = temp_env_factory();
        insert_code(&db, "addr-test-0001", "alice@test.com").await;

        let (raw_key, _) = activate_address_code(&db, "addr-test-0001", "alice@test.com", &factory)
            .await
            .expect("activation must succeed");

        let rec = factory
            .db
            .verify_api_key(&crate::core::api::auth::sha256_hex(&raw_key))
            .await
            .unwrap()
            .expect("key must exist");
        assert_eq!(rec.scopes, vec!["agent".to_string()]);
        assert_eq!(rec.category, "agent");
        assert_eq!(rec.email_address, "alice@test.com");
    }

    // P1-1: a code bound to one address cannot be activated for another.
    #[tokio::test]
    async fn activate_code_rejects_unbound_address() {
        let (db, factory) = temp_env_factory();
        insert_code(&db, "addr-test-0002", "alice@test.com").await;

        let err = activate_address_code(&db, "addr-test-0002", "bob@test.com", &factory)
            .await
            .expect_err("bound code must reject a different address");
        assert!(err.to_string().contains("bound to a different address"));

        // Case-insensitive match on the bound address still works.
        let (raw_key, _) = activate_address_code(&db, "addr-test-0002", "Alice@Test.COM", &factory)
            .await
            .expect("case-insensitive bound match must succeed");
        let rec = factory
            .db
            .verify_api_key(&crate::core::api::auth::sha256_hex(&raw_key))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.email_address, "Alice@Test.COM");
    }

    // P1-1: batch codes (empty binding) remain usable with any address.
    #[tokio::test]
    async fn activate_code_empty_binding_accepts_any_address() {
        let (db, factory) = temp_env_factory();
        insert_code(&db, "addr-test-0003", "").await;

        let (raw_key, _) = activate_address_code(&db, "addr-test-0003", "carol@test.com", &factory)
            .await
            .expect("unbound batch code must accept any address");
        let rec = factory
            .db
            .verify_api_key(&crate::core::api::auth::sha256_hex(&raw_key))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.scopes, vec!["agent".to_string()]);
    }

    // P1-1: concurrent redemptions of one code must yield exactly one key —
    // the claim is an atomic UPDATE ... WHERE claimed = 0, so the loser
    // gets affected=0 (or a None lookup if it reads after the claim) and is
    // rejected instead of minting a second key. The exact loser message
    // depends on interleaving, so we assert the invariant, not the wording.
    #[tokio::test]
    async fn concurrent_activation_of_same_code_yields_single_key() {
        let (db, factory) = temp_env_factory();
        insert_code(&db, "addr-test-race", "race@test.com").await;

        let (r1, r2) = tokio::join!(
            activate_address_code(&db, "addr-test-race", "race@test.com", &factory),
            activate_address_code(&db, "addr-test-race", "race@test.com", &factory),
        );
        let ok_count = [r1.as_ref(), r2.as_ref()]
            .iter()
            .filter(|r| r.is_ok())
            .count();
        assert_eq!(ok_count, 1, "exactly one concurrent redemption may succeed");
        let loser = [r1, r2]
            .into_iter()
            .find_map(|r| r.err())
            .expect("one side must fail");
        let msg = loser.to_string();
        assert!(
            msg.contains("already redeemed") || msg.contains("invalid or expired"),
            "loser must be rejected, got: {msg}"
        );
        // Exactly one key minted for the address.
        let key = db
            .get_api_key_by_email("race@test.com")
            .await
            .expect("key lookup")
            .expect("one key must exist");
        assert_eq!(key.scopes, vec!["agent".to_string()]);
    }

    // ── D7: a panic while holding the lock must not brick the limiter ─────
    #[test]
    fn d7_poisoned_activation_lock_still_serves_requests() {
        use std::panic;
        let ip = "203.0.113.7".parse::<IpAddr>().unwrap();
        // Poison the lock: lock it and panic while holding it.
        let _ = panic::catch_unwind(|| {
            let _g = ACTIVATION_ATTEMPTS.lock().unwrap();
            panic!("inject");
        });
        assert!(ACTIVATION_ATTEMPTS.is_poisoned(), "setup: lock is poisoned");

        // The next normal check must still work (into_inner, not a panic
        // into 500s), and the limiter must behave as before.
        assert!(
            check_activation_limit(ip),
            "poisoned lock must not block normal traffic"
        );
        for _ in 0..ACTIVATION_MAX_FAILURES {
            record_activation_failure(ip);
        }
        assert!(
            !check_activation_limit(ip),
            "failure cap still enforced after poison"
        );
        clear_activation_limit(ip);
        assert!(check_activation_limit(ip), "clear works after poison");
    }
}

#[cfg(test)]
mod activation_status_tests {
    use crate::core::errors::{app_error_status, AppError};
    use axum::http::StatusCode;

    #[test]
    fn d4_double_spend_maps_to_gone() {
        // A second redeem of a consumed code must be 410, not 500 (v1.0.7
        // contract). D4: the *state* (error variant) decides the status —
        // no wording inspection.
        assert_eq!(
            app_error_status(&AppError::ActivationCodeGone(
                "activation code already redeemed".into()
            )),
            StatusCode::GONE
        );
        assert_eq!(
            app_error_status(&AppError::ActivationCodeGone(
                "activation code expired".into()
            )),
            StatusCode::GONE
        );
    }

    #[test]
    fn d4_activation_status_contract() {
        // Only the gone state is 410 — an unknown/internal failure must not
        // silently become 410 (the old string matcher's failure mode).
        assert_eq!(
            app_error_status(&AppError::Internal("claim code: boom".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            app_error_status(&AppError::Forbidden(
                "activation code is bound to a different address".into()
            )),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn d12_code_count_parsing_rejects_out_of_range() {
        use super::parse_code_count;
        use serde_json::json;
        assert_eq!(
            parse_code_count(None),
            None,
            "absent field -> caller default"
        );
        assert_eq!(parse_code_count(Some(&json!(1))), Some(1));
        assert_eq!(parse_code_count(Some(&json!(10_000))), Some(10_000));
        assert_eq!(
            parse_code_count(Some(&json!(10_001))),
            None,
            "above batch cap"
        );
        assert_eq!(parse_code_count(Some(&json!(0))), None, "zero rejected");
        assert_eq!(
            parse_code_count(Some(&json!(u32::MAX as u64 + 1))),
            None,
            "does not fit u32 (defensive on narrow targets)"
        );
        // u32::MAX itself exceeds the batch cap, so it is rejected by the cap
        // (the u32-fit check is a belt-and-braces guard for narrow targets).
        assert_eq!(parse_code_count(Some(&json!(u32::MAX as u64))), None);
    }
    #[test]
    fn activation_code_format_is_unified() {
        use super::random_code;
        let re = regex::Regex::new(r"^(sys|addr)-([0-9a-f]{4}-){5}[0-9a-f]{4}$").unwrap();
        for prefix in ["sys", "addr"] {
            let code = random_code(prefix);
            assert!(re.is_match(&code), "bad code: {code}");
        }
    }

    #[test]
    fn email_templates_are_english_and_advanced_aligned() {
        let sys = super::system_activation_email(
            "Ada",
            "test.local",
            "sys-1111-2222-3333-4444-5555-6666",
            "http://gw",
        );
        assert!(sys.contains("within 7 days"));
        assert!(sys.contains("Activate my AIMail system test.local"));
        assert!(
            !sys.contains("dsh") && !sys.contains("renew") && !sys.contains("valid for the period")
        );
        let addr = super::address_activation_email(
            "Ada",
            "alice@test.local",
            "addr-1111-2222-3333-4444-5555-6666",
            "ada@example.com",
            "http://gw",
        );
        assert!(addr.contains("within 24 hours"));
        assert!(addr.contains("My safety officer (manager) is ada@example.com"));
        assert!(
            !addr.contains("dsh")
                && !addr.contains("renew")
                && !addr.contains("valid for the period")
        );
        let sys_noname = super::system_activation_email(
            "",
            "test.local",
            "sys-1111-2222-3333-4444-5555-6666",
            "http://gw",
        );
        assert!(sys_noname.starts_with("Hello,\n"));
        let addr_noname = super::address_activation_email(
            "",
            "alice@test.local",
            "addr-1111-2222-3333-4444-5555-6666",
            "ada@example.com",
            "http://gw",
        );
        assert!(addr_noname.starts_with("Hello,\n"));
        let verify = super::verification_email_body("123456");
        assert!(verify.contains("It expires in 10 minutes"));
        for text in [&sys, &addr, &verify] {
            assert!(
                !text.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "CJK in email"
            );
            assert!(
                !text.contains("dsh")
                    && !text.contains("renew")
                    && !text.contains("valid for the period")
            );
        }
    }

    #[test]
    fn apply_page_is_english_and_dark() {
        let p = super::APPLY_PAGE;
        assert!(p.contains("lang=\"en\""));
        assert!(p.contains("#0f1117"));
        assert!(p.contains("#5b6af0"));
        assert!(
            !p.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
            "CJK in /apply"
        );
    }
}
