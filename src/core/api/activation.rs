//! Activation code handlers (core).

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::StatusCode,
    response::Json,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::core::api::auth::require_scope_any;
use crate::core::api::types::{ErrorResponse, HttpState};
use crate::core::storage::ApiKeyRecord;

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
        let future = chrono::Utc::now() + chrono::Duration::days(7);
        Some(future.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    };
    let mut codes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let code = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let parts: Vec<String> = (0..6)
                .map(|_| {
                    let val: u32 = rng.gen_range(0..0x10000);
                    format!("{:04x}", val as u16)
                })
                .collect();
            format!("addr-{}", parts.join("-"))
        };
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

/// Redeem an address activation code → creates API key.
pub async fn activate_address_code(
    db: &crate::core::storage::Database,
    code: &str,
    email_address: &str,
    scopes: &[String],
    factory: &crate::core::factory::EnvFactory,
) -> crate::core::errors::AppResult<(String, i64)> {
    let hash = crate::core::api::auth::sha256_hex(code);
    let (system_id, _) = db.lookup_activation_code(&hash).await?.ok_or_else(|| {
        crate::core::errors::AppError::Internal("invalid or expired activation code".into())
    })?;

    let (raw_key, key_hash, key_prefix) = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let raw_bytes: [u8; 32] = rng.gen();
        let raw_key = hex::encode(raw_bytes);
        let hash = crate::core::api::auth::sha256_hex(&raw_key);
        let prefix = raw_key[..8].to_string();
        (raw_key, hash, prefix)
    };

    let actual_scopes: Vec<String> = if scopes.is_empty() {
        vec!["agent".to_string()]
    } else {
        scopes.to_vec()
    };

    let record = factory
        .create_api_key(
            &system_id,
            email_address,
            &key_hash,
            &key_prefix,
            &actual_scopes,
            None,
            "agent",
        )
        .await
        .map_err(|e| crate::core::errors::AppError::Internal(format!("create key: {e}")))?;

    db.delete_activation_code(&hash).await?;
    Ok((raw_key, record.id))
}

// ── Rate limiter for public activation endpoint ──────────────────

static ACTIVATION_ATTEMPTS: std::sync::LazyLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const ACTIVATION_MAX_FAILURES: u32 = 10;
const ACTIVATION_BLOCK_SECS: u64 = 300;

fn check_activation_limit(ip: IpAddr) -> bool {
    let map = ACTIVATION_ATTEMPTS.lock().unwrap();
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
    let mut map = ACTIVATION_ATTEMPTS.lock().unwrap();
    let entry = map.entry(ip).or_insert((0, Instant::now()));
    entry.0 += 1;
}

fn clear_activation_limit(ip: IpAddr) {
    ACTIVATION_ATTEMPTS.lock().unwrap().remove(&ip);
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn batch_generate_codes(
    State(state): State<HttpState>,
    Extension(api_key): Extension<ApiKeyRecord>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(e) = require_scope_any(&api_key, &["platform", "system"]) {
        return Err(e);
    }
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
    let count = body.get("count").and_then(|v| v.as_u64()).unwrap_or(1) as u32;

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
        let meta = state
            .factories
            .email
            .env_factory
            .resolve_domain_addr_meta(email)
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
        if meta.as_ref().map_or(true, |m| m.manager_address.is_empty()) {
            return Err((StatusCode::PRECONDITION_FAILED, Json(ErrorResponse {
                error: "Cannot generate activation code: manager_address not configured for this address".to_string(),
                detail: None,
            })));
        }
    }

    let raw_codes = generate_activation_codes(
        &state.factories.email.env_factory.db,
        system_id,
        domain,
        email,
        count.max(1).min(100),
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
    let scopes: Vec<String> = body
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

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
        &scopes,
        &state.factories.email.env_factory,
    )
    .await
    .map_err(|e| {
        record_activation_failure(ip);
        let code = match e.to_string().as_str() {
            s if s.contains("expired") => StatusCode::GONE,
            s if s.contains("invalid") => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
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
