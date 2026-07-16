//! API key management CRUD handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use tracing::info;
use uuid::Uuid;

use crate::core::api::auth::{
    is_agent_admin_scope, is_agent_scope, is_platform_admin_scope, is_system_admin_scope,
    require_agent_match, require_domain_match, require_scope_any, sha256_hex,
};
use crate::core::api::types::*;
use crate::core::storage::ApiKeyRecord;

/// POST /api/v1/api-keys — Create a new API key.
pub async fn create_api_key(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyResponse>), (StatusCode, Json<ErrorResponse>)> {
    if let Err(e) = require_scope_any(&api_key, &["platform", "system", "agent_admin"]) {
        return Err(e);
    }

    // ── Address quota check ──
    {
        let _system = match state
            .email_factory
            .env_factory
            .resolve_system(&req.system_id)
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "System not found".to_string(),
                        detail: None,
                    }),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Database error".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        };
        // Delegate quota check to QuotaChecker trait
        state
            .extensions
            .quota_checker
            .check_key_quota(&req.system_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "quota_exceeded".to_string(),
                        detail: Some(e.to_string()),
                    }),
                )
            })?;
    }

    // ── Category / domain_addr validation ──
    match req.category.as_str() {
        "platform" => {
            if !req.email_address.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_category".to_string(),
                        detail: Some("platform category requires empty email_address".to_string()),
                    }),
                ));
            }
        }
        "system" => {
            if !req.email_address.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_category".to_string(),
                        detail: Some("system category requires empty email_address".to_string()),
                    }),
                ));
            }
        }
        "domain" => {
            if req.email_address.is_empty() || req.email_address.contains('@') {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_category".to_string(),
                        detail: Some("domain category requires bare domain (no '@)".to_string()),
                    }),
                ));
            }
        }
        "agent" => {
            if !req.email_address.contains('@') {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_category".to_string(),
                        detail: Some("agent category requires email address with '@)".to_string()),
                    }),
                ));
            }
        }
        "bridge" => { /* arbitrary domain_addr */ }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_category".to_string(),
                    detail: Some(format!("unknown category: {}", req.category)),
                }),
            ));
        }
    }

    // ── Domain admin scope restriction ──
    // Domain-level admins (bare domain in email_address) may only create keys within their domain.
    // System-level (empty email) and platform admins pass through without restriction.
    if let Err(e) = require_domain_match(&api_key, &req.email_address) {
        return Err(e);
    }

    let raw_key = Uuid::new_v4().to_string().replace('-', "");
    let key_hash = sha256_hex(&raw_key);

    let scopes = if req.scopes.is_empty() {
        vec!["agent".to_string()]
    } else {
        req.scopes
    };

    // ── Hierarchical creation: PA(3) → SA(2) → Agent(1) ──
    let creator_is_pa = is_platform_admin_scope(&api_key);
    let creator_is_sa = is_system_admin_scope(&api_key);
    let creator_level = if creator_is_pa {
        3
    } else if creator_is_sa {
        2
    } else {
        1
    };

    let target_level = if scopes.iter().any(|s| s == "platform") {
        3
    } else if scopes.iter().any(|s| s == "system") {
        2
    } else {
        1
    };

    // System-level key (email="") creating a domain-category key is a
    // de-escalation (narrowing scope from whole system to one domain).
    // Allow same-level creation for this specific case.
    let is_system_to_domain = api_key.email_address.is_empty()
        && req.category == "domain"
        && !req.email_address.is_empty()
        && !req.email_address.contains('@');

    if creator_level <= target_level && !is_system_to_domain {
        let role = if creator_is_pa {
            "platform"
        } else if creator_is_sa {
            "system"
        } else {
            "agent_admin"
        };
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Cannot create key at or above your privilege level".to_string(),
                detail: Some(format!(
                    "Your max scope is '{}' (level {}), cannot create scopes at level {} or above",
                    role, creator_level, target_level,
                )),
            }),
        ));
    }

    // ── Address-level keys must not have admin scopes ──
    // PlatformAdmin and SystemAdmin are system-level roles (email_address="") only.
    // Address-level keys (non-empty email) are restricted to agent/whitelist scopes.
    // EXCEPTION: domain-category keys (bare domain email) may carry system scope
    //   for domain-level administration.
    if !req.email_address.is_empty() && req.category != "domain" {
        let system_scopes: &[&str] = &["platform", "system"];
        for s in &scopes {
            if system_scopes.contains(&s.as_str()) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Invalid scope for address-level key".to_string(),
                        detail: Some(format!(
                            "Scope '{}' is reserved for system-level keys (empty email_address). Address-level keys may only use 'send'/'agent' or 'whitelist'.",
                            s
                        )),
                    }),
                ));
            }
        }
    }

    // ── System scope check ──
    // System admin (admin system) can create keys for any system.
    // All other scopes are limited to keys within their own system.
    if api_key.system_id != "admin" && api_key.system_id != req.system_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some("Cannot create API keys for a different system".into()),
            }),
        ));
    }

    let key_prefix = &raw_key[..8];
    let expires_at = req.expires_at.as_deref();

    let record = match state
        .email_factory
        .env_factory
        .create_api_key(
            &req.system_id,
            &req.email_address,
            &key_hash,
            key_prefix,
            &scopes,
            expires_at,
            &req.category,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };

    info!(operation = "api_key_created", api_key_id = %record.id, system_id = %req.system_id, "API key created");

    let mut response: ApiKeyResponse = record.into();
    response.raw_key = Some(raw_key);
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/api-keys — Lookup API key by email (or list with scope filter).
pub async fn list_api_keys(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<ApiKeyResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let is_platform_admin = is_platform_admin_scope(&api_key);
    let is_system_admin = is_system_admin_scope(&api_key);
    let is_agent_admin = is_agent_admin_scope(&api_key);
    let is_agent = is_agent_scope(&api_key);

    let email_filter = params.get("email");

    let keys = if let Some(email) = email_filter {
        // Lookup by email — only agent/agent_admin/system_admin
        if !is_platform_admin && !is_system_admin && !is_agent_admin {
            // Agent: can only lookup self
            if is_agent && email != &api_key.email_address {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse { error: "Forbidden".to_string(), detail: None }),
                ));
            }
        }
        match state.email_factory.env_factory.resolve_api_key_by_email(email).await {
            Ok(Some(k)) => vec![k],
            Ok(None) => vec![],
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".to_string(), detail: Some(e.to_string()) }))),
        }
    } else if is_platform_admin {
        match state.email_factory.env_factory.list_api_keys().await {
            Ok(keys) => keys,
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".to_string(), detail: Some(e.to_string()) }))),
        }
    } else if is_system_admin || is_agent_admin {
        match state.email_factory.env_factory.list_api_keys_by_system(&api_key.system_id, "agent").await {
            Ok(keys) => keys,
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".to_string(), detail: Some(e.to_string()) }))),
        }
    } else if is_agent {
        match state.email_factory.env_factory.resolve_api_key_by_id(api_key.id).await {
            Ok(Some(k)) => vec![k],
            Ok(None) => vec![],
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".to_string(), detail: Some(e.to_string()) }))),
        }
    } else {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "Insufficient scope".to_string(), detail: None })));
    };

    Ok(Json(keys.into_iter().map(|r| r.into()).collect()))
}

/// GET /api/v1/api-keys/:id — Retrieve a specific API key.
pub async fn get_api_key(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Path(id): Path<i64>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(e) = require_scope_any(&api_key, &["platform", "system", "agent_admin"]) {
        return Err(e);
    }

    let record = match state
        .email_factory
        .env_factory
        .resolve_api_key_by_id(id)
        .await
    {
        Ok(Some(r)) => {
            let match_result = if is_agent_admin_scope(&api_key) {
                require_agent_match(&api_key, &r.email_address)
            } else {
                require_domain_match(&api_key, &r.email_address)
            };
            if let Err(e) = match_result {
                return Err(e);
            }
            r
        }
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "API key not found".to_string(),
                    detail: None,
                }),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };

    Ok(Json(record.into()))
}

/// PUT /api/v1/api-keys/:id — Update an API key (scopes, active, expiration, rotate).
pub async fn update_api_key(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // ── Admin (PA/SA/AA): disable any accessible key, rotate own key ──
    if is_platform_admin_scope(&api_key)
        || is_system_admin_scope(&api_key)
        || is_agent_admin_scope(&api_key)
    {
        // Admin can rotate their own key
        if req.rotate.unwrap_or(false) && id == api_key.id {
            let raw_key = Uuid::new_v4().to_string().replace('-', "");
            let key_hash = sha256_hex(&raw_key);
            let new_prefix = &raw_key[..8];
            match state
                .email_factory
                .env_factory
                .rotate_api_key(id, &key_hash, new_prefix)
                .await
            {
                Ok(Some(record)) => {
                    info!(
                        operation = "api_key_rotated",
                        api_key_id = id,
                        "Admin rotated own key"
                    );
                    let mut response: ApiKeyResponse = record.into();
                    response.raw_key = Some(raw_key);
                    return Ok(Json(response));
                }
                Ok(None) => {
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "API key not found".to_string(),
                            detail: None,
                        }),
                    ));
                }
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Database error".to_string(),
                            detail: Some(e.to_string()),
                        }),
                    ));
                }
            }
        }
        // Admin cannot modify scopes on anyone's key
        if req.scopes.is_some() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Insufficient scope".to_string(),
                    detail: Some(
                        "Admin keys can only disable keys or rotate their own".to_string(),
                    ),
                }),
            ));
        }
        // Verify key exists
        let existing = match state
            .email_factory
            .env_factory
            .resolve_api_key_by_id(id)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "API key not found".to_string(),
                        detail: None,
                    }),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Database error".to_string(),
                        detail: Some(e.to_string()),
                    }),
                ));
            }
        };
        // SA uses domain_match, AA uses agent_match (domain suffix), PA skips
        if !is_platform_admin_scope(&api_key) {
            let match_result = if is_agent_admin_scope(&api_key) {
                require_agent_match(&api_key, &existing.email_address)
            } else {
                require_domain_match(&api_key, &existing.email_address)
            };
            if let Err(e) = match_result {
                return Err(e);
            }
        }
        match state
            .email_factory
            .env_factory
            .update_api_key(id, None, req.is_active)
            .await
        {
            Ok(update_result) => match update_result {
                Some(record) => {
                    info!(
                        operation = "api_key_updated",
                        api_key_id = id,
                        "API key updated by admin"
                    );
                    Ok(Json(record.into()))
                }
                None => Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "API key not found".to_string(),
                        detail: None,
                    }),
                )),
            },
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else if is_agent_scope(&api_key) {
        // Agent can only rotate their own key
        if id != api_key.id {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Agent can only rotate their own key".to_string(),
                    detail: None,
                }),
            ));
        }
        if !req.rotate.unwrap_or(false) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Agent can only rotate their key, not update other fields".to_string(),
                    detail: None,
                }),
            ));
        }
        let raw_key = Uuid::new_v4().to_string().replace('-', "");
        let key_hash = sha256_hex(&raw_key);
        let new_prefix = &raw_key[..8];
        match state
            .email_factory
            .env_factory
            .rotate_api_key(id, &key_hash, new_prefix)
            .await
        {
            Ok(Some(record)) => {
                info!(
                    operation = "api_key_rotated",
                    api_key_id = id,
                    "API key rotated by agent"
                );
                let mut response: ApiKeyResponse = record.into();
                response.raw_key = Some(raw_key);
                Ok(Json(response))
            }
            Ok(None) => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "API key not found".to_string(),
                    detail: None,
                }),
            )),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: None,
            }),
        ));
    }
}

/// DELETE /api/v1/api-keys/:id — Delete an API key.
pub async fn delete_api_key(
    state: State<HttpState>,
    api_key: Extension<ApiKeyRecord>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if let Err(e) = require_scope_any(&api_key, &["platform", "system", "agent_admin"]) {
        return Err(e);
    }

    // Verify key exists and check domain match
    let existing = match state
        .email_factory
        .env_factory
        .resolve_api_key_by_id(id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "API key not found".to_string(),
                    detail: None,
                }),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };

    let match_result = if is_agent_admin_scope(&api_key) {
        require_agent_match(&api_key, &existing.email_address)
    } else {
        require_domain_match(&api_key, &existing.email_address)
    };
    if let Err(e) = match_result {
        return Err(e);
    }

    match state.email_factory.env_factory.delete_api_key(id).await {
        Ok(()) => {
            info!(
                operation = "api_key_deleted",
                api_key_id = id,
                "API key deleted"
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}
