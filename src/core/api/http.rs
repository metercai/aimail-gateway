//! HTTP router construction and admin CRUD handlers.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::Path,
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;

use tracing::info;

use crate::core::api::activation::activate_address_handler;
use crate::core::api::auth::{
    auth_layer, check_whitelist_access, is_admin_scope, is_agent_admin_scope, is_agent_scope,
    is_platform_admin_scope, is_system_admin_scope, require_domain_match, require_scope_any,
};
use crate::core::api::files::{download_attachment, upload_attachment};
use crate::core::api::keys::{
    create_api_key, delete_api_key, get_api_key, list_api_keys, update_api_key,
};
use crate::core::api::monitor::health_check;
use crate::core::api::send::send_email;
use crate::core::api::types::*;
use crate::core::api::whoami::whoami;
use crate::core::storage::{ApiKeyRecord, Database};
use crate::core::strategy::RouterHook;

pub fn create_router(
    state: HttpState,
    router_hook: Arc<dyn RouterHook>,
    domain_handler: Option<axum::routing::MethodRouter<HttpState>>,
    list_domain_handler: Option<axum::routing::MethodRouter<HttpState>>,
) -> Router {
    // Health check: no IP restriction — open access
    let health = Router::new()
        .route("/health", get(health_check))
        .with_state(state.clone());

    // API routes: auth layer
    let api_env_factory = state.factories.email.env_factory.clone();
    let api = Router::new()
        // API Key CRUD
        .route("/api/v1/key/rotate", post(rotate_own_key))
        .route("/api/v1/admin/api-keys", post(create_api_key))
        .route("/api/v1/admin/api-keys", get(list_api_keys))
        .route("/api/v1/admin/api-keys/:id", get(get_api_key))
        .route("/api/v1/admin/api-keys/:id", put(update_api_key))
        .route("/api/v1/admin/api-keys/:id", delete(delete_api_key))
        // Outbound send
        .route("/api/v1/send", post(send_email))
        // Whoami
        .route("/api/v1/whoami", get(whoami))
        // Attachments
        .route("/api/v1/upload", post(upload_attachment))
        .route("/api/v1/attachments/:id", get(download_attachment))
        // System CRUD via RouterHook
        // Admin: system domain CRUD
        .route(
            "/api/v1/admin/systems/:sid/domains",
            domain_handler.unwrap_or_else(|| post(create_system_domain)),
        )
        .route(
            "/api/v1/admin/systems/:sid/domains",
            list_domain_handler.unwrap_or_else(|| get(list_system_domains)),
        )
        .route(
            "/api/v1/admin/system-domains/:id",
            put(update_system_domain),
        )
        .route(
            "/api/v1/admin/system-domains/:id",
            delete(delete_system_domain),
        )
        // Admin: agent address registration (under existing bare domain)
        .route(
            "/api/v1/admin/systems/:sid/addresses",
            post(register_address),
        )
        // Admin: agent metadata (manager, signature, persona, webhook)
        .route("/api/v1/admin/agent-meta/:email", put(update_agent_meta))
        // Admin: agent-scoped key-value state (profiles, summaries, message metadata)
        .route("/api/v1/agent-state/:key", get(get_agent_state))
        .route("/api/v1/agent-state/:key", put(put_agent_state))
        .route("/api/v1/agent-state/:key", delete(delete_agent_state))
        // Admin: contact profiles (semantic: atomic write + name index + search)
        .route("/api/v1/contacts/:address", put(put_contact_profile))
        .route("/api/v1/contacts/:address", get(get_contact_profile))
        .route("/api/v1/contacts", get(get_contacts_by_name))
        // Admin: thread summary (auto-resolve thread_id from message_id)
        .route(
            "/api/v1/thread-summary/:message_id",
            put(put_thread_summary),
        )
        .route(
            "/api/v1/thread-summary/:message_id",
            get(get_thread_summary),
        )
        // Admin: whitelist CRUD
        .route("/api/v1/whitelists", post(create_whitelist))
        .route("/api/v1/whitelists", get(list_whitelists))
        .route("/api/v1/whitelists/check", get(check_whitelist))
        .route("/api/v1/whitelists/:id", put(update_whitelist))
        .route("/api/v1/whitelists/:id", delete(delete_whitelist))
        .route("/api/v1/whitelists", delete(delete_whitelist_by_params))
        .route("/api/v1/whitelists", put(update_whitelist_by_params))
        // Admin: pending deliveries (pull-mode for amail-bridge)
        .route("/api/v1/admin/pending", post(list_pending_deliveries))
        .route("/api/v1/admin/pending/ack", post(ack_pending_deliveries))
        // Admin: check if domain exists globally (integrate.sh domain uniqueness)
        .route("/api/v1/admin/domains/check", get(check_domain_exists))
        .with_state(state.clone())
        .route_layer(axum::middleware::from_fn(move |req, next| {
            auth_layer(api_env_factory.clone(), req, next)
        }));

    let base_router = Router::new()
        .merge(health)
        .merge(api)
        // Activation: address code redemption (no auth — code IS the credential)
        .route("/api/v1/activate-address", post(activate_address_handler))
        .with_state(state.clone());

    let router = router_hook.mount(base_router);
    // Auto-register a2a_board toolset API (available to all consumers)
    let board_routes = {
        // Board routes use Bearer token auth (board_members.board_token),
        // NOT API key auth. Each handler calls verify_board_token() internally.
        // Routes are intentionally outside the api auth_layer.
        Router::new()
            .route(
            "/api/v1/board/:board_id/task/:task_id",
            get(crate::board::handlers::handle_get_task),
        )
        .route(
            "/api/v1/board/:board_id/tasks",
            get(crate::board::handlers::handle_list_tasks),
        )
        .route(
            "/api/v1/board/:board_id/members",
            get(crate::board::handlers::handle_list_members),
        )
        .route(
            "/api/v1/board/:board_id/status",
            get(crate::board::handlers::handle_board_status),
        )
        .route(
            "/api/v1/board/:board_id/roles",
            get(crate::board::handlers::handle_list_roles),
        )
        .route(
            "/api/v1/board/:board_id/task/:task_id/heartbeat",
            post(crate::board::handlers::handle_post_heartbeat),
        )
        .with_state(state.clone())
    }; // end board_routes block
    router.merge(board_routes)
}

/// POST /api/v1/key/rotate — Rotate own API key (any scope).
async fn rotate_own_key(
    state: axum::extract::State<HttpState>,
    api_key: axum::extract::Extension<ApiKeyRecord>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    use crate::core::api::auth::sha256_hex;
    use uuid::Uuid;
    let raw_key = Uuid::new_v4().to_string().replace('-', "");
    let key_hash = sha256_hex(&raw_key);
    let new_prefix = &raw_key[..8];
    match state
        .factories
        .email
        .env_factory
        .rotate_api_key(api_key.id, &key_hash, new_prefix)
        .await
    {
        Ok(Some(_record)) => Ok(Json(serde_json::json!({"raw_key": raw_key}))),
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
}

// ── System Domain CRUD ──

pub async fn create_system_domain(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(tid): Path<String>,
    Json(req): Json<CreateSystemDomainRequest>,
) -> Result<(StatusCode, Json<SystemDomainResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;

    // This endpoint is for bare domains only.
    if req.domain.contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_domain".to_string(),
                detail: Some("Use POST /api/v1/admin/systems/{sid}/addresses to register agent email addresses".to_string()),
            }),
        ));
    }

    // Only enforce domain match for agent/scoped keys, not for system admins
    let is_admin_like = is_system_admin_scope(&api_key);
    if !is_admin_like {
        if let Err(e) = require_domain_match(&api_key, &req.domain) {
            return Err(e);
        }
    }
    // Verify system exists
    match state.factories.email.env_factory.resolve_system(&tid).await {
        Ok(Some(_)) => {
            // ── Domain quota check (only for bare domains) ──
            state
                .extensions
                .quota_checker
                .check_domain_quota(&tid)
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
    }

    match state
        .factories
        .email
        .env_factory
        .create_domain(
            &req.id,
            &tid,
            &req.domain,
            req.webhook_url.as_deref(),
            req.webhook_secret.as_deref(),
            req.manager_address.as_deref(),
        )
        .await
    {
        Ok(record) => {
            info!(
                operation = "domain_created",
                system_domain_id = %req.id,
                system_id = %tid,
                domain = %req.domain,
                "System domain created"
            );
            let resp: SystemDomainResponse = record.into();
            Ok((StatusCode::CREATED, Json(resp)))
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

// ── Agent Address Registration ──

#[derive(Debug, Deserialize)]
pub struct RegisterAddressQuery {
    #[serde(default)]
    pub generate_code: bool,
}

/// POST /api/v1/admin/systems/:sid/addresses — Register an agent email address.
async fn register_address(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(tid): Path<String>,
    Query(query): Query<RegisterAddressQuery>,
    Json(req): Json<RegisterAddressRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system", "agent_admin"])?;

    // Extract bare domain from the email address
    let bare_domain = req.email.rsplit('@').next().unwrap_or("");
    if bare_domain.is_empty() || !req.email.contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_email".to_string(),
                detail: Some("email must be a valid agent@domain address".to_string()),
            }),
        ));
    }

    // Validate local-part characters (RFC 5321 atext minus '.',
    // which is reserved as persona/system-id separator).
    // Mode is determined by system_id prefix, not by dot count:
    //   shared-* → profile.system_name@domain (1 dot after persona strip)
    //   other    → profile@domain (0 dots after persona strip)
    let local = req.email.rsplit('@').nth(1).unwrap_or("");
    if local.is_empty() || local.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_email".to_string(),
                detail: Some("local-part must be 1-64 characters".to_string()),
            }),
        ));
    }

    // Strip optional persona prefix (everything before the first dot).
    let base = match local.split_once('.') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => local,
    };

    let is_shared = tid.starts_with("shared-");

    if is_shared {
        // ── Shared domain: profile.system_name → exactly 1 dot ──
        let dot_count = base.bytes().filter(|&b| b == b'.').count();
        if dot_count != 1 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some("shared-domain address must use profile.system_id@domain format".to_string()),
                }),
            ));
        }
        let (profile, sys_id) = base.split_once('.').unwrap();
        if profile.is_empty() || profile.len() > 64
            || sys_id.is_empty() || sys_id.len() > 64
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some("shared-domain segments must be 1-64 characters each".to_string()),
                }),
            ));
        }
        if let Some(bad) = profile.bytes().find(|&b| !is_atext_no_dot(b)) {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: "invalid_email".into(),
                detail: Some(format!("illegal char in profile: '{}' (0x{:02X})", bad as char, bad)),
            })));
        }
        if let Some(bad) = sys_id.bytes().find(|&b| !is_atext_no_dot(b)) {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: "invalid_email".into(),
                detail: Some(format!("illegal char in system-id: '{}' (0x{:02X})", bad as char, bad)),
            })));
        }
    } else {
        // ── Non-shared: no system-id suffix ──
        if base.bytes().any(|b| b == b'.') {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some("non-shared address must not contain dot after persona prefix".to_string()),
                }),
            ));
        }
        if let Some(bad) = base.bytes().find(|&b| !is_atext_no_dot(b)) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some(format!("illegal character '{}' in local-part (0x{:02X})", bad as char, bad)),
                }),
            ));
        }
    }

    // agent_admin scope: must match their domain
    if is_agent_admin_scope(&api_key) {
        if let Err(e) = require_domain_match(&api_key, bare_domain) {
            return Err(e);
        }
    }

    // Verify system exists
    let system = state
        .factories
        .email
        .env_factory
        .resolve_system(&tid)
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
    if system.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "System not found".to_string(),
                detail: None,
            }),
        ));
    }

    // Verify bare domain already exists under this system
    let domain_record = state
        .factories
        .email
        .env_factory
        .lookup_domain_addr(bare_domain)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::PRECONDITION_FAILED,
                Json(ErrorResponse {
                    error: "Bare domain not found".to_string(),
                    detail: Some(format!(
                        "Register domain '{}' first via POST /api/v1/admin/systems/{}/domains",
                        bare_domain, tid
                    )),
                }),
            )
        })?;

    if !domain_record.is_active {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(ErrorResponse {
                error: "Domain is inactive".to_string(),
                detail: None,
            }),
        ));
    }

    // Create system_domains + domain_addr_meta for the agent email
    match state
        .factories
        .email
        .env_factory
        .create_domain(
            &req.id,
            &tid,
            &req.email,
            req.webhook_url.as_deref(),
            req.webhook_secret.as_deref(),
            req.manager_address.as_deref(),
        )
        .await
    {
        Ok(record) => {
            info!(
                operation = "agent_address_registered",
                system_id = %tid,
                email = %req.email,
                domain = %bare_domain,
                "Agent address registered"
            );
            let resp: SystemDomainResponse = record.into();

            if query.generate_code {
                match crate::core::api::activation::generate_activation_codes(
                    &state.factories.email.env_factory.db,
                    &tid,
                    bare_domain,
                    Some(&req.email),
                    1,
                )
                .await
                {
                    Ok(codes) => {
                        if codes.is_empty() {
                            return Err((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: "Backend returned empty code list".to_string(),
                                    detail: None,
                                }),
                            ));
                        }
                        let raw_code = codes.into_iter().next().unwrap_or_default();
                        Ok((
                            StatusCode::CREATED,
                            Json(serde_json::json!({
                                "status": "created",
                                "domain": resp,
                                "activation_code": raw_code,
                            })),
                        ))
                    }
                    Err(e) => Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to generate activation code".to_string(),
                            detail: Some(e.to_string()),
                        }),
                    )),
                }
            } else {
                Ok((
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "status": "created",
                        "domain": resp,
                    })),
                ))
            }
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

/// GET /api/v1/admin/systems/:sid/domains — List domains for a system.
async fn list_system_domains(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(tid): Path<String>,
) -> Result<Json<Vec<SystemDomainResponse>>, (StatusCode, Json<ErrorResponse>)> {
    // Platform admin: unrestricted access to all systems
    if is_platform_admin_scope(&api_key) {
        // allowed
    } else {
        require_scope_any(&api_key, &["system"])?;
        // Guard: system-scoped key only sees own system's domains
        if api_key.system_id != tid {
            return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
                error: "Cross-system access denied".into(),
                detail: Some(format!(
                    "Key system '{}' cannot list domains of system '{}'",
                    api_key.system_id, tid
                )),
            })));
        }
    }
    match state
        .factories
        .email
        .env_factory
        .list_domains_by_system(&tid)
        .await
    {
        Ok(records) => Ok(Json(records.into_iter().map(|r| r.into()).collect())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}

/// GET /api/v1/admin/domains/check?domain=xxx — Check if a domain is registered in any system.
async fn check_domain_exists(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<HashMap<String, bool>>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["platform", "system"])?;
    let domain = params.get("domain").map(|s| s.as_str()).unwrap_or("");
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing 'domain' query parameter".to_string(),
                detail: None,
            }),
        ));
    }
    let exists = state
        .factories
        .email
        .env_factory
        .lookup_domain_addr(domain)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )
        })?
        .is_some();
    let mut result = HashMap::new();
    result.insert("exists".to_string(), exists);
    Ok(Json(result))
}

/// PUT /api/v1/admin/system-domains/:id — Update a system domain.
async fn update_system_domain(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSystemDomainRequest>,
) -> Result<Json<SystemDomainResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;
    // Verify existence and domain ownership
    let existing_domain = match state.factories.email.env_factory.resolve_domain(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "System domain not found".to_string(),
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

    // Domain ownership check — skipped for admin-scoped keys
    let is_admin_like = is_system_admin_scope(&api_key);
    if !is_admin_like {
        let req_domain = existing_domain
            .domain
            .rsplit('@')
            .next()
            .unwrap_or(&existing_domain.domain);
        if let Err(e) = require_domain_match(&api_key, req_domain) {
            return Err(e);
        }
    }

    match state
        .factories
        .email
        .env_factory
        .update_domain(
            &id,
            req.webhook_url.as_deref(),
            req.webhook_secret.as_deref(),
            req.is_active,
        )
        .await
    {
        Ok(update_result) => match update_result {
            Some(record) => {
                info!(operation = "domain_updated", system_domain_id = %id, "System domain updated");
                Ok(Json(record.into()))
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "System domain not found".to_string(),
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
}

/// DELETE /api/v1/admin/system-domains/:id — Delete a system domain.
async fn delete_system_domain(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;
    // Verify existence and domain ownership
    let existing_domain = match state.factories.email.env_factory.resolve_domain(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "System domain not found".to_string(),
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
    let is_admin_like = is_system_admin_scope(&api_key);
    if !is_admin_like {
        let req_domain = existing_domain
            .domain
            .rsplit('@')
            .next()
            .unwrap_or(&existing_domain.domain);
        if let Err(e) = require_domain_match(&api_key, req_domain) {
            return Err(e);
        }
    }

    match state.factories.email.env_factory.delete_domain(&id).await {
        Ok(()) => {
            info!(operation = "domain_deleted", system_domain_id = %id, "System domain deleted");
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

// ── Agent Meta (domain_addr_meta) ──

/// PUT /api/v1/admin/agent-meta/:email — Update agent metadata.
/// SystemAdmin and AgentAdmin only. Webhook config is managed via system-domains.
async fn update_agent_meta(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(email): Path<String>,
    Json(req): Json<UpdateAgentMetaRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;

    let email = email.to_lowercase();
    let existing = state
        .factories
        .email
        .env_factory
        .resolve_domain_addr_meta(&email)
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

    let existing = existing.ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse {
        error: "Agent not found".to_string(),
        detail: Some(format!("No metadata for agent '{}' — register the address first via POST /api/v1/admin/systems/{{sid}}/addresses", email)),
    })))?;

    // AA: must be the manager of this agent
    if is_agent_admin_scope(&api_key) {
        if existing.manager_address != api_key.email_address {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not the manager of this agent".to_string(),
                    detail: Some(format!(
                        "You ({}) are not the manager of '{}'",
                        api_key.email_address, email
                    )),
                }),
            ));
        }
    }

    // Merge: keep existing values where request field is None
    let manager = req
        .manager_address
        .as_deref()
        .unwrap_or(&existing.manager_address);
    let signature = req
        .agent_signature
        .as_deref()
        .unwrap_or(&existing.agent_signature);
    let persona = req
        .agent_persona
        .as_deref()
        .unwrap_or(&existing.agent_persona);

    state
        .factories
        .email
        .env_factory
        .upsert_domain_addr_meta(
            &email,
            &existing.system_id,
            Some(manager),
            Some(signature),
            Some(persona),
        )
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

    info!(operation = "agent_meta_updated", email = %email, "Agent metadata updated");

    // Sync whitelist when manager_address changes
    if manager != existing.manager_address {
        let _system_id = &existing.system_id;
        // Remove old manager whitelist entry if it existed
        if !existing.manager_address.is_empty() {
            let _ = state
                .factories
                .email
                .env_factory
                .delete_whitelist_entry_by_value(&email, &existing.manager_address)
                .await;
        }
        // Create new manager whitelist entry
        if !manager.is_empty() {
            let _ = state
                .factories
                .email
                .env_factory
                .create_whitelist_entry(
                    &email,
                    "all",
                    manager,
                    Some("Agent ↔ Manager (auto-synced)"),
                )
                .await;
        }
    }

    Ok(Json(serde_json::json!({
        "email": email,
        "manager_address": manager,
        "agent_signature": signature,
        "agent_persona": persona,
    })))
}

// ── Whitelist CRUD ──

async fn create_whitelist(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(req): Json<CreateWhitelistRequest>,
) -> Result<(StatusCode, Json<WhitelistResponse>), (StatusCode, Json<ErrorResponse>)> {
    // ── Agent/AA scope: auto-set category='agent' and api_key_id
    if is_agent_scope(&api_key) || is_agent_admin_scope(&api_key) {
        // AA: verify manager binding via domain_addr_meta
        let agent_key_id = if is_agent_admin_scope(&api_key) {
            let meta = state
                .factories
                .email
                .env_factory
                .resolve_domain_addr_meta(&req.domain_addr)
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
            let meta = meta.ok_or((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Agent not found".to_string(),
                    detail: Some(format!("No metadata for agent '{}'", req.domain_addr)),
                }),
            ))?;
            if meta.manager_address != api_key.email_address {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Not the manager of this agent".to_string(),
                        detail: Some(format!(
                            "You ({}) are not the manager of '{}'",
                            api_key.email_address, req.domain_addr
                        )),
                    }),
                ));
            }
            // Find the agent's API key to bind the whitelist entry
            state
                .factories
                .email
                .env_factory
                .resolve_api_key_by_email(&req.domain_addr)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Database error".to_string(),
                            detail: Some(e.to_string()),
                        }),
                    )
                })?
                .map(|k| k.id)
        } else {
            check_whitelist_access(&api_key, &req.domain_addr)?;
            Some(api_key.id)
        };
        // Whitelist per-key limit enforced by advanced edition
        // via RouterHook middleware (POST /api/v1/whitelists intercept).
        match state
            .factories
            .email
            .env_factory
            .create_whitelist_entry_full(
                &req.domain_addr,
                &req.direction,
                &req.value,
                "agent",
                agent_key_id,
                req.description.as_deref(),
            )
            .await
        {
            Ok(record) => {
                info!(
                    operation = "whitelist_created",
                    agent_id = %api_key.id,
                    value = %req.value,
                    "Agent whitelist entry created"
                );
                Ok((StatusCode::CREATED, Json(record.into())))
            }
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else if is_system_admin_scope(&api_key) {
        // SystemAdmin: can create DOMAIN-level whitelist entries only
        check_whitelist_access(&api_key, &req.domain_addr)?;
        match state
            .factories
            .email
            .env_factory
            .create_whitelist_entry(
                &req.domain_addr,
                &req.direction,
                &req.value,
                req.description.as_deref(),
            )
            .await
        {
            Ok(record) => {
                info!(
                    operation = "whitelist_created",
                    system_id = %api_key.system_id,
                    value = %req.value,
                    "Whitelist entry created"
                );
                Ok((StatusCode::CREATED, Json(record.into())))
            }
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else if is_platform_admin_scope(&api_key) {
        // PlatformAdmin: only allowed to toggle is_active via update, not create
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: Some(
                    "PlatformAdmin can only view and toggle whitelist entries".to_string(),
                ),
            }),
        ));
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: None,
            }),
        ))
    }
}

/// GET /api/v1/whitelists — List all whitelist entries.
#[derive(Deserialize)]
struct ListWhitelistsQuery {
    domain: Option<String>,
}

async fn list_whitelists(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Query(query): Query<ListWhitelistsQuery>,
) -> Result<Json<Vec<WhitelistResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let domain = query.domain.as_deref().unwrap_or("");
    if is_agent_scope(&api_key) {
        // Agent: only return category='agent' AND api_key_id=their own key id
        match state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(domain)
            .await
        {
            Ok(records) => {
                let filtered: Vec<WhitelistResponse> = records
                    .into_iter()
                    .filter(|r| r.category == "agent" && r.api_key_id == Some(api_key.id))
                    .map(|r| r.into())
                    .collect();
                Ok(Json(filtered))
            }
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else if is_agent_admin_scope(&api_key) {
        // AA: return category='agent' entries for agents they manage
        // Fetch all managed agent emails from domain_addr_meta, then filter whitelist
        let all = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(domain)
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
        let mut managed: Vec<WhitelistResponse> = Vec::new();
        for entry in all {
            if entry.category != "agent" {
                continue;
            }
            if let Ok(Some(meta)) = state
                .factories
                .email
                .env_factory
                .resolve_domain_addr_meta(&entry.domain_addr)
                .await
            {
                if meta.manager_address == api_key.email_address {
                    managed.push(entry.into());
                }
            }
        }
        Ok(Json(managed))
    } else if is_admin_scope(&api_key) {
        match state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(domain)
            .await
        {
            Ok(records) => Ok(Json(records.into_iter().map(|r| r.into()).collect())),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            )),
        }
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: None,
            }),
        ))
    }
}

/// GET /api/v1/whitelists/check — Check if a value is whitelisted.
#[derive(Deserialize)]
struct CheckWhitelistQuery {
    domain_addr: String,
    value: String,
    #[serde(default = "default_whitelist_direction")]
    direction: String,
}

fn default_whitelist_direction() -> String {
    "all".to_string()
}

async fn check_whitelist(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Query(query): Query<CheckWhitelistQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let is_platform_admin = is_platform_admin_scope(&api_key);
    let is_system_admin = is_system_admin_scope(&api_key);
    let is_agent_admin = is_agent_admin_scope(&api_key);
    let is_agent = is_agent_scope(&api_key);
    if !is_platform_admin && !is_system_admin && !is_agent_admin && !is_agent {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: Some(
                    "Whitelist check requires admin, system, agent_admin, or agent scope"
                        .to_string(),
                ),
            }),
        ));
    }
    // SystemAdmin: domain_addr must match their domain
    if is_system_admin {
        if let Err(e) = require_domain_match(&api_key, &query.domain_addr) {
            return Err(e);
        }
    }
    // AgentAdmin: verify manager binding via domain_addr_meta
    if is_agent_admin {
        let meta = state
            .factories
            .email
            .env_factory
            .resolve_domain_addr_meta(&query.domain_addr)
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
        let meta = meta.ok_or((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Agent not found".to_string(),
                detail: Some(format!("No metadata for agent '{}'", query.domain_addr)),
            }),
        ))?;
        if meta.manager_address != api_key.email_address {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not the manager of this agent".to_string(),
                    detail: Some(format!(
                        "You ({}) are not the manager of '{}'",
                        api_key.email_address, query.domain_addr
                    )),
                }),
            ));
        }
    }
    // Agent: domain_addr must be their own email
    if is_agent && api_key.email_address != query.domain_addr {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                detail: Some(
                    "Agent can only check whitelist for their own email address".to_string(),
                ),
            }),
        ));
    }
    // Proceed with check
    match state
        .factories
        .email
        .env_factory
        .check_whitelisted(&query.domain_addr, &query.value, &query.direction)
        .await
    {
        Ok(whitelisted) => Ok(Json(serde_json::json!({
            "whitelisted": whitelisted,
            "domain_addr": query.domain_addr,
            "value": query.value,
            "direction": query.direction,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}

/// PUT /api/v1/whitelists/:id — Toggle a whitelist entry active/inactive.
async fn update_whitelist(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateWhitelistRequest>,
) -> Result<Json<WhitelistResponse>, (StatusCode, Json<ErrorResponse>)> {
    if is_agent_scope(&api_key) || is_agent_admin_scope(&api_key) {
        // Agent/AA: can only update own entries (AA via manager binding)
        match state
            .factories
            .email
            .env_factory
            .get_whitelist_entry_by_id(id)
            .await
        {
            Ok(Some(entry)) => {
                // AA: verify manager binding via domain_addr_meta
                if is_agent_admin_scope(&api_key) {
                    let meta = state
                        .factories
                        .email
                        .env_factory
                        .resolve_domain_addr_meta(&entry.domain_addr)
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
                    let meta = meta.ok_or((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "Agent not found".to_string(),
                            detail: Some(format!("No metadata for agent '{}'", entry.domain_addr)),
                        }),
                    ))?;
                    if meta.manager_address != api_key.email_address {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(ErrorResponse {
                                error: "Not the manager of this agent".to_string(),
                                detail: Some(format!(
                                    "You ({}) are not the manager of '{}'",
                                    api_key.email_address, entry.domain_addr
                                )),
                            }),
                        ));
                    }
                } else {
                    if entry.api_key_id != Some(api_key.id) {
                        return Err((
                            StatusCode::NOT_FOUND,
                            Json(ErrorResponse {
                                error: "Whitelist entry not found".into(),
                                detail: None,
                            }),
                        ));
                    }
                }
                check_whitelist_access(&api_key, &entry.domain_addr)?;
            }
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Whitelist entry not found".into(),
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
    } else if is_system_admin_scope(&api_key) {
        // SystemAdmin: unrestricted access
    } else if is_platform_admin_scope(&api_key) {
        // PlatformAdmin: unrestricted access
    } else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".into(),
                detail: None,
            }),
        ));
    }

    match state
        .factories
        .email
        .env_factory
        .update_whitelist_entry(id, req.is_active, req.direction)
        .await
    {
        Ok(update_result) => match update_result {
            Some(record) => {
                info!(
                    operation = "whitelist_updated",
                    whitelist_id = id,
                    "Whitelist entry updated"
                );
                Ok(Json(record.into()))
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Whitelist entry not found".to_string(),
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
}

/// DELETE /api/v1/whitelists — Delete a whitelist entry by domain+value.
#[derive(Deserialize)]
struct DeleteWhitelistByParams {
    domain_addr: String,
    value: String,
}

async fn delete_whitelist_by_params(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Query(query): Query<DeleteWhitelistByParams>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // ── Scope-tiered permission (same pattern as delete_whitelist by ID) ──
    if is_agent_scope(&api_key) || is_agent_admin_scope(&api_key) {
        // Agent/AA: can only delete own entries (AA via manager binding)
        // AA: verify manager binding first
        if is_agent_admin_scope(&api_key) {
            let meta = state
                .factories
                .email
                .env_factory
                .resolve_domain_addr_meta(&query.domain_addr)
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
            let meta = meta.ok_or((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Agent not found".to_string(),
                    detail: Some(format!("No metadata for agent '{}'", query.domain_addr)),
                }),
            ))?;
            if meta.manager_address != api_key.email_address {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Not the manager of this agent".to_string(),
                        detail: Some(format!(
                            "You ({}) are not the manager of '{}'",
                            api_key.email_address, query.domain_addr
                        )),
                    }),
                ));
            }
        }
        let entries = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(&query.domain_addr)
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
        let found = entries.into_iter().find(|e| {
            e.value == query.value
                && (is_agent_admin_scope(&api_key) || e.api_key_id == Some(api_key.id))
        });
        match found {
            Some(entry) => {
                state
                    .factories
                    .email
                    .env_factory
                    .delete_whitelist_entry(entry.id)
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
                Ok(StatusCode::NO_CONTENT)
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Whitelist entry not found".to_string(),
                    detail: None,
                }),
            )),
        }
    } else if is_system_admin_scope(&api_key) || is_platform_admin_scope(&api_key) {
        // Admin: unrestricted access
        check_whitelist_access(&api_key, &query.domain_addr)?;
        let entries = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(&query.domain_addr)
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
        let found = entries.into_iter().find(|e| e.value == query.value);
        match found {
            Some(entry) => {
                // PA/SA cannot delete agent-category entries
                if entry.category == "agent" {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "Admin cannot delete agent-category whitelist entries".into(),
                            detail: Some(
                                "Use the agent or agent_admin scope to manage agent whitelists"
                                    .into(),
                            ),
                        }),
                    ));
                }
                state
                    .factories
                    .email
                    .env_factory
                    .delete_whitelist_entry(entry.id)
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
                Ok(StatusCode::NO_CONTENT)
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Whitelist entry not found".to_string(),
                    detail: None,
                }),
            )),
        }
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: None,
            }),
        ))
    }
}

/// PUT /api/v1/whitelists — Update a whitelist entry by domain+value.
#[derive(Deserialize)]
struct UpdateWhitelistByParams {
    domain_addr: String,
    value: String,
}

async fn update_whitelist_by_params(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Query(query): Query<UpdateWhitelistByParams>,
    Json(req): Json<UpdateWhitelistRequest>,
) -> Result<Json<WhitelistResponse>, (StatusCode, Json<ErrorResponse>)> {
    // ── Scope-tiered permission (same pattern as update_whitelist by ID) ──
    if is_agent_scope(&api_key) || is_agent_admin_scope(&api_key) {
        // Agent/AA: can only update own entries (AA via manager binding)
        // AA: verify manager binding first
        if is_agent_admin_scope(&api_key) {
            let meta = state
                .factories
                .email
                .env_factory
                .resolve_domain_addr_meta(&query.domain_addr)
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
            let meta = meta.ok_or((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Agent not found".to_string(),
                    detail: Some(format!("No metadata for agent '{}'", query.domain_addr)),
                }),
            ))?;
            if meta.manager_address != api_key.email_address {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Not the manager of this agent".to_string(),
                        detail: Some(format!(
                            "You ({}) are not the manager of '{}'",
                            api_key.email_address, query.domain_addr
                        )),
                    }),
                ));
            }
        }
        let entries = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(&query.domain_addr)
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
        let found = entries.into_iter().find(|e| {
            e.value == query.value
                && (is_agent_admin_scope(&api_key) || e.api_key_id == Some(api_key.id))
        });
        match found {
            Some(entry) => {
                let result = state
                    .factories
                    .email
                    .env_factory
                    .update_whitelist_entry(entry.id, req.is_active, req.direction)
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
                match result {
                    Some(record) => {
                        info!(
                            operation = "whitelist_updated",
                            whitelist_id = record.id,
                            "Whitelist entry updated"
                        );
                        Ok(Json(record.into()))
                    }
                    None => Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Whitelist entry not found".to_string(),
                            detail: None,
                        }),
                    )),
                }
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Whitelist entry not found".to_string(),
                    detail: None,
                }),
            )),
        }
    } else if is_system_admin_scope(&api_key) || is_platform_admin_scope(&api_key) {
        // Admin: unrestricted access
        check_whitelist_access(&api_key, &query.domain_addr)?;
        let entries = state
            .factories
            .email
            .env_factory
            .list_whitelist_entries(&query.domain_addr)
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
        let found = entries.into_iter().find(|e| e.value == query.value);
        match found {
            Some(entry) => {
                // PA/SA cannot update agent-category entries
                if entry.category == "agent" {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "Admin cannot update agent-category whitelist entries".into(),
                            detail: Some(
                                "Use the agent or agent_admin scope to manage agent whitelists"
                                    .into(),
                            ),
                        }),
                    ));
                }
                let result = state
                    .factories
                    .email
                    .env_factory
                    .update_whitelist_entry(entry.id, req.is_active, req.direction)
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
                match result {
                    Some(record) => {
                        info!(
                            operation = "whitelist_updated",
                            whitelist_id = record.id,
                            "Whitelist entry updated"
                        );
                        Ok(Json(record.into()))
                    }
                    None => Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Whitelist entry not found".to_string(),
                            detail: None,
                        }),
                    )),
                }
            }
            None => Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Whitelist entry not found".to_string(),
                    detail: None,
                }),
            )),
        }
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: None,
            }),
        ))
    }
}

/// DELETE /api/v1/whitelists/:id — Delete a whitelist entry by ID.
async fn delete_whitelist(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if is_agent_scope(&api_key) || is_agent_admin_scope(&api_key) {
        // Agent/AA: can only delete own entries (AA via manager binding)
        match state
            .factories
            .email
            .env_factory
            .get_whitelist_entry_by_id(id)
            .await
        {
            Ok(Some(entry)) => {
                // AA: verify manager binding via domain_addr_meta
                if is_agent_admin_scope(&api_key) {
                    let meta = state
                        .factories
                        .email
                        .env_factory
                        .resolve_domain_addr_meta(&entry.domain_addr)
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
                    let meta = meta.ok_or((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "Agent not found".to_string(),
                            detail: Some(format!("No metadata for agent '{}'", entry.domain_addr)),
                        }),
                    ))?;
                    if meta.manager_address != api_key.email_address {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(ErrorResponse {
                                error: "Not the manager of this agent".to_string(),
                                detail: Some(format!(
                                    "You ({}) are not the manager of '{}'",
                                    api_key.email_address, entry.domain_addr
                                )),
                            }),
                        ));
                    }
                } else {
                    if entry.api_key_id != Some(api_key.id) {
                        return Err((
                            StatusCode::NOT_FOUND,
                            Json(ErrorResponse {
                                error: "Whitelist entry not found".into(),
                                detail: None,
                            }),
                        ));
                    }
                }
                check_whitelist_access(&api_key, &entry.domain_addr)?;
            }
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Whitelist entry not found".into(),
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
    } else if is_system_admin_scope(&api_key) {
        // SystemAdmin: unrestricted access.
        let existing = state
            .factories
            .email
            .env_factory
            .get_whitelist_entry_by_id(id)
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
        match existing {
            Some(ref entry) => check_whitelist_access(&api_key, &entry.domain_addr)?,
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Whitelist entry not found".into(),
                        detail: None,
                    }),
                ));
            }
        }
    } else if is_platform_admin_scope(&api_key) {
        // PlatformAdmin: unrestricted access
    } else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".into(),
                detail: None,
            }),
        ));
    }

    // PA/SA cannot delete agent-category entries
    if is_platform_admin_scope(&api_key) || is_system_admin_scope(&api_key) {
        let entry = state
            .factories
            .email
            .env_factory
            .get_whitelist_entry_by_id(id)
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
        let entry = entry.ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Whitelist entry not found".into(),
                detail: None,
            }),
        ))?;
        if entry.category == "agent" {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Admin cannot delete agent-category whitelist entries".into(),
                    detail: Some(
                        "Use the agent or agent_admin scope to manage agent whitelists".into(),
                    ),
                }),
            ));
        }
    }

    match state
        .factories
        .email
        .env_factory
        .delete_whitelist_entry(id)
        .await
    {
        Ok(()) => {
            info!(
                operation = "whitelist_deleted",
                whitelist_id = id,
                "Whitelist entry deleted"
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

// ── Agent State handlers ──────────────────────────────────────────

/// GET /api/v1/agent-state/:key
///
/// Requires agent scope. Agent address derived from api_key.email_address.
async fn get_agent_state(
    state: axum::extract::State<HttpState>,
    Path(key): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "agent state requires a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    match state
        .factories
        .email
        .env_factory
        .db
        .agent_state_get(agent_addr, &key)
        .await
    {
        Ok(Some((k, v))) => Ok(Json(serde_json::json!({"key": k, "value": v}))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "agent_state entry not found".to_string(),
                detail: None,
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}

/// PUT /api/v1/agent-state/:key
async fn put_agent_state(
    state: axum::extract::State<HttpState>,
    Path(key): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(body): Json<AgentStatePutRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "agent state requires a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    match state
        .factories
        .email
        .env_factory
        .db
        .agent_state_put(agent_addr, &key, &body.value)
        .await
    {
        Ok(()) => Ok(Json(serde_json::json!({"success": true}))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}

/// DELETE /api/v1/agent-state/:key
async fn delete_agent_state(
    state: axum::extract::State<HttpState>,
    Path(key): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "agent state requires a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    match state
        .factories
        .email
        .env_factory
        .db
        .agent_state_delete(agent_addr, &key)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: Some(e.to_string()),
            }),
        )),
    }
}

// ── Contact Profile handlers ─────────────────────────────────────

/// PUT /api/v1/contacts/:address — atomic profile write + name index
async fn put_contact_profile(
    state: axum::extract::State<HttpState>,
    Path(address): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(body): Json<ContactProfileRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "contacts require a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    let db = &state.factories.email.env_factory.db;

    // Extract new name
    let new_name: String = serde_json::from_str::<serde_json::Value>(&body.profile)
        .ok()
        .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
        .unwrap_or_default();

    // Get old profile for merge + old name cleanup
    let old_value = db
        .agent_state_get(agent_addr, &format!("profile:{}", address))
        .await
        .unwrap_or(None);
    let old_name: String = old_value
        .as_ref()
        .and_then(|(_, v)| {
            serde_json::from_str::<serde_json::Value>(v)
                .ok()
                .and_then(|j| j.get("name").and_then(|n| n.as_str()).map(String::from))
        })
        .unwrap_or_default();

    // Merge if old exists
    let final_profile = if let Some((_, old)) = &old_value {
        merge_profile_json(old, &body.profile)
    } else {
        body.profile.clone()
    };

    // Write profile
    if let Err(e) = db
        .agent_state_put(agent_addr, &format!("profile:{}", address), &final_profile)
        .await
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: Some(e.to_string()),
            }),
        ));
    }

    // Name index maintenance
    if !old_name.is_empty() && old_name.to_lowercase() != new_name.to_lowercase() {
        remove_from_name_index(db, agent_addr, &old_name, &address).await;
    }
    if !new_name.is_empty() {
        add_to_name_index(db, agent_addr, &new_name, &address).await;
    }

    Ok(Json(serde_json::json!({"success": true})))
}

/// GET /api/v1/contacts/:address — read contact profile by address
async fn get_contact_profile(
    state: axum::extract::State<HttpState>,
    Path(address): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "contacts require a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    let db = &state.factories.email.env_factory.db;
    match db
        .agent_state_get(agent_addr, &format!("profile:{}", address))
        .await
    {
        Ok(Some((_, value))) => Ok(Json(
            serde_json::json!({"address": address, "profile": value}),
        )),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "contact not found".to_string(),
                detail: None,
            }),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: None,
            }),
        )),
    }
}

/// GET /api/v1/contacts?name=... — search contacts by name
async fn get_contacts_by_name(
    state: axum::extract::State<HttpState>,
    Query(query): Query<ContactsByNameQuery>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "contacts require a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    let db = &state.factories.email.env_factory.db;
    let name_key = query.name.to_lowercase();

    let index_value = db
        .agent_state_get(agent_addr, &format!("name:{}", name_key))
        .await
        .unwrap_or(None);
    let results = if let Some((_, idx)) = index_value {
        let addresses: Vec<String> = serde_json::from_str::<serde_json::Value>(&idx)
            .ok()
            .and_then(|v| v.get("addresses").cloned())
            .and_then(|a| serde_json::from_value::<Vec<String>>(a).ok())
            .unwrap_or_default();
        let mut out = Vec::new();
        for addr in &addresses {
            if let Ok(Some((_, profile))) = db
                .agent_state_get(agent_addr, &format!("profile:{}", addr))
                .await
            {
                out.push(serde_json::json!({"address": addr, "profile": profile}));
            }
        }
        out
    } else {
        Vec::new()
    };

    Ok(Json(serde_json::json!({"results": results})))
}

// ── Thread Summary handler ────────────────────────────────────────

/// PUT /api/v1/thread-summary/:message_id — resolve thread_id + write summary
async fn put_thread_summary(
    state: axum::extract::State<HttpState>,
    Path(message_id): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(body): Json<ThreadSummaryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "thread summary requires a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    let db = &state.factories.email.env_factory.db;

    // Resolve thread_id from message metadata
    let thread_id = match db
        .agent_state_get(agent_addr, &format!("msg:{}", message_id))
        .await
    {
        Ok(Some((_, meta))) => serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| {
                v.get("thread_id")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            })
            .unwrap_or(message_id.clone()),
        _ => message_id.clone(),
    };

    if body.summary.trim().is_empty() {
        let _ = db
            .agent_state_delete(agent_addr, &format!("thread:{}", thread_id))
            .await;
    } else {
        if let Err(e) = db
            .agent_state_put(agent_addr, &format!("thread:{}", thread_id), &body.summary)
            .await
        {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "database error".to_string(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    }

    Ok(Json(
        serde_json::json!({"success": true, "thread_id": thread_id}),
    ))
}

/// GET /api/v1/thread-summary/:message_id — resolve thread_id + read summary
async fn get_thread_summary(
    state: axum::extract::State<HttpState>,
    Path(message_id): Path<String>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["agent", "agent_admin", "system", "platform"])?;
    let agent_addr = &api_key.email_address;
    if agent_addr.is_empty() {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse {
            error: "thread summary requires a non-empty email_address — system-level keys must use an agent-scoped key for this endpoint".to_string(),
            detail: None,
        })));
    }
    let db = &state.factories.email.env_factory.db;

    // Resolve thread_id from message metadata
    let thread_id = match db
        .agent_state_get(agent_addr, &format!("msg:{}", message_id))
        .await
    {
        Ok(Some((_, meta))) => serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| {
                v.get("thread_id")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            })
            .unwrap_or(message_id.clone()),
        _ => message_id.clone(),
    };

    match db
        .agent_state_get(agent_addr, &format!("thread:{}", thread_id))
        .await
    {
        Ok(Some((_, summary))) => Ok(Json(serde_json::json!({
            "thread_id": thread_id, "summary": summary
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "thread summary not found".to_string(),
                detail: None,
            }),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "database error".to_string(),
                detail: None,
            }),
        )),
    }
}

// ── Name index helpers ────────────────────────────────────────────

async fn remove_from_name_index(db: &Database, agent_addr: &str, name: &str, address: &str) {
    let key = format!("name:{}", name.to_lowercase());
    if let Ok(Some((_, idx))) = db.agent_state_get(agent_addr, &key).await {
        let mut addrs: Vec<String> = serde_json::from_str::<serde_json::Value>(&idx)
            .ok()
            .and_then(|v| v.get("addresses").cloned())
            .and_then(|a| serde_json::from_value::<Vec<String>>(a).ok())
            .unwrap_or_default();
        addrs.retain(|a| a != address);
        if addrs.is_empty() {
            let _ = db.agent_state_delete(agent_addr, &key).await;
        } else {
            let _ = db
                .agent_state_put(
                    agent_addr,
                    &key,
                    &serde_json::json!({"addresses": addrs}).to_string(),
                )
                .await;
        }
    }
}

async fn add_to_name_index(db: &Database, agent_addr: &str, name: &str, address: &str) {
    let key = format!("name:{}", name.to_lowercase());
    let mut addrs: Vec<String> =
        if let Ok(Some((_, idx))) = db.agent_state_get(agent_addr, &key).await {
            serde_json::from_str::<serde_json::Value>(&idx)
                .ok()
                .and_then(|v| v.get("addresses").cloned())
                .and_then(|a| serde_json::from_value::<Vec<String>>(a).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
    if !addrs.contains(&address.to_string()) {
        addrs.push(address.to_string());
    }
    let _ = db
        .agent_state_put(
            agent_addr,
            &key,
            &serde_json::json!({"addresses": addrs}).to_string(),
        )
        .await;
}

/// Simple JSON field-level merge: new keys overwrite, arrays are replaced.
fn merge_profile_json(old: &str, new: &str) -> String {
    let mut base: serde_json::Value =
        serde_json::from_str(old).unwrap_or(serde_json::Value::Object(Default::default()));
    let patch: serde_json::Value =
        serde_json::from_str(new).unwrap_or(serde_json::Value::Object(Default::default()));
    if let (serde_json::Value::Object(ref mut b), serde_json::Value::Object(p)) =
        (&mut base, &patch)
    {
        for (k, v) in p {
            b.insert(k.clone(), v.clone());
        }
    }
    base.to_string()
}

// ── Pending deliveries (pull-mode for amail-bridge) ──

#[derive(Deserialize)]
struct PendingPollRequest {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    filter: Vec<String>,
}
fn default_limit() -> i64 {
    20
}

#[derive(Deserialize)]
struct AckRequest {
    ids: Vec<i64>,
}

async fn list_pending_deliveries(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(req): Json<PendingPollRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system", "bridge"])?;

    let system_id = &api_key.system_id;

    // Build domain filter: prefer `filter` param, fall back to `emails`
    let use_filter = !req.filter.is_empty();

    // Preprocess filter: domains absorb exact emails and regex, then regex absorbs emails
    let effective_filter: Vec<String> = if use_filter {
        preprocess_pending_filter(&req.filter)
    } else if !req.emails.is_empty() {
        // Legacy: extract unique domains from email list
        let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();
        for email in &req.emails {
            if let Some(domain) = email.rsplit('@').next() {
                domains.insert(domain.to_string());
            }
        }
        domains.into_iter().collect()
    } else {
        Vec::new()
    };

    let use_domains: Option<Vec<String>> = if effective_filter.is_empty() {
        None
    } else {
        Some(effective_filter)
    };

    let records = state
        .factories
        .email
        .env_factory
        .db
        .list_pending_deliveries(system_id, req.limit, use_domains.as_deref())
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

    // Group deliveries by body hash so identical payloads share one copy.
    // This reduces bridge poll response size when multiple recipients
    // received the same email (common for mailing-list / broadcast).
    use std::collections::{hash_map::DefaultHasher, HashMap};
    use std::hash::{Hash, Hasher};
    let mut batches_map: HashMap<i64, Vec<(i64, String, String)>> = HashMap::new();
    let mut batch_order: Vec<(i64, String)> = Vec::new(); // (hash, body)
    for r in &records {
        let mut hasher = DefaultHasher::new();
        r.payload.hash(&mut hasher);
        let h = hasher.finish() as i64;
        let entry = batches_map.entry(h).or_insert_with(|| {
            batch_order.push((
                h,
                serde_json::from_str::<serde_json::Value>(&r.payload)
                    .unwrap_or(serde_json::Value::Null)
                    .to_string(),
            ));
            Vec::new()
        });
        entry.push((r.id, r.email.clone(), r.headers.clone()));
    }

    let batches: Vec<serde_json::Value> = batch_order.iter().map(|(h, body)| {
        let deliveries: Vec<serde_json::Value> = batches_map[h].iter().map(|(id, email, headers)| {
            serde_json::json!({
                "id": id,
                "email": email,
                "headers": serde_json::from_str::<serde_json::Value>(headers).unwrap_or(serde_json::Value::Null),
            })
        }).collect();
        serde_json::json!({
            "body": serde_json::from_str::<serde_json::Value>(body).unwrap_or(serde_json::Value::Null),
            "deliveries": deliveries,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "batches": batches })))
}

async fn ack_pending_deliveries(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(req): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system", "bridge"])?;

    const MAX_ACK: usize = 500;
    if req.ids.len() > MAX_ACK {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "too many ids".to_string(),
                detail: Some(format!("max {} ids per ACK", MAX_ACK)),
            }),
        ));
    }

    let count = state
        .factories
        .email
        .env_factory
        .db
        .ack_deliveries(&req.ids)
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
    Ok(Json(serde_json::json!({ "acked": count })))
}

// ── Probe Webhook ───────────────────────────────────────────────

/// Probe network reachability to a host:port from the relay.
///
/// Used by integrate.sh to determine whether to deploy the bridge in
/// push mode (relay can reach the agent's machine) or pull mode (relay
/// cannot, bridge must poll).

// ── Public config ─────────────────────────────────────────────────

/// Preprocess pending poll filter: domains absorb exact emails and regex.
/// Bare domains (no '@') wrap all entries under them.
fn preprocess_pending_filter(raw: &[String]) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    let mut remaining: Vec<String> = Vec::new();

    for entry in raw {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if !entry.contains('@') {
            // Bare domain — highest priority, absorbs everything under it
            if !domains.contains(&entry.to_string()) {
                domains.push(entry.to_string());
            }
        } else {
            remaining.push(entry.to_string());
        }
    }

    if domains.is_empty() {
        return remaining; // no domains to absorb, return as-is
    }

    // Filter remaining entries: keep only those whose domain isn't covered
    let mut result: Vec<String> = domains;
    for entry in &remaining {
        if let Some(entry_domain) = entry.rsplit('@').next() {
            if !result.contains(&entry_domain.to_string()) {
                result.push(entry.clone());
            }
        }
    }
    result
}

// ── Email address validation ──────────────────────────────────────────

/// RFC 5321 `atext` characters excluding '.' (dot).
/// Dot is reserved as persona/system-id separator in amail addresses.
fn is_atext_no_dot(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
        | b'*' | b'+' | b'-' | b'/' | b'=' | b'?'
        | b'^' | b'_' | b'`' | b'{' | b'|' | b'}' | b'~'
    )
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_domain_absorbs_exact() {
        let r = preprocess_pending_filter(&["x.com".into(), "alice@x.com".into()]);
        assert_eq!(r, vec!["x.com"]);
    }

    #[test]
    fn test_unmatched_preserved() {
        let r = preprocess_pending_filter(&["x.com".into(), "bob@y.com".into()]);
        assert_eq!(r.len(), 2);
        assert!(r.contains(&"x.com".to_string()));
        assert!(r.contains(&"bob@y.com".to_string()));
    }
}
