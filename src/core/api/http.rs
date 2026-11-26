//! HTTP router construction and admin CRUD handlers.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE},
    http::StatusCode,
    response::{Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::core::errors::AppError;
use tracing::{info, warn};

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
use crate::core::api::types::{SSE_HEARTBEAT_SECS, SSE_MAX_LIFE_SECS};
use crate::core::api::welcome::send_welcome;
use crate::core::api::whoami::whoami;
use crate::core::pending_notifier::{NotifyKey, PendingNotifier, WaitOutcome};
use crate::core::storage::{ApiKeyRecord, Database, DomainAddrMetaRecord};
use crate::core::strategy::RouterHook;
use futures_util::stream::unfold;

pub fn create_router(
    state: HttpState,
    router_hook: Arc<dyn RouterHook>,
    domain_handler: Option<axum::routing::MethodRouter<HttpState>>,
    list_domain_handler: Option<axum::routing::MethodRouter<HttpState>>,
    send_handler: Option<axum::routing::MethodRouter<HttpState>>,
    whitelist_handler: Option<axum::routing::MethodRouter<HttpState>>,
) -> Router {
    // Health check: no IP restriction — open access
    let health = Router::new()
        .route("/health", get(health_check))
        .with_state(state.clone());

    // API routes: auth layer
    let api_env_factory = state.factories.email.env_factory.clone();
    // Body cap tracks the configured attachment limit (P2-2): the auth layer
    // buffers the full body for signature hashing, so it must accept at least
    // as much as the upload handler will later accept.
    // D6: per-route body caps for the auth layer's streaming read — regular
    // JSON routes 1 MB; the upload endpoint gets the configured attachment
    // limit + 1 MB margin for MIME framing.
    let body_caps = crate::core::api::auth::BodyCaps {
        regular: crate::core::api::auth::REGULAR_API_BODY_CAP,
        attachment: state.config.storage.attachment_max_size as u64 + 1024 * 1024,
    };
    let api = Router::new()
        // API Key CRUD
        .route("/api/v1/key/rotate", post(rotate_own_key))
        .route("/api/v1/admin/api-keys", post(create_api_key))
        .route("/api/v1/admin/api-keys", get(list_api_keys))
        .route("/api/v1/admin/api-keys/:id", get(get_api_key))
        .route("/api/v1/admin/api-keys/:id", put(update_api_key))
        .route("/api/v1/admin/api-keys/:id", delete(delete_api_key))
        // Outbound send
        .route(
            "/api/v1/send",
            send_handler.unwrap_or_else(|| post(send_email)),
        )
        .route("/api/v1/system/welcome", post(send_welcome))
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
        .route(
            "/api/v1/admin/systems/:sid/addresses/rename",
            post(rename_agent_address),
        )
        // Admin: single-address read-only probe (existence + validity ONLY;
        // no list endpoint and no row content — see get_address_status)
        .route(
            "/api/v1/admin/systems/:sid/addresses/:addr",
            get(get_address_status),
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
        // Admin: whitelist CRUD
        .route(
            "/api/v1/whitelists",
            post(whitelist_handler.unwrap_or_else(|| post(create_whitelist))),
        )
        .route("/api/v1/whitelists", get(list_whitelists))
        .route("/api/v1/whitelists/check", get(check_whitelist))
        .route("/api/v1/whitelists/:id", put(update_whitelist))
        .route("/api/v1/whitelists/:id", delete(delete_whitelist))
        .route("/api/v1/whitelists", delete(delete_whitelist_by_params))
        .route("/api/v1/whitelists", put(update_whitelist_by_params))
        // Admin: pending deliveries (pull-mode for aimail-bridge)
        // Retired pull scopes (owner ruling 2026-11-26): one pull transport remains, the
        // AgentSystemId aggregate below. These three stay ROUTED so an old client gets a precise
        // 410 instead of a 404 that looks like a typo. Webhook PUSH never used them and is
        // unaffected.
        .route(
            "/api/v1/admin/pending",
            post(retired_pull_scope).get(retired_pull_scope),
        )
        .route(
            "/api/v1/admin/pending/stream",
            get(retired_pull_scope).post(retired_pull_scope),
        )
        .route(
            "/api/v1/admin/pending/ack",
            post(retired_pull_scope).get(retired_pull_scope),
        )
        // AgentSystemId aggregation (one client identity, many addresses)
        .route(
            "/api/v1/agent-system/pending",
            post(list_agent_system_pending),
        )
        .route(
            "/api/v1/agent-system/pending/ack",
            post(ack_agent_system_pending),
        )
        .route(
            "/api/v1/agent-system/pending/stream",
            get(agent_system_stream),
        )
        // Admin: probe inbound-endpoint reachability (CLI install webhook plan,
        // 2026-10-13: restored from v1.0; pure TCP classifier — the caller
        // interprets the error class, e.g. the agent probe treats
        // connection_refused as "path open, process not yet listening")
        .route("/api/v1/admin/probe-webhook", post(probe_webhook))
        // Admin: check if domain exists globally (integrate.sh domain uniqueness)
        .route("/api/v1/admin/domains/check", get(check_domain_exists))
        .with_state(state.clone())
        .route_layer(axum::middleware::from_fn(move |req, next| {
            let ef = api_env_factory.clone();
            let caps = body_caps;
            async move { auth_layer(ef, req, next, caps).await }
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
    let key_hash = crate::core::api::seal::store_hash(&sha256_hex(&raw_key));
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

    // D2 write-side boundary: a `system`-scoped key manages only its own
    // system's resources; cross-system writes are refused before any DB
    // mutation. Platform admins are unrestricted (mirrors the read-side
    // exemption in list_system_domains / get_address_status).
    if !is_platform_admin_scope(&api_key) && api_key.system_id != tid {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "Key system '{}' cannot manage system '{}'",
                    api_key.system_id, tid
                )),
            }),
        ));
    }

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
        require_domain_match(&api_key, &req.domain)?;
    }
    // Verify system exists
    match state.factories.email.env_factory.resolve_system(&tid).await {
        Ok(Some(_)) => {
            // ── Domain admission check (only for bare domains) ──
            state
                .extensions
                .admission_gate
                .admit_domain(&tid)
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

/// Resolve the manager an address registration actually writes.
///
/// Precedence (first non-empty wins, values trimmed):
///   1. explicit `manager_address` from the request body
///   2. per-system default (`systems.manager_address`, persisted at activation)
///   3. config-file default (`[admin] manager_default`, empty by default)
///
/// `None` means "no manager source at all" — the address is registered
/// without a manager row (never a `value=''` whitelist row).
fn resolve_effective_manager(
    explicit: Option<&str>,
    system_default: Option<&str>,
    config_default: Option<&str>,
) -> Option<String> {
    [explicit, system_default, config_default]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|m| !m.is_empty())
        .map(str::to_string)
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
    // Persona prefix is NOT present during registration — it is
    // added dynamically by the inbound SMTP receiver.
    //
    // Mode is determined by system_id prefix:
    //   shared-* → profile.system_name@domain (exactly 1 dot)
    //   other    → profile@domain (no dots)
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

    let dot_count = local.bytes().filter(|&b| b == b'.').count();

    if tid.starts_with("shared-") {
        // ── Shared domain: profile.system_name@domain ──
        if dot_count != 1 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some(
                        "shared-domain address must use profile.system_id@domain format"
                            .to_string(),
                    ),
                }),
            ));
        }
        let (profile, sys_id) = local.split_once('.').unwrap();
        if profile.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".into(),
                    detail: Some("profile segment must not be empty".into()),
                }),
            ));
        }
        if let Some(bad) = profile.bytes().find(|&b| !is_atext_no_dot(b)) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".into(),
                    detail: Some(format!(
                        "illegal char in profile: '{}' (0x{:02X})",
                        bad as char, bad
                    )),
                }),
            ));
        }
        // Validate system_id naming rules (same as activate_system.py SYSNAME_RE):
        // lowercase start, 3-8 chars, [a-z0-9_-] only, not "a2a" or ".a2a"
        if !sys_id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
            || sys_id.len() < 3
            || sys_id.len() > 8
            || sys_id
                .bytes()
                .any(|b| !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".into(),
                    detail: Some(
                        "system-id must be 3-8 chars, lowercase letter start, [a-z0-9_-] only"
                            .into(),
                    ),
                }),
            ));
        }
        if sys_id == "a2a" || sys_id.contains(".a2a") {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".into(),
                    detail: Some("'a2a' is a reserved system-id".into()),
                }),
            ));
        }
    } else {
        // ── Non-shared: no dots. ".a2a@" is reserved exclusively for
        // board addresses ({short}.a2a@{domain}) — registering any
        // address carrying that marker is rejected (same rationale as
        // the reserved 'a2a' system-id on shared domains).
        if local.ends_with(".a2a") {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some("'.a2a@' is reserved for board addresses".to_string()),
                }),
            ));
        }
        if dot_count != 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some("non-shared address must not contain dots".to_string()),
                }),
            ));
        }
        if let Some(bad) = local.bytes().find(|&b| !is_atext_no_dot(b)) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_email".to_string(),
                    detail: Some(format!(
                        "illegal character '{}' in local-part (0x{:02X})",
                        bad as char, bad
                    )),
                }),
            ));
        }
    }

    // agent_admin scope: must match their domain
    if is_agent_admin_scope(&api_key) {
        require_domain_match(&api_key, bare_domain)?;
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

    // ── Effective manager resolution (single authority, server-side) ──
    // Precedence: explicit request value > per-system default (persisted at
    // activation) > config-file default (AdminConfig.manager_default, empty by
    // default).
    // Empty result = register without a manager row — never a value='' row.
    // The client-side hard gate (CLI register) still refuses zero-source
    // registrations; this only fills the documented defaults.
    let effective_manager = resolve_effective_manager(
        req.manager_address.as_deref(),
        system.as_ref().map(|s| s.manager_address.as_str()),
        state.config.admin.manager_default.as_deref(),
    );

    // Verify the domain anchor exists under this system.
    // Lookup key: non-shared → bare domain (e.g. "company.com");
    // shared → system anchor "system_name@bare_domain" (e.g.
    // "vfy@aimail.token.tm"), derived from the address's system_name
    // segment. Both modes resolve through the same table lookup and
    // the same system_id equality check below — only the key differs.
    let lookup_key = if tid.starts_with("shared-") {
        let sys_name = local.rsplit('.').next().unwrap_or("");
        format!("{}@{}", sys_name, bare_domain)
    } else {
        bare_domain.to_string()
    };
    let domain_record = state
        .factories
        .email
        .env_factory
        .lookup_domain_addr(&lookup_key)
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
            let (err, detail) = if tid.starts_with("shared-") {
                (
                    "System anchor not found".to_string(),
                    Some(format!(
                        "System anchor '{}' not found — the shared-domain system must be activated to create it",
                        lookup_key
                    )),
                )
            } else {
                (
                    "Bare domain not found".to_string(),
                    Some(format!(
                        "Register domain '{}' first via POST /api/v1/admin/systems/{}/domains",
                        bare_domain, tid
                    )),
                )
            };
            (StatusCode::PRECONDITION_FAILED, Json(ErrorResponse { error: err, detail }))
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

    // The anchor must belong to the requesting system (same equality
    // check for both modes — the shared anchor is owned by its system).
    if domain_record.system_id != tid {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                detail: Some("Domain does not belong to this system".to_string()),
            }),
        ));
    }

    // ── Address admission check ──
    state
        .extensions
        .admission_gate
        .admit_address(&tid)
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
            effective_manager.as_deref(),
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
            // Auto-create bidirectional whitelist: agent <-> manager. Uses
            // the EFFECTIVE manager (explicit or default) — a default manager
            // that is not whitelisted cannot receive from or reply to the
            // agent, which would break the closure the default promises.
            if let Some(manager) = effective_manager.as_deref() {
                if let Err(e) = state
                    .factories
                    .email
                    .env_factory
                    .create_whitelist_entry(
                        &req.email,
                        "all",
                        manager,
                        Some("Agent <-> Manager (auto-created)"),
                    )
                    .await
                {
                    warn!(operation = "auto_whitelist_failed", email = %req.email, error = %e);
                }
            }
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
        Err(e) if matches!(&e, AppError::Conflict(_)) => {
            // Address already registered — idempotent sync of manager meta
            // and bidirectional whitelist (register retries are safe).
            //
            // Uses the SAME `effective_manager` the new path wrote (explicit >
            // system default > config default), not `req.manager_address`
            // alone. The Conflict arm only fires on a cross-system collision
            // (same-system re-register takes the factory upsert Ok path and
            // never reaches here), so a client that omitted manager_address
            // expecting the server default still gets the resolved value
            // instead of the sync silently skipping — the single-resolution
            // promise holds on this path too.
            if let Some(manager) = effective_manager.as_deref() {
                let _ = state
                    .factories
                    .email
                    .env_factory
                    .db
                    .upsert_domain_addr_meta(&req.email, &tid, Some(manager), None, None)
                    .await;
                if let Err(e2) = state
                    .factories
                    .email
                    .env_factory
                    .create_whitelist_entry(
                        &req.email,
                        "all",
                        manager,
                        Some("Agent <-> Manager (auto-created)"),
                    )
                    .await
                {
                    warn!(operation = "auto_whitelist_failed", email = %req.email, error = %e2);
                }
            }
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "already_exists".to_string(),
                    detail: Some(e.to_string()),
                }),
            ))
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

/// Fill the agent-meta fields (manager_address / agent_signature / agent_persona)
/// on a domain response from its `domain_addr_meta` row. Bare domains have no
/// meta row → fields stay empty.
fn apply_domain_meta(resp: &mut SystemDomainResponse, meta: Option<&DomainAddrMetaRecord>) {
    if let Some(m) = meta {
        resp.manager_address = m.manager_address.clone();
        resp.agent_signature = m.agent_signature.clone();
        resp.agent_persona = m.agent_persona.clone();
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
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cross-system access denied".into(),
                    detail: Some(format!(
                        "Key system '{}' cannot list domains of system '{}'",
                        api_key.system_id, tid
                    )),
                }),
            ));
        }
    }
    match state
        .factories
        .email
        .env_factory
        .list_domains_by_system(&tid)
        .await
    {
        Ok(records) => {
            // Enrich address-type records with their per-agent meta so the
            // response carries manager_address / agent_signature / agent_persona
            // instead of empty strings.
            let metas = state
                .factories
                .email
                .env_factory
                .list_domain_addr_meta_by_system(&tid)
                .await
                .unwrap_or_default();
            let meta_by_addr: std::collections::HashMap<&str, &DomainAddrMetaRecord> = metas
                .iter()
                .map(|m| (m.email_address.as_str(), m))
                .collect();
            let resp = records
                .into_iter()
                .map(|r| {
                    let mut resp: SystemDomainResponse = r.clone().into();
                    if r.domain.contains('@') {
                        if let Some(m) = meta_by_addr.get(r.domain.as_str()) {
                            apply_domain_meta(&mut resp, Some(m));
                        }
                    }
                    resp
                })
                .collect();
            Ok(Json(resp))
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

    // D2 write-side boundary: a `system`-scoped key manages only its own
    // system's resources; cross-system writes are refused before any DB
    // mutation. Platform admins are unrestricted (mirrors the read-side
    // exemption in list_system_domains / get_address_status).
    if !is_platform_admin_scope(&api_key) && existing_domain.system_id != api_key.system_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "Domain '{}' belongs to system '{}', not '{}'",
                    existing_domain.domain, existing_domain.system_id, api_key.system_id
                )),
            }),
        ));
    }

    // Domain ownership check — skipped for admin-scoped keys
    let is_admin_like = is_system_admin_scope(&api_key);
    if !is_admin_like {
        let req_domain = existing_domain
            .domain
            .rsplit('@')
            .next()
            .unwrap_or(&existing_domain.domain);
        require_domain_match(&api_key, req_domain)?;
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
                let mut resp: SystemDomainResponse = record.clone().into();
                // Enrich address-type records with their per-agent meta.
                if record.domain.contains('@') {
                    if let Ok(Some(meta)) = state
                        .factories
                        .email
                        .env_factory
                        .resolve_domain_addr_meta(&record.domain)
                        .await
                    {
                        apply_domain_meta(&mut resp, Some(&meta));
                    }
                }
                Ok(Json(resp))
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

    // D2 write-side boundary: a `system`-scoped key manages only its own
    // system's resources; cross-system writes are refused before any DB
    // mutation. Platform admins are unrestricted (mirrors the read-side
    // exemption in list_system_domains / get_address_status).
    if !is_platform_admin_scope(&api_key) && existing_domain.system_id != api_key.system_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "Domain '{}' belongs to system '{}', not '{}'",
                    existing_domain.domain, existing_domain.system_id, api_key.system_id
                )),
            }),
        ));
    }

    let is_admin_like = is_system_admin_scope(&api_key);
    if !is_admin_like {
        let req_domain = existing_domain
            .domain
            .rsplit('@')
            .next()
            .unwrap_or(&existing_domain.domain);
        require_domain_match(&api_key, req_domain)?;
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

// ── Agent address rename (identity switch with full resource inheritance) ──

/// POST /api/v1/admin/systems/:sid/addresses/rename
/// Atomically renames an agent address old@domain → new@domain on the same
/// domain. The agent's api_key is re-pointed (not regenerated), and every
/// server-side reference — whitelists (both sides), contact/state keys,
/// boards/members/tasks/events, webhook record — is migrated in one
/// transaction, so the switch inherits all resources. The old address
/// stops working (identity switch is complete); mail history snapshots are
/// untouched.
#[derive(Debug, Deserialize)]
pub struct RenameAddressRequest {
    pub old_email: String,
    pub new_email: String,
}

async fn rename_agent_address(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path(tid): Path<String>,
    Json(req): Json<RenameAddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;
    // agent_admin may only rename their own address.
    if is_agent_admin_scope(&api_key) && api_key.email_address != req.old_email {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "not_owner".into(),
                detail: Some("agent_admin keys may only rename their own address".into()),
            }),
        ));
    }
    let old = req.old_email.trim().to_lowercase();
    let new = req.new_email.trim().to_lowercase();
    if old == new {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "same_address".into(),
                detail: None,
            }),
        ));
    }
    // Same bare domain required (rename is a local-part switch).
    let old_domain = old.rsplit('@').next().unwrap_or("");
    let new_domain = new.rsplit('@').next().unwrap_or("");
    if old_domain.is_empty() || new_domain != old_domain {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "cross_domain_rename".into(),
                detail: Some("rename must stay on the same bare domain".into()),
            }),
        ));
    }
    // Local-part shape mirrors register_address validation.
    let new_local = new.split('@').next().unwrap_or("");
    let dot_count = new_local.bytes().filter(|&b| b == b'.').count();
    let legal = !new_local.is_empty()
        && new_local.len() <= 64
        && new_local.bytes().all(is_atext_no_dot)
        && if tid.starts_with("shared-") {
            dot_count == 1
        } else {
            dot_count == 0
        };
    if !legal {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "invalid_email".into(),
            detail: Some("new local-part must match the system's address format (shared: one dot; non-shared: none), atext-no-dot only".into()),
        })));
    }
    // `new` must not already be registered anywhere.
    let ef = &state.factories.email.env_factory;
    if ef.lookup_domain_addr(&new).await.ok().flatten().is_some()
        || ef
            .db
            .get_domain_addr_meta(&new)
            .await
            .ok()
            .flatten()
            .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "already_exists".into(),
                detail: Some(format!("'{new}' is already a registered address")),
            }),
        ));
    }
    // `old` must exist and belong to this system.
    let rec = match ef.db.get_system_domain_by_name(&old).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "agent_not_found".into(),
                    detail: Some(format!("No registered address '{old}'")),
                }),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".into(),
                    detail: Some(e.to_string()),
                }),
            ));
        }
    };
    if rec.system_id != tid {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some("Address does not belong to this system".into()),
            }),
        ));
    }

    if let Err(e) = ef.db.rename_agent_address_refs(&old, &new).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
                detail: Some(e.to_string()),
            }),
        ));
    }
    info!(operation = "agent_address_renamed", system_id = %tid, old = %old, new = %new, "Agent address renamed with resource inheritance");
    Ok(Json(serde_json::json!({
        "status": "renamed",
        "old": old,
        "new": new,
        "system_id": tid,
        "key_preserved": true,
    })))
}

// ── Single-address read-only probe ──

/// Response of `GET /api/v1/admin/systems/:sid/addresses/:addr`.
///
/// **Exactly two booleans — never a row.** The endpoint exists so a caller
/// (gate / quota pre-check) can ask "is this address there, and is it
/// usable?" without the gateway ever serializing a row: no `webhook_url`, no
/// `webhook_secret`, no manager/signature/persona, no id, no timestamps.
/// A list/enumeration endpoint over a system's addresses was explicitly
/// rejected by the owner for the same data-security reason.
///
/// `valid` is derived from the **real** schema: `system_domains` has one
/// liveness column, `is_active` (`core/storage.rs` CREATE TABLE), and the
/// migrations in `core/storage.rs` only create tables — no ALTER TABLE adds a
/// validity/expiry column to any of them. So `valid = is_active` — there is
/// no date column to consult. `exists` = a `system_domains` row whose
/// `domain_addr` equals the
/// probe AND belongs to the probed system.
///
/// The struct having no other fields is load-bearing: the unit tests assert
/// the serialized object has exactly `{exists, valid}`, so a future field
/// cannot be added silently.
#[derive(Debug, Serialize)]
struct AddressStatusResponse {
    exists: bool,
    valid: bool,
}

impl AddressStatusResponse {
    /// The single non-disclosing answer. Used for "no such row", for a value
    /// that cannot be an address, and for every unauthorized agent-scope
    /// probe — identical bytes in all three cases, so the response is not an
    /// existence oracle.
    fn absent() -> Self {
        Self {
            exists: false,
            valid: false,
        }
    }
}

/// GET /api/v1/admin/systems/:sid/addresses/:addr — read-only existence +
/// validity probe for ONE address (`:addr` = the full email, URL-encoded).
///
/// Authorization reuses the existing scope predicates — no second auth model:
/// - `platform` → any system, any address (same rule as GET .../domains);
/// - `system` / `agent_admin` → only its own system; a foreign `:sid` is
///   `403` like the sibling handlers (a 403 confirms no row);
/// - `agent` → only its own address under its own system; any other probe
///   (another address, or another system) returns the neutral
///   `{false,false}`, byte-identical to a nonexistent address ⇒ no
///   existence leak. The DB is not even queried in that case;
/// - any other scope (`bridge`, …) → `403` via `require_scope_any`.
///
/// A value without `@` can never report `exists = true`: this endpoint
/// probes addresses, never the bare-domain rows that share the table.
async fn get_address_status(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Path((tid, addr)): Path<(String, String)>,
) -> Result<Json<AddressStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let addr = addr.trim().to_lowercase();

    if is_platform_admin_scope(&api_key) {
        // platform admin: unrestricted (mirrors GET /api/v1/admin/systems/:sid/domains)
    } else if is_system_admin_scope(&api_key) || is_agent_admin_scope(&api_key) {
        if api_key.system_id != tid {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cross-system access denied".into(),
                    detail: Some(format!(
                        "Key system '{}' cannot read addresses of system '{}'",
                        api_key.system_id, tid
                    )),
                }),
            ));
        }
    } else if is_agent_scope(&api_key) {
        // Agent keys see their own address and nothing else — and only under
        // their own system. Anything else gets the neutral answer, with no DB
        // round trip and no distinguishable status code.
        let is_own = api_key.email_address.eq_ignore_ascii_case(&addr);
        if !is_own || api_key.system_id != tid {
            return Ok(Json(AddressStatusResponse::absent()));
        }
    } else {
        require_scope_any(&api_key, &["system", "agent_admin"])?;
    }

    // Domain-level rows live in the same table; they are not addresses.
    if !addr.contains('@') {
        return Ok(Json(AddressStatusResponse::absent()));
    }

    let record = state
        .factories
        .email
        .env_factory
        .lookup_domain_addr(&addr)
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

    // The row must belong to the probed system; a row of another system is
    // simply "not this system's address".
    Ok(Json(match record.filter(|r| r.system_id == tid) {
        Some(r) => AddressStatusResponse {
            exists: true,
            valid: r.is_active,
        },
        None => AddressStatusResponse::absent(),
    }))
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

    // D2 write-side boundary: a `system`-scoped key manages only its own
    // system's resources; cross-system writes are refused before any DB
    // mutation. Platform admins are unrestricted (mirrors the read-side
    // exemption in list_system_domains / get_address_status).
    if !is_platform_admin_scope(&api_key) && existing.system_id != api_key.system_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".into(),
                detail: Some(format!(
                    "Agent '{}' belongs to system '{}', not '{}'",
                    email, existing.system_id, api_key.system_id
                )),
            }),
        ));
    }

    // AA: must be the manager of this agent
    // D10: manager match is case-insensitive (stored value is normalized on write).
    if is_agent_admin_scope(&api_key)
        && !existing
            .manager_address
            .eq_ignore_ascii_case(&api_key.email_address)
    {
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

pub async fn create_whitelist(
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
            check_whitelist_access(
                &api_key,
                &req.domain_addr,
                state
                    .factories
                    .email
                    .env_factory
                    .owning_system_of(&req.domain_addr)
                    .await
                    .as_deref(),
            )?;
            Some(api_key.id)
        };
        // Whitelist per-key limit is enforced by a request interceptor in builds
        // that install one (POST /api/v1/whitelists intercept).
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
        check_whitelist_access(
            &api_key,
            &req.domain_addr,
            state
                .factories
                .email
                .env_factory
                .owning_system_of(&req.domain_addr)
                .await
                .as_deref(),
        )?;
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
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient scope".to_string(),
                detail: Some(
                    "PlatformAdmin can only view and toggle whitelist entries".to_string(),
                ),
            }),
        ))
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
    if is_agent_scope(&api_key) && !is_admin_scope(&api_key) {
        // Agent: only return category='agent' AND api_key_id=their own key id
        // NOTE: admin-scoped keys that also carry "agent" scope (system keys
        // get scopes=["system","agent"]) must NOT take this branch — admin
        // visibility is strictly wider (see is_admin_scope branch below).
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
    } else if is_agent_admin_scope(&api_key)
        && !is_system_admin_scope(&api_key)
        && !is_platform_admin_scope(&api_key)
    {
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
        require_domain_match(&api_key, &query.domain_addr)?;
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
    // System auto-mail sender is whitelisted by construction — agents must
    // never request adding it to their whitelist/contacts (it is the
    // gateway itself; config.system_sender() is the single Rust-side
    // source). Any direction: inbound auto mails are system deliveries,
    // outbound to noreply lands in the sink.
    if query.value.trim().to_lowercase() == state.config.system_sender().to_lowercase() {
        return Ok(Json(serde_json::json!({
            "whitelisted": true,
            "system_sender": true,
            "domain_addr": query.domain_addr,
            "value": query.value,
            "direction": query.direction,
        })));
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
                check_whitelist_access(
                    &api_key,
                    &entry.domain_addr,
                    state
                        .factories
                        .email
                        .env_factory
                        .owning_system_of(&entry.domain_addr)
                        .await
                        .as_deref(),
                )?;
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
        check_whitelist_access(
            &api_key,
            &query.domain_addr,
            state
                .factories
                .email
                .env_factory
                .owning_system_of(&query.domain_addr)
                .await
                .as_deref(),
        )?;
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
        check_whitelist_access(
            &api_key,
            &query.domain_addr,
            state
                .factories
                .email
                .env_factory
                .owning_system_of(&query.domain_addr)
                .await
                .as_deref(),
        )?;
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
                check_whitelist_access(
                    &api_key,
                    &entry.domain_addr,
                    state
                        .factories
                        .email
                        .env_factory
                        .owning_system_of(&entry.domain_addr)
                        .await
                        .as_deref(),
                )?;
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
            Some(ref entry) => check_whitelist_access(
                &api_key,
                &entry.domain_addr,
                state
                    .factories
                    .email
                    .env_factory
                    .owning_system_of(&entry.domain_addr)
                    .await
                    .as_deref(),
            )?,
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
    // System auto-mail sender (configurable: noreply@{smtp.hostname} via
    // config.system_sender()) is a known entity by construction — not a
    // registered contact. Return it without a DB lookup so agent contact
    // checks never treat auto mails as unknown senders.
    if address.trim().to_lowercase() == state.config.system_sender().to_lowercase() {
        return Ok(Json(serde_json::json!({
            "address": address,
            "profile": {"type": "system", "auto_mail": true},
        })));
    }
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
///
/// GET /api/v1/contacts?addresses=a,b,c — batch profile lookup (preprocessor).
/// The FIRST address in the list is the inbound sender; the rest are
/// recipients. Returns:
///   {
///     "my_profile":         {address, profile} | null  — the calling agent's
///                                       approved persona (domain_addr_meta),
///     "sender_profile":     {address: profile}  — sender's stored profile,
///     "recipients_profile": {address: profile}  — recipients' stored profiles,
///     "results":            [{address, profile}]  — all found, in input order
///   }
/// Profiles are stored under base-address keys (`profile:{base}`);
/// persona-prefixed addresses resolve by stripping the prefix, with a
/// fallback to a literal full-address key. Returned addresses keep the
/// full (persona-prefixed) form the caller passed.
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

    // ── Batch branch: profile lookup by address list ──
    if let Some(raw) = query
        .addresses
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut seen = std::collections::HashSet::new();
        let addresses: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .filter(|s| seen.insert(s.clone()))
            .collect();
        if addresses.len() > 50 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "too many addresses (max 50)".to_string(),
                    detail: None,
                }),
            ));
        }

        // Self profile: the approved persona is the single source of truth.
        let my_profile: Option<serde_json::Value> = match db.get_domain_addr_meta(agent_addr).await
        {
            Ok(Some(meta)) if !meta.agent_persona.is_empty() => Some(serde_json::json!({
                "address": agent_addr,
                "profile": meta.agent_persona,
            })),
            _ => None,
        };

        let mut sender_profile = serde_json::Map::new();
        let mut recipients_profile = serde_json::Map::new();
        let mut results = Vec::new();
        for (i, addr) in addresses.iter().enumerate() {
            if let Some(profile) = fetch_contact_profile(db, agent_addr, addr).await {
                if i == 0 {
                    sender_profile.insert(addr.clone(), serde_json::Value::String(profile.clone()));
                } else {
                    recipients_profile
                        .insert(addr.clone(), serde_json::Value::String(profile.clone()));
                }
                results.push(serde_json::json!({
                    "address": addr,
                    "profile": profile,
                }));
            }
        }

        return Ok(Json(serde_json::json!({
            "my_profile": my_profile,
            "sender_profile": sender_profile,
            "recipients_profile": recipients_profile,
            "results": results,
        })));
    }

    // ── Name search branch ──
    let name = match &query.name {
        Some(n) if !n.trim().is_empty() => n.trim().to_lowercase(),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "either name or addresses query parameter is required".to_string(),
                    detail: None,
                }),
            ));
        }
    };

    let index_value = db
        .agent_state_get(agent_addr, &format!("name:{}", name))
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

/// Look up a stored contact profile for `addr` under the calling agent.
/// Tries the persona-stripped base address first, then the literal
/// full address (legacy entries stored with a persona prefix).
async fn fetch_contact_profile(db: &Database, agent_addr: &str, addr: &str) -> Option<String> {
    let (base, _persona) = crate::core::email::utils::strip_persona(addr);
    if let Ok(Some((_, v))) = db
        .agent_state_get(agent_addr, &format!("profile:{}", base))
        .await
    {
        return Some(v);
    }
    if base != addr {
        if let Ok(Some((_, v))) = db
            .agent_state_get(agent_addr, &format!("profile:{}", addr))
            .await
        {
            return Some(v);
        }
    }
    None
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

// ── Pending deliveries (pull-mode for aimail-bridge) ──

#[derive(Deserialize, Clone)]
struct PendingPollRequest {
    /// Max rows to hand out. The scope is fixed by the endpoint (one AgentSystemId); the retired
    /// per-address/system variants were the only users of `emails` / `filter` / `timeout_ms`.
    limit: i64,
}
fn default_limit() -> i64 {
    20
}

#[derive(Deserialize)]
struct AckRequest {
    ids: Vec<i64>,
}

/// Group pending records into batches keyed by payload hash so identical
/// payloads share one body (mailing-list / broadcast responses stay small).
/// Single source of truth for the pull response shape — the POST handler
/// and the SSE `mail` event both use this, so their shapes cannot drift.
fn group_pending_batches(
    records: &[crate::core::storage::PendingDeliveryRecord],
) -> serde_json::Value {
    use std::collections::{hash_map::DefaultHasher, HashMap};
    use std::hash::{Hash, Hasher};
    let mut batches_map: HashMap<i64, Vec<(i64, String, String)>> = HashMap::new();
    let mut batch_order: Vec<(i64, String)> = Vec::new(); // (hash, body)
    for r in records {
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

    serde_json::json!({ "batches": batches })
}

fn agent_system_id_from_headers(
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let id = headers
        .get("x-agent-system-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 80
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "missing AgentSystemId".to_string(),
                    detail: Some("X-Agent-System-Id header is required".to_string()),
                }),
            )
        })?;
    Ok(id.to_string())
}

/// Stable synthetic slot id for an AgentSystemId. The address key used to
/// authenticate the aggregate is only a representative; the single-slot lock
/// must be per (AgentSystemId, Gateway), not per representative address key.
/// Negative ids cannot collide with sqlite api_keys row ids.
fn agent_system_slot_id(agent_system_id: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    agent_system_id.hash(&mut hasher);
    -((hasher.finish() & 0x7fff_ffff_ffff_ffff) as i64) - 1
}

async fn require_agent_system_owner(
    db: &crate::core::storage::Database,
    api_key: &ApiKeyRecord,
    agent_system_id: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !api_key.scopes.iter().any(|s| s == "agent") || api_key.email_address.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "agent scope required".to_string(),
                detail: Some(
                    "AgentSystemId aggregation requires an address-scoped key".to_string(),
                ),
            }),
        ));
    }
    let owned = db
        .list_agent_system_addresses(agent_system_id)
        .await
        .unwrap_or_default();
    let email = api_key.email_address.to_lowercase();
    if !owned.iter().any(|(a, _)| a.to_lowercase() == email) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "not the AgentSystemId owner".to_string(),
                detail: Some(format!("{email} is not owned by {agent_system_id}")),
            }),
        ));
    }
    Ok(())
}

/// Parse the client's anchor claims from `X-Aimail-Anchor: <email>;<sha256>` headers.
///
/// The anchor itself is an AGENT-side concept (dsh: workspace path, pi: cwd, openclaw: agent
/// workspace), so the gateway never learns or interprets it — it only compares the opaque hash the
/// client computed at activation with the one the request presents now. Multiple addresses ride in
/// multiple header values because one aggregate pull covers a whole AgentSystemId.
fn parse_anchor_claims(
    headers: &axum::http::HeaderMap,
) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for value in headers.get_all("x-aimail-anchor").iter() {
        let Ok(raw) = value.to_str() else { continue };
        for part in raw.split(',') {
            let mut it = part.splitn(2, ';');
            let email = it.next().unwrap_or("").trim().to_lowercase();
            let hash = it.next().unwrap_or("").trim().to_lowercase();
            if email.contains('@')
                && hash.len() == 64
                && hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                out.insert(email, hash);
            }
        }
    }
    out
}

/// Contract §7.1 (anchor binding) — STRICT: a pull that cannot prove its anchors is refused.
///
/// Owner ruling 2026-11-25: there is no production deployment yet, so there is no legitimate
/// anchor-less client to stay compatible with — the lenient rollout ("no record ⇒ allow") is gone.
/// A pull is accepted only when:
///
/// 1. the request carries `X-Aimail-Anchor` claims at all (`anchor_required`);
/// 2. every address this AgentSystemId owns has a registered anchor (`anchor_unregistered`);
/// 3. every claim equals the hash registered at activation (`anchor_mismatch`).
///
/// This is what makes "edit the local binding file and the mailbox moves" impossible: the anchor is
/// registered at activation, so a client that re-points its address locally presents a different
/// hash and is refused here — before any mail is handed out.
async fn enforce_anchor_binding(
    db: &crate::core::storage::Database,
    agent_system_id: &str,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let claimed = parse_anchor_claims(headers);
    if claimed.is_empty() {
        return Err(anchor_refusal(
            "anchor_required",
            "this pull carries no X-Aimail-Anchor claim. Every aggregate pull MUST present \
             `email;sha256(anchor)` for each address of the AgentSystemId (contract §7.1); \
             the client hashes the agent's own stable anchor (dsh/openclaw: the workspace, \
             pi: ~/.pi/agent)."
                .to_string(),
        ));
    }
    // ONE query for the whole decision (addresses + their registered anchor): this runs on every
    // SSE connect, every long-poll and every ack, so it must cost the same as the lenient version
    // that preceded it (one indexed statement) — not two.
    let rows = db
        .agent_system_address_anchors_cached(agent_system_id)
        .await
        .map_err(|e| {
            // Fail CLOSED, not open: if the witness cannot be read, the anchor cannot be proven, and
            // "cannot prove" must never turn into "let it through" (v2.5 makes this a hard rule).
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    detail: Some(format!("cannot verify the anchor binding: {e}")),
                }),
            )
        })?;
    if rows.is_empty() {
        // No address is bound to this AgentSystemId ⇒ no mail can be handed out. Nothing to verify.
        return Ok(());
    }
    // 2) every address of the group must have an anchor: an activation that did not register one
    //    leaves the address movable by editing the binding file, which is exactly what §7.1 forbids.
    // 3) the claims must match what activation registered (including "this address is missing").
    let mut unregistered: Vec<String> = Vec::new();
    let mut bad: Vec<String> = Vec::new();
    // One scratch buffer, reused: `parse_anchor_claims` already lowercased the keys, so a per-row
    // `to_lowercase()` would allocate twice per address for nothing. This loop is O(addresses) and
    // runs on every pull; keep it allocation-free apart from the (rare) refusal lists.
    let mut key = String::new();
    for (address, registered) in rows.iter() {
        match registered {
            None => unregistered.push(address.clone()),
            Some(want) => {
                key.clear();
                key.push_str(address);
                key.make_ascii_lowercase();
                let got = claimed.get(&key).map(|v| v.as_str()).unwrap_or("");
                if !got.eq_ignore_ascii_case(want) {
                    bad.push(address.clone());
                }
            }
        }
    }
    if !unregistered.is_empty() {
        unregistered.sort();
        return Err(anchor_refusal(
            "anchor_unregistered",
            format!(
                "no anchor is registered for: {}. The address must be (re-)activated with an \
                 anchor before it can be pulled — an unanchored address could be moved by editing \
                 the local binding file (contract §7.1).",
                unregistered.join(", ")
            ),
        ));
    }
    if bad.is_empty() {
        return Ok(());
    }
    bad.sort();
    Err(anchor_refusal(
        "anchor_mismatch",
        format!(
            "the anchor registered at activation does not match this request for: {}. \
             The anchor is fixed by activation — re-activate to move an address.",
            bad.join(", ")
        ),
    ))
}

/// One 403 shape for every anchor refusal (the client must be able to tell the three apart).
fn anchor_refusal(error: &str, detail: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: error.to_string(),
            detail: Some(detail),
        }),
    )
}

async fn agent_system_stream(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    headers: axum::http::HeaderMap,
    client_id: ClientId,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let agent_system_id = agent_system_id_from_headers(&headers)?;
    let db = &state.factories.email.env_factory.db;
    require_agent_system_owner(db, &api_key, &agent_system_id).await?;
    enforce_anchor_binding(db, &agent_system_id, &headers).await?;
    sse_response_scoped(
        state,
        api_key,
        std::time::Duration::from_secs(SSE_HEARTBEAT_SECS),
        std::time::Duration::from_secs(SSE_MAX_LIFE_SECS),
        client_id.0,
        agent_system_id,
    )
    .await
}

async fn list_agent_system_pending(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    headers: axum::http::HeaderMap,
    client_id: ClientId,
    Json(req): Json<PendingPollRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let agent_system_id = agent_system_id_from_headers(&headers)?;
    let db = &state.factories.email.env_factory.db;
    require_agent_system_owner(db, &api_key, &agent_system_id).await?;
    enforce_anchor_binding(db, &agent_system_id, &headers).await?;
    // One consumer per (AgentSystemId, Gateway): the aggregate stream and the
    // aggregate long-poll share the same synthetic slot, so a second client
    // cannot double-deliver the same ASID mailbox.
    let slot_key = agent_system_slot_id(&agent_system_id);
    if !state.delivery_slot.try_acquire(
        slot_key,
        client_id_of(&client_id),
        std::time::Duration::from_secs(SLOT_POLL_LEASE_SECS),
    ) {
        return Err(occupied_error(
            "another client holds this AgentSystemId; retry later".to_string(),
        ));
    }
    let _guard = SlotGuard::new(
        state.delivery_slot.clone(),
        slot_key,
        client_id_of(&client_id),
    );
    let records = db
        .list_pending_for_agent_system(&agent_system_id, req.limit)
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
    Ok(Json(group_pending_batches(&records)))
}

async fn ack_agent_system_pending(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if req.ids.len() > 500 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "too many ids".to_string(),
                detail: Some("max 500 ids per ACK".to_string()),
            }),
        ));
    }
    let agent_system_id = agent_system_id_from_headers(&headers)?;
    let db = &state.factories.email.env_factory.db;
    require_agent_system_owner(db, &api_key, &agent_system_id).await?;
    enforce_anchor_binding(db, &agent_system_id, &headers).await?;
    let count = db
        .ack_pending_for_agent_system(&agent_system_id, &req.ids)
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

// Probe network reachability to a host:port from the relay.
//
// 2026-10-13: restored from v1.0 (`7d766b5^`) for the CLI install webhook
// plan. This endpoint is a **pure TCP classifier** — it reports the outcome
// class (`connected` / `connection_refused` / `timeout` / `unreachable` /
// `loopback_not_allowed`) and it is the **caller** that interprets it
// against the plan:
// - agent-endpoint probe (GW → AIMAIL_AGENT_HOST): `connection_refused`
//   means the path is open but the agent process is not listening yet
//   (the agent starts after install) ⇒ treated as REACHABLE.
// - bridge-endpoint probe (GW → AIMAIL_BRIDGE_HOST): `connection_refused`
//   means the bridge process is down ⇒ treated as UNREACHABLE (degrade).
// Loopback targets are rejected by the endpoint itself so a remote GW can
// never "probe" its own machine.

// ── Pending delivery SSE stream (S2 primary transport) ───────
//
// `GET /api/v1/admin/pending/stream` — auth identical to the POST pull
// (same auth layer; a GET signs with an empty body, `auth.rs`). One
// long-lived event stream per client:
//
//   * connect-time query ⇒ `event: mail` (data == POST response shape,
//     built by the SAME `group_pending_batches` ⇒ shape parity by
//     construction, not by test);
//   * writer wake-ups and the heartbeat both re-query under the caller's
//     OWN scope filter and emit only rows with `id > watermark`
//     (at-least-once: a reconnect re-sends unacked rows; clients dedupe
//     by delivery id — same contract as long-pull);
//   * `: ping` heartbeat every `heartbeat` (contract:
//     `SSE_HEARTBEAT_SECS`; defensive — prod runs no proxy, ruling
//     2026-10-26, so it also doubles as the missed-notify safety net);
//   * the server closes the stream at `life` (contract:
//     `SSE_MAX_LIFE_SECS`); clients reconnect with backoff and fall back
//     to long-poll when the endpoint is absent (e.g. server rollback).
//
// The stream NEVER acks — acks stay on `POST /ack`.

struct SseStreamState {
    db: std::sync::Arc<crate::core::storage::Database>,
    nkey: NotifyKey,
    req: PendingPollRequest,
    /// Max delivery id already emitted on this connection. 0 = nothing yet.
    watermark: i64,
    /// Notifier gen the caller has already observed; wait for gen > this.
    since: u64,
    heartbeat: std::time::Duration,
    life: std::time::Duration,
    started: tokio::time::Instant,
    /// Rows already fetched but not yet emitted, in id order.
    ///
    /// A queue (not a single "first batch") because ONE frame is now bounded by BYTES: whatever
    /// does not fit is emitted by the following steps instead of being held in one giant frame.
    /// Total memory per stream stays within `snapshot_bytes`.
    queue: std::collections::VecDeque<crate::core::storage::PendingDeliveryRecord>,
    /// Byte budget for one frame (and for the fetch that fills the queue). 0 = count-only.
    snapshot_bytes: usize,
    /// Capacity permit (concurrent-stream cap). Held for the life of the stream; dropping it
    /// frees the slot even on an abrupt disconnect, because the stream future is dropped too.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// When set, this stream is scoped to an AgentSystemId (aggregate mode).
    agent_system_id: Option<String>,
    /// Single-slot claim: released on drop (abrupt disconnect, zero grace)
    /// or explicitly on the max-life rotation (grace window).
    guard: SlotGuard,
}

type SseItem = Result<String, std::io::Error>;

/// `X-Aimail-Client` header: the client's stable process identity for the
/// single-slot mailbox lock. Absent/empty = legacy client (id "").
struct ClientId(String);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for ClientId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    // Trait implementation (axum extractor) — the single call site is the
    // axum router dispatching `GET /api/v1/events` (D14: retained, not dead code).
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let id = parts
            .headers
            .get("X-Aimail-Client")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or("")
            .to_string();
        Ok(Self(id))
    }
}

/// 409 "occupied": another client currently holds this key's mailbox slot
/// (stream or long-poll). Distinct from auth/scope errors so clients can
/// back off in place without degrading their transport.
fn occupied_error(detail: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse {
            error: "occupied".to_string(),
            detail: Some(detail),
        }),
    )
}

/// The slot identity for a request: the client id, or "" for legacy
/// clients that send no `X-Aimail-Client` header.
fn client_id_of(cid: &ClientId) -> &str {
    &cid.0
}

/// Take up to `budget` bytes of queued records (always at least one) for the NEXT frame.
///
/// Bytes, not rows: a single mail can be up to `smtp.max_message_size`, so "20 rows" is not a bound.
/// Keeping the batch together preserves `group_pending_batches` de-duplication (one body, N
/// deliveries) while keeping the frame — and the copy `format!` makes of it — inside the budget.
fn drain_frame_batch(
    queue: &mut std::collections::VecDeque<crate::core::storage::PendingDeliveryRecord>,
    budget: usize,
) -> Vec<crate::core::storage::PendingDeliveryRecord> {
    let mut out: Vec<crate::core::storage::PendingDeliveryRecord> = Vec::new();
    let mut used = 0usize;
    while let Some(rec) = queue.front() {
        let size = rec.payload.len() + rec.headers.len();
        if budget > 0 && !out.is_empty() && used + size > budget {
            break;
        }
        used += size;
        if let Some(rec) = queue.pop_front() {
            out.push(rec);
        }
    }
    out
}

/// Admission for one more concurrent stream.
///
/// The cap lives on the state ([`HttpState::sse_slots`]) so tests can size it; the permit is kept
/// in the stream state, which means an abrupt disconnect frees the slot when the future drops.
fn try_take_sse_slot(
    state: &HttpState,
) -> Result<tokio::sync::OwnedSemaphorePermit, (StatusCode, Json<ErrorResponse>)> {
    state.sse_slots.clone().try_acquire_owned().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "sse_capacity".to_string(),
                detail: Some(format!(
                    "{} concurrent streams are already open (http.max_sse_connections); \
                     retry with backoff",
                    state.config.http.max_sse_connections
                )),
            }),
        )
    })
}

fn sse_mail_frame(payload: &serde_json::Value) -> SseItem {
    Ok(format!("event: mail\ndata: {}\n\n", payload))
}

/// One unfold step. Returns the next frame (mail or ping) plus the
/// updated state, or `None` when the stream ends (max life).
async fn sse_stream_step(mut st: SseStreamState) -> Option<(SseItem, SseStreamState)> {
    let notifier = PendingNotifier::global();

    // Anything already queued (connect snapshot or a previous over-budget fetch) goes out first,
    // one BUDGETED frame at a time — never the whole queue in one allocation.
    if !st.queue.is_empty() {
        let batch = drain_frame_batch(&mut st.queue, st.snapshot_bytes);
        if !batch.is_empty() {
            st.watermark = batch.iter().map(|r| r.id).max().unwrap_or(st.watermark);
            return Some((sse_mail_frame(&group_pending_batches(&batch)), st));
        }
    }

    loop {
        if st.started.elapsed() >= st.life {
            // Max-life rotation: hand the slot back with the grace window
            // (same client re-acquires on reconnect; a stranger waits out
            // the grace). An abrupt disconnect instead drops the guard
            // with zero grace.
            st.guard.release_on_rotation();
            return None;
        }
        let agent_system_id = st.agent_system_id.clone().unwrap_or_default();
        // Event-driven first: ingest calls `notify_agent_system` right after the pending row
        // commits, so new mail is pushed in ~one DB query instead of waiting out the heartbeat.
        // The heartbeat is the TIMEOUT: keep-alive, lost-notify fallback and the only clock when
        // nothing is happening (its timeout path does NOT query the store).
        let outcome = notifier.wait_since(&st.nkey, st.since, st.heartbeat).await;
        st.since = notifier.snapshot(&st.nkey);
        if matches!(outcome, WaitOutcome::Timeout) {
            return Some((Ok(": ping\n\n".to_string()), st));
        }
        match st
            .db
            .list_pending_for_agent_system_budgeted(
                &agent_system_id,
                st.req.limit,
                st.snapshot_bytes,
            )
            .await
        {
            Ok(records) => {
                for rec in records {
                    if rec.id > st.watermark {
                        st.queue.push_back(rec);
                    }
                }
                if !st.queue.is_empty() {
                    let batch = drain_frame_batch(&mut st.queue, st.snapshot_bytes);
                    st.watermark = batch.iter().map(|r| r.id).max().unwrap_or(st.watermark);
                    return Some((sse_mail_frame(&group_pending_batches(&batch)), st));
                }
            }
            Err(_) => { /* next wake re-queries */ }
        }
        // Woke (or storage error) with nothing new: keep waiting.
    }
}

/// Build the SSE response for the given caller. `heartbeat`/`life` are
/// parameters so tests can inject short periods; the public handler passes
/// the contract constants.
/// Retired pull scopes (owner ruling 2026-11-26): per-address and system/domain pull are gone;
/// the ONLY pull transport is the AgentSystemId aggregate (`/api/v1/agent-system/pending*`).
///
/// Kept as a route (not a 404) so an outdated client is told exactly what to do. Webhook PUSH is
/// untouched — it never went through these paths.
async fn retired_pull_scope() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::GONE,
        Json(ErrorResponse {
            error: "pull_scope_retired".to_string(),
            detail: Some(
                "the per-address / system-scope pull endpoints were retired: pull via \
                 POST /api/v1/agent-system/pending (stream/ack siblings) with an agent-scope key \
                 plus X-Agent-System-Id and X-Aimail-Anchor. Webhook push is unaffected."
                    .to_string(),
            ),
        }),
    )
}

async fn sse_response_scoped(
    state: State<HttpState>,
    _api_key: crate::core::storage::ApiKeyRecord,
    heartbeat: std::time::Duration,
    life: std::time::Duration,
    client_id: String,
    agent_system_id: String,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Capacity FIRST: a reconnect storm must be refused cheaply (503) before it allocates the
    // slot, the snapshot or the stream state. The permit rides in the stream state, so an abrupt
    // disconnect releases it with the future.
    let permit = try_take_sse_slot(&state)?;
    // Single-slot claim BEFORE any work: the first connection wins; a
    // different client is 409 without building a stream. Same client
    // (reconnect / rotation) re-acquires and refreshes. Aggregate streams use
    // a synthetic ASID slot (the representative key is not the identity).
    let slot_key = agent_system_slot_id(&agent_system_id);
    if !state.delivery_slot.try_acquire(
        slot_key,
        client_id.as_str(),
        std::time::Duration::from_secs(SLOT_STREAM_LEASE_SECS),
    ) {
        // Diagnostics: name the HOLDER (whoever currently occupies the slot),
        // not this rejected requester.
        let holder = state
            .delivery_slot
            .holder_id(slot_key)
            .filter(|h| !h.is_empty())
            .map(|h| format!(" (client {h})"))
            .unwrap_or_default();
        return Err(occupied_error(format!(
            "another client holds the mailbox for this key{holder}; retry later"
        )));
    }
    let db = &state.factories.email.env_factory.db;
    let notifier = PendingNotifier::global();
    // No filter on the stream: the scope fork IS the range (§2.5).
    let req = PendingPollRequest {
        limit: default_limit(),
    };
    // Budgeted: the connect snapshot is the only place where "20 rows" can mean hundreds of MB
    // (20 x up to smtp.max_message_size). The rest stays pending and arrives on a later frame.
    let initial = db
        .list_pending_for_agent_system_budgeted(
            &agent_system_id,
            req.limit,
            state.config.http.connect_snapshot_bytes,
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
    // Aggregate streams wait on the AgentSystem key (pushed on ingest), not on the representative
    // address' key: mail for a non-representative member would never wake it.
    let nkey = crate::core::pending_notifier::NotifyKey::AgentSystem(agent_system_id.clone());
    // Snapshot AFTER the connect query: rows already emitted cannot be
    // double-emitted by their own notify.
    let since = notifier.snapshot(&nkey);

    let st = SseStreamState {
        db: db.clone(),
        nkey,
        req,
        watermark: 0,
        since,
        heartbeat,
        life,
        started: tokio::time::Instant::now(),
        queue: initial.into_iter().collect(),
        snapshot_bytes: state.config.http.connect_snapshot_bytes,
        _permit: Some(permit),
        agent_system_id: Some(agent_system_id),
        guard: SlotGuard::new(state.delivery_slot.clone(), slot_key, client_id.as_str()),
    };
    let stream = unfold(st, |st| async move { sse_stream_step(st).await });
    let resp = Response::builder()
        .header(CONTENT_TYPE, "text/event-stream")
        .header(CACHE_CONTROL, "no-cache")
        // Defensive: disable proxy response buffering. Production runs no
        // reverse proxy (ruling 2026-10-26) — kept so a future proxy
        // cannot silently buffer the stream.
        .header("X-Accel-Buffering", "no")
        .header(CONNECTION, "keep-alive")
        .body(Body::from_stream(stream));
    match resp {
        Ok(r) => Ok(r),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "stream build failed".to_string(),
                detail: None,
            }),
        )),
    }
}

/// Run one probe and classify the outcome. Pure classifier (2026-10-13):
/// the caller interprets the `error` class against the plan (see
/// `probe_webhook`). Returns the JSON payload the endpoint returns.
pub(crate) async fn probe_reachability(addr: &str) -> serde_json::Value {
    // Reject loopback addresses — probe is meant for cross-machine connectivity
    if let Ok(sock_addr) = addr.parse::<std::net::SocketAddr>() {
        if sock_addr.ip().is_loopback() {
            return serde_json::json!({
                "reachable": false,
                "error": "loopback_not_allowed",
                "detail": "Probe does not accept loopback addresses (127.0.0.1/::1). Provide a routable IP.",
            });
        }
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(addr),
    )
    .await;

    match result {
        Ok(Ok(_stream)) => serde_json::json!({
            "reachable": true,
            "error": "connected",
        }),
        Ok(Err(e)) => {
            let kind = e.kind();
            let error_str = if kind == std::io::ErrorKind::ConnectionRefused {
                "connection_refused"
            } else {
                "unreachable"
            };
            serde_json::json!({
                "reachable": false,
                "error": error_str,
                "detail": e.to_string(),
            })
        }
        Err(_elapsed) => serde_json::json!({
            "reachable": false,
            "error": "timeout",
            "detail": "dial tcp timeout after 5s",
        }),
    }
}

async fn probe_webhook(
    _state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(req): Json<ProbeWebhookRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_scope_any(&api_key, &["system"])?;
    Ok(Json(probe_reachability(&req.addr).await))
}

// ── Public config ─────────────────────────────────────────────────

// ── Email address validation ──────────────────────────────────────────

/// RFC 5321 `atext` characters excluding '.' (dot).
/// Dot is reserved as persona/system-id separator in AIMail addresses.
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

    // ─── P3-8: domain response meta enrichment ───

    fn domain_record(domain: &str) -> crate::core::storage::SystemDomainRecord {
        crate::core::storage::SystemDomainRecord {
            id: "d1".to_string(),
            system_id: "sys1".to_string(),
            domain: domain.to_string(),
            webhook_url: None,
            webhook_secret: None,
            is_active: true,
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
        }
    }

    fn meta_record(email: &str, manager: &str) -> DomainAddrMetaRecord {
        DomainAddrMetaRecord {
            email_address: email.to_string(),
            system_id: "sys1".to_string(),
            manager_address: manager.to_string(),
            agent_signature: "sig".to_string(),
            agent_persona: "persona".to_string(),
            is_active: true,
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
        }
    }

    #[test]
    fn apply_domain_meta_fills_address_record() {
        // Address-type record with a meta row → fields filled.
        let mut resp: SystemDomainResponse = domain_record("agent@x.com").into();
        assert_eq!(resp.manager_address, "", "baseline must be empty");
        apply_domain_meta(&mut resp, Some(&meta_record("agent@x.com", "mgr@x.com")));
        assert_eq!(resp.manager_address, "mgr@x.com");
        assert_eq!(resp.agent_signature, "sig");
        assert_eq!(resp.agent_persona, "persona");
    }

    #[test]
    fn apply_domain_meta_leaves_bare_domain_empty() {
        // Bare domain has no meta row → fields stay empty.
        let mut resp: SystemDomainResponse = domain_record("x.com").into();
        apply_domain_meta(&mut resp, None);
        assert_eq!(resp.manager_address, "");
        assert_eq!(resp.agent_signature, "");
        assert_eq!(resp.agent_persona, "");
    }

    // ─── GET /api/v1/admin/systems/:sid/addresses/:addr (read-only probe) ───
    //
    // The endpoint answers with EXACTLY `{exists, valid}` and nothing else.
    // These tests drive the real router (auth layer + handler + DB), not a
    // copy of the logic, so they cover the whole request path.

    use crate::base::strategy::{BaseRouterHook, BaseSystemStore};
    use crate::core::api::auth::compute_api_signature;
    use crate::core::api::dedup::SendDeduper;
    use crate::core::api::monitor::Metrics;
    use crate::core::api::seal::store_hash;
    use crate::core::config::Config;
    use crate::core::email::factory::MailFactories;
    use crate::core::strategy::ExtensionProviders;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// The security stance, in one place: the probe body carries ONLY
    /// `{exists, valid}`. Adding any field (webhook/secret/manager/…) must
    /// break this assertion.
    fn assert_only_two_fields(body: &serde_json::Value) {
        let obj = body
            .as_object()
            .unwrap_or_else(|| panic!("probe response must be a JSON object, got {body}"));
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["exists", "valid"],
            "probe response must expose ONLY {{exists, valid}} — got {body}"
        );
    }

    /// DB + HTTP state + router over a throwaway DB directory.
    async fn probe_fixture(
        tag: &str,
    ) -> (
        Arc<Database>,
        HttpState,
        tokio::sync::mpsc::Receiver<String>,
        std::path::PathBuf,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-http-probe-{tag}-{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Database::open(dir.join("aimail.db"), 4, None).unwrap());
        let mut config = Config::default();
        config.storage.path = dir.clone();
        let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(8);
        let state = HttpState {
            factories: MailFactories::new(db.clone(), &dir, Arc::new(BaseSystemStore)),
            metrics: Arc::new(Metrics::new()),
            config,
            trigger_tx,
            extensions: Arc::new(ExtensionProviders::base()),
            dns_resolver: None,
            send_deduper: SendDeduper::new(Duration::from_secs(60), 64),
            delivery_slot: SingleSlotLock::new(),
            sse_slots: Arc::new(tokio::sync::Semaphore::new(
                tokio::sync::Semaphore::MAX_PERMITS,
            )),
            health_extra: None,
        };
        (db, state, trigger_rx, dir)
    }

    // ── Peak shaving (2026-11-26): byte budget, budgeted frames, concurrent-stream cap ──

    // ── Retired scopes (2026-11-26) + the single remaining pull transport ──────────────────

    /// Drain up to `want` SSE frames (`event:` … `\n\n`) from a response body.
    async fn read_sse_events(
        body: axum::body::Body,
        want: usize,
        timeout: std::time::Duration,
    ) -> Vec<String> {
        use futures_util::StreamExt;
        let mut stream = body.into_data_stream();
        let mut out: Vec<String> = Vec::new();
        let mut buf = String::new();
        let deadline = tokio::time::Instant::now() + timeout;
        while out.len() < want {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(Ok(bytes))) => {
                    buf.push_str(&String::from_utf8_lossy(&bytes));
                    while let Some(idx) = buf.find("\n\n") {
                        let frame: String = buf.drain(..idx + 2).collect();
                        let frame = frame.trim_end().to_string();
                        if !frame.is_empty() {
                            out.push(frame);
                        }
                        if out.len() >= want {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        out
    }

    fn anchor_header(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (email, hash) in pairs {
            h.append(
                "x-aimail-anchor",
                format!("{email};{hash}").parse().unwrap(),
            );
        }
        h
    }

    #[tokio::test]
    async fn retired_pull_scopes_answer_410_with_the_new_transport() {
        let (code, body) = super::retired_pull_scope().await;
        assert_eq!(code, axum::http::StatusCode::GONE);
        assert_eq!(body.0.error, "pull_scope_retired");
        assert!(
            body.0
                .detail
                .unwrap_or_default()
                .contains("/api/v1/agent-system/pending"),
            "the refusal must point at the surviving transport"
        );
    }

    #[tokio::test]
    async fn aggregate_stream_serves_the_whole_group_and_takes_one_slot() {
        use axum::extract::State;
        let (db, state, _rx, dir) = probe_fixture("agg-stream").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        db.bind_agent_system_address("as-agg", "a@x.com", "sys1")
            .await
            .unwrap();
        db.bind_agent_system_address("as-agg", "b@x.com", "sys1")
            .await
            .unwrap();
        db.set_address_anchor("a@x.com", &"a".repeat(64))
            .await
            .unwrap();
        seed_key(&db, "sys1", "a@x.com", &["agent"], "aggkey-1").await;
        seed_pending(&db, "sys1", "a@x.com", "a@x.com", "hello-a").await;
        seed_pending(&db, "sys1", "b@x.com", "b@x.com", "hello-b").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        let resp = super::sse_response_scoped(
            State(state.clone()),
            key.clone(),
            Duration::from_secs(5),
            Duration::from_secs(10),
            "agg-1".to_string(),
            "as-agg".to_string(),
        )
        .await
        .unwrap();
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/event-stream"
        );

        // A different client on the same AgentSystemId is refused while the stream is HELD
        // (single consumer). Asked before consuming the body, because dropping the stream
        // releases the slot.
        let err = super::sse_response_scoped(
            State(state.clone()),
            key.clone(),
            Duration::from_secs(5),
            Duration::from_secs(10),
            "agg-stranger".to_string(),
            "as-agg".to_string(),
        )
        .await
        .expect_err("second consumer must be refused");
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);

        let events = read_sse_events(resp.into_body(), 1, Duration::from_secs(3)).await;
        assert_eq!(events.len(), 1, "expected the connect snapshot frame");
        let data = events[0]
            .trim_start_matches("event: mail\ndata: ")
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(
            batch_delivery_emails(&parsed),
            vec!["a@x.com".to_string(), "b@x.com".to_string()],
            "one frame carries the whole group"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn aggregate_pending_and_ack_stay_inside_the_agent_system() {
        use axum::extract::{Extension, State};
        let (db, state, _rx, dir) = probe_fixture("agg-pending").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        for (asid, email) in [("as-agg", "a@x.com"), ("as-other", "z@x.com")] {
            db.bind_agent_system_address(asid, email, "sys1")
                .await
                .unwrap();
            db.set_address_anchor(email, &"a".repeat(64)).await.unwrap();
        }
        seed_key(&db, "sys1", "a@x.com", &["agent"], "aggkey-2").await;
        seed_pending(&db, "sys1", "a@x.com", "a@x.com", "mine").await;
        seed_pending(&db, "sys1", "z@x.com", "z@x.com", "theirs").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        let mut headers = anchor_header(&[("a@x.com", &"a".repeat(64))]);
        headers.insert("x-agent-system-id", "as-agg".parse().unwrap());
        let req = super::PendingPollRequest { limit: 20 };
        let listed = super::list_agent_system_pending(
            State(state.clone()),
            Extension(key.clone()),
            headers.clone(),
            super::ClientId("agg-p".to_string()),
            axum::Json(req),
        )
        .await
        .expect("aggregate pending");
        let body = listed.0;
        assert_eq!(batch_delivery_emails(&body), vec!["a@x.com".to_string()]);
        let ids: Vec<i64> = body["batches"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|b| b["deliveries"].as_array().unwrap().clone())
            .map(|d| d["id"].as_i64().unwrap())
            .collect();
        let _acked = super::ack_agent_system_pending(
            State(state.clone()),
            Extension(key),
            headers,
            axum::Json(super::AckRequest { ids }),
        )
        .await
        .expect("ack");
        assert!(db
            .list_pending_for_agent_system("as-agg", 20)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.list_pending_for_agent_system("as-other", 20)
                .await
                .unwrap()
                .len(),
            1,
            "another AgentSystemId keeps its mail"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn aggregate_stream_is_woken_by_ingest_not_by_the_clock() {
        // The whole point of the AgentSystem notify key: a stream sitting on a 30 s heartbeat must
        // hand the mail over as soon as ingest commits it, not on the next tick.
        use super::{sse_stream_step, SseStreamState};
        use crate::core::api::types::SlotGuard;
        use crate::core::pending_notifier::{NotifyKey, PendingNotifier};

        let (db, state, _rx, dir) = probe_fixture("sse-wake").await;
        db.bind_agent_system_address("as-wake", "w@test.local", "shared_addr_1")
            .await
            .unwrap();
        let notifier = PendingNotifier::global();
        let key = NotifyKey::AgentSystem("as-wake".to_string());
        let since = notifier.snapshot(&key);

        let st = SseStreamState {
            db: db.clone(),
            nkey: key.clone(),
            req: super::PendingPollRequest { limit: 20 },
            watermark: 0,
            since,
            heartbeat: std::time::Duration::from_secs(30),
            life: std::time::Duration::from_secs(300),
            started: tokio::time::Instant::now(),
            queue: std::collections::VecDeque::new(),
            snapshot_bytes: 32 * 1024,
            _permit: None,
            agent_system_id: Some("as-wake".to_string()),
            guard: SlotGuard::new(state.delivery_slot.clone(), 1, "wake-test"),
        };

        let waiter = tokio::spawn(async move { sse_stream_step(st).await });
        // Ingest side: commit the row, then notify (the production order).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        db.insert_pending_delivery(
            "shared_addr_1",
            "test.local",
            "w@test.local",
            "{}",
            "{\"body\":\"hi\"}",
        )
        .await
        .unwrap();
        notifier.notify_agent_system("as-wake");

        let (item, _st) = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("must wake on notify, not after the 30 s heartbeat")
            .expect("step task")
            .expect("a frame");
        let frame = item.expect("frame is Ok");
        assert!(frame.contains("event: mail"), "got: {frame}");
        assert!(frame.contains("\"body\""), "got: {frame}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn frame_batch_is_bounded_by_bytes_and_takes_at_least_one() {
        use super::drain_frame_batch;
        use crate::core::storage::PendingDeliveryRecord;
        use std::collections::VecDeque;
        let rec = |id: i64| PendingDeliveryRecord {
            id,
            system_id: "s".into(),
            domain_addr: "d".into(),
            email: "a@test.local".into(),
            headers: "{}".into(),
            payload: "x".repeat(1000),
            status: "pending".into(),
            created_at: "t".into(),
        };
        let mut q: VecDeque<_> = (1..=5).map(rec).collect();

        // Two records (1002 B each) fit in 2500 B, the third does not.
        let batch = drain_frame_batch(&mut q, 2500);
        assert_eq!(batch.len(), 2, "the frame must stop at the byte budget");
        assert_eq!(q.len(), 3, "the rest stays queued for the next frame");

        // 0 = count-only (the historical behaviour).
        assert_eq!(drain_frame_batch(&mut q, 0).len(), 3);

        // A single mail larger than the budget still moves: progress over purity.
        let mut big: VecDeque<_> = (1..=2).map(rec).collect();
        assert_eq!(drain_frame_batch(&mut big, 1).len(), 1);
    }

    #[tokio::test]
    async fn a_stream_is_refused_with_503_once_the_cap_is_reached() {
        use super::try_take_sse_slot;
        let (_db, mut state, _rx, dir) = probe_fixture("sse-cap").await;
        state.sse_slots = Arc::new(tokio::sync::Semaphore::new(2));

        let held: Vec<_> = (0..2)
            .map(|_| try_take_sse_slot(&state).expect("within cap"))
            .collect();
        let err = try_take_sse_slot(&state).expect_err("over cap must be refused");
        assert_eq!(err.0, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1.error, "sse_capacity");

        // Dropping a permit frees exactly one slot (the abrupt-disconnect path).
        drop(held);
        let _released = try_take_sse_slot(&state).expect("capacity is released with the permit");
        std::fs::remove_dir_all(dir).ok();
    }

    fn probe_router(state: &HttpState) -> Router {
        let hook: Arc<dyn RouterHook> = Arc::new(BaseRouterHook(state.clone()));
        create_router(state.clone(), hook, None, None, None, None)
    }

    /// Insert a key whose raw material is known to the test, so it can sign.
    async fn seed_key(db: &Database, sid: &str, email: &str, scopes: &[&str], raw_key: &str) {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let category = if email.is_empty() { "system" } else { "agent" };
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            sid,
            email,
            &store_hash(&crate::core::api::auth::sha256_hex(raw_key)),
            &raw_key[..8],
            &scopes,
            None,
            category,
        ))
        .await
        .unwrap();
    }

    /// Full router round-trip with a v1 signature (the client signs the
    /// ENCODED path it sends).
    async fn signed_get(
        router: Router,
        raw_key: &str,
        identity: &str,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let sig = compute_api_signature(
            &crate::core::api::auth::sha256_hex(raw_key),
            "GET",
            path,
            &ts,
            b"",
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .header("X-Api-Identity", identity)
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", sig)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// Mutating twin of `signed_get`: v1 signature computed over the JSON body
    /// actually sent (the signature covers sha256(body)).
    async fn signed_put(
        router: Router,
        raw_key: &str,
        identity: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let body_bytes = serde_json::to_vec(body).unwrap();
        let sig = compute_api_signature(
            &crate::core::api::auth::sha256_hex(raw_key),
            "PUT",
            path,
            &ts,
            &body_bytes,
        );
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(path)
            .header("Content-Type", "application/json")
            .header("X-Api-Identity", identity)
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", sig)
            .body(axum::body::Body::from(body_bytes))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// POST round-trip with a v1 signature (same as signed_put, POST verb).
    async fn signed_post(
        router: Router,
        raw_key: &str,
        identity: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let body_bytes = serde_json::to_vec(body).unwrap();
        let sig = compute_api_signature(
            &crate::core::api::auth::sha256_hex(raw_key),
            "POST",
            path,
            &ts,
            &body_bytes,
        );
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .header("X-Api-Identity", identity)
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", sig)
            .body(axum::body::Body::from(body_bytes))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// DELETE round-trip with a v1 signature (empty body, same scheme).
    async fn signed_delete(
        router: Router,
        raw_key: &str,
        identity: &str,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let sig = compute_api_signature(
            &crate::core::api::auth::sha256_hex(raw_key),
            "DELETE",
            path,
            &ts,
            b"",
        );
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(path)
            .header("X-Api-Identity", identity)
            .header("X-Api-Timestamp", &ts)
            .header("X-Api-Signature", sig)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    // ─── D2 write-side boundary: system-scope keys cannot manage other systems ───

    /// A `system`-scoped key of sysA must NOT create a domain under sysB —
    /// 403, and no domain row for sysB is created (rejection precedes the DB
    /// insert).
    #[tokio::test]
    async fn d2_write_system_key_cannot_create_domain_of_other_system() {
        let (db, state, _rx, _dir) = probe_fixture("d2w-create-xsys").await;
        seed_key(&db, "sysA", "", &["system"], "d2wkeyC01").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "d2wkeyC01",
            "sysA",
            "/api/v1/admin/systems/sysB/domains",
            &serde_json::json!({"id": "dX", "domain": "xsys.example"}),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
        let row = db.get_system_domain("dX").await.unwrap();
        assert!(row.is_none(), "cross-system create must not persist a row");
    }

    /// Own-system create still succeeds (regression: the boundary must not
    /// break the legitimate path).
    #[tokio::test]
    async fn d2_write_system_key_still_creates_own_domain() {
        let (_db, state, _rx, _dir) = probe_fixture("d2w-create-own").await;
        seed_key(
            &state.factories.email.env_factory.db,
            "sysA",
            "",
            &["system"],
            "d2wkeyC02",
        )
        .await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "d2wkeyC02",
            "sysA",
            "/api/v1/admin/systems/sysA/domains",
            &serde_json::json!({"id": "dOwn", "domain": "own.example"}),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED, "body was {resp}");
        assert_eq!(resp["system_id"], serde_json::json!("sysA"));
    }

    /// A `system`-scoped key of sysA must NOT update a domain owned by sysB —
    /// 403, and the domain's webhook fields are untouched.
    #[tokio::test]
    async fn d2_write_system_key_cannot_update_domain_of_other_system() {
        let (db, state, _rx, _dir) = probe_fixture("d2w-update-xsys").await;
        db.insert_system_domain("dB1", "sysB", "b.example", None, None)
            .await
            .unwrap();
        seed_key(&db, "sysA", "", &["system"], "d2wkeyU01").await;

        let (status, resp) = signed_put(
            probe_router(&state),
            "d2wkeyU01",
            "sysA",
            "/api/v1/admin/system-domains/dB1",
            &serde_json::json!({"webhook_url": "https://attacker.example/hook"}),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
        let row = db.get_system_domain("dB1").await.unwrap().unwrap();
        assert_eq!(row.webhook_url, None, "cross-system update must not mutate");
    }

    /// A `system`-scoped key of sysA must NOT delete a domain owned by sysB —
    /// 403, and the row survives.
    #[tokio::test]
    async fn d2_write_system_key_cannot_delete_domain_of_other_system() {
        let (db, state, _rx, _dir) = probe_fixture("d2w-delete-xsys").await;
        db.insert_system_domain("dB2", "sysB", "b2.example", None, None)
            .await
            .unwrap();
        seed_key(&db, "sysA", "", &["system"], "d2wkeyD01").await;

        let (status, resp) = signed_delete(
            probe_router(&state),
            "d2wkeyD01",
            "sysA",
            "/api/v1/admin/system-domains/dB2",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
        assert!(
            db.get_system_domain("dB2").await.unwrap().is_some(),
            "cross-system delete must not remove the row"
        );
    }

    /// A `system`-scoped key of sysA must NOT update the meta of an agent
    /// registered under sysB — 403, and the manager field is untouched.
    #[tokio::test]
    async fn d2_write_system_key_cannot_update_meta_of_other_system_agent() {
        let (db, state, _rx, _dir) = probe_fixture("d2w-meta-xsys").await;
        db.upsert_domain_addr_meta("b@x.com", "sysB", None, None, None)
            .await
            .unwrap();
        seed_key(&db, "sysA", "", &["system"], "d2wkeyM01").await;

        let (status, resp) = signed_put(
            probe_router(&state),
            "d2wkeyM01",
            "sysA",
            "/api/v1/admin/agent-meta/b@x.com",
            &serde_json::json!({"manager_address": "attacker@evil.example"}),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
        let meta = db.get_domain_addr_meta("b@x.com").await.unwrap().unwrap();
        assert_eq!(
            meta.manager_address, "",
            "cross-system meta update must not mutate"
        );
    }

    /// Regression (found via e2e, not unit): a **platform**-scoped key
    /// (the bootstrap admin key — `category=platform`, `scopes=[platform,system]`,
    /// `system_id` = the bootstrap id, which is NOT the tid it manages) must
    /// cross the write-side system boundary freely. The boundary mirrors the
    /// read side (list_system_domains / get_address_status): platform admins
    /// are exempt from the `system_id == tid` check; only a plain
    /// `system`-scoped key is confined to its own system. Without the
    /// platform exemption the e2e bootstrap admin key (system_id=system-XXXX)
    /// could not create a domain under tid=admin → silent 403 → cascade.
    #[tokio::test]
    async fn d2_write_platform_key_crosses_system_boundary() {
        let (db, state, _rx, _dir) = probe_fixture("d2w-platform").await;
        // bootstrap admin key: platform scope, system_id differs from tid.
        seed_key(&db, "system-b001", "", &["platform", "system"], "d2wkeyP01").await;

        // create
        let (status, resp) = signed_post(
            probe_router(&state),
            "d2wkeyP01",
            "system-b001",
            "/api/v1/admin/systems/admin/domains",
            &serde_json::json!({"id": "dP1", "domain": "plat.example"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "body was {resp}");
        assert_eq!(resp["system_id"], serde_json::json!("admin"));

        // update (cross-system target: domain under tid=admin, key system_id=system-b001)
        let (status, _resp) = signed_put(
            probe_router(&state),
            "d2wkeyP01",
            "system-b001",
            "/api/v1/admin/system-domains/dP1",
            &serde_json::json!({"webhook_url": "https://hooks.example.com/hook"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "platform update must not be 403");

        // delete
        let (status, _resp) = signed_delete(
            probe_router(&state),
            "d2wkeyP01",
            "system-b001",
            "/api/v1/admin/system-domains/dP1",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "platform delete must not be 403"
        );
    }

    // ─── POST /api/v1/system/welcome — unified endpoint (agent + system) ───

    /// Agent branch: an agent-scope key with a bound, active address gets
    /// the welcome for ITS OWN address; the body `to` is ignored (a
    /// bogus address in the body must not change the outcome).
    #[tokio::test]
    async fn welcome_agent_branch_derives_to_from_key_and_ignores_body() {
        let (db, state, _rx, _dir) = probe_fixture("welcome-agent").await;
        db.insert_system_domain("d1", "sys1", "agent1@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "agent1@x.com", &["agent"], "agentkey01").await;

        let body = serde_json::json!({"to": ["nobody@nowhere.test"]});
        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey01",
            "sys1",
            "/api/v1/system/welcome",
            &body,
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert!(resp["email_id"].as_str().is_some(), "body was {resp}");
        assert!(resp["message_id"].as_str().is_some(), "body was {resp}");
        // The agent has no manager meta → no cc.
        assert_eq!(resp["cc"], serde_json::json!([]), "body was {resp}");
        // The derived record's `to` is the key's own address, not the body.
        let email_id = resp["email_id"].as_str().unwrap().to_string();
        let rec = state
            .factories
            .email
            .env_factory
            .db
            .get_email(&email_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            rec.recipients.contains("\"to\":[\"agent1@x.com\"]"),
            "record to must be the key's own address, got {}",
            rec.recipients
        );
    }

    /// Agent branch: an agent-scope key without a bound address is rejected.
    #[tokio::test]
    async fn welcome_agent_branch_key_without_bound_address_rejected() {
        let (db, state, _rx, _dir) = probe_fixture("welcome-agent-nobound").await;
        seed_key(&db, "sys1", "", &["agent"], "agentkey02").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey02",
            "sys1",
            "/api/v1/system/welcome",
            &serde_json::json!({"to": []}),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
    }

    /// System branch regression anchor: a system-scope key still welcomes
    /// the `to` it names in the body (original behavior, byte-identical).
    #[tokio::test]
    async fn welcome_system_branch_still_uses_body_to() {
        let (db, state, _rx, _dir) = probe_fixture("welcome-system").await;
        db.insert_system_domain("d1", "sys1", "agent2@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0003").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "syskey0003",
            "sys1",
            "/api/v1/system/welcome",
            &serde_json::json!({"to": ["agent2@x.com"]}),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert!(resp["email_id"].as_str().is_some(), "body was {resp}");
    }

    /// Defect 1 (2026-10-25): a `system`-scoped key of system A must NOT
    /// welcome an active address of system B — 403, and **zero side
    /// effects**: no email record of any kind lands in the DB (rejection
    /// precedes `create_outbound`/`create_inbound`).
    #[tokio::test]
    async fn welcome_cross_system_system_key_rejected_with_no_side_effects() {
        let (db, state, _rx, _dir) = probe_fixture("welcome-xsys-system").await;
        db.insert_system_domain("dA", "sysA", "a@x.com", None, None)
            .await
            .unwrap();
        db.insert_system_domain("dB", "sysB", "b@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sysA", "", &["system"], "xsyskeyA01").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "xsyskeyA01",
            "sysA",
            "/api/v1/system/welcome",
            &serde_json::json!({"to": ["b@x.com"]}),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
        // Zero side effects: no record (inbound or outbound) for any system.
        let emails = db.list_emails(100).await.unwrap();
        assert!(
            emails.is_empty(),
            "cross-system welcome must create no records, got {} record(s)",
            emails.len()
        );
        let a = db.count_emails_by_system("sysA").await.unwrap();
        let b = db.count_emails_by_system("sysB").await.unwrap();
        assert_eq!(a, 0, "sysA must have no welcome record");
        assert_eq!(b, 0, "sysB must have no welcome record");
    }

    /// Defect 1 (2026-10-25): a `platform`-scoped key MAY welcome an active
    /// address of a different system (cross-system is a platform capability,
    /// unchanged behavior).
    #[tokio::test]
    async fn welcome_cross_system_platform_key_allowed() {
        let (db, state, _rx, _dir) = probe_fixture("welcome-xsys-platform").await;
        db.insert_system_domain("dA", "sysA", "a@x.com", None, None)
            .await
            .unwrap();
        db.insert_system_domain("dB", "sysB", "b@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sysA", "", &["platform"], "xsyskeyP01").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "xsyskeyP01",
            "sysA",
            "/api/v1/system/welcome",
            &serde_json::json!({"to": ["b@x.com"]}),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert!(resp["email_id"].as_str().is_some(), "body was {resp}");
    }

    /// State ①: an existing, active address ⇒ {true,true}, two fields only.
    #[tokio::test]
    async fn address_probe_existing_active_address_is_true_true() {
        let (db, state, _rx, _dir) = probe_fixture("exists").await;
        db.insert_system_domain("d1", "sys1", "alice@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0001").await;

        let (status, body) = signed_get(
            probe_router(&state),
            "syskey0001",
            "sys1",
            "/api/v1/admin/systems/sys1/addresses/alice%40x.com",
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(body, serde_json::json!({"exists": true, "valid": true}));
        assert_only_two_fields(&body);
    }

    /// State ②: a nonexistent address ⇒ {false,false} — and still nothing else.
    #[tokio::test]
    async fn address_probe_missing_address_is_false_false_with_no_extra_fields() {
        let (db, state, _rx, _dir) = probe_fixture("missing").await;
        seed_key(&db, "sys1", "", &["system"], "syskey0002").await;

        let (status, body) = signed_get(
            probe_router(&state),
            "syskey0002",
            "sys1",
            "/api/v1/admin/systems/sys1/addresses/nobody%40x.com",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"exists": false, "valid": false}));
        assert_only_two_fields(&body);
    }

    /// State ④: deactivating the row (the only liveness knob the table has)
    /// flips `valid` to false while `exists` stays true.
    #[tokio::test]
    async fn address_probe_deactivated_address_is_valid_false() {
        let (db, state, _rx, _dir) = probe_fixture("deactivated").await;
        db.insert_system_domain("d1", "sys1", "alice@x.com", None, None)
            .await
            .unwrap();
        db.update_system_domain("d1", None, None, Some(false))
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0003").await;

        let (status, body) = signed_get(
            probe_router(&state),
            "syskey0003",
            "sys1",
            "/api/v1/admin/systems/sys1/addresses/alice%40x.com",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({"exists": true, "valid": false}),
            "is_active=0 must yield valid=false"
        );
        assert_only_two_fields(&body);
    }

    /// REGRESSION (the reported defect, end-to-end): the read path caches
    /// positive domain lookups for 30s, and `PUT` must evict. Pre-fix, a read
    /// that warmed the cache kept answering `{exists:true, valid:true}` after
    /// the domain was deactivated, flipping only when the TTL expired
    /// (measured t+30.1s).
    #[tokio::test]
    async fn address_probe_reflects_deactivation_immediately_after_put() {
        let (db, state, _rx, _dir) = probe_fixture("deactivate-then-probe").await;
        db.insert_system_domain("d1", "sys1", "alice@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0004").await;
        let router = probe_router(&state);
        let probe_path = "/api/v1/admin/systems/sys1/addresses/alice%40x.com";

        // 1) First read WARMS the positive lookup cache — the precondition.
        let (status, body) = signed_get(router.clone(), "syskey0004", "sys1", probe_path).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(body, serde_json::json!({"exists": true, "valid": true}));
        assert!(
            db.domain_cache.read().unwrap().contains_key("alice@x.com"),
            "precondition: the probe must have populated the domain cache"
        );

        // 2) Deactivate through the real API (PUT /admin/system-domains/:id).
        let (put_status, put_body) = signed_put(
            router.clone(),
            "syskey0004",
            "sys1",
            "/api/v1/admin/system-domains/d1",
            &serde_json::json!({"is_active": false}),
        )
        .await;
        assert_eq!(put_status, StatusCode::OK, "PUT body was {put_body}");

        // 3) The very next read — no sleep — must already report invalid.
        let (status, body) = signed_get(router, "syskey0004", "sys1", probe_path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({"exists": true, "valid": false}),
            "stale cache: update_system_domain must invalidate the domain cache"
        );
        assert_only_two_fields(&body);
    }

    /// State ③: an agent-scope key probing ANOTHER live address of the same
    /// system must be indistinguishable from probing a nonexistent one — same
    /// status, same bytes. (Its own address still answers truthfully.)
    #[tokio::test]
    async fn agent_scope_probe_of_another_address_leaks_nothing() {
        let (db, state, _rx, _dir) = probe_fixture("agent-scope").await;
        db.insert_system_domain("d1", "sys1", "alice@x.com", None, None)
            .await
            .unwrap();
        db.insert_system_domain("d2", "sys1", "bob@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "alice@x.com", &["agent"], "agentkey0001").await;
        let router = probe_router(&state);

        // Own address: truthful.
        let (own_status, own) = signed_get(
            router.clone(),
            "agentkey0001",
            "alice@x.com",
            "/api/v1/admin/systems/sys1/addresses/alice%40x.com",
        )
        .await;
        assert_eq!(own_status, StatusCode::OK);
        assert_eq!(own, serde_json::json!({"exists": true, "valid": true}));

        // Someone else's LIVE address of the same system.
        let (other_status, other) = signed_get(
            router.clone(),
            "agentkey0001",
            "alice@x.com",
            "/api/v1/admin/systems/sys1/addresses/bob%40x.com",
        )
        .await;
        // A nonexistent address.
        let (none_status, none) = signed_get(
            router.clone(),
            "agentkey0001",
            "alice@x.com",
            "/api/v1/admin/systems/sys1/addresses/nobody%40x.com",
        )
        .await;

        assert_eq!(other, serde_json::json!({"exists": false, "valid": false}));
        assert_only_two_fields(&other);
        assert_eq!(other_status, none_status, "status must not discriminate");
        assert_eq!(
            other, none,
            "probing another agent's live address must be byte-identical to probing a missing one"
        );

        // Another system's sid, with its own address in the path.
        let (foreign_status, foreign) = signed_get(
            router,
            "agentkey0001",
            "alice@x.com",
            "/api/v1/admin/systems/sys2/addresses/alice%40x.com",
        )
        .await;
        assert_eq!(foreign_status, StatusCode::OK);
        assert_eq!(
            foreign,
            serde_json::json!({"exists": false, "valid": false})
        );
    }

    /// A system-scope key may not read a foreign system (403, like the sibling
    /// handlers — a 403 confirms no row).
    #[tokio::test]
    async fn system_scope_cross_system_probe_is_forbidden() {
        let (db, state, _rx, _dir) = probe_fixture("cross-system").await;
        db.insert_system_domain("d1", "sys2", "bob@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0004").await;

        let (status, _body) = signed_get(
            probe_router(&state),
            "syskey0004",
            "sys1",
            "/api/v1/admin/systems/sys2/addresses/bob%40x.com",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// A bridge-scope key has no business here: 403, never an answer.
    #[tokio::test]
    async fn bridge_scope_cannot_probe_addresses() {
        let (db, state, _rx, _dir) = probe_fixture("bridge-scope").await;
        db.insert_system_domain("d1", "sys1", "alice@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["bridge"], "bridgekey01").await;

        let (status, _body) = signed_get(
            probe_router(&state),
            "bridgekey01",
            "sys1",
            "/api/v1/admin/systems/sys1/addresses/alice%40x.com",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// A bare-domain value (domain-level row, same table) can never report
    /// `exists=true` through the ADDRESS probe.
    #[tokio::test]
    async fn probe_of_a_bare_domain_never_reports_exists() {
        let (db, state, _rx, _dir) = probe_fixture("bare-domain").await;
        db.insert_system_domain("d0", "sys1", "x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey0005").await;

        let (status, body) = signed_get(
            probe_router(&state),
            "syskey0005",
            "sys1",
            "/api/v1/admin/systems/sys1/addresses/x.com",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"exists": false, "valid": false}));
        assert_only_two_fields(&body);
    }

    /// Structural guard independent of the router: the response type itself
    /// can only ever serialize two booleans.
    #[test]
    fn probe_response_type_serializes_to_exactly_exists_and_valid() {
        let hit = serde_json::to_value(AddressStatusResponse {
            exists: true,
            valid: false,
        })
        .unwrap();
        assert_only_two_fields(&hit);
        assert_eq!(hit, serde_json::json!({"exists": true, "valid": false}));

        let absent = serde_json::to_value(AddressStatusResponse::absent()).unwrap();
        assert_only_two_fields(&absent);
        assert_eq!(absent, serde_json::json!({"exists": false, "valid": false}));
    }

    // 2026-10-13: the restored probe-webhook endpoint must classify outcomes,
    // never decide reachability — interpretation belongs to the caller
    // (CLI install webhook plan).
    //
    // Note: the `connected` and `connection_refused` classes need a
    // non-loopback target to observe (the endpoint's loopback guard is the
    // very behavior pinned by the first test), so they are not exercised on
    // a 127.0.0.1 listener here. The `connected` branch is the v1.0
    // behavior, byte-for-byte.
    #[tokio::test]
    async fn probe_classifies_loopback_as_not_allowed() {
        let res = probe_reachability("127.0.0.1:9099").await;
        assert_eq!(res["reachable"], serde_json::json!(false));
        assert_eq!(res["error"], serde_json::json!("loopback_not_allowed"));
    }

    #[tokio::test]
    async fn probe_classifies_unroutable_target_as_timeout() {
        // 240.0.0.0/4 is IETF protocol assignment — no route, packets are
        // dropped, so the connect attempt runs to the 5s timeout.
        let res = probe_reachability("240.0.0.1:9").await;
        assert_eq!(res["reachable"], serde_json::json!(false));
        assert_eq!(res["error"], serde_json::json!("timeout"));
    }

    // ─── POST /api/v1/admin/pending — scope fork, long-pull hold, ack ───
    //
    // Baseline golden for the pull response shape (pre-existing for
    // system/bridge, NEW for agent scope). Agent keys must see ONLY their
    // own address; hold must wake on new mail; ack must stay inside the
    // caller's system / address.

    async fn seed_pending(db: &Database, sid: &str, addr: &str, email: &str, body: &str) -> i64 {
        db.insert_pending_delivery(
            sid,
            addr,
            email,
            r#"{"From":"from@x.com","Subject":"hi"}"#,
            &serde_json::json!({"body": body, "subject": "hi"}).to_string(),
        )
        .await
        .unwrap()
    }

    fn batch_delivery_emails(body: &serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(batches) = body["batches"].as_array() {
            for b in batches {
                if let Some(dels) = b["deliveries"].as_array() {
                    for d in dels {
                        out.push(d["email"].as_str().unwrap_or("").to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    // ─── effective manager resolution (registration defaults) ───
    //
    // Precedence: explicit > per-system default > config default. A whitespace
    // value counts as absent at every level, and "no source" stays None so the
    // registration writes no manager row (never a `value=''` whitelist row).

    #[test]
    fn effective_manager_explicit_wins_over_all_defaults() {
        assert_eq!(
            resolve_effective_manager(Some("explicit@x.com"), Some("sys@x.com"), Some("cfg@x.com")),
            Some("explicit@x.com".to_string())
        );
    }

    #[test]
    fn effective_manager_system_default_beats_config_default() {
        assert_eq!(
            resolve_effective_manager(None, Some("sys@x.com"), Some("cfg@x.com")),
            Some("sys@x.com".to_string())
        );
    }

    #[test]
    fn effective_manager_config_default_is_last_resort() {
        assert_eq!(
            resolve_effective_manager(None, None, Some("cfg@x.com")),
            Some("cfg@x.com".to_string())
        );
    }

    #[test]
    fn effective_manager_blank_values_are_absent() {
        assert_eq!(
            resolve_effective_manager(Some("   "), Some(""), Some("  \t")),
            None
        );
        assert_eq!(
            resolve_effective_manager(Some(""), None, Some("cfg@x.com")),
            Some("cfg@x.com".to_string())
        );
    }

    #[test]
    fn effective_manager_trims_surrounding_whitespace() {
        assert_eq!(
            resolve_effective_manager(Some("  mgr@x.com  "), None, None),
            Some("mgr@x.com".to_string())
        );
    }

    /// R6 (2026-10-29 QA): the idempotent `already_exists` (409) arm must use
    /// the SAME effective manager the new path resolves, not
    /// `req.manager_address` alone. A client that omits `manager_address`
    /// (expecting the server default) must still get the resolved value synced
    /// into meta/whitelist instead of the sync silently skipping.
    ///
    /// The 409 arm is reached when the address row already belongs to a
    /// DIFFERENT system while the domain anchor is owned by the requesting
    /// system (the same-system retry instead takes the factory upsert Ok path
    /// and never reaches this arm — see the factory's `create_domain`).
    /// The effective manager here comes from the config-file default, since the
    /// base `SystemStore` exposes no per-system default.
    #[tokio::test]
    async fn register_409_arm_syncs_effective_manager_not_request_only() {
        let (db, mut state, _rx, _dir) = probe_fixture("reg409").await;
        // The only manager source available in this fixture: the config default.
        state.config.admin.manager_default = Some("cfgmgr@default.example".to_string());

        // Anchor (bare domain) owned by the REQUESTING system sysB …
        db.insert_system_domain("danchor", "sysB", "shared.example", None, None)
            .await
            .unwrap();
        // … but the address row already belongs to a DIFFERENT system sysA.
        db.insert_system_domain("daddr", "sysA", "agent@shared.example", None, None)
            .await
            .unwrap();
        seed_key(&db, "sysB", "", &["system"], "r6key01x").await;

        // sysB registers the colliding address, OMITTING manager_address.
        let (status, resp) = signed_post(
            probe_router(&state),
            "r6key01x",
            "sysB",
            "/api/v1/admin/systems/sysB/addresses",
            &serde_json::json!({"id": "r1", "email": "agent@shared.example"}),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT, "body was {resp}");

        // The 409 arm synced the EFFECTIVE manager (config default) — not the
        // absent request value. Before the fix this was None and the meta was
        // left untouched.
        let meta = db
            .get_domain_addr_meta("agent@shared.example")
            .await
            .unwrap()
            .expect("409 arm must have synced the meta row");
        assert_eq!(
            meta.manager_address, "cfgmgr@default.example",
            "409 arm must use the effective manager, got {:?}",
            meta.manager_address
        );

        // … and the bidirectional whitelist carries the same manager. The
        // resolver attributes it to the address's owning system (sysA).
        let wl = db.list_whitelists("sysA").await.unwrap();
        assert!(
            wl.iter()
                .any(|w| w.domain_addr == "agent@shared.example"
                    && w.value == "cfgmgr@default.example"),
            "409 arm must have synced the manager whitelist, got {:?}",
            wl
        );
    }
}

#[cfg(test)]
mod anchor_header_tests {
    use super::parse_anchor_claims;
    use axum::http::{HeaderMap, HeaderValue};

    fn hash(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    #[test]
    fn parses_one_claim_per_header_value() {
        let mut h = HeaderMap::new();
        h.append(
            "x-aimail-anchor",
            HeaderValue::from_str(&format!("a@example.com;{}", hash('a'))).unwrap(),
        );
        h.append(
            "x-aimail-anchor",
            HeaderValue::from_str(&format!("B@Example.com;{}", hash('b'))).unwrap(),
        );
        let got = parse_anchor_claims(&h);
        assert_eq!(got.get("a@example.com"), Some(&hash('a')));
        assert_eq!(
            got.get("b@example.com"),
            Some(&hash('b')),
            "address is normalized"
        );
    }

    #[test]
    fn parses_comma_separated_claims_in_one_value() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-aimail-anchor",
            HeaderValue::from_str(&format!(
                "a@example.com;{},b@example.com;{}",
                hash('a'),
                hash('b')
            ))
            .unwrap(),
        );
        let got = parse_anchor_claims(&h);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn junk_is_ignored_not_trusted() {
        let mut h = HeaderMap::new();
        h.append("x-aimail-anchor", HeaderValue::from_static("nonsense"));
        h.append(
            "x-aimail-anchor",
            HeaderValue::from_static("a@example.com;short"),
        );
        h.append(
            "x-aimail-anchor",
            HeaderValue::from_static("not-an-address;"),
        ); // no hash
        assert!(parse_anchor_claims(&h).is_empty());
    }
}

#[cfg(test)]
mod anchor_enforcement_tests {
    //! Owner ruling 2026-11-25: the lenient rollout ("no recorded anchor ⇒ allow") is gone. A pull
    //! is refused unless it presents claims, every address of the group is anchored, and every claim
    //! matches. These cases pin all three refusals plus the one acceptance path.
    use super::enforce_anchor_binding;
    use crate::core::storage::Database;
    use axum::http::{HeaderMap, HeaderValue};

    fn temp_db() -> Database {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("aimail-gw-enforce-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Database::open(dir.join("test.db"), 1, None).expect("open db")
    }

    fn hash(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn claims(pairs: &[(&str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (address, value) in pairs {
            h.append(
                "x-aimail-anchor",
                HeaderValue::from_str(&format!("{address};{value}")).unwrap(),
            );
        }
        h
    }

    async fn seed(db: &Database) {
        db.bind_agent_system_address("as-1", "a@example.com", "shared_addr_1")
            .await
            .unwrap();
        db.set_address_anchor("a@example.com", &hash('a'))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn refuses_a_pull_that_carries_no_claim() {
        let db = temp_db();
        seed(&db).await;
        let err = enforce_anchor_binding(&db, "as-1", &HeaderMap::new())
            .await
            .expect_err("an anchor-less pull must be refused");
        assert_eq!(err.1.error, "anchor_required");
    }

    #[tokio::test]
    async fn refuses_an_address_whose_activation_registered_no_anchor() {
        let db = temp_db();
        db.bind_agent_system_address("as-1", "a@example.com", "shared_addr_1")
            .await
            .unwrap();
        // No set_address_anchor: the address could be moved by editing the binding file.
        let err = enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('a'))]))
            .await
            .expect_err("an unanchored address must be refused");
        assert_eq!(err.1.error, "anchor_unregistered");
        assert!(err
            .1
            .detail
            .clone()
            .unwrap_or_default()
            .contains("a@example.com"));
    }

    #[tokio::test]
    async fn refuses_a_claim_that_does_not_match_the_registration() {
        let db = temp_db();
        seed(&db).await;
        let err = enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('b'))]))
            .await
            .expect_err("a moved anchor must be refused");
        assert_eq!(err.1.error, "anchor_mismatch");
    }

    #[tokio::test]
    async fn refuses_when_one_address_of_the_group_is_missing_from_the_claims() {
        let db = temp_db();
        seed(&db).await;
        db.bind_agent_system_address("as-1", "b@example.com", "shared_addr_1")
            .await
            .unwrap();
        db.set_address_anchor("b@example.com", &hash('b'))
            .await
            .unwrap();
        let err = enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('a'))]))
            .await
            .expect_err("a partial claim list must be refused");
        assert_eq!(err.1.error, "anchor_mismatch");
        assert!(err
            .1
            .detail
            .clone()
            .unwrap_or_default()
            .contains("b@example.com"));
    }

    #[tokio::test]
    async fn a_re_anchored_address_is_refused_on_the_next_pull() {
        // Cache correctness at the enforcement level: the second call must see the new witness and
        // refuse the OLD claim. A cache that outlived its writer would be an enforcement bypass.
        let db = temp_db();
        seed(&db).await;
        enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('a'))]))
            .await
            .expect("the registered anchor is accepted");

        db.set_address_anchor("a@example.com", &hash('b'))
            .await
            .unwrap();
        let err = enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('a'))]))
            .await
            .expect_err("the stale claim must be refused right away");
        assert_eq!(err.1.error, "anchor_mismatch");

        enforce_anchor_binding(&db, "as-1", &claims(&[("a@example.com", hash('b'))]))
            .await
            .expect("the new claim is accepted");
    }

    #[tokio::test]
    async fn accepts_a_pull_that_proves_every_anchor() {
        let db = temp_db();
        seed(&db).await;
        db.bind_agent_system_address("as-1", "b@example.com", "shared_addr_1")
            .await
            .unwrap();
        db.set_address_anchor("b@example.com", &hash('b'))
            .await
            .unwrap();
        enforce_anchor_binding(
            &db,
            "as-1",
            &claims(&[("a@example.com", hash('a')), ("b@example.com", hash('b'))]),
        )
        .await
        .expect("a fully proven pull is allowed");
    }
}
