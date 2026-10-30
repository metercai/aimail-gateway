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
use crate::core::api::types::{PULL_HOLD_MAX_MS, SSE_HEARTBEAT_SECS, SSE_MAX_LIFE_SECS};
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
    let body_cap =
        crate::core::api::auth::signature_body_cap(state.config.storage.attachment_max_size as u64);
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
        .route("/api/v1/admin/pending", post(list_pending_deliveries))
        .route("/api/v1/admin/pending/stream", get(pending_stream))
        .route("/api/v1/admin/pending/ack", post(ack_pending_deliveries))
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
            let cap = body_cap;
            async move { auth_layer(ef, req, next, cap).await }
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

    // AA: must be the manager of this agent
    if is_agent_admin_scope(&api_key) && existing.manager_address != api_key.email_address {
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
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    filter: Vec<String>,
    /// Long-pull hold (ms). 0 = return immediately (current behavior,
    /// byte-identical); >0 = when the query is empty, wait up to this long
    /// (clamped to `PULL_HOLD_MAX_MS`) for new mail before returning.
    #[serde(default)]
    timeout_ms: i64,
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

/// Isolation key for pull waiters — mirrors the storage filters of
/// [`pending_records_for`] exactly (single source of truth: that function
/// calls this one). agent ⇒ its own (system_id, lowercased email), or
/// `None` when the key has no bound address (handler 403s); system/bridge
/// ⇒ the system key.
fn pending_notify_key(key: &ApiKeyRecord) -> Option<NotifyKey> {
    if is_agent_scope(key) {
        if key.email_address.is_empty() {
            return None;
        }
        return Some(NotifyKey::Email {
            system_id: key.system_id.clone(),
            email: key.email_address.to_lowercase(),
        });
    }
    Some(NotifyKey::System(key.system_id.clone()))
}

/// Resolve the pending rows the calling key may see, per scope.
/// Agent keys see ONLY their own address (`(system_id, lowercased email)`);
/// `emails`/`filter` are accepted and ignored — scope IS the range (§2.5).
/// System/bridge keys see system-wide rows with the existing domain filter.
/// Returns the matching notifier key so hold/SSE can wait on the same key
/// the query filtered by.
async fn pending_records_for(
    db: &Database,
    key: &ApiKeyRecord,
    req: &PendingPollRequest,
) -> Result<
    (NotifyKey, Vec<crate::core::storage::PendingDeliveryRecord>),
    (StatusCode, Json<ErrorResponse>),
> {
    let nkey = pending_notify_key(key).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "No bound address".to_string(),
                detail: Some(
                    "agent-scope key has no bound address; pull requires a bound address"
                        .to_string(),
                ),
            }),
        )
    })?;

    match &nkey {
        NotifyKey::Email { system_id, email } => {
            let records = db
                .list_pending_by_email(system_id, email, req.limit)
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
            Ok((nkey, records))
        }
        NotifyKey::System(system_id) => {
            require_scope_any(key, &["system", "bridge"])?;
            let use_filter = !req.filter.is_empty();
            let effective_filter: Vec<String> = if use_filter {
                preprocess_pending_filter(&req.filter)
            } else if !req.emails.is_empty() {
                let mut domains: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
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
            let records = db
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
            Ok((nkey, records))
        }
    }
}

async fn list_pending_deliveries(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    client_id: ClientId,
    Json(req): Json<PendingPollRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Single-slot claim: long-poll holds the same slot as the stream path.
    // The lease auto-expires (SLOT_POLL_LEASE_SECS) if the holder dies —
    // no explicit release; a request is stateless.
    if !state.delivery_slot.try_acquire(
        api_key.id,
        client_id_of(&client_id),
        std::time::Duration::from_secs(SLOT_POLL_LEASE_SECS),
    ) {
        return Err(occupied_error(
            "another client holds the mailbox for this key; retry later".to_string(),
        ));
    }
    let db = &state.factories.email.env_factory.db;
    let notifier = PendingNotifier::global();
    let hold =
        std::time::Duration::from_millis(req.timeout_ms.clamp(0, PULL_HOLD_MAX_MS as i64) as u64);

    // Snapshot BEFORE the query: a notify after this point is either visible
    // in the query (row committed first) or observed via the wake-up. A notify
    // before the snapshot has its row visible to the query.
    let nkey = pending_notify_key(&api_key).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "No bound address".to_string(),
                detail: Some(
                    "agent-scope key has no bound address; pull requires a bound address"
                        .to_string(),
                ),
            }),
        )
    })?;
    let since = notifier.snapshot(&nkey);

    let (_key, mut records) = pending_records_for(db, &api_key, &req).await?;

    if records.is_empty() && !hold.is_zero() {
        match notifier.wait_since(&nkey, since, hold).await {
            WaitOutcome::Woke => {
                records = pending_records_for(db, &api_key, &req).await?.1;
            }
            WaitOutcome::Timeout => {}
        }
    }

    Ok(Json(group_pending_batches(&records)))
}

async fn ack_pending_deliveries(
    state: axum::extract::State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    Json(req): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
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

    let db = &state.factories.email.env_factory.db;
    // Scope fork: an agent-scope key may ack ONLY its own address (same
    // ownership check as the list path, §2.5); its scope guard is the bound
    // email itself. system/bridge keys are restricted to their own system —
    // the identity comes from the authenticated key, never from the request
    // body, so cross-system ids affect 0 rows.
    let count = if is_agent_scope(&api_key) {
        if api_key.email_address.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "No bound address".to_string(),
                    detail: Some(
                        "agent-scope key has no bound address; ack requires a bound address"
                            .to_string(),
                    ),
                }),
            ));
        }
        let email = api_key.email_address.to_lowercase();
        db.ack_pending_by_email(&api_key.system_id, &email, &req.ids)
            .await
    } else {
        require_scope_any(&api_key, &["system", "bridge"])?;
        db.ack_deliveries(&api_key.system_id, &req.ids).await
    }
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
    api_key: crate::core::storage::ApiKeyRecord,
    nkey: NotifyKey,
    req: PendingPollRequest,
    /// Max delivery id already emitted on this connection. 0 = nothing yet.
    watermark: i64,
    /// Notifier gen the caller has already observed; wait for gen > this.
    since: u64,
    heartbeat: std::time::Duration,
    life: std::time::Duration,
    started: tokio::time::Instant,
    /// Connect-time rows, emitted as the first frame.
    pending_first: Option<Vec<crate::core::storage::PendingDeliveryRecord>>,
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

fn sse_mail_frame(payload: &serde_json::Value) -> SseItem {
    Ok(format!("event: mail\ndata: {}\n\n", payload))
}

/// One unfold step. Returns the next frame (mail or ping) plus the
/// updated state, or `None` when the stream ends (max life).
async fn sse_stream_step(mut st: SseStreamState) -> Option<(SseItem, SseStreamState)> {
    let notifier = PendingNotifier::global();

    // First frame: whatever the connect-time query found.
    if let Some(records) = st.pending_first.take() {
        if !records.is_empty() {
            st.watermark = records.iter().map(|r| r.id).max().unwrap_or(0);
            return Some((sse_mail_frame(&group_pending_batches(&records)), st));
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
        let outcome = notifier.wait_since(&st.nkey, st.since, st.heartbeat).await;
        // Snapshot AFTER the wait: a notify between the wait and this point
        // has gen > snapshot ⇒ caught by the NEXT wait; one before has
        // its row committed ⇒ seen by the re-query below.
        st.since = notifier.snapshot(&st.nkey);

        match pending_records_for(&st.db, &st.api_key, &st.req).await {
            Ok((_k, records)) => {
                let fresh: Vec<_> = records
                    .into_iter()
                    .filter(|r| r.id > st.watermark)
                    .collect();
                if !fresh.is_empty() {
                    st.watermark = fresh.iter().map(|r| r.id).max().unwrap_or(st.watermark);
                    return Some((sse_mail_frame(&group_pending_batches(&fresh)), st));
                }
            }
            Err(_) => {
                // Transient storage error: keep the stream alive; the next
                // wake-up re-queries.
            }
        }
        if matches!(outcome, WaitOutcome::Timeout) {
            return Some((Ok(": ping\n\n".to_string()), st));
        }
        // Woke (or storage error) with nothing new: keep waiting.
    }
}

/// Build the SSE response for the given caller. `heartbeat`/`life` are
/// parameters so tests can inject short periods; the public handler passes
/// the contract constants.
async fn sse_response(
    state: State<HttpState>,
    api_key: crate::core::storage::ApiKeyRecord,
    heartbeat: std::time::Duration,
    life: std::time::Duration,
    client_id: String,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Single-slot claim BEFORE any work: the first connection wins; a
    // different client is 409 without building a stream. Same client
    // (reconnect / rotation) re-acquires and refreshes.
    if !state.delivery_slot.try_acquire(
        api_key.id,
        client_id.as_str(),
        std::time::Duration::from_secs(SLOT_STREAM_LEASE_SECS),
    ) {
        // Diagnostics: name the HOLDER (whoever currently occupies the slot),
        // not this rejected requester.
        let holder = state
            .delivery_slot
            .holder_id(api_key.id)
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
        emails: Vec::new(),
        filter: Vec::new(),
        timeout_ms: 0,
    };
    let (nkey, initial) = pending_records_for(db, &api_key, &req).await?;
    // Snapshot AFTER the connect query: rows already emitted cannot be
    // double-emitted by their own notify.
    let since = notifier.snapshot(&nkey);

    let st = SseStreamState {
        db: db.clone(),
        api_key: api_key.clone(),
        nkey,
        req,
        watermark: 0,
        since,
        heartbeat,
        life,
        started: tokio::time::Instant::now(),
        pending_first: Some(initial),
        guard: SlotGuard::new(state.delivery_slot.clone(), api_key.id, client_id.as_str()),
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

async fn pending_stream(
    state: State<HttpState>,
    axum::extract::Extension(api_key): axum::extract::Extension<ApiKeyRecord>,
    client_id: ClientId,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    sse_response(
        state,
        api_key,
        std::time::Duration::from_secs(SSE_HEARTBEAT_SECS),
        std::time::Duration::from_secs(SSE_MAX_LIFE_SECS),
        client_id.0,
    )
    .await
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
        };
        (db, state, trigger_rx, dir)
    }

    fn probe_router(state: &HttpState) -> Router {
        let hook: Arc<dyn RouterHook> = Arc::new(BaseRouterHook(state.clone()));
        create_router(state.clone(), hook, None, None, None, None)
    }

    /// Insert a key whose raw material is known to the test, so it can sign.
    async fn seed_key(db: &Database, sid: &str, email: &str, scopes: &[&str], raw_key: &str) {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        let category = if email.is_empty() { "system" } else { "agent" };
        db.insert_api_key(
            sid,
            email,
            &store_hash(&crate::core::api::auth::sha256_hex(raw_key)),
            &raw_key[..8],
            &scopes,
            None,
            category,
        )
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

    /// Baseline golden: system-scope pull sees every pending row of its
    /// system, grouped by identical payload.
    #[tokio::test]
    async fn pull_system_scope_sees_all_rows_grouped_by_body() {
        let (db, state, _rx, _dir) = probe_fixture("pull-sys").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey01").await;
        seed_pending(&db, "sys1", "x.com", "a@x.com", "hello").await;
        seed_pending(&db, "sys1", "x.com", "b@x.com", "hello").await;
        seed_pending(&db, "sys1", "y.com", "c@y.com", "world").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "syskey01",
            "sys1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        // Two distinct payloads ⇒ exactly two batches (grouping preserved).
        assert_eq!(
            resp["batches"].as_array().unwrap().len(),
            2,
            "body was {resp}"
        );
        assert_eq!(
            batch_delivery_emails(&resp),
            vec!["a@x.com", "b@x.com", "c@y.com"],
            "body was {resp}"
        );
    }

    /// Baseline golden: agent-scope pull sees ONLY its own address, even
    /// when other addresses in the same system have mail.
    #[tokio::test]
    async fn pull_agent_scope_returns_only_own_address() {
        let (db, state, _rx, _dir) = probe_fixture("pull-agent").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "a@x.com", &["agent"], "agentkey03").await;
        seed_pending(&db, "sys1", "x.com", "a@x.com", "mine").await;
        seed_pending(&db, "sys1", "x.com", "b@x.com", "notmine").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey03",
            "sys1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        let batches = resp["batches"].as_array().unwrap();
        assert_eq!(batches.len(), 1, "body was {resp}");
        assert_eq!(
            batch_delivery_emails(&resp),
            vec!["a@x.com"],
            "body was {resp}"
        );
    }

    /// Agent key without a bound address: pull is 403 (no isolation key).
    #[tokio::test]
    async fn pull_agent_unbound_address_rejected() {
        let (db, state, _rx, _dir) = probe_fixture("pull-agent-nobound").await;
        seed_key(&db, "sys1", "", &["agent"], "agentkey04").await;

        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey04",
            "sys1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20 }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body was {resp}");
    }

    /// Long-pull: an empty hold returns the mail that arrives during the
    /// hold (woken by the writer's notify), without waiting the full hold.
    #[tokio::test]
    async fn pull_agent_hold_wakes_on_new_mail() {
        let (db, state, _rx, _dir) = probe_fixture("pull-agent-hold").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "a@x.com", &["agent"], "agentkey05").await;

        let started = std::time::Instant::now();
        let router = probe_router(&state);
        let db2 = db.clone();
        // Simulate the writer's contract (C5 wires this into the webhook):
        // insert the row, then notify the agent key.
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            seed_pending(&db2, "sys1", "x.com", "a@x.com", "late").await;
            crate::core::pending_notifier::PendingNotifier::global()
                .notify_email("sys1", "a@x.com");
        });
        let (status, resp) = signed_post(
            router,
            "agentkey05",
            "sys1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20, "timeout_ms": 3000 }),
        )
        .await;
        writer.await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(
            batch_delivery_emails(&resp),
            vec!["a@x.com"],
            "body was {resp}"
        );
        // Woken by the writer, not by the 3s timeout.
        assert!(
            elapsed < Duration::from_millis(2500),
            "hold was not woken, took {elapsed:?}"
        );
    }

    /// Long-pull timeout: no mail arrives ⇒ 200 + empty batches after the
    /// hold elapses (clients treat it as an ordinary empty round).
    ///
    /// Uses a UNIQUE system_id so the process-global notifier key is
    /// isolated from the sibling `..._wakes_on_new_mail` test (they share
    /// the same `PendingNotifier::global()` instance, so a same-key notify
    /// from the other test would otherwise wake this waiter early).
    #[tokio::test]
    async fn pull_agent_hold_timeout_returns_empty() {
        let (db, state, _rx, _dir) = probe_fixture("pull-agent-hold-to").await;
        db.insert_system_domain("d1", "holdto1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "holdto1", "a@x.com", &["agent"], "agentkey06").await;

        let started = std::time::Instant::now();
        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey06",
            "holdto1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20, "timeout_ms": 800 }),
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(resp["batches"], serde_json::json!([]), "body was {resp}");
        assert!(
            elapsed >= Duration::from_millis(750),
            "returned before the hold elapsed: {elapsed:?}"
        );
    }

    /// Cross-system ack is a no-op (the identity filter is the calling key's
    /// own system_id — an existing row of another system survives).
    #[tokio::test]
    async fn ack_system_key_cannot_ack_other_system_rows() {
        let (db, state, _rx, _dir) = probe_fixture("ack-xsys").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "", &["system"], "syskey02").await;
        seed_key(&db, "sys2", "", &["system"], "syskey03").await;
        let id = seed_pending(&db, "sys1", "x.com", "a@x.com", "x").await;

        // sys2's key tries to ack sys1's row.
        let (status, resp) = signed_post(
            probe_router(&state),
            "syskey03",
            "sys2",
            "/api/v1/admin/pending/ack",
            &serde_json::json!({ "ids": [id] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(resp["acked"], serde_json::json!(0), "body was {resp}");
        // Row is still there for its owner.
        let (status, resp) = signed_post(
            probe_router(&state),
            "syskey02",
            "sys1",
            "/api/v1/admin/pending",
            &serde_json::json!({ "limit": 20 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(
            batch_delivery_emails(&resp),
            vec!["a@x.com"],
            "body was {resp}"
        );
    }

    /// Agent ack: cross-address is a no-op, own address is acked.
    #[tokio::test]
    async fn ack_agent_key_only_acks_own_address() {
        let (db, state, _rx, _dir) = probe_fixture("ack-agent").await;
        db.insert_system_domain("d1", "sys1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sys1", "a@x.com", &["agent"], "agentkey07").await;
        let own = seed_pending(&db, "sys1", "x.com", "a@x.com", "mine").await;
        let other = seed_pending(&db, "sys1", "x.com", "b@x.com", "theirs").await;

        // Try to ack the other address's row: no-op.
        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey07",
            "sys1",
            "/api/v1/admin/pending/ack",
            &serde_json::json!({ "ids": [other] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(resp["acked"], serde_json::json!(0), "body was {resp}");

        // Own row: acked.
        let (status, resp) = signed_post(
            probe_router(&state),
            "agentkey07",
            "sys1",
            "/api/v1/admin/pending/ack",
            &serde_json::json!({ "ids": [own] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {resp}");
        assert_eq!(resp["acked"], serde_json::json!(1), "body was {resp}");
    }

    // ── SSE stream tests (Phase 1.5) ──────────────────────────────
    // Each test uses a UNIQUE system_id: `PendingNotifier::global()` is
    // a process-wide static, so a sibling test's notify on the same key
    // would otherwise wake this test's stream early.

    /// Read up to `want` complete SSE events (frames end with a blank
    /// line) from a response body, bounded by `timeout`.
    async fn read_sse_events(body: Body, want: usize, timeout: std::time::Duration) -> Vec<String> {
        use futures_util::StreamExt;
        let mut stream = body.into_data_stream();
        let mut buf = String::new();
        let mut events = Vec::new();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if events.len() >= want {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let chunk = tokio::time::timeout(remaining, stream.next()).await;
            match chunk {
                Ok(Some(Ok(bytes))) => {
                    buf.push_str(&String::from_utf8_lossy(&bytes));
                    while let Some(pos) = buf.find("\n\n") {
                        events.push(buf[..pos].to_string());
                        buf.drain(..=pos + 1);
                    }
                }
                Ok(Some(Err(e))) => {
                    events.push(format!("#ERR {e}"));
                    break;
                }
                Ok(None) => break, // stream ended
                Err(_) => break,   // timeout
            }
        }
        events
    }

    /// Headers per contract + first frame == the POST response shape for
    /// the same rows (byte-identical `group_pending_batches` output), and
    /// the agent sees ONLY its own address.
    #[tokio::test]
    async fn sse_stream_headers_shape_and_agent_isolation() {
        let (db, state, _rx, _dir) = probe_fixture("sse-1").await;
        db.insert_system_domain("d1", "sse1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sse1", "a@x.com", &["agent"], "ssek1key").await;
        // Two rows, same payload ⇒ one batch; a second address (other key)
        // must NOT appear.
        seed_pending(&db, "sse1", "a@x.com", "a@x.com", "hello-1").await;
        seed_pending(&db, "sse1", "b@x.com", "b@x.com", "hello-1").await;

        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();
        let resp = sse_response(
            State(state),
            key,
            Duration::from_secs(5),
            Duration::from_secs(10),
            "test-sse-1".to_string(),
        )
        .await
        .unwrap();

        // Header contract.
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-cache");
        assert_eq!(resp.headers().get("x-accel-buffering").unwrap(), "no");
        assert_eq!(resp.headers().get("connection").unwrap(), "keep-alive");

        let events = read_sse_events(resp.into_body(), 1, Duration::from_secs(3)).await;
        assert_eq!(events.len(), 1, "expected one mail frame, got {events:?}");
        assert!(
            events[0].starts_with("event: mail\ndata: "),
            "{:?}",
            events[0]
        );

        // data payload == POST response shape for the agent's own rows.
        let records = db
            .list_pending_by_email("sse1", "a@x.com", 200)
            .await
            .unwrap();
        let expected = group_pending_batches(&records).to_string();
        assert_eq!(events[0][18..], expected, "shape must equal POST output");
        // Isolation: only a@x.com present.
        assert!(expected.contains("a@x.com"));
        assert!(!expected.contains("b@x.com"));
    }

    /// system-scope stream sees the whole system (all addresses, all
    /// distinct payloads).
    #[tokio::test]
    async fn sse_stream_system_scope_sees_all() {
        let (db, state, _rx, _dir) = probe_fixture("sse-2").await;
        db.insert_system_domain("d1", "sse2", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sse2", "sys@x.com", &["system"], "ssek2key").await;
        seed_pending(&db, "sse2", "a@x.com", "a@x.com", "p1").await;
        seed_pending(&db, "sse2", "b@x.com", "b@x.com", "p2").await;

        let key = db.get_api_key_by_email("sys@x.com").await.unwrap().unwrap();
        let resp = sse_response(
            State(state),
            key,
            Duration::from_secs(5),
            Duration::from_secs(10),
            "test-sse-2".to_string(),
        )
        .await
        .unwrap();
        let events = read_sse_events(resp.into_body(), 1, Duration::from_secs(3)).await;
        assert_eq!(events.len(), 1, "got {events:?}");
        let v: serde_json::Value = serde_json::from_str(&events[0][18..]).unwrap();
        assert_eq!(v["batches"].as_array().unwrap().len(), 2);
        let all: String = v.to_string();
        assert!(all.contains("a@x.com") && all.contains("b@x.com"));
    }

    /// Empty connect + writer wake-up ⇒ mail frame arrives quickly
    /// (at-least-once: the wake-up re-queries and emits new rows).
    #[tokio::test]
    async fn sse_stream_wakes_on_new_mail() {
        let (db, state, _rx, _dir) = probe_fixture("sse-3").await;
        db.insert_system_domain("d1", "sse3", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sse3", "a@x.com", &["agent"], "ssek3key").await;

        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();
        let resp = sse_response(
            State(state),
            key,
            Duration::from_secs(5),
            Duration::from_secs(10),
            "test-sse-3".to_string(),
        )
        .await
        .unwrap();

        // Writer simulation: insert AFTER connect, then notify (exactly
        // what webhook.rs does post-commit).
        let db2 = db.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            seed_pending(&db2, "sse3", "x.com", "a@x.com", "late").await;
            crate::core::pending_notifier::PendingNotifier::global()
                .notify_email("sse3", "a@x.com");
            crate::core::pending_notifier::PendingNotifier::global().notify_system("sse3");
        });

        let started = std::time::Instant::now();
        let events = read_sse_events(resp.into_body(), 1, Duration::from_secs(4)).await;
        let elapsed = started.elapsed();
        writer.await.unwrap();

        assert_eq!(events.len(), 1, "got {events:?}");
        assert!(events[0].starts_with("event: mail"), "{:?}", events[0]);
        assert!(events[0].contains("late"));
        assert!(
            elapsed < Duration::from_secs(2),
            "wake-up took too long: {elapsed:?}"
        );
    }

    /// at-least-once: rows sent on connection 1 but NOT acked are
    /// re-sent on connection 2 (watermark resets per connection).
    #[tokio::test]
    async fn sse_stream_reconnect_resends_unacked() {
        let (db, state, _rx, _dir) = probe_fixture("sse-4").await;
        db.insert_system_domain("d1", "sse4", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sse4", "a@x.com", &["agent"], "ssek4key").await;
        seed_pending(&db, "sse4", "a@x.com", "a@x.com", "persist").await;

        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        // Connection 1: sees the row (and we deliberately do NOT ack).
        let resp1 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_secs(5),
            Duration::from_secs(2),
            "test-sse-4".to_string(),
        )
        .await
        .unwrap();
        let ev1 = read_sse_events(resp1.into_body(), 1, Duration::from_secs(3)).await;
        assert_eq!(ev1.len(), 1, "conn1 got {ev1:?}");
        assert!(ev1[0].contains("persist"));

        // Connection 2: the unacked row is re-sent.
        let resp2 = sse_response(
            State(state),
            key,
            Duration::from_secs(5),
            Duration::from_secs(2),
            "test-sse-4".to_string(),
        )
        .await
        .unwrap();
        let ev2 = read_sse_events(resp2.into_body(), 1, Duration::from_secs(3)).await;
        assert_eq!(ev2.len(), 1, "conn2 got {ev2:?}");
        assert!(ev2[0].contains("persist"), "unacked row must be re-sent");
    }

    /// Heartbeat (injected 100ms) pings while idle; the stream ends at
    /// the injected max life.
    #[tokio::test]
    async fn sse_stream_heartbeat_and_max_life() {
        let (db, state, _rx, _dir) = probe_fixture("sse-5").await;
        db.insert_system_domain("d1", "sse5", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "sse5", "a@x.com", &["agent"], "ssek5key").await;

        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();
        let resp = sse_response(
            State(state),
            key,
            Duration::from_millis(100),
            Duration::from_millis(900),
            "test-sse-5".to_string(),
        )
        .await
        .unwrap();
        // 900ms life @ 100ms heartbeat ⇒ ≥5 pings, then the stream ends.
        let events = read_sse_events(resp.into_body(), 5, Duration::from_secs(3)).await;
        assert!(events.len() >= 5, "expected ≥5 pings, got {events:?}");
        assert!(events.iter().all(|e| e == ": ping"), "{events:?}");
    }

    // ─── Single-slot mailbox lock (one client per key) ─────────────

    /// Poll the pending endpoint as `client` (returns status + error body).
    async fn poll_as(
        state: &HttpState,
        key: &crate::core::storage::ApiKeyRecord,
        client: &str,
    ) -> (StatusCode, Option<String>) {
        let req = Json(PendingPollRequest {
            limit: 10,
            emails: Vec::new(),
            filter: Vec::new(),
            timeout_ms: 0,
        });
        let r = list_pending_deliveries(
            State(state.clone()),
            axum::extract::Extension(key.clone()),
            ClientId(client.to_string()),
            req,
        )
        .await;
        match r {
            Ok(_) => (StatusCode::OK, None),
            Err((s, Json(e))) => (s, Some(e.error)),
        }
    }

    /// First connection wins; a different client is 409 without building a
    /// stream; the same client re-acquires (reconnect / rotation).
    #[tokio::test]
    async fn slot_stream_first_wins_and_same_client_reacquires() {
        let (db, state, _rx, _dir) = probe_fixture("slot-1").await;
        db.insert_system_domain("d1", "slot1", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot1", "a@x.com", &["agent"], "slotk1key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        let r1 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "c1".to_string(),
        )
        .await;
        assert!(r1.is_ok(), "first connection must win");
        let r2 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "c2".to_string(),
        )
        .await;
        assert_eq!(
            r2.as_ref().unwrap_err().0,
            StatusCode::CONFLICT,
            "a different client must be 409 while c1 holds the slot"
        );
        let r3 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "c1".to_string(),
        )
        .await;
        assert!(r3.is_ok(), "the same client re-acquires (reconnect)");
        // Legacy clients (no header ⇒ id "") are just another client.
        let r4 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            String::new(),
        )
        .await;
        assert_eq!(r4.as_ref().unwrap_err().0, StatusCode::CONFLICT);
    }

    /// The 409 "occupied" detail must name the HOLDER, not the rejected
    /// requester (regression: the detail used to print the requester's own
    /// client id, mislabeling it as the holder).
    #[tokio::test]
    async fn slot_stream_409_detail_names_holder_not_requester() {
        let (db, state, _rx, _dir) = probe_fixture("slot-6").await;
        db.insert_system_domain("d1", "slot6", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot6", "a@x.com", &["agent"], "slotk6key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        // c1 takes the slot and holds it (a short-lived stream is enough —
        // we only need the slot claimed while c2 is rejected).
        let r1 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "holder-c1".to_string(),
        )
        .await;
        assert!(r1.is_ok(), "first connection must win");
        let r2 = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "requester-c2".to_string(),
        )
        .await;
        let (status, Json(e)) = r2.unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
        let detail = e.detail.as_deref().unwrap_or("");
        assert!(
            detail.contains("holder-c1"),
            "detail must name the holder, got: {detail:?}"
        );
        assert!(
            !detail.contains("requester-c2"),
            "detail must not name the rejected requester, got: {detail:?}"
        );
    }

    /// The slot is per API KEY, not per client id: one process (one
    /// client id) holding two different agents' keys must get both
    /// streams — same id on a *different* key is a different slot, so
    /// it can never 409-occupy or be occupied by the other connection.
    #[tokio::test]
    async fn slot_is_per_key_same_client_id_multiple_agents() {
        let (db, state, _rx, _dir) = probe_fixture("slot-7").await;
        db.insert_system_domain("d1", "slot7", "a@x.com", None, None)
            .await
            .unwrap();
        db.insert_system_domain("d2", "slot7b", "b@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot7", "a@x.com", &["agent"], "slotk7keya").await;
        seed_key(&db, "slot7b", "b@x.com", &["agent"], "slotk7keyb").await;
        let key_a = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();
        let key_b = db.get_api_key_by_email("b@x.com").await.unwrap().unwrap();

        // One client id, two keys: both streams must succeed while both
        // are open (the second must NOT see the first's slot).
        let r1 = sse_response(
            State(state.clone()),
            key_a.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "shared-c1".to_string(),
        )
        .await;
        assert!(r1.is_ok(), "agent A's stream must win its own slot");
        let r2 = sse_response(
            State(state.clone()),
            key_b.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "shared-c1".to_string(),
        )
        .await;
        assert!(
            r2.is_ok(),
            "same client id on a DIFFERENT key must not 409 (slot is per key)"
        );
        // Cross-check: a genuinely different client on key A is still
        // blocked — per-key isolation did not weaken the per-key lock.
        let r3 = sse_response(
            State(state.clone()),
            key_a.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "other-c2".to_string(),
        )
        .await;
        assert_eq!(
            r3.as_ref().unwrap_err().0,
            StatusCode::CONFLICT,
            "a different client on the same key must still 409"
        );
    }

    /// A stranger is 409 while a stream holder is ACTIVE and stays 409
    /// after the holder's max-life rotation (grace window); the holder's
    /// own client is never blocked.
    #[tokio::test]
    async fn slot_stream_holder_active_and_rotation_grace() {
        let (db, state, _rx, _dir) = probe_fixture("slot-2").await;
        db.insert_system_domain("d1", "slot2", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot2", "a@x.com", &["agent"], "slotk2key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        // Holder consumes the stream to its max life (200ms) ⇒ the
        // rotation path releases the slot WITH the grace window.
        let holder = tokio::spawn({
            let st = state.clone();
            let k = key.clone();
            async move {
                let r = sse_response(
                    State(st),
                    k,
                    Duration::from_millis(50),
                    Duration::from_millis(200),
                    "holder-1".to_string(),
                )
                .await;
                if let Ok(resp) = r {
                    read_sse_events(resp.into_body(), 100, Duration::from_millis(800)).await;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Stranger blocked while the holder is active.
        let (s, _) = poll_as(&state, &key, "stranger-1").await;
        assert_eq!(s, StatusCode::CONFLICT, "stranger 409 while holder active");
        // The holder's own client is never blocked (refresh).
        let (s2, _) = poll_as(&state, &key, "holder-1").await;
        assert_eq!(s2, StatusCode::OK);
        holder.await.unwrap();
        // After the rotation, the stranger is still blocked (grace window).
        let (s3, _) = poll_as(&state, &key, "stranger-2").await;
        assert_eq!(
            s3,
            StatusCode::CONFLICT,
            "stranger stays 409 during the post-rotation grace window"
        );
        // The owner still gets through the grace (reconnect).
        let (s4, _) = poll_as(&state, &key, "holder-1").await;
        assert_eq!(s4, StatusCode::OK);
    }

    /// Abrupt disconnect (the reader stops ⇒ the stream drops) releases the
    /// slot with ZERO grace: a stranger takes over at once.
    #[tokio::test]
    async fn slot_stream_abrupt_drop_zero_grace() {
        let (db, state, _rx, _dir) = probe_fixture("slot-3").await;
        db.insert_system_domain("d1", "slot3", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot3", "a@x.com", &["agent"], "slotk3key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        let resp = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "h3".to_string(),
        )
        .await
        .unwrap();
        // Read one frame, then stop: the body drops ⇒ guard drop (zero grace).
        let _ev = read_sse_events(resp.into_body(), 1, Duration::from_millis(300)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (s, _) = poll_as(&state, &key, "stranger-3").await;
        assert_eq!(
            s,
            StatusCode::OK,
            "a stranger takes over immediately after an abrupt disconnect"
        );
    }

    /// Long-poll lease: while a holder's lease is live the stranger is 409;
    /// after expiry the stranger takes over (no explicit release exists —
    /// a dead holder's lease simply expires). The same-client refresh path
    /// is covered by the types unit tests + slot_poll_blocked_by_stream_holder.
    #[tokio::test]
    async fn slot_poll_lease_expiry_takeover() {
        let (db, state, _rx, _dir) = probe_fixture("slot-4").await;
        db.insert_system_domain("d1", "slot4", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot4", "a@x.com", &["agent"], "slotk4key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        // Simulate a poll holder with a short lease via the public API.
        assert!(state
            .delivery_slot
            .try_acquire(key.id, "poll-holder", Duration::from_millis(120)));
        let (s, _) = poll_as(&state, &key, "other-1").await;
        assert_eq!(s, StatusCode::CONFLICT, "lease live ⇒ stranger 409");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (s3, _) = poll_as(&state, &key, "other-2").await;
        assert_eq!(
            s3,
            StatusCode::OK,
            "after lease expiry the stranger takes over"
        );
    }

    /// The poll path is the SAME slot as the stream path: a live stream
    /// holder blocks a stranger's poll (not just a stranger's stream).
    #[tokio::test]
    async fn slot_poll_blocked_by_stream_holder() {
        let (db, state, _rx, _dir) = probe_fixture("slot-5").await;
        db.insert_system_domain("d1", "slot5", "a@x.com", None, None)
            .await
            .unwrap();
        seed_key(&db, "slot5", "a@x.com", &["agent"], "slotk5key").await;
        let key = db.get_api_key_by_email("a@x.com").await.unwrap().unwrap();

        let resp = sse_response(
            State(state.clone()),
            key.clone(),
            Duration::from_millis(50),
            Duration::from_secs(10),
            "stream-holder".to_string(),
        )
        .await
        .unwrap();
        // Keep the stream alive (actively polled) so the slot stays held.
        let keeper = tokio::spawn({
            async move {
                read_sse_events(resp.into_body(), 100, Duration::from_millis(500)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (s, detail) = poll_as(&state, &key, "poller-x").await;
        assert_eq!(
            s,
            StatusCode::CONFLICT,
            "a stranger's poll is 409 while the stream holds"
        );
        assert!(
            detail.as_deref().is_some_and(|d| d.contains("occupied")),
            "{detail:?}"
        );
        // The holder's own client can still poll.
        let (s2, _) = poll_as(&state, &key, "stream-holder").await;
        assert_eq!(s2, StatusCode::OK);
        keeper.await.unwrap();
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
