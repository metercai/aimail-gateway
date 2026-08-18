//! Board HTTP API handlers — entry point only.
//! Auth (Bearer member token) lives here; all business logic delegates
//! to the shared awareness layer (same implementation as the
//! email-command path in `commands.rs`).

use crate::board::awareness;
use crate::board::db;
use crate::core::api::types::HttpState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Extract Bearer token from Authorization header.
fn extract_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Verify the token matches a board member. Returns the member email on success.
fn verify_board_token(
    headers: &HeaderMap,
    storage_path: &str,
    board_id: &str,
    member_email: &str,
) -> Option<String> {
    let token = extract_token(headers)?;
    if member_email.is_empty() {
        return None;
    }
    let conn = db::open_board_db(storage_path, board_id).ok()?;
    db::verify_member_token(&conn, board_id, token, member_email)
        .ok()
        .flatten()
}

/// S2: token auth + role authorization in one step — mirrors the email
/// command path (require_role in commands.rs). Returns the member email
/// only when the token is valid AND the member's role may use `verb`.
fn authorize(
    headers: &HeaderMap,
    storage_path: &str,
    board_id: &str,
    member_email: &str,
    verb: &str,
) -> Option<String> {
    let email = verify_board_token(headers, storage_path, board_id, member_email)?;
    let conn = db::open_board_db(storage_path, board_id).ok()?;
    let member = db::get_member(&conn, board_id, &email).ok()??;
    db::check_role_permission(&conn, &member.role, verb)
        .ok()
        .and_then(|allowed| allowed.then_some(email))
}

pub async fn handle_list_tasks(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str()).unwrap_or("");
    if authorize(&headers, &s, &board_id, email, "list").is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid token or role"})),
        ));
    }
    let status_filter = query.get("status").map(|s| s.as_str());
    let assignee_filter = query.get("assignee").map(|a| a.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::list_tasks(&conn, &board_id, status_filter, assignee_filter) {
            Ok(tasks) => Ok(Json(json!({"status": "ok", "tasks": tasks}))),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}

pub async fn handle_list_members(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str()).unwrap_or("");
    if authorize(&headers, &s, &board_id, email, "members").is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid token or role"})),
        ));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::list_members(&conn, &board_id, query.get("email").map(|v| v.as_str())) {
            Ok(members) => Ok(Json(json!({"status": "ok", "members": members}))),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}

pub async fn handle_list_roles(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str()).unwrap_or("");
    if authorize(&headers, &s, &board_id, email, "roles").is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid token or role"})),
        ));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::list_roles(&conn) {
            Ok(roles) => Ok(Json(json!({"status": "ok", "roles": roles}))),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}

pub async fn handle_get_task(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str()).unwrap_or("");
    if authorize(&headers, &s, &board_id, email, "show").is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid token or role"})),
        ));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::get_task(&conn, &task_id) {
            Ok((task, parent_summaries)) => {
                let mut body = json!({"status": "ok", "task": task});
                if !parent_summaries.is_empty() {
                    body["parent_summaries"] = json!(parent_summaries);
                }
                Ok(Json(body))
            }
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}

pub async fn handle_post_heartbeat(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    // Bearer token identifies the member → member email is the heartbeat actor.
    let actor = match authorize(
        &headers,
        &s,
        &board_id,
        query.get("email").map(|v| v.as_str()).unwrap_or(""),
        "heartbeat",
    ) {
        Some(email) => email,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"invalid token or role"})),
            ))
        }
    };
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::heartbeat(&conn, &task_id, &actor) {
            Ok(_) => Ok(Json(
                json!({"status": "ok", "message": "heartbeat recorded"}),
            )),
            Err(e) => Err((
                StatusCode::FORBIDDEN,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}

pub async fn handle_board_status(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str()).unwrap_or("");
    if authorize(&headers, &s, &board_id, email, "status").is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid token or role"})),
        ));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match awareness::board_status(&conn, &board_id) {
            Ok(status) => Ok(Json(json!({
                "status": "ok",
                "board": status["board"],
                "pipeline": status["pipeline"],
            }))),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("{:?}", e)})),
            )),
        },
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{:?}", e)})),
        )),
    }
}
