//! Board handlers — Bearer token auth for member-specific access
use crate::board::db;
use axum::extract::{Path, State, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::collections::HashMap;
use crate::core::api::types::HttpState;
use serde_json::{json, Value};

/// Extract Bearer token from Authorization header.
fn extract_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("Authorization")?
        .to_str().ok()?
        .strip_prefix("Bearer ")
}

/// Verify the token matches a board member. Returns the member email on success.
fn verify_board_token(headers: &HeaderMap, storage_path: &str, board_id: &str) -> Option<String> {
    let token = extract_token(headers)?;
    let conn = db::open_board_db(storage_path, board_id).ok()?;
    db::verify_member_token(&conn, board_id, token).ok().flatten()
}

pub async fn handle_list_tasks(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    let status_filter = query.get("status").map(|s| s.as_str());
    let assignee_filter = query.get("assignee").map(|a| a.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::list_tasks(&conn, &board_id, status_filter, assignee_filter) {
            Ok(tasks) => Ok(Json(json!({"status": "ok", "tasks": tasks}))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}

pub async fn handle_list_members(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    let email = query.get("email").map(|v| v.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::list_members(&conn, &board_id) {
            Ok(members) => {
                let filtered: Vec<_> = if let Some(e) = email {
                    members.into_iter().filter(|m| m.email == e).collect()
                } else { members };
                Ok(Json(json!({"status": "ok", "members": filtered})))
            }
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}

pub async fn handle_list_roles(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::get_role_permissions(&conn, &board_id) {
            Ok(roles) => Ok(Json(json!({"status": "ok", "roles": roles}))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}

pub async fn handle_get_task(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::get_task(&conn, &task_id) {
            Ok(task) => Ok(Json(json!({"status": "ok", "task": task}))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}

pub async fn handle_post_heartbeat(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::update_task_updated_at(&conn, &task_id) {
            Ok(_) => Ok(Json(json!({"status": "ok", "message": "heartbeat recorded"}))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}

pub async fn handle_board_status(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    if verify_board_token(&headers, &s, &board_id).is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid token"}))));
    }
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::get_board(&conn, &board_id) {
            Ok(board) => Ok(Json(json!({"status": "ok", "board": board}))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("{:?}", e)})))),
    }
}
