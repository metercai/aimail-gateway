//! Board handlers — State<HttpState> with :board_id syntax (axum 0.7)

use crate::board::db;

use axum::extract::{Path, State, Query};
use std::collections::HashMap;
use axum::Json;
use crate::core::api::types::HttpState;
use serde_json::{json, Value};


pub async fn handle_list_tasks(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let status_filter = query.get("status").map(|s| s.as_str());
    let assignee_filter = query.get("assignee").map(|a| a.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::list_tasks(&conn, &board_id, status_filter, assignee_filter) {
            Ok(tasks) => Json(json!({"status": "ok", "tasks": tasks})),
            Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
        },
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}

pub async fn handle_list_members(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let email = query.get("email").map(|v| v.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::list_members(&conn, &board_id) {
            Ok(members) => {
                let filtered: Vec<_> = if let Some(e) = email {
                    members.into_iter().filter(|m| m.email == e).collect()
                } else { members };
                Json(json!({"status": "ok", "members": filtered}))
            }
            Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
        },
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}

/// GET /api/v1/board/:board_id/roles?role=xxx
pub async fn handle_list_roles(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let role = query.get("role").map(|v| v.as_str());
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => {
            let all_roles = match crate::board::commands::do_roles(&conn) {
                Ok(r) => r,
                Err(e) => return Json(json!({"status": "error", "error": format!("{:?}", e)})),
            };
            if let Some(r) = role {
                let members = db::list_members(&conn, &board_id).unwrap_or_default();
                let emails: Vec<String> = members.into_iter()
                    .filter(|m| m.role == r).map(|m| m.email).collect();
                let verbs = all_roles.get(r).cloned().unwrap_or_default();
                Json(json!({"status": "ok", "role": r, "members": emails, "verbs": verbs}))
            } else {
                Json(json!({"status": "ok", "roles": all_roles}))
            }
        }
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}


/// GET /api/v1/board/:board_id/task/:task_id
pub async fn handle_get_task(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match db::get_task(&conn, &task_id) {
            Ok(task) => Json(json!({"status": "ok", "task": task})),
            Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
        },
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}

/// POST /api/v1/board/:board_id/task/:task_id/heartbeat
pub async fn handle_post_heartbeat(
    Path((board_id, task_id)): Path<(String, String)>,
    State(state): State<HttpState>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    let actor = query.get("actor").map(|s| s.as_str()).unwrap_or("api");
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => match crate::board::commands::do_heartbeat(&conn, &task_id, actor) {
            Ok(_) => Json(json!({"status": "ok"})),
            Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
        },
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}


/// GET /api/v1/board/:board_id/status — pipeline overview
pub async fn handle_board_status(
    Path(board_id): Path<String>,
    State(state): State<HttpState>,
) -> Json<Value> {
    let s = state.config.storage.path.to_string_lossy().to_string();
    match db::open_board_db(&s, &board_id) {
        Ok(conn) => {
            // Board metadata
            let board_info = match db::get_board(&conn, &board_id) {
                Ok(b) => json!({
                    "id": b.id, "short_id": b.short_id, "board_email": b.board_email,
                    "description": b.description, "status": b.status.to_string(),
                    "plan_version": b.plan_version, "plan_text": b.plan_text, "plan_confirmed_at": b.plan_confirmed_at,
                    "criteria_version": b.criteria_version, "criteria_text": b.criteria_text, "criteria_confirmed_at": b.criteria_confirmed_at,
                    "created_at": b.created_at, "completed_at": b.completed_at,
                }),
                Err(_) => json!({"id": board_id}),
            };

            // Pipeline: tasks grouped by status
            let pipeline = match db::list_tasks(&conn, &board_id, None, None) {
                Ok(tasks) => {
                    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
                    for t in &tasks {
                        groups.entry(t.status.to_string()).or_default().push(t.short_id.clone());
                    }
                    let keys = ["todo","ready","running","reviewing","done","blocked","cancelled"];
                    let mut result = serde_json::Map::new();
                    for k in &keys {
                        let list = groups.remove(*k).unwrap_or_default();
                        result.insert(k.to_string(), json!({"count": list.len(), "tasks": list}));
                    }
                    json!(result)
                }
                Err(_) => json!({}),
            };

            // Dependencies: parent-child relationships
            let deps = match db::list_tasks(&conn, &board_id, None, None) {
                Ok(tasks) => {
                    let mut dep_map = serde_json::Map::new();
                    let all_ids: Vec<String> = tasks.iter().map(|t| t.short_id.clone()).collect();
                    for t in &tasks {
                        let parents: Vec<String> = t.parent_ids.clone();
                        let children: Vec<String> = all_ids.iter()
                            .filter(|id| tasks.iter().any(|x| x.short_id == **id && x.parent_ids.contains(&t.short_id)))
                            .cloned().collect();
                        let assignee = if !t.assignee.is_empty() { Some(t.assignee.clone()) } else { None };
                        let reviewer = t.reviewer.clone();
                        dep_map.insert(t.short_id.clone(), json!({
                            "parents": parents, "children": children,
                            "assignee": assignee, "reviewer": reviewer
                        }));
                    }
                    json!(dep_map)
                }
                Err(_) => json!({}),
            };

            Json(json!({"status":"ok", "board": board_info, "pipeline": pipeline, "dependencies": deps}))
        }
        Err(e) => Json(json!({"status": "error", "error": format!("{:?}", e)})),
    }
}
