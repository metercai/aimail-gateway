//! 19 verb business logic for a2a_board commands.
//!
//! Each handler receives the board DB connection, a notifier, the command,
//! and the sender email. Returns a CommandResponse.

use crate::board::db;
use std::cell::RefCell;
use crate::board::models::*;
use crate::board::notify::Notifier;
use crate::core::errors::AppResult;
use chrono::Utc;
use rusqlite::Connection;

/// Execute a single A2A command.
pub fn execute_command(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    match cmd.verb.as_str() {
        "complete" => handle_complete(conn, notifier, cmd, sender),
        "approve" => handle_approve(conn, notifier, cmd, sender),
        "review" => handle_review(conn, notifier, cmd, sender),
        "verify" => handle_approve(conn, notifier, cmd, sender),
        "reject" => handle_reject(conn, notifier, cmd, sender),
        "block" => handle_block(conn, notifier, cmd, sender),
        "unblock" => handle_unblock(conn, notifier, cmd, sender),
        "heartbeat" => handle_heartbeat(conn, cmd, sender),
        "comment" => handle_comment(conn, notifier, cmd, sender),
        "cancel" => handle_cancel(conn, notifier, cmd, sender),
        "assign" => handle_reassign(conn, notifier, cmd, sender),
        "reassign" => handle_reassign(conn, notifier, cmd, sender),
        "edit" => handle_edit(conn, cmd, sender),
        "deadline" => handle_deadline(conn, cmd, sender),
        "output" => handle_output(conn, notifier, cmd, sender),
        "show" => handle_show(conn, cmd),
        "list" => handle_list(conn, cmd),
        "members" => handle_members(conn, cmd),
        "gateway-info" => handle_gateway_info(conn, cmd),
        "create" => handle_create(conn, notifier, cmd, sender),
            "refresh" => handle_init(conn, notifier, cmd, sender),
        "init" => handle_init(conn, notifier, cmd, sender),
        "arbitrate" => handle_arbitrate(conn, notifier, cmd, sender),
        _ => Ok(CommandResponse {
            status: "error".to_string(),
            task: None,
            error: Some(format!("unknown verb: {}", cmd.verb)),
        }),
    }
}

// ── Authorisation helpers ─────────────────────────────────────────────

fn require_role(conn: &Connection, board_id: &str, sender: &str, verb: &str) -> AppResult<()> {
    let member = db::get_member(conn, board_id, sender)?;
    match member {
        Some(m) => {
            if db::check_role_permission(conn, &m.role, verb)? {
                Ok(())
            } else {
                Err(crate::core::errors::AppError::Forbidden(
                    format!("role '{}' not permitted for verb '{}'", m.role, verb),
                ))
            }
        }
        None => Err(crate::core::errors::AppError::Forbidden(
            format!("sender not a board member: {}", sender),
        )),
    }
}

fn require_assignee(task: &Task, sender: &str) -> AppResult<()> {
    if task.assignee == sender {
        Ok(())
    } else {
        Err(crate::core::errors::AppError::Forbidden(
            format!("only assignee can perform this action: {}", sender),
        ))
    }
}

fn require_reviewer(task: &Task, sender: &str) -> AppResult<()> {
    if task.reviewer.as_deref() == Some(sender) {
        Ok(())
    } else {
        Err(crate::core::errors::AppError::Forbidden(
            format!("only the assigned reviewer can perform this action: {}", sender),
        ))
    }
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn extract_task_id(cmd: &A2aCommand) -> AppResult<String> {
    cmd.task_id.clone().ok_or_else(|| {
        crate::core::errors::AppError::BadRequest("task_id required".to_string())
    })
}

fn ok_response(task: Option<Task>) -> CommandResponse {
    CommandResponse {
        status: "ok".to_string(),
        task,
        error: None,
    }
}

// ── Handlers ──────────────────────────────────────────────────────────

fn handle_complete(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_assignee(&task, sender)?;

    let ts = now();
    if task.reviewer.is_some() {
        task.status = TaskStatus::Reviewing;
    } else {
        task.status = TaskStatus::Done;
        task.completed_at = Some(ts.clone());
    }
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0,
        task_id: task.id.clone(),
        event_type: "completed".to_string(),
        actor: sender.to_string(),
        payload: None,
        created_at: ts,
    })?;

    if task.reviewer.is_some() {
        notifier.notify_review_needed(&task);
    } else {
        promote_children(conn, notifier, &task);
        notifier.notify_approved(&task);
    }
    Ok(ok_response(Some(task)))
}

fn handle_review(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let reviewer = cmd.params.as_ref()
        .and_then(|p| p.get("reviewer").and_then(|v| v.as_str()))
        .ok_or_else(|| crate::core::errors::AppError::BadRequest("reviewer required".to_string()))?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "review")?;
    task.reviewer = Some(reviewer.to_string());
    task.status = TaskStatus::Reviewing;
    task.updated_at = now();
    db::update_task(conn, &task)?;
    notifier.notify_review_needed(&task);
    Ok(ok_response(Some(task)))
}

fn handle_approve(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_reviewer(&task, sender)?;

    let ts = now();
    task.status = TaskStatus::Done;
    task.completed_at = Some(ts.clone());
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "approved".to_string(),
        actor: sender.to_string(), payload: None, created_at: ts,
    })?;
    notifier.notify_approved(&task);
    promote_children(conn, notifier, &task);
    Ok(ok_response(Some(task)))
}

fn handle_reject(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_reviewer(&task, sender)?;

    let reason = cmd.params.as_ref()
        .and_then(|p| p.get("reason").and_then(|v| v.as_str()))
        .unwrap_or("");
    let ts = now();
    task.status = TaskStatus::Running;
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "rejected".to_string(),
        actor: sender.to_string(),
        payload: Some(serde_json::json!({"reason": reason})),
        created_at: ts,
    })?;
    notifier.notify_rejected(&task, reason);
    Ok(ok_response(Some(task)))
}

fn handle_block(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    // Worker can block their own tasks; orchestrator can block any
    if sender != task.assignee {
        require_role(conn, &task.board_id, sender, "block")?;
    }

    let ts = now();
    task.status = TaskStatus::Blocked;
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "blocked".to_string(),
        actor: sender.to_string(), payload: None, created_at: ts,
    })?;
    notifier.notify_blocked(&task, sender);
    Ok(ok_response(Some(task)))
}

fn handle_unblock(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "unblock")?;

    let ts = now();
    task.status = TaskStatus::Running;
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "unblocked".to_string(),
        actor: sender.to_string(), payload: None, created_at: ts,
    })?;
    notifier.notify_unblocked(&task, sender);
    Ok(ok_response(Some(task)))
}

fn handle_heartbeat(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    db::touch_task(conn, &task_id)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task_id.clone(), event_type: "heartbeat".to_string(),
        actor: sender.to_string(), payload: None, created_at: now(),
    })?;
    Ok(ok_response(None))
}

fn handle_comment(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let comment = cmd.params.as_ref()
        .and_then(|p| p.get("text").and_then(|v| v.as_str()))
        .unwrap_or("");
    let ts = now();
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task_id.clone(), event_type: "comment".to_string(),
        actor: sender.to_string(),
        payload: Some(serde_json::json!({"text": comment})),
        created_at: ts,
    })?;

    let task = db::get_task(conn, &task_id)?;
    notifier.notify_comment(&task, sender, comment);
    Ok(ok_response(None))
}

fn handle_cancel(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "cancel")?;

    let ts = now();
    task.status = TaskStatus::Cancelled;
    task.cancelled_at = Some(ts.clone());
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "cancelled".to_string(),
        actor: sender.to_string(), payload: None, created_at: ts,
    })?;
    notifier.notify_cancelled(&task);
    Ok(ok_response(Some(task)))
}

fn handle_reassign(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "reassign")?;

    let new_assignee = cmd.params.as_ref()
        .and_then(|p| p.get("assignee").and_then(|v| v.as_str()))
        .unwrap_or("");
    if new_assignee.is_empty() {
        return Err(crate::core::errors::AppError::BadRequest("assignee required".to_string()));
    }
    task.assignee = new_assignee.to_string();
    task.updated_at = now();
    db::update_task(conn, &task)?;
    notifier.notify_assigned(&task);
    Ok(ok_response(Some(task)))
}

fn handle_edit(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "edit")?;

    if let Some(params) = &cmd.params {
        if let Some(title) = params.get("title").and_then(|v| v.as_str()) {
            task.title = title.to_string();
        }
        if let Some(body) = params.get("body").and_then(|v| v.as_str()) {
            task.body = body.to_string();
        }
    }
    task.updated_at = now();
    db::update_task(conn, &task)?;
    Ok(ok_response(Some(task)))
}

fn handle_deadline(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "deadline")?;

    let deadline = cmd.params.as_ref()
        .and_then(|p| p.get("deadline").and_then(|v| v.as_str()))
        .unwrap_or("");
    task.deadline = Some(deadline.to_string());
    task.updated_at = now();
    db::update_task(conn, &task)?;
    Ok(ok_response(Some(task)))
}

fn handle_output(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "output")?;

    if task.status != TaskStatus::Done {
        return Err(crate::core::errors::AppError::BadRequest(
            "output task is not done yet".to_string(),
        ));
    }

    // Verify pipeline integrity
    let issues = db::verify_pipeline_integrity(conn, &task.board_id)?;
    if !issues.is_empty() {
        return Err(crate::core::errors::AppError::BadRequest(
            format!("pipeline issues: {}", issues.join(", ")),
        ));
    }

    let ts = now();
    db::insert_event(conn, &TaskEvent {
        id: 0, task_id: task.id.clone(), event_type: "output".to_string(),
        actor: sender.to_string(), payload: None, created_at: ts.clone(),
    })?;

    let mut board = db::get_board(conn, &task.board_id)?;
    board.output_task_id = Some(task.id.clone());
    board.status = BoardStatus::AwaitingOwner;
    db::update_board(conn, &board)?;

    notifier.notify_output(&task);
    Ok(ok_response(Some(task)))
}

fn handle_show(conn: &Connection, cmd: &A2aCommand) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let task = db::get_task(conn, &task_id)?;
    Ok(ok_response(Some(task)))
}

fn handle_list(conn: &Connection, cmd: &A2aCommand) -> AppResult<CommandResponse> {
    // params: board_id (from command params)
    let board_id = cmd.params.as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .unwrap_or("");
    let status = cmd.params.as_ref()
        .and_then(|p| p.get("status").and_then(|v| v.as_str()));
    let assignee = cmd.params.as_ref()
        .and_then(|p| p.get("assignee").and_then(|v| v.as_str()));
    let tasks = db::list_tasks(conn, board_id, status, assignee)?;
    Ok(CommandResponse {
        status: "ok".to_string(),
        task: None,
        error: None,
    })
}

fn handle_members(conn: &Connection, cmd: &A2aCommand) -> AppResult<CommandResponse> {
    let board_id = cmd.params.as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .unwrap_or("");
    let members = db::list_members(conn, board_id)?;
    Ok(CommandResponse {
        status: "ok".to_string(),
        task: None,
        error: None,
    })
}

fn handle_gateway_info(_conn: &Connection, _cmd: &A2aCommand) -> AppResult<CommandResponse> {
    // gateway-url is returned from the interceptor, not from board.db
    Ok(CommandResponse {
        status: "ok".to_string(),
        task: None,
        error: None,
    })
}

fn handle_create(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let board_id = cmd.params.as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .ok_or_else(|| crate::core::errors::AppError::BadRequest("board_id required".to_string()))?;
    require_role(conn, board_id, sender, "create")?;

    if let Some(params) = &cmd.params {
        if let Some(tasks) = params.get("tasks").and_then(|v| v.as_array()) {
            // Validate graph: all parents in this batch
            for t in tasks {
                let title = t.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let assignee = t.get("assignee").and_then(|v| v.as_str()).unwrap_or("");
                let short_id = db::next_short_id(conn, board_id)?;
                let task_id = db::make_task_id(board_id, &short_id);
                let ts = now();
                let task = Task {
                    id: task_id,
                    short_id,
                    board_id: board_id.to_string(),
                    title: title.to_string(),
                    body: t.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    status: TaskStatus::Ready,
                    assignee: assignee.to_string(),
                    reviewer: t.get("reviewer").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    parent_ids: t.get("parents").and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                    tags: t.get("tags").and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                    summary: String::new(),
                    metadata: t.get("metadata").map(|v| v.to_string()),
                    created_by: sender.to_string(),
                    created_at: ts.clone(),
                    updated_at: ts,
                    completed_at: None,
                    cancelled_at: None,
                    deadline: None,
                };
                db::create_task(conn, &task)?;
                notifier.notify_assigned(&task);
            }
        }
    }
    Ok(ok_response(None))
}

fn handle_init(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let board_id = &notifier.board.id;
    let short_id = &notifier.board.short_id;
    let ts = now();

    let description = cmd.params.as_ref()
        .and_then(|p| p.get("description")).and_then(|v| v.as_str()).map(String::from);
    let board = Board {
        id: board_id.clone(),
        short_id: short_id.clone(),
        board_email: notifier.board.board_email.clone(),
        description,
        status: BoardStatus::Active,
        output_task_id: None,
        plan_version: None,
            plan_text: None,
        plan_confirmed_at: None,
        criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
        gateway_url: notifier.board.gateway_url.clone(),
        created_at: ts.clone(),
        completed_at: None,
    };
    db::create_board(conn, &board)?;

    // Add members (required)
    let members_arr = cmd.params.as_ref()
        .and_then(|p| p.get("members"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| crate::core::errors::AppError::BadRequest("members array required".to_string()))?;
    for m in members_arr {
        let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
        let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("worker");
        let display_name = m.get("display_name").and_then(|v| v.as_str()).unwrap_or(email);
        if !email.is_empty() {
            db::add_member(conn, &Member {
                email: email.to_string(),
                role: role.to_string(),
                display_name: display_name.to_string(),
                board_id: board_id.clone(),
                joined_at: Some(ts.clone()),
                domains: None,
                capability_snapshot: None,
            })?;
        }
    }

    // Hardcoded: only human can refresh board
    let sender_member = db::get_member(conn, board_id, sender)?;
    match sender_member {
        Some(m) if m.role == "owner" => {},
        _ => return Err(crate::core::errors::AppError::Forbidden("only human can refresh board".to_string())),
    }

    // Seed role_permissions: defaults first, then user overrides
    seed_default_role_permissions(conn)?;
    if let Some(permissions) = cmd.params.as_ref()
        .and_then(|p| p.get("role_permissions"))
        .and_then(|v| v.as_array())
    {
        let perms: Vec<(String, Vec<String>)> = permissions
            .iter()
            .filter_map(|entry| {
                let role = entry.get("role")?.as_str()?.to_string();
                let verbs: Vec<String> = entry.get("verbs")?
                    .as_array()?
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Some((role, verbs))
            })
            .collect();
        db::insert_role_permissions(conn, board_id, &perms)?;
        tracing::info!("[a2a_board] role_permissions override: {} roles", perms.len());
    }

    notifier.notify_all(board_id, &format!("Board {} initialized", short_id));
    Ok(ok_response(None))
}


/// Default role-permission mappings (secure defaults).
/// Each verb is mapped to allowed roles. If role_permissions is provided in init,
/// these defaults are overwritten by the user-specified values.
fn seed_default_role_permissions(conn: &Connection) -> AppResult<()> {
    let defaults: &[(&str, &[&str])] = &[
        ("orchestrator", &["create","assign","review","block","unblock",
                           "cancel","reassign","edit","deadline","output","notify",
                           "members","roles","config","arbitrate","comment","list","show",
                           "status","heartbeat"]),
        ("verifier",     &["verify","approve","reject","output","comment",
                           "list","show","roles","members","status","heartbeat"]),
        ("worker",       &["complete","commit","block","heartbeat","comment","list","show","roles","members","status"]),
        ("owner",        &["create","unblock","reassign","comment","list","show","status","members","roles"]),
    ];
    for (role, verbs) in defaults {
        for verb in *verbs {
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role, verb) VALUES (?1, ?2)",
                rusqlite::params![role, verb],
            )?;
        }
    }
    Ok(())
}

fn handle_arbitrate(conn: &Connection, notifier: &Notifier, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = cmd.task_id.clone().unwrap_or_default();
    let task = if task_id.is_empty() {
        None
    } else {
        db::get_task(conn, &task_id).ok()
    };
    let board_id = task.as_ref().map(|t| t.board_id.as_str()).unwrap_or("");
    let requester_role = db::get_member(conn, board_id, sender)?
        .map(|m| m.role)
        .unwrap_or_default();
    if requester_role != "orchestrator" && requester_role != "verifier" {
        return Err(crate::core::errors::AppError::Forbidden(
            "only orchestrator or verifier can arbitrate".to_string(),
        ));
    }

    let dispute = cmd.params.as_ref()
        .and_then(|p| p.get("dispute").and_then(|v| v.as_str()))
        .unwrap_or("");
    let admin_email = ""; // TODO: resolve from board config

    notifier.notify_arbitrate(task.as_ref(), sender, admin_email, dispute);
    Ok(ok_response(None))
}

// ── Helpers ───────────────────────────────────────────────────────────

fn promote_children(conn: &Connection, notifier: &Notifier, parent: &Task) {
    // Find tasks whose parent_ids contain this task's short_id
    if let Ok(tasks) = db::list_tasks(conn, &parent.board_id, None, None) {
        for mut child in tasks {
            if child.parent_ids.contains(&parent.short_id) {
                // Check if all parents are done
                let all_done = child.parent_ids.iter().all(|pid| {
                    db::list_tasks(conn, &parent.board_id, Some("done"), None)
                        .map(|t| t.iter().any(|x| x.short_id == *pid))
                        .unwrap_or(false)
                });
                if all_done && child.status == TaskStatus::Todo {
                    child.status = TaskStatus::Ready;
                    let _ = db::update_task(conn, &child);
                    notifier.notify_assigned(&child);
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::db;
    use std::cell::RefCell;
use crate::board::models::*;
    use crate::board::notify::Notifier;
    use crate::core::email::factory::EmailFactory;
    use rusqlite::Connection;
    use std::sync::Arc;

    fn setup() -> (Connection, String, Notifier) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        db::init_schema(&conn).unwrap();

        let board_id = "testboardid0001";
        let board = Board {
            id: board_id.to_string(),
            short_id: "test".to_string(),
            board_email: "test.a2a@test.io".to_string(),
            description: Some("test board".to_string()),
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            gateway_url: "".to_string(),
            created_at: now(),
            completed_at: None,
        };
        db::create_board(&conn, &board).unwrap();

        // Create members
        for (email, role) in &[
            ("orch@t.io", "orchestrator"),
            ("veri@t.io", "verifier"),
            ("worker@t.io", "worker"),
            ("human@t.io", "owner"),
        ] {
            db::add_member(&conn, &Member {
                email: email.to_string(),
                role: role.to_string(),
                display_name: email.to_string(),
                board_id: board_id.to_string(),
                joined_at: None,
                domains: None,
                capability_snapshot: None,
            }).unwrap();
        }

        let notifier = Notifier {
            email_factory: todo!(), // 单元测试中不发送通知
            system_id: "test",
            board: &board,
            gateway_domain: "test.io",
            tasks: RefCell::new(Vec::new()),
        };

        (conn, board_id.to_string(), notifier)
    }

    fn make_cmd(verb: &str, task_id: Option<&str>, params: Option<serde_json::Value>) -> A2aCommand {
        A2aCommand {
            verb: verb.to_string(),
            task_id: task_id.map(|s| s.to_string()),
            params,
        }
    }

    fn make_task(conn: &Connection, board_id: &str, short_id: &str, assignee: &str) -> String {
        let task = Task {
            id: db::make_task_id(board_id, short_id),
            short_id: short_id.to_string(),
            board_id: board_id.to_string(),
            title: format!("Task {}", short_id),
            body: "body".to_string(),
            status: TaskStatus::Running,
            assignee: assignee.to_string(),
            reviewer: None,
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(conn, &task).unwrap();
        task.id
    }

    // ── complete ──
    #[test]
    fn test_complete_as_assignee() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("complete", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Done);
    }

    #[test]
    fn test_complete_as_non_assignee() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("complete", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io");
        assert!(resp.is_err(), "非 assignee 应拒绝 complete");
    }

    // ── block ──
    #[test]
    fn test_block_by_any_member() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("block", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    // ── approve with reviewer ──
    #[test]
    fn test_approve_as_reviewer() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Reviewing,
            assignee: "worker@t.io".to_string(),
            reviewer: Some("veri@t.io".to_string()),
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("approve", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "veri@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Done);
    }

    #[test]
    fn test_approve_as_non_reviewer() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Reviewing,
            assignee: "worker@t.io".to_string(),
            reviewer: Some("veri@t.io".to_string()),
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("approve", Some(&tid), None);
        assert!(execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io").is_err());
    }

    // ── unblock by orchestrator ──
    #[test]
    fn test_unblock_by_orchestrator() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Blocked,
            assignee: "worker@t.io".to_string(),
            reviewer: None,
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("unblock", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Running);
    }

    #[test]
    fn test_unblock_by_worker_denied() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Blocked,
            assignee: "worker@t.io".to_string(),
            reviewer: None,
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("unblock", Some(&tid), None);
        assert!(execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").is_err());
    }

    // ── output by verifier ──
    #[test]
    fn test_output_by_verifier() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Done,
            assignee: "worker@t.io".to_string(),
            reviewer: None,
            parent_ids: vec![],
            tags: vec![],
            summary: "final output".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        // Update board output_task_id
        let mut board = db::get_board(&conn, &board_id).unwrap();
        board.output_task_id = Some(tid.clone());
        db::update_board(&conn, &board).unwrap();

        let cmd = make_cmd("output", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "veri@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    // ── unknown verb ──
    #[test]
    fn test_unknown_verb() {
        let (conn, _, _) = setup();
        let cmd = make_cmd("unknown_verb", None, None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.error.unwrap().contains("unknown"));
    }

    // ── cancel by orchestrator ──
    #[test]
    fn test_cancel_by_orchestrator() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("cancel", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);
    }

    #[test]
    fn test_cancel_by_worker_denied() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("cancel", Some(&tid), None);
        assert!(execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").is_err());
    }

    // ── reassign by orchestrator ──
    #[test]
    fn test_reassign_by_orchestrator() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("reassign", Some(&tid), Some(serde_json::json!({"assignee": "veri@t.io"})));
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.assignee, "veri@t.io");
    }

    // ── heartbeat ──
    #[test]
    fn test_heartbeat() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("heartbeat", Some(&tid), None);
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    // ── edit ──
    #[test]
    fn test_edit_title() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("edit", Some(&tid), Some(serde_json::json!({"title": "New Title"})));
        let resp = execute_command(&conn, &nn.as_notifier(&board), &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.title, "New Title");
    }

    // ── complete with reviewer → reviewing ──
    #[test]
    fn test_complete_with_reviewer_enters_reviewing() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Running,
            assignee: "worker@t.io".to_string(),
            reviewer: Some("veri@t.io".to_string()),
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("complete", Some(&tid), None);
        execute_command(&conn, &nn.as_notifier(&board), &cmd, "worker@t.io").unwrap();
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Reviewing);
    }

    // ── reject → running ──
    #[test]
    fn test_reject_returns_to_running() {
        let (conn, board_id, board) = setup_with_board();
        let nn = NullNotifier;
        let mut t = Task {
            id: db::make_task_id(&board_id, "T1"),
            short_id: "T1".to_string(),
            board_id: board_id.clone(),
            title: "Test".to_string(),
            body: "".to_string(),
            status: TaskStatus::Reviewing,
            assignee: "worker@t.io".to_string(),
            reviewer: Some("veri@t.io".to_string()),
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &t).unwrap();
        let tid = t.id.clone();
        let cmd = make_cmd("reject", Some(&tid), Some(serde_json::json!({"reason": "needs revision"})));
        execute_command(&conn, &nn.as_notifier(&board), &cmd, "veri@t.io").unwrap();
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Running);
    }
}
