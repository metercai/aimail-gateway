//! 19 verb business logic for a2a_board commands.
//!
//! Each handler receives the board DB connection, a notifier, the command,
//! and the sender email. Returns a CommandResponse.

use crate::board::db;
use crate::board::models::*;
use crate::board::notify::Notifier;
use crate::core::errors::AppResult;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;

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
        "continue" => handle_continue(conn, notifier, cmd, sender),
        "cancel" => handle_cancel(conn, notifier, cmd, sender),
        "assign" => handle_reassign(conn, notifier, cmd, sender),
        "reassign" => handle_reassign(conn, notifier, cmd, sender),
        "edit" => handle_edit(conn, cmd, sender),
        "deadline" => handle_deadline(conn, cmd, sender),
        "reopen" => handle_reopen(conn, notifier, cmd, sender),
        "output" => handle_output(conn, notifier, cmd, sender),
        "show" => handle_show(conn, cmd, sender),
        "list" => handle_list(conn, cmd, sender),
        "members" => handle_members(conn, cmd, sender),
        "roles" => handle_roles(conn, cmd, sender),
        "status" => handle_board_status(conn, cmd, sender),
        "gateway-info" => handle_gateway_info(conn, cmd),
        "create" => handle_create(conn, notifier, cmd, sender),
        "refresh" => handle_init(conn, notifier, cmd, sender),
        "init" => handle_init(conn, notifier, cmd, sender),
        "arbitrate" => handle_arbitrate(conn, notifier, cmd, sender),
        _ => Ok(CommandResponse {
            status: "error".to_string(),
            task: None,
            data: None,
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
                Err(crate::core::errors::AppError::Forbidden(format!(
                    "role '{}' not permitted for verb '{}'",
                    m.role, verb
                )))
            }
        }
        None => Err(crate::core::errors::AppError::Forbidden(format!(
            "sender not a board member: {}",
            sender
        ))),
    }
}

fn require_assignee(task: &Task, sender: &str) -> AppResult<()> {
    if task.assignee == sender {
        Ok(())
    } else {
        Err(crate::core::errors::AppError::Forbidden(format!(
            "only assignee can perform this action: {}",
            sender
        )))
    }
}

fn require_member(conn: &Connection, board_id: &str, sender: &str) -> AppResult<()> {
    match db::get_member(conn, board_id, sender)? {
        Some(_) => Ok(()),
        None => Err(crate::core::errors::AppError::Forbidden(format!(
            "sender not a board member: {}",
            sender
        ))),
    }
}

fn require_reviewer(task: &Task, sender: &str) -> AppResult<()> {
    if task.reviewer.as_deref() == Some(sender) {
        Ok(())
    } else {
        Err(crate::core::errors::AppError::Forbidden(format!(
            "only the assigned reviewer can perform this action: {}",
            sender
        )))
    }
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn extract_task_id(cmd: &A2aCommand) -> AppResult<String> {
    cmd.task_id
        .clone()
        .ok_or_else(|| crate::core::errors::AppError::BadRequest("task_id required".to_string()))
}

fn ok_response(task: Option<Task>) -> CommandResponse {
    CommandResponse {
        status: "ok".to_string(),
        task,
        data: None,
        error: None,
    }
}

fn data_response(data: serde_json::Value) -> CommandResponse {
    CommandResponse {
        status: "ok".to_string(),
        task: None,
        data: Some(data),
        error: None,
    }
}

// ── Handlers ──────────────────────────────────────────────────────────

pub fn do_complete(
    conn: &Connection,
    notifier: &Notifier,
    task_id: &str,
    sender: &str,
    summary: Option<String>,
) -> AppResult<Task> {
    let mut task = db::get_task(conn, task_id)?;
    require_assignee(&task, sender)?;

    if let Some(ref s) = summary {
        task.summary = s.clone();
    }

    let ts = now();
    if task.reviewer.is_some() {
        task.status = TaskStatus::Reviewing;
    } else {
        task.status = TaskStatus::Done;
        task.completed_at = Some(ts.clone());
    }
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "completed".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts,
        },
    )?;

    if task.reviewer.is_some() {
        notifier.notify_review_needed(&task);
    } else {
        promote_children(conn, notifier, &task);
        notifier.notify_approved(&task);
    }
    Ok(task)
}

fn handle_complete(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let summary = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("summary").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    let task = do_complete(conn, notifier, &task_id, sender, summary)?;
    Ok(ok_response(Some(task)))
}

fn handle_review(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let reviewer = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("reviewer").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            crate::core::errors::AppError::BadRequest("reviewer required".to_string())
        })?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "review")?;
    task.reviewer = Some(reviewer.to_string());
    task.status = TaskStatus::Reviewing;
    task.updated_at = now();
    db::update_task(conn, &task)?;
    notifier.notify_review_needed(&task);
    Ok(ok_response(Some(task)))
}

fn handle_approve(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_reviewer(&task, sender)?;
    if task.status != TaskStatus::Reviewing {
        return Err(crate::core::errors::AppError::BadRequest(format!(
            "approve invalid for task status: {}",
            task.status
        )));
    }

    let ts = now();
    task.status = TaskStatus::Done;
    task.completed_at = Some(ts.clone());
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "approved".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts,
        },
    )?;
    notifier.notify_approved(&task);
    promote_children(conn, notifier, &task);
    Ok(ok_response(Some(task)))
}

fn handle_reject(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_reviewer(&task, sender)?;
    if task.status != TaskStatus::Reviewing {
        return Err(crate::core::errors::AppError::BadRequest(format!(
            "reject invalid for task status: {}",
            task.status
        )));
    }

    let reason = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("reason").and_then(|v| v.as_str()))
        .unwrap_or("");
    let ts = now();
    task.status = TaskStatus::Running;
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "rejected".to_string(),
            actor: sender.to_string(),
            payload: Some(serde_json::json!({"reason": reason})),
            created_at: ts,
        },
    )?;
    notifier.notify_rejected(&task, reason);
    Ok(ok_response(Some(task)))
}

fn handle_block(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
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
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "blocked".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts,
        },
    )?;
    notifier.notify_blocked(&task, sender);
    Ok(ok_response(Some(task)))
}

fn handle_unblock(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "unblock")?;

    let ts = now();
    task.status = TaskStatus::Running;
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "unblocked".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts,
        },
    )?;
    notifier.notify_unblocked(&task, sender);
    Ok(ok_response(Some(task)))
}

fn handle_heartbeat(
    conn: &Connection,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    crate::board::awareness::heartbeat(conn, &task_id, sender)?;
    Ok(ok_response(None))
}

fn handle_comment(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let comment = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("text").and_then(|v| v.as_str()))
        .unwrap_or("");
    let task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "comment")?;
    let ts = now();
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task_id.clone(),
            event_type: "comment".to_string(),
            actor: sender.to_string(),
            payload: Some(serde_json::json!({"text": comment})),
            created_at: ts,
        },
    )?;

    notifier.notify_comment(&task, sender, comment);
    Ok(ok_response(None))
}

fn handle_cancel(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "cancel")?;
    if task.status != TaskStatus::Blocked {
        return Err(crate::core::errors::AppError::BadRequest(
            "cancel only allowed for blocked tasks".to_string(),
        ));
    }

    let ts = now();
    task.status = TaskStatus::Cancelled;
    task.cancelled_at = Some(ts.clone());
    task.updated_at = ts.clone();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "cancelled".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts,
        },
    )?;
    notifier.notify_cancelled(&task);
    Ok(ok_response(Some(task)))
}

fn handle_reassign(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "reassign")?;

    let new_assignee = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("assignee").and_then(|v| v.as_str()))
        .unwrap_or("");
    if new_assignee.is_empty() {
        return Err(crate::core::errors::AppError::BadRequest(
            "assignee required".to_string(),
        ));
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

fn handle_deadline(
    conn: &Connection,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "deadline")?;

    let deadline = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("deadline").and_then(|v| v.as_str()))
        .unwrap_or("");
    task.deadline = Some(deadline.to_string());
    task.updated_at = now();
    db::update_task(conn, &task)?;
    Ok(ok_response(Some(task)))
}

fn handle_continue(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let mut task = db::get_task(conn, &task_id)?;
    require_assignee(&task, sender)?;

    let progress = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("progress").and_then(|v| v.as_str()))
        .unwrap_or("");
    let note = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("note").and_then(|v| v.as_str()))
        .unwrap_or("");

    task.summary = progress.to_string();
    task.updated_at = now();
    db::update_task(conn, &task)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "continue_request".to_string(),
            actor: sender.to_string(),
            payload: Some(serde_json::json!({"progress": progress, "note": note})),
            created_at: now(),
        },
    )?;
    notifier.notify_assigned(&task);
    Ok(ok_response(Some(task)))
}

fn handle_output(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let task = db::get_task(conn, &task_id)?;
    require_role(conn, &task.board_id, sender, "output")?;

    if task.status != TaskStatus::Done {
        return Err(crate::core::errors::AppError::BadRequest(
            "output task is not done yet".to_string(),
        ));
    }

    // Verify pipeline integrity
    let issues = db::verify_pipeline_integrity(conn, &task.board_id)?;
    if !issues.is_empty() {
        return Err(crate::core::errors::AppError::BadRequest(format!(
            "pipeline issues: {}",
            issues.join(", ")
        )));
    }

    let ts = now();
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "output".to_string(),
            actor: sender.to_string(),
            payload: None,
            created_at: ts.clone(),
        },
    )?;

    let mut board = db::get_board(conn, &task.board_id)?;
    board.output_task_id = Some(task.id.clone());
    board.status = BoardStatus::AwaitingOwner;
    db::update_board(conn, &board)?;

    notifier.notify_output(&task);
    Ok(ok_response(Some(task)))
}

fn handle_show(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let task_id = extract_task_id(cmd)?;
    let (task, parent_summaries) = crate::board::awareness::get_task(conn, &task_id)?;
    require_member(conn, &task.board_id, sender)?;

    let mut resp = ok_response(Some(task));
    if !parent_summaries.is_empty() {
        resp.data = Some(json!({"parent_summaries": parent_summaries}));
    }
    Ok(resp)
}

fn handle_list(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    // params: board_id (from command params)
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .unwrap_or("");
    require_member(conn, board_id, sender)?;
    let status = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("status").and_then(|v| v.as_str()));
    let assignee = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("assignee").and_then(|v| v.as_str()));
    let tasks = crate::board::awareness::list_tasks(conn, board_id, status, assignee)?;
    let task_list: Vec<serde_json::Value> = tasks
        .iter()
        .map(|t| {
            json!({
                "id": t.id, "short_id": t.short_id, "title": t.title,
                "status": t.status.to_string(), "assignee": t.assignee,
                "reviewer": t.reviewer, "parent_ids": t.parent_ids,
            })
        })
        .collect();
    Ok(data_response(json!({"tasks": task_list})))
}

fn handle_roles(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .unwrap_or("");
    require_member(conn, board_id, sender)?;
    let roles = crate::board::awareness::list_roles(conn)?;
    let role_names: Vec<String> = roles.keys().cloned().collect();
    tracing::info!("[a2a_board] roles: {:?}", role_names);
    Ok(data_response(json!({"roles": roles})))
}

fn handle_board_status(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            crate::core::errors::AppError::BadRequest("board_id required".to_string())
        })?;
    require_member(conn, board_id, sender)?;
    let status = crate::board::awareness::board_status(conn, board_id)?;

    tracing::info!("[a2a_board] board_status: board={}", board_id);
    Ok(data_response(status))
}

fn handle_members(conn: &Connection, cmd: &A2aCommand, sender: &str) -> AppResult<CommandResponse> {
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .unwrap_or("");
    require_member(conn, board_id, sender)?;
    let members = crate::board::awareness::list_members(conn, board_id, None)?;
    let member_list: Vec<serde_json::Value> = members
        .iter()
        .map(|m| {
            json!({
                "email": m.email, "role": m.role, "display_name": m.display_name
            })
        })
        .collect();
    Ok(data_response(json!({"members": member_list})))
}

fn handle_gateway_info(_conn: &Connection, _cmd: &A2aCommand) -> AppResult<CommandResponse> {
    // gateway-url is returned from the interceptor, not from board.db
    Ok(CommandResponse {
        status: "ok".to_string(),
        task: None,
        error: None,
        data: None,
    })
}

fn handle_create(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            crate::core::errors::AppError::BadRequest("board_id required".to_string())
        })?;
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
                    body: t
                        .get("body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    status: if assignee.is_empty() {
                        TaskStatus::Triage
                    } else {
                        TaskStatus::Ready
                    },
                    assignee: assignee.to_string(),
                    reviewer: t
                        .get("reviewer")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    parent_ids: t
                        .get("parents")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    tags: t
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
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

fn handle_init(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let board_id = &notifier.board_id;
    let short_id = &notifier.board_short_id;
    let ts = now();

    // refresh keeps the existing goal when none is provided
    // (INSERT OR REPLACE would otherwise overwrite it with NULL).
    let existing_goal = db::get_board(conn, board_id).ok().and_then(|b| b.goal);
    let description = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("description"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or(existing_goal);
    let board = Board {
        id: board_id.clone(),
        short_id: short_id.clone(),
        board_email: notifier.board_email.clone(),
        goal: description,
        status: BoardStatus::Active,
        output_task_id: None,
        plan_version: None,
        plan_text: None,
        plan_confirmed_at: None,
        criteria_version: None,
        criteria_text: None,
        criteria_confirmed_at: None,
        created_at: ts.clone(),
        completed_at: None,
    };
    // Idempotent upsert: first-time init creates the board record;
    // refresh on an existing board (auto-created by the interceptor)
    // must not fail — create_board refuses duplicates (903facc A2).
    match db::get_board(conn, board_id) {
        Ok(existing) => {
            let mut updated = existing;
            if board.goal.is_some() {
                updated.goal = board.goal.clone();
            }
            updated.status = BoardStatus::Active;
            db::update_board(conn, &updated)?;
        }
        Err(_) => {
            db::create_board(conn, &board)?;
        }
    }

    // Add members (required)
    let members_arr = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("members"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            crate::core::errors::AppError::BadRequest("members array required".to_string())
        })?;
    // Hardcoded: only human (owner) can refresh board — check BEFORE
    // any member mutation so a non-owner can never alter the member set.
    let sender_member = db::get_member(conn, board_id, sender)?;
    match sender_member {
        Some(m) if m.role == "owner" => {}
        _ => {
            return Err(crate::core::errors::AppError::Forbidden(
                "only human can refresh board".to_string(),
            ))
        }
    }

    // Existing members keep their tokens; only new members get fresh
    // tokens (so existing credentials stay valid across refreshes).
    let existing_tokens: std::collections::HashMap<String, String> = db::list_members(conn, &board_id)?
        .into_iter()
        .filter_map(|m| m.board_token.clone().map(|t| (m.email, t)))
        .collect();
    let mut new_members: Vec<(String, String)> = Vec::new(); // (email, token)
    for m in members_arr {
        let email = m.get("email").and_then(|v| v.as_str()).unwrap_or("");
        let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("worker");
        let display_name = m
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or(email);
        if !email.is_empty() {
            let token = existing_tokens
                .get(email)
                .cloned()
                .unwrap_or_else(db::generate_board_token);
            if !existing_tokens.contains_key(email) {
                new_members.push((email.to_string(), token.clone()));
            }
            db::add_member(
                conn,
                &Member {
                    email: email.to_string(),
                    role: role.to_string(),
                    display_name: display_name.to_string(),
                    board_id: board_id.clone(),
                    board_token: Some(token),
                    joined_at: Some(ts.clone()),
                    domains: None,
                    capability_snapshot: None,
                },
            )?;
        }
    }

    // Keep the host gateway's board group whitelist in sync with the
    // current member set (members changed via this refresh command).
    if let Ok(all_members) = db::list_members(conn, &board_id) {
        let emails: Vec<String> = all_members.iter().map(|m| m.email.clone()).collect();
        let _ = conn.execute(
            "DELETE FROM board_whitelists WHERE board_email = ?1",
            rusqlite::params![notifier.board_email],
        );
        for e in &emails {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO board_whitelists (board_email, member_addr) VALUES (?1, ?2)",
                rusqlite::params![notifier.board_email, e],
            );
        }
        tracing::info!(operation = "board_group_whitelist_refresh", board_email = %notifier.board_email, members = emails.len());
    }

    // Seed role_permissions: defaults first, then user overrides
    seed_default_role_permissions(conn)?;
    if let Some(permissions) = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("role_permissions"))
        .and_then(|v| v.as_array())
    {
        let perms: Vec<(String, Vec<String>)> = permissions
            .iter()
            .filter_map(|entry| {
                let role = entry.get("role")?.as_str()?.to_string();
                let verbs: Vec<String> = entry
                    .get("verbs")?
                    .as_array()?
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Some((role, verbs))
            })
            .collect();
        db::insert_role_permissions(conn, board_id, &perms)?;
        tracing::info!(
            "[a2a_board] role_permissions override: {} roles",
            perms.len()
        );
    }

    // Notifications: new members get an invite (with their token and the
    // FULL member set in X-Board-Members); everyone gets a member-list
    // change notice (also full set incl. the new members) so recipient
    // gateways replace their group whitelist consistently.
    if let Ok(all_members) = db::list_members(conn, &board_id) {
        let full_csv: String = all_members
            .iter()
            .map(|m| m.email.as_str())
            .collect::<Vec<_>>()
            .join(",");
        for (email, token) in &new_members {
            notifier.notify_invite(
                email,
                token,
                &board_id,
                &notifier.board_email,
                &short_id,
                &full_csv,
            );
        }
        notifier.notify_all(board_id, &format!("member list updated ({} members)", all_members.len()));
    }
    Ok(ok_response(None))
}

/// Default role-permission mappings (secure defaults).
/// Each verb is mapped to allowed roles. If role_permissions is provided in init,
/// these defaults are overwritten by the user-specified values.
/// Single source of truth lives in db::seed_default_role_permissions (L3).
fn seed_default_role_permissions(conn: &Connection) -> AppResult<()> {
    db::seed_default_role_permissions(conn)
}

fn handle_reopen(
    conn: &Connection,
    _notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
    let board_id = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("board_id").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            crate::core::errors::AppError::BadRequest("board_id required".to_string())
        })?;
    require_role(conn, board_id, sender, "reopen")?;

    let mut board = db::get_board(conn, board_id)?;
    if board.status != BoardStatus::AwaitingOwner {
        return Err(crate::core::errors::AppError::BadRequest(
            "board is not awaiting owner review".to_string(),
        ));
    }

    // Reset all done tasks to running; also demote already-Ready
    // children back to Todo — they became executable only because the
    // parent completed, so reopening the parent must invalidate them
    // (L4: reopen was one-way, leaving children runnable while the
    // parent was being redone).
    let tasks = db::list_tasks(conn, board_id, None, None)?;
    let reopened: Vec<String> = tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Done)
        .map(|t| t.short_id.clone())
        .collect();
    for mut task in tasks {
        if task.status == TaskStatus::Done {
            task.status = TaskStatus::Running;
            task.updated_at = now();
            db::update_task(conn, &task)?;
        } else if task.status == TaskStatus::Ready
            && task.parent_ids.iter().any(|p| reopened.contains(p))
        {
            // Child of a reopened task: not ready to run until the
            // parent completes again.
            task.status = TaskStatus::Todo;
            task.updated_at = now();
            db::update_task(conn, &task)?;
        }
    }

    board.status = BoardStatus::Active;
    board.plan_version = None;
    board.criteria_version = None;
    db::update_board(conn, &board)?;

    Ok(ok_response(None))
}

fn handle_arbitrate(
    conn: &Connection,
    notifier: &Notifier,
    cmd: &A2aCommand,
    sender: &str,
) -> AppResult<CommandResponse> {
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

    let dispute = cmd
        .params
        .as_ref()
        .and_then(|p| p.get("dispute").and_then(|v| v.as_str()))
        .unwrap_or("");
    let admin_email = ""; // TODO: resolve from board config (no admin field on Board yet)

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
    use crate::board::models::*;
    use crate::board::notify::Notifier;
    use rusqlite::Connection;
    use std::cell::RefCell;

    fn setup() -> (Connection, String, Notifier) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        db::init_schema(&conn).unwrap();
        seed_default_role_permissions(&conn).unwrap();

        let board_id = "testboardid0001";
        let board = Board {
            id: board_id.to_string(),
            short_id: "test".to_string(),
            board_email: "test.a2a@test.io".to_string(),
            goal: Some("test board".to_string()),
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
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
            db::add_member(
                &conn,
                &Member {
                    email: email.to_string(),
                    role: role.to_string(),
                    display_name: email.to_string(),
                    board_id: board_id.to_string(),
                    board_token: None,
                    joined_at: None,
                    domains: None,
                    capability_snapshot: None,
                },
            )
            .unwrap();
        }

        let notifier = Notifier {
            email_factory: None,
            board_db_path: "".to_string(),
            system_id: "test".to_string(),
            board_short_id: board.short_id.clone(),
            board_email: board.board_email.clone(),
            board_id: board.id.clone(),
            gateway_domain: "test.io".to_string(),
            gateway_url: "".to_string(),
            attachments_json: None,
            tasks: RefCell::new(Vec::new()),
        };

        (conn, board_id.to_string(), notifier)
    }

    fn make_cmd(
        verb: &str,
        task_id: Option<&str>,
        params: Option<serde_json::Value>,
    ) -> A2aCommand {
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

    fn make_task_with_reviewer(conn: &Connection, board_id: &str, short_id: &str, assignee: &str, reviewer: &str) -> String {
        let mut t = Task {
            id: db::make_task_id(board_id, short_id),
            short_id: short_id.to_string(),
            board_id: board_id.to_string(),
            title: format!("Task {}", short_id),
            body: "body".to_string(),
            status: TaskStatus::Running,
            assignee: assignee.to_string(),
            reviewer: Some(reviewer.to_string()),
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
        db::create_task(conn, &t).unwrap();
        t.id
    }

    // ── complete ──────────────────────────────────────────────────
    #[test]
    fn test_complete_without_reviewer() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("complete", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Done);
    }

    #[test]
    fn test_complete_with_reviewer_transitions_to_reviewing() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        let cmd = make_cmd("complete", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Reviewing);
    }

    #[test]
    fn test_complete_rejected_for_non_assignee() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("complete", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io");
        assert!(resp.is_err());
    }

    // ── heartbeat ─────────────────────────────────────────────────
    #[test]
    fn test_heartbeat_ready_to_running() {
        let (conn, board_id, notifier) = setup();
        // Create a task explicitly in Ready status
        let mut t = Task {
            id: db::make_task_id(&board_id, "H1"),
            short_id: "H1".to_string(),
            board_id: board_id.to_string(),
            title: "Heartbeat task".to_string(),
            body: "test".to_string(),
            status: TaskStatus::Ready,
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
        let cmd = make_cmd("heartbeat", Some(&t.id), None);
        let resp = execute_command(&conn, &notifier, &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &t.id).unwrap();
        assert_eq!(task.status, TaskStatus::Running);
    }

    #[test]
    fn test_heartbeat_rejected_for_non_assignee() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "H1", "worker@t.io");
        let cmd = make_cmd("heartbeat", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io");
        assert!(resp.is_err());
    }

    // ── block / unblock ───────────────────────────────────────────
    #[test]
    fn test_block_by_assignee() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("block", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "worker@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let task = db::get_task(&conn, &tid).unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[test]
    fn test_block_by_orchestrator() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("block", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Blocked);
    }

    #[test]
    fn test_unblock() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        // block first
        execute_command(&conn, &notifier, &make_cmd("block", Some(&tid), None), "worker@t.io").unwrap();
        // unblock
        let cmd = make_cmd("unblock", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Running);
    }

    // ── cancel ────────────────────────────────────────────────────
    #[test]
    fn test_cancel_blocked_task() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        execute_command(&conn, &notifier, &make_cmd("block", Some(&tid), None), "worker@t.io").unwrap();
        let cmd = make_cmd("cancel", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Cancelled);
    }

    #[test]
    fn test_cancel_rejected_for_non_blocked() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("cancel", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io");
        assert!(resp.is_err());
    }

    // ── approve / reject ──────────────────────────────────────────
    #[test]
    fn test_approve_by_reviewer() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        // complete first → Reviewing
        execute_command(&conn, &notifier, &make_cmd("complete", Some(&tid), None), "worker@t.io").unwrap();
        // approve
        let cmd = make_cmd("approve", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "veri@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Done);
    }

    #[test]
    fn test_reject_by_reviewer() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        execute_command(&conn, &notifier, &make_cmd("complete", Some(&tid), None), "worker@t.io").unwrap();
        let cmd = make_cmd("reject", Some(&tid), Some(serde_json::json!({"reason": "needs work"})));
        let resp = execute_command(&conn, &notifier, &cmd, "veri@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Running);
    }

    #[test]
    fn test_approve_rejected_for_non_reviewer() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        execute_command(&conn, &notifier, &make_cmd("complete", Some(&tid), None), "worker@t.io").unwrap();
        let cmd = make_cmd("approve", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io");
        assert!(resp.is_err());
    }

    // ── approve/reject status machine (P2-2) ─────────────────────
    #[test]
    fn test_approve_rejected_unless_reviewing() {
        // A task that is not in Reviewing must not be approvable even by
        // its reviewer — the state machine must gate the transition.
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        let cmd = make_cmd("approve", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "veri@t.io");
        assert!(resp.is_err(), "approve of non-Reviewing task must be rejected");
    }

    #[test]
    fn test_reject_rejected_unless_reviewing() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task_with_reviewer(&conn, &board_id, "T1", "worker@t.io", "veri@t.io");
        let cmd = make_cmd("reject", Some(&tid), Some(serde_json::json!({"reason": "x"})));
        let resp = execute_command(&conn, &notifier, &cmd, "veri@t.io");
        assert!(resp.is_err(), "reject of non-Reviewing task must be rejected");
    }

    // ── reopen demotes Ready children (L4) ────────────────────────
    #[test]
    fn test_reopen_demotes_ready_children() {
        let (conn, board_id, notifier) = setup();
        // Parent task: done. Child: ready (promoted when parent completed).
        let ptid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let child = Task {
            id: db::make_task_id(&board_id, "T2"),
            short_id: "T2".to_string(),
            board_id: board_id.clone(),
            title: "Child".to_string(),
            body: String::new(),
            status: TaskStatus::Ready,
            assignee: "worker@t.io".to_string(),
            reviewer: None,
            parent_ids: vec!["T1".to_string()],
            tags: vec![],
            summary: String::new(),
            metadata: None,
            created_by: "orch@t.io".to_string(),
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        };
        db::create_task(&conn, &child).unwrap();
        // Parent done + board awaiting owner
        let mut parent = db::get_task(&conn, &ptid).unwrap();
        parent.status = TaskStatus::Done;
        db::update_task(&conn, &parent).unwrap();
        let mut board = db::get_board(&conn, &board_id).unwrap();
        board.status = BoardStatus::AwaitingOwner;
        db::update_board(&conn, &board).unwrap();

        let cmd = make_cmd("reopen", None, Some(serde_json::json!({"board_id": board_id})));
        let resp = execute_command(&conn, &notifier, &cmd, "human@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let child_after = db::get_task(&conn, &db::make_task_id(&board_id, "T2")).unwrap();
        assert_eq!(
            child_after.status,
            TaskStatus::Todo,
            "Ready child of a reopened task must be demoted to Todo"
        );
    }

    // ── seed unification (L3) ─────────────────────────────────────
    #[test]
    fn test_orchestrator_has_output_and_create_perms() {
        // Both creation paths must give orchestrator the full verb set —
        // output (new path) and create/status (init path) must coexist.
        let (conn, _board_id, _notifier) = setup();
        assert!(db::check_role_permission(&conn, "orchestrator", "output").unwrap());
        assert!(db::check_role_permission(&conn, "orchestrator", "create").unwrap());
        assert!(db::check_role_permission(&conn, "orchestrator", "status").unwrap());
        assert!(db::check_role_permission(&conn, "orchestrator", "init").unwrap());
        assert!(db::check_role_permission(&conn, "owner", "reopen").unwrap());
    }

    // ── queries ───────────────────────────────────────────────────
    #[test]
    fn test_list_tasks() {
        let (conn, board_id, notifier) = setup();
        make_task(&conn, &board_id, "T1", "worker@t.io");
        make_task(&conn, &board_id, "T2", "worker@t.io");
        let cmd = make_cmd("list", None, Some(serde_json::json!({"board_id": board_id})));
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn test_show_task() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("show", Some(&tid), None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn test_status() {
        let (conn, board_id, notifier) = setup();
        let cmd = make_cmd("status", None, Some(serde_json::json!({"board_id": board_id})));
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn test_members() {
        let (conn, board_id, notifier) = setup();
        let cmd = make_cmd("members", None, Some(serde_json::json!({"board_id": board_id})));
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn test_roles() {
        let (conn, board_id, notifier) = setup();
        let cmd = make_cmd("roles", None, Some(serde_json::json!({"board_id": board_id})));
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    // ── comment ───────────────────────────────────────────────────
    #[test]
    fn test_comment() {
        let (conn, board_id, notifier) = setup();
        let tid = make_task(&conn, &board_id, "T1", "worker@t.io");
        let cmd = make_cmd("comment", Some(&tid), Some(serde_json::json!({"text": "looks good"})));
        let resp = execute_command(&conn, &notifier, &cmd, "veri@t.io").unwrap();
        assert_eq!(resp.status, "ok");
    }

    // ── unknown verb ──────────────────────────────────────────────
    #[test]
    fn test_unknown_verb_returns_error() {
        let (conn, _board_id, notifier) = setup();
        let cmd = make_cmd("nonexistent", None, None);
        let resp = execute_command(&conn, &notifier, &cmd, "orch@t.io").unwrap();
        assert_eq!(resp.status, "error");
    }

    // ── init/refresh idempotency (903facc A2 regression) ──────────
    #[test]
    fn test_init_on_existing_board_succeeds() {
        // handle_init must not fail when the board record already exists
        // (interceptor auto-creates it before dispatching the command).
        let (conn, board_id, notifier) = setup();
        let cmd = make_cmd(
            "init",
            None,
            Some(serde_json::json!({
                "members": [
                    {"email": "orch@t.io", "role": "orchestrator", "display_name": "Orch"},
                    {"email": "worker@t.io", "role": "worker", "display_name": "Worker"},
                ],
                "description": "updated goal",
            })),
        );
        let resp = execute_command(&conn, &notifier, &cmd, "human@t.io").unwrap();
        assert_eq!(resp.status, "ok");
        let board = db::get_board(&conn, &board_id).unwrap();
        assert_eq!(board.goal.as_deref(), Some("updated goal"));
        assert_eq!(board.status, BoardStatus::Active);
    }

    #[test]
    fn test_init_non_owner_rejected() {
        // Only an owner member may refresh the member set.
        let (conn, _board_id, notifier) = setup();
        let cmd = make_cmd(
            "init",
            None,
            Some(serde_json::json!({
                "members": [
                    {"email": "orch@t.io", "role": "orchestrator", "display_name": "Orch"},
                ],
            })),
        );
        let resp = execute_command(&conn, &notifier, &cmd, "worker@t.io");
        assert!(resp.is_err(), "non-owner init must be rejected");
    }
}
