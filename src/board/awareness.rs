//! Board awareness layer — the agent-facing surface for inspecting the
//! whole work state (boards, tasks, members, progress, blockers) and
//! reporting status, so the agent can decide its next action.
//!
//! This is the SINGLE implementation shared by both entry points:
//! the email-command path (`commands.rs`) and the HTTP API path
//! (`handlers.rs`). Entries only authenticate and wrap responses —
//! the queries and mutations below are identical for both.

use crate::board::db;
use crate::board::models::{Task, TaskEvent, TaskStatus};
use crate::core::errors::AppResult;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;

fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Get a board's working status: goal (description / plan version /
/// acceptance output) plus a per-status pipeline of all tasks with
/// their assignees — current progress and blockers at a glance.
pub fn board_status(conn: &Connection, board_id: &str) -> AppResult<Value> {
    let board = db::get_board(conn, board_id)?;
    let tasks = db::list_tasks(conn, board_id, None, None)?;

    let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
    for t in &tasks {
        groups
            .entry(t.status.to_string())
            .or_default()
            .push(json!({"short_id": t.short_id, "assignee": t.assignee}));
    }
    // All task statuses, matching TaskStatus's serialized names (lowercase).
    let keys = [
        "triage", "todo", "ready", "running", "reviewing", "done",
        "blocked", "cancelled", "archived",
    ];
    let mut pipeline = serde_json::Map::new();
    for k in &keys {
        let list = groups.remove(*k).unwrap_or_default();
        pipeline.insert(k.to_string(), json!({"count": list.len(), "tasks": list}));
    }

    Ok(json!({
        "board": {
            "id": board.id,
            "short_id": board.short_id,
            "status": board.status.to_string(),
            "goal": board.goal,
            "plan_version": board.plan_version,
            "plan_confirmed_at": board.plan_confirmed_at,
            "output_task_id": board.output_task_id,
        },
        "pipeline": pipeline,
    }))
}

/// List tasks of a board, optionally filtered by status and assignee.
/// Returns full task records.
pub fn list_tasks(
    conn: &Connection,
    board_id: &str,
    status: Option<&str>,
    assignee: Option<&str>,
) -> AppResult<Vec<Task>> {
    db::list_tasks(conn, board_id, status, assignee)
}

/// Get one task with its full record plus parent-task summaries
/// (short_id / title / summary for each parent). Entries wrap the
/// pieces in their own response shape. Board is derived from the
/// task record itself, so no board_id is needed at the call site.
pub fn get_task(conn: &Connection, task_id: &str) -> AppResult<(Task, Vec<Value>)> {
    let task = db::get_task(conn, task_id)?;

    let parent_summaries: Vec<Value> = task
        .parent_ids
        .iter()
        .filter_map(|pid| {
            db::list_tasks(conn, &task.board_id, None, None)
                .ok()?
                .into_iter()
                .find(|t| t.short_id == *pid)
                .map(|p| json!({"short_id": p.short_id, "title": p.title, "summary": p.summary}))
        })
        .collect();

    Ok((task, parent_summaries))
}

/// List board members (full records), optionally filtered by email.
pub fn list_members(conn: &Connection, board_id: &str, email: Option<&str>) -> AppResult<Vec<crate::board::models::Member>> {
    let members = db::list_members(conn, board_id)?;
    Ok(if let Some(e) = email {
        members.into_iter().filter(|m| m.email == e).collect()
    } else {
        members
    })
}

/// Role → permitted verbs map for the board.
pub fn list_roles(conn: &Connection) -> AppResult<HashMap<String, Vec<String>>> {
    let mut stmt = conn.prepare("SELECT role, verb FROM role_permissions ORDER BY role, verb")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let mut map = HashMap::new();
    for (role, verb) in rows {
        map.entry(role).or_insert_with(Vec::new).push(verb);
    }
    Ok(map)
}

/// Report liveness for a task: only the assignee may heartbeat; a Ready
/// task moves to Running; other statuses reject. Touches updated_at and
/// records a heartbeat event.
pub fn heartbeat(conn: &Connection, task_id: &str, actor: &str) -> AppResult<()> {
    let mut task = db::get_task(conn, task_id)?;
    if task.assignee != actor {
        return Err(crate::core::errors::AppError::Forbidden(
            "only assignee can heartbeat".to_string(),
        ));
    }
    if task.status == TaskStatus::Ready {
        task.status = TaskStatus::Running;
        db::update_task(conn, &task)?;
    } else if task.status != TaskStatus::Running {
        return Err(crate::core::errors::AppError::BadRequest(format!(
            "heartbeat invalid for task status: {}",
            task.status
        )));
    }
    db::touch_task(conn, task_id)?;
    db::insert_event(
        conn,
        &TaskEvent {
            id: 0,
            task_id: task_id.to_string(),
            event_type: "heartbeat".to_string(),
            actor: actor.to_string(),
            payload: None,
            created_at: now(),
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::models::{Board, BoardStatus};

    fn setup() -> (Connection, String) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        db::init_schema(&conn).unwrap();
        let board_id = "awareness-test-0001";
        let board = Board {
            id: board_id.to_string(),
            short_id: "awt".to_string(),
            board_email: "awt.a2a@test.io".to_string(),
            goal: Some("awareness test board".to_string()),
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: Some("v3".to_string()),
            plan_text: Some("plan".to_string()),
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            created_at: now(),
            completed_at: None,
        };
        db::create_board(&conn, &board).unwrap();
        // Create members (tasks.assignee has FK to board_members.email)
        for email in ["a@t.io", "b@t.io", "c@t.io", "intruder@t.io"] {
            db::add_member(
                &conn,
                &crate::board::models::Member {
                    email: email.to_string(),
                    role: "worker".to_string(),
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
        (conn, board_id.to_string())
    }

    fn make_task(
        conn: &Connection,
        board_id: &str,
        short_id: &str,
        assignee: &str,
        status: TaskStatus,
    ) -> String {
        let task = Task {
            id: db::make_task_id(board_id, short_id),
            short_id: short_id.to_string(),
            board_id: board_id.to_string(),
            title: format!("Task {}", short_id),
            body: "body".to_string(),
            status,
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

    #[test]
    fn board_status_pipeline_aggregates_progress_and_blockers() {
        let (conn, board_id) = setup();
        make_task(&conn, &board_id, "T1", "a@t.io", TaskStatus::Running);
        make_task(&conn, &board_id, "T2", "b@t.io", TaskStatus::Running);
        make_task(&conn, &board_id, "T3", "c@t.io", TaskStatus::Blocked);

        let v = board_status(&conn, &board_id).unwrap();
        // board section: goal / status present
        assert_eq!(v["board"]["short_id"], "awt");
        assert_eq!(v["board"]["goal"], "awareness test board");
        assert_eq!(v["board"]["status"], "active");
        // pipeline: running 2 (with assignees), blocked 1
        assert_eq!(v["pipeline"]["running"]["count"], 2);
        assert_eq!(v["pipeline"]["running"]["tasks"][0]["assignee"], "a@t.io");
        assert_eq!(v["pipeline"]["blocked"]["count"], 1);
        assert_eq!(v["pipeline"]["blocked"]["tasks"][0]["short_id"], "T3");
        assert_eq!(v["pipeline"]["blocked"]["tasks"][0]["assignee"], "c@t.io");
        // empty states present with count 0
        assert_eq!(v["pipeline"]["done"]["count"], 0);
    }

    #[test]
    fn heartbeat_ready_task_advances_to_running() {
        let (conn, board_id) = setup();
        let tid = make_task(&conn, &board_id, "T1", "a@t.io", TaskStatus::Ready);
        heartbeat(&conn, &tid, "a@t.io").unwrap();
        assert_eq!(db::get_task(&conn, &tid).unwrap().status, TaskStatus::Running);
    }

    #[test]
    fn heartbeat_rejects_non_assignee() {
        let (conn, board_id) = setup();
        let tid = make_task(&conn, &board_id, "T1", "a@t.io", TaskStatus::Running);
        assert!(heartbeat(&conn, &tid, "intruder@t.io").is_err());
    }

    #[test]
    fn heartbeat_rejects_status_other_than_ready_or_running() {
        let (conn, board_id) = setup();
        let tid = make_task(&conn, &board_id, "T1", "a@t.io", TaskStatus::Done);
        assert!(heartbeat(&conn, &tid, "a@t.io").is_err());
    }
}
