//! board.db CRUD operations.
//!
//! Each board has its own SQLite database at:
//!   {storage.path}/a2a_board/{board_id}/board.db

use crate::board::models::*;
use crate::core::errors::AppResult;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::PathBuf;

/// Open or create a board database by board_id.
pub fn open_board_db(storage_path: &str, board_id: &str) -> AppResult<Connection> {
    // Single-file layout: a2a_board/{board_id}.db — the db filename IS the
    // board-address hash, binding the board address to its data file 1:1
    // (no intermediate directory). Legacy directory layout is migrated
    // in place on first open.
    let dir = PathBuf::from(storage_path).join("a2a_board");
    std::fs::create_dir_all(&dir)?;
    let db_path = dir.join(format!("{board_id}.db"));
    let legacy = dir.join(board_id).join("board.db");
    if !db_path.exists() && legacy.exists() {
        if let Some(parent) = legacy.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::rename(&legacy, &db_path);
        let _ = std::fs::remove_dir_all(dir.join(board_id));
    }
    let conn = Connection::open(&db_path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    init_schema(&conn)?;
    Ok(conn)
}

pub(crate) fn init_schema(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS boards (
            id TEXT PRIMARY KEY,
            short_id TEXT UNIQUE NOT NULL,
            board_email TEXT NOT NULL,
            goal TEXT,
            status TEXT DEFAULT 'active',
            output_task_id TEXT,
            plan_version TEXT,
            plan_text TEXT,
            plan_confirmed_at TEXT,
            criteria_version TEXT,
            criteria_text TEXT,
            criteria_confirmed_at TEXT,
            created_at TEXT,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS board_members (
            email TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL,
            board_token TEXT,
            board_id TEXT REFERENCES boards(id),
            joined_at TEXT,
            domains TEXT,
            capability_snapshot TEXT
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            short_id TEXT NOT NULL,
            board_id TEXT REFERENCES boards(id),
            title TEXT,
            body TEXT,
            status TEXT DEFAULT 'todo',
            assignee TEXT REFERENCES board_members(email),
            reviewer TEXT,
            parent_ids TEXT DEFAULT '[]',
            tags TEXT DEFAULT '[]',
            summary TEXT DEFAULT '',
            metadata TEXT,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT,
            completed_at TEXT,
            cancelled_at TEXT,
            deadline TEXT
        );
        CREATE TABLE IF NOT EXISTS role_permissions (
            role TEXT NOT NULL,
            verb TEXT NOT NULL,
            PRIMARY KEY (role, verb)
        );

        CREATE TABLE IF NOT EXISTS task_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT REFERENCES tasks(id),
            event_type TEXT,
            actor TEXT,
            payload TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS task_seq (
            board_id TEXT PRIMARY KEY,
            next_val INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

// ── Board CRUD ────────────────────────────────────────────────────────

pub fn create_board(conn: &Connection, board: &Board) -> AppResult<()> {
    // Collision check: the board id is derived from (short_id, domain) —
    // creating the same board again must refuse, never silently replace
    // (INSERT OR REPLACE would overwrite an existing board's data).
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM boards WHERE id = ?1",
        [&board.id],
        |r| r.get(0),
    )?;
    if exists > 0 {
        return Err(crate::core::errors::AppError::Validation(format!(
            "board '{}' already exists (short id '{}')",
            board.id, board.short_id
        )));
    }
    conn.execute(
        "INSERT INTO boards (id, short_id, board_email, goal, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            board.id,
            board.short_id,
            board.board_email,
            board.goal,
            board.status.to_string(),
            board.created_at,
        ],
    )?;
    Ok(())
}

/// Archive a board — set status to Archived.
pub fn archive_board(conn: &Connection, board_id: &str) -> AppResult<()> {
    conn.execute(
        "UPDATE boards SET status = 'archived', completed_at = ?1 WHERE id = ?2",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), board_id],
    )?;
    Ok(())
}

pub fn get_board(conn: &Connection, board_id: &str) -> AppResult<Board> {
    conn.query_row(
        "SELECT id, short_id, board_email, goal, status, output_task_id, plan_version,
                plan_text, plan_confirmed_at, criteria_version, criteria_text, criteria_confirmed_at, created_at, completed_at
         FROM boards WHERE id = ?1",
        params![board_id],
        |row| {
            Ok(Board {
                id: row.get(0)?,
                short_id: row.get(1)?,
                board_email: row.get(2)?,
                goal: row.get(3)?,
                status: match row.get::<_, String>(4)?.as_str() {
                    "archived" => BoardStatus::Archived,
                    "awaiting_owner" => BoardStatus::AwaitingOwner,
                    "completed" => BoardStatus::Completed,
                    _ => BoardStatus::Active,
                },
                output_task_id: row.get(5)?,
                plan_version: row.get(6)?,
                plan_text: row.get(7)?,
                plan_confirmed_at: row.get(8)?,
                criteria_version: row.get(9)?,
                criteria_text: row.get(10)?,
                criteria_confirmed_at: row.get(11)?,
                created_at: row.get(12)?,
                completed_at: row.get(13)?,
            })
        },
    )
    .map_err(Into::into)
}

pub fn update_board(conn: &Connection, board: &Board) -> AppResult<()> {
    conn.execute(
        "UPDATE boards SET status=?1, output_task_id=?2, plan_version=?3, plan_text=?4,
         plan_confirmed_at=?5, criteria_version=?6, criteria_text=?7,
         criteria_confirmed_at=?8, completed_at=?9, goal=?10
         WHERE id=?11",
        params![
            board.status.to_string(),
            board.output_task_id,
            board.plan_version,
            board.plan_text,
            board.plan_confirmed_at,
            board.criteria_version,
            board.criteria_text,
            board.criteria_confirmed_at,
            board.completed_at,
            board.goal,
            board.id,
        ],
    )?;
    Ok(())
}

pub fn short_id_exists(conn: &Connection, short_id: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM boards WHERE short_id = ?1",
        params![short_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

// ── Member CRUD ───────────────────────────────────────────────────────

pub fn add_member(conn: &Connection, member: &Member) -> AppResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO board_members (email, role, display_name, board_id, board_token, joined_at, domains)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            member.email,
            member.role,
            member.display_name,
            member.board_id,
            member.board_token,
            member.joined_at,
            member.domains.as_ref().map(|d| serde_json::to_string(d).unwrap_or_default()),
        ],
    )?;
    Ok(())
}

/// Generate a board token: bdt_ + 32 hex chars.
pub fn generate_board_token() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::thread_rng().gen();
    format!("bdt_{}", hex::encode(bytes))
}

/// Insert multiple role-permission relationships (from init email).
pub fn insert_role_permissions(
    conn: &Connection,
    _board_id: &str,
    permissions: &[(String, Vec<String>)],
) -> AppResult<()> {
    for (role, verbs) in permissions {
        for verb in verbs {
            conn.execute(
                "INSERT OR REPLACE INTO role_permissions (role, verb) VALUES (?1, ?2)",
                rusqlite::params![role, verb],
            )?;
        }
    }
    Ok(())
}

/// Known board roles (S5 whitelist). Custom role strings are rejected at
/// member registration and role_permissions override — an arbitrary role
/// used to get open-mode permissions (R2) and enabled privilege escalation.
pub const KNOWN_ROLES: &[&str] = &["orchestrator", "verifier", "worker", "owner"];

/// Known command verbs (S5 whitelist for role_permissions overrides).
/// Union of every role's seeded verb set — typos/unknown verbs are rejected
/// instead of silently creating inert permission rows.
pub const KNOWN_VERBS: &[&str] = &[
    "init", "tasks", "create", "assign", "review", "block", "unblock",
    "cancel", "reassign", "edit", "deadline", "output", "notify", "members",
    "roles", "config", "arbitrate", "comment", "list", "show", "status",
    "heartbeat", "verify", "approve", "reject", "complete", "commit", "reopen",
];

/// Single source of truth for default role→verb permissions (L3 fix:
/// the seed previously existed twice with different verb sets — init
/// path (commands.rs) and new path (interceptor.rs) diverged, so the
/// same role had different capabilities depending on how the board was
/// created). This is the union: every role gets its full verb set on
/// every creation path.
pub fn seed_default_role_permissions(conn: &Connection) -> AppResult<()> {
    let defaults: &[(&str, &[&str])] = &[
        (
            "orchestrator",
            &[
                "init",
                "tasks",
                "create",
                "assign",
                "review",
                "block",
                "unblock",
                "cancel",
                "reassign",
                "edit",
                "deadline",
                "output",
                "notify",
                "members",
                "roles",
                "config",
                "arbitrate",
                "comment",
                "list",
                "show",
                "status",
                "heartbeat",
            ],
        ),
        (
            "verifier",
            &[
                "verify",
                "approve",
                "reject",
                "output",
                "comment",
                "list",
                "show",
                "roles",
                "members",
                "status",
                "heartbeat",
            ],
        ),
        (
            "worker",
            &[
                "complete",
                "commit",
                "block",
                "heartbeat",
                "comment",
                "list",
                "show",
                "roles",
                "members",
                "status",
            ],
        ),
        (
            "owner",
            &[
                "create",
                "tasks",
                "unblock",
                "reassign",
                "reopen",
                "comment",
                "list",
                "show",
                "status",
                "members",
                "roles",
                "heartbeat",
            ],
        ),
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

/// Check if a role has permission for a verb (R2: an unseeded role used to
/// be open — allow-all — which combined with S5's arbitrary roles meant a
/// custom role got every verb. Now: known roles are seeded idempotently on
/// first check; unknown roles are denied outright).
pub fn check_role_permission(conn: &Connection, role: &str, verb: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM role_permissions WHERE role = ?1",
        rusqlite::params![role],
        |r| r.get(0),
    )?;
    if count == 0 {
        if KNOWN_ROLES.contains(&role) {
            // Legacy board (created before every creation path seeded):
            // seed defaults once — INSERT OR IGNORE is idempotent.
            seed_default_role_permissions(conn)?;
        } else {
            // Unknown role: no permissions at all.
            return Ok(false);
        }
    }
    let allowed: i64 = conn.query_row(
        "SELECT COUNT(*) FROM role_permissions WHERE role = ?1 AND verb = ?2",
        rusqlite::params![role, verb],
        |r| r.get(0),
    )?;
    Ok(allowed > 0)
}

pub fn get_member(conn: &Connection, board_id: &str, email: &str) -> AppResult<Option<Member>> {
    let mut stmt = conn.prepare(
        "SELECT email, role, display_name, board_token, board_id, joined_at, domains, capability_snapshot
     FROM board_members WHERE board_id = ?1 AND email = ?2",
    )?;
    let mut rows = stmt.query(params![board_id, email])?;
    if let Some(row) = rows.next()? {
        Ok(Some(Member {
            email: row.get(0)?,
            role: row.get(1)?,
            display_name: row.get(2)?,
            board_token: row.get(3)?,
            board_id: row.get(4)?,
            joined_at: row.get(5)?,
            domains: row
                .get::<_, Option<String>>(6)?
                .and_then(|s| serde_json::from_str(&s).ok()),
            capability_snapshot: row.get(7)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn list_members(conn: &Connection, board_id: &str) -> AppResult<Vec<Member>> {
    let mut stmt = conn.prepare(
        "SELECT email, role, display_name, board_token, board_id, joined_at, domains, capability_snapshot
         FROM board_members WHERE board_id = ?1",
    )?;
    let rows = stmt.query_map(params![board_id], |row| {
        Ok(Member {
            email: row.get(0)?,
            role: row.get(1)?,
            display_name: row.get(2)?,
            board_token: row.get(3)?,
            board_id: row.get(4)?,
            joined_at: row.get(5)?,
            domains: row
                .get::<_, Option<String>>(6)?
                .and_then(|s| serde_json::from_str(&s).ok()),
            capability_snapshot: row.get(7)?,
        })
    })?;
    let mut members = Vec::new();
    for r in rows {
        members.push(r?);
    }
    Ok(members)
}

/// Get role permissions for a board (from role_permissions table).
pub fn get_role_permissions(
    conn: &Connection,
    _board_id: &str,
) -> AppResult<Vec<(String, Vec<String>)>> {
    let mut stmt = conn.prepare("SELECT role, verb FROM role_permissions")?;
    let rows: Vec<_> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (role, verb) in rows {
        map.entry(role).or_default().push(verb);
    }
    Ok(map.into_iter().collect())
}

/// Record heartbeat by updating task updated_at.

/// Verify a board token. Returns member email on success.
pub fn verify_member_token(
    conn: &Connection,
    board_id: &str,
    token: &str,
    member_email: &str,
) -> AppResult<Option<String>> {
    // Dual-credential auth: token AND member email must both match the
    // same board_members row — a token alone proves nothing.
    let mut stmt = conn.prepare(
        "SELECT email FROM board_members WHERE board_id = ?1 AND board_token = ?2 AND email = ?3",
    )?;
    let result = stmt
        .query_row(params![board_id, token, member_email], |row| row.get(0))
        .optional()?;
    Ok(result)
}

pub fn update_task_updated_at(conn: &Connection, task_id: &str) -> AppResult<()> {
    conn.execute(
        "UPDATE tasks SET updated_at = datetime('now') WHERE id = ?1",
        params![task_id],
    )?;
    Ok(())
}

// ── Task CRUD ─────────────────────────────────────────────────────────

pub fn create_task(conn: &Connection, task: &Task) -> AppResult<()> {
    conn.execute(
        "INSERT INTO tasks (id, short_id, board_id, title, body, status, assignee,
         reviewer, parent_ids, tags, summary, metadata, created_by, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            task.id,
            task.short_id,
            task.board_id,
            task.title,
            task.body,
            task.status.to_string(),
            task.assignee,
            task.reviewer,
            serde_json::to_string(&task.parent_ids).unwrap_or_default(),
            serde_json::to_string(&task.tags).unwrap_or_default(),
            task.summary,
            task.metadata,
            task.created_by,
            task.created_at,
            task.updated_at,
        ],
    )?;
    Ok(())
}

pub fn get_task(conn: &Connection, task_id: &str) -> AppResult<Task> {
    conn.query_row(
        "SELECT id, short_id, board_id, title, body, status, assignee, reviewer,
                parent_ids, tags, summary, metadata, created_by, created_at, updated_at,
                completed_at, cancelled_at, deadline
         FROM tasks WHERE id = ?1",
        params![task_id],
        |row| {
            Ok(Task {
                id: row.get(0)?,
                short_id: row.get(1)?,
                board_id: row.get(2)?,
                title: row.get(3)?,
                body: row.get(4)?,
                status: parse_task_status(&row.get::<_, String>(5)?),
                assignee: row.get(6)?,
                reviewer: row.get(7)?,
                parent_ids: row
                    .get::<_, String>(8)
                    .map(|s| serde_json::from_str(&s).unwrap_or_default())
                    .unwrap_or_default(),
                tags: row
                    .get::<_, String>(9)
                    .map(|s| serde_json::from_str(&s).unwrap_or_default())
                    .unwrap_or_default(),
                summary: row.get(10)?,
                metadata: row.get(11)?,
                created_by: row.get(12)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                completed_at: row.get(15)?,
                cancelled_at: row.get(16)?,
                deadline: row.get(17)?,
            })
        },
    )
    .map_err(Into::into)
}

pub fn list_tasks(
    conn: &Connection,
    board_id: &str,
    status_filter: Option<&str>,
    assignee_filter: Option<&str>,
) -> AppResult<Vec<Task>> {
    let mut sql = "SELECT id, short_id, board_id, title, body, status, assignee, reviewer,
                   parent_ids, tags, summary, metadata, created_by, created_at, updated_at,
                   completed_at, cancelled_at, deadline
                   FROM tasks WHERE board_id = ?1"
        .to_string();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> =
        vec![Box::new(board_id.to_string())];
    let mut param_idx = 2;

    if let Some(s) = status_filter {
        sql.push_str(&format!(" AND status = ?{}", param_idx));
        param_values.push(Box::new(s.to_string()));
        param_idx += 1;
    }
    if let Some(a) = assignee_filter {
        sql.push_str(&format!(" AND assignee = ?{}", param_idx));
        param_values.push(Box::new(a.to_string()));
    }

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(Task {
            id: row.get(0)?,
            short_id: row.get(1)?,
            board_id: row.get(2)?,
            title: row.get(3)?,
            body: row.get(4)?,
            status: parse_task_status(&row.get::<_, String>(5)?),
            assignee: row.get(6)?,
            reviewer: row.get(7)?,
            parent_ids: row
                .get::<_, String>(8)
                .map(|s| serde_json::from_str(&s).unwrap_or_default())
                .unwrap_or_default(),
            tags: row
                .get::<_, String>(9)
                .map(|s| serde_json::from_str(&s).unwrap_or_default())
                .unwrap_or_default(),
            summary: row.get(10)?,
            metadata: row.get(11)?,
            created_by: row.get(12)?,
            created_at: row.get(13)?,
            updated_at: row.get(14)?,
            completed_at: row.get(15)?,
            cancelled_at: row.get(16)?,
            deadline: row.get(17)?,
        })
    })?;
    let mut tasks = Vec::new();
    for r in rows {
        tasks.push(r?);
    }
    Ok(tasks)
}

pub fn update_task(conn: &Connection, task: &Task) -> AppResult<()> {
    conn.execute(
        "UPDATE tasks SET status=?1, title=?2, body=?3, assignee=?4, reviewer=?5,
         parent_ids=?6, tags=?7, summary=?8, metadata=?9, updated_at=?10,
         completed_at=?11, cancelled_at=?12, deadline=?13
         WHERE id=?14",
        params![
            task.status.to_string(),
            task.title,
            task.body,
            task.assignee,
            task.reviewer,
            serde_json::to_string(&task.parent_ids).unwrap_or_default(),
            serde_json::to_string(&task.tags).unwrap_or_default(),
            task.summary,
            task.metadata,
            task.updated_at,
            task.completed_at,
            task.cancelled_at,
            task.deadline,
            task.id,
        ],
    )?;
    Ok(())
}

pub fn touch_task(conn: &Connection, task_id: &str) -> AppResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE tasks SET updated_at=?1 WHERE id=?2",
        params![now, task_id],
    )?;
    Ok(())
}

// ── Event ─────────────────────────────────────────────────────────────

pub fn insert_event(conn: &Connection, event: &TaskEvent) -> AppResult<()> {
    conn.execute(
        "INSERT INTO task_events (task_id, event_type, actor, payload, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event.task_id,
            event.event_type,
            event.actor,
            event
                .payload
                .as_ref()
                .map(|p| serde_json::to_string(p).unwrap_or_default()),
            event.created_at,
        ],
    )?;
    Ok(())
}

// ── Pipeline integrity ────────────────────────────────────────────────

/// Verify that all intermediate tasks in the plan have been completed
/// and that the output task is done.
pub fn verify_pipeline_integrity(conn: &Connection, board_id: &str) -> AppResult<Vec<String>> {
    let mut issues = Vec::new();

    // Check for any tasks that are not in done/cancelled status
    let mut stmt = conn.prepare(
        "SELECT short_id, status FROM tasks
         WHERE board_id = ?1 AND status NOT IN ('done', 'cancelled', 'triage', 'archived')",
    )?;
    let rows = stmt.query_map(params![board_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for r in rows {
        let (short_id, status) = r?;
        issues.push(format!("{} status={}", short_id, status));
    }

    Ok(issues)
}

// ── Helpers ───────────────────────────────────────────────────────────

fn parse_task_status(s: &str) -> TaskStatus {
    match s {
        "ready" => TaskStatus::Ready,
        "running" => TaskStatus::Running,
        "reviewing" => TaskStatus::Reviewing,
        "done" => TaskStatus::Done,
        "blocked" => TaskStatus::Blocked,
        "cancelled" => TaskStatus::Cancelled,
        _ => TaskStatus::Todo,
    }
}

/// Generate a sequential short_id (T1, T2, T3...).
/// Atomic per-board counter (task_seq): concurrent creates and deleted
/// tasks can never collide or reuse ids (L5 — COUNT(*)+1 raced and
/// reused ids after deletions).
pub fn next_short_id(conn: &Connection, board_id: &str) -> AppResult<String> {
    let next: i64 = conn.query_row(
        "INSERT INTO task_seq (board_id, next_val) VALUES (?1, 1)
         ON CONFLICT(board_id) DO UPDATE SET next_val = next_val + 1
         RETURNING next_val",
        params![board_id],
        |row| row.get(0),
    )?;
    Ok(format!("T{}", next))
}

/// Generate a unique task ID: t_{board_id}_{short_id}
pub fn make_task_id(board_id: &str, short_id: &str) -> String {
    format!("t_{}_{}", short_id, &board_id[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::models::*;

    fn setup_db() -> (Connection, String) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        init_schema(&conn).unwrap();
        let board_id = "a3f8c21b9d4e73b2f0c1";
        let board = Board {
            id: board_id.to_string(),
            short_id: "pgmig001".to_string(),
            board_email: "pgmig001.a2a@test.io".to_string(),
            goal: None,
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            created_at: "2026-07-01T00:00:00Z".to_string(),
            completed_at: None,
        };
        create_board(&conn, &board).unwrap();

        // Create default members so FK constraints on tasks pass
        for (email, role) in &[
            ("orch@t.io", "orchestrator"),
            ("veri@t.io", "verifier"),
            ("worker@t.io", "worker"),
            ("owner@t.io", "owner"),
            ("alice@t.io", "worker"),
            ("bob@t.io", "worker"),
        ] {
            let m = make_member(board_id, email, role);
            add_member(&conn, &m).unwrap();
        }

        (conn, board_id.to_string())
    }

    fn make_member(board_id: &str, email: &str, role: &str) -> Member {
        Member {
            email: email.to_string(),
            role: role.to_string(),
            display_name: email.to_string(),
            board_id: board_id.to_string(),
            board_token: Some("test-token".into()),
            joined_at: None,
            domains: None,
            capability_snapshot: None,
        }
    }

    fn make_task(board_id: &str, short_id: &str, assignee: &str) -> Task {
        Task {
            id: make_task_id(board_id, short_id),
            short_id: short_id.to_string(),
            board_id: board_id.to_string(),
            title: format!("Task {}", short_id),
            body: "test body".to_string(),
            status: TaskStatus::Ready,
            assignee: assignee.to_string(),
            reviewer: None,
            parent_ids: vec![],
            tags: vec![],
            summary: "".to_string(),
            metadata: None,
            created_by: assignee.to_string(),
            created_at: "2026-07-01T00:00:00Z".to_string(),
            updated_at: "2026-07-01T00:00:00Z".to_string(),
            completed_at: None,
            cancelled_at: None,
            deadline: None,
        }
    }

    #[test]
    fn test_make_task_id() {
        let tid = make_task_id("a3f8c21b9d4e73b2f0c1", "T1");
        assert_eq!(tid, "t_T1_a3f8c21b");
    }

    #[test]
    fn test_create_and_get_board() {
        let (conn, board_id) = setup_db();
        let board = get_board(&conn, &board_id).unwrap();
        assert_eq!(board.short_id, "pgmig001");
        assert_eq!(board.status, BoardStatus::Active);
    }

    #[test]
    fn test_create_board_rejects_duplicate() {
        // A2: same derived board_id must not silently overwrite the board.
        let (conn, board_id) = setup_db();
        let dup = Board {
            id: board_id.clone(),
            short_id: "pgmig001".to_string(),
            board_email: "pgmig001.a2a@test.io".to_string(),
            goal: Some("duplicate".to_string()),
            status: BoardStatus::Active,
            output_task_id: None,
            plan_version: None,
            plan_text: None,
            plan_confirmed_at: None,
            criteria_version: None,
            criteria_text: None,
            criteria_confirmed_at: None,
            created_at: "2026-07-02T00:00:00Z".to_string(),
            completed_at: None,
        };
        assert!(
            create_board(&conn, &dup).is_err(),
            "duplicate create_board must be rejected"
        );
        // Original board untouched
        let board = get_board(&conn, &board_id).unwrap();
        assert_eq!(board.short_id, "pgmig001");
        assert_eq!(board.created_at, "2026-07-01T00:00:00Z", "original board must survive");
    }

    #[test]
    fn test_add_and_get_member() {
        let (conn, board_id) = setup_db();
        let member = make_member(&board_id, "alice@test.io", "orchestrator");
        add_member(&conn, &member).unwrap();
        let found = get_member(&conn, &board_id, "alice@test.io").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().role, "orchestrator");
    }

    #[test]
    fn test_get_member_not_found() {
        let (conn, board_id) = setup_db();
        let found = get_member(&conn, &board_id, "nobody@test.io").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_list_members() {
        let (conn, board_id) = setup_db();
        add_member(&conn, &make_member(&board_id, "alice@t.io", "orchestrator")).unwrap();
        add_member(&conn, &make_member(&board_id, "bob@t.io", "worker")).unwrap();
        let members = list_members(&conn, &board_id).unwrap();
        assert_eq!(members.len(), 6, "setup_db creates 6 members; add_member with OR REPLACE doesn't add new ones");
    }

    #[test]
    fn test_create_and_get_task() {
        let (conn, board_id) = setup_db();
        let task = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &task).unwrap();
        let found = get_task(&conn, &task.id).unwrap();
        assert_eq!(found.short_id, "T1");
        assert_eq!(found.status, TaskStatus::Ready);
    }

    #[test]
    fn test_update_task_status() {
        let (conn, board_id) = setup_db();
        let mut task = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &task).unwrap();
        task.status = TaskStatus::Running;
        task.updated_at = "2026-07-01T01:00:00Z".to_string();
        update_task(&conn, &task).unwrap();
        let found = get_task(&conn, &task.id).unwrap();
        assert_eq!(found.status, TaskStatus::Running);
    }

    #[test]
    fn test_touch_task_updates_time() {
        let (conn, board_id) = setup_db();
        let task = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &task).unwrap();
        touch_task(&conn, &task.id).unwrap();
        let found = get_task(&conn, &task.id).unwrap();
        assert_ne!(found.updated_at, task.updated_at);
    }

    #[test]
    fn test_list_tasks_by_status() {
        let (conn, board_id) = setup_db();
        let mut t1 = make_task(&board_id, "T1", "alice@t.io");
        t1.status = TaskStatus::Done;
        create_task(&conn, &t1).unwrap();
        let mut t2 = make_task(&board_id, "T2", "bob@t.io");
        t2.status = TaskStatus::Running;
        create_task(&conn, &t2).unwrap();
        let done_tasks = list_tasks(&conn, &board_id, Some("done"), None).unwrap();
        assert_eq!(done_tasks.len(), 1);
        assert_eq!(done_tasks[0].short_id, "T1");
    }

    #[test]
    fn test_list_tasks_by_assignee() {
        let (conn, board_id) = setup_db();
        let t1 = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &t1).unwrap();
        let t2 = make_task(&board_id, "T2", "bob@t.io");
        create_task(&conn, &t2).unwrap();
        let alice_tasks = list_tasks(&conn, &board_id, None, Some("alice@t.io")).unwrap();
        assert_eq!(alice_tasks.len(), 1);
    }

    #[test]
    fn test_insert_event() {
        let (conn, board_id) = setup_db();
        let task = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &task).unwrap();
        let event = TaskEvent {
            id: 0,
            task_id: task.id.clone(),
            event_type: "completed".to_string(),
            actor: "alice@t.io".to_string(),
            payload: None,
            created_at: "2026-07-01T00:00:00Z".to_string(),
        };
        insert_event(&conn, &event).unwrap();
    }

    #[test]
    fn test_short_id_exists() {
        let (conn, _) = setup_db();
        assert!(short_id_exists(&conn, "pgmig001").unwrap());
        assert!(!short_id_exists(&conn, "nonexist").unwrap());
    }

    #[test]
    fn test_verify_pipeline_integrity_clean() {
        let (conn, board_id) = setup_db();
        let mut t1 = make_task(&board_id, "T1", "alice@t.io");
        t1.status = TaskStatus::Done;
        t1.completed_at = Some("2026-07-01T00:00:00Z".to_string());
        create_task(&conn, &t1).unwrap();
        let issues = verify_pipeline_integrity(&conn, &board_id).unwrap();
        assert!(issues.is_empty(), "pipeline should be clean when all tasks done");
    }

    #[test]
    fn test_verify_pipeline_integrity_pending() {
        let (conn, board_id) = setup_db();
        let t1 = make_task(&board_id, "T1", "alice@t.io"); // status=Ready
        create_task(&conn, &t1).unwrap();
        let issues = verify_pipeline_integrity(&conn, &board_id).unwrap();
        assert!(!issues.is_empty(), "pipeline should report issues when tasks are pending");
    }

    #[test]
    fn test_next_short_id() {
        let (conn, board_id) = setup_db();
        let id1 = next_short_id(&conn, &board_id).unwrap();
        assert_eq!(id1, "T1");
        let t1 = make_task(&board_id, "T1", "alice@t.io");
        create_task(&conn, &t1).unwrap();
        let id2 = next_short_id(&conn, &board_id).unwrap();
        assert_eq!(id2, "T2");
    }

    // ── R2: role_permissions open-mode closure ─────────────────────
    #[test]
    fn test_check_role_permission_unknown_role_denied() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // Unknown role on an unseeded table used to be open (allow-all).
        assert!(!check_role_permission(&conn, "admin", "list").unwrap());
        assert!(!check_role_permission(&conn, "root", "arbitrate").unwrap());
    }

    #[test]
    fn test_check_role_permission_known_role_seeds_and_allows() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // Known role on an empty (legacy) table: seeded idempotently, then
        // its default verbs apply; non-default verbs still denied.
        assert!(check_role_permission(&conn, "worker", "list").unwrap());
        assert!(check_role_permission(&conn, "worker", "heartbeat").unwrap());
        assert!(!check_role_permission(&conn, "worker", "arbitrate").unwrap());
        assert!(check_role_permission(&conn, "orchestrator", "init").unwrap());
        assert!(!check_role_permission(&conn, "orchestrator", "complete").unwrap());
    }
}
