//! Board lifecycle management — periodic scans for stale heartbeats,
//! stale tasks, and completed boards.
//!
//! Called from the scheduler batch loop (`core/scheduler/batch.rs`) on
//! configurable intervals. Each board has its own independent SQLite file
//! under `<storage_path>/a2a_board/<board_id>/`.

use std::path::PathBuf;

use crate::board::db;
use crate::board::models::*;
use crate::core::config::Config;
use crate::core::errors::AppResult;

// ── Heartbeat stale scan (default: every 15 min) ──────────────────

/// Mark `running` tasks whose heartbeat hasn't updated within the threshold as `blocked`.
pub async fn scan_stale_heartbeats(storage_path: &str, threshold_secs: u64) {
    let boards = match list_active_boards(storage_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "[a2a_board] sweeper: failed to list boards for heartbeat scan");
            return;
        }
    };
    if boards.is_empty() {
        return;
    }
    let now = chrono::Utc::now();
    for board_id in boards {
        let conn = match db::open_board_db(storage_path, &board_id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let tasks = match db::list_tasks(&conn, &board_id, Some("running"), None) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(board = %board_id, error = %e, "[a2a_board] sweeper: failed to list running tasks");
                continue;
            }
        };
        for task in tasks {
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&task.updated_at) {
                let elapsed = (now - parsed.with_timezone(&chrono::Utc)).num_seconds();
                if elapsed > threshold_secs as i64 && elapsed >= 0 {
                    let mut t = task;
                    t.status = TaskStatus::Blocked;
                    let _ = db::update_task(&conn, &t);
                    tracing::warn!(
                        "[a2a_board] sweeper: blocking stale task {} in board {} ({}s silent)",
                        t.short_id,
                        board_id,
                        elapsed
                    );
                }
            }
        }
    }
}

// ── Stale task scan (default: every 6 hours) ──────────────────────

/// Warn on `reviewing` tasks that haven't been updated within the threshold.
pub async fn scan_stale_tasks(storage_path: &str, threshold_secs: u64) {
    let boards = match list_active_boards(storage_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "[a2a_board] sweeper: failed to list boards for stale task scan");
            return;
        }
    };
    if boards.is_empty() {
        return;
    }
    let now = chrono::Utc::now();
    for board_id in boards {
        let conn = match db::open_board_db(storage_path, &board_id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let tasks = match db::list_tasks(&conn, &board_id, Some("reviewing"), None) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(board = %board_id, error = %e, "[a2a_board] sweeper: failed to list reviewing tasks");
                continue;
            }
        };
        for task in tasks {
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&task.updated_at) {
                let elapsed = (now - parsed.with_timezone(&chrono::Utc)).num_seconds();
                if elapsed > threshold_secs as i64 && elapsed >= 0 {
                    tracing::warn!(
                        "[a2a_board] sweeper: stale review on task {} in board {} ({}s)",
                        task.short_id,
                        board_id,
                        elapsed
                    );
                }
            }
        }
    }
}

// ── Completed board archive scan (default: daily) ──────────────────

/// Archive boards that are `Completed` and older than the threshold.
pub async fn scan_completed_boards(storage_path: &str, threshold_secs: u64) {
    let boards = match list_active_boards(storage_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "[a2a_board] sweeper: failed to list boards for archive scan");
            return;
        }
    };
    if boards.is_empty() {
        return;
    }
    let now = chrono::Utc::now();
    for board_id in boards {
        let conn = match db::open_board_db(storage_path, &board_id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let board = match db::get_board(&conn, &board_id) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(board = %board_id, error = %e, "[a2a_board] sweeper: failed to get board");
                continue;
            }
        };
        if board.status == BoardStatus::Completed {
            if let Some(ref completed) = board.completed_at {
                if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(completed) {
                    let elapsed = (now - parsed.with_timezone(&chrono::Utc)).num_seconds();
                    if elapsed > threshold_secs as i64 {
                        tracing::info!(
                            "[a2a_board] sweeper: archiving completed board {} ({}s since completion)",
                            board.short_id, elapsed
                        );
                        if let Err(e) = db::archive_board(&conn, &board_id) {
                            tracing::warn!(board = %board_id, error = %e, "[a2a_board] sweeper: failed to archive board");
                        }
                    }
                }
            }
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// List active board IDs from the filesystem (`<storage_path>/a2a_board/`).
pub fn list_active_boards(storage_path: &str) -> AppResult<Vec<String>> {
    let dir = PathBuf::from(storage_path).join("a2a_board");
    let mut ids = Vec::new();
    if !dir.exists() {
        return Ok(ids);
    }
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                if name != "_archived" {
                    ids.push(name.to_string());
                }
            }
        }
    }
    Ok(ids)
}

// ── Public flow entry (called from scheduler) ──────────────────────

/// Check whether each scan should run based on elapsed time since last execution.
/// Spawns async tasks on separate tokio workers so scans don't block the scheduler batch loop.
pub fn board_sweeper_flow(config: &Config) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // ── Heartbeat stale scan ──
    static LAST_HEARTBEAT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let last_hb = LAST_HEARTBEAT.load(std::sync::atomic::Ordering::Relaxed);
    let hb_interval = config.board.sweeper_interval_seconds;
    if now - last_hb >= hb_interval {
        LAST_HEARTBEAT.store(now, std::sync::atomic::Ordering::Relaxed);
        let storage = config.storage.path.to_str().unwrap_or("").to_string();
        let threshold = config.board.heartbeat_stale_seconds;
        tokio::task::spawn(async move {
            scan_stale_heartbeats(&storage, threshold).await;
        });
    }

    // ── Stale task scan ──
    static LAST_STALE_TASK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let last_stale = LAST_STALE_TASK.load(std::sync::atomic::Ordering::Relaxed);
    // Configurable: use `task_timeout_seconds` as the scan interval (default 259200s = 3days)
    // but cap at a reasonable scan frequency.  Use half of the timeout as the scan interval.
    let stale_interval = config.board.task_timeout_seconds / 2;
    if now - last_stale >= stale_interval {
        LAST_STALE_TASK.store(now, std::sync::atomic::Ordering::Relaxed);
        let storage = config.storage.path.to_str().unwrap_or("").to_string();
        let threshold = config.board.task_timeout_seconds;
        tokio::task::spawn(async move {
            scan_stale_tasks(&storage, threshold).await;
        });
    }

    // ── Completed board archive scan ──
    static LAST_ARCHIVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let last_archive = LAST_ARCHIVE.load(std::sync::atomic::Ordering::Relaxed);
    // Daily by default (86400s), but use archive_retention_days if configured
    let archive_interval = config
        .board
        .archive_retention_days
        .map(|days| (days.max(1)) * 86400)
        .unwrap_or(86400u64);
    if now - last_archive >= archive_interval {
        LAST_ARCHIVE.store(now, std::sync::atomic::Ordering::Relaxed);
        let storage = config.storage.path.to_str().unwrap_or( "").to_string();
        let threshold = config
            .board
            .archive_retention_days
            .map(|days| (days.max(1)) * 86400)
            .unwrap_or(config.board.task_timeout_seconds);
        tokio::task::spawn(async move {
            scan_completed_boards(&storage, threshold).await;
        });
    }
}
