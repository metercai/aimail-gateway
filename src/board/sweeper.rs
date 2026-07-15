//! BoardSweeper — 定时扫描 Board 生命周期，主动补漏。
//!
//! 处理事件流覆盖不到的场景：僵死心跳、任务超时、自动归档。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::board::db;
use crate::board::models::*;
use crate::board::notify::Notifier;
use crate::core::config::Config;
use crate::core::email::factory::EmailFactory;
use crate::core::errors::AppResult;

pub struct BoardSweeper {
    storage_path: String,
    email_factory: Arc<EmailFactory>,
    config: Config,
}

impl BoardSweeper {
    pub fn new(storage_path: &str, email_factory: Arc<EmailFactory>, config: &Config) -> Self {
        Self {
            storage_path: storage_path.to_string(),
            email_factory,
            config: config.clone(),
        }
    }

    pub async fn run(&self) {
        let interval = self.config.board.sweeper_interval_seconds;
        let mut tick: u64 = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            tick += 1;

            // ── 15-min scan ──
            self.scan_stale_heartbeats().await;

            // ── 6-hour scan ──
            if tick % 24 == 0 {
                self.scan_stale_tasks().await;
            }

            // ── Daily scan ──
            if tick % 96 == 0 {
                self.scan_completed_boards().await;
            }
        }
    }

    async fn scan_stale_heartbeats(&self) {
        let threshold = self.config.board.heartbeat_stale_seconds;
        if let Ok(boards) = self.list_active_boards() {
            for board_id in boards {
                let conn = match db::open_board_db(&self.storage_path, &board_id) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let tasks = db::list_tasks(&conn, &board_id, Some("running"), None).unwrap_or_default();
                let now = chrono::Utc::now();
                for task in tasks {
                    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&task.updated_at) {
                        let elapsed = (now - parsed.with_timezone(&chrono::Utc)).num_seconds();
                        if elapsed > threshold as i64 && elapsed >= 0 {
                            let mut t = task;
                            t.status = TaskStatus::Blocked;
                            let reason = format!("worker silence: last heartbeat at {}", t.updated_at);
                            let _ = db::update_task(&conn, &t);
                            tracing::warn!("[a2a_board] sweeper: blocking stale task {} ({}s silent)", t.short_id, elapsed);
                        }
                    }
                }
            }
        }
    }

    async fn scan_stale_tasks(&self) {
        let threshold = self.config.board.task_timeout_seconds;
        if let Ok(boards) = self.list_active_boards() {
            for board_id in boards {
                let conn = match db::open_board_db(&self.storage_path, &board_id) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                for status in &["reviewing"] {
                    let tasks = db::list_tasks(&conn, &board_id, Some(status), None).unwrap_or_default();
                    let now = chrono::Utc::now();
                    for task in tasks {
                        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&task.updated_at) {
                            let elapsed = (now - parsed.with_timezone(&chrono::Utc)).num_seconds();
                            if elapsed > threshold as i64 && elapsed >= 0 {
                                tracing::warn!("[a2a_board] sweeper: stale review on {} ({}s)", task.short_id, elapsed);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn scan_completed_boards(&self) {
        if let Ok(boards) = self.list_active_boards() {
            for board_id in boards {
                let conn = match db::open_board_db(&self.storage_path, &board_id) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if let Ok(board) = db::get_board(&conn, &board_id) {
                    if board.status == BoardStatus::Completed {
                        if let Some(ref completed) = board.completed_at {
                            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(completed) {
                                let elapsed = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc)).num_seconds();
                                if elapsed > self.config.board.task_timeout_seconds as i64 {
                                    tracing::info!("[a2a_board] sweeper: archiving board {}", board.short_id);
                                    db::archive_board(&conn, &board_id).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn list_active_boards(&self) -> AppResult<Vec<String>> {
        let dir = PathBuf::from(&self.storage_path).join("a2a_board");
        let mut ids = Vec::new();
        if dir.exists() {
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
        }
        Ok(ids)
    }
}
