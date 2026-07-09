//! Board archiver — 7 天自动归档。

use crate::board::db;
use chrono::Utc;
use std::thread;
use std::time::Duration;

pub fn archive_loop(storage_path: &str) {
    let path = std::path::PathBuf::from(storage_path).join("a2a_board");
    loop {
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                let board_id = entry.file_name().to_string_lossy().to_string();
                if let Ok(conn) = db::open_board_db(storage_path, &board_id) {
                    if let Ok(board) = db::get_board(&conn, &board_id) {
                        if let Some(ref completed_at) = board.completed_at {
                            if let Ok(completed) = chrono::DateTime::parse_from_rfc3339(completed_at) {
                                let age = Utc::now().signed_duration_since(completed);
                                if age.num_days() >= 7 {
                                    if let Ok(mut b) = db::get_board(&conn, &board_id) {
                                        b.status = crate::board::models::BoardStatus::Archived;
                                        let _ = db::update_board(&conn, &b);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(3600));
    }
}
