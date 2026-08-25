//! Board address registry — in-memory cache of all board addresses known to
//! this gateway instance.
//!
//! Board addresses (`{short}[.{sys}].a2a@{domain}`) are NOT registered in
//! `system_domains` (the `a2a` local part is reserved at the API layer), so
//! RCPT cannot resolve them through the regular domain lookup. Instead the
//! SMTP receiver asks this registry: **substantive check** — the address is
//! accepted only if this gateway actually has that board on disk; anything
//! else is bounced with 550 (address does not exist). The only creation
//! entry point is the Owner `[A2A] new` protocol, which inserts into the
//! registry after creating the board.

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use super::db;

/// One registered board address.
#[derive(Debug, Clone)]
pub struct BoardEntry {
    pub board_id: String,
    /// Owning system (None for legacy boards created before the column
    /// existed — RCPT falls back to resolving it from the board DB).
    pub system_id: Option<String>,
}

/// In-memory cache of board addresses.
pub struct BoardRegistry {
    /// board_email (lowercase) -> entry
    entries: RwLock<HashMap<String, BoardEntry>>,
}

impl BoardRegistry {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Load all boards from `storage_path/a2a_board/*.db` into the cache.
    /// Called once at startup (and available for tests).
    pub fn load(&self, storage_path: &str) -> usize {
        let board_dir = Path::new(storage_path).join("a2a_board");
        let refs = match db::list_boards(storage_path) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    operation = "board_registry_load_failed",
                    dir = %board_dir.display(),
                    error = %e,
                    "Board registry load failed — board addresses will be rejected until restart"
                );
                return 0;
            }
        };
        let mut map = self.entries.write().unwrap();
        let mut loaded = 0usize;
        for r in refs {
            map.insert(
                r.board_email.to_lowercase(),
                BoardEntry {
                    board_id: r.id,
                    system_id: r.system_id.filter(|s| !s.is_empty()),
                },
            );
            loaded += 1;
        }
        tracing::info!(
            operation = "board_registry_loaded",
            boards = loaded,
            "Board registry loaded from disk"
        );
        loaded
    }

    /// Substantive check: does this gateway have a board at `board_email`?
    /// Case-insensitive (SMTP addresses are case-insensitive).
    pub fn lookup(&self, board_email: &str) -> Option<BoardEntry> {
        self.entries.read().unwrap().get(board_email.to_lowercase().as_str()).cloned()
    }

    /// Register a newly created board (Owner `[A2A] new` path).
    pub fn insert(&self, board_email: &str, board_id: &str, system_id: Option<String>) {
        let mut map = self.entries.write().unwrap();
        map.insert(
            board_email.to_lowercase(),
            BoardEntry {
                board_id: board_id.to_string(),
                system_id: system_id.filter(|s| !s.is_empty()),
            },
        );
    }

    /// Drop a board address (advanced: system released / board cleared).
    pub fn remove(&self, board_email: &str) {
        let mut map = self.entries.write().unwrap();
        map.remove(board_email.to_lowercase().as_str());
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

impl Default for BoardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BoardRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoardRegistry")
            .field("boards", &self.entries.read().unwrap().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("boardreg-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    #[test]
    fn test_lookup_miss_unknown_board() {
        let reg = BoardRegistry::new();
        assert!(reg.lookup("nope.a2a@example.com").is_none());
    }

    #[test]
    fn test_insert_lookup_case_insensitive() {
        let reg = BoardRegistry::new();
        reg.insert("abc.a2a@example.com", "b1", Some("sys-1".into()));
        let e = reg.lookup("ABC.a2a@EXAMPLE.com").unwrap();
        assert_eq!(e.board_id, "b1");
        assert_eq!(e.system_id.as_deref(), Some("sys-1"));
    }

    #[test]
    fn test_insert_empty_system_id_becomes_none() {
        let reg = BoardRegistry::new();
        reg.insert("abc.a2a@example.com", "b1", Some("".into()));
        assert!(reg.lookup("abc.a2a@example.com").unwrap().system_id.is_none());
    }

    #[test]
    fn test_remove() {
        let reg = BoardRegistry::new();
        reg.insert("abc.a2a@example.com", "b1", None);
        assert_eq!(reg.len(), 1);
        reg.remove("ABC.a2a@example.com");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_load_from_disk() {
        let dir = temp_dir("load");
        let board_dir = Path::new(&dir).join("a2a_board");
        std::fs::create_dir_all(&board_dir).unwrap();
        // One board DB
        let board_email = "loadboard.a2a@example.com";
        let board_id = crate::board::models::derive_board_id(board_email);
        let path = board_dir.join(format!("{board_id}.db"));
        let conn = rusqlite::Connection::open(&path).unwrap();
        db::init_schema(&conn).unwrap();
        db::create_board(
            &conn,
            &crate::board::models::Board {
                id: board_id.clone(),
                short_id: "loadboard".into(),
                board_email: board_email.into(),
                goal: None,
                status: crate::board::models::BoardStatus::Active,
                output_task_id: None,
                plan_version: None,
                plan_text: None,
                plan_confirmed_at: None,
                criteria_version: None,
                criteria_text: None,
                criteria_confirmed_at: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                completed_at: None,
                system_id: Some("sys-load".into()),
            },
        )
        .unwrap();
        drop(conn);
        // One stray file (not a board DB) — load must skip it gracefully
        std::fs::write(board_dir.join("junk.txt"), b"not a db").unwrap();

        let reg = BoardRegistry::new();
        let n = reg.load(&dir);
        assert_eq!(n, 1, "exactly the real board should load (stray file skipped)");
        let e = reg.lookup(board_email).unwrap();
        assert_eq!(e.board_id, board_id);
        assert_eq!(e.system_id.as_deref(), Some("sys-load"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
