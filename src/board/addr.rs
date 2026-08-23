//! Shared A2A board-address identification and resolution.
//!
//! Both entry points — SMTP inbound (RCPT) and the HTTP send API — must
//! treat board addresses (`{short}[.{sys}].a2a@{domain}`) identically:
//!
//!   - form detection ([is_board_address])
//!   - substantive existence check against the [BoardRegistry]
//!   - owning-system resolution (registry value, orchestrator fallback)
//!   - stranger-command detection ([is_stranger_command])
//!
//! Keeping this in one module prevents the two entry points from drifting:
//! the SMTP handler and the send API each call these functions instead of
//! re-implementing the rules.

use std::path::Path;

use rusqlite::OptionalExtension;

use super::models::parse_board_email;
use crate::core::factory::EnvFactory;

/// Universal stranger commands: a sender not on the recipient's "from"
/// whitelist may still send these subjects (SMTP defers the rejection to
/// the DATA phase; the send API bypasses the inbound whitelist filter).
pub const STRANGER_COMMANDS: &[&str] = &["[WHOAMI]"];

/// Form-level board-address predicate — the single authority for "is this
/// a board address?". Mirrors the SMTP RCPT entry check: any address whose
/// local part ends in `.a2a` is a board address and must never be run
/// through persona stripping (which would split `{short}.a2a` on the first
/// dot and destroy the address). Case-insensitive — email addresses are
/// case-insensitive.
pub fn is_board_address(addr: &str) -> bool {
    addr.to_ascii_lowercase().contains(".a2a@")
}

/// `true` when the subject starts with one of the universal stranger
/// commands ([STRANGER_COMMANDS]).
pub fn is_stranger_command(subject: &str) -> bool {
    let upper = subject.to_uppercase();
    STRANGER_COMMANDS.iter().any(|cmd| upper.starts_with(cmd))
}

/// Failure class for [resolve_board_recipient].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardAddrError {
    /// Not a valid `{short}[.{sys}].a2a@{domain}` form.
    Invalid,
    /// Valid form, but this gateway does not have the board.
    NotFound,
    /// Board exists, but no owning system can be resolved.
    NoSystem,
}

impl std::fmt::Display for BoardAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoardAddrError::Invalid => write!(f, "invalid board address"),
            BoardAddrError::NotFound => write!(f, "board does not exist on this gateway"),
            BoardAddrError::NoSystem => write!(f, "board owning system not resolvable"),
        }
    }
}

/// A fully resolved board recipient.
#[derive(Debug, Clone)]
pub struct BoardRecipient {
    pub short_id: String,
    pub board_id: String,
    pub domain: String,
    /// Owning system (registry value, or — for legacy boards created
    /// before the `boards.system_id` column existed — the orchestrator
    /// member's registered system).
    pub system_id: String,
}

/// Parse + substantive registry check + owning-system resolution.
///
/// Shared by the SMTP RCPT handler and the HTTP send API so both entry
/// points accept/reject board addresses identically. The registry is the
/// only existence source — a board is deliverable only if this gateway
/// actually has it (creation happens exclusively via the Owner `[A2A] new`
/// protocol, which inserts into the registry).
pub async fn resolve_board_recipient(
    env: &EnvFactory,
    storage_path: &Path,
    board_email: &str,
) -> Result<BoardRecipient, BoardAddrError> {
    let (short_id, board_id, domain) =
        parse_board_email(board_email).ok_or(BoardAddrError::Invalid)?;

    let entry = env.board_registry().lookup(board_email).ok_or_else(|| {
        tracing::warn!(
            operation = "board_recipient_not_found",
            board_id = %board_id,
            recipient = %board_email,
            "A2A board address not on this gateway — rejected (no auto-create)"
        );
        BoardAddrError::NotFound
    })?;

    // Owning system, resolved from best to worst source:
    //   1. registry system_id (boards.system_id, set at creation)
    //   2. orchestrator member's registered system (legacy boards,
    //      created before the system_id column existed)
    let mut system_id = entry.system_id;
    if system_id.as_deref().map(str::is_empty).unwrap_or(true) {
        let db_path = storage_path
            .join("a2a_board")
            .join(format!("{board_id}.db"));
        // Extract the orchestrator email and DROP the connection before any
        // await — rusqlite::Connection is !Send and must not be held across
        // an await point (it would make this future !Send).
        let orch_email = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()
        .and_then(|conn| {
            conn.query_row(
                "SELECT email FROM board_members WHERE board_id = ?1 AND role = 'orchestrator' LIMIT 1",
                rusqlite::params![&board_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
        });
        if let Some(orch_email) = orch_email {
            system_id = env
                .lookup_domain_addr(&orch_email)
                .await
                .ok()
                .flatten()
                .map(|r| r.system_id);
        }
    }
    let system_id = match system_id {
        Some(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!(
                operation = "board_recipient_no_system",
                board_id = %board_id,
                "A2A board has no resolvable owning system"
            );
            return Err(BoardAddrError::NoSystem);
        }
    };

    Ok(BoardRecipient {
        short_id,
        board_id,
        domain,
        system_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::registry::BoardRegistry;

    #[test]
    fn is_board_address_forms() {
        assert!(is_board_address("abc.a2a@example.com"));
        assert!(is_board_address("abc.sysname.a2a@example.com"));
        assert!(is_board_address("ABC.A2A@EXAMPLE.COM"));
        assert!(is_board_address("a.a2a@b.c")); // multi-label domain still matches the form
        assert!(!is_board_address("a2a@example.com"));
        assert!(!is_board_address("abc.a2a"));
        assert!(!is_board_address("user@sub.a2a.example.com"));
    }

    #[test]
    fn is_stranger_command_prefix() {
        assert!(is_stranger_command("[WHOAMI]"));
        assert!(is_stranger_command("[whoami] who am i"));
        assert!(!is_stranger_command(" [WHOAMI] x")); // prefix only — leading space breaks it
        assert!(!is_stranger_command("[A2A] list"));
        assert!(!is_stranger_command(""));
    }

    /// Sync core of the resolution, split for tests that don't need an
    /// `EnvFactory`: form + registry + system-id selection.
    fn resolve_sync(
        registry: &BoardRegistry,
        board_email: &str,
    ) -> Result<(String, String, String, Option<String>), BoardAddrError> {
        let (short_id, board_id, domain) =
            parse_board_email(board_email).ok_or(BoardAddrError::Invalid)?;
        let entry = registry.lookup(board_email).ok_or(BoardAddrError::NotFound)?;
        Ok((
            short_id,
            board_id,
            domain,
            entry.system_id,
        ))
    }

    #[test]
    fn resolve_invalid_form() {
        let reg = BoardRegistry::new();
        assert_eq!(
            resolve_sync(&reg, "not-a-board@example.com").err(),
            Some(BoardAddrError::Invalid)
        );
        assert_eq!(
            resolve_sync(&reg, "a2a@example.com").err(),
            Some(BoardAddrError::Invalid)
        );
    }

    #[test]
    fn resolve_not_found() {
        let reg = BoardRegistry::new();
        reg.insert("other.a2a@example.com", "b2", Some("sys-2".into()));
        assert_eq!(
            resolve_sync(&reg, "missing.a2a@example.com").err(),
            Some(BoardAddrError::NotFound)
        );
    }

    #[test]
    fn resolve_ok_with_registry_system() {
        let reg = BoardRegistry::new();
        reg.insert("abc.a2a@example.com", "b1", Some("sys-1".into()));
        let (short, board_id, domain, sys) = resolve_sync(&reg, "abc.a2a@example.com").unwrap();
        assert_eq!(short, "abc");
        // board_id is derived from the address (deterministic hash), not the
        // registry-stored value.
        assert_eq!(board_id, crate::board::models::derive_board_id("abc.a2a@example.com"));
        assert_eq!(domain, "example.com");
        assert_eq!(sys.as_deref(), Some("sys-1"));
    }
}
