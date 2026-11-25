//! SQLite storage layer — connection pool, schema, and CRUD operations.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use tracing::debug;

use crate::core::errors::{AppError, AppResult};
use crate::core::whitelist::{is_whitelisted_wildcard, WhitelistCache};

// Global database handle — set once at startup.

// ── Database Pool ──────────────────────────────────────────────────────

/// Cached domain lookups: `domain -> (fetched_at, record)`.
pub type DomainCacheMap = Arc<RwLock<HashMap<String, (Instant, Option<SystemDomainRecord>)>>>;

/// Thread-safe, cloneable database handle backed by an `r2d2_sqlite` connection pool.
#[derive(Clone)]
pub struct Database {
    pool: Pool<SqliteConnectionManager>,
    /// Absolute path of the SQLite file this Database talks to. Used to
    /// derive sibling storage areas (e.g. per-board DBs under a2a_board/).
    db_file: std::path::PathBuf,
    pub whitelist_cache: Arc<WhitelistCache>,
    /// Domain lookup cache.
    pub domain_cache: DomainCacheMap,
}

/// Fail closed when encryption is requested but the binary has no SQLCipher.
///
/// `PRAGMA key` is silently ignored by a plain SQLite build: the database would be
/// written in PLAINTEXT while the operator believes it is encrypted (proven
/// 2026-10-30 on the `bundled` build: header "SQLite format 3", readable with no key).
/// `PRAGMA cipher_version` returns a row only when the SQLCipher codec is compiled in.
fn ensure_cipher_support(conn: &Connection) -> AppResult<()> {
    let ver: Option<String> = conn
        .query_row("PRAGMA cipher_version;", [], |r| r.get(0))
        .ok();
    match ver.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => Ok(()),
        _ => Err(AppError::Config(
            "storage.encryption = true requires a SQLCipher build, but this binary has none \
             (PRAGMA key would be ignored and the database would be stored in PLAINTEXT). \
             Rebuild with the `sqlcipher` feature, or set storage.encryption = false."
                .to_string(),
        )),
    }
}

/// Restrict the database (and its WAL sidecars) to owner read/write.
///
/// The open path already chmods an EXISTING file; a freshly created database kept the
/// umask default (observed 0644 on first start), so apply it once after creation too.
fn lock_down_db_permissions(db_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut targets = vec![db_path.to_path_buf()];
        for suffix in ["-wal", "-shm"] {
            targets.push(std::path::PathBuf::from(format!(
                "{}{}",
                db_path.display(),
                suffix
            )));
        }
        for p in targets {
            if let Ok(meta) = std::fs::metadata(&p) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&p, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = db_path;
}

impl Database {
    pub fn open<P: AsRef<Path>>(
        path: P,
        pool_size: u32,
        encryption_key: Option<&str>,
    ) -> AppResult<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            // Only a directory we create ourselves is safe to lock down to 0700 —
            // an operator-supplied mount may be shared with other services.
            // (cfg-gated: on Windows nothing below reads it, and -D warnings would fire.)
            #[cfg(unix)]
            let existed = parent.exists();
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            if !existed {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        // Set restrictive file permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path_ref.exists() {
                let mut perms = std::fs::metadata(path_ref)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path_ref, perms)?;
            }
        }

        // Write-lock wait applied to *every* pooled connection; mirrors the
        // startup `PRAGMA busy_timeout` below. SQLite's default is 0 (fail
        // immediately with SQLITE_BUSY), which is what made concurrent writes
        // surface as 500 "database is locked".
        const BUSY_TIMEOUT_MS: i64 = 5000;

        let manager = SqliteConnectionManager::file(path_ref);

        // Every pooled connection must carry the same pragmas. r2d2 opens
        // connections lazily and the startup pragmas below (`journal_mode`,
        // `busy_timeout`) only ever ran on the single connection used during
        // init — a pooled connection created later kept SQLite's default
        // `busy_timeout = 0`, so the moment it met a concurrent writer
        // (scheduler first-delivery claim / mark-completed, retry inspection)
        // the write failed immediately with SQLITE_BUSY, surfacing as a 500
        // `{"error":"DB error","detail":"internal error: database is locked"}`
        // on write endpoints. Reproduced deterministically by
        // an e2e renewal scenario (2026-09-21); `WAL` itself
        // is a persistent database property, so only `busy_timeout` needs to be
        // (re)applied per connection.
        let manager = if let Some(key) = encryption_key {
            // Escape single quotes in the key to prevent SQL injection.
            // Key is derived via HMAC-SHA256 (hex-encoded), so quotes are
            // extremely unlikely, but defense-in-depth is appropriate here.
            let safe_key = key.replace('\'', "''");
            let key_owned = safe_key;
            manager.with_init(move |conn| {
                conn.execute_batch(&format!("PRAGMA key = '{}';", key_owned))?;
                conn.execute_batch(&format!("PRAGMA busy_timeout = {};", BUSY_TIMEOUT_MS))?;
                Ok(())
            })
        } else {
            manager.with_init(|conn| {
                conn.execute_batch(&format!("PRAGMA busy_timeout = {};", BUSY_TIMEOUT_MS))?;
                Ok(())
            })
        };

        let pool = r2d2::Pool::builder()
            .max_size(pool_size)
            .build(manager)
            .map_err(|e| AppError::Internal(format!("Failed to create connection pool: {}", e)))?;

        {
            let conn = pool.get().map_err(|e| {
                AppError::Internal(format!("Failed to get connection from pool: {}", e))
            })?;

            // Fail closed before touching the schema: a build without SQLCipher would
            // ignore `PRAGMA key` and store the database in PLAINTEXT.
            if encryption_key.is_some() {
                ensure_cipher_support(&conn)?;
            }

            // Auto-detect unencrypted DB and rekey in-place.
            if let Some(enc_key) = encryption_key {
                if let Err(e) = init_connection(&conn) {
                    if format!("{}", e).contains("file is not a database") {
                        tracing::warn!(
                            "DB appears unencrypted — migrating to encrypted (one-time). \
                             This happens on first restart after admin key provisioning."
                        );
                        drop(conn);
                        drop(pool);
                        migrate_to_encrypted(path_ref, enc_key)?;
                        let manager2 = SqliteConnectionManager::file(path_ref);
                        let key2 = enc_key.to_string();
                        let manager2 = manager2.with_init(move |conn| {
                            conn.execute_batch(&format!("PRAGMA key = '{}';", key2))?;
                            Ok(())
                        });
                        let pool2 = r2d2::Pool::builder()
                            .max_size(pool_size)
                            .build(manager2)
                            .map_err(|e| {
                                AppError::Internal(format!(
                                    "Failed to create connection pool after rekey: {}",
                                    e
                                ))
                            })?;
                        let conn2 = pool2.get().map_err(|e| {
                            AppError::Internal(format!(
                                "Failed to get connection after rekey: {}",
                                e
                            ))
                        })?;
                        init_connection(&conn2)?;
                        lock_down_db_permissions(path_ref);
                        return Ok(Self {
                            pool: pool2,
                            db_file: path_ref.to_path_buf(),
                            whitelist_cache: Arc::new(WhitelistCache::new()),
                            domain_cache: Arc::new(RwLock::new(HashMap::new())),
                        });
                    }
                    return Err(e);
                }
            } else {
                init_connection(&conn)?;
            }
        }

        lock_down_db_permissions(path_ref);
        Ok(Self {
            db_file: path_ref.to_path_buf(),
            pool,
            whitelist_cache: Arc::new(WhitelistCache::new()),
            domain_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn call<F, R>(&self, f: F) -> AppResult<R>
    where
        F: FnOnce(&Connection) -> AppResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| {
                tracing::error!(operation="pool_connection_error", error = %e, "Pool connection error");
                AppError::Internal(format!("Pool error: {}", e))
            })?;
            f(&conn)
        })
        .await
        .map_err(|e| {
            tracing::error!(operation="blocking_task_join_error", error = %e, "Blocking task join error");
            AppError::Internal(format!("Blocking task failed: {}", e))
        })?
    }

    /// Execute a closure inside a SQLite transaction.
    /// Automatically commits on success, rolls back on error.
    pub async fn call_tx<F, R>(&self, f: F) -> AppResult<R>
    where
        F: FnOnce(&Transaction<'_>) -> AppResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| {
                tracing::error!(operation="pool_connection_error", error = %e, "Pool connection error");
                AppError::Internal(format!("Pool error: {}", e))
            })?;
            // BEGIN IMMEDIATE: every `call_tx` body is a read-then-write
            // transaction (see the address-activation path). With the default
            // DEFERRED behaviour the first SELECT pins a WAL snapshot; if any
            // other connection commits before this tx writes, SQLite refuses the
            // write with SQLITE_BUSY ("database is locked") — a stale-snapshot
            // condition `busy_timeout` cannot wait out, since only replaying the
            // transaction can succeed. Acquiring the write lock up front makes
            // the per-connection busy_timeout (5s) actually apply and removes
            // the read-then-upgrade failure (2026-09-21; reproduced by
            // a renewal scenario under scheduler writes, 2026-09-21).
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| {
                    AppError::Internal(format!("Transaction begin failed: {}", e))
                })?;
            let result = f(&tx)?;
            tx.commit().map_err(|e| {
                AppError::Internal(format!("Transaction commit failed: {}", e))
            })?;
            Ok(result)
        })
        .await
        .map_err(|e| {
            tracing::error!(operation="blocking_task_join_error", error = %e, "Blocking task join error");
            AppError::Internal(format!("Blocking task failed: {}", e))
        })?
    }
}

fn init_connection(conn: &Connection) -> AppResult<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    run_migrations(conn)?;
    check_schema_version(conn)?;
    Ok(())
}

/// Encrypt a plaintext database with SQLCipher.
/// Encrypt an existing plaintext database in place (one-time, opt-in via
/// `storage.encryption = true` after the admin key exists).
///
/// `PRAGMA rekey` cannot turn a plaintext database into an encrypted one — it only
/// changes the key of a database that is already encrypted (SQLCipher 4 returns
/// "file is not a database"; this was the reason the old implementation never worked).
/// The supported direction is `sqlcipher_export`: attach an encrypted target, copy every
/// table into it, then swap the files.
fn migrate_to_encrypted(path: &Path, key: &str) -> AppResult<()> {
    let tmp = path.with_extension("enc-tmp");
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    let shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
    let _ = std::fs::remove_file(&tmp);

    {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA key = '';")?; // explicit plaintext mode
                                                 // Fold any WAL content into the main file before copying it out.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let safe_key = key.replace('\'', "''");
        let sql = format!(
            "ATTACH DATABASE '{tmp}' AS encrypted KEY '{safe_key}';\n\
             SELECT sqlcipher_export('encrypted');\n\
             DETACH DATABASE encrypted;",
            tmp = tmp.display()
        );
        conn.execute_batch(&sql)?;
    }

    // Keep the plaintext original next to the new file (operator can delete it once
    // they verified the encrypted database opens) and drop stale WAL sidecars.
    let backup = path.with_extension("plaintext-bak");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(path, &backup)?;
    std::fs::rename(&tmp, path)?;
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
    tracing::info!(
        operation = "db_encrypted",
        backup = %backup.display(),
        "Database migrated to SQLCipher (plaintext original kept as .plaintext-bak)"
    );
    Ok(())
}

const SCHEMA_VERSION: i64 = 1;

/// Retention window (days) for `delivered` pending_deliveries rows, kept as an
/// audit trail before purge.
const DELIVERED_AUDIT_RETENTION_DAYS: i64 = 7;

fn check_schema_version(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);",
    )?;
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE((SELECT version FROM _schema_version WHERE id=1), 0)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if current == 0 {
        conn.execute(
            "INSERT INTO _schema_version (id, version) VALUES (1, ?1)",
            params![SCHEMA_VERSION],
        )?;
        tracing::info!(
            operation = "schema_init",
            version = SCHEMA_VERSION,
            "Database schema initialized"
        );
    } else if current != SCHEMA_VERSION {
        return Err(crate::core::errors::AppError::Config(format!(
            "Database schema version mismatch: DB has v{}, program expects v{}. Please migrate or reset the database.",
            current, SCHEMA_VERSION
        )));
    }
    Ok(())
}

fn run_migrations(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "

        CREATE TABLE IF NOT EXISTS system_domains (
            id             TEXT PRIMARY KEY,
            system_id      TEXT NOT NULL,
            domain_addr    TEXT NOT NULL UNIQUE,
            webhook_url    TEXT,
            webhook_secret TEXT,
            is_active      INTEGER NOT NULL DEFAULT 1,
            created_at     TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_system_domains_system ON system_domains(system_id);

        INSERT OR IGNORE INTO system_domains (id, system_id, domain_addr) VALUES ('dom_admin', 'admin', 'admin.relay');

        CREATE TABLE IF NOT EXISTS domain_addr_meta (
            email_address   TEXT PRIMARY KEY,
            system_id       TEXT NOT NULL,
            manager_address TEXT NOT NULL DEFAULT '',
            agent_signature TEXT NOT NULL DEFAULT '',
            agent_persona   TEXT NOT NULL DEFAULT '',
            is_active       INTEGER NOT NULL DEFAULT 1,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_domain_addr_meta_system ON domain_addr_meta(system_id);

        -- Address ↔ anchor identifier (2026-11-25). The anchor is the AGENT-side binding anchor
        -- (dsh: workspace path, pi: cwd, openclaw: agent workspace) and is therefore NOT part of the
        -- address model: the client hashes it together with the address, registers the hash at
        -- activation, and sends it on every pull. The gateway only stores/compares an opaque token,
        -- so a new host type needs no gateway change — only its own anchor string.
        CREATE TABLE IF NOT EXISTS address_anchor (
            email_address TEXT PRIMARY KEY,
            anchor_id     TEXT NOT NULL,
            updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS whitelists (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id  TEXT NOT NULL,
            domain_addr TEXT NOT NULL,
            direction  TEXT NOT NULL DEFAULT 'all' CHECK(direction IN ('from','to','all')),
            value      TEXT NOT NULL,
            description TEXT,
            is_active  INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            category   TEXT NOT NULL DEFAULT 'system',
            api_key_id INTEGER,
            UNIQUE(system_id, domain_addr, value)
        );
        CREATE INDEX IF NOT EXISTS idx_whitelists_lookup ON whitelists(system_id, domain_addr, direction, is_active);

        -- Board group whitelist: board_email -> member addresses, built
        -- from member invite/change notifications (X-Board-Members header).
        -- check_whitelisted consults this to auto-allow board members.
        CREATE TABLE IF NOT EXISTS board_whitelists (
            board_email TEXT NOT NULL,
            member_addr TEXT NOT NULL,
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (board_email, member_addr)
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id     TEXT NOT NULL,
            domain_addr   TEXT NOT NULL,
            key_hash      TEXT NOT NULL UNIQUE,
            key_prefix    TEXT NOT NULL,
            scopes       TEXT NOT NULL DEFAULT '[\"agent\"]',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at    TEXT,
            last_used_at  TEXT,
            category      TEXT NOT NULL DEFAULT 'system',
            activation_code_hash TEXT,
            activation_expires_at TEXT,
            claimed_at    TEXT,
            UNIQUE(system_id, domain_addr)
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON api_keys(domain_addr, is_active);
        -- D11: the auth query also matches system-scoped keys by system_id;
        -- without this index that half of the OR was a full table scan.
        CREATE INDEX IF NOT EXISTS idx_api_keys_system_id ON api_keys(system_id, is_active);

        -- AgentSystemId aggregation ownership: one address belongs to exactly
        -- one local Agent-system instance. Re-activation by another instance
        -- transfers ownership (upsert on address), while the SSE/pending query
        -- is scoped by agent_system_id.
        CREATE TABLE IF NOT EXISTS agent_system_addresses (
            address          TEXT PRIMARY KEY,
            agent_system_id  TEXT NOT NULL,
            system_id        TEXT NOT NULL,
            created_at       TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_agent_system_addresses_owner
            ON agent_system_addresses(agent_system_id);

        -- Remaining tables
        CREATE TABLE IF NOT EXISTS activation_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT NOT NULL UNIQUE, code_prefix TEXT NOT NULL,
            code_cipher TEXT,
            code_type TEXT NOT NULL CHECK(code_type IN ('address','product')),
            product_id TEXT, system_id TEXT,
            domain TEXT, email_address TEXT,
            applicant_email TEXT,
            claimed INTEGER NOT NULL DEFAULT 0,
            claimed_at TEXT, claimed_by TEXT, expires_at TEXT,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            is_shipped INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_activation_lookup ON activation_codes(claimed, is_frozen);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_system ON activation_codes(system_id);
        CREATE INDEX IF NOT EXISTS idx_activation_codes_domain ON activation_codes(domain);

        CREATE TABLE IF NOT EXISTS agent_state (
            agent_addr  TEXT NOT NULL,
            state_key   TEXT NOT NULL,
            state_value TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            UNIQUE(agent_addr, state_key)
        );
        CREATE INDEX IF NOT EXISTS idx_agent_state_lookup ON agent_state(agent_addr, state_key);

        CREATE TABLE IF NOT EXISTS pending_deliveries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id   TEXT NOT NULL,
            domain_addr TEXT NOT NULL,
            email       TEXT NOT NULL,
            headers     TEXT NOT NULL,
            payload     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pending_system ON pending_deliveries(system_id, created_at);

        -- Email tables
        CREATE TABLE IF NOT EXISTS attachment_permissions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            attachment_id TEXT NOT NULL,
            user_email    TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(attachment_id, user_email)
        );
        CREATE INDEX IF NOT EXISTS idx_attachment_perm ON attachment_permissions(attachment_id, user_email);

        CREATE TABLE IF NOT EXISTS emails (
            id              TEXT PRIMARY KEY,
            -- Born state is 'readying' (preparing). The app always passes the
            -- status explicitly via insert_email(); this DEFAULT only matters
            -- for direct-DB scripts and documents the lifecycle:
            -- readying → (trigger claim) sending | (recovery flip) ready → sending.
            status          TEXT NOT NULL DEFAULT 'readying',
            system_id       TEXT NOT NULL,
            direction       TEXT NOT NULL CHECK(direction IN ('inbound', 'outbound')),
            sender          TEXT NOT NULL,
            recipients      TEXT NOT NULL,
            endpoints       TEXT,
            subject         TEXT NOT NULL DEFAULT '',
            body            TEXT NOT NULL,
            headers         TEXT,
            attachments     TEXT,
            send_count      INTEGER NOT NULL DEFAULT 0,
            last_sent_at    TEXT NOT NULL DEFAULT (datetime('now')),
            next_retry_at   TEXT,
            -- DEFAULT 5 here is a safety net for direct DB scripts;
            -- the application always passes max_attempts explicitly via
            -- insert_email(). The config default is config::default_max_attempts() = 3.
            max_attempts    INTEGER NOT NULL DEFAULT 5,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            sender_signature  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_emails_scheduler ON emails(next_retry_at, send_count);
        CREATE INDEX IF NOT EXISTS idx_emails_system ON emails(system_id);
        CREATE INDEX IF NOT EXISTS idx_emails_system_date ON emails(system_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);

        CREATE TABLE IF NOT EXISTS attachments_meta (
            id           TEXT PRIMARY KEY,
            filename     TEXT NOT NULL,
            content_type TEXT,
            sender_email TEXT NOT NULL,
            mail_id      TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_attachments_meta_created ON attachments_meta(created_at);

        -- Schema convergence (V2 self-service cleanup): the pilot-era
        -- email_verifications and mock_inbox tables were dev-only fixtures
        -- that never belonged in the product schema — advanced verifies
        -- through an in-process map and mails flow through the real outbound
        -- queue. Drop them on upgrade so existing databases converge to the
        -- exact structure fresh ones get (SCHEMA_VERSION unchanged).
        DROP TABLE IF EXISTS email_verifications;
        DROP TABLE IF EXISTS mock_inbox;
",
    )?;
    // D10: one-time legacy migration — lowercase any manager_address written
    // before case-insensitive comparison existed. Rows already lowercase are
    // untouched (idempotent; runs every boot, only touches dirty rows).
    {
        let dirty = conn
            .query_row(
                "SELECT COUNT(*) FROM domain_addr_meta WHERE manager_address <> LOWER(manager_address)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        if dirty > 0 {
            conn.execute(
                "UPDATE domain_addr_meta SET manager_address = LOWER(manager_address) WHERE manager_address <> LOWER(manager_address)",
                [],
            )?;
            tracing::info!(dirty, "D10: lowercased legacy manager_address rows");
        }
    }

    // activation_codes.applicant_email (V2 self-service): the applicant who
    // requested an address code; activation wires them in as the address's
    // default manager. Column name matches the advanced gateway's
    // activation-code structure so both editions share the same schema.
    // Idempotent per-boot migration (D10 pattern; SCHEMA_VERSION unchanged):
    //  - fresh DB: CREATE TABLE already has the column → no-op
    //  - v1.0.10 DB: legacy requester_email column → rename in place
    //  - pre-1.0.10 DB: add the column
    {
        let has_applicant: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('activation_codes') WHERE name = 'applicant_email'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        if has_applicant == 0 {
            let has_legacy: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('activation_codes') WHERE name = 'requester_email'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0);
            if has_legacy > 0 {
                conn.execute(
                    "ALTER TABLE activation_codes RENAME COLUMN requester_email TO applicant_email",
                    [],
                )?;
                tracing::info!(
                    operation = "schema_migration",
                    "Renamed activation_codes.requester_email to applicant_email"
                );
            } else {
                conn.execute(
                    "ALTER TABLE activation_codes ADD COLUMN applicant_email TEXT",
                    [],
                )?;
                tracing::info!(
                    operation = "schema_migration",
                    "Added activation_codes.applicant_email column to pre-existing database"
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SystemRecord {
    pub id: String,
    pub admin_email: String,
    pub limits_config: Option<String>,

    pub is_active: bool,
    pub created_at: String,
    /// System-level default manager for agent address registration.
    /// Persisted at activation (the activation code's delivery address); empty
    /// = no per-system default, callers fall back to the config file.
    pub manager_address: String,
}

#[derive(Debug, Clone)]
pub struct SystemDomainRecord {
    pub id: String,
    pub system_id: String,
    pub domain: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct PendingDeliveryRecord {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub email: String,
    pub headers: String,
    pub payload: String,
    pub status: String,
    pub created_at: String,
}

fn system_domain_row(r: &rusqlite::Row) -> rusqlite::Result<SystemDomainRecord> {
    Ok(SystemDomainRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        domain: r.get(2)?,
        webhook_url: r.get(3)?,
        webhook_secret: r.get(4)?,
        is_active: r.get::<_, i32>(5)? != 0,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

/// Per-agent metadata: manager address, signature, persona.
#[derive(Debug, Clone)]
pub struct DomainAddrMetaRecord {
    pub email_address: String,
    pub system_id: String,
    pub manager_address: String,
    pub agent_signature: String,
    pub agent_persona: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

fn domain_addr_meta_row(r: &rusqlite::Row) -> rusqlite::Result<DomainAddrMetaRecord> {
    Ok(DomainAddrMetaRecord {
        email_address: r.get(0)?,
        system_id: r.get(1)?,
        manager_address: r.get::<_, String>(2).unwrap_or_default(),
        agent_signature: r.get::<_, String>(3).unwrap_or_default(),
        agent_persona: r.get::<_, String>(4).unwrap_or_default(),
        is_active: r.get::<_, i32>(5)? != 0,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

// ── Agent state ──────────────────────

fn agent_state_row(r: &rusqlite::Row) -> rusqlite::Result<(String, String, String)> {
    Ok((
        r.get::<_, String>(0)?, // state_key
        r.get::<_, String>(1)?, // state_value
        r.get::<_, String>(2)?, // updated_at
    ))
}

impl Database {
    pub async fn agent_state_get(
        &self,
        agent_addr: &str,
        state_key: &str,
    ) -> AppResult<Option<(String, String)>> {
        let (agent_addr, state_key) = (agent_addr.to_string(), state_key.to_string());
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT state_key, state_value, updated_at FROM agent_state WHERE agent_addr = ?1 AND state_key = ?2"
            )?;
            let mut rows = stmt.query_map(params![agent_addr, state_key], agent_state_row)?;
            match rows.next() {
                Some(Ok((key, value, _))) => Ok(Some((key, value))),
                Some(Err(e)) => Err(e.into()),
                None => Ok(None),
            }
        }).await
    }

    pub async fn agent_state_put(
        &self,
        agent_addr: &str,
        state_key: &str,
        state_value: &str,
    ) -> AppResult<()> {
        let (agent_addr, state_key, state_value) = (
            agent_addr.to_string(),
            state_key.to_string(),
            state_value.to_string(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO agent_state (agent_addr, state_key, state_value, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(agent_addr, state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at",
                params![agent_addr, state_key, state_value, now],
            )?;
            Ok(())
        }).await
    }

    pub async fn agent_state_delete(&self, agent_addr: &str, state_key: &str) -> AppResult<()> {
        let (agent_addr, state_key) = (agent_addr.to_string(), state_key.to_string());
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM agent_state WHERE agent_addr = ?1 AND state_key = ?2",
                params![agent_addr, state_key],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn insert_system_domain(
        &self,
        id: &str,
        system_id: &str,
        domain: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
    ) -> AppResult<SystemDomainRecord> {
        let (id, system_id, domain) = (id.to_string(), system_id.to_string(), domain.to_string());
        let (webhook_url, webhook_secret) = (
            webhook_url.map(String::from),
            webhook_secret.map(String::from),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let domain_for_cache = domain.clone();
        let record = self.call(move |conn| {
            conn.execute(
                "INSERT INTO system_domains (id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
                params![id, system_id, domain, webhook_url, webhook_secret, now],
            )?;
            Ok(SystemDomainRecord {
                id, system_id, domain,
                webhook_url, webhook_secret,
                is_active: true, created_at: now.clone(), updated_at: now,
            })
        }).await?;
        // ── Invalidate domain cache ──
        // Without this, a prior cache-miss (None) would be served stale for up to 30s.
        if let Ok(mut cache) = self.domain_cache.write() {
            cache.remove(&domain_for_cache);
        }
        Ok(record)
    }

    /// Seed a config-provided bare domain only when absent. Never updates an
    /// existing row: the runtime domain API remains authoritative.
    pub async fn seed_system_domain_if_absent(
        &self,
        id: &str,
        system_id: &str,
        domain: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
    ) -> AppResult<bool> {
        let (id, system_id, domain) = (id.to_string(), system_id.to_string(), domain.to_string());
        let (webhook_url, webhook_secret) = (
            webhook_url.map(String::from),
            webhook_secret.map(String::from),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let domain_for_cache = domain.clone();
        let inserted = self
            .call(move |conn| {
                let n = conn.execute(
                    "INSERT INTO system_domains
                       (id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
                     ON CONFLICT(domain_addr) DO NOTHING",
                    params![id, system_id, domain, webhook_url, webhook_secret, now],
                )?;
                Ok(n > 0)
            })
            .await?;
        if inserted {
            if let Ok(mut cache) = self.domain_cache.write() {
                cache.remove(&domain_for_cache);
            }
        }
        Ok(inserted)
    }

    pub async fn get_system_domain(&self, id: &str) -> AppResult<Option<SystemDomainRecord>> {
        let id = id.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE id = ?1",
                params![id],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn get_system_domain_by_domain(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let domain = domain.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE domain_addr = ?1",
                params![domain],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Fetch an ACTIVE system-domain record by domain name.
    /// Used by webhook delivery resolution — deactivated domains must not
    /// receive email (AUDIT-1 P2-4).
    pub async fn get_active_system_domain_by_domain(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let domain = domain.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE domain_addr = ?1 AND is_active = 1",
                params![domain],
                system_domain_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn list_system_domains(&self, system_id: &str) -> AppResult<Vec<SystemDomainRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], system_domain_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn update_system_domain(
        &self,
        id: &str,
        webhook_url: Option<&str>,
        webhook_secret: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<Option<SystemDomainRecord>> {
        let (id, wu, ws) = (
            id.to_string(),
            webhook_url.map(String::from),
            webhook_secret.map(String::from),
        );
        let id_for_cache = id.clone();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let updated = self.call(move |conn| {
            let affected = conn.execute(
                "UPDATE system_domains SET webhook_url = ?1, webhook_secret = ?2, is_active = COALESCE(?3, is_active), updated_at = ?4 WHERE id = ?5",
                params![wu, ws, is_active.map(|a| a as i32), now, id],
            )?;
            if affected == 0 { return Ok(None); }
            let updated = conn.query_row(
                "SELECT id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at FROM system_domains WHERE id = ?1",
                params![id],
                system_domain_row,
            )?;
            Ok(Some(updated))
        })
        .await?;
        // ── Invalidate domain cache ──
        // Without this, a previously cached positive lookup would keep serving
        // the pre-update record (old webhook / is_active) for up to the 30s
        // TTL — deactivations would not be visible to readers immediately.
        // Same shape as `delete_system_domain`: cache keys are the raw query
        // strings callers pass in, so match on the stored record id instead of
        // a possibly-differently-cased domain to stay format-agnostic.
        if updated.is_some() {
            if let Ok(mut cache) = self.domain_cache.write() {
                cache.retain(|_, (_, rec)| {
                    rec.as_ref().map(|r| r.id != id_for_cache).unwrap_or(true)
                });
            }
        }
        Ok(updated)
    }

    pub async fn delete_system_domain(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        let id_for_cache = id.clone();
        self.call(move |conn| {
            conn.execute("DELETE FROM system_domains WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await?;
        // Evict any cached copy of the deleted record. Cache keys are the raw
        // query strings callers pass in, so match on the stored id rather than
        // a possibly-differently-cased domain to be format-agnostic.
        if let Ok(mut cache) = self.domain_cache.write() {
            cache.retain(|_, (_, rec)| rec.as_ref().map(|r| r.id != id_for_cache).unwrap_or(true));
        }
        Ok(())
    }

    /// Atomically rename an agent address `old` → `new` across every
    /// referencing table, inheriting all server-side resources:
    ///
    /// - `system_domains`/`domain_addr_meta` rows are re-keyed in place
    ///   (webhook/secret/manager/signature/persona ride along — same row);
    /// - `api_keys.domain_addr` is re-pointed — the agent's key itself is
    ///   untouched, so the agent keeps working under the new address with
    ///   the same credential (no re-activation);
    /// - `whitelists` (domain_addr AND value sides), `agent_state`
    ///   (agent_addr and address-embedded state keys), `boards.board_email`,
    ///   `board_members.email`, `tasks.assignee/reviewer/created_by`,
    ///   `task_events.actor` are migrated via copy-new/delete-old so a
    ///   pre-existing new-key row wins (INSERT OR IGNORE semantics);
    /// - mail history (`emails`, snapshots) is untouched — those are
    ///   immutable string snapshots of the old identity.
    ///
    /// The whole migration runs in one `execute_batch` (single implicit
    /// transaction): any failure rolls back everything.
    ///
    /// Caller must already have validated: `old` exists and belongs to the
    /// requesting system, `new` is not registered anywhere, `new` is on the
    /// same bare domain as `old`, `new`'s local part is legal, and no
    /// `board_members` row already carries `new` (member merge is refused).
    pub async fn rename_agent_address_refs(&self, old: &str, new: &str) -> AppResult<()> {
        // Defense-in-depth: address components are strictly bounded so no
        // quoting/escaping hazards can reach the batch text.
        let safe = |s: &str| -> bool {
            !s.is_empty()
                && s.len() <= 255
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(
                            b,
                            b'@' | b'.'
                                | b'-'
                                | b'_'
                                | b'+'
                                | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'/'
                                | b'='
                                | b'?'
                                | b'^'
                                | b'`'
                                | b'{'
                                | b'|'
                                | b'}'
                                | b'~'
                                | b'!'
                        )
                })
        };
        assert!(
            safe(old) && safe(new),
            "rename addresses must be bounded atext/no-quote strings"
        );
        let old = old.to_string();
        let new = new.to_string();
        let old_for_cache = old.clone();
        let db_file = self.db_file.clone();

        self.call(move |conn| {
            let batch = format!(
                r#"
BEGIN;
-- domain_addr_meta: re-key in place (PK update; caller pre-checked new absent)
UPDATE domain_addr_meta SET email_address = '{new}' WHERE email_address = '{old}';
-- api_keys: re-point the agent key (key material untouched)
UPDATE api_keys SET domain_addr = '{new}' WHERE domain_addr = '{old}';
-- system_domains: re-key in place (webhook/secret ride along)
UPDATE system_domains SET domain_addr = '{new}' WHERE domain_addr = '{old}';
-- whitelists, domain_addr side: copy to new key then drop old rows
INSERT OR IGNORE INTO whitelists(system_id,domain_addr,direction,value,description,is_active,created_at,category,api_key_id)
  SELECT system_id,'{new}',direction,value,description,is_active,created_at,category,api_key_id
  FROM whitelists WHERE domain_addr = '{old}';
DELETE FROM whitelists WHERE domain_addr = '{old}';
-- whitelists, value side (other agents' rows pointing at the old address):
-- copy with the value rewritten, then drop the originals.
INSERT OR IGNORE INTO whitelists(system_id,domain_addr,direction,value,description,is_active,created_at,category,api_key_id)
  SELECT system_id,domain_addr,direction,'{new}',description,is_active,created_at,category,api_key_id
  FROM whitelists WHERE value = '{old}' AND domain_addr <> '{old}';
DELETE FROM whitelists WHERE value = '{old}' AND domain_addr <> '{old}';
-- whitelists rows already re-keyed above whose value was also the old
-- address (agent <-> manager bidirectional entries on the renamed address)
UPDATE whitelists SET value = '{new}' WHERE domain_addr = '{new}' AND value = '{old}';
-- agent_state: agent_addr side + state keys embedding the address
-- (profile:/summary:/…:{old} → …:{new}); copy then drop.
INSERT OR IGNORE INTO agent_state(agent_addr,state_key,state_value,created_at,updated_at)
  SELECT CASE WHEN agent_addr = '{old}' THEN '{new}' ELSE agent_addr END,
         replace(state_key,'{old}','{new}'), state_value, created_at, updated_at
  FROM agent_state WHERE agent_addr = '{old}' OR state_key LIKE '%{old}%';
DELETE FROM agent_state WHERE agent_addr = '{old}';
DELETE FROM agent_state WHERE agent_addr <> '{old}' AND state_key LIKE '%{old}%';
COMMIT;
"#,
            );
            if let Err(e) = conn.execute_batch(&batch) {
                // Any statement failed mid-batch: the implicit transaction
                // opened by BEGIN is still open — roll it back so the
                // pooled connection never leaks a half-applied migration.
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e.into());
            }

            // Boards live in per-board DB files ({storage}/a2a_board/*.db,
            // one file per board). Migrate the address there file by file;
            // a failing board file is logged and skipped — it never blocks
            // the main-library migration (board data is not lost, only the
            // stale name remains until the next member sync).
            let boards_dir = db_file.parent().unwrap_or(std::path::Path::new("")).join("a2a_board");
            if boards_dir.is_dir() {
                let board_sql = format!(
                    "UPDATE boards SET board_email = '{new}' WHERE board_email = '{old}';
                     INSERT OR IGNORE INTO board_members(email,role,display_name,board_token,board_id,joined_at,domains,capability_snapshot)
                       SELECT '{new}',role,display_name,board_token,board_id,joined_at,domains,capability_snapshot
                       FROM board_members WHERE email = '{old}';
                     UPDATE tasks SET assignee = '{new}' WHERE assignee = '{old}';
                     UPDATE tasks SET reviewer = '{new}' WHERE reviewer = '{old}';
                     UPDATE tasks SET created_by = '{new}' WHERE created_by = '{old}';
                     UPDATE task_events SET actor = '{new}' WHERE actor = '{old}';
                     DELETE FROM board_members WHERE email = '{old}';"
                );
                if let Ok(entries) = std::fs::read_dir(&boards_dir) {
                    for entry in entries.flatten() {
                    let pth = entry.path();
                    if pth.extension().and_then(|e| e.to_str()) != Some("db") {
                        continue;
                    }
                        if let Ok(bconn) = rusqlite::Connection::open(&pth) {
                            if let Err(e) = bconn.execute_batch(&board_sql) {
                                eprintln!("[rename] board db {} update failed: {}", pth.display(), e);
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;
        // Evict any cached lookup of the renamed address: its `system_domains`
        // row was re-keyed, so a cached positive hit would keep serving the old
        // address (and its system_id) for up to the 30s TTL. Cache keys are the
        // raw query strings callers pass in, so match both the key and the
        // stored record to stay format-agnostic (same rationale as
        // `delete_system_domain`).
        if let Ok(mut cache) = self.domain_cache.write() {
            cache.retain(|key, (_, rec)| {
                key != &old_for_cache
                    && rec
                        .as_ref()
                        .map(|r| r.domain != old_for_cache)
                        .unwrap_or(true)
            });
        }
        Ok(())
    }

    // NOTE: the per-domain webhook lookup lives in the storage layer that owns
    // the `systems` table, not in this module.

    /// Get a system domain record by domain name (uses cache).
    pub async fn get_system_domain_by_name(
        &self,
        domain: &str,
    ) -> AppResult<Option<SystemDomainRecord>> {
        // Check cache for positive hits only — never cache None
        // (security critical: domain deletions/creations must be visible immediately)
        {
            let cache = self
                .domain_cache
                .read()
                .map_err(|_| AppError::Internal("domain cache lock poisoned".into()))?;
            if let Some((ts, record)) = cache.get(domain) {
                if ts.elapsed() < std::time::Duration::from_secs(30) && record.is_some() {
                    return Ok(record.clone());
                }
            }
        }
        let result = self.get_system_domain_by_domain(domain).await?;
        // Cache positive hits only
        if result.is_some() {
            if let Ok(mut cache) = self.domain_cache.write() {
                let len = cache.len();
                if len > 1000 {
                    cache.retain(|_, (ts, _)| ts.elapsed() < std::time::Duration::from_secs(60));
                }
                cache.insert(domain.to_string(), (Instant::now(), result.clone()));
            }
        }
        Ok(result)
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DOMAIN ADDR META — per-agent-address metadata
    // ═══════════════════════════════════════════════════════════════════

    /// Insert or replace an agent metadata row.
    pub async fn upsert_domain_addr_meta(
        &self,
        email: &str,
        system_id: &str,
        manager_address: Option<&str>,
        agent_signature: Option<&str>,
        agent_persona: Option<&str>,
    ) -> AppResult<DomainAddrMetaRecord> {
        let (email, system_id) = (email.to_lowercase(), system_id.to_string());
        let (ma, sig, persona) = (
            // D10: normalize manager_address to lowercase on write — manager
            // identity is compared case-insensitively (see is_manager), so the
            // stored form must not depend on how the client cased it.
            manager_address.unwrap_or("").trim().to_lowercase(),
            agent_signature.unwrap_or("").to_string(),
            agent_persona.unwrap_or("").to_string(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO domain_addr_meta (email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
                 ON CONFLICT(email_address) DO UPDATE SET
                   system_id = excluded.system_id,
                   manager_address = excluded.manager_address,
                   agent_signature = excluded.agent_signature,
                   agent_persona = excluded.agent_persona,
                   updated_at = excluded.updated_at",
                params![email, system_id, ma, sig, persona, now],
            )?;
            Ok(DomainAddrMetaRecord {
                email_address: email,
                system_id,
                manager_address: ma,
                agent_signature: sig,
                agent_persona: persona,
                is_active: true,
                created_at: now.clone(),
                updated_at: now,
            })
        }).await
    }

    /// Set the safety-officer (manager) landing point for an address-code
    /// activation, with the advanced gateway's exact semantics:
    ///   - first activation → the applicant is written;
    ///   - existing non-empty manager → **preserved** (self-service change is
    ///     not valid; changes go through the admin path only);
    ///   - agent_signature / agent_persona → never touched (welcome persona
    ///     chain values must survive re-activation).
    ///
    /// Returns the EFFECTIVE manager after the upsert (may differ from the
    /// passed applicant on renewal) — the value the activation response and
    /// the whitelist entry must use so the binding cannot diverge.
    pub async fn set_domain_addr_meta_manager(
        &self,
        email: &str,
        system_id: &str,
        manager: &str,
    ) -> AppResult<Option<String>> {
        let (email, system_id, manager) = (
            email.to_lowercase(),
            system_id.to_string(),
            manager.to_lowercase(),
        );
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO domain_addr_meta (email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, '', '', 1, ?4, ?4)
                 ON CONFLICT(email_address) DO UPDATE SET
                   manager_address = CASE WHEN domain_addr_meta.manager_address = ''
                                          THEN excluded.manager_address
                                          ELSE domain_addr_meta.manager_address END,
                   updated_at = excluded.updated_at",
                params![email, system_id, manager, now],
            )?;
            let effective: Option<String> = conn
                .query_row(
                    "SELECT manager_address FROM domain_addr_meta WHERE email_address = ?1",
                    params![email],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(effective.filter(|s: &String| !s.is_empty()))
        })
        .await
    }

    /// Get agent metadata by email address.
    pub async fn get_domain_addr_meta(
        &self,
        email: &str,
    ) -> AppResult<Option<DomainAddrMetaRecord>> {
        let email = email.to_lowercase();
        self.call(move |conn| {
            conn.query_row(
                "SELECT email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at
                 FROM domain_addr_meta WHERE email_address = ?1",
                params![email],
                domain_addr_meta_row,
            ).optional().map_err(Into::into)
        }).await
    }

    /// List all agent metadata rows for a system.
    pub async fn list_domain_addr_meta_by_system(
        &self,
        system_id: &str,
    ) -> AppResult<Vec<DomainAddrMetaRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at
                 FROM domain_addr_meta WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], domain_addr_meta_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }).await
    }

    /// Delete agent metadata by email address.
    pub async fn delete_domain_addr_meta(&self, email: &str) -> AppResult<()> {
        let email = email.to_lowercase();
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM domain_addr_meta WHERE email_address = ?1",
                params![email],
            )?;
            Ok(())
        })
        .await
    }
}

#[derive(Debug, Clone)]
pub struct WhitelistRecord {
    pub id: i64,
    pub system_id: String,
    pub domain_addr: String,
    pub direction: String,
    pub value: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub category: String,
    pub api_key_id: Option<i64>,
}

fn whitelist_row(r: &rusqlite::Row) -> rusqlite::Result<WhitelistRecord> {
    Ok(WhitelistRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        domain_addr: r.get(2)?,
        direction: r.get(3)?,
        value: r.get(4)?,
        description: r.get(5)?,
        is_active: r.get::<_, i32>(6)? != 0,
        created_at: r.get(7)?,
        category: r.get(8)?,
        api_key_id: r.get(9)?,
    })
}

impl Database {
    #[allow(clippy::too_many_arguments)] // explicit parameter list is deliberate: internal constructor/handler API
    pub async fn insert_whitelist(
        &self,
        system_id: &str,
        domain_addr: &str,
        direction: &str,
        value: &str,
        category: &str,
        api_key_id: Option<i64>,
        description: Option<&str>,
    ) -> AppResult<WhitelistRecord> {
        debug!(
            operation = "insert_whitelist",
            system_id = %system_id,
            domain = %domain_addr,
            direction = %direction,
            value = %value,
            "Whitelist entry inserted"
        );
        let (system_id, domain_addr, direction, value) = (
            system_id.to_string(),
            domain_addr.to_string(),
            direction.to_string(),
            value.to_string(),
        );
        let category = category.to_string();
        let description = description.map(String::from);
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
             conn.execute(
                 // Recreate = overwrite: direction is a one-of-three choice
                 // (to/from/all) per (system_id, domain_addr, value), so a
                 // later create with a different direction replaces the
                 // existing rule (last write wins). AUDIT-1 P2-7 originally
                 // froze direction on conflict, but that made a second
                 // direction un-persistable (4.3c: 'to' row existed, 'from'
                 // create hit the conflict and silently kept 'to').
                 "INSERT INTO whitelists (system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8) ON CONFLICT(system_id, domain_addr, value) DO UPDATE SET direction=excluded.direction, is_active=1, description=CASE WHEN excluded.description IS NOT NULL THEN excluded.description ELSE description END",
                 params![system_id, domain_addr, direction, value, description, now, category, api_key_id],
             )?;
            let id = conn.last_insert_rowid();
            Ok(WhitelistRecord {
                id, system_id, domain_addr, direction, value, description, is_active: true, created_at: now,
                category, api_key_id,
            })
        }).await
    }

    pub async fn get_whitelist(
        &self,
        system_id: &str,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<Option<WhitelistRecord>> {
        let (system_id, domain_addr, value) = (
            system_id.to_string(),
            domain_addr.to_string(),
            value.to_string(),
        );
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE system_id = ?1 AND domain_addr = ?2 AND value = ?3 LIMIT 1",
                params![system_id, domain_addr, value],
                whitelist_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Look up a whitelist entry by its primary key ID (used for cache invalidation on delete).
    pub async fn get_whitelist_by_id(&self, id: i64) -> AppResult<Option<WhitelistRecord>> {
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE id = ?1 LIMIT 1",
                params![id],
                whitelist_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn list_whitelists(&self, system_id: &str) -> AppResult<Vec<WhitelistRecord>> {
        let system_id = system_id.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE system_id = ?1",
            )?;
            let rows = stmt.query_map(params![system_id], whitelist_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn update_whitelist(
        &self,
        id: i64,
        is_active: Option<bool>,
        direction: Option<String>,
    ) -> AppResult<Option<WhitelistRecord>> {
        debug!(
            operation = "update_whitelist",
            id = %id,
            is_active = ?is_active,
            direction = ?direction,
            "Whitelist entry updated"
        );
        self.call(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, direction, value, description, is_active, created_at, category, api_key_id FROM whitelists WHERE id = ?1",
                params![id],
                whitelist_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            if let Some(a) = is_active { record.is_active = a; }
            if let Some(ref d) = direction { record.direction = d.clone(); }
            conn.execute(
                "UPDATE whitelists SET is_active = ?1, direction = COALESCE(?2, direction) WHERE id = ?3",
                params![record.is_active as i32, direction, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    pub async fn delete_whitelist(&self, id: i64) -> AppResult<()> {
        debug!(
            operation = "delete_whitelist",
            id = %id,
            "Whitelist entry deleted"
        );
        self.call(move |conn| {
            conn.execute("DELETE FROM whitelists WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }

    /// Delete a whitelist entry by domain_addr and value (for manager commands).
    /// Returns Ok(()) even if no matching entry was found.
    pub async fn delete_whitelist_by_domain_and_value(
        &self,
        domain_addr: &str,
        value: &str,
    ) -> AppResult<()> {
        let (domain_addr, value) = (domain_addr.to_string(), value.to_string());
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM whitelists WHERE domain_addr = ?1 AND value = ?2",
                params![domain_addr, value],
            )?;
            Ok(())
        })
        .await
    }

    /// Count whitelist entries for a specific api_key (agent scope).
    pub async fn count_whitelist_entries_by_api_key(
        &self,
        system_id: &str,
        api_key_id: i64,
    ) -> AppResult<i64> {
        let (system_id,) = (system_id.to_string(),);
        self.call(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM whitelists WHERE system_id = ?1 AND api_key_id = ?2 AND category = 'agent'",
                params![system_id, api_key_id],
                |r| r.get(0),
            )?;
            Ok(count)
        }).await
    }

    /// P0: Count active whitelist entries for (system, domain, directions).
    /// Used to distinguish "empty whitelist = open" from "non-empty whitelist = restrictive".
    /// Pre-generated branches for 1-3 directions to avoid dynamic SQL allocation.
    pub async fn count_whitelist_entries(
        &self,
        system_id: &str,
        domain: &str,
        directions: &[&str],
    ) -> AppResult<i64> {
        let (system_id, domain) = (system_id.to_string(), domain.to_string());
        let dirs: Vec<String> = directions.iter().map(|d| d.to_string()).collect();
        self.call(move |conn| {
            let count: i64 = match dirs.len() {
                1 => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction=?3 AND is_active=1",
                    params![system_id, domain, dirs[0]], |r| r.get(0),
                )?,
                2 => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction IN (?3,?4) AND is_active=1",
                    params![system_id, domain, dirs[0], dirs[1]], |r| r.get(0),
                )?,
                _ => conn.query_row(
                    "SELECT COUNT(*) FROM whitelists WHERE system_id=?1 AND domain_addr=?2 AND direction IN (?3,?4,?5) AND is_active=1",
                    params![system_id, domain, dirs[0], dirs[1], dirs.get(2).cloned().unwrap_or_default()], |r| r.get(0),
                )?,
            };
            Ok(count)
        }).await
    }

    /// Check if a value is whitelisted for a given domain+system+direction.
    /// direction: "from" (sender check), "to" (recipient check), or "all" (both)
    ///
    /// Fetches all active wildcard patterns from the whitelist table and matches
    /// `value` against them using the in-memory `WhitelistCache`. When no active
    /// entries exist for the scope, the answer is **deny** (returns `false`).
    /// Whether `member_addr` is a member of the board `board_email`
    /// (board group whitelist, populated by invite notifications).
    pub async fn is_board_member(&self, board_email: &str, member_addr: &str) -> AppResult<bool> {
        let be = board_email.to_string();
        let ma = member_addr.to_string();
        self.call(move |conn| {
            let n: i64 = conn.query_row(
                "SELECT count(*) FROM board_whitelists WHERE board_email = ?1 AND member_addr = ?2",
                rusqlite::params![be, ma],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
        .await
    }

    /// Replace the member list of a board (full sync from notification).
    pub async fn replace_board_members(
        &self,
        board_email: &str,
        members: &[String],
    ) -> AppResult<usize> {
        let be = board_email.to_string();
        let members: Vec<String> = members.to_vec();
        self.call(move |conn| {
            conn.execute("DELETE FROM board_whitelists WHERE board_email = ?1", [&be])?;
            let mut n = 0;
            for m in &members {
                n += conn.execute(
                    "INSERT OR IGNORE INTO board_whitelists (board_email, member_addr) VALUES (?1, ?2)",
                    rusqlite::params![be, m],
                )?;
            }
            Ok(n)
        })
        .await
    }

    pub async fn is_whitelisted(
        &self,
        system_id: &str,
        domain_addr: &str,
        value: &str,
        direction: &str,
    ) -> AppResult<bool> {
        let (system_id, domain_addr, value, direction) = (
            system_id.to_string(),
            domain_addr.to_string(),
            value.to_string(),
            direction.to_string(),
        );
        let cache = Arc::clone(&self.whitelist_cache);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT value FROM whitelists \
                 WHERE system_id = ?1 AND domain_addr = ?2 \
                   AND (direction = ?3 OR direction = 'all') \
                   AND is_active = 1",
            )?;
            let patterns: Vec<String> = stmt
                .query_map(params![system_id, domain_addr, direction], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;

            if patterns.is_empty() {
                return Ok(false);
            }
            Ok(is_whitelisted_wildcard(&patterns, &value, cache.as_ref()))
        })
        .await
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub system_id: String,
    pub email_address: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub category: String,
    pub activation_code_hash: Option<String>,
    pub activation_expires_at: Option<String>,
    pub claimed_at: Option<String>,
}

/// Parameters for creating/rotating an API key. A struct keeps the two
/// storage/factory signatures under clippy's argument limit without allow.
pub struct ApiKeyParams<'a> {
    pub system_id: &'a str,
    pub email_address: &'a str,
    pub key_hash: &'a str,
    pub key_prefix: &'a str,
    pub scopes: &'a [String],
    pub expires_at: Option<&'a str>,
    pub category: &'a str,
}

impl<'a> ApiKeyParams<'a> {
    pub fn new(
        system_id: &'a str,
        email_address: &'a str,
        key_hash: &'a str,
        key_prefix: &'a str,
        scopes: &'a [String],
        expires_at: Option<&'a str>,
        category: &'a str,
    ) -> Self {
        Self {
            system_id,
            email_address,
            key_hash,
            key_prefix,
            scopes,
            expires_at,
            category,
        }
    }
}

impl Database {
    /// Bind an address to the local AgentSystemId that activated it.
    pub async fn bind_agent_system_address(
        &self,
        agent_system_id: &str,
        address: &str,
        system_id: &str,
    ) -> AppResult<()> {
        let id = agent_system_id.trim().to_string();
        let addr = address.trim().to_lowercase();
        let sid = system_id.trim().to_string();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO agent_system_addresses (address, agent_system_id, system_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(address) DO UPDATE SET
                   agent_system_id = excluded.agent_system_id,
                   system_id = excluded.system_id",
                params![addr, id, sid],
            )?;
            Ok(())
        })
        .await
    }

    /// Remove the ASID ownership row for an address once its LAST active
    /// agent key is gone. Re-activation by another instance still upserts the
    /// row; this only cleans up after deregistration so a deleted address can
    /// never keep receiving aggregate deliveries.
    pub async fn remove_agent_system_address_if_unowned(
        &self,
        system_id: &str,
        address: &str,
    ) -> AppResult<bool> {
        let sid = system_id.trim().to_string();
        let addr = address.trim().to_lowercase();
        self.call(move |conn| {
            let n = conn.execute(
                "DELETE FROM agent_system_addresses
                 WHERE system_id = ?1 AND address = ?2
                   AND NOT EXISTS (
                     SELECT 1 FROM api_keys
                     WHERE system_id = ?1 AND domain_addr = ?2
                       AND category = 'agent' AND is_active = 1
                   )",
                params![sid, addr],
            )?;
            Ok(n > 0)
        })
        .await
    }

    /// Addresses owned by one AgentSystemId on this gateway.
    pub async fn list_agent_system_addresses(
        &self,
        agent_system_id: &str,
    ) -> AppResult<Vec<(String, String)>> {
        let id = agent_system_id.trim().to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT address, system_id FROM agent_system_addresses
                 WHERE agent_system_id = ?1 ORDER BY address",
            )?;
            let rows = stmt.query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await
    }
    /// Record the anchor identifier for one address (opaque client-side hash).
    ///
    /// Overwriting is intentional: a legitimate re-anchor (contract §13.3 move) is an explicit,
    /// authenticated action by the key holder, and this call is how the gateway learns the new value.
    pub async fn set_address_anchor(&self, email: &str, anchor_id: &str) -> AppResult<()> {
        let email = email.to_lowercase();
        let anchor_id = anchor_id.to_string();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO address_anchor (email_address, anchor_id, updated_at)
                 VALUES (?1, ?2, datetime('now'))
                 ON CONFLICT(email_address) DO UPDATE SET
                    anchor_id = excluded.anchor_id,
                    updated_at = excluded.updated_at",
                params![email, anchor_id],
            )?;
            Ok(())
        })
        .await
    }

    /// The anchor identifier recorded for one address (`None` = never registered).
    pub async fn get_address_anchor(&self, email: &str) -> AppResult<Option<String>> {
        let email = email.to_lowercase();
        self.call(move |conn| {
            conn.query_row(
                "SELECT anchor_id FROM address_anchor WHERE email_address = ?1",
                params![email],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
        })
        .await
    }

    /// Anchor identifiers for every address of an AgentSystemId (only the ones registered).
    pub async fn list_agent_system_anchors(
        &self,
        agent_system_id: &str,
    ) -> AppResult<Vec<(String, String)>> {
        let id = agent_system_id.trim().to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT a.address, m.anchor_id
                 FROM agent_system_addresses a
                 JOIN address_anchor m ON m.email_address = lower(a.address)
                 WHERE a.agent_system_id = ?1 ORDER BY a.address",
            )?;
            let rows = stmt.query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await
    }
}

pub fn api_key_row(r: &rusqlite::Row) -> rusqlite::Result<ApiKeyRecord> {
    Ok(ApiKeyRecord {
        id: r.get(0)?,
        system_id: r.get(1)?,
        email_address: r.get(2)?,
        key_hash: r.get(3)?,
        key_prefix: r.get(4)?,
        scopes: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        is_active: r.get::<_, i32>(6)? != 0,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        last_used_at: r.get(9)?,
        category: r.get(10)?,
        activation_code_hash: r.get(11)?,
        activation_expires_at: r.get(12)?,
        claimed_at: r.get(13)?,
    })
}

impl Database {
    /// Sealing of stored credential material (2026-09-22): seal historical plaintext hashes (`sha256(raw_key)`) in place into `v1:...`.
    ///
    /// Idempotent - already-sealed rows are skipped, so the migration can be interrupted/re-run; it also means it can be rolled back anytime (the code accepts both forms).
    /// Returns (newly sealed count, skipped count).
    pub async fn reseal_api_keys(&self) -> AppResult<(usize, usize)> {
        use crate::core::api::seal;
        let key = seal::key_ref().ok_or_else(|| {
            AppError::Internal("seal key not loaded — refusing to reseal credentials".into())
        })?;
        self.call_tx(move |conn| {
            let rows: Vec<(i64, String)> = {
                let mut stmt = conn.prepare("SELECT id, key_hash FROM api_keys")?;
                let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                it.collect::<Result<Vec<_>, _>>()?
            };
            let (mut done, mut skipped) = (0usize, 0usize);
            for (id, stored) in rows {
                if seal::is_sealed(&stored) {
                    skipped += 1;
                    continue;
                }
                let sealed = seal::seal(key, &stored)
                    .map_err(|e| AppError::Internal(format!("seal failed: {e}")))?;
                conn.execute(
                    "UPDATE api_keys SET key_hash = ?1 WHERE id = ?2",
                    rusqlite::params![sealed, id],
                )?;
                done += 1;
            }
            Ok((done, skipped))
        })
        .await
    }

    /// Count sealed credential rows (used by the startup fail-closed check: sealed material present but admin-key unavailable => refuse to start).
    pub async fn count_sealed_api_keys(&self) -> AppResult<usize> {
        self.call_tx(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM api_keys WHERE key_hash LIKE 'v1:%'",
                [],
                |r| r.get(0),
            )?;
            Ok(n as usize)
        })
        .await
    }

    /// Ensure an activated agent address has a system_domains row so SMTP
    /// RCPT resolves it (base's address activation historically only created
    /// the key; advanced creates the row). Idempotent.
    pub async fn ensure_agent_address_domain(
        &self,
        system_id: &str,
        email_address: &str,
    ) -> AppResult<()> {
        let (system_id, email_address) = (system_id.to_string(), email_address.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO system_domains (id, system_id, domain_addr, webhook_url, webhook_secret, is_active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, NULL, NULL, 1, ?4, ?4)",
                params![format!("addr-{}", email_address), system_id, email_address, now],
            )?;
            Ok(())
        }).await
    }

    /// Activation-safe key write: first activation inserts, a repeat
    /// activation rotates the existing (system_id, domain_addr) row in place.
    /// The old raw key is invalid immediately (key_hash replaced).
    pub async fn upsert_api_key(&self, params: ApiKeyParams<'_>) -> AppResult<i64> {
        let ApiKeyParams {
            system_id,
            email_address,
            key_hash,
            key_prefix,
            scopes,
            expires_at,
            category,
        } = params;
        let (system_id, email_address, key_hash, key_prefix) = (
            system_id.to_string(),
            email_address.to_string(),
            key_hash.to_string(),
            key_prefix.to_string(),
        );
        let scopes_json = serde_json::to_string(scopes)
            .map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {e}")))?;
        let expires_at_owned = expires_at.map(String::from);
        let category = category.to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            let id: i64 = conn.query_row(
                "INSERT INTO api_keys (system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL, ?8)
                 ON CONFLICT(system_id, domain_addr) DO UPDATE SET
                   key_hash = excluded.key_hash,
                   key_prefix = excluded.key_prefix,
                   scopes = excluded.scopes,
                   is_active = 1,
                   expires_at = excluded.expires_at,
                   last_used_at = NULL
                 RETURNING id",
                params![system_id, email_address, key_hash, key_prefix, scopes_json, now, expires_at_owned, category],
                |r| r.get(0),
            )?;
            Ok(id)
        }).await
    }

    pub async fn insert_api_key(&self, params: ApiKeyParams<'_>) -> AppResult<ApiKeyRecord> {
        let ApiKeyParams {
            system_id,
            email_address,
            key_hash,
            key_prefix,
            scopes,
            expires_at,
            category,
        } = params;
        let (system_id, email_address, key_hash, key_prefix) = (
            system_id.to_string(),
            email_address.to_string(),
            key_hash.to_string(),
            key_prefix.to_string(),
        );
        let scopes_json = serde_json::to_string(scopes)
            .map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {e}")))?;
        let scopes_vec = scopes.to_vec();
        let expires_at_owned = expires_at.map(String::from);
        let category = category.to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO api_keys (system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL, ?8)",
                params![system_id, email_address, key_hash, key_prefix, scopes_json, now, expires_at_owned, category],
            )?;
            let id = conn.last_insert_rowid();
            Ok(ApiKeyRecord {
                id, system_id, email_address, key_hash, key_prefix,
                scopes: scopes_vec,
                is_active: true, created_at: now,
                expires_at: expires_at_owned, last_used_at: None,
                category,
                activation_code_hash: None,
                activation_expires_at: None,
                claimed_at: None,
            })
        }).await
    }

    pub async fn list_api_keys(&self) -> AppResult<Vec<ApiKeyRecord>> {
        self.call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys",
            )?;
            let rows = stmt.query_map((), api_key_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    pub async fn get_api_key(&self, id: i64) -> AppResult<Option<ApiKeyRecord>> {
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    pub async fn update_api_key(
        &self,
        id: i64,
        scopes: Option<Vec<String>>,
        is_active: Option<bool>,
    ) -> AppResult<Option<ApiKeyRecord>> {
        let scopes_vec = scopes;
        self.call_tx(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            if let Some(s) = scopes_vec {
                record.scopes = s;
            }
            if let Some(a) = is_active { record.is_active = a; }
            let scopes_json = serde_json::to_string(&record.scopes).map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {}", e)))?;
            conn.execute(
                "UPDATE api_keys SET scopes = ?1, is_active = ?2 WHERE id = ?3",
                params![scopes_json, record.is_active as i32, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    pub async fn delete_api_key(&self, id: i64) -> AppResult<()> {
        self.call(move |conn| {
            conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
    }

    /// Align an existing key's category + scopes in place (2026-09-26).
    ///
    /// Used by bootstrap paths that must bring a legacy system-category admin key up
    /// to the platform-category shape: the raw key value is untouched, so the
    /// credential seal (`key_hash`) and every secret derived from the raw key keep working.
    /// Only `category` and `scopes` change.
    pub async fn update_api_key_category_and_scopes(
        &self,
        id: i64,
        category: &str,
        scopes: &[String],
    ) -> AppResult<()> {
        let (category, scopes) = (category.to_string(), scopes.to_vec());
        self.call(move |conn| {
            let scopes_json = serde_json::to_string(&scopes)
                .map_err(|e| AppError::Internal(format!("serde_json::to_string failed: {}", e)))?;
            conn.execute(
                "UPDATE api_keys SET category = ?1, scopes = ?2 WHERE id = ?3",
                params![category, scopes_json, id],
            )?;
            Ok(())
        })
        .await
    }

    /// Rotate an API key: update the key_hash and key_prefix.
    pub async fn rotate_api_key(
        &self,
        id: i64,
        new_key_hash: &str,
        new_key_prefix: &str,
    ) -> AppResult<Option<ApiKeyRecord>> {
        let (new_key_hash, new_key_prefix) = (new_key_hash.to_string(), new_key_prefix.to_string());
        self.call_tx(move |conn| {
            let current = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE id = ?1",
                params![id],
                api_key_row,
            ).optional()?;
            let mut record = match current { Some(r) => r, None => return Ok(None) };
            record.key_hash = new_key_hash;
            record.key_prefix = new_key_prefix;
            conn.execute(
                "UPDATE api_keys SET key_hash = ?1, key_prefix = ?2 WHERE id = ?3",
                params![record.key_hash, record.key_prefix, record.id],
            )?;
            Ok(Some(record))
        }).await
    }

    /// List API keys filtered by system_id and category.
    pub async fn list_api_keys_by_system(
        &self,
        system_id: &str,
        category: &str,
    ) -> AppResult<Vec<ApiKeyRecord>> {
        let (system_id, category) = (system_id.to_string(), category.to_string());
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE system_id = ?1 AND category = ?2",
            )?;
            let rows = stmt.query_map(params![system_id, category], api_key_row)?;
            let mut results = Vec::new();
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Look up an API key by email address.
    pub async fn get_api_key_by_email(&self, email: &str) -> AppResult<Option<ApiKeyRecord>> {
        let email = email.to_string();
        self.call(move |conn| {
            let row = conn.query_row(
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE domain_addr = ?1 AND is_active = 1 LIMIT 1",
                params![email],
                api_key_row,
            ).optional()?;
            Ok(row)
        }).await
    }

    /// Update `last_used_at` for an API key (best-effort observability).
    pub async fn touch_api_key_last_used(&self, id: i64) -> AppResult<()> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                params![now, id],
            )?;
            Ok(())
        })
        .await
    }

    /// D5: batch-flush accumulated `last_used_at` updates (one UPDATE per key,
    /// all in a single transaction). Returns the number of keys written.
    pub async fn flush_api_keys_last_used(&self, ids: &[i64]) -> AppResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let ids: Vec<i64> = ids.to_vec();
        // call_tx = BEGIN IMMEDIATE + commit — the batch is one atomic write.
        self.call_tx(move |tx| {
            for id in &ids {
                tx.execute(
                    "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                    params![now, id],
                )
                .map_err(|e| AppError::Internal(format!("update last_used_at: {e}")))?;
            }
            Ok(ids.len())
        })
        .await
    }

    /// Candidate keys for signature verification, by caller identity.
    ///
    /// Identity is the key's `domain_addr` (address-scoped keys) or its
    /// `system_id` (system-level keys). It must be non-empty — the auth layer
    /// refuses empty identities before any database access (D1).
    ///
    /// The returned `key_hash` (= sha256 of the raw key) is the HMAC secret:
    /// the client derives the same value offline, so the raw key never
    /// crosses the wire (see docs/API-SIGNATURE-PROTOCOL.md).
    pub async fn list_api_keys_by_identity(&self, identity: &str) -> AppResult<Vec<ApiKeyRecord>> {
        let identity = identity.to_string();
        self.call(move |conn| {
            let mut results = Vec::new();
            // Fail closed: an empty identity matches no key. Without this
            // guard, `domain_addr = ''` / `system_id = ''` would match every
            // system-level key (their domain_addr is empty) — a full-table
            // scan by brute force. The auth layer already refuses empty
            // identities before any DB access; this is the second line.
            if identity.is_empty() {
                return Ok(results);
            }
            let mut stmt = conn.prepare(
                // D11: split the OR into two indexed lookups (UNION ALL) so each
                // half can SEARCH via idx_api_keys_lookup / idx_api_keys_system_id.
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) AND domain_addr = ?1
                 UNION ALL
                 SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) AND system_id = ?1",
            )?;
            let rows = stmt.query_map(params![identity], api_key_row)?;
            for row in rows { results.push(row?); }
            Ok(results)
        }).await
    }

    /// Verify an API key hash exists and is active.
    /// Returns the full ApiKeyRecord if valid, None if invalid/expired/deactivated.
    pub async fn verify_api_key(&self, key_hash: &str) -> AppResult<Option<ApiKeyRecord>> {
        // stored material may be sealed ("v1:"): an equality lookup must try both the **sealed form** and the historical plaintext form (migration/rollback windows).
        let sealed = crate::core::api::seal::seal_if_loaded(key_hash);
        let key_hash = key_hash.to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            let row = conn.query_row(
                // Use strftime with RFC 3339 format for date comparison.
                // datetime('now') produces "YYYY-MM-DD HH:MM:SS" (space-separated),
                // while expires_at may be stored in RFC 3339 with T separator,
                // which makes same-day comparison unreliable.
                "SELECT id, system_id, domain_addr, key_hash, key_prefix, scopes, is_active, created_at, expires_at, last_used_at, category, activation_code_hash, activation_expires_at, claimed_at FROM api_keys WHERE key_hash IN (?1, ?2) AND is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) LIMIT 1",
                params![sealed.clone().unwrap_or_else(|| key_hash.clone()), key_hash],
                api_key_row,
            ).optional()?;
            if let Some(ref record) = row {
                // Update last_used_at on successful verification (best-effort)
                // Use Chrono RFC 3339 format consistent with created_at and other tables.
                let _ = conn.execute(
                    "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                    params![now, record.id],
                );
            }
            Ok(row)
        }).await
    }

    /// Connection pool accessor for out-of-tree consumers that wrap this pool.
    /// Public interface: consumed by an out-of-tree build (raw SQL over the
    /// shared pool) — not dead code, the compiler just can't see it here.
    #[allow(dead_code)]
    pub fn raw_pool(&self) -> Pool<SqliteConnectionManager> {
        self.pool.clone()
    }

    // ── Public apply: outbound-mail readback ─────────────────────────

    /// Read actual queued outbound emails by recipient (the advanced pattern
    /// queues via create_outbound; tests and the /apply page read the spool
    /// or this queue — never a dedicated product table).
    pub async fn list_outbound_for_recipient(
        &self,
        to_addr: &str,
        limit: i64,
    ) -> AppResult<Vec<(String, String, String, String)>> {
        let (to_addr, limit) = (to_addr.to_string(), limit.clamp(1, 50));
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, subject, body, created_at FROM emails
                 WHERE direction = 'outbound' AND recipients LIKE '%' || ?1 || '%'
                 ORDER BY created_at DESC LIMIT ?2",
            )?;
            let mut rows = stmt.query(params![to_addr, limit])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
            }
            Ok(out)
        })
        .await
    }

    /// Distinct bare domains of the current (single) system, excluding the
    /// built-in admin relay and address rows.
    pub async fn current_system_domains(&self) -> AppResult<Vec<(String, String)>> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT system_id, domain_addr FROM system_domains
                 WHERE domain_addr NOT LIKE '%@%' AND domain_addr != 'admin.relay' AND is_active = 1
                 ORDER BY domain_addr",
            )?;
            let mut rows = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push((row.get(0)?, row.get(1)?));
            }
            Ok(out)
        })
        .await
    }

    // ── Activation Codes ──────────────────────────────────────────────

    /// Insert a new activation code. Returns the row ID.
    #[allow(clippy::too_many_arguments)] // explicit parameter list is deliberate: internal constructor/handler API
    pub async fn insert_activation_code(
        &self,
        code_hash: &str,
        code_prefix: &str,
        code_type: &str,
        system_id: &str,
        domain: &str,
        email_address: &str,
        expires_at: Option<&str>,
    ) -> AppResult<i64> {
        let (code_hash, code_prefix, code_type, system_id, domain, email_address) = (
            code_hash.to_string(),
            code_prefix.to_string(),
            code_type.to_string(),
            system_id.to_string(),
            domain.to_string(),
            email_address.to_string(),
        );
        let expires = expires_at.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO activation_codes (code_hash, code_prefix, code_type, system_id, domain, email_address, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![code_hash, code_prefix, code_type, system_id, domain, email_address, expires, now],
            )?;
            Ok(conn.last_insert_rowid())
        }).await
    }

    /// Look up an unclaimed, non-frozen, non-expired activation code.
    /// Returns (system_id, email_address) if valid, or None.
    pub async fn lookup_activation_code(
        &self,
        code_hash: &str,
    ) -> AppResult<Option<(String, String)>> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT system_id, email_address FROM activation_codes
                 WHERE code_hash = ?1 AND claimed = 0 AND is_frozen = 0
                 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            )?;
            let mut rows = stmt.query(params![code_hash])?;
            if let Some(row) = rows.next()? {
                Ok(Some((
                    row.get(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                )))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Full metadata for preflight (does NOT consume the code).
    pub async fn lookup_activation_code_meta(
        &self,
        code_hash: &str,
    ) -> AppResult<Option<(String, String, String, String, bool, Option<String>, bool)>> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT code_type, system_id, domain, COALESCE(email_address,''), claimed, expires_at, is_frozen
                 FROM activation_codes WHERE code_hash = ?1",
            )?;
            let mut rows = stmt.query(params![code_hash])?;
            if let Some(row) = rows.next()? {
                Ok(Some((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get(5)?,
                    row.get::<_, i64>(6)? != 0,
                )))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Mark an activation code as claimed.
    /// Returns true if the claim succeeded (code existed and was unclaimed),
    /// false if the code was already claimed or no longer present.
    pub async fn claim_activation_code(
        &self,
        code_hash: &str,
        claimed_by: &str,
    ) -> AppResult<bool> {
        let (code_hash, claimed_by) = (code_hash.to_string(), claimed_by.to_string());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.call(move |conn| {
            let affected = conn.execute(
                "UPDATE activation_codes SET claimed = 1, claimed_at = ?2, claimed_by = ?3
                 WHERE code_hash = ?1 AND claimed = 0",
                params![code_hash, now, claimed_by],
            )?;
            Ok(affected == 1)
        })
        .await
    }

    /// Delete an activation code after use (codes are single-use, no accumulation).
    pub async fn delete_activation_code(&self, code_hash: &str) -> AppResult<()> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            conn.execute(
                "DELETE FROM activation_codes WHERE code_hash = ?1",
                params![code_hash],
            )?;
            Ok(())
        })
        .await
    }

    /// Record the applicant's email on a self-service applied code
    /// (written at apply time, before redemption). The applicant becomes the
    /// address's default manager (safety officer) when the code is activated —
    /// mirroring the admin registration path, where the manager is resolved and
    /// bound at registration. Column name matches the advanced gateway's
    /// activation-code structure (`applicant_email`) so both editions share the
    /// same activation-code schema.
    pub async fn set_activation_code_applicant(
        &self,
        code_hash: &str,
        applicant_email: &str,
    ) -> AppResult<()> {
        let (code_hash, applicant_email) = (code_hash.to_string(), applicant_email.to_string());
        self.call(move |conn| {
            conn.execute(
                "UPDATE activation_codes SET applicant_email = ?2 WHERE code_hash = ?1",
                params![code_hash, applicant_email],
            )?;
            Ok(())
        })
        .await
    }

    /// Read the applicant's email bound to a self-service applied code.
    /// `None` for admin/batch codes (no applicant recorded).
    pub async fn get_activation_code_applicant(
        &self,
        code_hash: &str,
    ) -> AppResult<Option<String>> {
        let code_hash = code_hash.to_string();
        self.call(move |conn| {
            let v: Option<String> = conn
                .query_row(
                    "SELECT COALESCE(applicant_email, '') FROM activation_codes WHERE code_hash = ?1",
                    params![code_hash],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(v.filter(|s| !s.is_empty()))
        })
        .await
    }

    // Pending deliveries (pull mode — aimail-bridge long-poll)
    pub async fn insert_pending_delivery(
        &self,
        system_id: &str,
        domain_addr: &str,
        email: &str,
        headers_json: &str,
        payload_json: &str,
    ) -> AppResult<i64> {
        let sid = system_id.to_string();
        let da = domain_addr.to_string();
        let em = email.to_string();
        let hdrs = headers_json.to_string();
        let pl = payload_json.to_string();
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO pending_deliveries (system_id, domain_addr, email, headers, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sid, da, em, hdrs, pl],
            )?;
            Ok(conn.last_insert_rowid())
        }).await
    }

    /// Count pending-delivery rows whose payload references `mail_id`
    /// (the pull payload carries the source mail id as top-level `mail_id`).
    pub async fn count_pending_for_mail_id(&self, mail_id: &str) -> AppResult<i64> {
        let mid = mail_id.to_string();
        self.call(move |conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pending_deliveries WHERE json_extract(payload, '$.mail_id') = ?1",
                params![mid],
                |r| r.get(0),
            )?;
            Ok(n)
        })
        .await
    }

    pub async fn list_pending_deliveries(
        &self,
        system_id: &str,
        limit: i64,
        domains: Option<&[String]>,
    ) -> AppResult<Vec<PendingDeliveryRecord>> {
        let sid = system_id.to_string();
        let domain_filter = domains.map(|d| d.to_vec());
        self.call(move |conn| {
            let mut sql =
                "SELECT id, system_id, domain_addr, email, headers, payload, status, created_at
                 FROM pending_deliveries
                 WHERE system_id = ?1"
                    .to_string();
            if let Some(ref domains) = domain_filter {
                if !domains.is_empty() {
                    let mut conditions: Vec<String> = Vec::new();
                    for _ in domains.iter() {
                        // Parameterized LIKE: value is bound, never interpolated
                        // (AUDIT-1 P1-1: raw format! allowed SQL injection via
                        // malicious domain strings from authenticated clients).
                        // Placeholders: ?1=system_id, ?2=limit, ?3+ = LIKE values.
                        conditions.push(format!("domain_addr LIKE ?{}", conditions.len() + 3));
                    }
                    sql.push_str(&format!(" AND ({})", conditions.join(" OR ")));
                }
            }
            sql.push_str(" ORDER BY created_at ASC LIMIT ?2");
            let mut stmt = conn.prepare(&sql)?;
            // Build param list: system_id, limit, then one LIKE value per domain
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
                vec![Box::new(sid.clone()), Box::new(limit)];
            if let Some(ref domains) = domain_filter {
                for d in domains.iter() {
                    params.push(Box::new(format!("%@{}", d)));
                }
            }
            let rows = stmt.query_map(
                rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
                |r| {
                    Ok(PendingDeliveryRecord {
                        id: r.get(0)?,
                        system_id: r.get(1)?,
                        domain_addr: r.get(2)?,
                        email: r.get(3)?,
                        headers: r.get(4)?,
                        payload: r.get(5)?,
                        status: r.get(6)?,
                        created_at: r.get(7)?,
                    })
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(crate::core::errors::AppError::from)
        })
        .await
    }

    /// Agent-scoped pending query: rows for ONE (system_id, email) only.
    /// Email-dimension query: the isolation key must match the storage filter
    /// exactly (§2.5: scope IS the range; a key can only ever see its own
    /// address).
    pub async fn list_pending_by_email(
        &self,
        system_id: &str,
        email: &str,
        limit: i64,
    ) -> AppResult<Vec<PendingDeliveryRecord>> {
        let (sid, e) = (system_id.to_string(), email.to_string());
        let lim = limit.clamp(1, 200);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, system_id, domain_addr, email, headers, payload, status, created_at
                 FROM pending_deliveries
                 WHERE system_id = ?1 AND email = ?2 AND status = 'pending'
                 ORDER BY id ASC LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![sid, e, lim], |r| {
                    Ok(PendingDeliveryRecord {
                        id: r.get(0)?,
                        system_id: r.get(1)?,
                        domain_addr: r.get(2)?,
                        email: r.get(3)?,
                        headers: r.get(4)?,
                        payload: r.get(5)?,
                        status: r.get(6)?,
                        created_at: r.get(7)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .await
    }

    /// AgentSystemId aggregation: pending rows for every address owned by the
    /// local Agent-system instance. The join is on BOTH address and system id
    /// so a coincidentally same-named address in another system is excluded.
    pub async fn list_pending_for_agent_system(
        &self,
        agent_system_id: &str,
        limit: i64,
    ) -> AppResult<Vec<PendingDeliveryRecord>> {
        let id = agent_system_id.to_string();
        let lim = limit.clamp(1, 200);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT p.id, p.system_id, p.domain_addr, p.email, p.headers, p.payload,
                        p.status, p.created_at
                 FROM pending_deliveries p
                 JOIN agent_system_addresses a
                   ON a.address = p.email AND a.system_id = p.system_id
                 WHERE a.agent_system_id = ?1 AND p.status = 'pending'
                 ORDER BY p.id ASC LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![id, lim], |r| {
                    Ok(PendingDeliveryRecord {
                        id: r.get(0)?,
                        system_id: r.get(1)?,
                        domain_addr: r.get(2)?,
                        email: r.get(3)?,
                        headers: r.get(4)?,
                        payload: r.get(5)?,
                        status: r.get(6)?,
                        created_at: r.get(7)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .await
    }

    /// AgentSystemId-scoped ack: only rows whose address is owned by this
    /// Agent-system instance can be deleted.
    pub async fn ack_pending_for_agent_system(
        &self,
        agent_system_id: &str,
        ids: &[i64],
    ) -> AppResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let id = agent_system_id.to_string();
        let id_list = ids.to_vec();
        self.call(move |conn| {
            let placeholders: Vec<String> =
                (2..=id_list.len() + 1).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "DELETE FROM pending_deliveries
                 WHERE id IN ({})
                   AND EXISTS (
                     SELECT 1 FROM agent_system_addresses a
                     WHERE a.agent_system_id = ?1
                       AND a.address = pending_deliveries.email
                       AND a.system_id = pending_deliveries.system_id
                   )",
                placeholders.join(",")
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(id)];
            for id in id_list.iter() {
                params.push(Box::new(*id));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let n = conn.execute(&sql, param_refs.as_slice())?;
            Ok(n)
        })
        .await
    }

    /// Agent-scoped ack: delete ONLY rows whose (system_id, email) match —
    /// cross-address ids affect 0 rows (ownership check: ids outside the
    /// (system_id, email) scope are simply not matched).
    pub async fn ack_pending_by_email(
        &self,
        system_id: &str,
        email: &str,
        ids: &[i64],
    ) -> AppResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let (sid, e) = (system_id.to_string(), email.to_string());
        let id_list = ids.to_vec();
        self.call(move |conn| {
            let placeholders: Vec<String> =
                (1..=id_list.len() + 2).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "DELETE FROM pending_deliveries WHERE system_id = ?1 AND email = ?2 AND id IN ({})",
                placeholders.join(",")
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(sid), Box::new(e)];
            for id in id_list.iter() {
                params.push(Box::new(*id));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let n = conn.execute(&sql, param_refs.as_slice())?;
            Ok(n)
        })
        .await
    }

    /// System/bridge-scoped ack: delete rows by id, RESTRICTED to the
    /// calling key's own system (identity from auth, never from the
    /// request body) — cross-system ids affect 0 rows.
    pub async fn ack_deliveries(&self, system_id: &str, ids: &[i64]) -> AppResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let sid = system_id.to_string();
        let id_list = ids.to_vec();
        self.call(move |conn| {
            let placeholders: Vec<String> =
                (2..=id_list.len() + 1).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "DELETE FROM pending_deliveries WHERE system_id = ?1 AND id IN ({})",
                placeholders.join(",")
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(sid)];
            for id in id_list.iter() {
                params.push(Box::new(*id));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let n = conn.execute(&sql, param_refs.as_slice())?;
            Ok(n)
        })
        .await
    }

    pub async fn cleanup_deliveries(&self, ttl_hours: u64) -> AppResult<()> {
        let ttl = ttl_hours as i64;
        let delivered_cutoff = format!("-{} days", DELIVERED_AUDIT_RETENTION_DAYS);
        self.call(move |conn| {
            // Clean delivered entries older than the audit retention window
            conn.execute(
                "DELETE FROM pending_deliveries WHERE status = 'delivered' AND created_at < datetime('now', ?1)",
                [&delivered_cutoff],
            )?;
            // Clean stale pending entries older than configured TTL
            let ttl_sql = format!("-{} hours", ttl);
            let deleted = conn.execute(
                "DELETE FROM pending_deliveries WHERE status = 'pending' AND created_at < datetime('now', ?1)",
                [&ttl_sql],
            )?;
            if deleted > 0 {
                tracing::info!(count = deleted, ttl_hours = ttl_hours,
                    "Cleaned stale pending deliveries");
            }
            Ok(())
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db() -> Database {
        temp_db_with_path().0
    }

    fn temp_db_with_path() -> (Database, std::path::PathBuf) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-test-{}", ts));
        std::fs::create_dir_all(&dir).unwrap();
        // Database::open expects the SQLite FILE path (like main.rs passes
        // config.storage.db_path() = <dir>/aimail.db), not a directory.
        let path = dir.join("aimail.db");
        let db = Database::open(&path, 4, None).unwrap();
        (db, path)
    }

    /// Unique on-disk SQLite file with only the given DDL (raw rusqlite, so
    /// Database::open's migration path is what under test).
    fn scratch_db_with_ddl(ddl: &str) -> (std::path::PathBuf, rusqlite::Connection) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aimailgw-legacy-{}", ts));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aimail.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(ddl).unwrap();
        (path, conn)
    }

    fn table_names(conn: &rusqlite::Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    fn activation_code_columns(conn: &rusqlite::Connection) -> Vec<String> {
        let mut stmt = conn.prepare("PRAGMA table_info(activation_codes)").unwrap();
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    /// The advanced gateway's activation-code structure — base must stay
    /// column-for-column identical (the whole point of the V2 cleanup).
    const ADVANCED_ACTIVATION_COLUMNS: &[&str] = &[
        "id",
        "code_hash",
        "code_prefix",
        "code_cipher",
        "code_type",
        "product_id",
        "system_id",
        "domain",
        "email_address",
        "applicant_email",
        "claimed",
        "claimed_at",
        "claimed_by",
        "expires_at",
        "is_frozen",
        "is_shipped",
        "created_by",
        "created_at",
    ];

    /// Column SET parity (not physical order): legacy databases gain the
    /// column via ADD COLUMN (appended), while fresh ones carry it in the
    /// CREATE TABLE — both editions do the same, so order is a physical
    /// artifact; the invariant is "same 18 columns, no more no less".
    fn assert_advanced_aligned(conn: &rusqlite::Connection) {
        let mut got = activation_code_columns(conn);
        let mut want: Vec<String> = ADVANCED_ACTIVATION_COLUMNS
            .iter()
            .map(|s| s.to_string())
            .collect();
        got.sort();
        want.sort();
        assert_eq!(
            got, want,
            "activation_codes must match the advanced column structure exactly"
        );
    }

    #[tokio::test]
    async fn fresh_db_has_advanced_activation_schema_and_no_fixture_tables() {
        let (db, _path) = temp_db_with_path();
        db.call(|conn| {
            let tables = table_names(conn);
            assert!(
                !tables.contains(&"email_verifications".to_string()),
                "email_verifications must not exist (in-process verification instead)"
            );
            assert!(
                !tables.contains(&"mock_inbox".to_string()),
                "mock_inbox must not exist (test fixtures live in files, not the product DB)"
            );
            assert!(tables.contains(&"agent_system_addresses".to_string()));
            assert_advanced_aligned(conn);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn v1_0_10_db_converges_on_open() {
        // v1.0.10 shape: requester_email column + the two fixture tables.
        let (path, seed) = scratch_db_with_ddl(
            "CREATE TABLE activation_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE, code_prefix TEXT NOT NULL,
                code_cipher TEXT,
                code_type TEXT NOT NULL CHECK(code_type IN ('address','product')),
                product_id TEXT, system_id TEXT,
                domain TEXT, email_address TEXT,
                requester_email TEXT,
                claimed INTEGER NOT NULL DEFAULT 0,
                claimed_at TEXT, claimed_by TEXT, expires_at TEXT,
                is_frozen INTEGER NOT NULL DEFAULT 0,
                is_shipped INTEGER NOT NULL DEFAULT 0,
                created_by TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            INSERT INTO activation_codes (code_hash, code_prefix, code_type, email_address, requester_email)
            VALUES ('h1', 'addr-', 'address', 'a@x.test', 'old-applicant@x.test');
            CREATE TABLE email_verifications (email TEXT PRIMARY KEY);
            CREATE TABLE mock_inbox (id INTEGER PRIMARY KEY);
            CREATE TABLE _schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
            INSERT INTO _schema_version (id, version) VALUES (1, 1);",
        );
        // Pre-seed a row in the fixture tables: dropping them is expected.
        seed.execute("INSERT INTO mock_inbox (id) VALUES (1)", [])
            .unwrap();
        drop(seed);

        let db = Database::open(&path, 4, None).unwrap();
        db.call(|conn| {
            let tables = table_names(conn);
            assert!(
                !tables.contains(&"email_verifications".to_string()),
                "legacy email_verifications must be dropped on upgrade"
            );
            assert!(
                !tables.contains(&"mock_inbox".to_string()),
                "legacy mock_inbox must be dropped on upgrade"
            );
            assert_advanced_aligned(conn);
            // The applicant value must survive the RENAME COLUMN.
            let kept: Option<String> = conn
                .query_row(
                    "SELECT applicant_email FROM activation_codes WHERE code_hash = 'h1'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            assert_eq!(kept.as_deref(), Some("old-applicant@x.test"));
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pre_1_0_10_db_gains_applicant_column_on_open() {
        // 1.0.0 baseline shape: no requester/applicant column at all.
        let (path, _seed) = scratch_db_with_ddl(
            "CREATE TABLE activation_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE, code_prefix TEXT NOT NULL,
                code_cipher TEXT,
                code_type TEXT NOT NULL CHECK(code_type IN ('address','product')),
                product_id TEXT, system_id TEXT,
                domain TEXT, email_address TEXT,
                claimed INTEGER NOT NULL DEFAULT 0,
                claimed_at TEXT, claimed_by TEXT, expires_at TEXT,
                is_frozen INTEGER NOT NULL DEFAULT 0,
                is_shipped INTEGER NOT NULL DEFAULT 0,
                created_by TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE TABLE _schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
            INSERT INTO _schema_version (id, version) VALUES (1, 1);",
        );
        drop(_seed);

        let db = Database::open(&path, 4, None).unwrap();
        db.call(|conn| {
            assert_advanced_aligned(conn);
            let legacy: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('activation_codes') WHERE name = 'requester_email'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(legacy, 0, "requester_email must not be introduced");
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pending_domains_filter_is_parameterized() {
        // AUDIT-1 P1-1: a malicious domain string must be treated as a literal
        // LIKE pattern, never spliced into SQL.
        let db = temp_db();
        db.insert_pending_delivery("sys1", "agent@good.test", "agent@good.test", "{}", "{}")
            .await
            .unwrap();
        db.insert_pending_delivery("sys1", "agent@evil.com", "agent@evil.com", "{}", "{}")
            .await
            .unwrap();

        // Injection attempt: closes the LIKE, ORs a tautology, comments out the rest.
        let evil = "x' OR '1'='1";
        let rows = db
            .list_pending_deliveries("sys1", 50, Some(&[evil.to_string()]))
            .await
            .unwrap();
        // No rows match the literal pattern "%@x' OR '1'='1" → empty.
        assert!(rows.is_empty(), "injection must not return rows");

        // Normal filter still works.
        let rows = db
            .list_pending_deliveries("sys1", 50, Some(&["good.test".to_string()]))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].email, "agent@good.test");
    }

    #[tokio::test]
    async fn list_pending_by_email_isolates_to_one_address() {
        let db = temp_db();
        db.insert_pending_delivery("sys1", "a@x.test", "a@x.test", "{}", "{}")
            .await
            .unwrap();
        db.insert_pending_delivery("sys1", "b@x.test", "b@x.test", "{}", "{}")
            .await
            .unwrap();
        db.insert_pending_delivery("sys2", "a@x.test", "a@x.test", "{}", "{}")
            .await
            .unwrap();

        // Same email under a DIFFERENT system is invisible.
        let rows = db
            .list_pending_by_email("sys1", "a@x.test", 200)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].system_id, "sys1");
        assert_eq!(rows[0].email, "a@x.test");

        // Other address of the same system is invisible.
        let rows = db
            .list_pending_by_email("sys1", "b@x.test", 200)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].email, "b@x.test");

        // No row ⇒ empty, no error.
        let rows = db
            .list_pending_by_email("sys1", "nobody@x.test", 200)
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn ack_pending_by_email_only_deletes_matching_address() {
        let db = temp_db();
        let id_a = db
            .insert_pending_delivery("sys1", "a@x.test", "a@x.test", "{}", "{}")
            .await
            .unwrap();
        let id_b = db
            .insert_pending_delivery("sys1", "b@x.test", "b@x.test", "{}", "{}")
            .await
            .unwrap();
        let id_a_sys2 = db
            .insert_pending_delivery("sys2", "a@x.test", "a@x.test", "{}", "{}")
            .await
            .unwrap();

        // Cross-address ids affect 0 rows (ownership check §2.5).
        let n = db
            .ack_pending_by_email("sys1", "a@x.test", &[id_b, id_a_sys2])
            .await
            .unwrap();
        assert_eq!(n, 0, "cross-address/cross-system ids must not delete");
        let remaining = db
            .list_pending_by_email("sys1", "a@x.test", 200)
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1, "own row must survive");

        // Own id deletes exactly 1.
        let n = db
            .ack_pending_by_email("sys1", "a@x.test", &[id_a])
            .await
            .unwrap();
        assert_eq!(n, 1);
        let remaining = db
            .list_pending_by_email("sys1", "a@x.test", 200)
            .await
            .unwrap();
        assert!(remaining.is_empty());

        // Empty ids short-circuits to 0.
        assert_eq!(
            db.ack_pending_by_email("sys1", "a@x.test", &[])
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn active_domain_query_excludes_deactivated() {
        // AUDIT-1 P2-4
        let db = temp_db();
        db.insert_system_domain("d1", "sys1", "active.test", Some("http://a"), None)
            .await
            .unwrap();
        db.insert_system_domain("d2", "sys1", "dead.test", Some("http://d"), None)
            .await
            .unwrap();
        db.update_system_domain("d2", None, None, Some(false))
            .await
            .unwrap();

        assert!(db
            .get_active_system_domain_by_domain("active.test")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .get_active_system_domain_by_domain("dead.test")
            .await
            .unwrap()
            .is_none());
    }

    /// REGRESSION (cache invalidation): a write must evict the positive domain
    /// lookup cache, otherwise readers keep seeing the PRE-update row for up to
    /// the 30s TTL. Measured production symptom: after `PUT is_active=false`
    /// the probe still answered `{exists:true, valid:true}` until t+30.1s.
    #[tokio::test]
    async fn update_system_domain_is_visible_immediately_after_write() {
        let db = temp_db();
        db.insert_system_domain("d1", "sys1", "alice@x.com", Some("http://old"), None)
            .await
            .unwrap();

        // 1) Warm the cache with a positive hit — the precondition of the bug.
        let cached = db
            .get_system_domain_by_name("alice@x.com")
            .await
            .unwrap()
            .expect("seeded row");
        assert_eq!(cached.webhook_url.as_deref(), Some("http://old"));
        assert!(
            db.domain_cache.read().unwrap().contains_key("alice@x.com"),
            "fixture must seed the cache, otherwise this test proves nothing"
        );

        // 2) Update the webhook and deactivate.
        let updated = db
            .update_system_domain("d1", Some("http://new"), None, Some(false))
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(updated.webhook_url.as_deref(), Some("http://new"));
        assert!(!updated.is_active);

        // 3) The very next read must already reflect the write — no sleep, no
        //    TTL wait.
        let fresh = db
            .get_system_domain_by_name("alice@x.com")
            .await
            .unwrap()
            .expect("row still exists");
        assert_eq!(
            fresh.webhook_url.as_deref(),
            Some("http://new"),
            "stale cache: update_system_domain must invalidate the domain cache"
        );
        assert!(!fresh.is_active, "deactivation must be visible immediately");

        // 4) The cache still caches: the read above repopulated the positive
        //    entry (invalidation, not disabling — TTL semantics preserved).
        let cache = db.domain_cache.read().unwrap();
        assert_eq!(cache.len(), 1);
        let (_, rec) = cache.get("alice@x.com").expect("positive hit re-cached");
        assert_eq!(
            rec.as_ref().unwrap().webhook_url.as_deref(),
            Some("http://new")
        );
    }

    /// REGRESSION (cache invalidation, rename path): `rename_agent_address_refs`
    /// re-keys the `system_domains` row, so a cached lookup under the OLD
    /// address must be evicted — otherwise readers resolve an address that no
    /// longer exists for the whole TTL.
    #[tokio::test]
    async fn rename_agent_address_evicts_cached_old_lookup() {
        let db = temp_db();
        db.insert_system_domain("d1", "sys1", "old@x.com", Some("http://w"), None)
            .await
            .unwrap();
        db.get_system_domain_by_name("old@x.com")
            .await
            .unwrap()
            .expect("seeded row");
        assert!(db.domain_cache.read().unwrap().contains_key("old@x.com"));

        db.rename_agent_address_refs("old@x.com", "new@x.com")
            .await
            .unwrap();

        assert!(
            db.get_system_domain_by_name("old@x.com")
                .await
                .unwrap()
                .is_none(),
            "a renamed-away address must not be served from the cache"
        );
        let rec = db
            .get_system_domain_by_name("new@x.com")
            .await
            .unwrap()
            .expect("renamed row");
        assert_eq!(rec.domain, "new@x.com");
        assert_eq!(rec.webhook_url.as_deref(), Some("http://w"));
    }

    #[tokio::test]
    async fn whitelist_conflict_overwrites_direction() {
        // Recreate = overwrite: direction is one of (to/from/all) per
        // (system_id, domain_addr, value); a later create with a different
        // direction replaces the existing rule (last write wins). This is
        // what makes the to→from→all sequence (category-4 4.3a/4.3c/4.3d)
        // work — previously the frozen-direction behavior (AUDIT-1 P2-7)
        // made a second direction un-persistable.
        let db = temp_db();
        db.insert_whitelist("sys1", "a@x.com", "from", "v@y.com", "system", None, None)
            .await
            .unwrap();
        db.insert_whitelist("sys1", "a@x.com", "to", "v@y.com", "system", None, None)
            .await
            .unwrap();
        let rec = db
            .get_whitelist("sys1", "a@x.com", "v@y.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.direction, "to", "later create overwrites direction");
        // Single row, not two.
        let n: i64 = db
            .call(|conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM whitelists WHERE system_id='sys1' AND domain_addr='a@x.com' AND value='v@y.com'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(n, 1, "one row per (system_id, domain_addr, value)");
    }

    #[tokio::test]
    async fn endpoint_status_update_targets_existing_keys() {
        // Regression: a broken json_set path (`$.\"dom\".status` containing a
        // literal backslash) matched no key and instead created a garbage
        // key — the original endpoint stayed "pending" forever, so
        // check_all_endpoints_completed never returned true and webhook
        // delivery was retried indefinitely (re-running interceptors,
        // re-creating boards, rotating member tokens).
        let db = temp_db();
        let endpoints = r#"{"orch@y.com":{"url":"http://a","status":"pending"},"ver@y.com":{"url":"http://b","status":"pending"}}"#;
        db.insert_email(
            "e1",
            "sys1",
            "outbound",
            "s@x.com",
            "r@y.com",
            "subj",
            "body",
            Some(endpoints),
            None,
            None,
            3,
        )
        .await
        .unwrap();

        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "both pending → not all completed"
        );

        assert!(
            db.update_email_endpoint_status("e1", "orch@y.com", "success")
                .await
                .unwrap(),
            "known endpoint key must match"
        );
        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "one endpoint still pending → not all completed"
        );

        assert!(db
            .update_email_endpoint_status("e1", "ver@y.com", "success")
            .await
            .unwrap());
        assert!(
            db.check_all_endpoints_completed("e1").await.unwrap(),
            "all endpoints success → completed"
        );

        // No garbage key: the endpoints column must contain exactly the two
        // original domains (the old bug created a `\"orch@y.com` key and left
        // the real ones pending).
        let rec = db.get_email("e1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(rec.endpoints.as_deref().unwrap()).unwrap();
        let obj = v.as_object().expect("endpoints is a JSON object");
        assert_eq!(obj.len(), 2, "no garbage keys in endpoints JSON");
        assert!(obj.contains_key("orch@y.com"));
        assert!(obj.contains_key("ver@y.com"));
    }

    #[tokio::test]
    async fn endpoint_status_update_creates_key_from_null_endpoints() {
        // Regression: pull-mode (bridge) domains build NO endpoint key at
        // insert time, so `endpoints` is NULL. SQLite `json_set(NULL, ...)`
        // returns NULL — the success mark was lost,
        // check_all_endpoints_completed stayed false, and the scheduler
        // treated the successful delivery as a failure, retrying to
        // max_attempts and re-inserting a pending delivery on every pass
        // (the 3x delivery storm). COALESCE(endpoints, '{}') makes the
        // success mark land and the email complete on first delivery.
        let db = temp_db();
        db.insert_email(
            "e1",
            "sys1",
            "inbound",
            "ext@x.com",
            "agent@pull.test",
            "subj",
            "body",
            None,
            None,
            None,
            3,
        )
        .await
        .unwrap();

        assert!(
            !db.check_all_endpoints_completed("e1").await.unwrap(),
            "NULL endpoints → not completed (nothing delivered yet)"
        );

        assert!(
            db.update_email_endpoint_status("e1", "pull.test", "success")
                .await
                .unwrap(),
            "NULL endpoints must gain the key, not stay NULL"
        );
        assert!(
            db.check_all_endpoints_completed("e1").await.unwrap(),
            "success mark must make the email complete"
        );

        // The key landed with the right status and nothing else.
        let rec = db.get_email("e1").await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(rec.endpoints.as_deref().unwrap()).unwrap();
        let obj = v.as_object().expect("endpoints is a JSON object");
        assert_eq!(obj.len(), 1);
        assert_eq!(
            obj["pull.test"]["status"].as_str(),
            Some("success"),
            "status written under the domain key"
        );
    }

    // ── readying → ready → sending state machine ────────────────────
    //
    // The flake this guards: a tick batch used to see a freshly-inserted
    // inbound email (born `ready`) before its attachments were saved, and
    // delivered a payload with an empty attachment list. Now every email is
    // born `readying` and the tick only ever reads `ready`, so the race is
    // structurally impossible. These tests pin each invariant down.

    /// Activation-confirmation rows (the Cc copies that make reply-activation
    /// work) are retained in `emails` past the normal NDR window and removed
    /// only once the activation code itself expires — the cleanup batch reads
    /// `x-aimail-activation-expires-at` in preference to `last_sent_at`.
    #[tokio::test]
    async fn delivered_expired_prefers_activation_expiry_header() {
        let db = temp_db();
        let confirm = |expires: &str| {
            serde_json::json!({
                "x-aimail-activation-confirm": "1",
                "x-aimail-activation-expires-at": expires,
            })
            .to_string()
        };
        let future = confirm("2099-01-01T00:00:00.000Z");
        let past = confirm("2000-01-01T00:00:00.000Z");
        db.insert_email(
            "exp-plain",
            "sys1",
            "inbound",
            "a@x.com",
            "{}",
            "s",
            "b",
            None,
            None,
            None,
            3,
        )
        .await
        .unwrap();
        db.insert_email(
            "exp-live",
            "sys1",
            "inbound",
            "no-reply@x.com",
            "{}",
            "s",
            "b",
            None,
            None,
            Some(&future),
            3,
        )
        .await
        .unwrap();
        db.insert_email(
            "exp-stale",
            "sys1",
            "inbound",
            "no-reply@x.com",
            "{}",
            "s",
            "b",
            None,
            None,
            Some(&past),
            3,
        )
        .await
        .unwrap();
        for id in ["exp-plain", "exp-live", "exp-stale"] {
            db.update_email_delivered(id).await.unwrap();
        }

        // A cutoff one hour ahead expires the plain row (last_sent_at ≈ now)
        // and the already-expired confirmation — but never the live one.
        let cutoff = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let expired: Vec<String> = db
            .get_delivered_expired_before(&cutoff, 50)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(expired.contains(&"exp-plain".to_string()), "{expired:?}");
        assert!(expired.contains(&"exp-stale".to_string()), "{expired:?}");
        assert!(
            !expired.contains(&"exp-live".to_string()),
            "a live activation confirmation must survive the NDR window: {expired:?}"
        );

        // Once the code expires, the same row is collected too.
        let after = (chrono::Utc::now() + chrono::Duration::days(365 * 200))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let later: Vec<String> = db
            .get_delivered_expired_before(&after, 50)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(later.contains(&"exp-live".to_string()), "{later:?}");
    }

    #[tokio::test]
    async fn born_state_is_readying() {
        // Invariant 1: every insert lands in `readying`, never `ready`.
        let db = temp_db();
        db.insert_email(
            "born1", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        let rec = db.get_email("born1").await.unwrap().unwrap();
        assert_eq!(rec.status, "readying");
    }

    #[tokio::test]
    async fn readying_invisible_to_tick_and_overlimit() {
        // Invariant 2 (the flake fix): the tick (Flow 2) and the overlimit
        // fetch (Flow 1) only read `ready`. A born `readying` email is
        // invisible to both, so a half-prepared payload can never be
        // delivered early. Once flipped to `ready`, the tick sees it.
        let db = temp_db();
        db.insert_email(
            "inv1", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        assert!(
            db.get_pending_retry_emails(10).await.unwrap().is_empty(),
            "tick must not see a readying email"
        );
        assert!(
            db.get_overlimit_emails(10).await.unwrap().is_empty(),
            "overlimit fetch must not see a readying email"
        );

        // Flip to ready (what crash recovery / retry fallback do) → visible.
        assert!(db.flip_readying_to_ready("inv1").await.unwrap());
        assert_eq!(db.get_pending_retry_emails(10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn claim_ready_accepts_readying_and_ready() {
        // Invariant 3: the trigger claims from either state via CAS.
        // `readying` (first delivery) and `ready` (recovery / retry
        // fallback) are both claimable; a second claim must fail
        // (single-delivery guarantee).
        let db = temp_db();
        db.insert_email(
            "c1", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        let first = db.claim_ready("c1").await.unwrap();
        assert!(first.is_some(), "trigger must claim a readying email");
        assert_eq!(first.unwrap().status, "sending");
        assert!(
            db.claim_ready("c1").await.unwrap().is_none(),
            "double claim must fail — single delivery"
        );

        // A `ready` email (retry fallback) is claimable too; `sending` is not.
        db.insert_email(
            "c2", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        db.flip_readying_to_ready("c2").await.unwrap();
        assert!(db.claim_ready("c2").await.unwrap().is_some());
        assert!(db.claim_ready("c2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn flip_readying_is_cas() {
        // Invariant 4: the crash-recovery flip is a no-op once a trigger has
        // already claimed the email (flip-vs-claim race resolves safely).
        let db = temp_db();
        db.insert_email(
            "f1", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        assert!(db.claim_ready("f1").await.unwrap().is_some());
        assert!(
            !db.flip_readying_to_ready("f1").await.unwrap(),
            "flip must not resurrect a claimed email"
        );
    }

    #[tokio::test]
    async fn ready_retry_relands_in_ready_not_readying() {
        // Invariant 5: a failed delivery falls back to `ready` (with a
        // backoff), never back to `readying` — so a retry is always
        // tick-claimable and can never re-enter the hidden birth state.
        let db = temp_db();
        db.insert_email(
            "r1", "sys1", "inbound", "a@x.com", "{}", "s", "b", None, None, None, 3,
        )
        .await
        .unwrap();
        db.claim_ready("r1").await.unwrap(); // trigger → sending
        let rec = db
            .update_email_ready_retry("r1", 1, "2099-01-01T00:00:00Z")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.status, "ready");
        // Past-due retry is visible to the tick.
        db.update_email_ready_retry("r1", 1, "2000-01-01T00:00:00Z")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(db.get_pending_retry_emails(10).await.unwrap().len(), 1);
    }

    /// Seed the board tables the migration touches (Database::open only
    /// creates the core schema; board tables are created by the board module).
    fn seed_board_tables(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS boards (
                id TEXT PRIMARY KEY, short_id TEXT UNIQUE NOT NULL,
                board_email TEXT NOT NULL, goal TEXT, status TEXT DEFAULT 'active',
                output_task_id TEXT, plan_version TEXT, plan_text TEXT,
                plan_confirmed_at TEXT, criteria_version TEXT, criteria_text TEXT,
                criteria_confirmed_at TEXT, created_at TEXT, completed_at TEXT, system_id TEXT
            );
            CREATE TABLE IF NOT EXISTS board_members (
                email TEXT PRIMARY KEY, role TEXT NOT NULL, display_name TEXT NOT NULL,
                board_token TEXT, board_id TEXT REFERENCES boards(id), joined_at TEXT,
                domains TEXT, capability_snapshot TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, short_id TEXT NOT NULL, board_id TEXT REFERENCES boards(id),
                title TEXT, body TEXT, status TEXT DEFAULT 'todo',
                assignee TEXT REFERENCES board_members(email), reviewer TEXT,
                parent_ids TEXT DEFAULT '[]', tags TEXT DEFAULT '[]', summary TEXT DEFAULT '',
                metadata TEXT, created_by TEXT, created_at TEXT, updated_at TEXT,
                completed_at TEXT, cancelled_at TEXT, deadline TEXT
            );
            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT REFERENCES tasks(id),
                event_type TEXT, actor TEXT, payload TEXT, created_at TEXT
            );",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn rename_agent_address_migrates_all_references() {
        let (db, path) = temp_db_with_path();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "INSERT INTO system_domains(id,system_id,domain_addr,webhook_url,webhook_secret)
                   VALUES('d1','shared-sys1','old.agent@shared.example','http://hook','sec');
                 INSERT INTO domain_addr_meta(email_address,system_id,manager_address,agent_signature,agent_persona)
                   VALUES('old.agent@shared.example','shared-sys1','mgr@example.com','sig','persona');
                 INSERT INTO api_keys(system_id,domain_addr,key_hash,key_prefix,scopes,category)
                   VALUES('shared-sys1','old.agent@shared.example','hash123','pref','[\"agent\"]','agent');
                 INSERT INTO whitelists(system_id,domain_addr,direction,value,description,category)
                   VALUES('shared-sys1','old.agent@shared.example','all','mgr@example.com','agent-side','system'),
                         ('shared-sys1','other.agent@shared.example','all','old.agent@shared.example','peer-side','system');
                 INSERT INTO agent_state(agent_addr,state_key,state_value)
                   VALUES('old.agent@shared.example','profile:old.agent@shared.example','{\"name\":\"Old\"}');
",
            )
            .unwrap();
        }

        // Boards live in per-board db files: {storage}/a2a_board/{id}.db
        let board_dir = path.parent().unwrap().join("a2a_board");
        std::fs::create_dir_all(&board_dir).unwrap();
        {
            let bconn = rusqlite::Connection::open(board_dir.join("b1.db")).unwrap();
            seed_board_tables(&bconn);
            bconn.execute_batch(
                "INSERT INTO boards(id,short_id,board_email,goal) VALUES('b1','b1','old.agent@shared.example','g');
                 INSERT INTO board_members(email,role,display_name,board_token,board_id,domains)
                   VALUES('old.agent@shared.example','owner','Old Agent','tok','b1','[\"b1\"]');
                 INSERT INTO tasks(id,short_id,board_id,title,assignee,reviewer,created_by)
                   VALUES('t1','t1','b1','x','old.agent@shared.example','old.agent@shared.example','old.agent@shared.example');
                 INSERT INTO task_events(task_id,event_type,actor,payload)
                   VALUES('t1','comment','old.agent@shared.example','{}');",
            )
            .unwrap();
        }

        db.rename_agent_address_refs("old.agent@shared.example", "new.agent@shared.example")
            .await
            .unwrap();

        let conn = rusqlite::Connection::open(&path).unwrap();
        // system_domains: re-keyed, webhook rides along
        let row: (String, String) = conn
            .query_row(
                "SELECT domain_addr, webhook_secret FROM system_domains WHERE id='d1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            ("new.agent@shared.example".to_string(), "sec".to_string())
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM system_domains WHERE domain_addr='old.agent@shared.example'"
            ),
            0
        );
        // domain_addr_meta re-keyed with manager/signature intact
        let meta: (String, String) = conn
            .query_row(
                "SELECT manager_address, agent_signature FROM domain_addr_meta WHERE email_address='new.agent@shared.example'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(meta, ("mgr@example.com".to_string(), "sig".to_string()));
        // api_keys: re-pointed, key material untouched
        let key: (String, String) = conn
            .query_row(
                "SELECT domain_addr, key_hash FROM api_keys WHERE key_prefix='pref'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            key,
            (
                "new.agent@shared.example".to_string(),
                "hash123".to_string()
            )
        );
        // whitelists both sides migrated, no orphans
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='new.agent@shared.example' AND value='mgr@example.com'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='other.agent@shared.example' AND value='new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE value='old.agent@shared.example'"
            ),
            0
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM whitelists WHERE domain_addr='old.agent@shared.example'"
            ),
            0
        );
        // agent_state: addr re-keyed + embedded state key rewritten
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM agent_state WHERE agent_addr='new.agent@shared.example' AND state_key='profile:new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &conn,
                "SELECT COUNT(*) FROM agent_state WHERE agent_addr='old.agent@shared.example'"
            ),
            0
        );
        // boards/members/tasks/events all follow (in the per-board db file)
        let bconn = rusqlite::Connection::open(board_dir.join("b1.db")).unwrap();
        assert_eq!(
            count_rows(
                &bconn,
                "SELECT COUNT(*) FROM boards WHERE board_email='new.agent@shared.example'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &bconn,
                "SELECT COUNT(*) FROM board_members WHERE email='new.agent@shared.example' AND role='owner' AND board_token='tok'"
            ),
            1
        );
        assert_eq!(
            count_rows(
                &bconn,
                "SELECT COUNT(*) FROM board_members WHERE email='old.agent@shared.example'"
            ),
            0
        );
        let t: (String, String) = bconn
            .query_row(
                "SELECT assignee, reviewer FROM tasks WHERE id='t1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            t,
            (
                "new.agent@shared.example".to_string(),
                "new.agent@shared.example".to_string()
            )
        );
        assert_eq!(
            count_rows(
                &bconn,
                "SELECT COUNT(*) FROM task_events WHERE actor='new.agent@shared.example'"
            ),
            1
        );
    }

    fn count_rows(conn: &rusqlite::Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    // ── Two-key bootstrap (2026-09-26 owner ruling) ─────────────────────────────
    // A = gateway-side platform-category admin key, B = agent-side system key. Both share
    // the instance's bootstrap `system_id`, and `api_keys` carries a UNIQUE index on
    // (system_id, domain_addr), so B is stored under the reserved `.system` scope marker.
    #[tokio::test]
    async fn gateway_and_agent_keys_coexist_for_one_system() {
        let db = temp_db();
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            "system-1",
            "",
            "hashA",
            "prefA",
            &["platform".to_string(), "system".to_string()],
            None,
            "platform",
        ))
        .await
        .unwrap();
        // B under the reserved marker — must NOT collide with A's empty domain_addr.
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            "system-1",
            crate::core::server::SYSTEM_KEY_DOMAIN_ADDR,
            "hashB",
            "prefB",
            &["system".to_string()],
            None,
            "system",
        ))
        .await
        .expect("system key must coexist with the platform key of the same system");

        let all = db.list_api_keys().await.unwrap();
        assert_eq!(all.len(), 2, "both bootstrap keys live in one DB");
        assert_eq!(all.iter().filter(|k| k.category == "platform").count(), 1);
        assert_eq!(all.iter().filter(|k| k.category == "system").count(), 1);
        // Identity lookup matches either column: the shared system id resolves BOTH keys,
        // the reserved marker resolves the agent-side one.
        assert_eq!(
            db.list_api_keys_by_identity("system-1")
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            db.list_api_keys_by_identity(crate::core::server::SYSTEM_KEY_DOMAIN_ADDR)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    // Legacy single-system instances provisioned the admin key as category="system"
    // (empty domain_addr). Aligning it must be an in-place UPDATE — re-minting would
    // rotate the deployment root secret and strand every sealed credential.
    #[tokio::test]
    async fn legacy_system_admin_key_is_aligned_in_place() {
        let db = temp_db();
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            "system-1",
            "",
            "hashLegacy",
            "prefLegacy",
            &["system".to_string()],
            None,
            "system",
        ))
        .await
        .unwrap();
        let factory = crate::core::factory::EnvFactory::new(
            std::sync::Arc::new(db.clone()),
            std::sync::Arc::new(crate::base::strategy::BaseSystemStore),
        );

        let migrated = crate::core::server::align_legacy_system_admin_key(&factory, "system-1")
            .await
            .unwrap()
            .expect("legacy row is found");
        assert_eq!(migrated.category, "system");
        assert_eq!(migrated.key_hash, "hashLegacy");

        let platform_rows = db
            .list_api_keys_by_system("system-1", "platform")
            .await
            .unwrap();
        assert_eq!(
            platform_rows.len(),
            1,
            "row now carries the platform category"
        );
        assert_eq!(
            platform_rows[0].key_hash, "hashLegacy",
            "raw key material untouched"
        );
        assert_eq!(
            platform_rows[0].scopes,
            vec!["platform".to_string(), "system".to_string()]
        );
        assert!(
            db.list_api_keys_by_system("system-1", "system")
                .await
                .unwrap()
                .is_empty(),
            "no system-category admin key remains (only the migration target)"
        );

        // Idempotent: a second pass finds nothing left to align.
        assert!(
            crate::core::server::align_legacy_system_admin_key(&factory, "system-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ── D11: identity lookup uses per-column indexes, not a full scan ─────
    #[tokio::test]
    async fn d11_identity_lookup_searches_via_indexes_not_full_scan() {
        let (db, path) = temp_db_with_path();
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            "system-1",
            "agent@shared.example",
            "hashA",
            "prefA",
            &["agent".to_string()],
            None,
            "agent",
        ))
        .await
        .unwrap();
        db.insert_api_key(crate::core::storage::ApiKeyParams::new(
            "system-1",
            "",
            "hashB",
            "prefB",
            &["system".to_string()],
            None,
            "system",
        ))
        .await
        .unwrap();

        // Behavior: an address-scoped identity resolves the address key, the
        // system identity resolves the system key.
        assert_eq!(
            db.list_api_keys_by_identity("agent@shared.example")
                .await
                .unwrap()
                .len(),
            1
        );
        let by_system = db.list_api_keys_by_identity("system-1").await.unwrap();
        assert_eq!(
            by_system.len(),
            2,
            "both keys match the shared system identity"
        );

        // Plan: the split query must SEARCH both halves via the per-column
        // indexes — no SCAN of api_keys anywhere.
        let raw = rusqlite::Connection::open(&path).unwrap();
        let plan: Vec<String> = {
            let mut stmt = raw
                .prepare(
                    "EXPLAIN QUERY PLAN
                     SELECT id FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) AND domain_addr = 'x'
                     UNION ALL
                     SELECT id FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) AND system_id = 'x'",
                )
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap();
            let mut out = Vec::new();
            for row in rows {
                out.push(row.unwrap());
            }
            out
        };
        let joined = plan.join("\n");
        assert!(
            !joined.to_uppercase().contains("SCAN API_KEYS"),
            "D11: auth identity query must not full-scan api_keys: {joined}"
        );
        assert!(
            joined.to_uppercase().contains("USING INDEX"),
            "D11: both halves must SEARCH via an index: {joined}"
        );
    }

    // ── D10: manager_address normalized on write, legacy rows migrated ─────
    #[tokio::test]
    async fn d10_manager_address_normalized_lowercased_on_write() {
        let db = temp_db();
        let rec = db
            .upsert_domain_addr_meta(
                "Agent@Shared.Example",
                "system-1",
                Some("  Manager@Example.COM "),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            rec.manager_address, "manager@example.com",
            "write side must trim + lowercase manager_address"
        );
        let again = db
            .get_domain_addr_meta("agent@shared.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.manager_address, "manager@example.com");
    }

    #[tokio::test]
    async fn d10_legacy_mixed_case_manager_is_migrated_on_open() {
        let (db, path) = temp_db_with_path();
        // Simulate a pre-D10 row (mixed case) by bypassing the D10 write-side
        // normalization with a raw INSERT, then reopen the DB (fresh process)
        // and assert run_migrations lowercased it.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO domain_addr_meta (email_address, system_id, manager_address, agent_signature, agent_persona, is_active, created_at, updated_at)
                 VALUES ('legacy@test.com', 'system-1', 'Legacy@Test.COM', '', '', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        drop(db);
        let db2 = Database::open(&path, 4, None).unwrap();
        let rec = db2
            .get_domain_addr_meta("legacy@test.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            rec.manager_address, "legacy@test.com",
            "one-time migration must lowercase the legacy row"
        );
    }

    // ── D5: batched last_used_at flush ──

    #[tokio::test]
    async fn d5_batched_last_used_one_write_per_key_per_flush() {
        let dir = std::env::temp_dir().join(format!("aimailgw-d5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = std::sync::Arc::new(Database::open(dir.join("aimail.db"), 4, None).unwrap());

        let rec = db
            .insert_api_key(crate::core::storage::ApiKeyParams::new(
                "sys1",
                "agent@test.com",
                &"a".repeat(64),
                "abcd",
                &["agent".to_string()],
                None,
                "agent",
            ))
            .await
            .unwrap();

        let tracker = std::sync::Arc::new(crate::core::factory::LastUsedTracker::new());
        // 100 uses of the same key within one second — the hot path only
        // notes in memory (zero DB writes here).
        for _ in 0..100 {
            tracker.note(rec.id);
        }
        // One flush → exactly one pending id → one UPDATE (≤ 2 by contract).
        let written = crate::core::server::last_used_flush_once(&db, &tracker)
            .await
            .unwrap_or_else(|e| panic!("flush: {e}"));
        assert_eq!(written, 1);
        // The second flush right after has nothing to write.
        let written2 = crate::core::server::last_used_flush_once(&db, &tracker)
            .await
            .unwrap_or_else(|e| panic!("flush: {e}"));
        assert_eq!(written2, 0);

        // The value landed in the database.
        let rec_id = rec.id;
        let v: Option<String> = db
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT last_used_at FROM api_keys WHERE id = ?1")?;
                let mut rows = stmt.query_map([rec_id], |r| r.get::<_, String>(0))?;
                match rows.next() {
                    Some(Ok(v)) => Ok(Some(v)),
                    Some(Err(e)) => Err(e.into()),
                    None => Ok(None),
                }
            })
            .await
            .unwrap();
        assert!(
            v.as_deref().unwrap().starts_with('2'),
            "last_used_at: {v:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn agent_system_pending_is_isolated_and_ackable() {
        let db = temp_db();
        db.bind_agent_system_address("asid_a", "a@x.test", "sys_a")
            .await
            .unwrap();
        db.bind_agent_system_address("asid_b", "b@x.test", "sys_b")
            .await
            .unwrap();
        let a = db
            .insert_pending_delivery("sys_a", "a@x.test", "a@x.test", "{}", "{}")
            .await
            .unwrap();
        let b = db
            .insert_pending_delivery("sys_b", "b@x.test", "b@x.test", "{}", "{}")
            .await
            .unwrap();

        let only_a = db
            .list_pending_for_agent_system("asid_a", 50)
            .await
            .unwrap();
        assert_eq!(only_a.iter().map(|r| r.id).collect::<Vec<_>>(), vec![a]);
        let only_b = db
            .list_pending_for_agent_system("asid_b", 50)
            .await
            .unwrap();
        assert_eq!(only_b.iter().map(|r| r.id).collect::<Vec<_>>(), vec![b]);

        // Cross-owner ack must affect 0 rows.
        assert_eq!(
            db.ack_pending_for_agent_system("asid_a", &[b])
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            db.ack_pending_for_agent_system("asid_a", &[a])
                .await
                .unwrap(),
            1
        );
        assert!(db
            .list_pending_for_agent_system("asid_b", 50)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == b));
    }

    #[tokio::test]
    async fn agent_system_ownership_is_removed_only_after_last_agent_key() {
        let db = temp_db();
        db.bind_agent_system_address("asid_x", "x@x.test", "sys_x")
            .await
            .unwrap();
        let key = db
            .insert_api_key(ApiKeyParams::new(
                "sys_x",
                "x@x.test",
                "hash_x",
                "prefix",
                &["agent".to_string()],
                None,
                "agent",
            ))
            .await
            .unwrap();
        // A live agent key still owns the address: keep the mapping.
        assert!(!db
            .remove_agent_system_address_if_unowned("sys_x", "x@x.test")
            .await
            .unwrap());
        assert_eq!(
            db.list_agent_system_addresses("asid_x")
                .await
                .unwrap()
                .len(),
            1
        );
        // Last key removed ⇒ ownership row is deleted.
        db.delete_api_key(key.id).await.unwrap();
        assert!(db
            .remove_agent_system_address_if_unowned("sys_x", "x@x.test")
            .await
            .unwrap());
        assert!(db
            .list_agent_system_addresses("asid_x")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn agent_system_pending_is_isolated_across_gateway_databases() {
        // Two Gateways are independent databases; the same AgentSystemId and
        // address must not leak pending rows across them.
        let a = temp_db();
        let b = temp_db();
        a.bind_agent_system_address("asid_same", "same@x.test", "sys_a")
            .await
            .unwrap();
        b.bind_agent_system_address("asid_same", "same@x.test", "sys_b")
            .await
            .unwrap();
        let id_a = a
            .insert_pending_delivery("sys_a", "same@x.test", "same@x.test", "{}", "{}")
            .await
            .unwrap();
        let id_b = b
            .insert_pending_delivery("sys_b", "same@x.test", "same@x.test", "{}", "{}")
            .await
            .unwrap();

        assert_eq!(
            a.list_pending_for_agent_system("asid_same", 50)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![id_a]
        );
        assert_eq!(
            b.list_pending_for_agent_system("asid_same", 50)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![id_b]
        );
        // Ack ids are local to each Gateway's database; acking A's row must
        // not clear B's row.
        assert_eq!(
            a.ack_pending_for_agent_system("asid_same", &[id_a])
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            b.list_pending_for_agent_system("asid_same", 50)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn d5_tracker_note_is_idempotent_and_drain_clears() {
        use crate::core::factory::LastUsedTracker;
        let t = LastUsedTracker::new();
        for _ in 0..50 {
            t.note(7);
        }
        t.note(8);
        let v = t.drain();
        assert_eq!(v.len(), 2, "50 notes of one key collapse to one entry");
        assert!(v.contains(&7) && v.contains(&8));
        assert!(t.drain().is_empty(), "drain clears the set");
    }
    #[tokio::test]
    async fn config_domain_seed_is_insert_only() {
        let db = temp_db();
        assert!(db
            .seed_system_domain_if_absent("cfg-a.example", "sys", "a.example", None, None)
            .await
            .unwrap());
        // Second seed must not overwrite the existing row.
        assert!(!db
            .seed_system_domain_if_absent(
                "cfg-a.example",
                "sys",
                "a.example",
                Some("http://127.0.0.1/hook"),
                None,
            )
            .await
            .unwrap());
        let rec = db
            .get_system_domain_by_name("a.example")
            .await
            .unwrap()
            .expect("seeded row");
        assert_eq!(rec.webhook_url, None, "existing row must be untouched");
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::*;

    /// Unique scratch path under the OS temp dir (no dev-dependency needed).
    fn temp_db() -> Database {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("aimail-gw-anchor-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let db = Database::open(dir.join("test.db"), 1, None).expect("open db");
        let _ = dir; // kept for the process lifetime; the OS temp dir is cleaned by the CI runner
        db
    }

    #[tokio::test]
    async fn anchor_round_trip_per_address() {
        let db = temp_db();
        assert_eq!(db.get_address_anchor("A@Example.com").await.unwrap(), None);
        let hash = "a".repeat(64);
        db.set_address_anchor("A@Example.com", &hash).await.unwrap();
        // case-insensitive address, exact hash
        assert_eq!(
            db.get_address_anchor("a@example.com").await.unwrap(),
            Some(hash.clone())
        );
    }

    #[tokio::test]
    async fn re_anchor_overwrites_instead_of_duplicating() {
        let db = temp_db();
        db.set_address_anchor("a@example.com", &"1".repeat(64))
            .await
            .unwrap();
        db.set_address_anchor("a@example.com", &"2".repeat(64))
            .await
            .unwrap();
        assert_eq!(
            db.get_address_anchor("a@example.com").await.unwrap(),
            Some("2".repeat(64))
        );
    }

    #[tokio::test]
    async fn list_for_agent_system_only_returns_registered_addresses() {
        let db = temp_db();
        db.bind_agent_system_address("asid_x", "a@example.com", "sys-1")
            .await
            .unwrap();
        db.bind_agent_system_address("asid_x", "b@example.com", "sys-1")
            .await
            .unwrap();
        db.set_address_anchor("a@example.com", &"a".repeat(64))
            .await
            .unwrap();
        let got = db.list_agent_system_anchors("asid_x").await.unwrap();
        assert_eq!(got.len(), 1, "only the address that registered an anchor: {got:?}");
        assert_eq!(got[0].0, "a@example.com");
        assert_eq!(got[0].1, "a".repeat(64));
    }
}
