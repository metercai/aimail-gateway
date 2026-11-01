//! aimail-gateway CLI entry point.

mod server;

use clap::Parser;
use std::fs;

use aimail_base::core::cli::daemon;
use aimail_base::core::cli::{cmd_status, cmd_stop, init_tracing, Cli, Commands};
use aimail_base::core::errors::{AppError, AppResult};

pub use aimail_base::core::config::Config;
pub use aimail_base::core::email::factory::{AttachmentFactory, EmailFactory};
pub use aimail_base::core::factory::EnvFactory;
pub use aimail_base::core::storage::Database;
pub use server::Server;

#[tokio::main]
async fn main() -> AppResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    // ── Test config mode: validate & exit ──────────────────────────
    if cli.test_config {
        return cmd_test_config(&cli);
    }

    match cli.command.as_ref().unwrap_or(&Commands::Start) {
        Commands::Start => cmd_start(&cli).await,
        Commands::Stop => cmd_stop(&cli.pid_file),
        Commands::Restart => {
            cmd_stop(&cli.pid_file)?;
            cmd_start(&cli).await
        }
        Commands::Status => cmd_status("aimail-gateway", &cli.pid_file),
    }
}

async fn cmd_start(cli: &Cli) -> AppResult<()> {
    // Daemonize
    if daemon::daemonize(cli)? {
        return Ok(());
    }

    // Check for existing instance
    daemon::check_existing_pid(&cli.pid_file)?;

    // Load configuration
    let config_path = cli.config.to_string_lossy().to_string();
    let mut config = aimail_base::core::config::load(&config_path)?;

    // Apply CLI overrides
    if let Some(ref db_path) = cli.db {
        config.storage.path = db_path.clone();
    }
    if let Some(ref addr) = cli.port {
        config.smtp.bind = addr.clone();
    }
    if let Some(ref level) = cli.log_level {
        config.logging.level = level.clone();
    }

    // Clamp attachment size
    daemon::clamp_attachment_size(&mut config);

    // Initialize tracing
    init_tracing(&config.logging, None);

    tracing::info!(
        operation = "app_start",
        version = concat!("gateway-", env!("CARGO_PKG_VERSION")),
        commit = env!("GIT_VERSION"),
        "Starting"
    );

    // Write PID and log
    daemon::write_pid_and_log(&cli.pid_file, &config)?;

    // Create server
    let db_path = config.storage.db_path();
    // platform admin-key file: in production point it outside the DB directory (e.g. /etc/aimail/admin.key, 0600 root);
    // when unset, the historical location <db>.admin_key is kept (tests/CI only).
    let key_path: std::path::PathBuf =
        config.storage.admin_key_file.clone().unwrap_or_else(|| {
            std::path::PathBuf::from(format!("{}.admin_key", db_path.display()))
        });
    if key_path.parent() == db_path.parent() {
        tracing::warn!(
            operation = "admin_key_colocated",
            path = %key_path.display(),
            "platform admin key sits in the same directory as the database — a backup of that              directory would leak both; move it (e.g. /etc/aimail/admin.key, 0600 root)"
        );
    }

    // Derive DB encryption key from admin key via HMAC-SHA256.
    // Only when SQLCipher is enabled (storage.encryption = true); base defaults
    // to false, so the DB stays plaintext unless explicitly opted in.
    let db_key: Option<String> = if config.storage.encryption {
        // The encryption key is derived from the admin key, which is minted on the FIRST
        // start. Enabling encryption on a host that has no key file yet would otherwise
        // open (and write) a PLAINTEXT database and only migrate on the next restart —
        // a silent plaintext window. Refuse instead: the operator starts once with
        // encryption disabled (key minted + plaintext DB), then flips it on and the
        // database is migrated in place on the next start.
        let raw = std::fs::read_to_string(&key_path)
            .ok()
            .filter(|k| !k.trim().is_empty());
        let Some(raw) = raw else {
            return Err(AppError::Config(format!(
                "storage.encryption = true requires an existing admin key file ({}): the \
                 database key is derived from it, and the file is created by the first start. \
                 Start once with storage.encryption = false, then set it to true — the \
                 database is migrated to encrypted in place on the next start.",
                key_path.display()
            )));
        };
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(raw.as_bytes()).expect("HMAC-SHA256 key derivation");
        mac.update(b"aimail-gateway:db:encryption:v1");
        Some(hex::encode(mac.finalize().into_bytes()))
    } else {
        None
    };

    // Captured before `config`/`db_path` are moved into the server: the key files live
    // next to them by default (see the persistence helper below).
    let system_key_file_cfg = config.storage.system_key_file.clone();
    let storage_dir = config.storage.path.clone();
    let db_path_owned = db_path.clone();

    let server = server::Server::new(config, db_path, db_key.as_deref())?;

    // Provision admin API key and persist to {db_path}.admin_key
    let keys = server.setup_admin_key().await?;
    let admin_key = keys.admin_key.clone();

    // ── Persist both keys + announce the agent-side one (2026-09-26 owner ruling) ──
    // Shared helper so every binary that provisions keys behaves and speaks identically:
    // the admin key stays on the gateway side, the system key is what an agent host uses
    // (`aimail install -k`).
    let banner = aimail_base::core::server::persist_provisioned_keys(
        Some(&key_path),
        system_key_file_cfg.as_deref(),
        &storage_dir,
        &db_path_owned,
        &keys,
    );
    if !banner.is_empty() {
        print!("{banner}");
    }

    // ── stored credential material sealing (2026-09-22 hardening) ──────────────────────────────
    // root secret = the platform admin-key; subkey = HMAC-SHA256(admin_key, "aimail-gateway:key-seal:v1").
    // goal: someone with only the DB (backup/read-only replica/logical export/SQL injection) can no longer impersonate signatures with key_hash.
    let admin_for_seal = if !admin_key.is_empty() {
        admin_key.clone()
    } else {
        std::fs::read_to_string(&key_path).unwrap_or_default()
    };
    aimail_base::core::api::seal::init(&admin_for_seal);
    if !aimail_base::core::api::seal::loaded() {
        tracing::warn!(
            operation = "seal_key_unavailable",
            path = %key_path.display(),
            "no platform admin key available — credential material cannot be sealed or opened"
        );
    }
    // fail closed: the DB already holds sealed material but the admin-key is unobtainable => refuse to start (otherwise every signature 401s)
    let sealed_rows = server.count_sealed_credentials().await?;
    if let Err(e) = aimail_base::core::api::seal::ensure_loaded(sealed_rows > 0) {
        tracing::error!(operation = "seal_fail_closed", error = %e, "refusing to start");
        return Err(aimail_base::core::errors::AppError::Internal(e));
    }
    // idempotent migration: historical plaintext hashes are sealed in place (interruptible/re-runnable; the code accepts both forms => rollback possible)
    match server.reseal_credentials().await {
        Ok((done, already)) => tracing::info!(
            operation = "credential_reseal",
            sealed = done,
            already_sealed = already,
            "credential material sealed at rest"
        ),
        Err(e) => tracing::warn!(operation = "credential_reseal_failed", error = %e,
            "credential reseal skipped (will retry next start)"),
    }

    let result = server.run().await;

    // Clean up PID file on exit
    let _ = fs::remove_file(&cli.pid_file);

    result
}

// ── Test config ────────────────────────────────────────────────────────

fn cmd_test_config(cli: &Cli) -> AppResult<()> {
    let config_path = cli.config.to_string_lossy();
    eprintln!("Testing configuration: {}", config_path);

    let raw = std::fs::read_to_string(config_path.as_ref())
        .map_err(|e| AppError::Config(format!("cannot read {}: {}", config_path, e)))?;

    let config: Config =
        toml::from_str(&raw).map_err(|e| AppError::Config(format!("TOML parse error: {e}")))?;

    config.validate()?;

    eprintln!(
        "Config OK — hostname={}, smtp={}, http={}, storage={}",
        config.smtp.hostname.as_deref().unwrap_or("(unset)"),
        config.smtp.bind,
        config.http.bind,
        config.storage.path.display(),
    );
    Ok(())
}
