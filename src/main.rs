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
    // 平台 admin-key 文件: 生产应指向 DB 目录之外(如 /etc/aimail/admin.key, 0600 root);
    // 未配置时沿用历史位置 <db>.admin_key(仅供测试/CI)。
    let key_path: std::path::PathBuf = config
        .storage
        .admin_key_file
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.admin_key", db_path.display())));
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
        std::fs::read_to_string(&key_path)
            .ok()
            .filter(|k| !k.is_empty())
            .map(|k| {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                let mut mac =
                    HmacSha256::new_from_slice(k.as_bytes()).expect("HMAC-SHA256 key derivation");
                mac.update(b"aimail-gateway:db:encryption:v1");
                hex::encode(mac.finalize().into_bytes())
            })
    } else {
        None
    };

    let server = server::Server::new(config, db_path, db_key.as_deref())?;

    // Provision admin API key and persist to {db_path}.admin_key
    let admin_key = server.setup_admin_key().await?;
    if !admin_key.is_empty() {
        if let Err(e) = std::fs::write(&key_path, &admin_key) {
            tracing::warn!(operation="admin_key_write_failed", path = %key_path.display(), %e, "Failed to write admin key file");
        }
    }

    // ── 库内凭据材料密封(2026-09-22 加固) ──────────────────────────────
    // 根秘密 = 平台 admin-key; 子密钥 = HMAC-SHA256(admin_key, "aimail-gateway:key-seal:v1")。
    // 目的: 仅拿到 DB(备份/只读副本/逻辑导出/SQL 注入)的人无法再用 key_hash 冒充签名。
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
    // fail closed: 库里已有密封材料却拿不到 admin-key ⇒ 拒绝启动(否则每个签名都会 401)
    let sealed_rows = server.count_sealed_credentials().await?;
    if let Err(e) = aimail_base::core::api::seal::ensure_loaded(sealed_rows > 0) {
        tracing::error!(operation = "seal_fail_closed", error = %e, "refusing to start");
        return Err(aimail_base::core::errors::AppError::Internal(e));
    }
    // 幂等迁移: 历史明文哈希就地密封(可中断/可重复; 代码两种形态都接受 ⇒ 可回滚)
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

    let config: Config = toml::from_str(&raw)
        .map_err(|e| AppError::Config(format!("TOML parse error: {e}")))?;

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
