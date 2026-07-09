//! amail-gateway CLI entry point.

mod server;

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process;

use amail_base::core::cli::daemon;
use amail_base::core::cli::{
    cmd_status, cmd_stop, init_tracing, is_process_alive, read_pid_file, Cli, Commands,
};
use amail_base::core::config::LoggingConfig;
use amail_base::core::errors::{AppError, AppResult};

pub use amail_base::core::config::Config;
pub use amail_base::core::email::factory::{AttachmentFactory, EmailFactory};
pub use amail_base::core::factory::EnvFactory;
pub use amail_base::core::storage::Database;
pub use server::Server;

#[tokio::main]
async fn main() -> AppResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command.as_ref().unwrap_or(&Commands::Start) {
        Commands::Start => cmd_start(&cli).await,
        Commands::Stop => cmd_stop(&cli.pid_file),
        Commands::Restart => {
            cmd_stop(&cli.pid_file)?;
            cmd_start(&cli).await
        }
        Commands::Status => cmd_status("amail-gateway", &cli.pid_file),
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
    let mut config = amail_base::core::config::load(&config_path)?;

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
    let key_path = format!("{}.admin_key", db_path.display());

    // Derive DB encryption key from admin key via HMAC-SHA256.
    let db_key: Option<String> = if true {
        std::fs::read_to_string(&key_path)
            .ok()
            .filter(|k| !k.is_empty())
            .map(|k| {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                let mut mac =
                    HmacSha256::new_from_slice(k.as_bytes()).expect("HMAC-SHA256 key derivation");
                mac.update(b"amail-relay:db:encryption:v1");
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
            tracing::warn!(operation="admin_key_write_failed", %key_path, %e, "Failed to write admin key file");
        }
    }

    let result = server.run().await;

    // Clean up PID file on exit
    let _ = fs::remove_file(&cli.pid_file);

    result
}
