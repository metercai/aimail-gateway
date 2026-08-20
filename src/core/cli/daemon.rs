use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::core::errors::{AppError, AppResult};

/// Daemonize via self-exec (fork-free, works with tokio).
/// Returns `true` if the parent process should exit after spawning.
pub fn daemonize(cli: &super::Cli) -> AppResult<bool> {
    if !cli.daemon || std::env::var("AIMAILGW_DAEMONIZED").is_ok() {
        return Ok(false);
    }

    let exe = std::env::current_exe()
        .map_err(|e| AppError::Config(format!("Cannot determine executable path: {e}")))?;
    let mut child = std::process::Command::new(&exe);
    child.args(
        std::env::args()
            .skip(1)
            .filter(|a| a != "--daemon" && a != "-d"),
    );
    child
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    child.env("AIMAILGW_DAEMONIZED", "1");

    let mut spawned = child
        .spawn()
        .map_err(|e| AppError::Config(format!("Failed to spawn daemon process: {e}")))?;
    let child_pid = spawned.id();

    for _ in 0..25 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if super::read_pid_file(&cli.pid_file).is_ok() {
            println!("Daemon started (PID: {child_pid})");
            return Ok(true);
        }
    }

    match spawned
        .try_wait()
        .map_err(|e| AppError::Config(format!("Failed to check daemon status: {e}")))?
    {
        Some(status) => Err(AppError::Config(format!(
            "Daemon process exited early (PID: {child_pid}, status: {status})"
        ))),
        None => {
            eprintln!("Warning: daemon started (PID: {child_pid}) but PID file not found");
            Ok(true)
        }
    }
}

/// Check for an existing PID file; remove if stale.
pub fn check_existing_pid(pid_file: &PathBuf) -> AppResult<()> {
    let pid = match super::read_pid_file(pid_file) {
        Ok(pid) => pid,
        Err(_) => return Ok(()),
    };
    if super::is_process_alive(pid) {
        return Err(AppError::Config(format!(
            "Server is already running (PID: {pid}). Use 'stop' first or 'restart'."
        )));
    }
    let _ = fs::remove_file(pid_file);
    Ok(())
}

/// Write PID file and log startup info.
pub fn write_pid_and_log(
    pid_file: &PathBuf,
    config: &crate::core::config::Config,
) -> AppResult<()> {
    use std::process;

    let pid = process::id();
    fs::write(pid_file, pid.to_string()).map_err(|e| {
        AppError::Config(format!(
            "Failed to write PID file {}: {}",
            pid_file.display(),
            e
        ))
    })?;

    tracing::info!(operation = "smtp_listener_start", addr = %config.smtp.bind, "SMTP listener");
    tracing::info!(operation = "http_api_start", addr = %config.http.bind, "HTTP API");
    tracing::info!(operation = "pid_written", pid = pid, file = %pid_file.display(), "PID written");

    Ok(())
}

/// Clamp attachment_max_size to leave room for email envelope overhead.
pub fn clamp_attachment_size(config: &mut crate::core::config::Config) {
    const RESERVED: usize = 64 * 1024;
    let max_msg = config.smtp.max_message_size;
    if config.storage.attachment_max_size + RESERVED > max_msg {
        let clamped = max_msg.saturating_sub(RESERVED);
        tracing::warn!(
            "attachment_max_size {} clamped to {} (max_message_size {} - {}KB)",
            config.storage.attachment_max_size,
            clamped,
            max_msg,
            RESERVED / 1024,
        );
        config.storage.attachment_max_size = clamped;
    }
}

/// Bind a TCP listener with SO_REUSEADDR (avoids TIME_WAIT on restart).
pub async fn bind_with_reuseaddr(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    use tokio::net::TcpSocket;
    let socket_addr: SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid address '{}': {}", addr, e),
        )
    })?;
    let socket = if socket_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(socket_addr)?;
    socket.listen(1024)
}
