pub mod daemon;
pub mod graceful;
// Shared CLI utilities — used by both gateway and advanced binaries.

use std::path::PathBuf;
#[cfg(not(unix))]
use std::process;

use clap::{Parser, Subcommand};

use crate::core::config::LoggingConfig;
use crate::core::errors::AppResult;

#[derive(Parser)]
#[command(
    name = "aimail-gateway",
    version = env!("CARGO_PKG_VERSION"),
    about = "Self-hosted SMTP-to-HTTP mail relay",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short = 'c', long, default_value = "config.toml", global = true)]
    pub config: PathBuf,

    #[arg(long)]
    pub db: Option<PathBuf>,

    #[arg(short = 'p', long)]
    pub port: Option<String>,

    #[arg(short = 'l', long)]
    pub log_level: Option<String>,

    #[arg(long, default_value = "/tmp/amail-relay.pid")]
    pub pid_file: PathBuf,

    #[arg(short = 'd', long)]
    pub daemon: bool,

    /// Test configuration file for errors and exit (no server start).
    #[arg(short = 't', long, global = true)]
    pub test_config: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Start,
    Stop,
    Restart,
    Status,
}

pub fn cmd_stop(pid_file: &PathBuf) -> AppResult<()> {
    let pid = read_pid_file(pid_file).map_err(|e| {
        crate::core::errors::AppError::Config(format!(
            "No PID file found at {}. Is the server running? ({})",
            pid_file.display(),
            e
        ))
    })?;

    if !is_process_alive(pid) {
        println!("Process {} is not running. Removing stale PID file.", pid);
        let _ = std::fs::remove_file(pid_file);
        return Ok(());
    }

    println!("Sending SIGTERM to process {}...", pid);

    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    #[cfg(not(unix))]
    {
        let _ = process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .output();
    }

    for _i in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if !is_process_alive(pid) {
            println!("Server stopped successfully.");
            let _ = std::fs::remove_file(pid_file);
            return Ok(());
        }
    }

    eprintln!("Server did not stop gracefully. Sending SIGKILL...");

    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }

    let _ = std::fs::remove_file(pid_file);
    Ok(())
}

pub fn cmd_status(app_name: &str, pid_file: &PathBuf) -> AppResult<()> {
    match read_pid_file(pid_file) {
        Ok(pid) if is_process_alive(pid) => {
            println!("{} is running (PID: {})", app_name, pid);
            println!("PID file: {}", pid_file.display());
        }
        Ok(pid) => {
            println!(
                "{} is NOT running (stale PID: {} in {})",
                app_name,
                pid,
                pid_file.display()
            );
        }
        Err(_) => {
            println!(
                "{} is NOT running (no PID file at {})",
                app_name,
                pid_file.display()
            );
        }
    }
    Ok(())
}

pub fn read_pid_file(path: &PathBuf) -> Result<u32, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
    let pid: u32 = content
        .trim()
        .parse()
        .map_err(|e| format!("Invalid PID in {}: {}", path.display(), e))?;
    Ok(pid)
}

pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

pub fn init_tracing(cfg: &LoggingConfig, log_writer: Option<Box<dyn std::io::Write + Send>>) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    let inner: Box<dyn std::io::Write + Send> = if let Some(ref path) = cfg.file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("failed to open log file {:?}: {}", path, e));
        Box::new(file)
    } else {
        Box::new(std::io::stdout())
    };

    let writer: Box<dyn std::io::Write + Send> = match log_writer {
        Some(w) => Box::new(w),
        None => inner,
    };

    let (non_blocking, _guard) = tracing_appender::non_blocking(writer);
    builder.with_writer(non_blocking).init();
    std::mem::forget(_guard);
}
