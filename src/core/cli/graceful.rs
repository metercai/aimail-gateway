use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::core::errors::AppResult;

const GRACEFUL_TIMEOUT_SECS: u64 = 15;

pub async fn wait_for_services(
    cancel: CancellationToken,
    mut http_handle: JoinHandle<AppResult<()>>,
    mut smtp_handle: JoinHandle<AppResult<()>>,
    mut retry_handle: JoinHandle<AppResult<()>>,
    mut cleanup_handle: JoinHandle<()>,
) -> AppResult<()> {
    info!(
        operation = "services_started",
        "All services started. Waiting for cancellation..."
    );
    cancel.cancelled().await;

    let timeout = tokio::time::sleep(Duration::from_secs(GRACEFUL_TIMEOUT_SECS));
    tokio::pin!(timeout);

    // SMTP
    tokio::select! {
        result = &mut smtp_handle => {
            match result {
                Ok(Ok(())) => info!(operation = "smtp_server_shutdown", "SMTP server shut down cleanly"),
                Ok(Err(e)) => warn!(operation = "smtp_server_error", error = %e, "SMTP server exited with error"),
                Err(e) => warn!(operation = "smtp_task_panic", error = %e, "SMTP task panicked"),
            }
        }
        _ = &mut timeout => {
            warn!(operation = "smtp_shutdown_timeout", timeout_secs = GRACEFUL_TIMEOUT_SECS, "SMTP server shutdown timed out");
        }
    }

    // Retry Worker
    tokio::select! {
        result = &mut retry_handle => {
            match result {
                Ok(Ok(())) => info!(operation = "retry_worker_shutdown", "Retry worker shut down cleanly"),
                Ok(Err(e)) => warn!(operation = "retry_worker_error", error = %e, "Retry worker exited with error"),
                Err(e) => warn!(operation = "retry_task_panic", error = %e, "Retry task panicked"),
            }
        }
        _ = &mut timeout => {
            warn!(operation = "retry_shutdown_timeout", timeout_secs = GRACEFUL_TIMEOUT_SECS, "Retry worker shutdown timed out");
        }
    }

    // HTTP Server (axum graceful shutdown already triggered by cancel)
    tokio::select! {
        result = &mut http_handle => {
            match result {
                Ok(Ok(())) => info!(operation = "http_server_shutdown", "HTTP server shut down cleanly"),
                Ok(Err(e)) => warn!(operation = "http_server_error", error = %e, "HTTP server exited with error"),
                Err(e) => warn!(operation = "http_task_panic", error = %e, "HTTP task panicked"),
            }
        }
        _ = &mut timeout => {
            warn!(operation = "http_shutdown_timeout", timeout_secs = GRACEFUL_TIMEOUT_SECS, "HTTP server shutdown timed out");
        }
    }

    // Cleanup Worker
    tokio::select! {
        result = &mut cleanup_handle => {
            match result {
                Ok(()) => info!(operation = "cleanup_worker_shutdown", "Cleanup worker shut down cleanly"),
                Err(e) => warn!(operation = "cleanup_task_panic", error = %e, "Cleanup task panicked"),
            }
        }
        _ = &mut timeout => {
            warn!(operation = "cleanup_shutdown_timeout", timeout_secs = GRACEFUL_TIMEOUT_SECS, "Cleanup worker shutdown timed out");
        }
    }

    info!(
        operation = "services_shutdown",
        "All services shut down. Goodbye."
    );
    Ok(())
}
