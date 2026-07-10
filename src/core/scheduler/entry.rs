use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::errors::AppResult;
use crate::core::smtp::sender::SmtpRelay;
use crate::core::strategy::MessageSigner;

use super::batch::{process_batch, InflightSet};
use super::flows::immediate_forward;

/// Scheduler that wakes on interval ticks and an mpsc trigger from SMTP receiver
/// Returns an error if SMTP delivery cannot be initialized — fatal for base edition.
pub async fn run_retry_worker_with_trigger(
    email_factory: EmailFactory,
    attachment_factory: AttachmentFactory,
    config: Config,
    mut trigger_rx: mpsc::Receiver<String>,
    metrics: Metrics,
    cancel: CancellationToken,
    inflight: InflightSet,
    dkim_signer: Option<Arc<dyn MessageSigner>>,
    dns_resolver: Option<Arc<hickory_resolver::TokioAsyncResolver>>,
) -> AppResult<()> {
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.webhook.timeout_secs + 5))
        .build()
        .unwrap_or_else(|_| {
            warn!(
                operation = "scheduler_reqwest_failed",
                "Failed to build reqwest client for scheduler, using default"
            );
            reqwest::Client::new()
        });

    let smtp_relay = match SmtpRelay::from_config(
        &config.relay,
        Arc::new(email_factory.clone()),
        config.smtp.hostname.as_deref(),
        dkim_signer,
        dns_resolver,
    ) {
        Ok(relay) => {
            let mode = if config
                .relay
                .smtp_server
                .as_deref()
                .map_or(false, |s| !s.is_empty())
            {
                "relay"
            } else {
                "direct-mx"
            };
            info!(operation = "smtp_delivery_initialized", %mode, "SMTP delivery initialized");
            Some(relay)
        }
        Err(e) => {
            error!(operation="smtp_relay_fatal", %e, "SMTP relay not configured — base edition cannot deliver email");
            return Err(e);
        }
    };

    let poll_interval = Duration::from_secs(config.retry.poll_interval_secs);
    let batch_size = config.retry.batch_size;

    info!(operation="scheduler_started",
        poll_interval_secs = config.retry.poll_interval_secs,
        batch_size,
        multiplier = config.retry.multiplier,
        initial_backoff = config.retry.initial_backoff_secs,
        max_backoff = config.retry.max_backoff_secs,
        max_attempts = config.retry.max_attempts,
        smtp_relay_configured = smtp_relay.is_some(),
        "Scheduler v1.0 started with trigger channel (quad-flow: overlimit → retry → forward → attachment-expiry)"
    );

    let mut interval = time::interval(poll_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                tracing::debug!("Scheduler periodic tick");
                if let Ok(count) = email_factory.count_by_status("ready").await {
                    metrics.set_scheduler_pending_count(count);
                }
                process_batch(&email_factory, &attachment_factory, &config, &http_client, &smtp_relay, &metrics, batch_size, &inflight).await;
            }
            Some(mail_uuid) = trigger_rx.recv() => {
                debug!(operation="scheduler_trigger_wake", %mail_uuid, "Scheduler woken by SMTP receiver trigger");
                // Register in inflight set so interval batch skips this email
                inflight.lock().await.insert(mail_uuid.clone());
                match email_factory.get(&mail_uuid).await {
                    Ok(Some(record)) => {
                        // Guard: skip if already processed by interval sweep
                        if record.status != "ready" {
                            inflight.lock().await.remove(&mail_uuid);
                            // Don't call immediate_forward, fall through to de-register
                        } else {
                            immediate_forward(
                                &email_factory, &attachment_factory, &config, &http_client, &smtp_relay, &record, &metrics,
                            ).await;
                        }
                    }
                    Ok(None) => {
                        warn!(operation="trigger_email_not_found", %mail_uuid, "Trigger: email not found (already processed?)");
                    }
                    Err(e) => {
                        error!(operation="trigger_lookup_failed", %mail_uuid, %e, "Trigger: failed to look up email");
                    }
                }
                // De-register — the email is now completed/retried by immediate_forward
                inflight.lock().await.remove(&mail_uuid);
                debug!(%mail_uuid, "Trigger: removed from inflight set");
            }
            _ = cancel.cancelled() => {
                info!(operation="scheduler_cancellation", "Scheduler: cancellation received, shutting down");
                break Ok(());
            }
        }
    }
}
