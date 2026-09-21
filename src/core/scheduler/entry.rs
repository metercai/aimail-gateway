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
use crate::core::strategy::OutboundTransform;

use super::batch::process_batch;
use super::flows::immediate_forward;

/// Scheduler that wakes on interval ticks and an mpsc trigger from SMTP receiver
/// Returns an error if SMTP delivery cannot be initialized — fatal for base edition.
pub async fn run_retry_worker_with_trigger(
    email_factory: EmailFactory,
    attachment_factory: AttachmentFactory,
    config: Config,
    trigger_tx: mpsc::Sender<String>,
    mut trigger_rx: mpsc::Receiver<String>,
    metrics: Metrics,
    cancel: CancellationToken,
    outbound: Arc<dyn OutboundTransform>,
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

    // 投递并发化(方案 B): relay/metrics 包成 Arc 以便搬进 spawn 的投递任务;
    // 方法调用与 `&x` 传参靠 deref 自动兼容, 下游签名无需改动。
    let smtp_relay = match SmtpRelay::from_config(
        &config.relay,
        Arc::new(email_factory.clone()),
        config.smtp.hostname.as_deref(),
        outbound,
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
    // Clone the trigger sender for the tick path: the exhaustion flows
    // (overlimit auto-replies, retry notifications) insert new `readying`
    // emails and must wake the scheduler for their first delivery.
    let trigger_tx = trigger_tx.clone();

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

    // ── 并发投递(方案 B): 上限 smtp.max_concurrent_deliveries(默认 4) ──
    let metrics = Arc::new(metrics);
    let smtp_relay = Arc::new(smtp_relay);
    let delivery_sem = Arc::new(tokio::sync::Semaphore::new(
        config.smtp.max_concurrent_deliveries.max(1),
    ));

    let mut interval = time::interval(poll_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                tracing::debug!("Scheduler periodic tick");
                if let Ok(count) = email_factory.count_pending_emails().await {
                    metrics.set_scheduler_pending_count(count);
                }
                process_batch(&email_factory, &attachment_factory, &config, &http_client, &smtp_relay, &metrics, batch_size, &trigger_tx).await;
            }
            Some(mail_uuid) = trigger_rx.recv() => {
                debug!(operation="scheduler_trigger_wake", %mail_uuid, "Scheduler woken by SMTP receiver trigger");
                // 先取槽位再 spawn: 排队期间邮件仍是 readying(救援扫描可兜底),
                // claim 已保证同一封不会重复投递 ⇒ 无需额外 in-flight 集合。
                let permit = match delivery_sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let record = match email_factory.claim_ready(&mail_uuid).await {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        debug!(%mail_uuid, "Trigger: email already consumed before dispatch");
                        drop(permit);
                        continue;
                    }
                    Err(e) => {
                        error!(operation="trigger_claim_failed", %mail_uuid, %e, "Trigger: CAS claim failed");
                        drop(permit);
                        continue;
                    }
                };
                let (ef, af, cfg, hc, sr, mt, tx) = (
                    email_factory.clone(), attachment_factory.clone(), config.clone(),
                    http_client.clone(), smtp_relay.clone(), metrics.clone(), trigger_tx.clone(),
                );
                tokio::spawn(async move {
                    immediate_forward(&ef, &af, &cfg, &hc, &sr, &record, &mt, Some(&tx)).await;
                    drop(permit);
                });
            }
            _ = cancel.cancelled() => {
                info!(operation="scheduler_cancellation", "Scheduler: cancellation received, shutting down");
                break Ok(());
            }
        }
    }
}
