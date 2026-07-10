//! Shared server utilities.

use axum::Router;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::core::api::monitor::Metrics;
use crate::core::config::Config;
use crate::core::email::factory::{AttachmentFactory, EmailFactory};
use crate::core::errors::{AppError, AppResult};
use crate::core::strategy::{InboundSecurity, QuotaChecker, RateLimitChecker};
use hex;
use rand::Rng;

pub fn spawn_smtp(
    config: &crate::core::config::SmtpConfig,
    email_factory: Arc<EmailFactory>,
    attachment_factory: Arc<AttachmentFactory>,
    arc_config: Arc<Config>,
    trigger_tx: mpsc::Sender<String>,
    cancel: CancellationToken,
    metrics: Arc<Metrics>,
    inbound_security: Arc<dyn InboundSecurity>,
    rate_limiter: Arc<dyn RateLimitChecker>,
    quota_checker: Arc<dyn QuotaChecker>,
) -> AppResult<JoinHandle<AppResult<()>>> {
    let listen_addr = config.bind.clone();
    let max_connections = config.max_connections;
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));
    info!(
        operation = "smtp_max_connections",
        max_connections = max_connections,
        "SMTP max connections"
    );

    let handle = tokio::spawn(async move {

        let listener = match crate::core::cli::daemon::bind_with_reuseaddr(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(operation="smtp_bind_failed", %e, addr = %listen_addr, "Failed to bind SMTP listener");
                return Err(e.into());
            }
        };
        info!(operation="smtp_listening", addr = %listen_addr, "SMTP server listening");

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            trace!(?peer_addr, "SMTP accepted connection");
                            // Acquire an owned permit — Arc<Semaphore> variant that
                            // lives independently of the local clone.
                            let permit = match conn_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!(operation="smtp_connection_limit", peer_addr = %peer_addr, "SMTP connection limit reached, dropping");
                                    metrics.inc_smtp_connections_rejected();
                                    continue;
                                }
                            };
                            let email_factory = email_factory.clone();
                            let attachment_factory = attachment_factory.clone();
                            let arc_config = arc_config.clone();
                            let trigger_tx = trigger_tx.clone();
                            let inbound_security = inbound_security.clone();
                            let metrics = metrics.clone();
                            let rate_limiter = rate_limiter.clone();
                            let quota_checker = quota_checker.clone();
                            // Convert tokio TcpStream → std TcpStream so we can run
                            // mailin (sync) on a blocking thread.  This avoids the
                            // "Cannot start a runtime from within a runtime" panic
                            // when ConnectionHandler::block_on calls
                            // Handle::current().block_on(...).

                            // Disable Nagle's algorithm so SMTP greeting and
                            // responses are sent immediately instead of being
                            // delayed for coalescing.  Without this, the small
                            // SMTP greeting (~20-30 bytes) may sit in the
                            // kernel buffer, causing clients (lettre) to read
                            // an incomplete response.
                            if let Err(e) = stream.set_nodelay(true) {
                                tracing::warn!(operation="tcp_nodelay_failed", %e, "Failed to set TCP_NODELAY on SMTP stream");
                            }

                            let std_stream = match stream.into_std() {
                                Ok(s) => {
                                    // Belt-and-suspenders: also try nodelay on std stream
                                    let _ = s.set_nodelay(true);
                                    // CRITICAL: into_std() returns the stream still in
                                    // non-blocking mode (tokio sets the fd O_NONBLOCK).
                                    // mailin uses blocking BufRead::read_line() under
                                    // spawn_blocking, so it needs the stream back in
                                    // blocking mode to avoid EAGAIN on every read.
                                    if let Err(e) = s.set_nonblocking(false) {
                                        tracing::warn!(operation="set_blocking_failed", %e, "Failed to set blocking mode on SMTP stream");
                                    }
                                    // Set read timeout to prevent slowloris — idle connections
                                    // holding semaphore permits indefinitely.
                                    if let Err(e) = s.set_read_timeout(Some(std::time::Duration::from_secs(120))) {
                                        tracing::warn!(operation="set_read_timeout_failed", %e, "Failed to set read timeout on SMTP stream");
                                    }
                                    s
                                }
                                Err(e) => {
                                    tracing::warn!(operation="tcp_to_std_failed", %e, "Failed to convert TcpStream to std; dropping connection");
                                    continue;
                                }
                            };
                            tokio::task::spawn_blocking(move || {
                                let _permit = permit;
                                crate::core::smtp::receiver::handle_smtp_session_blocking(std_stream, peer_addr, email_factory, attachment_factory, arc_config, inbound_security, trigger_tx, metrics, rate_limiter, quota_checker);
                            });
                        }
                        Err(e) => {
                            error!(operation="smtp_accept_error", %e, "SMTP accept error");
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    info!(operation="smtp_cancellation", "SMTP server: cancellation received, stopping listener");
                    break;
                }
            }
        }

        info!(operation = "smtp_server_stopped", "SMTP server shut down");
        Ok(())
    });

    Ok(handle)
}

pub fn api_endpoint_url(config: &Config) -> String {
    let scheme = "http";
    if let Some(ref host) = config.http.hostname {
        let port = config.http.bind.rsplit(':').next().unwrap_or("80");
        format!("{}://{}:{}", scheme, host, port)
    } else {
        format!("{}://{}", scheme, config.http.bind)
    }
}

pub async fn bind_with_reuseaddr(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    use std::net::SocketAddr;

    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let socket = match socket_addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };

    socket.set_reuseaddr(true)?;
    socket.bind(socket_addr)?;
    socket.listen(1024)
}

pub fn spawn_http_single_port(
    router: Router,
    config: &crate::core::config::Config,
    cancel: CancellationToken,
) -> JoinHandle<AppResult<()>> {
    let http_cfg = config.http.clone();
    tokio::spawn(async move {
        // ── Plain HTTP (TLS migrated to advanced edition) ──
        let listener = bind_with_reuseaddr(&http_cfg.bind)
            .await
            .unwrap_or_else(|e| panic!("HTTP bind failed on {}: {}", http_cfg.bind, e));
        info!(operation="http_listening", addr = %http_cfg.bind, "HTTP server listening");

        let shutdown_future = async move {
            cancel.cancelled().await;
            info!(
                operation = "http_shutdown_initiated",
                "HTTP server: graceful shutdown initiated"
            );
        };

        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_future)
        .await?;

        Ok(())
    })
}

pub fn spawn_retry_worker(
    email_factory: crate::core::email::factory::EmailFactory,
    attachment_factory: crate::core::email::factory::AttachmentFactory,
    config: crate::core::config::Config,
    trigger_rx: tokio::sync::mpsc::Receiver<String>,
    metrics: crate::core::api::monitor::Metrics,
    cancel: CancellationToken,
    inflight: crate::core::scheduler::InflightSet,
    dkim_signer: Option<Arc<dyn crate::core::strategy::MessageSigner>>,
    dns_resolver: Option<Arc<hickory_resolver::TokioAsyncResolver>>,
) -> JoinHandle<AppResult<()>> {
    tokio::spawn(async move {
        crate::core::scheduler::run_retry_worker_with_trigger(
            email_factory,
            attachment_factory,
            config,
            trigger_rx,
            metrics,
            cancel,
            inflight,
            dkim_signer,
            dns_resolver,
        )
        .await
    })
}

/// Generate and persist the admin API key.
pub async fn setup_admin_key(
    db: &crate::core::storage::Database,
    config: &crate::core::config::Config,
    system_store: std::sync::Arc<dyn crate::core::strategy::SystemStore>,
) -> crate::core::errors::AppResult<String> {
    let db_arc = std::sync::Arc::new(db.clone());
    let factory = crate::core::factory::EnvFactory::new(
        db_arc,
        system_store,
        Arc::new(crate::core::whitelist::ExactKeyResolver),
    );

    let existing = factory
        .list_api_keys_by_system("admin", "platform")
        .await
        .map_err(|e| AppError::Internal(format!("check admin key: {e}")))?;
    if !existing.is_empty() {
        tracing::info!(
            operation = "admin_bootstrap_skip",
            "Admin key already exists, skipping bootstrap"
        );
        return Ok(String::new());
    }

    let mut rng = rand::thread_rng();
    let raw_bytes: [u8; 32] = rng.gen();
    let raw_key = hex::encode(raw_bytes);
    let key_hash = crate::core::api::auth::sha256_hex(&raw_key);
    let key_prefix = &raw_key[..8];

    factory
        .create_api_key(
            "admin",
            "",
            &key_hash,
            key_prefix,
            &["platform".to_string(), "system".to_string()],
            None,
            "platform",
        )
        .await
        .map_err(|e| AppError::Internal(format!("admin api-key: {e}")))?;

    tracing::info!(
        operation="admin_key_provisioned",
        key_prefix = %key_prefix,
        endpoint = %api_endpoint_url(config),
        "Admin API key provisioned (PlatformAdmin + SystemAdmin)"
    );
    Ok(raw_key)
}
