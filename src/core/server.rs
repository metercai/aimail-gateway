//! Shared server utilities.

use axum::Router;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::core::api::types::HttpState;
use crate::core::config::Config;
use crate::core::errors::{AppError, AppResult};
use hex;
use rand::Rng;

pub fn spawn_smtp<H: mailin::Handler + Clone + Send + 'static>(
    http_state: &HttpState,
    handler: H,
    cancel: CancellationToken,
) -> AppResult<JoinHandle<AppResult<()>>> {
    let listen_addr = http_state.config.smtp.bind.clone();
    let max_connections = http_state.config.smtp.max_connections;
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let metrics = http_state.metrics.clone();

    // Extract owned Arc values before entering async move
    let arc_config = Arc::new(http_state.config.clone());

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
                            let arc_config = arc_config.clone();
                            let handler = handler.clone();
                            // Convert tokio TcpStream → std TcpStream so we can run
                            // mailin (sync) on a blocking thread.  This avoids the
                            // "Cannot start a runtime from within a runtime" panic
                            // when the handler calls
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
                                crate::core::smtp::receiver::handle_smtp_session_blocking(std_stream, peer_addr, arc_config, handler);
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

// ── retry worker ──────────────────────────────────────────────────

pub fn spawn_retry_worker(
    http_state: &HttpState,
    trigger_rx: tokio::sync::mpsc::Receiver<String>,
    cancel: CancellationToken,
) -> JoinHandle<AppResult<()>> {
    let email_factory = (*http_state.factories.email).clone();
    let attachment_factory = (*http_state.factories.attachment).clone();
    let config = http_state.config.clone();
    let metrics = (*http_state.metrics).clone();
    let dkim_signer =
        Some(http_state.extensions.dkim_signer.clone()
            as Arc<dyn crate::core::strategy::MessageSigner>);
    let dns_resolver = http_state.dns_resolver.clone();
    let inflight = crate::core::scheduler::new_inflight_set();
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

    // ── Bootstrap system-id, persisted across restarts ──────────────
    let sid_path = config.storage.path.join("system.id");
    let bootstrap_id = if let Ok(s) = std::fs::read_to_string(&sid_path) {
        let trimmed = s.trim();
        if !trimmed.is_empty() { trimmed.to_string() }
        else { generate_and_save_bootstrap_id(&sid_path) }
    } else {
        generate_and_save_bootstrap_id(&sid_path)
    };

    let existing = factory
        .list_api_keys_by_system(&bootstrap_id, "platform")
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
            &bootstrap_id,
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

/// Create a shared DNS resolver.
/// Priority: relay.dns_server (config) > system /etc/resolv.conf.
pub fn create_dns_resolver(
    config: &Config,
) -> AppResult<Arc<hickory_resolver::TokioAsyncResolver>> {
    if let Some(ref addr_str) = config.relay.dns_server {
        let sa: std::net::SocketAddr = addr_str.parse().map_err(|e| {
            AppError::Internal(format!(
                "Invalid relay.dns_server address '{}': {e}",
                addr_str
            ))
        })?;
        let mut resolver_cfg = hickory_resolver::config::ResolverConfig::new();
        resolver_cfg.add_name_server(hickory_resolver::config::NameServerConfig::new(
            sa,
            hickory_resolver::config::Protocol::Udp,
        ));
        let opts = hickory_resolver::config::ResolverOpts::default();
        Ok(Arc::new(hickory_resolver::TokioAsyncResolver::tokio(
            resolver_cfg,
            opts,
        )))
    } else {
        hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .map(Arc::new)
            .map_err(|e| AppError::DnsResolve(format!("Failed to create DNS resolver: {e}")))
    }
}

/// Register the StrangerInterceptor for universal commands ([WHOAMI] etc.).
pub fn register_stranger_interceptor(http_state: &HttpState) {
    let email_factory = http_state.factories.email.clone();
    let max_attempts = http_state.config.retry.max_attempts as i32;
    let sid_path = http_state.config.storage.path.join("system.id");
    let bootstrap_id = std::fs::read_to_string(&sid_path)
        .ok().and_then(|s| if s.trim().is_empty() { None } else { Some(s.trim().to_string()) })
        .unwrap_or_else(|| {
            let id = format!("system-{:04x}", rand::random::<u16>());
            let _ = std::fs::write(&sid_path, &id);
            id
        });

    // ── Legacy support: if the bootstrap ID doesn't exist yet but
    //    there are existing api_keys under "admin", use "admin" once
    //    then migrate.  One-shot migration.

    email_factory
        .env_factory
        .register_interceptor(std::sync::Arc::new(
            crate::core::stranger_interceptor::StrangerInterceptor::new(
                email_factory.clone(),
                &bootstrap_id,
                max_attempts,
            ),
        )
            as std::sync::Arc<dyn crate::core::strategy::InboundInterceptor>);
}

/// Register the A2A board interceptor.
pub fn register_board_interceptors(http_state: &HttpState) {
    let email_factory = http_state.factories.email.clone();
    let attachment_factory = http_state.factories.attachment.clone();
    let storage_path = http_state.config.storage.path.to_str().unwrap_or("");
    let endpoint = api_endpoint_url(&http_state.config);
    let board_quota = http_state.extensions.board_quota.clone();
    crate::board::interceptor::register(
        &email_factory,
        &attachment_factory,
        storage_path,
        &endpoint,
        board_quota,
    );
}

/// Spawn a background worker that periodically cleans up stale pending deliveries.
pub fn spawn_cleanup_worker(
    db: Arc<crate::core::storage::Database>,
    ttl_hours: u64,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
            ttl_hours.max(1) * 3600 / 2,
        ));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(e) = db.cleanup_deliveries(ttl_hours).await {
                        tracing::warn!(error = %e, "Failed to cleanup pending deliveries");
                    }
                }
            }
        }
    })
}

fn generate_and_save_bootstrap_id(path: &std::path::Path) -> String {
    use rand::Rng;
    let id = format!("system-{:04x}", rand::thread_rng().gen::<u16>());
    let _ = std::fs::write(path, &id);
    id
}
