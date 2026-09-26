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
        // ── Plain HTTP (the advanced edition fronts this with its own TLS) ──
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
    let outbound = http_state.extensions.outbound.clone();
    let dns_resolver = http_state.dns_resolver.clone();
    let trigger_tx = http_state.trigger_tx.clone();
    tokio::spawn(async move {
        crate::core::scheduler::run_retry_worker_with_trigger(
            email_factory,
            attachment_factory,
            config,
            trigger_tx,
            trigger_rx,
            metrics,
            cancel,
            outbound,
            dns_resolver,
        )
        .await
    })
}

/// Keys the gateway provisions at startup (2026-09-26, owner ruling).
///
/// Two distinct keys by design:
///   * `admin_key`  — gateway-side only, `category="platform"`, scopes `["platform","system"]`.
///     It is ALSO the deployment root secret (credential sealing + DB encryption derive from
///     it), so it must never be handed to an agent host.
///   * `system_key` — agent-side integration key, `category="system"`, scopes `["system"]`,
///     same `system_id`. This is what `aimail install -k` uses on a host: integrating an
///     agent never requires platform authority.
///
/// A field is empty when that key already existed (idempotent restart) or when provisioning
/// was not requested (`provision_system_key == false` on multi-system cloud builds, where
/// agent hosts instead obtain a system key from `POST /api/v1/activate-system`).
#[derive(Clone, Debug, Default)]
pub struct AdminKeys {
    /// Freshly minted gateway-side admin key (empty ⇒ already existed).
    pub admin_key: String,
    /// Freshly minted agent-side system key (empty ⇒ already existed / not requested).
    pub system_key: String,
    /// The instance's bootstrap system id (`<storage>/system.id`) — both keys carry it as
    /// their `system_id`, i.e. it is the identity a client must declare for them.
    pub system_id: String,
    /// Whether this deployment provisions an agent-side system key AT ALL. False on
    /// multi-system cloud builds (agent hosts get theirs from `POST /api/v1/activate-system`),
    /// where the key file is neither written, nor announced, nor expected to exist.
    /// Callers persist/announce B only when this is true — otherwise a system-category key
    /// belonging to some other product (e.g. a shared-domain instance key) makes the
    /// persistence layer emit a bogus "file missing, delete that key" advisory.
    pub system_key_expected: bool,
}

/// Reserved `domain_addr` for the agent-side system key.
///
/// `api_keys` carries `UNIQUE(system_id, domain_addr)` (inline, 2026-09-26), and BOTH
/// bootstrap keys of a single-system instance share `system_id` and an empty
/// `domain_addr`. Rather than rebuild the credentials table, the agent-side key is
/// stored under this reserved, non-domain scope marker — dot-prefixed so it can never
/// collide with a real (bare) domain. Identity lookup matches `domain_addr = ?1 OR
/// system_id = ?1`, so a client declaring the instance's system id still resolves it.
pub const SYSTEM_KEY_DOMAIN_ADDR: &str = ".system";

/// Generate and persist the API keys. Returns the cleartext keys (one-time display).
pub async fn setup_admin_key(
    db: &crate::core::storage::Database,
    config: &crate::core::config::Config,
    system_store: std::sync::Arc<dyn crate::core::strategy::SystemStore>,
    provision_system_key: bool,
) -> crate::core::errors::AppResult<AdminKeys> {
    let db_arc = std::sync::Arc::new(db.clone());
    let factory = crate::core::factory::EnvFactory::new(db_arc, system_store);

    // ── Bootstrap system-id, persisted across restarts ──────────────
    let sid_path = config.storage.path.join("system.id");
    let bootstrap_id = if let Ok(s) = std::fs::read_to_string(&sid_path) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            trimmed.to_string()
        } else {
            generate_and_save_bootstrap_id(&sid_path)
        }
    } else {
        generate_and_save_bootstrap_id(&sid_path)
    };

    let mut keys = AdminKeys {
        admin_key: String::new(),
        system_key: String::new(),
        system_id: bootstrap_id.clone(),
        system_key_expected: provision_system_key,
    };

    // ── Gateway-side admin key (category=platform, scopes=[platform,system]) ──
    // Stays on the gateway: it is the deployment root secret (sealing + DB encryption).
    let existing = factory
        .list_api_keys_by_system(&bootstrap_id, "platform")
        .await
        .map_err(|e| AppError::Internal(format!("check admin key: {e}")))?;
    if !existing.is_empty() {
        tracing::info!(
            operation = "admin_bootstrap_skip",
            "Admin key already exists, skipping bootstrap"
        );
    } else {
        let mut rng = rand::thread_rng();
        let raw_bytes: [u8; 32] = rng.gen();
        let raw_key = hex::encode(raw_bytes);
        let key_hash =
            crate::core::api::seal::store_hash(&crate::core::api::auth::sha256_hex(&raw_key));
        let key_prefix = &raw_key[..8];
        keys.admin_key = raw_key.clone();

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
            "Admin API key provisioned (PlatformAdmin + SystemAdmin; gateway-side only)"
        );
    }

    // ── Agent-side system key (category=system, scopes=[system], same system_id) ──
    // Deliberately NOT platform-scoped: an agent host integrating with this instance must
    // never need platform authority. Written to <storage dir>/<system id>.system.key and
    // shown once on the console (2026-09-26 owner ruling).
    if provision_system_key {
        let existing_system = factory
            .list_api_keys_by_system(&bootstrap_id, "system")
            .await
            .map_err(|e| AppError::Internal(format!("check system key: {e}")))?;
        if existing_system.is_empty() {
            let (raw_system_key, system_prefix) = mint_api_key();
            factory
                .create_api_key(
                    &bootstrap_id,
                    SYSTEM_KEY_DOMAIN_ADDR,
                    &crate::core::api::seal::store_hash(&crate::core::api::auth::sha256_hex(
                        &raw_system_key,
                    )),
                    &system_prefix,
                    &["system".to_string()],
                    None,
                    "system",
                )
                .await
                .map_err(|e| AppError::Internal(format!("system api-key: {e}")))?;
            tracing::info!(
                operation = "system_key_provisioned",
                key_prefix = %system_prefix,
                system_id = %bootstrap_id,
                "System key provisioned — agent-side integration key (`aimail install -k`); \
                 the admin key stays on the gateway side"
            );
            keys.system_key = raw_system_key;
        } else {
            tracing::info!(
                operation = "system_key_bootstrap_skip",
                "System key already exists, skipping bootstrap"
            );
        }
    }

    Ok(keys)
}

/// Mint a fresh 32-byte API key (hex) + its display prefix. No configuration override —
/// there is deliberately no way to supply a key from config.
fn mint_api_key() -> (String, String) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let raw_bytes: [u8; 32] = rng.gen();
    let raw_key = hex::encode(raw_bytes);
    let prefix = raw_key[..8].to_string();
    (raw_key, prefix)
}

/// Align a legacy single-system admin key to the platform-category shape (2026-09-26).
///
/// Legacy `standalone` (and pre-ruling single-system) instances provisioned the bootstrap
/// admin key as `category="system"`, `scopes=["system"]`, `domain_addr=""`. Both bootstrap
/// paths now use `category="platform"`, `scopes=["platform","system"]` — but a legacy row
/// must be ALIGNED IN PLACE, never re-minted: the raw key value is the deployment root
/// secret (credential sealing + DB/base-key derivation), so rotating it would strand every
/// sealed credential in the database. Only `category`/`scopes` change here.
///
/// Returns the pre-migration record when a legacy row was migrated, `None` when there was
/// nothing to align (fresh install, or already aligned).
pub async fn align_legacy_system_admin_key(
    factory: &crate::core::factory::EnvFactory,
    bootstrap_id: &str,
) -> crate::core::errors::AppResult<Option<crate::core::storage::ApiKeyRecord>> {
    let legacy = factory
        .list_api_keys_by_system(bootstrap_id, "system")
        .await?
        .into_iter()
        .find(|k| k.email_address.is_empty());
    if let Some(rec) = &legacy {
        factory
            .update_api_key_category_and_scopes(
                rec.id,
                "platform",
                &["platform".to_string(), "system".to_string()],
            )
            .await?;
    }
    Ok(legacy)
}

/// What the persistence step should do about the agent-side system key.
///
/// Kept as a pure decision (no IO, no logging) so the cloud-vs-single-system split is
/// unit-testable: the 2026-09-26 cloud regression was a WARN-only symptom, which a
/// file-level assertion could not have caught.
#[derive(Debug, PartialEq, Eq)]
enum SystemKeyAction {
    /// This deployment does not provision an agent-side system key at all (multi-system
    /// cloud build) — no file to write, nothing to announce, nothing to expect on disk.
    NotProvisioned,
    /// Freshly minted this boot: write it out and announce it once.
    WriteNew,
    /// Already in the database (idempotent restart): its file must hold the raw value.
    ExpectExisting,
}

fn system_key_action(system_key_expected: bool, minted: bool) -> SystemKeyAction {
    match (system_key_expected, minted) {
        (false, _) => SystemKeyAction::NotProvisioned,
        (true, true) => SystemKeyAction::WriteNew,
        (true, false) => SystemKeyAction::ExpectExisting,
    }
}

/// Write the provisioned keys to disk and return the one-time console banner.
///
/// Shared by the base and advanced binaries so both announce the same thing: the
/// gateway-side admin key file (never handed to agents) and the agent-side system key
/// file (`<storage dir>/<system id>.system.key`). Colocation with the DB is warned about
/// for both, for the same reason (a directory backup would leak the deployment root
/// secret). Paths are passed in because the binaries resolve them before the config is
/// moved into the server.
pub fn persist_provisioned_keys(
    admin_key_file: Option<&std::path::Path>,
    system_key_file: Option<&std::path::Path>,
    storage_dir: &std::path::Path,
    db_path: &std::path::Path,
    keys: &AdminKeys,
) -> String {
    let db_parent = db_path.parent().map(|p| p.to_path_buf());
    let admin_path: std::path::PathBuf = admin_key_file
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.admin_key", db_path.display())));
    if admin_path.parent().map(|p| p.to_path_buf()) == db_parent {
        tracing::warn!(
            operation = "admin_key_colocated",
            path = %admin_path.display(),
            "platform admin key sits in the same directory as the database — a backup of that \
             directory would leak both; move it (e.g. /etc/aimail/admin.key, 0600 root)"
        );
    }
    if !keys.admin_key.is_empty() {
        if let Err(e) = std::fs::write(&admin_path, &keys.admin_key) {
            tracing::warn!(operation = "admin_key_write_failed", path = %admin_path.display(), %e, "Failed to write admin key file");
        }
    }

    // ── Agent-side system key ───────────────────────────────────────
    // Cloud (multi-system) builds never provision one (agent hosts use
    // `POST /api/v1/activate-system`), so there is neither a file to write or announce
    // nor one expected to exist — and a system-category key owned by some other product
    // (e.g. a shared-domain instance key) must not trigger a bogus advisory.
    let action = system_key_action(keys.system_key_expected, !keys.system_key.is_empty());
    if action == SystemKeyAction::NotProvisioned {
        return String::new();
    }
    let system_path: std::path::PathBuf = system_key_file
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| storage_dir.join(format!("{}.system.key", keys.system_id)));
    if system_path.parent().map(|p| p.to_path_buf()) == db_parent {
        tracing::warn!(
            operation = "system_key_colocated",
            path = %system_path.display(),
            "system key sits in the same directory as the database — move it out (e.g. \
             /etc/aimail/system.key, 0600 root)"
        );
    }
    match action {
        SystemKeyAction::NotProvisioned => String::new(),
        SystemKeyAction::WriteNew => {
            if let Err(e) = std::fs::write(&system_path, format!("{}\n", keys.system_key)) {
                tracing::warn!(operation = "system_key_write_failed", path = %system_path.display(), %e, "Failed to write system key file");
            }
            format!(
                "\n── AIMail system key (agent-side integration) ──\n  system id : {}\n  key       : {}\n  file      : {}\n  use it on an agent host: aimail install -k <key>   (the admin key stays on the gateway side)\n",
                keys.system_id,
                keys.system_key,
                system_path.display()
            )
        }
        // Nothing minted this boot ⇒ the key already exists in the database, so its file
        // (which holds the only copy of the raw value) must be here.
        SystemKeyAction::ExpectExisting => {
            if !system_path.exists() {
                tracing::warn!(
                    operation = "system_key_file_missing",
                    path = %system_path.display(),
                    system_id = %keys.system_id,
                    "a system key exists in the database but its file is missing — the raw key cannot \
                     be recovered; delete that key (POST /api/v1/admin/api-keys/:id) and restart to \
                     mint a fresh one"
                );
            }
            String::new()
        }
    }
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
        .ok()
        .and_then(|s| {
            if s.trim().is_empty() {
                None
            } else {
                Some(s.trim().to_string())
            }
        })
        .unwrap_or_else(|| {
            let id = format!("system-{:04x}", rand::random::<u16>());
            let _ = std::fs::write(&sid_path, &id);
            id
        });

    email_factory
        .env_factory
        .register_interceptor(std::sync::Arc::new(
            crate::core::stranger_interceptor::StrangerInterceptor::new(
                email_factory.clone(),
                &bootstrap_id,
                max_attempts,
                Some(http_state.trigger_tx.clone()),
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
    let admission_gate = http_state.extensions.admission_gate.clone();
    crate::board::interceptor::register(
        &email_factory,
        &attachment_factory,
        storage_path,
        &endpoint,
        admission_gate,
        Some(http_state.trigger_tx.clone()),
        crate::board::notify::ReplyPolicy::parse(&http_state.config.board.command_reply),
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

#[cfg(test)]
mod tests {
    use super::{system_key_action, SystemKeyAction};

    // Regression (2026-09-26, found live on a cloud fixture): the persistence step used to
    // compute the agent-side key path unconditionally, so a multi-system cloud deployment
    // logged `system_key_colocated` and — because some OTHER product's system-category key
    // (a shared-domain instance key) existed in the database — a bogus
    // `system_key_file_missing` advisory telling the operator to delete that key. Cloud
    // builds never provision B (agent hosts use POST /api/v1/activate-system), so the
    // decision must be a no-op for them no matter what is in the database.
    #[test]
    fn cloud_deployments_never_manage_the_system_key_file() {
        assert_eq!(
            system_key_action(false, false),
            SystemKeyAction::NotProvisioned,
            "no system key in the database ⇒ nothing to expect on disk"
        );
        assert_eq!(
            system_key_action(false, true),
            SystemKeyAction::NotProvisioned,
            "even with a key value at hand, cloud must not write/announce a system key file"
        );
    }

    #[test]
    fn single_system_deployments_write_then_expect_the_system_key_file() {
        assert_eq!(system_key_action(true, true), SystemKeyAction::WriteNew);
        assert_eq!(
            system_key_action(true, false),
            SystemKeyAction::ExpectExisting,
            "idempotent restart: the raw value only exists in the file"
        );
    }
}
