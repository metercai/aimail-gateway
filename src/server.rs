use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use aimail_base::core::config::Config;
use aimail_base::core::errors::AppResult;
use aimail_base::core::storage::Database;

use aimail_base::core::api::http::create_router;
use aimail_base::core::api::monitor::Metrics;
use aimail_base::core::strategy::RouterHook;

/// aimail-gateway server: SMTP, HTTP, and retry worker.
pub struct Server {
    config: Config,
    db: Database,
    metrics: Arc<Metrics>,
    /// Activation code encryption key.
    pub base_key: std::sync::OnceLock<[u8; 32]>,
}

impl Server {
    /// Create a new server instance.
    pub fn new(config: Config, db_path: PathBuf, db_key: Option<&str>) -> AppResult<Self> {
        info!(db_path = ?db_path, "Opening database");

        if db_key.is_some() {
            info!(
                "Database encryption enabled (SQLCipher AES-256-CBC, key derived from admin_key)"
            );
        }

        let db = Database::open(&db_path, 25, db_key)?;
        // Neutral prefix: the version string identifies the binary, not an edition.
        let metrics = Arc::new(Metrics::with_version(concat!(
            "gateway-",
            env!("GIT_VERSION")
        )));

        Ok(Self {
            config,
            db,
            metrics,
            base_key: std::sync::OnceLock::new(),
        })
    }

    /// Return a shared reference to the underlying database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Provision the startup keys: gateway-side admin key + (single-system build)
    /// agent-side system key. See `aimail_base::core::server::setup_admin_key`.
    pub async fn setup_admin_key(&self) -> AppResult<aimail_base::core::server::AdminKeys> {
        aimail_base::core::server::setup_admin_key(
            &self.db,
            &self.config,
            Arc::new(aimail_base::base::strategy::BaseSystemStore),
            true,
        )
        .await
    }

    /// At startup, seal the DB's historical plaintext credential material in place (idempotent).
    pub async fn reseal_credentials(&self) -> AppResult<(usize, usize)> {
        self.db.reseal_api_keys().await
    }

    /// For the startup fail-closed check: the number of sealed credential rows in the DB.
    pub async fn count_sealed_credentials(&self) -> AppResult<usize> {
        self.db.count_sealed_api_keys().await
    }

    pub async fn run(self) -> AppResult<()> {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            info!(
                operation = "shutdown_signal",
                "Shutdown signal received. Initiating graceful shutdown..."
            );
            cancel_clone.cancel();
        });

        self.run_with_cancel(cancel).await
    }

    /// Start services and run until cancelled.
    pub async fn run_with_cancel(self, cancel: CancellationToken) -> AppResult<()> {
        let (trigger_tx, trigger_rx) = mpsc::channel::<String>(self.config.smtp.channel_capacity);

        let db = self.db;
        let metrics = self.metrics;
        let config = self.config;

        let endpoint = aimail_base::core::server::api_endpoint_url(&config);
        info!(%endpoint, "HTTP API endpoint");

        if config.webhook.allow_private_targets {
            info!(
                operation = "webhook_private_targets_enabled",
                "D3: [webhook] allow_private_targets = true — webhook delivery to \
                 loopback/private/link-local/ULA targets is PERMITTED. This weakens the \
                 blind-SSRF defence; keep it off unless this gateway runs a private \
                 single-machine deployment."
            );
        }

        if config.api.allow_unidentified_keys {
            info!(
                operation = "unidentified_keys_enabled",
                "D1: [api] allow_unidentified_keys = true — requests with an empty \
                 X-Api-Identity fall back to a 64-key candidate scan; without this flag \
                 they are refused with 401 identity_required before any body read or \
                 database access."
            );
        }

        let db_arc = Arc::new(db.clone());

        let system_store: Arc<dyn aimail_base::core::strategy::SystemStore> =
            Arc::new(aimail_base::base::strategy::BaseSystemStore);

        let dns_resolver = aimail_base::core::server::create_dns_resolver(&config)?;
        let extensions = Arc::new(aimail_base::core::strategy::ExtensionProviders::base());
        let http_state = aimail_base::core::api::types::HttpState {
            // D9: the [api] signature window (default 120 s) and the optional
            // replay cache are wired into the shared env factory here — the
            // single production wiring point for API request authentication.
            factories: aimail_base::core::email::factory::MailFactories::new_with_signature_auth(
                db_arc.clone(),
                &config.storage.path,
                system_store.clone(),
                config.api.signature_window_secs,
                config.api.replay_protection,
                config.webhook.allow_private_targets,
                config.api.allow_unidentified_keys,
            ),
            metrics: metrics.clone(),
            config: config.clone(),
            trigger_tx: trigger_tx.clone(),
            extensions: extensions.clone(),
            dns_resolver: Some(dns_resolver.clone()),
            send_deduper: aimail_base::core::api::dedup::SendDeduper::new(
                std::time::Duration::from_secs(config.retry.send_dedupe_window_secs),
                4096,
            ),
            delivery_slot: aimail_base::core::api::types::SingleSlotLock::new(),
            health_extra: None,
        };

        // ── Register interceptors (a2a_board, [WHOAMI]) ──
        aimail_base::core::server::register_stranger_interceptor(&http_state);
        aimail_base::core::server::register_board_interceptors(&http_state);
        let base_hook: Arc<dyn RouterHook> = Arc::new(aimail_base::base::strategy::BaseRouterHook(
            http_state.clone(),
        ));
        let router_hook: Arc<dyn RouterHook> = base_hook;
        // SMTP inbound handler: pure business logic — no security layer, no
        // rate limits, no TLS (those concerns live outside this path).
        let smtp_handler = aimail_base::core::smtp::receiver::ConnectionHandler::new(
            Arc::new(config.clone()),
            http_state.factories.email.clone(),
            http_state.factories.attachment.clone(),
            http_state.trigger_tx.clone(),
            http_state.metrics.clone(),
        );
        let smtp_handle =
            aimail_base::core::server::spawn_smtp(&http_state, smtp_handler, cancel.clone())?;

        // Clone http_state before create_router moves it
        let http_state_for_worker = http_state.clone();
        let router = create_router(http_state, router_hook, None, None, None, None);

        let retry_handle = aimail_base::core::server::spawn_retry_worker(
            &http_state_for_worker,
            trigger_rx,
            cancel.clone(),
        );
        let http_handle =
            aimail_base::core::server::spawn_http_single_port(router, &config, cancel.clone());

        let cleanup_handle = aimail_base::core::server::spawn_cleanup_worker(
            db_arc.clone(),
            config.webhook.pending_ttl_hours,
            cancel.clone(),
        );

        // D5: batch-flush last_used_at (30 s cadence). The worker exits on
        // cancel WITHOUT flushing; the final flush runs below, after the
        // services have drained.
        let last_used_tracker = http_state_for_worker
            .factories
            .email
            .env_factory
            .last_used_tracker()
            .clone();
        let last_used_handle = aimail_base::core::server::spawn_last_used_flush_worker(
            db_arc.clone(),
            last_used_tracker.clone(),
            30,
            cancel.clone(),
        );

        let shutdown = aimail_base::core::cli::graceful::wait_for_services(
            cancel,
            http_handle,
            smtp_handle,
            retry_handle,
            cleanup_handle,
        )
        .await;

        // D5: final flush — the HTTP server is fully down (wait_for_services
        // awaited it), so no new notes can arrive while this writes; every
        // key used during the run is now persisted.
        if let Err(_e) =
            tokio::time::timeout(std::time::Duration::from_secs(5), last_used_handle).await
        {
            tracing::warn!(
                operation = "last_used_flush_worker_join_timeout",
                "last_used flush worker did not exit in time"
            );
        }
        if let Err(e) =
            aimail_base::core::server::last_used_flush_once(&db_arc, &last_used_tracker).await
        {
            tracing::warn!(
                operation = "last_used_final_flush_failed",
                error = %e,
                "final last_used_at flush failed"
            );
        }

        shutdown
    }
}

// ── Shutdown Signal ──────────────────────────────────────────────────

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    async {
        let mut term = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    .await;

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
