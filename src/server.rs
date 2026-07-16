use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use amail_base::core::config::Config;
use amail_base::core::email::factory::AttachmentFactory;
use amail_base::core::email::factory::EmailFactory;
use amail_base::core::errors::AppResult;
use amail_base::board::quota::NoopBoardQuota;
use amail_base::core::storage::Database;

use amail_base::core::api::http::create_router;
use amail_base::core::api::monitor::Metrics;
use amail_base::core::scheduler;
use amail_base::core::strategy::{MessageSigner, RouterHook};

use amail_base::base::strategy::BaseMessageSigner;

/// amail-gateway server: SMTP, HTTP, and retry worker.
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
        db.init_global();
        let metrics = Arc::new(Metrics::with_version(concat!("base-", env!("GIT_VERSION"))));

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

    /// Generate and persist the admin API key. Returns the cleartext key.
    pub async fn setup_admin_key(&self) -> AppResult<String> {
        amail_base::core::server::setup_admin_key(
            &self.db,
            &self.config,
            Arc::new(amail_base::base::strategy::BaseSystemStore),
        )
        .await
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

        {
            let endpoint = amail_base::core::server::api_endpoint_url(&config);
    let has_tls = false;
            info!(%endpoint, has_tls, "HTTP API endpoint");
        }

        let db_arc = Arc::new(db.clone());

        let system_store: Arc<dyn amail_base::core::strategy::SystemStore> =
            Arc::new(amail_base::base::strategy::BaseSystemStore);

        let email_factory = Arc::new(EmailFactory::new(
            db_arc.clone(),
            config.storage.attachments_dir(),
            system_store.clone(),
        ));
        let attachment_factory = Arc::new(AttachmentFactory::new(
            db_arc.clone(),
            config.storage.attachments_dir(),
        ));

        // ── Register interceptors (a2a_board, [WHOAMI]) ──
        {
            let endpoint = amail_base::core::server::api_endpoint_url(&config);
            amail_base::core::server::register_stranger_interceptor(
                &email_factory,
                "admin",
            );
            amail_base::core::server::register_board_interceptors(
                &email_factory,
                &attachment_factory,
                config.storage.path.to_str().unwrap_or(""),
                &endpoint,
                Arc::new(NoopBoardQuota),
            );
        }

        let dkim_signer: Arc<dyn MessageSigner> = Arc::new(BaseMessageSigner);

        let extensions = Arc::new(amail_base::core::strategy::ExtensionProviders::base());
        let http_state = amail_base::core::api::types::HttpState {
            email_factory: (*email_factory).clone(),
            attachment_factory: (*attachment_factory).clone(),
            metrics: metrics.clone(),
            config: config.clone(),
            trigger_tx: trigger_tx.clone(),
            extensions: extensions.clone(),
        };
        let base_hook: Arc<dyn RouterHook> = Arc::new(
            amail_base::base::strategy::BaseRouterHook(http_state.clone()),
        );
        let router_hook: Arc<dyn RouterHook> = base_hook;
        let smtp_handle = amail_base::core::server::spawn_smtp(
            &http_state,
            cancel.clone(),
        )?;

        let router = create_router(http_state, router_hook, None, None);

        let metrics_for_worker = (*metrics).clone();
        let inflight = scheduler::new_inflight_set();
        let dns_resolver = amail_base::core::server::create_dns_resolver(&config)?;
        let retry_handle = amail_base::core::server::spawn_retry_worker(
            (*email_factory).clone(),
            (*attachment_factory).clone(),
            config.clone(),
            trigger_rx,
            metrics_for_worker,
            cancel.clone(),
            inflight,
            Some(dkim_signer.clone() as Arc<dyn MessageSigner>),
            Some(dns_resolver.clone()),
        );
        let http_handle =
            amail_base::core::server::spawn_http_single_port(router, &config, cancel.clone());

        amail_base::core::server::spawn_cleanup_worker(
            db_arc.clone(),
            config.webhook.pending_ttl_hours,
            cancel.clone(),
        );

        amail_base::core::cli::graceful::wait_for_services(
            cancel,
            http_handle,
            smtp_handle,
            retry_handle,
        )
        .await
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
