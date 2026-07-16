use std::path::PathBuf;

use serde::Deserialize;

/// Full application configuration loaded via: Defaults → TOML → Env Override.
///
/// Environment variables use the prefix `AMAILGW_` and map to nested fields
/// using double underscores (e.g. `AMAILGW_HTTP_ADDR` → `http.addr`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// File path this config was loaded from (for advanced features that
    /// need to re-read sections from the original TOML).
    #[serde(skip)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default, alias = "database")]
    pub storage: StorageConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub retry: RetryConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub board: BoardConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    /// Bind address for the HTTP API server (e.g. "127.0.0.1:3000").
    #[serde(default = "default_http_listen_addr")]
    pub bind: String,
    /// Public hostname for the HTTP API (used for display and logging).
    /// Kept in base edition for api_endpoint_url(); TLS moved to advanced.
    #[serde(default)]
    pub hostname: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_listen_addr(),
            hostname: None,
        }
    }
}

impl HttpConfig {
    /// Parse `addr` into (host, port).  If no port is specified, defaults to 80.
    ///
    /// Examples:
    ///   "0.0.0.0:8080" → ("0.0.0.0", 8080)
    ///   "0.0.0.0"      → ("0.0.0.0", 80)
    ///   "127.0.0.1"    → ("127.0.0.1", 80)
    pub fn parsed_bind(&self) -> (&str, u16) {
        if let Some((host, port_str)) = self.bind.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host, port);
            }
        }
        (&self.bind, 80)
    }

    /// True when dual-port mode (80 + 443) should be enabled.
    ///
    /// Conditions: addr port == 80 AND hostname is set.
    /// This is checked by the advanced-edition server binding.
    pub fn is_dual_port(&self) -> bool {
        let (_, port) = self.parsed_bind();
        port == 80 && self.hostname.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    #[serde(default = "default_smtp_listen_addr")]
    pub bind: String,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// EHLO/HELO hostname for outbound connections and SMTP banner.
    /// Should match the PTR record (e.g. "amail.token.tm") for deliverability.
    /// Default: system hostname (or "amail-relay").
    #[serde(default)]
    pub hostname: Option<String>,
    /// Maximum concurrent SMTP connections. (default: 100)
    #[serde(default = "default_smtp_max_connections")]
    pub max_connections: usize,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            bind: default_smtp_listen_addr(),
            max_message_size: default_max_message_size(),
            channel_capacity: default_channel_capacity(),
            hostname: None,
            max_connections: default_smtp_max_connections(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// SQLite database file path.
    #[serde(default = "default_storage_dir")]
    pub path: PathBuf,
    #[serde(default = "default_db_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_encryption_enabled")]
    pub encryption: bool,
    #[serde(default = "default_attachment_max_size")]
    pub attachment_max_size: usize,
    #[serde(default = "default_attachment_lifetime_hours")]
    pub attachment_lifetime_hours: u32,
    #[serde(default)]
    pub attachment_allowed_types: Vec<String>,
    #[serde(default = "default_attachment_max_count")]
    pub attachment_max_attachments: usize,
}

fn default_encryption_enabled() -> bool {
    false
}

impl StorageConfig {
    pub fn db_path(&self) -> PathBuf {
        self.path.join("amail.db")
    }

    pub fn attachments_dir(&self) -> PathBuf {
        self.path.join("attachments")
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_storage_dir(),
            pool_size: default_db_pool_size(),
            encryption: false,
            attachment_max_size: default_attachment_max_size(),
            attachment_lifetime_hours: default_attachment_lifetime_hours(),
            attachment_allowed_types: Vec::new(),
            attachment_max_attachments: default_attachment_max_count(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// HTTP request timeout per webhook call, in seconds.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,

    /// Max age of pending deliveries before cleanup, in hours.
    /// Pull-mode deliveries older than this are deleted.
    /// Default: 72 (3 days).
    #[serde(default = "default_pending_ttl_hours")]
    pub pending_ttl_hours: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_webhook_timeout(),
            pending_ttl_hours: default_pending_ttl_hours(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_secs: u64,
    #[serde(default = "default_multiplier")]
    pub multiplier: u64,
    #[serde(default = "default_max_backoff")]
    pub max_backoff_secs: u64,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: i32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_backoff_secs: default_initial_backoff(),
            multiplier: default_multiplier(),
            max_backoff_secs: default_max_backoff(),
            poll_interval_secs: default_poll_interval(),
            batch_size: default_batch_size(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    pub smtp_server: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Custom DNS server address (host:port) for all DNS queries (SPF, MX, DKIM).
    /// Takes precedence over system /etc/resolv.conf.
    /// Override precedence: mx_dns_override > dns_server > resolv.conf
    #[serde(default)]
    pub dns_server: Option<String>,
    #[serde(default = "default_auto_reply_from")]
    pub auto_reply_from: Option<String>,
    #[serde(default = "default_auto_reply_subject_prefix")]
    pub auto_reply_subject_prefix: String,
    #[serde(default = "default_auto_reply_body")]
    pub auto_reply_body: Option<String>,
    /// NDR bounce correlation window (seconds). Emails stay in "delivered" status
    /// for this long before being finalized to "completed". Default: 7200s (2h).
    #[serde(default = "default_delivery_window")]
    pub delivery_window_secs: u64,
    /// MX DNS overrides for direct delivery mode (domain -> host:port).
    /// Only used when relay.smtp_server is empty (direct MX mode).
    #[serde(default)]
    pub mx_dns_override: Option<std::collections::HashMap<String, String>>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            smtp_server: None,
            username: None,
            password: None,
            dns_server: None,
            auto_reply_from: default_auto_reply_from(),
            auto_reply_subject_prefix: default_auto_reply_subject_prefix(),
            auto_reply_body: default_auto_reply_body(),
            delivery_window_secs: default_delivery_window(),
            mx_dns_override: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

/// Owner contact email exposed via the /health endpoint.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AdminConfig {
    /// Contact email address of the service owner/operator.
    #[serde(default)]
    pub email: Option<String>,
}

// ── Load: Defaults → TOML → Env Override ─────────────────────────────

/// Load configuration from a TOML file, then overlay `AMAILGW_*` env vars.
///
/// Precedence (lowest → highest): struct defaults → TOML file → environment variables.
pub fn load(path: &str) -> Result<Config, crate::core::errors::AppError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::core::errors::AppError::Config(format!("failed to read config {}: {}", path, e))
    })?;

    let mut config: Config = toml::from_str(&content).map_err(|e| {
        crate::core::errors::AppError::Config(format!("failed to parse config {}: {}", path, e))
    })?;

    // Apply environment variable overrides (AMAILGW_* prefix)
    apply_env_overrides(&mut config);

    // Record path for advanced features that need to re-read sections
    config.config_path = Some(path.to_string());

    Ok(config)
}

/// Apply `AMAILGW_*` environment variable overrides to the config.
///
/// Mapping convention:
/// - `AMAILGW_HTTP_ADDR` → `http.addr`
/// - `AMAILGW_SMTP_ADDR` → `smtp.addr` (alias: listen_addr)
fn apply_env_overrides(config: &mut Config) {
    // ── Core external resources (bind address, upstream services) ──
    // HTTP
    if let Ok(v) = std::env::var("AMAILGW_HTTP_ADDR") {
        if !v.is_empty() {
            config.http.bind = v;
        }
    }

    // SMTP
    if let Ok(v) = std::env::var("AMAILGW_SMTP_ADDR") {
        if !v.is_empty() {
            config.smtp.bind = v;
        }
    }

    // Database
    if let Ok(v) = std::env::var("AMAILGW_STORAGE_PATH") {
        if !v.is_empty() {
            config.storage.path = PathBuf::from(v);
        }
    }

    // Relay (upstream SMTP)
    if let Ok(v) = std::env::var("AMAILGW_RELAY_SMTP_SERVER") {
        if !v.is_empty() {
            config.relay.smtp_server = Some(v);
        }
    }
    if let Ok(v) = std::env::var("AMAILGW_RELAY_USERNAME") {
        if !v.is_empty() {
            config.relay.username = Some(v);
        }
    }
    if let Ok(v) = std::env::var("AMAILGW_RELAY_PASSWORD") {
        if !v.is_empty() {
            config.relay.password = Some(v);
        }
    }

    // Logging
    if let Ok(v) = std::env::var("AMAILGW_LOGGING_LEVEL") {
        if !v.is_empty() {
            config.logging.level = v;
        }
    }
}

fn default_http_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_smtp_listen_addr() -> String {
    "0.0.0.0:25".to_string()
}

fn default_storage_dir() -> PathBuf {
    PathBuf::from("./data")
}

fn default_db_pool_size() -> u32 {
    25
}

fn default_max_message_size() -> usize {
    10 * 1024 * 1024
}

fn default_webhook_timeout() -> u64 {
    10
}

fn default_pending_ttl_hours() -> u64 {
    72
}

fn default_max_attempts() -> u32 {
    3
}

fn default_initial_backoff() -> u64 {
    5
}

fn default_max_backoff() -> u64 {
    300
}

fn default_poll_interval() -> u64 {
    5
}

fn default_batch_size() -> i32 {
    50
}

fn default_auto_reply_subject_prefix() -> String {
    "[Auto-Reply] ".to_string()
}

fn default_auto_reply_body() -> Option<String> {
    Some(
        "This is an automated message from the amail system. \
         The delivery could not be completed after all retry attempts. \
         For assistance, please contact your service administrator."
            .to_string(),
    )
}

fn default_auto_reply_from() -> Option<String> {
    None
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_channel_capacity() -> usize {
    1000
}

fn default_multiplier() -> u64 {
    2
}

fn default_attachment_max_size() -> usize {
    20 * 1024 * 1024 // 20 MB
}

fn default_attachment_lifetime_hours() -> u32 {
    720
}

fn default_attachment_max_count() -> usize {
    5
}

fn default_smtp_max_connections() -> usize {
    100
}

fn default_delivery_window() -> u64 {
    7200
}

#[derive(Debug, Clone, Deserialize)]
pub struct BoardConfig {
    #[serde(default = "default_heartbeat_stale")]
    pub heartbeat_stale_seconds: u64,
    #[serde(default = "default_task_timeout")]
    pub task_timeout_seconds: u64,
    #[serde(default = "default_sweeper_interval")]
    pub sweeper_interval_seconds: u64,
    pub max_active_boards: Option<usize>,
    pub archive_retention_days: Option<u64>,
}

impl Default for BoardConfig {
    fn default() -> Self {
        Self {
            heartbeat_stale_seconds: default_heartbeat_stale(),
            task_timeout_seconds: default_task_timeout(),
            sweeper_interval_seconds: default_sweeper_interval(),
            max_active_boards: Some(5),
            archive_retention_days: None,
        }
    }
}

fn default_heartbeat_stale() -> u64 {
    14400
}
fn default_task_timeout() -> u64 {
    259200
}
fn default_sweeper_interval() -> u64 {
    900
}
