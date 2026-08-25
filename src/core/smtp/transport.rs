//! SMTP transport builder.

use std::sync::Arc;

use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::extension::ClientId;
use lettre::AsyncSmtpTransport;
use lettre::Tokio1Executor;

use crate::core::config::RelayConfig;
use crate::core::errors::{AppError, AppResult};
use crate::core::smtp::mx_deliverer::MxDelivererImpl;

pub(crate) enum SmtpTransportMode {
    /// Upstream SMTP relay.
    Relay(AsyncSmtpTransport<Tokio1Executor>),
    /// Direct MX delivery (default mode when no upstream relay is configured).
    DirectMx(Arc<MxDelivererImpl>),
}

/// Apply an optional EHLO hostname to a transport builder.
fn with_hostname(
    builder: lettre::transport::smtp::AsyncSmtpTransportBuilder,
    hostname: Option<&str>,
) -> lettre::transport::smtp::AsyncSmtpTransportBuilder {
    if let Some(name) = hostname {
        if !name.is_empty() {
            return builder.hello_name(ClientId::Domain(name.to_string()));
        }
    }
    builder
}

/// Build a lettre SMTP transport from `RelayConfig` (upstream relay mode).
///
/// Supports:
/// - Plain SMTP (no auth, no TLS) — `builder_dangerous`
/// - SMTP with STARTTLS — `starttls_relay()`
/// - SMTP over TLS (smtps://) — `relay()`
/// - SMTP with username/password credentials
pub(crate) fn build_transport(
    config: &RelayConfig,
    hostname: Option<&str>,
) -> AppResult<AsyncSmtpTransport<Tokio1Executor>> {
    let server = config.smtp_server.as_deref().unwrap_or("127.0.0.1:25");

    let (scheme_stripped, has_scheme) = if let Some(h) = server.strip_prefix("smtps://") {
        (h, "smtps")
    } else if let Some(h) = server.strip_prefix("smtp+starttls://") {
        (h, "starttls")
    } else {
        (server, "plain")
    };

    let (host, port) = match scheme_stripped.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(25)),
        None => (scheme_stripped, 25),
    };

    let builder: lettre::transport::smtp::AsyncSmtpTransportBuilder = match has_scheme {
        "smtps" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| AppError::Config(format!("failed to build SMTPS transport: {e}")))?,
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| AppError::Config(format!("failed to build STARTTLS transport: {e}")))?,
        _ => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
    };

    let builder = builder.port(port);
    let builder = with_hostname(builder, hostname);

    let builder = if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        if !user.is_empty() && !pass.is_empty() {
            let creds = Credentials::new(user.clone(), pass.clone());
            builder.credentials(creds)
        } else {
            builder
        }
    } else {
        builder
    };

    let transport = builder.build::<Tokio1Executor>();

    Ok(transport)
}
