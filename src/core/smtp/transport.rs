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

/// Parse a (scheme-stripped) server string into (host, port).
/// The default port follows the scheme: SMTPS=465, STARTTLS=587, plain=25.
/// An explicit port always wins; an unparseable port falls back to the
/// scheme default.
fn parse_host_port<'a>(server: &'a str, scheme: &'a str) -> (&'a str, u16) {
    let default_port: u16 = match scheme {
        "smtps" => 465,
        "starttls" => 587,
        _ => 25,
    };
    match server.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(default_port)),
        None => (server, default_port),
    }
}

/// Split a supported relay URL scheme from its host:port payload.
/// `smtp://` is explicit plain SMTP; an unknown scheme is a startup
/// configuration error instead of a DNS lookup on a string containing `://`.
fn split_server(server: &str) -> AppResult<(&str, &str)> {
    if let Some(h) = server.strip_prefix("smtps://") {
        return Ok((h, "smtps"));
    }
    if let Some(h) = server.strip_prefix("smtp+starttls://") {
        return Ok((h, "starttls"));
    }
    if let Some(h) = server.strip_prefix("smtp://") {
        return Ok((h, "plain"));
    }
    if server.contains("://") {
        return Err(AppError::Config(format!(
            "unsupported relay.smtp_server scheme (expected smtp://, smtp+starttls:// or smtps://): {server}"
        )));
    }
    Ok((server, "plain"))
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

    let (scheme_stripped, has_scheme) = split_server(server)?;
    let (host, port) = parse_host_port(scheme_stripped, has_scheme);

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

#[cfg(test)]
mod tests {
    use super::*;

    // P2-3: default port must follow the scheme, explicit port always wins.
    #[test]
    fn parse_host_port_scheme_defaults() {
        assert_eq!(
            parse_host_port("mail.example.com", "smtps"),
            ("mail.example.com", 465)
        );
        assert_eq!(
            parse_host_port("mail.example.com", "starttls"),
            ("mail.example.com", 587)
        );
        assert_eq!(
            parse_host_port("mail.example.com", "plain"),
            ("mail.example.com", 25)
        );
    }

    #[test]
    fn split_server_accepts_smtp_scheme() {
        assert_eq!(
            split_server("smtp://mailpit:1025").unwrap(),
            ("mailpit:1025", "plain")
        );
        assert_eq!(
            split_server("smtp+starttls://mail:587").unwrap(),
            ("mail:587", "starttls")
        );
        assert_eq!(
            split_server("smtps://mail:465").unwrap(),
            ("mail:465", "smtps")
        );
        assert_eq!(split_server("mail:25").unwrap(), ("mail:25", "plain"));
    }

    #[test]
    fn split_server_rejects_unknown_scheme_at_startup() {
        let err = split_server("http://mail:25").unwrap_err();
        assert!(format!("{err}").contains("unsupported relay.smtp_server scheme"));
    }

    #[test]
    fn parse_host_port_explicit_port_wins() {
        assert_eq!(
            parse_host_port("mail.example.com:587", "smtps"),
            ("mail.example.com", 587)
        );
        assert_eq!(
            parse_host_port("mail.example.com:2525", "plain"),
            ("mail.example.com", 2525)
        );
    }

    #[test]
    fn parse_host_port_bad_port_falls_back_to_scheme_default() {
        assert_eq!(
            parse_host_port("mail.example.com:bad", "smtps"),
            ("mail.example.com", 465)
        );
        assert_eq!(
            parse_host_port("mail.example.com:bad", "plain"),
            ("mail.example.com", 25)
        );
    }
}
