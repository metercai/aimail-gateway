//! MX resolution — DNS lookup and transport construction for direct delivery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioAsyncResolver;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::AsyncSmtpTransport;
use lettre::Tokio1Executor;
use tracing::info;

use crate::core::errors::{AppError, AppResult};

/// An MX record for a recipient domain.
#[derive(Debug, Clone)]
pub struct MxRecord {
    /// Hostname or IP:port of the mail exchanger.
    pub exchange: String,
    /// Lower preference = higher priority.
    pub preference: u16,
}

/// Pool of cached SMTP transports keyed by MX hostname.
#[derive(Clone)]
pub struct MxTransportPool {
    inner: Arc<tokio::sync::Mutex<HashMap<String, (AsyncSmtpTransport<Tokio1Executor>, Instant)>>>,
    ttl: Duration,
}

impl MxTransportPool {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Get or create a transport for the given MX host.
    pub async fn get_or_create(
        &self,
        mx_host: &str,
        hostname: Option<&str>,
    ) -> AppResult<AsyncSmtpTransport<Tokio1Executor>> {
        let mut map = self.inner.lock().await;
        if let Some((transport, created_at)) = map.get(mx_host) {
            if created_at.elapsed() < self.ttl {
                return Ok(transport.clone());
            }
            map.remove(mx_host);
        }
        let transport = build_mx_transport(mx_host, hostname)?;
        map.insert(mx_host.to_string(), (transport.clone(), Instant::now()));
        Ok(transport)
    }
}

/// Resolve MX records for a domain.
pub async fn resolve_mx(
    domain: &str,
    mx_overrides: &HashMap<String, String>,
    resolver: &TokioAsyncResolver,
) -> AppResult<Vec<MxRecord>> {
    if let Some(override_addr) = mx_overrides.get(domain) {
        return Ok(vec![MxRecord {
            exchange: override_addr.clone(),
            preference: 10,
        }]);
    }

    let response = resolver
        .mx_lookup(domain)
        .await
        .map_err(|e| AppError::Smtp(format!("MX lookup failed for '{}': {}", domain, e)))?;

    let mut records: Vec<MxRecord> = response
        .iter()
        .map(|mx| MxRecord {
            exchange: mx.exchange().to_string(),
            preference: mx.preference(),
        })
        .collect();

    if records.is_empty() {
        return Err(AppError::Smtp(format!(
            "no MX records found for '{}'",
            domain
        )));
    }

    records.sort_by_key(|r| r.preference);
    let primary_mx = records.first().map(|r| r.exchange.as_str()).unwrap_or("?");
    info!(operation = "mx_resolved", domain = %domain, mx_count = records.len(), primary_mx = %primary_mx, "MX resolution");
    Ok(records)
}

/// Build a lettre transport to a raw MX host (port 25, opportunistic STARTTLS).
fn build_mx_transport(
    mx_host: &str,
    hostname: Option<&str>,
) -> AppResult<AsyncSmtpTransport<Tokio1Executor>> {
    let (host, port) = match mx_host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse::<u16>().unwrap()),
        _ => (mx_host, 25u16),
    };

    let tls_params = TlsParameters::new(host.to_string())
        .map_err(|e| AppError::Config(format!("TLS config: {e}")))?;
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .port(port)
        .tls(Tls::Opportunistic(tls_params));

    if let Some(name) = hostname {
        if !name.is_empty() {
            builder = builder.hello_name(lettre::transport::smtp::extension::ClientId::Domain(
                name.to_string(),
            ));
        }
    }

    let transport = builder.build();
    info!(operation = "mx_transport_built", mx = %mx_host);
    Ok(transport)
}
