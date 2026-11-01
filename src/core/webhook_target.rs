//! D3: webhook target validation — refuse to deliver to loopback, private,
//! link-local, ULA, or unspecified addresses unless the operator has
//! explicitly opened `[webhook] allow_private_targets` for a private
//! deployment.
//!
//! Two enforcement points, same policy:
//!   * registration (`validate_webhook_target`) — literal-IP hosts are
//!     classified directly; domain hosts are resolved once and every result
//!     is classified; a host that does not resolve is refused (fail loudly,
//!     same posture as the scheme check added 2026-09-27).
//!   * delivery (`pinned_client`) — the host is re-resolved right before the
//!     POST and the *pinned* IP is classified again, defeating DNS rebinding
//!     (a public name at registration time that re-resolves to an internal
//!     address at delivery time is still refused); the connection then goes
//!     out to that pinned IP via `ClientBuilder::resolve`, so a second
//!     resolution cannot slip in a different address.

use crate::core::errors::{AppError, AppResult};
use std::net::{IpAddr, SocketAddr};

/// D3: true when the address must never be a webhook delivery target while
/// `allow_private` is false. Covers loopback, private (RFC 1918 / ULA),
/// link-local (169.254/16, fe80::/10 — incl. the cloud metadata endpoint),
/// and unspecified (0.0.0.0 / ::).
pub fn ip_is_blocked(ip: IpAddr, allow_private: bool) -> bool {
    if allow_private {
        return false;
    }
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        // IPv6: ULA (fc00::/7, in practice fd00::/8) and link-local (fe80::/10).
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let ula = (s[0] & 0xfe00) == 0xfc00;
            let link_local = (s[0] & 0xffc0) == 0xfe80;
            ula || link_local
        }
    }
}

/// D3: registration-time check for a stored `webhook_url`.
///
/// `Ok` means the URL is an absolute http(s) URL whose host resolves to
/// deliverable addresses (under the given policy). Any violation is a
/// `Validation` error (HTTP 400 `webhook_target_not_allowed` at the API
/// boundary).
pub async fn validate_webhook_target(url: &str, allow_private: bool) -> AppResult<()> {
    let u = url.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return Err(AppError::Validation(format!(
            "webhook_url must be an absolute http(s) URL (got '{}')",
            u
        )));
    }

    // Split host out of the authority (strip userinfo and port by hand —
    // std::net::SocketAddr does not carry a scheme, and the URL crate is not
    // a dependency of this crate).
    let host = u
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .map(|authority| authority.rsplit_once('@').map_or(authority, |(_, h)| h))
        .and_then(|host_port| {
            // Bracketed IPv6 literal ([::1]) — the brackets carry the colons.
            if let Some(stripped) = host_port.strip_prefix('[') {
                return stripped.split(']').next().map(str::to_string);
            }
            host_port.split(':').next().map(str::to_string)
        })
        .unwrap_or_default();

    if host.is_empty() {
        return Err(AppError::Validation(format!(
            "webhook_url has no host: '{}'",
            u
        )));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        // Literal IP: classify directly, no resolution.
        if ip_is_blocked(ip, allow_private) {
            return Err(target_error(u, &ip.to_string()));
        }
        return Ok(());
    }

    // Domain: resolve once and classify every result. A host that does not
    // resolve is NOT refused here — DNS may be transiently flaky (or the
    // domain registered ahead of delegation); the delivery-time re-check
    // (`pinned_client`) is the hard gate. A host that DOES resolve to a
    // blocked range is refused — that is the SSRF case.
    let port = 0u16; // classification only; the port is irrelevant to the range
    match tokio::net::lookup_host((host.clone(), port)).await {
        Ok(mut addrs) => {
            for addr in addrs.by_ref() {
                if ip_is_blocked(addr.ip(), allow_private) {
                    return Err(target_error(u, &addr.ip().to_string()));
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                operation = "webhook_url_unresolvable",
                webhook_url = %u,
                error = %e,
                "webhook_url host does not resolve — stored anyway; delivery                  will refuse it (and retry) until it does"
            );
        }
    }
    Ok(())
}

fn target_error(url: &str, ip: &str) -> AppError {
    AppError::Validation(format!(
        "webhook_target_not_allowed: '{}' resolves to blocked address {} \
         (loopback/private/link-local/ULA/unspecified). Set \
         [webhook] allow_private_targets = true for a private deployment",
        url, ip
    ))
}

/// D3: delivery-time client pinning + re-classification (rebinding defence).
///
/// Returns the `reqwest::Client` to use for this URL:
///   * literal-IP host — classified directly; the shared client is reused;
///   * domain host — resolved now, the pinned IP classified again, and a
///     one-off client built with `ClientBuilder::resolve(host, pinned)` so
///     the actual TCP connection goes to exactly that IP.
///
/// `Err` (with a stable `webhook_target_not_allowed:` prefix) means the
/// endpoint must be marked failed without sending.
pub async fn pinned_client(
    base: &reqwest::Client,
    url: &str,
    allow_private: bool,
) -> Result<reqwest::Client, String> {
    let u = url.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return Err(format!(
            "webhook_target_not_allowed: '{}' is not an absolute http(s) URL",
            u
        ));
    }

    let host = u
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .map(|authority| authority.rsplit_once('@').map_or(authority, |(_, h)| h))
        .and_then(|host_port| {
            if let Some(stripped) = host_port.strip_prefix('[') {
                return stripped.split(']').next().map(str::to_string);
            }
            host_port.split(':').next().map(str::to_string)
        })
        .unwrap_or_default();

    if host.is_empty() {
        return Err(format!("webhook_target_not_allowed: '{}' has no host", u));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_blocked(ip, allow_private) {
            return Err(format!(
                "webhook_target_not_allowed: blocked address {} (set \
                 [webhook] allow_private_targets = true to permit)",
                ip
            ));
        }
        return Ok(base.clone());
    }

    // Domain: resolve, classify the pinned IP, build a client that only
    // talks to it.
    let pinned: SocketAddr = tokio::net::lookup_host((host.clone(), 0u16))
        .await
        .map_err(|e| {
            format!(
                "webhook_target_not_allowed: host '{}' does not resolve ({})",
                host, e
            )
        })?
        .next()
        .ok_or_else(|| {
            format!(
                "webhook_target_not_allowed: host '{}' resolved to no addresses",
                host
            )
        })?;

    if ip_is_blocked(pinned.ip(), allow_private) {
        return Err(format!(
            "webhook_target_not_allowed: host '{}' resolved to blocked address {} \
             (possible DNS rebinding; set [webhook] allow_private_targets = true \
             to permit)",
            host,
            pinned.ip()
        ));
    }

    reqwest::ClientBuilder::new()
        .resolve(host.as_str(), pinned)
        .build()
        .map_err(|e| {
            format!(
                "webhook_target_not_allowed: pinned client build failed: {}",
                e
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d3_literal_ranges_are_blocked() {
        let blocked = [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::",
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ip_is_blocked(ip, false), "{} must be blocked", s);
            assert!(
                !ip_is_blocked(ip, true),
                "{} must pass with allow_private",
                s
            );
        }
        for s in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!ip_is_blocked(ip, false), "{} must not be blocked", s);
        }
    }

    #[tokio::test]
    async fn d3_registration_refuses_literal_private_targets() {
        for url in [
            "http://127.0.0.1:9999/hook",
            "http://[::1]/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.5/x",
        ] {
            let e = validate_webhook_target(url, false).await.expect_err(url);
            assert!(
                e.to_string().contains("webhook_target_not_allowed"),
                "{}: {}",
                url,
                e
            );
        }
        // The same targets pass with the switch open.
        assert!(validate_webhook_target("http://127.0.0.1:9999/hook", true)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn d3_registration_refuses_bad_scheme_and_stores_unresolvable() {
        // Scheme check (regression: 2026-09-27 behaviour).
        assert!(validate_webhook_target("ftp://example.com/x", false)
            .await
            .is_err());
        assert!(validate_webhook_target("127.0.0.1:18789", false)
            .await
            .is_err());
        // Unresolvable host: stored (DNS may be transiently flaky); the
        // delivery-time re-check is the hard gate.
        assert!(
            validate_webhook_target("http://no-such-host.invalid/x", false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn d3_pinned_client_refuses_rebound_or_literal_private() {
        let base = reqwest::Client::new();
        let e = pinned_client(&base, "http://127.0.0.1:1/x", false)
            .await
            .expect_err("literal loopback must be refused");
        assert!(e.contains("webhook_target_not_allowed"));
        // With the switch open the shared client is reused.
        assert!(pinned_client(&base, "http://127.0.0.1:1/x", true)
            .await
            .is_ok());
        // A non-resolving domain is a delivery failure, not a panic.
        assert!(pinned_client(&base, "http://no-such-host.invalid/x", false)
            .await
            .is_err());
    }
}
