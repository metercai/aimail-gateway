//! `aimail-gateway-health` — standalone health probe for container HEALTHCHECK.
//!
//! Why a separate binary: the runtime image (Chainguard glibc-dynamic) ships no
//! shell and no curl, so `HEALTHCHECK CMD curl …` is impossible. This probe links
//! the same config layer as the server, derives the HTTP port from `[http].bind`
//! (or `AIMAILGW_HTTP_ADDR`), performs one `GET /health` and maps the result to an
//! exit code: 0 healthy · 1 unhealthy · 2 configuration/parse error.

use std::process::ExitCode;

/// Port from `host:port`; returns None when the bind string has no parseable port.
fn port_of(bind: &str) -> Option<u16> {
    bind.rsplit(':').next()?.trim().parse::<u16>().ok()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut cfg_path = "config.toml".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next() {
                Some(v) => cfg_path = v,
                None => {
                    eprintln!("aimail-gateway-health: --config needs a path");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("usage: aimail-gateway-health [-c <config.toml>]");
                println!("exit: 0 healthy · 1 unhealthy · 2 configuration error");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("aimail-gateway-health: unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    // Env override takes precedence over the file, mirroring the server.
    let bind = match std::env::var("AIMAILGW_HTTP_ADDR") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => match aimail_base::core::config::load(&cfg_path) {
            Ok(cfg) => cfg.http.bind,
            Err(e) => {
                eprintln!("aimail-gateway-health: cannot load {cfg_path}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    let Some(port) = port_of(&bind) else {
        eprintln!("aimail-gateway-health: cannot parse a port out of http.bind={bind}");
        return ExitCode::from(2);
    };

    // Probe loopback regardless of the wildcard bind address.
    let url = format!("http://127.0.0.1:{port}/health");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aimail-gateway-health: client build failed: {e}");
            return ExitCode::from(2);
        }
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => ExitCode::SUCCESS,
        Ok(resp) => {
            eprintln!("aimail-gateway-health: {url} -> HTTP {}", resp.status());
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("aimail-gateway-health: {url} unreachable: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::port_of;

    #[test]
    fn port_parsing() {
        assert_eq!(port_of("0.0.0.0:8080"), Some(8080));
        assert_eq!(port_of("127.0.0.1:18080"), Some(18080));
        assert_eq!(port_of("[::]:8080"), Some(8080));
        assert_eq!(port_of("no-port"), None);
    }
}
