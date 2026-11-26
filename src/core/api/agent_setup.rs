//! `agent-setup` — per-host install instructions, looked up by the AGENT ITSELF.
//!
//! Why this exists (owner ruling 2026-11-26): the activation prompt must stay short and must not be
//! rewritten every time a new host type is supported. The email therefore carries ONE line — "if
//! `aimail_address` is missing, ask the gateway what to run for your host" — and the agent, which
//! knows what it is, fetches the exact command from here:
//!
//! ```text
//! GET /api/v1/agent-setup/install?host=openclaw
//! → {"host":"openclaw","install":"openclaw plugins install agent-aimail …",
//!    "bootstrap":"curl -fsSL …/agent-setup/bootstrap?host=openclaw | sh", …}
//! ```
//!
//! # One URL, no OS guessing (owner ruling 2026-11-26, later refined)
//!
//! An agent should not have to work out whether it is on Windows before installing. So the field it
//! acts on is a *single* URL: `GET /api/v1/agent-setup/bootstrap?host=<host>`, which serves a script
//! that adapts itself:
//!
//! 1. **shell dialect** — if it is running under a Windows POSIX shim (`MINGW*`/`MSYS*`/`CYGWIN*`),
//!    it hands over to its PowerShell twin (`…&shell=ps1`) and exits; both twins are rendered from
//!    the same table below, so they cannot drift.
//! 2. **interpreter** — candidates are tried in order (`$AIMAIL_PYTHON`, the host's own runtime, then
//!    `python3`, then `python`); the first one that can actually `import sys` wins.
//! 3. **installer** — pip, falling back to `ensurepip`, then `uv pip`; or npm for the node hosts.
//! 4. **artifact source** — `$AIMAIL_SDK_URL` (a wheel/tarball served by the gateway) beats the
//!    index, which is what air-gapped containers without DNS need.
//!
//! Every step reports itself: the last line is either
//! `AIMAIL_BOOTSTRAP ok host=… kind=… version=… tool=…` or
//! `AIMAIL_BOOTSTRAP fail host=… code=… detail=…`, so the agent (and the L3 harness) can decide by
//! parsing rather than by guessing at exit codes alone.
//!
//! Public on purpose: this is documentation-shaped data (no secret, no tenant), and it is needed
//! BEFORE the agent owns any key — an agent that cannot install the plugin cannot activate either.

use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::core::api::types::ErrorResponse;

/// How the SDK/plugin becomes usable in this host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// Node host: SDK is an npm package; registration goes through the host CLI.
    Node,
    /// Python host: SDK is a wheel; the host picks it up through an entry point at boot.
    Python,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Python => "python",
        }
    }
}

/// One host's install recipe: what the agent runs, and what to do when the tool is still missing.
struct Recipe {
    host: &'static str,
    install: &'static str,
    restart: &'static str,
    kind: Kind,
    /// Interpreter candidates, most specific first (`$AIMAIL_PYTHON` is always prepended).
    pythons: &'static [&'static str],
    /// Command the host CLI needs for plugin registration, run only when that CLI exists.
    register: &'static str,
    /// Env vars / PATH names that identify this host when the agent did not say who it is.
    markers: &'static [&'static str],
}

/// Aliases an agent may use for itself (its product name), all folded onto one row.
const ALIASES: &[(&str, &str)] = &[
    ("dsh", "dsh"),
    ("deepseek-hub", "dsh"),
    ("deepseek-hub-agent", "dsh"),
    ("pi", "pi"),
    ("pi-coding-agent", "pi"),
    ("openclaw", "openclaw"),
    ("hermes", "hermes"),
    ("hermes-agent", "hermes"),
    ("deerflow", "deerflow"),
    ("deer-flow", "deerflow"),
];

const RECIPES: &[Recipe] = &[
    Recipe {
        host: "dsh",
        install: "dsh plugin --profile web add agent-aimail",
        restart: "restart the dsh host (the plugin loads at boot)",
        kind: Kind::Node,
        pythons: &[],
        register: "dsh plugin --profile web add agent-aimail",
        markers: &["DSH_HOME"],
    },
    Recipe {
        host: "pi",
        install: "pi install npm:agent-aimail",
        restart: "restart the pi session so the extension loads",
        kind: Kind::Node,
        pythons: &[],
        register: "pi install npm:agent-aimail",
        markers: &["PI_HOME"],
    },
    Recipe {
        host: "openclaw",
        install: "openclaw plugins install agent-aimail --force --accept-capabilities",
        restart: "restart the openclaw gateway so the plugin loads",
        kind: Kind::Node,
        pythons: &[],
        register: "openclaw plugins install agent-aimail --force --accept-capabilities",
        markers: &["OPENCLAW_HOME"],
    },
    Recipe {
        host: "hermes",
        install: "pip install agent-aimail",
        restart: "restart the hermes agent (the `hermes_agent.plugins` entry point loads at boot)",
        kind: Kind::Python,
        // Hermes runs the agent from a venv, but its tool runner uses a second interpreter; a wheel
        // installed into only one of them is invisible to half the host, so both are tried and the
        // one that ends up holding the distribution is the one reported back.
        pythons: &[
            "/opt/hermes/.venv/bin/python3",
            "/opt/hermes/tools/python/bin/python3",
        ],
        register: "",
        markers: &["HERMES_HOME"],
    },
    Recipe {
        host: "deerflow",
        install: "pip install agent-aimail",
        restart: "restart the deerflow host so the extension registry reloads",
        kind: Kind::Python,
        pythons: &["/opt/deerflow/.venv/bin/python3"],
        register: "",
        markers: &["DEERFLOW_HOME", "DEER_FLOW_HOME"],
    },
];

fn resolve(host: &str) -> Option<&'static Recipe> {
    let want = host.trim().to_lowercase();
    if want.is_empty() {
        return None;
    }
    let canonical = ALIASES
        .iter()
        .find(|(alias, _)| *alias == want)
        .map(|(_, canonical)| *canonical)?;
    RECIPES.iter().find(|r| r.host == canonical)
}

fn render(recipe: &Recipe, gateway: &str) -> Value {
    let base = gateway.trim_end_matches('/');
    let bootstrap = format!("{base}/api/v1/agent-setup/bootstrap?host={}", recipe.host);
    json!({
        "host": recipe.host,
        "kind": recipe.kind.as_str(),
        "install": recipe.install,
        "restart": recipe.restart,
        // The field to act on: ONE url, whatever the OS. The script decides shell dialect,
        // interpreter and installer at run time, so the agent never has to guess.
        "bootstrap": format!("curl -fsSL '{bootstrap}' | sh"),
        "bootstrap_url": bootstrap,
        "bootstrap_windows": format!("{bootstrap}&shell=ps1"),
        // One sentence an agent can act on without interpreting: run `install`, then re-check the
        // tool; if it is still missing, ask the user to restart the host and retry activation.
        "instruction": format!(
            "Run `curl -fsSL '{bootstrap}' | sh` now (it adapts to this OS and runtime itself; the last line says ok or fail). If `aimail_address` is still unavailable afterwards, {} and retry activation.",
            recipe.restart
        ),
    })
}

#[derive(Deserialize)]
pub struct SetupQuery {
    /// The host the agent runs in (`dsh` … `deerflow`). Aliases are folded server-side.
    #[serde(default)]
    pub host: String,
    /// Public base URL the caller reached us on, used to build absolute script URLs.
    #[serde(default)]
    pub gateway: String,
    /// `sh` (default) or `ps1`.
    #[serde(default)]
    pub shell: String,
    /// Format: `json` (default) or `script`.
    #[serde(default)]
    pub format: String,
}

/// Public base URL the caller reached us on: `$AIMAIL_GATEWAY`-free operation, and the Windows
/// hand-over inside the script needs it (`…/bootstrap?host=x&shell=ps1`).
fn request_base(headers: &HeaderMap) -> String {
    let pick = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let host = pick("x-forwarded-host").or_else(|| pick("host"));
    let scheme = pick("x-forwarded-proto").unwrap_or_else(|| "http".to_string());
    match host {
        Some(h) => format!("{}://{}", scheme.split(',').next().unwrap_or("http").trim(), h),
        None => String::new(),
    }
}

fn unknown_host<T>(host: &str) -> Result<T, (StatusCode, Json<ErrorResponse>)> {
    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "unknown_host".to_string(),
            detail: Some(format!(
                "no install recipe for host '{}'. Known hosts: {}. Re-request with ?host=<one of them>.",
                host.trim(),
                RECIPES
                    .iter()
                    .map(|r| r.host)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }),
    ))
}

/// `GET /api/v1/agent-setup/install?host=<host>` — the command for this host.
///
/// Unknown/absent host ⇒ 404 listing the known hosts, so an agent can correct itself in one turn
/// instead of guessing (this endpoint is the ONLY place that knows the commands).
pub async fn agent_setup_install(
    Query(q): Query<SetupQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let gateway = if q.gateway.trim().is_empty() {
        request_base(&headers)
    } else {
        q.gateway.clone()
    };
    match resolve(&q.host) {
        Some(recipe) => Ok(Json(render(recipe, &gateway))),
        None => unknown_host(&q.host),
    }
}

/// `GET /api/v1/agent-setup/bootstrap?host=<host>&shell=sh|ps1` — the self-adapting installer.
///
/// Served as plain text so `curl … | sh` works directly. `host` may be omitted: the script then
/// probes env markers and PATH (step 0) and only fails when it cannot tell.
pub async fn agent_setup_bootstrap(
    Query(q): Query<SetupQuery>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let gateway = if q.gateway.trim().is_empty() {
        request_base(&headers)
    } else {
        q.gateway.clone()
    };
    let recipe = if q.host.trim().is_empty() {
        None // let the script self-detect
    } else {
        match resolve(&q.host) {
            Some(r) => Some(r),
            None => return unknown_host(&q.host),
        }
    };

    let ps = matches!(q.shell.trim().to_lowercase().as_str(), "ps1" | "powershell" | "pwsh");
    let body = if ps {
        render_powershell(recipe, &gateway)
    } else {
        render_posix(recipe, &gateway)
    };
    let mime = if ps {
        "text/plain; charset=utf-8"
    } else {
        "text/x-shellscript; charset=utf-8"
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

/// `GET /api/v1/agent-setup` — index: which hosts are known and the URL shapes to call.
pub async fn agent_setup_index() -> Json<Value> {
    Json(json!({
        "install_url": "/api/v1/agent-setup/install?host=<host>",
        "bootstrap_url": "/api/v1/agent-setup/bootstrap?host=<host>",
        "hosts": RECIPES.iter().map(|r| r.host).collect::<Vec<_>>(),
        "note": "Ask this endpoint for the install recipe for YOUR host; then run its `bootstrap` command. That single command adapts to the OS, the interpreter and the installer by itself — do not pick a Windows or POSIX variant yourself.",
    }))
}

/* ------------------------------------------------------------------ script rendering */

fn per_host_cases() -> String {
    let mut out = String::new();
    for r in RECIPES {
        let kind = match r.kind {
            Kind::Node => "node",
            Kind::Python => "python",
        };
        let pys = if r.pythons.is_empty() {
            String::new()
        } else {
            r.pythons.join(" ")
        };
        out.push_str(&format!(
            "    {host})\n      HOST_MATCH=1; KIND={kind}; PYS=\"$PYS {pys}\"; REGISTER={register:?}\n      ;;\n",
            host = r.host,
            kind = kind,
            pys = pys,
            register = r.register,
        ));
    }
    out
}

/// Detection lines for the POSIX twin, generated from `markers` so the table stays the only truth.
fn per_host_detect() -> String {
    let mut out = String::new();
    for r in RECIPES {
        let cond = r
            .markers
            .iter()
            .map(|m| format!("[ -n \"${{{m}:-}}\" ]"))
            .collect::<Vec<_>>()
            .join(" || ");
        out.push_str(&format!(
            "      {host}) {cond} && HOST={host} ;;\n",
            host = r.host,
            cond = if cond.is_empty() { "false" } else { &cond },
        ));
    }
    out
}

fn host_list() -> String {
    RECIPES
        .iter()
        .map(|r| r.host)
        .collect::<Vec<_>>()
        .join(" ")
}

const POSIX_TEMPLATE: &str = r#"#!/bin/sh
# AIMail bootstrap — generated by the gateway, do not edit.
#   usage: curl -fsSL '<gateway>/api/v1/agent-setup/bootstrap?host=<host>' | sh
# Adapts by trying, not by guessing:
#   0. host      — @@HOST@@ or $AIMAIL_HOST, else env markers, else the host CLI on PATH
#   1. dialect   — Windows POSIX shim (MINGW/MSYS/CYGWIN) hands over to the .ps1 twin
#   2. runtime   — $AIMAIL_PYTHON, host runtime, python3, python (first that imports sys)
#   3. installer — pip, else ensurepip, else uv pip; npm for node hosts
#   4. source    — $AIMAIL_SDK_URL (offline artifact) beats the public index
# Last line is `AIMAIL_BOOTSTRAP ok …` or `AIMAIL_BOOTSTRAP fail …`.
set -u

GATEWAY="${AIMAIL_GATEWAY:-@@GATEWAY@@}"
PKG='@@PKG@@'
HOST="${AIMAIL_HOST:-@@HOST@@}"
SDK_URL="${AIMAIL_SDK_URL:-}"
PYS="${AIMAIL_PYTHON:-}"
KIND=''
REGISTER=''
HOST_MATCH=0

say() { printf '%s\n' "$*" >&2; }
note() { printf 'aimail-bootstrap: %s\n' "$*" >&2; }
fail() {
  printf 'AIMAIL_BOOTSTRAP fail host=%s code=%s detail=%s\n' "${HOST:-unknown}" "$1" "$2"
  exit 1
}
ok() {
  printf 'AIMAIL_BOOTSTRAP ok host=%s kind=%s version=%s tool=%s\n' \
    "$HOST" "${KIND:-unknown}" "$1" "${2:--}"
}

# ---------------------------------------------------------------- step 1: shell dialect
OS="$(uname -s 2>/dev/null || echo unknown)"
case "$OS" in
  MINGW*|MSYS*|CYGWIN*|Windows*)
    # This is a Windows POSIX shim: the native path lives in the PowerShell twin. Hand over
    # rather than half-implementing Windows — and cascade the hosts we might use to get there.
    note "windows shim ($OS): handing over to the PowerShell bootstrap"
    [ -n "$GATEWAY" ] || fail no_gateway "the Windows hand-over needs the gateway base url; re-run with AIMAIL_GATEWAY=<url>"
    Q="host=${HOST}&shell=ps1"
    URL="${GATEWAY%/}/api/v1/agent-setup/bootstrap?${Q}"
    for shell_bin in pwsh powershell; do
      command -v "$shell_bin" >/dev/null 2>&1 || continue
      exec "$shell_bin" -NoProfile -ExecutionPolicy Bypass -Command \
        "iwr -useb '${URL}' | iex"
    done
    command -v curl >/dev/null 2>&1 && command -v cmd >/dev/null 2>&1 && {
      # last resort: let cmd's powershell fetch and run it
      exec cmd /c "curl -fsSL \"${URL}\" -o \"%TEMP%\\aimail-bootstrap.ps1\" && powershell -NoProfile -ExecutionPolicy Bypass -File \"%TEMP%\\aimail-bootstrap.ps1\""
    }
    fail no_powershell "neither pwsh nor powershell is on PATH under $OS"
    ;;
esac

# ---------------------------------------------------------------- step 0: which host is this
if [ -z "$HOST" ]; then
  case "1" in
@@DETECT@@
  esac
fi
if [ -z "$HOST" ]; then
  for cand in @@HOSTLIST@@; do
    if command -v "$cand" >/dev/null 2>&1; then HOST=$cand; break; fi
  done
fi
[ -n "$HOST" ] || fail unknown_host "cannot tell which host this is; re-run with AIMAIL_HOST=<@@HOSTLIST@@>"

case "$HOST" in
@@CASES@@
  *) fail unknown_host "no recipe for '$HOST'; known: @@HOSTLIST@@" ;;
esac
note "host=$HOST kind=$KIND"

# ---------------------------------------------------------------- helpers
run() { # run <cmd...>, stream output to stderr so stdout stays machine-readable
  "$@" 1>&2 2>&2
}

# ---------------------------------------------------------------- step 4: artifact source
SPEC="$PKG"
PIPX=""
if [ -n "$SDK_URL" ]; then
  SPEC="$SDK_URL"
  # A local file is a self-contained artifact: resolving it through an index would just fail on an
  # air-gapped host for no reason.
  [ -f "$SPEC" ] && PIPX="--no-index"
  note "installing from $SPEC (offline artifact)"
fi

if [ "$KIND" = node ]; then
  # ------------------------------------------------------------ node hosts
  command -v npm >/dev/null 2>&1 || fail no_npm "npm is not on PATH; this host is a node host and has no python fallback"

  # Where the package landed, whichever prefix we had to use.
  pkg_root() {
    for r in "$(npm root -g 2>/dev/null)" "${AIMAIL_NPM_PREFIX:-$HOME/.local}/lib/node_modules"; do
      [ -n "$r" ] && [ -d "$r/$PKG" ] && { printf '%s' "$r"; return 0; }
    done
    return 1
  }
  pkg_version() { node -e "process.stdout.write(require('$1/$PKG/package.json').version)" 2>/dev/null || true; }

  ROOT="$(pkg_root || true)"
  VER=""
  [ -n "$ROOT" ] && VER="$(pkg_version "$ROOT")"

  if [ -z "$VER" ]; then
    note "npm install -g $SPEC"
    if ! run npm install -g "$SPEC"; then
      # An unprivileged account (containers typically run as uid 1000) owns no writable global
      # prefix and npm fails with EACCES. Do not give up: install into a private prefix and put it
      # on PATH -- that is what a user-level install means, and it is reversible.
      PREFIX="${AIMAIL_NPM_PREFIX:-$HOME/.local}"
      note "global prefix not writable; retrying with --prefix $PREFIX"
      mkdir -p "$PREFIX" || fail install_failed "cannot create $PREFIX"
      run npm install -g --prefix "$PREFIX" "$SPEC" \
        || fail install_failed "npm install -g $SPEC failed (global prefix and $PREFIX)"
      export PATH="$PREFIX/bin:$PATH"
    fi
    ROOT="$(pkg_root || true)"
    [ -n "$ROOT" ] && VER="$(pkg_version "$ROOT")"
  fi

  [ -n "$VER" ] || fail verify_failed "$PKG is not resolvable under any npm prefix ($(npm root -g 2>/dev/null || echo '?'))"
  if [ -n "$REGISTER" ] && [ "$HOST_MATCH" = 1 ]; then
    # Registration is host-specific; skip (do not fail) when this host's CLI is absent, which is
    # the normal case inside a plain container image.
    CLI="${REGISTER%% *}"
    if command -v "$CLI" >/dev/null 2>&1; then
      note "registering: $REGISTER"
      run sh -c "$REGISTER" || note "registration failed (the SDK itself is at $ROOT); restart the host and retry activation"
    else
      note "host CLI '$CLI' not on PATH — SDK installed at $ROOT, registration happens on host start"
    fi
  fi
  ok "$VER" "$ROOT/$PKG"
  exit 0
fi

# ---------------------------------------------------------------- python hosts
PICK=''
for cand in $PYS python3 python; do
  [ -n "$cand" ] || continue
  # `py -3` style candidates arrive as one token; eval keeps quoting sane.
  if eval "$cand -c 'import sys' >/dev/null 2>&1"; then PICK="$cand"; break; fi
done
[ -n "$PICK" ] || fail no_python "no usable interpreter among: $PYS python3 python"

PIP="$PICK -m pip"
if ! eval "$PIP --version >/dev/null 2>&1"; then
  note "$PICK has no pip; trying ensurepip"
  eval "$PICK -m ensurepip --upgrade >/dev/null 2>&1" || true
fi
if ! eval "$PIP --version >/dev/null 2>&1"; then
  if command -v uv >/dev/null 2>&1; then
    note "no pip; using uv pip --python $PICK"
    PIP="uv pip install --python $PICK"
  else
    fail no_pip "$PICK has no pip and uv is not installed"
  fi
fi

note "$PIP install $SPEC"
if ! eval "$PIP install --disable-pip-version-check --no-input --force-reinstall $PIPX '$SPEC' 1>&2 2>&2"; then
  fail install_failed "$PIP install $SPEC failed"
fi

# Verification must be a FRESH process through the same interpreter: that is the only way to see
# what the host will see at boot (a wheel installed into another interpreter stays invisible).
VER="$(eval "$PICK -c 'import importlib.metadata as m; print(m.version(\"agent-aimail\"))'" 2>/dev/null || true)"
[ -n "$VER" ] || fail verify_failed "agent-aimail is not importable from $PICK after install"

if [ -n "$REGISTER" ] && [ "$HOST_MATCH" = 1 ]; then
  note "registering: $REGISTER"
  eval "$REGISTER 1>&2 2>&2" || note "registration failed; restart the host and retry activation"
fi
ok "$VER" "$PICK"
exit 0
"#;

const POWERSHELL_TEMPLATE: &str = r#"# AIMail bootstrap (Windows) — generated by the gateway, do not edit.
# Twin of the POSIX script: same recipe table, same output contract.
#   iwr -useb '<gateway>/api/v1/agent-setup/bootstrap?host=<host>&shell=ps1' | iex
$ErrorActionPreference = 'Continue'
$Gateway = if ($env:AIMAIL_GATEWAY) { $env:AIMAIL_GATEWAY } else { '@@GATEWAY@@' }
$Pkg     = '@@PKG@@'
$Host_   = if ($env:AIMAIL_HOST) { $env:AIMAIL_HOST } else { '@@HOST@@' }
$SdkUrl  = $env:AIMAIL_SDK_URL

function Note($m) { Write-Host "aimail-bootstrap: $m" }
function Fail($code, $detail) {
  Write-Output "AIMAIL_BOOTSTRAP fail host=$($Host_) code=$code detail=$detail"
  exit 1
}

if (-not $Host_) {
  if ($env:DSH_HOME) { $Host_ = 'dsh' }
  elseif ($env:PI_HOME) { $Host_ = 'pi' }
  elseif ($env:OPENCLAW_HOME) { $Host_ = 'openclaw' }
  elseif ($env:HERMES_HOME) { $Host_ = 'hermes' }
  elseif ($env:DEERFLOW_HOME -or $env:DEER_FLOW_HOME) { $Host_ = 'deerflow' }
}
if (-not $Host_) { Fail 'unknown_host' "cannot tell which host this is; re-run with AIMAIL_HOST=<@@HOSTLIST@@>" }

$Kind = @{ @@KINDS@@ }[$Host_]
if (-not $Kind) { Fail 'unknown_host' "no recipe for '$Host_'; known: @@HOSTLIST@@" }
Note "host=$Host_ kind=$Kind"

$Spec = if ($SdkUrl) { $SdkUrl } else { $Pkg }
$PipX = @(); if ($SdkUrl -and (Test-Path $SdkUrl)) { $PipX = @('--no-index') }

if ($Kind -eq 'node') {
  if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Fail 'no_npm' 'npm is not on PATH' }
  $root = (npm root -g) 2>$null
  $pkgJson = Join-Path $root 'agent-aimail/package.json'
  if (-not (Test-Path $pkgJson)) {
    Note "npm install -g $Spec"
    npm install -g $Spec 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
      # No writable global prefix (typical for an unprivileged account): use a private one.
      $prefix = if ($env:AIMAIL_NPM_PREFIX) { $env:AIMAIL_NPM_PREFIX } else { Join-Path $HOME '.local' }
      Note "global prefix not writable; retrying with --prefix $prefix"
      New-Item -ItemType Directory -Force -Path $prefix | Out-Null
      npm install -g --prefix $prefix $Spec 2>&1 | Out-Host
      if ($LASTEXITCODE -ne 0) { Fail 'install_failed' "npm install -g $Spec failed (both prefixes)" }
      $env:PATH = "$prefix\bin;$env:PATH"
      $root = Join-Path $prefix 'lib/node_modules'
      $pkgJson = Join-Path $root 'agent-aimail/package.json'
    }
  }
  if (-not (Test-Path $pkgJson)) { Fail 'verify_failed' "package not found under $root" }
  $ver = (Get-Content $pkgJson -Raw | ConvertFrom-Json).version
  Write-Output "AIMAIL_BOOTSTRAP ok host=$Host_ kind=node version=$ver tool=$root/agent-aimail"
  exit 0
}

# python hosts: try candidates in order, first that runs wins
$py = $null
foreach ($c in @(@('py','-3'), @('python'), @('python3'))) {
  try {
    & $c[0] $c[1] -c 'import sys' 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $py = $c; break }
  } catch { }
}
if (-not $py) { Fail 'no_python' 'no usable interpreter (py -3, python, python3)' }
$pyExe = $py[0]; $pyArgs = @(); if ($py.Count -gt 1) { $pyArgs = @($py[1]) }

& $pyExe @pyArgs -m pip --version 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Note "$pyExe has no pip; trying ensurepip"; & $pyExe @pyArgs -m ensurepip --upgrade 2>&1 | Out-Null }
& $pyExe @pyArgs -m pip install --disable-pip-version-check --no-input --force-reinstall @PipX $Spec 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { Fail 'install_failed' "pip install $Spec failed" }

$ver = (& $pyExe @pyArgs -c 'import importlib.metadata as m; print(m.version("agent-aimail"))') 2>$null
if (-not $ver) { Fail 'verify_failed' "agent-aimail is not importable from $pyExe" }
Write-Output "AIMAIL_BOOTSTRAP ok host=$Host_ kind=python version=$ver tool=$pyExe"
exit 0
"#;

fn render_posix(recipe: Option<&Recipe>, gateway: &str) -> String {
    POSIX_TEMPLATE
        .replace("@@GATEWAY@@", gateway.trim_end_matches('/'))
        .replace("@@HOST@@", recipe.map(|r| r.host).unwrap_or(""))
        .replace("@@HOSTLIST@@", &host_list())
        .replace("@@CASES@@", per_host_cases().trim_end())
        .replace("@@DETECT@@", per_host_detect().trim_end())
        .replace("@@PKG@@", "agent-aimail")
}

fn render_powershell(recipe: Option<&Recipe>, gateway: &str) -> String {
    let kinds = RECIPES
        .iter()
        .map(|r| format!("'{}' = '{}'", r.host, r.kind.as_str()))
        .collect::<Vec<_>>()
        .join("; ");
    POWERSHELL_TEMPLATE
        .replace("@@GATEWAY@@", gateway.trim_end_matches('/'))
        .replace("@@HOST@@", recipe.map(|r| r.host).unwrap_or(""))
        .replace("@@HOSTLIST@@", &host_list())
        .replace("@@KINDS@@", &kinds)
        .replace("@@PKG@@", "agent-aimail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_host_has_a_runnable_command() {
        for host in ["dsh", "pi", "openclaw", "hermes", "deerflow"] {
            let r = resolve(host).unwrap_or_else(|| panic!("missing recipe for {host}"));
            assert!(
                !r.install.trim().is_empty(),
                "{host}: empty install command"
            );
            assert!(
                r.install.contains("agent-aimail"),
                "{host}: command must name the package, got {:?}",
                r.install
            );
        }
    }

    #[test]
    fn aliases_and_case_are_folded() {
        assert_eq!(resolve("DSH").map(|r| r.host), Some("dsh"));
        assert_eq!(resolve(" deer-flow ").map(|r| r.host), Some("deerflow"));
        assert_eq!(
            resolve("pi-coding-agent").map(|r| r.host),
            Some("pi"),
            "an agent may name itself by its product name"
        );
        assert!(resolve("unknown-agent").is_none());
        assert!(resolve("").is_none());
    }

    #[test]
    fn python_hosts_declare_an_interpreter_and_node_hosts_do_not() {
        for r in RECIPES {
            match r.kind {
                Kind::Python => assert!(
                    !r.pythons.is_empty(),
                    "{}: a python host must name its runtime, or the wheel lands elsewhere",
                    r.host
                ),
                Kind::Node => {
                    assert!(!r.register.is_empty(), "{}: node host needs a register", r.host)
                }
            }
        }
    }

    #[tokio::test]
    async fn unknown_host_is_a_404_that_lists_the_known_ones() {
        let err = agent_setup_install(Query(SetupQuery {
            host: "nope".to_string(),
            gateway: String::new(),
            shell: String::new(),
            format: String::new(),
        }), HeaderMap::new())
        .await
        .expect_err("unknown host must be refused");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1.error, "unknown_host");
        let detail = err.1.detail.clone().unwrap_or_default();
        for host in ["dsh", "pi", "openclaw", "hermes", "deerflow"] {
            assert!(detail.contains(host), "detail must list {host}: {detail}");
        }
    }

    #[tokio::test]
    async fn the_answer_carries_one_bootstrap_url_and_an_imperative_instruction() {
        let Json(body) = agent_setup_install(Query(SetupQuery {
            host: "hermes".to_string(),
            gateway: "http://gw.test".to_string(),
            shell: String::new(),
            format: String::new(),
        }), HeaderMap::new())
        .await
        .expect("known host");
        assert_eq!(body["host"], "hermes");
        assert_eq!(body["kind"], "python");
        assert_eq!(
            body["bootstrap_url"],
            "http://gw.test/api/v1/agent-setup/bootstrap?host=hermes"
        );
        let instruction = body["instruction"].as_str().unwrap_or_default();
        assert!(
            instruction.contains("curl -fsSL 'http://gw.test/api/v1/agent-setup/bootstrap?host=hermes' | sh"),
            "{instruction}"
        );
        assert!(instruction.contains("adapts to this OS"), "{instruction}");
        assert!(instruction.contains("retry activation"), "{instruction}");
    }

    #[test]
    fn the_script_carries_every_host_and_self_adapts() {
        let sh = render_posix(None, "http://gw.test");
        for line in [
            "hermes)", "deerflow)", "dsh)", "pi)", "openclaw)", // host table
            "MINGW*|MSYS*",      // windows hand-over
            "shell=ps1",         // twin url
            "ensurepip",         // pip fallback
            "uv pip",            // uv fallback
            "AIMAIL_SDK_URL",    // offline artifact
            "importlib.metadata", // fresh-process verification
            "AIMAIL_BOOTSTRAP ok", "AIMAIL_BOOTSTRAP fail",
        ] {
            assert!(sh.contains(line), "posix script must contain {line:?}");
        }
        assert!(!sh.contains("@@"), "unsubstituted placeholder left: {}", &sh[sh.find("@@").unwrap_or(0)..][..20.min(sh.len())]);
        let ps = render_powershell(None, "http://gw.test");
        for line in ["AIMAIL_BOOTSTRAP ok", "'hermes' = 'python'", "ensurepip"] {
            assert!(ps.contains(line), "powershell script must contain {line:?}");
        }
        assert!(!ps.contains("@@"), "unsubstituted placeholder in ps1");
    }

    #[test]
    fn a_known_host_is_baked_in_so_the_script_need_not_guess() {
        let r = resolve("openclaw").expect("recipe");
        let sh = render_posix(Some(r), "http://gw.test");
        assert!(
            sh.contains("HOST=\"${AIMAIL_HOST:-openclaw}\"") || sh.contains("HOST=${AIMAIL_HOST:-openclaw}"),
            "host must be baked in AND still overridable: {}",
            sh.lines().find(|l| l.starts_with("HOST=")).unwrap_or("<none>")
        );
    }

    #[test]
    fn the_script_is_valid_posix_sh() {
        // Catch quote/heredoc mistakes at test time: `sh -n` parses without executing.
        let script = render_posix(None, "http://gw.test");
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .expect("stdin")
                    .write_all(script.as_bytes())?;
                child.wait_with_output()
            });
        match out {
            Ok(o) => assert!(
                o.status.success(),
                "sh -n rejected the generated script: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => panic!("cannot run sh -n: {e}"),
        }
    }
}
