#!/usr/bin/env bash
# deploy-bin.sh — build, ship and run aimail-gateway on a remote host.
#
# Usage:
#   export AIMAIL_DEPLOY_HOST="1.2.3.4"
#   export AIMAIL_DEPLOY_PORT="22"            # optional, default 22
#   export AIMAIL_DEPLOY_USER="root"          # optional, default root
#   export AIMAIL_DEPLOY_KEY="$HOME/.ssh/id_deploy"   # optional
#
#   bash deploy-bin.sh build            # cargo build --release --locked
#   bash deploy-bin.sh preflight        # validate the remote config with -t
#   bash deploy-bin.sh upload           # upload .new, verify sha256, atomic swap, keep .prev
#   bash deploy-bin.sh start|stop|restart|status|logs|health
#   bash deploy-bin.sh setup-systemd    # install + enable the systemd unit
#
# The runtime config is NOT shipped by this script (secrets stay manual):
#   ssh … "mkdir -p /etc/aimail" && scp config.toml …:/etc/aimail/config.toml
set -euo pipefail

# ── Load .env file if present (caller environment wins) ────────────
ENV_FILE="$(cd "$(dirname "$0")" && pwd)/.env"
if [ -f "$ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        val="${val%\"}"; val="${val#\"}"
        [ -n "${!key:-}" ] && continue      # already set in the environment
        export "$key=$val"
    done < "$ENV_FILE"
fi

HOST="${AIMAIL_DEPLOY_HOST:?AIMAIL_DEPLOY_HOST not set}"
PORT="${AIMAIL_DEPLOY_PORT:-22}"
DEPLOY_USER="${AIMAIL_DEPLOY_USER:-root}"
KEY="${AIMAIL_DEPLOY_KEY:-}"
# Auto-detect the deploy key (no passphrase), otherwise fall back to ssh-agent.
if [ -z "$KEY" ] && [ -f "$HOME/.ssh/id_deploy" ]; then
    KEY="$HOME/.ssh/id_deploy"
fi

# accept-new = trust on first use, refuse a changed host key (MITM protection
# without the interactive prompt). The previous no-check + /dev/null pair made
# the whole deploy chain spoofable.
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
[ -n "$KEY" ] && SSH_OPTS+=(-i "$KEY")

SSH=(ssh -p "$PORT" "${SSH_OPTS[@]}" "${DEPLOY_USER}@${HOST}")
SCP=(scp -P "$PORT" "${SSH_OPTS[@]}")

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_BIN="${SCRIPT_DIR}/target/release/aimail-gateway"
REMOTE_BIN="/usr/local/bin/aimail-gateway"
REMOTE_DIR="/usr/local/bin"
CONFIG="/etc/aimail/config.toml"
WORKDIR="/var/aimail"
SERVICE_NAME="aimail-gateway"

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# Read the HTTP port from the remote config ([http] bind). Mirrors what the
# gateway itself would bind, so `health` does not hard-code 8080.
remote_http_port() {
    # [http] section → the bind line → strip the comment → take what follows the last
    # colon → keep digits. (`awk -F=` alone breaks on the trailing "# … 8080" comment.)
    "${SSH[@]}" "sed -n '/^\[http\]/,/^\[/p' '$CONFIG' 2>/dev/null \
        | grep -E '^[[:space:]]*bind[[:space:]]*=' | head -1 \
        | sed 's/#.*//' | sed 's/.*://' | tr -dc '0-9'" | tr -d '\r'
}

build() {
    echo "Building aimail-gateway (release, locked)..."
    cd "$SCRIPT_DIR"
    cargo build --release --locked --bins
    [ -f "$GATEWAY_BIN" ] || { echo "ERROR: build failed"; exit 1; }
    echo "OK ($(ls -lh "$GATEWAY_BIN" | awk '{print $5}'), sha256 $(sha256_of "$GATEWAY_BIN" | cut -c1-12)…)"
}

# Fail before touching a running service: the binary can validate the config.
preflight() {
    if "${SSH[@]}" "test -f '$CONFIG'"; then
        echo "Validating remote config ($CONFIG)..."
        if "${SSH[@]}" "'$REMOTE_BIN' -t -c '$CONFIG'"; then
            echo "OK: config is valid"
        else
            echo "ERROR: config validation failed — not restarting" >&2
            exit 1
        fi
    else
        echo "WARN: $CONFIG not found on the host — skipping config validation"
        echo "      upload it first: scp config.toml ${DEPLOY_USER}@${HOST}:/etc/aimail/config.toml"
    fi
}

upload() {
    echo "Uploading aimail-gateway..."
    [ -f "$GATEWAY_BIN" ] || { echo "ERROR: binary not found at $GATEWAY_BIN (run: $0 build)"; exit 1; }
    local local_sha remote_sha
    local_sha="$(sha256_of "$GATEWAY_BIN")"

    # Never scp onto the live binary: Linux returns ETXTBSY for an open executable,
    # and a partial write leaves a broken binary behind.
    "${SCP[@]}" "$GATEWAY_BIN" "${DEPLOY_USER}@${HOST}:${REMOTE_DIR}/aimail-gateway.new"
    remote_sha="$("${SSH[@]}" "sha256sum '${REMOTE_DIR}/aimail-gateway.new' | awk '{print \$1}'" | tr -d '\r')"
    if [ "$local_sha" != "$remote_sha" ]; then
        echo "ERROR: checksum mismatch (local $local_sha != remote $remote_sha) — upload aborted" >&2
        "${SSH[@]}" "rm -f '${REMOTE_DIR}/aimail-gateway.new'" || true
        exit 1
    fi

    # Atomic rename keeps the running process on the old inode; .prev is the rollback point.
    "${SSH[@]}" "if [ -f '$REMOTE_BIN' ]; then cp -a '$REMOTE_BIN' '$REMOTE_BIN.prev'; fi; \
        mv -f '${REMOTE_DIR}/aimail-gateway.new' '$REMOTE_BIN' && chmod 755 '$REMOTE_BIN'"
    echo "OK ($(ls -lh "$GATEWAY_BIN" | awk '{print $5}'), sha256 ${local_sha:0:12}…)"
    echo "     rollback: ssh … 'cp -a $REMOTE_BIN.prev $REMOTE_BIN && systemctl restart $SERVICE_NAME'"
}

has_unit() { "${SSH[@]}" "systemctl cat ${SERVICE_NAME} >/dev/null 2>&1"; }

start() {
    "${SSH[@]}" "mkdir -p '$WORKDIR'"
    if has_unit; then
        if "${SSH[@]}" "systemctl start ${SERVICE_NAME}"; then
            "${SSH[@]}" "systemctl is-active --quiet ${SERVICE_NAME}" \
                && { echo "started (systemd)"; return 0; }
        fi
        echo "ERROR: systemd start failed — recent log:" >&2
        "${SSH[@]}" "journalctl -u ${SERVICE_NAME} -n 20 --no-pager" >&2 || true
        # Deliberately NO nohup fallback here: a failed unit start (bad config, port
        # already bound) must not silently spawn a second instance fighting for :25.
        exit 1
    fi
    "${SSH[@]}" "cd '$WORKDIR' && nohup '$REMOTE_BIN' --config '$CONFIG' \
        >> /var/log/aimail-gateway.log 2>&1 & echo \$! > /var/run/aimail-gateway.pid"
    echo "started (background, pid file /var/run/aimail-gateway.pid)"
}

stop() {
    "${SSH[@]}" "systemctl stop ${SERVICE_NAME} 2>/dev/null || { \
        if [ -f /var/run/aimail-gateway.pid ]; then \
            kill \"\$(cat /var/run/aimail-gateway.pid)\" 2>/dev/null && rm -f /var/run/aimail-gateway.pid && echo 'stopped (pid file)'; \
        else echo 'not running'; fi; }"
}

restart() {
    preflight
    if has_unit; then
        "${SSH[@]}" "systemctl restart ${SERVICE_NAME}"
        "${SSH[@]}" "systemctl is-active --quiet ${SERVICE_NAME}" && echo "restarted (systemd)"
    else
        stop
        sleep 1
        start
    fi
}

status() {
    # MainPID comes from systemd; the pid-file branch is escaped so it expands on the
    # HOST — an unescaped $(cat …) runs locally and always prints an empty pid.
    "${SSH[@]}" "if systemctl is-active --quiet ${SERVICE_NAME}; then \
            echo \"running (systemd, MainPID \$(systemctl show -p MainPID --value ${SERVICE_NAME}))\"; \
        elif [ -f /var/run/aimail-gateway.pid ]; then \
            echo \"running (pid file: \$(cat /var/run/aimail-gateway.pid))\"; \
        else echo 'not running'; fi"
}

logs() {
    "${SSH[@]}" "journalctl -u ${SERVICE_NAME} --no-pager -n 50 2>/dev/null || \
        tail -50 /var/log/aimail-gateway.log 2>/dev/null || echo 'no logs'"
}

health() {
    local port
    port="$(remote_http_port)"
    # A failed lookup (missing config, no shell on the host) must not turn into a
    # garbage URL: only accept a plain number, otherwise fall back to the default.
    case "$port" in ''|*[!0-9]*) port=8080 ;; esac
    echo "Probing http://127.0.0.1:${port}/health (port from [http].bind)…"
    "${SSH[@]}" "command -v aimail-gateway-health >/dev/null 2>&1 \
        && aimail-gateway-health -c '$CONFIG' \
        || curl -sf 'http://127.0.0.1:${port}/health'" \
        && echo "OK" || { echo "FAILED"; exit 1; }
}

setup_systemd() {
    "${SSH[@]}" "cat > /etc/systemd/system/${SERVICE_NAME}.service << 'SYSTEMD'
[Unit]
Description=aimail-gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORKDIR
ExecStart=$REMOTE_BIN --config $CONFIG
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD
systemctl daemon-reload && systemctl enable ${SERVICE_NAME} >/dev/null 2>&1; echo 'systemd unit installed (enabled)'"
}

case "${1:-}" in
    build)          build ;;
    preflight)      preflight ;;
    upload)         upload ;;
    start)          start ;;
    stop)           stop ;;
    restart)        restart ;;
    status)         status ;;
    logs)           logs ;;
    health)         health ;;
    setup-systemd)  setup_systemd ;;
    *) echo "Usage: $0 {build|preflight|upload|start|stop|restart|status|logs|health|setup-systemd}" ; exit 2 ;;
esac
