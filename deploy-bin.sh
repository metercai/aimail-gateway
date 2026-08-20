#!/usr/bin/env bash
# deploy.sh — Deploy aimail-gateway to remote host
#
# Usage:
#   export AMAIL_DEPLOY_HOST="1.2.3.4"
#   export AMAIL_DEPLOY_PORT="22"
#   export AMAIL_DEPLOY_USER="root"
#   # SSH key path (optional, default ~/.ssh/id_rsa)
#   export AMAIL_DEPLOY_KEY="$HOME/.ssh/id_deploy"
#
#   bash amail-bin.sh build        # Build binary
#   bash amail-bin.sh upload       # Upload binary
#   bash amail-bin.sh start        # Start
#   bash amail-bin.sh stop         # Stop
#   bash amail-bin.sh restart      # Restart
#   bash amail-bin.sh status       # Status
#   bash amail-bin.sh logs         # View logs
#   bash amail-bin.sh health       # Health check

set -eo pipefail

# ── Load .env file if present ──────────────────────────────────────
ENV_FILE="$(cd "$(dirname "$0")" && pwd)/.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    . "$ENV_FILE"
    set +a
fi

HOST="${AMAIL_DEPLOY_HOST:?AMAIL_DEPLOY_HOST not set}"
PORT="${AMAIL_DEPLOY_PORT:-22}"
USER="${AMAIL_DEPLOY_USER:-root}"
KEY="${AMAIL_DEPLOY_KEY:-}"
# Auto-detect deploy SSH key (no passphrase)
if [ -z "$KEY" ] && [ -f "$HOME/.ssh/id_deploy" ]; then
    KEY="$HOME/.ssh/id_deploy"
fi
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
[ -n "$KEY" ] && SSH_OPTS="$SSH_OPTS -i $KEY"

SSH="ssh -p $PORT $SSH_OPTS ${USER}@${HOST}"
SCP="scp -P $PORT $SSH_OPTS"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_BIN="${SCRIPT_DIR}/target/release/aimail-gateway"
REMOTE_DIR="/usr/local/bin"
CONFIG="/etc/aimail/config.toml"
WORKDIR="/var/aimail"
SERVICE_NAME="aimail-gateway"

build() {
    echo "Building aimail-gateway (release)..."
    cd "$SCRIPT_DIR"
    cargo build --release
    [ -f "$GATEWAY_BIN" ] || { echo "ERROR: build failed"; exit 1; }
    echo "OK ($(ls -lh "$GATEWAY_BIN" | awk '{print $5}'))"
}

upload() {
    echo "Uploading aimail-gateway..."
    [ -f "$GATEWAY_BIN" ] || { echo "ERROR: binary not found at $GATEWAY_BIN"; exit 1; }
    $SCP "$GATEWAY_BIN" "${USER}@${HOST}:${REMOTE_DIR}/aimail-gateway"
    $SSH "chmod +x ${REMOTE_DIR}/aimail-gateway"
    echo "OK ($(ls -lh "$GATEWAY_BIN" | awk '{print $5}'))"
}

start() {
    $SSH "mkdir -p $WORKDIR && \
    systemctl cat ${SERVICE_NAME} >/dev/null 2>&1 && \
    systemctl start ${SERVICE_NAME} && echo 'started (systemd)' || \
    nohup ${REMOTE_DIR}/aimail-gateway --config $CONFIG \
      > /var/log/aimail-gateway.log 2>&1 & \
    echo \$! > /var/run/aimail-gateway.pid && \
    echo 'started (background)'"
}

stop() {
    $SSH "systemctl stop ${SERVICE_NAME} 2>/dev/null || \
    { [ -f /var/run/aimail-gateway.pid ] && \
      kill \$(cat /var/run/aimail-gateway.pid) 2>/dev/null && \
      rm -f /var/run/aimail-gateway.pid && echo 'stopped'; }"
}

restart() {
    stop
    sleep 1
    start
}

status() {
    $SSH "systemctl status ${SERVICE_NAME} 2>/dev/null || \
    { [ -f /var/run/aimail-gateway.pid ] && \
      echo 'running (pid: '$(cat /var/run/aimail-gateway.pid)')' || \
      echo 'not running'; }"
}

logs() {
    $SSH "journalctl -u ${SERVICE_NAME} --no-pager -n 50 2>/dev/null || \
    tail -50 /var/log/aimail-gateway.log 2>/dev/null || echo 'no logs'"
}

health() {
    $SSH "curl -sf http://127.0.0.1:8080/health && echo 'OK' || echo 'FAILED'"
}

setup_systemd() {
    $SSH "cat > /etc/systemd/system/${SERVICE_NAME}.service << 'SYSTEMD'
[Unit]
Description=aimail-gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORKDIR
ExecStart=${REMOTE_DIR}/aimail-gateway --config $CONFIG
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD
systemctl daemon-reload && echo 'systemd unit installed'"
}

case "$1" in
    build)          build ;;
    upload)         upload ;;
    start)          start ;;
    stop)           stop ;;
    restart)        restart ;;
    status)         status ;;
    logs)           logs ;;
    health)         health ;;
    setup-systemd)  setup_systemd ;;
    *) echo "Usage: $0 {build|upload|start|stop|restart|status|logs|health|setup-systemd}" ;;
esac
