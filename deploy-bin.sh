#!/usr/bin/env bash
# deploy.sh — Deploy amail-gateway to remote host
#
# Usage:
#   export AMAIL_DEPLOY_HOST="1.2.3.4"
#   export AMAIL_DEPLOY_PORT="22"
#   export AMAIL_DEPLOY_USER="root"
#   # SSH key path (optional, default ~/.ssh/id_rsa)
#   export AMAIL_DEPLOY_KEY="$HOME/.ssh/id_deploy"
#
#   bash amail-deploy.sh upload      # Upload binary
#   bash amail-deploy.sh start       # Start
#   bash amail-deploy.sh stop        # Stop
#   bash amail-deploy.sh restart     # Restart
#   bash amail-deploy.sh status      # Status
#   bash amail-deploy.sh logs        # View logs
#   bash amail-deploy.sh health      # Health check

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
GATEWAY_BIN="${SCRIPT_DIR}/target/release/amail-gateway"
REMOTE_DIR="/usr/local/bin"
CONFIG="/etc/amail/config.toml"
WORKDIR="/var/amail"
SERVICE_NAME="amail-gateway"

upload() {
    echo "Uploading amail-gateway..."
    [ -f "$GATEWAY_BIN" ] || { echo "ERROR: binary not found at $GATEWAY_BIN"; exit 1; }
    $SCP "$GATEWAY_BIN" "${USER}@${HOST}:${REMOTE_DIR}/amail-gateway"
    $SSH "chmod +x ${REMOTE_DIR}/amail-gateway"
    echo "OK ($(ls -lh "$GATEWAY_BIN" | awk '{print $5}'))"
}

start() {
    $SSH "mkdir -p $WORKDIR && \
    systemctl cat ${SERVICE_NAME} >/dev/null 2>&1 && \
    systemctl start ${SERVICE_NAME} && echo 'started (systemd)' || \
    nohup ${REMOTE_DIR}/amail-gateway --config $CONFIG \
      > /var/log/amail-gateway.log 2>&1 & \
    echo \$! > /var/run/amail-gateway.pid && \
    echo 'started (background)'"
}

stop() {
    $SSH "systemctl stop ${SERVICE_NAME} 2>/dev/null || \
    { [ -f /var/run/amail-gateway.pid ] && \
      kill \$(cat /var/run/amail-gateway.pid) 2>/dev/null && \
      rm -f /var/run/amail-gateway.pid && echo 'stopped'; }"
}

restart() {
    stop
    sleep 1
    start
}

status() {
    $SSH "systemctl status ${SERVICE_NAME} 2>/dev/null || \
    { [ -f /var/run/amail-gateway.pid ] && \
      echo 'running (pid: '$(cat /var/run/amail-gateway.pid)')' || \
      echo 'not running'; }"
}

logs() {
    $SSH "journalctl -u ${SERVICE_NAME} --no-pager -n 50 2>/dev/null || \
    tail -50 /var/log/amail-gateway.log 2>/dev/null || echo 'no logs'"
}

health() {
    $SSH "curl -sf http://127.0.0.1:8080/health && echo 'OK' || echo 'FAILED'"
}

setup_systemd() {
    $SSH "cat > /etc/systemd/system/${SERVICE_NAME}.service << 'SYSTEMD'
[Unit]
Description=amail-gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORKDIR
ExecStart=${REMOTE_DIR}/amail-gateway --config $CONFIG
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMD
systemctl daemon-reload && echo 'systemd unit installed'"
}

case "$1" in
    upload)         upload ;;
    start)          start ;;
    stop)           stop ;;
    restart)        restart ;;
    status)         status ;;
    logs)           logs ;;
    health)         health ;;
    setup-systemd)  setup_systemd ;;
    *) echo "Usage: $0 {upload|start|stop|restart|status|logs|health|setup-systemd}" ;;
esac
