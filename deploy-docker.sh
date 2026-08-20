#!/usr/bin/env bash
# deploy-docker.sh — Build & deploy aimail-gateway Docker image to remote host
#
# Usage:
#   export AMAIL_DEPLOY_HOST="1.2.3.4"
#   export AMAIL_DEPLOY_PORT="22"
#   export AMAIL_DEPLOY_USER="root"
#   export AMAIL_IMAGE_TAG="latest"    # optional, default: git hash
#
#   bash deploy-docker.sh              # build + push + run
#   bash deploy-docker.sh build        # build only
#   bash deploy-docker.sh push         # push only
#   bash deploy-docker.sh run          # run on remote (assumes image already pushed)
#   bash deploy-docker.sh stop         # stop remote container

set -eo pipefail

# ── Config ──────────────────────────────────────────────────────────────
ENV_FILE="$(cd "$(dirname "$0")" && pwd)/.env"
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

HOST="${AMAIL_DEPLOY_HOST:?AMAIL_DEPLOY_HOST not set}"
PORT="${AMAIL_DEPLOY_PORT:-22}"
USER="${AMAIL_DEPLOY_USER:-root}"
KEY="${AMAIL_DEPLOY_KEY:-}"
[ -z "$KEY" ] && [ -f "$HOME/.ssh/id_deploy" ] && KEY="$HOME/.ssh/id_deploy"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
[ -n "$KEY" ] && SSH_OPTS="$SSH_OPTS -i $KEY"

GIT_HASH=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
IMAGE_TAG="${AMAIL_IMAGE_TAG:-$GIT_HASH}"
IMAGE_NAME="aimail-gateway:${IMAGE_TAG}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_PATH="${AMAIL_CONFIG_PATH:-/etc/amail/config.toml}"
DATA_VOLUME="${AMAIL_DATA_VOLUME:-amail-data}"
HTTP_PORT="${AMAIL_HTTP_PORT:-8080}"
SMTP_PORT="${AMAIL_SMTP_PORT:-25}"

# ── Functions ───────────────────────────────────────────────────────────

build() {
    echo "Building ${IMAGE_NAME}..."
    cd "$SCRIPT_DIR"
    docker build \
        --build-arg GIT_COMMIT="$GIT_HASH" \
        -t "$IMAGE_NAME" .
    echo "OK ($(docker images --format '{{.Size}}' "$IMAGE_NAME"))"
}

push() {
    echo "Pushing ${IMAGE_NAME} to ${HOST}..."
    docker save "$IMAGE_NAME" | gzip | \
        ssh -p "$PORT" $SSH_OPTS "${USER}@${HOST}" "
            gunzip | docker load
        "
    echo "OK"
}

run() {
    echo "Starting container on ${HOST}..."
    ssh -p "$PORT" $SSH_OPTS "${USER}@${HOST}" "
        docker rm -f aimail-gateway 2>/dev/null || true
        docker run -d --restart=always \
            --name aimail-gateway \
            -p ${HTTP_PORT}:8080 \
            -p ${SMTP_PORT}:25 \
            -v ${CONFIG_PATH}:/config.toml:ro \
            -v ${DATA_VOLUME}:/data \
            ${IMAGE_NAME} \
            --config /config.toml
    "
    echo "OK"
    health
}

stop() {
    echo "Stopping container on ${HOST}..."
    ssh -p "$PORT" $SSH_OPTS "${USER}@${HOST}" "
        docker rm -f aimail-gateway 2>/dev/null && echo 'stopped' || echo 'not running'
    "
}

health() {
    ssh -p "$PORT" $SSH_OPTS "${USER}@${HOST}" "
        curl -sf http://127.0.0.1:${HTTP_PORT}/health && echo 'HEALTHY' || echo 'UNHEALTHY'
    "
}

logs() {
    ssh -p "$PORT" $SSH_OPTS "${USER}@${HOST}" "
        docker logs --tail 50 aimail-gateway 2>/dev/null || echo 'no logs'
    "
}

# ── Dispatch ────────────────────────────────────────────────────────────
case "${1:-all}" in
    build)  build ;;
    push)   push ;;
    run)    run ;;
    stop)   stop ;;
    logs)   logs ;;
    health) health ;;
    all)
        build
        push
        run
        ;;
    *)
        echo "Usage: $0 {build|push|run|stop|logs|health|all}"
        echo ""
        echo "  all     = build + push + run (default)"
        echo "  build   = build Docker image locally"
        echo "  push    = save+compress image, ssh pipe to remote docker load"
        echo "  run     = stop old container, start new one on remote"
        echo "  stop    = stop and remove container on remote"
        echo "  logs    = tail remote container logs"
        echo "  health  = check remote health endpoint"
        exit 1
        ;;
esac
