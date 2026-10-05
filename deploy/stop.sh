#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

ENV_FILE="/etc/ecdat/ecdat.env"

echo "=== Stopping ECDAT Production Services ==="

# Determine docker compose command
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    DOCKER_COMPOSE_CMD="docker-compose"
fi

# 1. Stop systemd services
echo "[*] Stopping ecdat-worker.service..."
sudo systemctl stop ecdat-worker.service || true

echo "[*] Stopping ecdat-api.service..."
sudo systemctl stop ecdat-api.service || true

# 2. Stop PostgreSQL container without deleting volume
if [[ -f "${ENV_FILE}" ]]; then
    echo "[*] Stopping PostgreSQL database container..."
    ${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml --env-file "${ENV_FILE}" stop postgres || true
else
    echo "[*] Stopping PostgreSQL database container..."
    ${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml stop postgres || true
fi

echo "[+] ECDAT production services stopped safely. Database volume 'ecdat-db' and .ecdat state are preserved."
