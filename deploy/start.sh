#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

ENV_FILE="/etc/ecdat/ecdat.env"

echo "=== Starting ECDAT Production Services ==="

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: Environment file ${ENV_FILE} not found." >&2
    echo "Copy deploy/ecdat.env.example to /etc/ecdat/ecdat.env and configure secrets first." >&2
    exit 1
fi

# Determine docker compose command
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    DOCKER_COMPOSE_CMD="docker-compose"
fi

# 1. Start PostgreSQL container
echo "[*] Starting PostgreSQL database container..."
${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml --env-file "${ENV_FILE}" up -d postgres

# 2. Start Ollama service if present
if systemctl is-active --quiet ollama 2>/dev/null || systemctl is-enabled --quiet ollama 2>/dev/null; then
    echo "[*] Starting Ollama AI daemon..."
    sudo systemctl start ollama || true
fi

# 3. Start systemd services
echo "[*] Starting ecdat-api.service..."
sudo systemctl start ecdat-api.service

echo "[*] Starting ecdat-worker.service..."
sudo systemctl start ecdat-worker.service

echo "[+] All ECDAT production services initiated."
