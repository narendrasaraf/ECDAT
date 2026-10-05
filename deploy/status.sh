#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

ENV_FILE="/etc/ecdat/ecdat.env"

echo "=================================================================="
echo " ECDAT Production Status Check "
echo "=================================================================="

# Determine docker compose command
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    DOCKER_COMPOSE_CMD="docker-compose"
fi

echo ""
echo "--- 1. API Health Endpoint (127.0.0.1:8000/api/health) ---"
if curl -s -f http://127.0.0.1:8000/api/health >/tmp/ecdat_health.json 2>/dev/null; then
    echo "[+] API is HEALTHY:"
    cat /tmp/ecdat_health.json
    echo ""
else
    echo "[-] API is UNHEALTHY or NOT RESPONSIVE on 127.0.0.1:8000"
fi

echo ""
echo "--- 2. Ubuntu Systemd Services Status ---"
for svc in ecdat-api ecdat-worker; do
    if systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
        echo "[+] ${svc}.service is ACTIVE (running)"
    else
        echo "[-] ${svc}.service is INACTIVE or FAILED"
    fi
done

echo ""
echo "--- 3. PostgreSQL Docker Container Status ---"
if [[ -f "${ENV_FILE}" ]]; then
    ${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml --env-file "${ENV_FILE}" ps
else
    ${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml ps
fi

echo ""
echo "--- 4. Local Ollama AI Status (127.0.0.1:11434) ---"
if curl -s -f http://127.0.0.1:11434/api/tags >/tmp/ollama_tags.json 2>/dev/null; then
    echo "[+] Ollama AI server is RESPONSIVE on 127.0.0.1:11434"
    cat /tmp/ollama_tags.json
    echo ""
else
    echo "[-] Ollama AI server is NOT RESPONSIVE on 127.0.0.1:11434"
fi

echo ""
echo "--- 5. Isolated Scanner Image (ecdat-scanner:local) ---"
if docker image inspect ecdat-scanner:local >/dev/null 2>&1; then
    echo "[+] Image 'ecdat-scanner:local' exists"
else
    echo "[-] Image 'ecdat-scanner:local' MISSING! Build it with: docker build -f Dockerfile.scanner -t ecdat-scanner:local ."
fi

echo ""
echo "=================================================================="
