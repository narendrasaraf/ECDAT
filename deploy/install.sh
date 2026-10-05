#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=================================================================="
echo " ECDAT Production Linux Installation Script "
echo "=================================================================="

# 1. Verify Ubuntu / Linux OS
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: deploy/install.sh must be executed on a Linux operating system (Ubuntu recommended)." >&2
    exit 1
fi
echo "[+] Operating system: Linux ($(uname -s)) verified"

# 2. Verify Python 3.12+
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is not installed." >&2
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [[ "${PYTHON_MAJOR}" -lt 3 ]] || { [[ "${PYTHON_MAJOR}" -eq 3 ]] && [[ "${PYTHON_MINOR}" -lt 12 ]]; }; then
    echo "ERROR: Python 3.12 or newer is required. Found Python ${PYTHON_VERSION}." >&2
    exit 1
fi
echo "[+] Python version: ${PYTHON_VERSION} verified"

# 3. Verify Node.js 24+
if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: node is not installed. Node.js 24+ is required for hybrid TLS and ML-DSA support." >&2
    exit 1
fi
NODE_VERSION=$(node -p 'process.versions.node')
NODE_MAJOR=$(node -p 'parseInt(process.versions.node.split(".")[0], 10)')

if [[ "${NODE_MAJOR}" -lt 24 ]]; then
    echo "ERROR: Node.js 24 or newer is required. Found Node v${NODE_VERSION}." >&2
    exit 1
fi
echo "[+] Node.js version: v${NODE_VERSION} verified"

# 4. Verify Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker CLI is not installed or not in PATH." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not accessible by the current user. Ensure Docker service is running and user is in the 'docker' group." >&2
    exit 1
fi
echo "[+] Docker daemon access verified"

# 5. Verify Docker Compose
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    echo "ERROR: Neither 'docker compose' plugin nor 'docker-compose' binary is installed." >&2
    exit 1
fi
echo "[+] Docker Compose verified (${DOCKER_COMPOSE_CMD})"

# 6. Create Python virtual environment if missing
if [[ ! -d ".venv" ]]; then
    echo "[*] Creating Python virtual environment in .venv..."
    python3 -m venv .venv
else
    echo "[+] Virtual environment .venv already exists."
fi

echo "[*] Installing Python requirements from requirements.lock..."
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.lock

# 7. Install frontend dependencies and build React web app
echo "[*] Installing web dependencies in apps/web..."
(cd apps/web && npm ci)

echo "[*] Building React frontend application..."
(cd apps/web && npm run build)

echo "[*] Installing chain dependencies in packages/chain..."
(cd packages/chain && npm ci)

# 8. Build Dockerfile.scanner as ecdat-scanner:local
echo "[*] Building isolated scanner Docker image (ecdat-scanner:local)..."
docker build -f Dockerfile.scanner -t ecdat-scanner:local .

# 9. Create required runtime directories under .ecdat
echo "[*] Creating runtime directories under .ecdat..."
mkdir -p .ecdat/logs .ecdat/staging .ecdat/exports

# 10. Run database migrations if environment file is already present
if [[ -f "/etc/ecdat/ecdat.env" ]]; then
    echo "[*] /etc/ecdat/ecdat.env detected. Running Alembic database migrations..."
    set -a
    source /etc/ecdat/ecdat.env
    set +a
    PYTHONPATH=services/api .venv/bin/python -m alembic upgrade head
else
    echo "[!] /etc/ecdat/ecdat.env is not yet created."
    echo "    Migrations will be executed during initial deployment after creating /etc/ecdat/ecdat.env."
fi

echo ""
echo "=================================================================="
echo " ECDAT Installation Complete! "
echo "=================================================================="
echo ""
echo "Follow these remaining manual steps to complete deployment:"
echo ""
echo "1. Configure Production Environment:"
echo "   sudo mkdir -p /etc/ecdat"
echo "   sudo cp deploy/ecdat.env.example /etc/ecdat/ecdat.env"
echo "   sudo chmod 600 /etc/ecdat/ecdat.env"
echo "   sudo nano /etc/ecdat/ecdat.env"
echo ""
echo "2. Start PostgreSQL Database Container:"
echo "   sudo ${DOCKER_COMPOSE_CMD} -f deploy/docker-compose.prod.yml --env-file /etc/ecdat/ecdat.env up -d postgres"
echo ""
echo "3. Run Database Migrations:"
echo "   set -a && source /etc/ecdat/ecdat.env && set +a"
echo "   PYTHONPATH=services/api .venv/bin/python -m alembic upgrade head"
echo ""
echo "4. Setup and Verify Local Ollama AI Model:"
echo "   ./deploy/ollama-setup.sh"
echo ""
echo "5. Install and Enable systemd Services:"
echo "   sudo cp deploy/ecdat-api.service deploy/ecdat-worker.service /etc/systemd/system/"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl enable --now ecdat-api ecdat-worker"
echo ""
echo "6. Setup Nginx and Let's Encrypt HTTPS:"
echo "   sudo cp deploy/nginx/ecdat.conf /etc/nginx/sites-available/ecdat"
echo "   sudo ln -sf /etc/nginx/sites-available/ecdat /etc/nginx/sites-enabled/ecdat"
echo "   sudo nginx -t && sudo systemctl reload nginx"
echo "   sudo certbot --nginx -d ecdat.example.com"
echo ""
