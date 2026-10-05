# ECDAT Production Deployment on Ubuntu / AWS EC2

This directory contains the production deployment scripts and configurations for hosting **ECDAT (Evidence Workbench)** on an AWS EC2 instance (or any standard Ubuntu Linux server) with public HTTPS access.

---

## 1. Production Architecture Overview

```
Internet (Public Client)
   │
   ▼ HTTPS (Port 443)
┌────────────────────────────────────────────────────────┐
│ Nginx Reverse Proxy & Web Server                      │
│ - Serves built React SPA (apps/web/dist)              │
│ - Proxies /api requests to 127.0.0.1:8000             │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP Loopback
                            ▼
┌────────────────────────────────────────────────────────┐
│ FastAPI Application (127.0.0.1:8000)                   │
│ - Systemd service: ecdat-api.service                   │
│ - Bound strictly to 127.0.0.1                         │
└───────────────┬──────────────────────────┬─────────────┘
                │                          │
                ▼                          ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│ PostgreSQL 17 (Docker)       │ │ Ollama Local AI       │
│ - 127.0.0.1:5432 (Loopback)  │ │ - 127.0.0.1:11434     │
│ - Named volume: ecdat-db     │ │ - Model: qwen3:1.7b   │
└──────────────────────────────┘ └───────────────────────┘
                ▲
                │ Database Session
┌───────────────┴────────────────────────────────────────┐
│ Trusted Host Worker                                    │
│ - Systemd service: ecdat-worker.service                │
│ - Launches isolated container scanners on host Docker  │
└───────────────────────────┬────────────────────────────┘
                            │ Host Docker Engine CLI
                            ▼
┌────────────────────────────────────────────────────────┐
│ Isolated Scanner Container (ecdat-scanner:local)       │
│ - Network: none                                        │
│ - User: 65532:65532 (non-root)                         │
│ - Read-Only Root Filesystem (--read-only)              │
│ - Dropped Capabilities (--cap-drop ALL)                │
│ - Security Options (--security-opt no-new-privileges)  │
│ - Bounded RAM / CPU / PIDs (512MB / 1 vCPU / 96 PIDs)  │
└────────────────────────────────────────────────────────┘
```

---

## 2. Security Guarantees & Constraints

1. **Docker Socket Isolation**: The Docker socket (`/var/run/docker.sock`) is **never** mounted into the FastAPI backend container or exposed to HTTP endpoints. The trusted worker runs as a separate host process to launch non-networked scanner containers.
2. **Loopback Bindings**: FastAPI (`127.0.0.1:8000`), PostgreSQL (`127.0.0.1:5432`), and Ollama (`127.0.0.1:11434`) bind **only** to local loopback.
3. **No Public AI Exposure**: Port 11434 is never forwarded by Nginx or open in AWS Security Groups.
4. **Scanner Isolation Boundary**: External uploaded archives are scanned inside containers configured with:
   - `--network none`
   - `--read-only`
   - `--cap-drop ALL`
   - `--security-opt no-new-privileges`
   - `--memory 512m --cpus 1 --pids-limit 96`
   - `--tmpfs /tmp:rw,noexec,nosuid,size=128m`
   - `--user 65532:65532`

---

## 3. EC2 Instance & Security Group Prerequisites

### Hardware Requirements
- **OS**: Ubuntu 24.04 LTS or Ubuntu 22.04 LTS
- **Instance Type**: `t3.medium` or `t3.large` (minimum 4 GB RAM, 2 vCPUs, 20 GB SSD storage)

### AWS Security Group Inbound Rules
Configure your EC2 Security Group with **only** these open inbound ports:

| Type | Port | Source | Purpose |
| --- | --- | --- | --- |
| SSH | 22 | Your IP | Secure Shell access |
| HTTP | 80 | 0.0.0.0/0 | Initial HTTP access & Certbot verification |
| HTTPS | 443 | 0.0.0.0/0 | Public secure HTTPS traffic |

> **IMPORTANT**: Ports `8000` (FastAPI), `5432` (PostgreSQL), and `11434` (Ollama) **MUST NOT** be opened in AWS Security Groups.

---

## 4. Software Dependencies Installation

On a fresh Ubuntu EC2 instance, install system dependencies:

```bash
# Update Ubuntu packages
sudo apt update && sudo apt upgrade -y

# Install Python 3.12+ and build tools
sudo apt install -y python3 python3-venv python3-pip git curl nginx certbot python3-certbot-nginx

# Install Node.js 24 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs

# Install Docker Engine and Docker Compose plugin
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

*Note: Log out and log back in after adding your user to the `docker` group.*

---

## 5. Deployment Step-by-Step

### Step 1: Clone Repository & Run Automated Build Script

```bash
cd /opt
sudo git clone https://github.com/pranavattarde/ecdat.git
sudo chown -R $USER:$USER /opt/ecdat
cd /opt/ecdat

# Execute automated install script
./deploy/install.sh
```

### Step 2: Environment Configuration

Copy the production environment template and set secure values:

```bash
sudo mkdir -p /etc/ecdat
sudo cp deploy/ecdat.env.example /etc/ecdat/ecdat.env
sudo chmod 600 /etc/ecdat/ecdat.env
sudo nano /etc/ecdat/ecdat.env
```

Ensure the following variables are configured in `/etc/ecdat/ecdat.env`:
- `ECDAT_PROFILE=isolated`
- `ECDAT_DEMO=0`
- `ECDAT_WORKER=0`
- `ECDAT_COOKIE_SECURE=1`
- `ECDAT_POSTGRES_PASSWORD=<GENERATED_RANDOM_PASSWORD>`
- `ECDAT_DATABASE_URL=postgresql+psycopg://ecdat:<GENERATED_RANDOM_PASSWORD>@127.0.0.1:5432/ecdat`
- `ECDAT_AI_PROVIDER=ollama`
- `ECDAT_AI_MODEL=qwen3:1.7b`
- `OLLAMA_HOST=http://127.0.0.1:11434`
- `ECDAT_ORIGIN=https://ecdat.example.com`

### Step 3: Start PostgreSQL Container

```bash
sudo docker compose -f deploy/docker-compose.prod.yml --env-file /etc/ecdat/ecdat.env up -d postgres
```

### Step 4: Run Database Migrations

```bash
set -a && source /etc/ecdat/ecdat.env && set +a
PYTHONPATH=services/api .venv/bin/python -m alembic upgrade head
```

### Step 5: Install & Configure Local Ollama AI

Install Ollama binary (if not already installed):

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Run the ECDAT Ollama setup script to lock binding to `127.0.0.1:11434` and pull `qwen3:1.7b`:

```bash
./deploy/ollama-setup.sh
```

### Step 6: Install & Enable Systemd Services

Create a dedicated system user `ecdat`:

```bash
sudo useradd -r -s /usr/sbin/nologin ecdat || true
sudo usermod -aG docker ecdat
sudo chown -R ecdat:ecdat /opt/ecdat/.ecdat
```

Install systemd unit files:

```bash
sudo cp deploy/ecdat-api.service deploy/ecdat-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ecdat-api.service ecdat-worker.service
```

### Step 7: Configure Nginx & Let's Encrypt HTTPS

Copy Nginx configuration and replace `ecdat.example.com` with your actual domain:

```bash
sudo cp deploy/nginx/ecdat.conf /etc/nginx/sites-available/ecdat
sudo sed -i 's/ecdat.example.com/your-domain.com/g' /etc/nginx/sites-available/ecdat
sudo ln -sf /etc/nginx/sites-available/ecdat /etc/nginx/sites-enabled/ecdat
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Obtain Let's Encrypt SSL Certificate:

```bash
sudo certbot --nginx -d your-domain.com
```

---

## 6. Managing & Monitoring Production

### Quick Control Scripts

```bash
# Start all production services
./deploy/start.sh

# Stop production services safely (preserves database data)
./deploy/stop.sh

# View system status & health
./deploy/status.sh
```

### Viewing Logs

```bash
# API logs
sudo journalctl -u ecdat-api.service -f

# Worker logs
sudo journalctl -u ecdat-worker.service -f

# PostgreSQL container logs
sudo docker compose -f deploy/docker-compose.prod.yml --env-file /etc/ecdat/ecdat.env logs -f postgres

# Nginx access & error logs
sudo tail -f /var/log/nginx/access.log /var/log/nginx/error.log
```

---

## 7. Rollback & Stop Procedures

To stop the system while leaving database volumes intact:

```bash
./deploy/stop.sh
```

To purge temporary staging data while preserving database records:

```bash
sudo rm -rf /opt/ecdat/.ecdat/staging/*
```

---

## 8. Local Ollama AI Deployment & Data Privacy

ECDAT is designed to prioritize data privacy and evidence integrity by running AI assistance locally on the host EC2 instance via **Ollama**.

### Key AI Architecture Guarantees
- **Local Host Execution**: When `ECDAT_AI_PROVIDER=ollama` (the default), inference is performed entirely on loopback (`http://127.0.0.1:11434`) using the local model (default `qwen3:1.7b`).
- **Zero Remote Cloud Data Leakage**: No evidence, project context, or queries are sent to external cloud APIs or remote servers. Restricted project data remains 100% local.
- **Opt-In Remote AI**: External cloud providers (such as Groq or Gemini) are disabled by default and require explicit environment configuration (`GROQ_API_KEY` / `GEMINI_API_KEY`) plus `public-demo` project disclosure settings.
- **Port Isolation**: Ollama's port (`11434`) is bound strictly to loopback (`127.0.0.1`) and is never proxied through Nginx or open in AWS Security Groups.
- **Evidence Schema & Policy Validation**: All AI outputs are validated against deterministic schemas and strict cryptographic rules (e.g. ML-KEM is never treated as a signature, and certificate authentication remains separate from key exchange). AI cannot approve proposals or alter canonical findings.

### Verifying Local AI Functionality

To run an automated test verifying local Ollama reachability, model loading, minimal inference, and loopback port isolation:

```bash
./deploy/test-ollama.sh
```

---

## 9. React Frontend Production Build & Routing Architecture

### Production Routing Model

```
Browser (Client)
   │
   ├──────► HTTPS GET /  ──────► Nginx ──────► Static Files (/opt/ecdat/apps/web/dist)
   │                             (try_files $uri $uri/ /index.html)
   │
   └──────► POST /api/* ───────► Nginx ──────► FastAPI Backend (127.0.0.1:8000)
                                 (Proxy Pass to loopback; Port 8000 remains unexposed)
```

### Key Frontend Architecture Properties

1. **Relative API Requests**: The client API helper [`apps/web/src/api.ts`](file:///c:/Users/HP/Downloads/SIH2026/SIH2026/apps/web/src/api.ts) invokes `fetch('/api' + path)` and uses `window.location.origin`. No hardcoded `localhost:8000` URLs exist in production assets.
2. **Development Proxy**: Vite's development proxy (`server.proxy['/api'] = 'http://127.0.0.1:8000'`) is used exclusively during local development (`npm run dev`). Production builds consist of static HTML/JS/CSS served directly by Nginx without Vite server runtime overhead.
3. **SPA Routing**: Nginx uses `try_files $uri $uri/ /index.html;` to support client-side React SPA routing seamlessly.
4. **Source Maps**: Production builds set `sourcemap: false` by default for lightweight assets. Source maps can be enabled for debugging by running `SOURCEMAP=true npm run build`.
5. **Backend Fallback**: FastAPI retains a low-priority static file handler (`@app.get('/{path:path}')`) for local development without Nginx, avoiding any dual-serving conflicts in production where Nginx handles static file requests first.


