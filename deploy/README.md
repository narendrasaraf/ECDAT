# ECDAT Production Deployment on Ubuntu / AWS EC2

This guide provides the complete, production-grade instructions for deploying **ECDAT (Evidence Workbench)** on an AWS EC2 Ubuntu server with public HTTPS access behind Nginx.

---

## 1. Production Architecture Overview

```
Internet (Public Client)
   │
   ▼ HTTPS (Port 443)
┌────────────────────────────────────────────────────────┐
│ Nginx Reverse Proxy & Web Server                      │
│ - Serves built React SPA (/opt/ecdat/apps/web/dist)   │
│ - Handles SPA client routing (try_files)              │
│ - Proxies /api requests to 127.0.0.1:8000             │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP Loopback
                            ▼
┌────────────────────────────────────────────────────────┐
│ FastAPI Application (127.0.0.1:8000)                   │
│ - Systemd service: ecdat-api.service                   │
│ - Bound strictly to 127.0.0.1                         │
│ - Runs as non-root user 'ecdat'                        │
└───────────────┬──────────────────────────┬─────────────┘
                │                          │
                ▼                          ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│ PostgreSQL 17 (Docker)       │ │ Ollama Local AI       │
│ - 127.0.0.1:5432 (Loopback)  │ │ - 127.0.0.1:11434     │
│ - Named volume: ecdat-db     │ │ - Model: qwen3:1.7b   │
│ - Never exposed publicly     │ │ - Host CPU inference  │
└──────────────────────────────┘ └───────────────────────┘
                ▲
                │ Database Session
┌───────────────┴────────────────────────────────────────┐
│ Trusted Host Worker                                    │
│ - Systemd service: ecdat-worker.service                │
│ - Runs as user 'ecdat' (supplementary group: docker)   │
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
│ - Mounted input artifact: readonly                     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Core Security Model & Constraints

1. **Docker Socket Isolation**: The Docker daemon socket (`/var/run/docker.sock`) is **never** mounted into the FastAPI application or exposed to web requests. Only the trusted background worker process communicates with Docker to run scanner tasks.
2. **Strict Loopback Bindings**: FastAPI (`127.0.0.1:8000`), PostgreSQL (`127.0.0.1:5432`), and Ollama (`127.0.0.1:11434`) bind **exclusively** to local loopback. None of these ports are accessible from the public internet.
3. **No Public AI Exposure**: Port 11434 is restricted to `127.0.0.1` and never forwarded by Nginx or open in EC2 Security Groups.
4. **Deterministic Scanner Sandboxing**: All scanner runs use hard kernel isolation flags:
   - `--network none`
   - `--read-only`
   - `--cap-drop ALL`
   - `--security-opt no-new-privileges`
   - `--memory 512m --cpus 1 --pids-limit 96`
   - `--tmpfs /tmp:rw,noexec,nosuid,size=128m`
   - `--user 65532:65532`
5. **Least-Privilege Services**: Systemd services run as a dedicated system user `ecdat` (`/usr/sbin/nologin`). Only `.ecdat` runtime directories are owned by `ecdat:ecdat`, preserving repository Git ownership.
6. **Environment File Security**: `/etc/ecdat/ecdat.env` is owned by `root:ecdat` with `640` permissions so service processes can read credentials without exposing secrets to other users.

---

## 3. EC2 Instance Sizing & Security Group Prerequisites

### Recommended Instance Specification
For smooth offline AI inference, scanning, and evidence processing, the recommended production sizing is:

- **Architecture**: `x86_64`
- **Instance Type**: `t3.xlarge`, `c6i.xlarge`, or `m6i.xlarge`
- **vCPU**: 4+ vCPUs
- **Memory**: 16 GB RAM
- **Storage**: 80–100 GB gp3 SSD
- **GPU**: **None required** (ECDAT uses CPU-based Ollama inference)

#### Why 16 GB RAM?
The 16 GB memory envelope comfortably accommodates concurrent services without swapping:
- **Ollama Engine & Qwen 3 (1.7B) Context**: ~3.5–4.5 GB
- **PostgreSQL 17 Database Engine**: ~512 MB – 1 GB
- **FastAPI Backend (Uvicorn)**: ~300–500 MB
- **Trusted Host Worker**: ~300–500 MB
- **Isolated Docker Scanner Containers**: ~512 MB bounded admission slot
- **Node.js 24 & Frontend Tooling**: ~2–3 GB peak during builds/migrations
- **Linux Kernel, Page Cache & Reserve Admission Floor**: ~350 MB admission threshold

> **Note on Smaller Instances**: `t3.medium` or `t3.large` (4–8 GB RAM) can be used for basic functional acceptance testing, but 16 GB RAM is required for smooth public demonstration and production stability under load.

### AWS Security Group Inbound Rules
Configure your EC2 Security Group to allow **only** these inbound ports:

| Type | Port | Protocol | Source | Purpose |
| --- | --- | --- | --- | --- |
| SSH | 22 | TCP | Your IP only (`x.x.x.x/32`) | Server administrative access |
| HTTP | 80 | TCP | `0.0.0.0/0` | HTTP traffic & Let's Encrypt validation |
| HTTPS | 443 | TCP | `0.0.0.0/0` | Secure public web access |

> **CRITICAL**: Do **NOT** open ports `8000` (FastAPI), `5432` (PostgreSQL), or `11434` (Ollama) in your AWS Security Group.

---

## 4. Software Dependencies Installation

On a fresh Ubuntu 24.04 or 22.04 LTS instance:

```bash
# 1. Update system packages
sudo apt update && sudo apt upgrade -y

# 2. Install Python 3.12+, build utilities, and Nginx/Certbot
sudo apt install -y python3 python3-venv python3-pip git curl nginx certbot python3-certbot-nginx

# 3. Install Node.js 24 (via NodeSource official repository)
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs

# 4. Install Docker Engine and Docker Compose v2 plugin
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

*Note: If you were just added to the `docker` group, log out and log back in or run `newgrp docker` to activate group membership.*

---

## 5. Step-by-Step Production Deployment

### Step 1: Clone Repository & Run Automated Build Script

```bash
cd /opt
sudo git clone https://github.com/narendrasaraf/ECDAT.git ecdat
sudo chown -R $USER:$USER /opt/ecdat
cd /opt/ecdat

# Run automated install script (creates ecdat user, builds scanner image, builds frontend)
./deploy/install.sh
```

### Step 2: Configure Production Environment & Secrets

```bash
# Create directory and copy template (will not overwrite if already existing)
sudo mkdir -p /etc/ecdat
sudo cp -n deploy/ecdat.env.example /etc/ecdat/ecdat.env

# Set strict permissions: readable only by root and ecdat service user
sudo chown root:ecdat /etc/ecdat/ecdat.env
sudo chmod 640 /etc/ecdat/ecdat.env

# Edit configuration with your random secure database password and public domain
sudo nano /etc/ecdat/ecdat.env
```

Ensure the following variables are set in `/etc/ecdat/ecdat.env`:
```dotenv
ECDAT_PROFILE=isolated
ECDAT_DEMO=0
ECDAT_WORKER=0
ECDAT_COOKIE_SECURE=1
ECDAT_POSTGRES_PASSWORD=GENERATE_A_SECURE_RANDOM_PASSWORD_HERE
ECDAT_DATABASE_URL=postgresql+psycopg://ecdat:GENERATE_A_SECURE_RANDOM_PASSWORD_HERE@127.0.0.1:5432/ecdat
ECDAT_AI_PROVIDER=ollama
ECDAT_AI_MODEL=qwen3:1.7b
OLLAMA_HOST=http://127.0.0.1:11434
ECDAT_ORIGIN=https://ecdat.example.com
```

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

Install Ollama binary:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Run the Ollama setup script to bind Ollama to loopback (`127.0.0.1:11434`), pull `qwen3:1.7b`, and run an inference test:
```bash
./deploy/ollama-setup.sh
```

### Step 6: Verify Runtime Permissions

Ensure `.ecdat` runtime directories are owned by the `ecdat` user:
```bash
sudo chown -R ecdat:ecdat /opt/ecdat/.ecdat
sudo chmod 750 /opt/ecdat/.ecdat
```
*(Do not recursively chown `/opt/ecdat` to `ecdat`; repository files remain owned by your deploy user).*

### Step 7: Install & Enable Systemd Services

```bash
sudo cp deploy/ecdat-api.service deploy/ecdat-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ecdat-api.service ecdat-worker.service
```

### Step 8: Configure Nginx & Let's Encrypt HTTPS

```bash
# Copy site configuration
sudo cp deploy/nginx/ecdat.conf /etc/nginx/sites-available/ecdat

# Replace example domain placeholder with your actual domain
sudo sed -i 's/ecdat.example.com/your-domain.com/g' /etc/nginx/sites-available/ecdat

# Enable site and disable default site
sudo ln -sf /etc/nginx/sites-available/ecdat /etc/nginx/sites-enabled/ecdat
sudo rm -f /etc/nginx/sites-enabled/default

# Test Nginx syntax and reload
sudo nginx -t && sudo systemctl reload nginx

# Obtain and install Let's Encrypt SSL certificate
sudo certbot --nginx -d your-domain.com
```

---

## 6. Deployment Verification Checklist

Run these commands to confirm that every tier of the production stack is healthy:

### 1. Service Status Checks
```bash
sudo systemctl status docker --no-pager
sudo docker compose -f /opt/ecdat/deploy/docker-compose.prod.yml ps
sudo systemctl status ollama --no-pager
sudo systemctl status ecdat-api --no-pager
sudo systemctl status ecdat-worker --no-pager
sudo nginx -t
```

### 2. Endpoint Checks
```bash
# Verify Docker container running
docker ps

# Verify Ollama local model list
curl -s http://127.0.0.1:11434/api/tags

# Verify ECDAT API health endpoint
curl -s http://127.0.0.1:8000/api/health

# Verify Ollama inference and isolation via automated test
./deploy/test-ollama.sh

# Run comprehensive system status script
./deploy/status.sh
```

### 3. Service Logs Monitoring
```bash
# Monitor FastAPI logs
sudo journalctl -u ecdat-api.service -f

# Monitor trusted host worker logs
sudo journalctl -u ecdat-worker.service -f

# Monitor Ollama logs
sudo journalctl -u ollama.service -f

# Monitor Nginx web traffic
sudo tail -f /var/log/nginx/access.log /var/log/nginx/error.log
```

---

## 7. Service Management & Operations

### Quick Service Controls
```bash
# Start all production services
./deploy/start.sh

# Stop application services safely (preserves database volume ecdat-db)
./deploy/stop.sh

# Check overall health and status
./deploy/status.sh
```

### Rollback / Clean Reset
To stop services without losing persistent database data:
```bash
./deploy/stop.sh
```

To purge temporary scan staging without affecting persisted records:
```bash
sudo rm -rf /opt/ecdat/.ecdat/staging/*
```

---

## 8. Local Ollama AI Deployment & Data Privacy

ECDAT is designed for data sovereignty and strict cryptographic evidence verification:

- **Local Host Execution**: When `ECDAT_AI_PROVIDER=ollama` (the default), inference runs entirely on loopback (`http://127.0.0.1:11434`) using the local `qwen3:1.7b` model.
- **Zero Remote Cloud Data Leakage**: No evidence, project context, or user queries are sent to external cloud AI providers.
- **Strict Opt-In for Cloud AI**: Remote providers (Groq/Gemini) are disabled by default and require explicit API keys plus `public-demo` project disclosure permissions. Restricted project data remains 100% local.
- **No AI Governance Authority**: Model output is advisory only. AI cannot approve proposals, execute migrations, or modify canonical scan evidence.
- **Hardened Validation**: Every response is verified against schema boundaries, citation allowlists, and strict cryptographic facts (ML-KEM is never treated as a signature, and RSA certificate authentication remains separate from hybrid key exchange).

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

1. **Relative API Requests**: [`apps/web/src/api.ts`](file:///c:/Users/HP/Downloads/SIH2026/SIH2026/apps/web/src/api.ts) calls relative `/api` paths with credentials and CSRF tokens. No hardcoded localhost or EC2 IP addresses exist in compiled assets.
2. **SPA Routing**: Nginx uses `try_files $uri $uri/ /index.html;` so direct URL navigation and page refreshes work smoothly.
3. **Optimized Assets**: Production builds omit source maps by default (`sourcemap: false`), keeping client bundles compact. Run `SOURCEMAP=true npm run build` if debugging symbols are required.
