# ECDAT · Evidence Workbench

ECDAT links cryptographic discovery, explicit uncertainty, an approved migration, real TLS verification and a portable evidence receipt. This repository is a working prototype under active acceptance testing. See [the architecture](docs/architecture.md), [implementation status](docs/implementation-status.md) and [scanner boundaries](docs/discovery-coverage.md).

## Run on Windows

Requirements: Python 3.12+, Node **24** for hybrid TLS and ML-DSA, and Docker Desktop for PostgreSQL and isolated archive discovery. The UI builds once and is served by the API. GPU inference is optional at startup.

```powershell
.\scripts\setup.ps1
.\scripts\start.ps1 -StartAI
```

Open **http://127.0.0.1:8000**. Explicit demo startup provisions these local-only accounts:

| Role | Username | Password |
| --- | --- | --- |
| Analyst | `analyst` | `demo-analyst-change-me` |
| Reviewer | `reviewer` | `demo-reviewer-change-me` |

Create the authored demonstration project in the interface. The initial discovery job runs in the separate worker. These accounts are for a loopback demonstration, not public deployment. Restricted projects are excluded from remote AI. No account registration or public hosting is performed by setup.

`scripts/stop.ps1` stops the API and worker that the launcher recorded, including their Windows interpreter children. It does not erase data. Data, private local keys, downloads and logs remain under `.ecdat/`, excluded from Git.

## PostgreSQL and isolated discovery

Set a generated `ECDAT_POSTGRES_PASSWORD` in `.env`, set `ECDAT_DATABASE_URL=postgresql+psycopg://ecdat:YOUR_PASSWORD@127.0.0.1:5433/ecdat`, and set `ECDAT_PROFILE=isolated`. Then:

```powershell
docker compose up -d postgres
docker build -f Dockerfile.scanner -t ecdat-scanner:local .
.\scripts\start.ps1 -Isolated
```

The API has no container socket mounted. The trusted host worker launches fixed commands. Discovery containers run as a non-root user with a read-only input, no network, no capabilities, bounded CPU/RAM/PIDs and a bounded temporary filesystem. They receive no database credentials or signing/provider keys. Syft is pinned and checked against the upstream release digest. Native mode accepts authored fixtures only; it is a development profile with SQLite, not the PostgreSQL deployment claim.

An admission lease serializes scanner jobs, verification and AI requests. Queued jobs report low memory instead of silently skipping checks. The configured memory threshold is an admission floor, not a guarantee that Windows will retain that much free RAM. Close unused applications when demonstrating the full stack on an 8 GB laptop. Discovery breadth is bounded and explicitly reported.

## AI and Evidence Investigator

The supplied local runtime uses `qwen3:1.7b`. On a new machine install [Ollama](https://ollama.com/download/windows), then run `scripts/start-ai.ps1 -PullModel` once. The script limits concurrent requests and loaded models to one. Configure:

```dotenv
ECDAT_AI_PROVIDER=ollama
ECDAT_AI_MODEL=qwen3:1.7b
OLLAMA_HOST=http://127.0.0.1:11434
```

ECDAT allows one model request, uses bounded context and unloads the model after the response. Initial GPU warmup can take longer than normal requests. A provider timeout is recorded as unavailable; it never becomes a fabricated answer. Configure Groq or Gemini with your own free-tier account/key if preferred. ECDAT does not enable billing or acquire keys. Cloud requests accept only public authored demonstration evidence; restricted project content remains local.

For the registered TLS contradiction, the real model ranks two distinct hypotheses from an evidence-gated catalog. The server assembles factual premises, citations and check boundaries deterministically and labels that division explicitly. Other free-form advice remains subject to human review. The server rejects unknown evidence IDs, extra authority fields and arbitrary operations. A requested check runs through the durable worker; its result becomes additional evidence. AI never approves a proposal or replaces a scanner result.

## Review and verification

1. Scan the authored baseline and inspect both the supplier expectation and the older imported observation.
2. Evaluate lifetime/migration/quantum-horizon intervals. Unknown measurements remain separate from timing urgency.
3. Inspect role-compatible alternatives and shared/blocked supplier prerequisites.
4. Create the supported `tls-hybrid` proposal. It binds the artifact, discovery baseline, exact patch, policy and acceptance contract.
5. Sign out and sign in as the separate reviewer. Approve the exact proposal.
6. Return as analyst and execute. ECDAT copies the input, changes only the reviewed TLS groups, rescans and performs authenticated loopback TLS tests.
7. Inspect each check and the retained **RSA certificate authentication** residual. Hybrid key exchange does not replace it.
8. Export the schema-validated CycloneDX 1.6 CBOM and replay bundle, then request a blockchain passport.

Self approval, stale bytes/baselines, an unexpected patch, disappeared files and parser regressions block acceptance. Strict hybrid rejects a classical-only peer; an approved fallback policy has separate behavior. Results concern the declared laboratory boundary, not every enterprise system.

## Blockchain passport and independent replay

Use the small native Anvil runtime for the real local EVM. The verified Windows binary is expected at `.ecdat/tools/foundry/anvil.exe`, or set `ECDAT_ANVIL`. See [blockchain commands and trust model](docs/blockchain-runtime.md).

The receipt carries salted Merkle commitments, exact approval/result bindings and Ed25519 plus ML-DSA-65 envelope signatures. The local chain records actual contract transactions with separate development accounts. **Local inclusion is not independent consensus or public-chain finality.** ML-DSA protects the detached envelope; it does not make Ethereum account signatures post-quantum.

The browser's file checker compares a file against a separately trusted SHA-256 value. The independent CLI also checks signatures, Merkle proofs and the pinned contract. It needs no ECDAT HTTP server:

```powershell
.venv\Scripts\python.exe scripts/replay.py PATH_TO_BUNDLE --expected-digest TRUSTED_CANONICAL_DIGEST --isolated --tls-lab
node packages/chain/scripts/verify-anchor.mjs PATH_TO_BUNDLE --passport PATH_TO_PASSPORT --trust TRUST_REGISTRY --deployment DEPLOYMENT_REGISTRY --state-dir LOCAL_CHAIN_STATE
```

Keep trust keys/deployment records obtained through an authenticated channel. A digest or key embedded in an untrusted file cannot establish authenticity by itself. Offline verification cannot establish fresh revocation or public-chain state. A configured Sepolia path uses free test ETH only; an external deployment is not claimed until its transactions are actually verified.

## Checks

The complete presentation route is in [the demonstration guide](docs/demo-guide.md). [Portable replay](docs/portable-replay.md) explains fresh certificate identity, isolated adapters and partial-result exit codes.

```powershell
.venv\Scripts\python.exe -m pytest -q
node --test --test-concurrency=1 packages/chain/test/*.test.mjs
npm.cmd --prefix apps/web run build
```

## Ubuntu / EC2 Production Deployment

For step-by-step instructions on deploying ECDAT on an AWS EC2 Ubuntu server with Nginx HTTPS, PostgreSQL, systemd services, local Ollama AI, and isolated Docker scanner, see [deploy/README.md](deploy/README.md).

Use Node 24, or point `ECDAT_NODE` to the bundled Node 24 executable. Run heavy checks sequentially on this laptop. Tests produce actual evidence; historical metrics from the supplied research documents are not treated as rerun results.
