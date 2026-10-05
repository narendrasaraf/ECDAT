# Implementation status

Updated 26 September 2026. The local demonstration prototype is implemented and its combined acceptance workflow passed. This is not a production deployment or a guarantee of SIH selection.

## Verified result

- Final run `20260926T123113Z-48f38747`: **40/40 live checks passed**, using PostgreSQL, the separate controller, isolated Docker discovery, actual Node 24 TLS, real local EVM transactions and independent verification.
- Final Python regression suite: **84 passed**, with two dependency deprecation warnings. This includes the 21 replay regression cases; those counts must not be added together.
- Portable replay: **lab_reproduced**, authenticated against the supplied trusted digest, **25 checks**, including exact findings/evidence/coverage/Syft comparisons and strict/fallback behavior using a fresh certificate identity.
- Actual local Qwen3 investigation and registered follow-up: seven automated checks passed, followed by reasoning/citation review. The model ranks evidence-gated hypotheses; factual statements and check boundaries are deterministic. General free-form advice remains advisory.
- Browser checks: identity switching, project visibility, measured candidate scope, separate approval, actual execution and local passport presentation passed. See `ui-acceptance.md` for records.
- Production UI build passed: 291.01 kB JavaScript, 88.93 kB gzip; CSS 25.29 kB, 6.00 kB gzip.
- Real ELF/Syft directory/OCI demonstration passed with 664 located symbol findings; symbol presence is explicitly partial evidence.
- Separate blockchain suite previously passed 14 tests; current live final run independently revalidated the changed exported bundle and its actual chain receipt.

## Delivered scope

All six innovations have working paths: coverage-preserving migration acceptance; contradiction-preserving evidence graph; interval scenarios separated from uncertainty; role and hard-constraint candidate selection with attributed/measured scope; independent portable replay; shared prerequisite planning with cycle and blocker handling.

The application includes scoped login, CSRF and project access checks, immutable evidence, an audit chain, durable jobs with retry/cancel/fencing, copied candidate artifacts, exact proposal binding and separate reviewer approval. The custom React workbench connects to these persisted backend records.

The AI advisor and Evidence Investigator use the local model, retain provenance, reject unauthorized identifiers/operations and never approve migrations. Restricted projects cannot use cloud providers. The TLS contradiction investigator was constrained after small-model free-form reasoning failed review; this design choice is visible, not concealed as generated factual prose.

Blockchain provides real local commitments, EIP-712 approval protection, supplier supersession/revocation, salted Merkle disclosure, Ed25519/ML-DSA envelope signatures and an independent pinned verifier. These are demonstrated locally; no public-chain finality is claimed.

## Running

Open Docker Desktop and run `scripts/start.ps1 -StartAI`, then open http://127.0.0.1:8000. This installation already contains the model, scanner image and native Anvil. Startup restores the configured local PostgreSQL service, checks readiness and uses one heavy compute slot. See `README.md` for clean-machine prerequisites and `docs/demo-guide.md` for presentation.

The latest case is named **Payment gateway · verified final demo**, project `5ac80a7c-466b-40f2-bf92-da578f2f32bb`. Its acceptance bundle digest is `958634ae55dcda5d17f8e893627fd87849d0f92d4d185f9d9db83fccf99dc6e9`.

## Evidence and limits

Machine-readable evidence is in `.ecdat/acceptance/end-to-end.json`, `backend-suite.xml`, `live-ai.json`, `isolated-adapters.json` and the final run directory. Historical failed/partial runs remain retained. An older parser-excerpt change is detected by replay; it was not scrubbed from old evidence.

The 8 GB / GTX 1650 installation has executed this workflow locally. Tasks are serialized and the model unloads afterward; this is not a general peak-memory guarantee for arbitrary uploads. Private keys are excluded from bundles, so behavioral replay uses a fresh identity and does not prove original key possession. Unsupported parser scope remains explicit.

External Sepolia deployment and free-cloud-provider credentials are not configured or verified. Local Anvil is controlled by one machine and has no independent consensus. Production hardening, deployment operations and formal accessibility/security certification are outside this authored local prototype claim. Historical research metrics remain historical rather than rerun evidence.
