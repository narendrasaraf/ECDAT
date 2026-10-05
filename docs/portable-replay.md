# Portable evidence replay

Run `python scripts/replay.py bundle.json --expected-digest TRUSTED_DIGEST --tls-lab --isolated --output replay.json` from the installed project. Obtain the canonical digest independently of the bundle. Dependencies are installed by project setup. Node 24 with hybrid TLS support is required for the optional TLS check. Docker and the installed `ecdat-scanner:local` image are required for `--isolated`.

The replay process does not connect to the ECDAT API. It checks canonical bytes, audit continuity, CycloneDX schema and inventory, proposal and approval bindings, restores safe snapshots into a temporary directory, and reruns the installed static scanner. It compares located findings, evidence, citations and coverage as multisets. Unknown or unsupported coverage remains visible; missing private material and unavailable external adapters produce a partial result.

`--isolated` runs the fixed scanner container with no network, read-only input and filesystem, dropped capabilities, a non-root user, 512 MB memory, one CPU, 96 process limit and bounded temporary space. Each scan is limited to 100 seconds and bounded output, with container cleanup on exit. This mode compares all recorded coverage and evidence including Syft; it never ignores differences to manufacture success. Without this option, successful external-adapter observations remain unavailable for complete replay.

`--tls-lab` explicitly opts into the fixed, authored loopback harness. Only the approved registered TLS group settings are passed to it. It never executes uploaded source or connects to supplied targets. The process creates a temporary RSA key and certificate, performs eight hybrid handshakes with authenticated payload checks, then tests a classical-only peer against strict or expressly permitted fallback policy. It compares those outcomes with the recorded laboratory observations. Maximum 16 verification records are replayed, each with a 30-second timeout.

**This is a fresh laboratory identity. It does not reproduce the original certificate identity, original latency, deployed production behavior, blockchain freshness, or enterprise security.** Keys are temporary and removed at completion. Blockchain verification is a separate independent operation using pinned deployment and enrolled signer keys.

Result `lab_reproduced` means both static observations and fresh-identity TLS behavior matched. `static_reproduced` means static observations matched without behavioral measurements. `partial` never counts as complete replay; a failed check returns `failed`.

## Actual checks on 2026-09-26

- Replay tests: 21 passed, including re-sealed semantic tampering, withheld snapshots, escaping paths, audit truncation, baseline provenance, strict/fallback policy, transport failure rejection and external-adapter evidence comparison/tampering.
- Fixed Node harness: both strict hybrid and permitted classical fallback passed, each with eight hybrid authenticated payload checks. Results saved locally in `.ecdat/acceptance/replay-fresh-tls.json`.
- Full fresh-bundle replay with isolated scanning and TLS passed: `lab_reproduced`, authenticated against the supplied independent digest, no failed or unavailable checks. Report: `.ecdat/acceptance/runs/20260926T122721Z-4641eefd/replay.json`. This includes all three artifacts, exact static coverage/evidence/findings comparisons including Syft, and both strict and permitted-fallback TLS behavior. Blockchain freshness remains a separate check.
