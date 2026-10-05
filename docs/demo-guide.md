# ECDAT demonstration guide

## Start

Open Docker Desktop, then run `scripts/start.ps1 -StartAI`. Open http://127.0.0.1:8000. The supplied installation has the scanner image, Anvil, local model and dependencies. For a clean machine follow README.md.

Analyst: `analyst` / `demo-analyst-change-me`. Separate reviewer: `reviewer` / `demo-reviewer-change-me`. These are local demonstration accounts.

## Eight-minute evidence story

1. **Show disagreement.** The supplier declaration expects strict hybrid key exchange; a dated imported observation records X25519. Inspect both sources in the evidence graph. RSA certificate authentication remains a separate finding.
2. **Show uncertainty.** Unsupported inputs remain visible in coverage. Lifetime [8,12], migration [2,4] and horizon [8,15] years produce a scenario-dependent interval of −5 to +8 years. These are authored assumptions, not quantum-hardware predictions.
3. **Show constrained choices.** Use a passed laboratory verification as capability evidence. Hybrid TLS is feasible within that laboratory scope. Requiring an HSM blocks it because HSM evidence is absent. Wrong-role alternatives remain excluded.
4. **Ask the investigator.** The real local model ranks two registered hypotheses for the mismatch. Evidence statements and test boundaries are deterministic. Execute the registered laboratory observation; preserve the original contradiction and append the new evidence.
5. **Demonstrate governance.** Inspect a proposal's exact patch and acceptance contract. The analyst cannot approve it. Sign in as reviewer, approve it, then return as analyst and execute.
6. **Show actual behavior.** Inspect eight authenticated hybrid handshakes and strict classical-peer rejection. A separately approved fallback policy permits authenticated classical exchange. Show unchanged original bytes and the remaining RSA authentication.
7. **Explain blockchain's purpose.** Export the CBOM and request the passport. The actual local contract binds proposal, separate decision and result commitment. Demonstrate salted Merkle proofs, selective disclosure, replay-resistant approvals and supplier revocation. ML-DSA protects the detached envelope; it does not make Ethereum post-quantum.
8. **Verify independently.** Check signatures, Merkle proofs and contract state using independently trusted pins. Replay exported bytes and compare findings, evidence and coverage. Optional isolated discovery and fresh-identity TLS replay reproduce laboratory behavior. Altered evidence fails verification.

## Boundaries to explain

Blockchain makes changes to committed evidence detectable; it cannot establish scanner truth. Local Anvil has no independently operated consensus. Sepolia requires external credentials and actual deployment before claiming public inclusion. A fresh replay certificate demonstrates behavior, not possession of the original private key or production security.

Keep heavy work sequential on the 8 GB laptop. Use the current fresh case for exact replay; old records retain a historical parser-excerpt difference that replay correctly detects. If AI is unavailable, show that state and continue deterministic review. Do not describe a stored response as live inference. Competition selection cannot be guaranteed.
