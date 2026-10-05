# ECDAT blockchain runtime and independent verification

The prototype runs an actual non-upgradeable Solidity EvidenceNotary contract on a native Anvil local EVM. Every displayed result transaction is a mined local transaction. This is a development network under one machine's control, not independent organizational consensus or a public-testnet deployment. The contract records commitments and attributed decisions; it cannot establish scanner truth.

## Runtime choice and dependencies

Use the verified native Anvil binary at `.ecdat/tools/foundry/anvil.exe`, or set `ECDAT_ANVIL` to a trusted installation. The provisioned runtime is Foundry/Anvil 1.8.3. Native Anvil replaces the initially considered Ganache package, avoiding its legacy dependency tree. The launcher binds only `127.0.0.1`, uses development chain ID 31337 and known local test keys, launches with hidden Windows process windows, and stops after each API operation. It uses the Cancun EVM target required by the pinned OpenZeppelin release. These development keys must never receive assets or authenticate a production operation.

Use Node 24 with ML-DSA support for the complete signature path. This machine's verified runtime is `C:/Users/prana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe` (v24.19.0). Ordinary Node 22 does not provide the complete ML-DSA path. The runtime performs real Ed25519 and ML-DSA-65 key generation/signing/verification; no signature test doubles are used. An unsupported runtime reports failure.

Install and test from `packages/chain`:

```powershell
npm.cmd ci
& $Node24 --test --test-concurrency=1 test/bundle.test.mjs test/notary.test.mjs test/integration.test.mjs
& $Node24 scripts/compile.mjs
```

`$Node24` denotes the explicitly selected trusted Node24 executable. Execute tests sequentially on the 8 GB machine. Memory targets in the architecture remain estimates until separately measured. The local EVM requires no GPU. `package-lock.json` pins JavaScript dependencies; audit it as dependencies change.

## API bridge

The trusted controller executes this fixed command, with an internally selected export path and state directory:

```powershell
& $Node24 packages/chain/scripts/api-anchor.mjs BUNDLE_JSON STATE_DIRECTORY
```

For example, use `.ecdat/chain` as the state directory. Never accept arbitrary client-supplied subprocess arguments, paths, keys or RPC methods. The first operation compiles/deploys the contract, assigns separate demo proposer/reviewer/verifier/supplier roles and creates local Ed25519/ML-DSA key pairs. Later operations reopen the persisted chain and pin the deployed code identity. Allow a 90-second controller timeout and serialize operations for each state directory. The trusted controller must terminate the process tree on timeout/cancellation, not only the Node parent.

The bridge verifies the bundle's canonical content digest, exact application proposal binding, matching approval and distinct `author_id`/`reviewer_id`. The contract then records proposal, reviewer decision and result commitment with separate local demo keys. A failed application verification can be recorded: `anchor.verification_status` preserves that failure. Both independent bundle verification and repeated anchor operations recheck the application proposal ID, proposal digest and migration result label against the committed bundle; changing a failed result label to passed is rejected even when its Merkle proofs and chain transaction remain valid. New passports also carry the application verification ID. Blockchain inclusion must not be rendered as a passed migration.

The bridge writes `deployment.json`, `trust.json`, private PEM keys, Anvil snapshots, pending operation journals and `passports/<bundle_digest>.json` in the state directory. Private PEM files stay outside exports; filesystem permissions and machine access protect the local demo keys. Node's POSIX mode flag is not a substitute for Windows ACL enforcement. The key IDs, not private keys, appear in output.

Standard output contains one JSON object. Successful output includes `status: "included-local"`, a complete `ecdat.passport.v1`, `passport_path`, `trust_path`, chain/contract/code identity, transaction/block identity and signatures. Failure produces `status: "failed"`, an error and a nonzero process exit. The API must not substitute a fabricated anchor when a subprocess fails. No output is labelled publicly finalized.

The exporter schema is `ecdat.bundle.v1`. Its `content_digest` is SHA-256 of RFC8785 canonical JSON for the entire envelope excluding `content_digest`. Added bundle fields are included in hashing automatically. Duplicate JSON object keys, nonfinite numbers, out-of-range integers and invalid Unicode are rejected. The configured JSON input maximum is 64 MiB; larger exports require an explicitly reviewed streaming design.

## Commitments and signatures

Each nonempty top-level array supplies one Merkle leaf per record. Scalar/object/empty-array fields each supply a leaf. Leaves bind opaque project ID, field/index identity, the canonical record digest and a random 256-bit salt. OpenZeppelin StandardMerkleTree supplies double-hashed safe leaves and compatible sorted-pair proofs. Salts remain in the authorized passport, not on chain. The contract receives only opaque IDs and digests/roots; public metadata still reveals transaction timing and actor relationships.

The detached signature envelope is:

```json
{"schema":"ecdat.passport.signature.v1","project_id":"...","bundle_digest":"...","merkle_root":"0x...","record_count":1}
```

Both local-demo signature key IDs are required by the external trust policy. Removing one signature is rejected rather than silently downgrading authentication. Ed25519 and ML-DSA signing are independent of Ethereum's EIP-712 authorization. Ethereum account signatures and consensus are not made post-quantum by this extra evidence signature.

The trust registry is an external trust input. An auditor must retain/enroll its public keys and required-key policy through a trusted channel. A bundle accompanied by attacker-selected public keys does not establish an identity. Local automatic demo enrollment demonstrates the mechanism, not a real organization's certification. Current code supports explicit key revocation in the trust registry; production key enrollment, rotation ceremonies and historical validity policy need operational controls.

## Independent verifier commands

No ECDAT HTTP API is needed to check the following:

```powershell
& $Node24 packages/chain/scripts/bundle.mjs verify BUNDLE_JSON --passport PASSPORT_JSON --trust TRUST_JSON
& $Node24 packages/chain/scripts/verify-anchor.mjs BUNDLE_JSON --passport PASSPORT_JSON --trust TRUST_JSON --deployment DEPLOYMENT_JSON --state-dir STATE_DIRECTORY
```

The first command checks canonical bundle digest, every expected record, complete Merkle root, individual inclusion proofs and required enrolled signatures. It explicitly reports `chain_status: "not_checked"`. Unsigned commitment-only verification reports `signature_status: "unsigned"` when no trust policy was supplied; supplying a trust policy requires a valid signature.

The second command additionally reopens an **existing** local chain (never deploys), checks independently pinned network/address/code identity, contract state, matching root/digest, separate actors, EIP-712 reviewer signature, block/receipt identity and the exact ResultRecorded event. Local finality is explicitly `local-development-no-independent-finality`. For a separately deployed public chain, use `--rpc URL` instead of `--state-dir`; the read-only verifier checks the chain's finalized block tag. A trusted RPC is not a consensus light client.

Selected disclosure:

```powershell
& $Node24 packages/chain/scripts/bundle.mjs disclose BUNDLE_JSON --passport PASSPORT_JSON --key evidence/0
& $Node24 packages/chain/scripts/bundle.mjs verify-disclosure DISCLOSURE_JSON --root INDEPENDENTLY_TRUSTED_MERKLE_ROOT
```

Membership verifies an item belongs to a committed set. It does not prove completeness or claim truth. Full deterministic replay remains the separate backend replay facility. Offline bundle verification does not establish fresh chain revocation/supersession status.

## Recovery and boundaries

Anvil snapshots preserve historical states and receipt data. The controller explicitly calls `anvil_dumpState` before stopping the Windows child; it does not rely on signal-triggered shutdown saving. A per-state-directory process lock prevents concurrent writers. A lock owned by a demonstrably absent process can be reclaimed; malformed/active locks require operator attention. Pending journals preserve the salted passport and EIP-712 decision before submission; snapshots are checkpointed after each confirmed transition. Retries inspect actual contract state and reuse recorded events. A completed repeat verifies the existing passport and returns the same transaction.

Source has no funds, upgrade proxy, arbitrary external calls or destructive history edit. On-chain roles use OpenZeppelin AccessControlDefaultAdminRules. Proposals bind immutable version/digest; reviewer decision binds chain ID, contract, proposal/version/digest, action, signer, nonce and deadline. Proposer/reviewer/verifier separation is checked even if an administrator grants overlapping roles. Supplier replacement and revocation preserve prior commitments. An administrator still controls role enrollment, and all local participants share one machine; this is an explicit trust limitation.

No Sepolia deployment, faucet acquisition or independent external witness has been executed or verified. `deploy.mjs` deliberately permits only localhost chain 31337. The separate `deploy-sepolia.mjs` implements the authorized public-testnet path using the same contract. Configure `ECDAT_SEPOLIA_RPC` with an available free RPC, `ECDAT_SEPOLIA_DEPLOYER_KEY` with a dedicated testnet key, and four distinct `ECDAT_PROPOSER_ADDRESS`, `ECDAT_REVIEWER_ADDRESS`, `ECDAT_VERIFIER_ADDRESS`, `ECDAT_SUPPLIER_ADDRESS` values. The administrator/deployer must be a fifth distinct account. Do not reuse mainnet accounts. Optional `ECDAT_SEPOLIA_STATE` controls the output directory; default is `.ecdat/sepolia`.

```powershell
& $Node24 packages/chain/scripts/deploy-sepolia.mjs
```

It enforces Sepolia chain ID 11155111, validates address separation, checks available test ETH against a conservative gas estimate and records deployment/code identity and actual role-enrollment transactions. It never buys test ETH or enables paid services. Missing credentials or insufficient faucet funds produce an explicit blocked/unconfigured result. RPC URLs, API keys and private keys are not written to logs or deployment records. Submitted transactions are retained before waiting; after any uncertain failure, reconcile `pending-deployment.json` and `deployment.json` rather than blindly redeploying. Partial role enrollment remains labelled pending and requires continuation against the existing deployment. The script does not automatically verify source on an explorer or claim finality without observing the finalized block. Public-contract behavior, external key enrollment and provider availability remain unverified until this path actually runs; it must not silently fall back to local status.

Official references: [Anvil](https://www.getfoundry.sh/anvil/index.html), [OpenZeppelin access control](https://docs.openzeppelin.com/contracts/5.x/access-control), [cryptographic utilities](https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography), [EIP-712](https://eips.ethereum.org/EIPS/eip-712), [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

## Final local verification record — 23 September 2026

The sequential Node 24 suite completed with **14 tests passed, zero failed or skipped**, in 31.36 seconds. It exercised real Anvil deployment and transactions, separate governance actors, wrong-chain/wrong-contract signatures, signer nonce replay prevention, rejection and cancellation boundaries, supplier supersession/revocation, canonical JSON and Merkle tamper detection, Ed25519 and native ML-DSA-65, API bridge persistence, independent CLI chain verification, interrupted-passport recovery and idempotent repeat.

Final review then found and fixed the result-label binding gap described above. The affected bundle and integration tests were rerun: **5 passed, zero failed or skipped**, in 29.23 seconds, including four negative cases that change only the passport's result status, application proposal ID, application verification ID or proposal digest. These are overlapping tests, not 19 distinct tests. Tests use authored fixtures and an actual local EVM; this record is not a claim that the full application or public Sepolia deployment has passed.

The Sepolia configuration command was also executed without credentials and returned `status: unconfigured`, `deployed: false`, listing the six required environment variable names. No public-network transaction was submitted. Application passport downloads may omit machine-local paths and add transport URLs/status without altering the signed canonical envelope; the independent verifier still requires separately enrolled trust keys and the original committed bundle.
