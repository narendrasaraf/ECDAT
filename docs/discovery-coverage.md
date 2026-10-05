# Discovery coverage and deterministic analysis

Version: `ecdat-discovery-0.1`. These are bounded static adapters. Located references are not proof of executed cryptography or exhaustive source analysis.

| Adapter | Supported behavior | Explicit boundary |
| --- | --- | --- |
| Python AST | `hashlib`, selected `cryptography` algorithm/hash/asymmetric constructors, PyCryptodome cipher/public-key calls; import aliases; real source lines; unknown keyword parameters | No interprocedural dataflow, dynamic imports, arbitrary wrappers or execution. Key generation is not automatically classified as signing. |
| JS/TS Tree-sitter | Node `crypto` named/default/namespace imports and `require` destructuring; hash/HMAC/cipher/sign/key-generation calls; literal vs unknown algorithm | No inferred WebCrypto flows, dynamic module loaders or runtime values. Whole-file syntax failures remain failed. |
| Certificates / public keys | PEM/DER X.509 and public-key algorithms, sizes and SPKI digests | Private PEM material is protected. Public keys without usage evidence have unknown role. Only first certificate in a PEM chain is inspected, reported partial. |
| ELF symbols | Real ELF structure via pyelftools; selected RSA/AES/SHA256/OpenSSL symbols | Always partial; symbol presence does not establish execution, role or stripped-code behavior. Malformed ELF preserves a failed coverage record. |
| Structured metadata | `tls.groups`, minimum version and declared authentication; attributed supplier/cloud/HSM metadata; attributed historical TLS observations | Imported observations are labeled imported; this adapter never claims it performed a network probe. |
| Syft inventory | Local directory inventory; explicitly named `.oci.tar` / `.oci.tar.gz` archives through local OCI archive source | Trusted isolated runner must opt in with `ECDAT_ENABLE_SYFT=1`; updater disabled, no registry/image pulls, one worker. Missing executable is unavailable, not success. Package presence is evidence, not confirmed crypto use. |

`scan_directory(Path)` returns `findings`, `evidence`, `coverage`, `conflicts`, and `manifest`. It does not execute uploaded source. Excerpts omit source arguments and private bytes. Unsupported files remain in the manifest and coverage. Individual parser failures do not discard completed evidence from other files. Inputs are bounded to 20 MB per file and 10,000 discovered entries; the trusted controller enforces process and output bounds. Python and JS imported names with possible rebinding/shadowing are conservatively suppressed for the whole file; this can miss an outer reference and is not full scope/dataflow analysis.

Strict configuration mismatches compare the same scope and role against allowed groups. RSA authentication plus hybrid key exchange is not a contradiction. An imported historical observation does not prove a current mismatch: the retained conflict explicitly requires temporal applicability review.

Archive intake rejects raw backslash names (including Windows normalization), traversal/absolute/drive/device paths, duplicate case-folded names, symlinks/hardlinks/devices, encrypted ZIP entries, file-as-directory collisions, oversized members, total expansion, compression-ratio and nesting limits. Extract to a fresh private staging directory; publish only when `ok` is true. Caller owns failed staging cleanup. Nested archive files are not recursively extracted by intake.

Analysis exports:

- `assess_context(data_lifetime, migration_time, quantum_horizon)` accepts scalar or `[low,high]` years, or `{low,high,unit}`. Equality does not trigger `X+Y>Z`. Missing values create investigation tasks; timing never invents evidence confidence.
- `candidate_options(role, peer_capabilities=None, **constraints)` returns feasible/blocked candidates and explicit exclusions. Unknown runtime/peer/HSM/resource support remains blocked. Role/protocol mismatches are rejected before ranking.
- `plan_tasks(tasks)` returns dependency order, actual strongly connected cycles, missing prerequisites, shared dependencies and propagated blockers. A shared prerequisite has one ID.
- `compare_coverage(before,after)` detects missing files, missing coverage records, parser regressions and adapter-version changes. It retains partial/unsupported residuals. A passed coverage comparison alone is not migration acceptance.

The tests in `tests/test_discovery.py` and `tests/test_analysis.py` are authored regression cases. They do not establish enterprise detection accuracy. Actual test execution and isolated Syft/container results belong in the implementation status report.
