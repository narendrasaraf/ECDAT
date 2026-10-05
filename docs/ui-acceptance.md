# UI acceptance record

## Completed browser checks, 25 September 2026

The browser integration run completed the following after the initial milestones below:

- Fixed and retested analyst → reviewer → analyst session switching on the same project. Signout clears project and transient state; inflight workspace reads are cancelled. Reviewer could not see the analyst's private project.
- Created and separately approved proposal `2d728b0e-b94b-4467-bbb9-0a84b99f687d` through the interface. UI-triggered verification `d90ae843-e00c-4a5b-a720-28cfe84fb0c1` displayed passed.
- Submitted measured capability evidence through the form. Hybrid TLS displayed feasible with its explicit registered-laboratory scope; signature support remained blocked. Candidate inspectors retain provenance and constraints.
- Inspected a real local passport at block 11 with passed migration result and explicit absence of independent consensus.
- Production build passed after accessible icon labels, session reset and capability form changes. Final measured bundle was 290.68 kB JavaScript / 88.84 kB gzip before the small provenance display addition. No exhaustive accessibility certification is claimed.

AI and independent replay have separate machine-readable reports. Historical milestone notes below are retained rather than rewritten as if the original state had passed.

Updated 2026-09-24. This records checks actually performed against the ECDAT workbench; it is not a claim that the full acceptance suite has passed.

## Preparation

- Read the Computer Use skill and current browser-control documentation.
- Inspected the existing React workbench, evidence graph, restricted-project form, passport downloads and API client.
- First browser connection to `http://127.0.0.1:8000` returned `ERR_CONNECTION_REFUSED` while the backend was being started. No workflow result is inferred from this attempt.

## Pending browser checks

Production build passed (`tsc -b && vite build`, Vite 6.4.3). Output: 284.89 kB JavaScript / 87.34 kB gzip, 25.29 kB CSS / 6.00 kB gzip. This is build validation, not a measured runtime memory result.

Code inspection found that small-screen navigation hides its text. Added explicit accessible names and tooltips to each navigation button so icon-only navigation remains identified for assistive technology.

- Analyst login and discovery records, evidence graph and record inspector.
- Context/scenario evaluation and exact proposal creation.
- Separate reviewer approval; controlled verification and durable job visibility.
- Export and passport presentation/download links (coordinate memory-heavy anchoring with the backend owner).
- Responsive layout, keyboard usability and error presentation.

AI provider calls are being tested separately by the backend owner and are not triggered by this browser run.

## Browser milestone 1: evidence, scenario, proposal

Actual local browser session authenticated as the configured demo analyst against port 8000.

- Payment gateway project `c36985ad-1a96-4929-a5c4-6d09681f43df` loaded 8 located findings, unsupported README coverage, unavailable Syft coverage and a retained declaration/observation contradiction.
- Changed the graph focus to `X25519MLKEM768 · supplier-claim.json`. The graph and equivalent relationship table returned one supporting link. Clicking the table opened the persisted evidence inspector with source path, line, excerpt, scan/job and project IDs.
- Saved intervals X=[8,12], Y=[2,4], Z=[8,15] through the form, then ran assessment. The displayed result was `scenario_dependent`, delta [-5,8] years. Wrong-role alternatives were visibly rejected; unverified runtime/peer support was visibly blocked.
- Created proposal `b20df68b-b1b8-41b8-8658-10449b71596b`. Inspector showed the exact `tls.json` diff from X25519 to X25519MLKEM768, immutable digests, strict fallback=false and eight required checks. Analyst approval/rejection buttons were disabled.
- Observed a backend reference-title encoding defect (`FIPS 203 Â· ML-KEM` and similar) and reported it to the backend owner. UI does not rewrite stored evidence to disguise it.
