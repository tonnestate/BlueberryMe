# Changelog

## 0.4.4 — 2026-10-05

Lightweight boundary-consolidation release.

### Host capability boundary

- Added a declarative host-capability manifest for privileged functions exposed by IDEs,
  SSMS-like hosts, browsers and other parent applications.
- Unmediated sensitive host capabilities are a hard FAIL.
- Structured sensitive surfaces may declare `BBM_STRUCTURED` mediation before agent ingress.
- Added explicit coverage for a `GetGridResults`-style result reader.

### Free-text egress

- Added conservative host free-text modes: `DENY`, opaque
  `BBM_FREE_TEXT_HANDLE`, and explicit `BBM_FREE_TEXT_SCAN`.
- Detector-based scan mode is marked as detector-bounded `AUTHORIZED_DISCLOSURE`,
  never zero-disclosure proof.
- Free-text mediation persists payload-free Privacy Receipts; scan receipts explicitly
  record detector-bounded coverage.
- No new NLP/LLM subsystem was added; the scan path reuses the existing detector.

### Reliability and tests

- Added reveal-budget persistence coverage across runtime restart.
- Added shared-SQLite concurrency coverage for reveal budgets.
- Added privacy-recipe fast-path persistence coverage across runtime restart.
- Added host-boundary and free-text regression tests.
- Added GitHub Actions CI for Python 3.11, 3.12 and 3.13 with compile and full pytest runs.

### Core minimality

- Documented the rule that adapters, providers and policy belong outside the mandatory core
  execution path when they can be expressed independently.
- Privacy compilation remains optional for execution.


## 0.4.3 — 2026-10-05

Hardening release.

### Key custody

- Persistent runtime startup now fails closed unless `BBM_MASTER_KEY_B64` or an existing
  `BBM_MASTER_KEY_FILE` outside the state directory is configured.
- Automatic creation of `master.key` beside the state database is restricted to
  explicit `BBM_DEV_MODE=1`.

### Selective disclosure

- Sensitive `REVEAL` policies reject wildcard agent identities.
- Sensitive `REVEAL` requires `max_reveal_rows_per_lease`.
- Reveal-row budget is reserved atomically and persists across repeated calls on one
  lease; rejected reservations consume no budget.
- The reference `PAYROLL_SUPPORT` policy is bound to `luna-payroll` and one revealed
  row per lease.
- Compiled and non-compiled egress use the same lease-scoped reveal budget.

### Architecture

- Privacy compilation is documented as an optional runtime capability rather than a
  prerequisite for the BBM core path.
- Gateway/package version strings aligned with 0.4.3.

### Tests

- Added regression coverage for production key fail-closed behavior, development-key
  creation, external key-file behavior, wildcard reveal rejection, mandatory reveal
  budget, repeated-call budget exhaustion and agent binding.


## 0.4.2 — 2026-10-05

Privacy-compilation release.

### Compile once

- Added `PrivacyRecipeCompiler` with an escalating classification graph: exact recipe,
  declared schema, structural inference, optional detector and agent suspicion.
- Reusable recipes are keyed by dataset + schema fingerprint + policy version + purpose
  + operation + destination. Hot-path dispatch is one exact encrypted-state lookup; no
  global candidate scan.
- Compiled fields record data class, disclosure action, provenance, evidence and
  contradictions.
- Added provenance states `DECLARED`, `STRUCTURAL`, `DETECTED`,
  `AGENT_SUSPECTED`, `CROSS_CONFIRMED` and `UNKNOWN`.
- Agent hints may tighten protection but cannot widen authority. Agent-only or contradicted
  results stay `CANDIDATE` and are not reusable `PRIMARY` recipes.
- Independent contradictions select the stricter policy result and prevent promotion.

### Compiled egress

- Added `EgressGate.protect_compiled_grid()`.
- Compiled execution re-checks current policy version, purpose, operation, destination,
  authenticated agent, lease scope and row limit.
- Fields that appear after compilation are denied until the surface is recompiled.
- Added exact invalidation for one compiled context.

### Documentation

- Added `docs/PRIVACY-COMPILER.md`.
- Reworked README ordering and presentation around the current architecture and releases.

### Tests

- Added coverage for exact recipe reuse, cross-confirmation, agent-hint non-widening,
  contradiction handling, compiled-grid zero-raw enforcement and context-specific dispatch.


## 0.4.1 — 2026-10-05

Selective-disclosure and egress-evidence release.

### Dataset-context egress

- Added `EgressGate` for structured agent-visible result surfaces.
- Added five disclosure actions: `DENY`, `AGGREGATE`, `HANDLE`, `MASKED`, `REVEAL`.
- Dataset rules can bind purpose, operation, destination, authenticated agent identity,
  lease scope, row count, field patterns and data classes.
- Agent/purpose/scope authority is derived from the active lease; callers cannot widen it
  through request fields.
- Unknown datasets fail closed with `BBM_DATASET_CLASSIFICATION_REQUIRED`.
- Added forced handle emission so dataset policy can be stricter than a generic class ALLOW.
- Secrets cannot be emitted by the selective-disclosure path.

### Privacy receipts

- Added payload-free receipts with `VERIFIED_PROTECTED`,
  `AUTHORIZED_DISCLOSURE`, `BLOCKED` and `UNVERIFIED`.
- Receipts count protected, denied, aggregate-only, masked and raw-release decisions and
  persist in encrypted BBM state without source values or handles.
- An uncontrolled result path may never be represented as protected.

### Reference policy

- Added an `HR.*` example: SQL debugging defaults employee fields to handles, denies
  IBAN/health/bank fields, keeps salary row values aggregate-only and limits bulk rows.
- Added narrowly scoped `PAYROLL_SUPPORT` disclosure for one `EMPLOYEE:*` row.
- `GetGridResults` is used as an integration-specific grid-reader example, not claimed
  as a Microsoft-standard SSMS API.

### Tests

- Added regression coverage for zero-raw employee-grid access, explicit payroll disclosure,
  unknown datasets, unverified paths, row limits, scope denial and payload-free receipts.


## 0.4.0 — 2026-10-05

Major boundary and scale release.

### Execution Boundary

- Added `blueberryme zone-check`: a transport/sandbox-independent conformance probe for credential environment, sensitive host paths, direct source/target reachability, cloud metadata, arbitrary Internet egress and positive BBM-gateway reachability.
- Added `blueberryme run-agent`: a deliberately thin wrapper around Anthropic sandbox-runtime (`srt`). BBM generates the restrictive profile; srt/OS primitives enforce it. Docker, Devcontainers, Kubernetes and VMs remain valid alternative boundaries.
- Generated Python/shell/MCP child processes are treated as untrusted code and must inherit the same Agent Zone. BlueberryMe does not attempt source-code intent analysis.
- Added an explicit IDE boundary: wrapping terminal commands does not sandbox built-in IDE file/search capabilities.

### Data plane

- Added reusable compiled structured-schema plans with a stable policy+schema fingerprint.
- Added bounded compiled-batch protection to keep memory proportional to chunk size.
- Added a small data-plane planner that prefers source-side aggregate pushdown for very large analytical requests that do not require entity references.
- Formalized the scale invariant: BBM state grows with active references/jobs/capsules, not with the source database size.

### Protocol / documentation

- BBM/1 draft moves to 0.4 and adds Execution Boundary and database-scale data-plane requirements without making a particular sandbox or SQL engine part of the protocol.
- Added `docs/EXECUTION-BOUNDARY.md` and `docs/DATA-PLANE.md`.
- Non-bypassability remains a deployment property, but v0.4 now provides a concrete probe for collecting evidence about the tested boundary.

### Tests

- Added unit coverage for restrictive srt profile generation, environment scrubbing, zone-check result semantics, schema compilation and pushdown planning.


## 0.3.1 — 2026-10-04

Hardening release from an end-to-end review. Protocol draft stays BBM/1-draft-0.3; the
spec text gains normative clarifications (§3.1, §6, §8.1, §12, §17).

### License

- **Relicensed from GPL-3.0-only to AGPL-3.0-only.** BlueberryMe runs as a network
  gateway; the AGPL ensures modified versions offered over a network share their source.
  The gateway exposes `GET /source` (configurable via `BBM_SOURCE_URL`).

### Security fixes

- **Intent replay race:** intents were checked for consumption before resolution but
  marked consumed only afterwards, so concurrent requests with one intent could all reach
  the target. Consumption is now atomic and happens before any value is resolved
  (`consume_or_reject`), also across processes sharing a SQLite state file.
- **Async double execution:** two workers could run the same job concurrently. Workers
  now need an expiring atomic claim; jobs of crashed workers are recovered after claim
  expiry; a cancel that arrives during execution discards the result.
- **Unauthenticated gateway:** the HTTP gateway accepted lease creation from anyone. It
  now separates control-plane (`BBM_CONTROL_TOKEN`) and agent-plane credentials
  (`BBM_AGENT_TOKENS`, identity from the token), refuses weak/shared tokens and fails
  closed when unconfigured.
- **Result-lease escalation:** `get_result` created a lease with caller-chosen operations
  and accepted any agent id. Results are now bound to the submitting agent, retrieval is
  atomic single-use, and the new lease is the intersection with the submitting lease.
- **Unsigned call attributes:** the field-to-class map is signed into the intent
  (`fields_hash`); response protection uses the intent's lease, not the call's.
- **Source-adapter exceptions** no longer escape `TargetAdapter.execute`; they map to
  `BBM_SOURCE_UNAVAILABLE`.

### Features

- Lease-local handle linkability (`linkability: LEASE` default, `OCCURRENCE` per class)
  with an HMAC-keyed lookup index that is deleted with the lease.
- Echo guard on sync and async return paths; declared response fields that echo a
  resolved value return the agent's original handle.
- `BlueberryRuntime.protect_response`, `materialize_for_target`, `scrub_echoes`,
  `purge_expired`, `lease_owner`, `lease_operations`.
- `blueberryme gen-token`; `blueberryme serve` warns about missing/insecure auth.
- `blueberryme.api` no longer creates state or reads credentials at import time
  (`create_app()` factory; `blueberryme.api:app` still works for uvicorn).

### Performance

- Lease-owned objects are deleted via an owner index instead of rewriting the full
  handle list into the lease record on every protect (was O(n²) per lease).
- One persistent SQLite connection, batched transactions per call, aggregated audit
  rows per call and decision.
- Reference benchmark (SQLite, 4 fields/record): 51 → ~6,600 records/s at 1,000 records,
  flat at 10,000.

### Compatibility

- v0.3.0 SQLite state files are migrated in place (`owner` column).
- `StateBackend` implementations need `delete_owned`, `consume_once`, `try_claim`,
  `release_claim`, `purge_expired` and `transaction`.
- Same value within a lease now returns the same handle by default (was a fresh handle).
- `AsyncJobGateway.get_result` requires the submitting agent's id.

### Tests

- 85 tests (was 45 with 8 failing): stale v0.2 tests ported, plus concurrency tests for
  replay, job claims and result retrieval, echo guard, linkability, gateway auth and
  storage migration.

## 0.3.0 — 2026-10-02

### Architecture

- Replaced agent-visible reversible ciphertext with random lease-local handles only.
- Added encrypted SOURCE references (pointer path) and encrypted CAPSULE references for values without a source.
- Added origin-to-sink data-flow policy.
- Added signed per-call Resolution Intent and trusted pull-style target resolution.
- Removed the public/general rehydration/decode API from the reference runtime surface.
- Added mandatory success-response re-tokenisation and catalogue-only target error handling.
- Added persistent encrypted state provider (SQLite reference implementation).
- Audit correlation now derives from persistent master key material rather than process-random keys.

### Async

- Added bounded async job pattern: `submit`, `status`, `get_result`, `cancel`.
- Jobs carry references/capsules, not leases; the submission lease can expire/die after submit.
- Added policy check at submit and again at execution.
- Added one-job signed intent, deadline, replay state and target idempotency key.
- Added encrypted result retention and new-lease re-tokenisation on retrieval.
- Added strict `row_version` value-drift detection.
- Added lazy async provider loading: enforce synchronously, enrich asynchronously.

### Data quality

- Unknown fields default to protected `UNKNOWN` handles instead of raw passthrough or whole-request failure.
- Invalid protected values default to handles.
- NULL/empty remain explicit distinct states.
- Raw bytes are supported so invalid UTF-8/legacy payloads can remain byte-exact behind the boundary.

### Security

- Fixed error surfaces so `ValueError`/target exception text is never sent back to clients.
- Added persistent consumed-intent state.
- Added documentation for mediated stdio environment/network/filesystem controls.
- Added explicit round-trip laundering and response-path requirements.
- Added async revocation, replay, drift and result-retention semantics.

### Tests

- 34 reference tests covering handles, source immutability, value drift, response re-tokenisation, safe errors, capabilities, async jobs, persistence, data quality and lazy async loading.

## 0.2.0 — 2026-10-02

Safe-degradation policy, short handles, structured rehydration guard, encrypted capability state and transport-neutral proxy core.

## 0.1.0 — 2026-10-02

Initial BBM/1 proof of concept.
