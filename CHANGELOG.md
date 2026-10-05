# Changelog

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
