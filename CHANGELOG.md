# Changelog

## 0.3.0 — 2026-10-02

### Hardening before release

- **Gateway authentication.** Per-tenant API keys (`BBM_API_KEYS_FILE`, hashed), optional agent binding, tenant/agent identity from the key instead of the request body, lease and job ownership checks. `blueberryme api-key` generates keys. Unauthenticated mode only with `BBM_DEV_MODE=1`.
- **Master key placement.** No implicit `master.key` next to `state.db` outside dev mode; `BBM_MASTER_KEY_FILE` must exist outside the state directory. `blueberryme keygen` creates a 0600 key file. **Upgrade:** move an existing `.blueberryme/master.key` out of the state directory and set `BBM_MASTER_KEY_FILE`.
- **Atomic job state.** State backends gain `compare_and_put`; job claim, completion, cancellation and retrieval use conditional writes. Two workers can no longer execute the same job; a crashed worker's claim expires (`run_lease_seconds`) and the job is taken over; a result is retrieved exactly once.
- **Policy floor.** `ALLOW` is refused for `SECRET` and `IBAN`, including through `default_action`.
- **Tests.** Runtime and proxy tests migrated to the v0.3 API; new tests for concurrency, keys, gateway auth and policy floor.

Custom `StateBackend` implementations must add `compare_and_put(kind, object_id, payload, expected, expires_at=None) -> bool`.

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
