# Changelog

## 0.2.0 — 2026-10-02

### Added

- BBM/1 draft 0.2 policy semantics.
- Safe-degradation policy for `NULL`, empty, malformed and transformation-failure states.
- Explicit policy inheritance with `extends`.
- International/Unicode-safe handling for names and addresses.
- Explicit non-guessing birth-date formats controlled by policy.
- Short `LEASE_HANDLE` representation backed only by authenticated encrypted tokens.
- Structured rehydration requiring exact target, operation and data class.
- `StructuredToolGuard` transport-neutral proxy core.
- Rejection of BBM references embedded in free-form passthrough fields.
- Batch protection with structural quarantine rather than whole-batch failure.
- Encrypted capability state for secrets/PATs.
- Payload-free evidence counters.
- Standard safe error codes.

### Changed

- Default enterprise behavior is now: **Never fail open. Degrade safely.**
- Unknown structured fields are suppressed rather than aborting otherwise safe records.
- Rehydration is no longer exposed as unconstrained token-to-string substitution.
- Demo now includes dirty and international data.

### Security

- Rehydration Prompt Injection surface reduced by typed whole-field resolution.
- Short handles are lease-scoped and disappear with lease destruction.
- Capability store no longer keeps plaintext secrets.

## 0.1.0 — 2026-10-02

Initial BBM/1 reference runtime with AES-SIV pseudonymisation, privacy leases, capabilities, policy-based transformations, payload-free audit and optional API/MCP adapters.
