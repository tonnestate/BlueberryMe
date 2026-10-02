# Security Policy and Threat Model

## Security objective

BlueberryMe aims to keep identity, credentials and general resolution authority outside AI agent/model context when the authorized task does not require them.

## v0.3 boundary

Trusted:

- BlueberryMe gateway/runtime state;
- source adapters;
- configured deterministic policy;
- master key/KMS integration;
- registered trusted target adapters.

Untrusted for direct identity/secrets:

- model/agent;
- model-generated text;
- model-selected tool arguments until validated;
- external target output until re-protected.

## Security-critical rules

1. Agent-visible sensitive references are random handles only.
2. There is no public general-purpose resolve/decode endpoint.
3. Resolution requires a signed per-call intent, target, operation, current policy and structured field schema.
4. Target success responses are re-tokenised before model return.
5. Target exception text is never returned to the agent.
6. Dirty data never causes raw-data fallback.
7. Infrastructure failure is fail-closed.
8. Source data is never rewritten by BlueberryMe.
9. Async execution checks policy both at submit and execution time.
10. SOURCE references enforce `row_version` by default.

## Key material

The HTTP reference gateway persists a local 32-byte master key by default so restart does not destroy audit correlation or encrypted job state. For production, inject approved key material (`BBM_MASTER_KEY_B64`) or integrate an organizational KMS/HSM.

The local file provider is a usability/reference mechanism, not an HSM claim.

## State

The SQLite provider encrypts object payloads before persistence. SQLite is not presented as an HA/DORA-ready distributed store; it is the minimal persistent reference provider.

## Async side effects

BlueberryMe supplies `job_id` as an idempotency key when supported by the target handler. Exactly-once external side effects require the target itself to enforce idempotency.

## Explicit non-goals

See `docs/THREAT-MODEL.md`. In particular, v0.3 does not claim protection against host-root compromise or live trusted-process memory scraping.

## Vulnerability reports

Do not include real personal data, credentials, production handles or source identifiers in public reports.
