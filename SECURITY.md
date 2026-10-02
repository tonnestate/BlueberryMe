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

A persistent runtime refuses to start without explicit key material: `BBM_MASTER_KEY_B64`, or `BBM_MASTER_KEY_FILE` pointing to an existing file outside the state directory. A key stored next to `state.db` is accepted only with `BBM_DEV_MODE=1`, because copying the state directory would otherwise disclose both ciphertext and key. For production, integrate an organizational KMS/HSM where available.

The local file provider is a usability/reference mechanism, not an HSM claim.

## Gateway authentication

The HTTP gateway requires an API key per request (`Authorization: Bearer`). The key file (`BBM_API_KEYS_FILE`) stores SHA-256 hashes only, each mapped to a tenant, allowed purposes and optionally one agent. Tenant and agent identity are taken from the key; contradicting body values are denied. Leases and jobs of other tenants (or other agents, for agent-bound keys) are reported as unknown. Without a key file the gateway starts only with `BBM_DEV_MODE=1`.

## Policy floor

The policy loader refuses `ALLOW` for `SECRET` and `IBAN`, including via `default_action`.

## State

The SQLite provider encrypts object payloads before persistence. SQLite is not presented as an HA/DORA-ready distributed store; it is the minimal persistent reference provider.

## Async side effects

BlueberryMe supplies `job_id` as an idempotency key when supported by the target handler. Exactly-once external side effects require the target itself to enforce idempotency.

## Explicit non-goals

See `docs/THREAT-MODEL.md`. In particular, v0.3 does not claim protection against host-root compromise or live trusted-process memory scraping.

## Vulnerability reports

Do not include real personal data, credentials, production handles or source identifiers in public reports.
