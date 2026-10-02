# Security policy

## Trust boundary

BlueberryMe treats AI models, agent harnesses, MCP clients, and external tool consumers as untrusted unless an explicit policy grants a narrowly scoped capability.

## v0.1 security invariants

1. Raw secrets must never be returned to the model-facing interface.
2. Reversible identity tokens require an active, unexpired lease.
3. Rehydration is denied if target, purpose, scope, data class, or lease state do not match policy.
4. Lease keys exist only in volatile process memory in the reference runtime.
5. Destroying a lease removes its key and capabilities from the runtime.
6. Audit events must not contain raw protected values, resolved values, ciphertext tokens, or secrets.
7. Unknown structured fields fail closed when strict mode is enabled.
8. Logging of request/response payloads must remain disabled at the privacy boundary.

## Known v0.1 limitations

- Process memory is a trusted boundary. A privileged host compromise can read in-memory values.
- Multi-node lease/key coordination is not implemented.
- The built-in free-text detector cannot guarantee complete PII detection.
- Quasi-identifier and inference-risk analysis is not yet automated.
- Database proxy enforcement is not yet implemented; callers must route data through the runtime.
- Secure hardware/KMS/HSM integration is not yet implemented.
- Cryptographic erasure is best-effort in managed-language process memory; destruction means removal of the usable runtime key/reference, not a guarantee that every historical RAM copy has been physically overwritten.

## Production direction

Production profiles should use hardened process isolation, KMS/HSM-backed key lifecycle, network egress controls, signed policy, tenant isolation, non-payload observability, and an enforced gateway so agents cannot bypass BlueberryMe.
