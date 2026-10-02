# Enterprise hardening roadmap

v0.2 deliberately stays small. It establishes the privacy semantics before introducing infrastructure scale.

## Next hardening slices

1. Transparent MCP stdio/HTTP proxy enforcement.
2. Database/API gateway adapters with schema policy and read-only first deployment.
3. KMS/HSM key providers and rotation/revocation tests.
4. Signed/versioned policy bundles with controlled promotion.
5. Quasi-identifier risk engine and configurable generalization strategies.
6. HA/failover testing with explicit prohibition of direct raw-data fallback.
7. Immutable evidence export and SIEM integration.
8. Workload identity, operator separation and break-glass controls.
9. Attack suite: prompt injection, token replay, cross-lease linkage, cache leakage, policy outage, key outage and bypass attempts.
10. Performance/effectiveness eval comparing raw-context task quality with privacy-compiled context.

## Acceptance direction

```text
unauthorized direct identifiers reaching model = 0
secrets reaching model                         = 0
unauthorized rehydration                       = 0
cross-lease deterministic linkage              = 0
privacy bypass under component failure         = 0
audit payloads containing protected values     = 0
```

Data-quality defects are measured separately from privacy-control failures.
