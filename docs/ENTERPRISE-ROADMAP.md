# Enterprise roadmap

v0.3 intentionally keeps the mandatory core small.

## Core now

- BBM/1 policy + data-flow semantics;
- random handles;
- encrypted pointer/capsule store;
- signed per-call intents;
- target-bound pull resolution;
- mandatory response/error protection;
- bounded async jobs;
- encrypted persistent SQLite reference store;
- payload-free persistent audit;
- lazy async optional providers.

## Provider-grade additions later

These should be adapters/providers, not hard dependencies of BBM/1:

- KMS/HSM master-key provider;
- HA/distributed state and queue provider;
- OPA/Cedar policy provider;
- SPIFFE/SPIRE workload identity;
- WORM/SIEM evidence sinks;
- Kubernetes/network policy packages;
- remote MCP proxy and mediated stdio broker implementations;
- Presidio/deeper free-text classifiers;
- RAG/embedding privacy path;
- quasi-identifier risk analysis and optional derived views;
- target conformance suite and canary leak monitor.

## Rule

> Load the minimum privacy machinery required to enforce the policy.

Enterprise hardening must not turn the default developer path into a mandatory infrastructure stack.
