# Security Policy and Threat Model

## Security objective

BlueberryMe aims to prevent AI agents from receiving direct identifiers, credentials or other values that are not required for their authorized task.

## v0.2 security boundary

Trusted boundary:

- BlueberryMe runtime;
- source systems intentionally placed behind it;
- configured policy;
- lease key material.

Untrusted for direct identity/secrets:

- LLM/model;
- external agent harness;
- model-generated text;
- model-selected tool arguments until validated.

## v0.2 hardening

### Structured rehydration

BlueberryMe does not perform find/replace de-tokenization in arbitrary model text. Rehydration accepts only a complete BBM reference in a declared structured field and checks target, operation, expected class, lease and class policy.

### Safe data-quality degradation

Malformed source data does not trigger a raw-data fallback. Default behavior suppresses malformed protected values and unknown fields.

### Short-handle storage

LLM-friendly short handles map to authenticated encrypted tokens, not plaintext identities.

### Capability storage

Capability secrets are stored as authenticated ciphertext under the active lease key, not as plaintext runtime dictionary values.

### Lease destruction

Lease destruction removes handle and capability state and overwrites the active Python `bytearray` key before dropping references.

This is not a guarantee that every historical copy of key/plaintext bytes has been physically overwritten in a managed runtime.

## Explicit non-goals in v0.2

v0.2 does not claim protection against:

- root/administrator compromise of the BlueberryMe host;
- live process-memory scraping;
- hardware/side-channel attacks;
- complete quasi-identifier detection in arbitrary free text;
- deliberate out-of-band raw database/API paths;
- compromised source systems;
- a transparent production MCP transport proxy (the v0.2 proxy core is transport-neutral).

## Fail-open prohibition

A privacy-control failure must never cause BlueberryMe to return the original protected value as a convenience fallback.

Source-data quality and privacy-control integrity are separate failure domains.

## Reporting

Do not include real personal data, credentials or production tokens in public vulnerability reports or issue examples.
