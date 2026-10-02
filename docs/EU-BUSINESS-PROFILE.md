# EU Business Privacy Profile — v0.2

BlueberryMe is designed to provide technical controls that can support EU privacy-by-design obligations in agentic systems. It is not a legal compliance certificate and does not determine lawful basis.

## Design mapping

| Privacy objective | BlueberryMe v0.2 mechanism |
|---|---|
| Purpose limitation | Every lease is bound to an explicit purpose. |
| Data minimisation | Allow, tokenize, generalize or deny per data class. |
| Storage limitation | Short-lived leases; removable handle/capability state; explicit destruction. |
| Pseudonymisation | Scoped reversible AES-SIV tokens; re-identification capability stays outside model context. |
| Privacy by design/default | Unknown structured fields suppress by default. |
| Data quality resilience | Invalid/NULL/foreign values degrade field-wise instead of causing unsafe fallback. |
| Controlled re-identification | Exact target + operation + class + active lease required. |
| Secret minimisation | Agent receives capability handle rather than PAT/API key. |
| Accountability | Payload-free evidence counters and decision audit. |
| Technical separation | Purpose/scope/lease binding reduces unintended linkage. |

## Dirty and international datasets

Enterprise datasets often contain:

- `NULL` values;
- malformed emails/phones/dates;
- legacy placeholders;
- mixed locales;
- non-Latin scripts;
- newly introduced columns;
- inconsistent formatting.

The profile therefore separates **privacy safety** from **data quality**.

Data-quality failure should suppress or generalize an affected field where possible. Privacy-control uncertainty must not cause raw values to pass through.

## Legal and organizational controls remain external

Organizations still need to determine controller/processor roles, lawful basis, special-category requirements, DPIA obligations, processor agreements, transfer safeguards, retention rules, data-subject-right procedures, incident response and sector-specific rules.

## Financial-sector hardening beyond v0.2

A production banking/insurance profile should add at least:

- KMS/HSM-backed key management;
- workload identity and strong administrator separation;
- high availability and tested fail-closed recovery;
- immutable/SIEM evidence export;
- signed/versioned policy promotion;
- network bypass prevention;
- transparent MCP/API/DB gateway enforcement;
- re-identification risk analysis for quasi-identifiers;
- red-team/TLPT-style attack scenarios where applicable to the institution's risk/testing regime.
