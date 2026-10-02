# EU Business Privacy Profile — v0.1

BlueberryMe is designed to provide technical controls that can support EU privacy obligations in agentic systems. It does not determine the lawful basis for processing and it does not certify GDPR compliance.

## Design mapping

| Privacy objective | BlueberryMe v0.1 mechanism |
|---|---|
| Purpose limitation | Every lease is bound to an explicit purpose. |
| Data minimisation | Per-data-class transformation: allow, tokenize, generalize, deny. |
| Storage limitation | Short-lived leases; volatile lease keys and capabilities; explicit destruction. |
| Pseudonymisation | Scoped reversible AES-SIV tokens; additional information/key remains outside the agent context. |
| Privacy by design/default | Strict structured-data mode defaults unknown fields to deny. |
| Access control | Rehydration requires active lease + target allow-list + data-class policy. |
| Accountability | Payload-free decision audit. |
| Technical separation | Scope/purpose binding prevents intentional cross-lease token linkage. |

## Legal/organizational controls remain external

An organization still needs to determine, among other things, controller/processor roles, lawful basis, special-category processing requirements, DPIA obligations, processor agreements, international transfer safeguards, retention periods, data subject rights procedures, incident response, and whether a particular data attribute is required for the task.

## High-sensitivity profiles

For insurance, social-security, healthcare, banking, HR, and similar uses, a production deployment should add explicit schema classification, KMS/HSM-backed keys, process/network isolation, signed policy, approved purpose catalogs, provider contractual controls, and documented bypass prevention.
