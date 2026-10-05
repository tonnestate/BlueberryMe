# EU Business Privacy Profile

This profile is a technical design baseline, not a legal certification.

BlueberryMe can support programs built around:

- purpose limitation through purpose-bound leases and jobs;
- data minimisation by replacing unneeded identifiers/secrets with references;
- storage limitation through lease/job/result TTL and cleanup;
- pseudonymisation/reference abstraction;
- privacy by design/default through pre-model enforcement;
- controlled re-identification at a trusted target boundary;
- accountability through payload-free audit and evidence;
- resilience through explicit fail-closed infrastructure behavior.

## Source immutability

The business source of truth is not rewritten. BlueberryMe creates a temporary protected view and trusted references to the original.

## Data quality

EU enterprise/legacy data is not assumed to be clean or German-only. The profile treats NULL, empty, malformed and international data as normal data-quality states rather than as a reason to expose raw values or stop an entire batch.

## Key custody

For persistent deployments, the reference profile expects master-key material to be configured outside the state directory. Local `master.key` generation is a development-only convenience gated by `BBM_DEV_MODE=1`.

## Organizational responsibilities remain

BlueberryMe does not determine:

- lawful basis;
- controller/processor roles;
- DPIA necessity/outcome;
- international transfer requirements;
- statutory retention periods;
- data-subject-right workflows;
- sector-specific legal permission to process a particular dataset;
- DORA criticality classification or outsourcing obligations.

Those remain governance/legal responsibilities of the deploying organization.
