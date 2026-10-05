# Selective Disclosure and Egress Receipts — v0.4.3

BlueberryMe v0.4.1 adds a dataset-context egress gate for structured result surfaces.

The objective is not "never disclose anything". It is:

> Disclose only what the active purpose, dataset, scope, operation and destination explicitly authorize, and record every raw disclosure as an `AUTHORIZED_DISCLOSURE` receipt.

A technically readable field is not automatically an authorized disclosure.

## Disclosure actions

Dataset-context policy can choose, per field or data class:

- `DENY` — the value does not cross the Agent Boundary.
- `AGGREGATE` — the row-level value does not cross; aggregate computation must remain behind the boundary.
- `HANDLE` — the agent receives a lease-local opaque BBM handle.
- `MASKED` — an explicitly authorized partial view is emitted.
- `REVEAL` — raw value disclosure is explicitly authorized.

`SECRET` is never emitted through `REVEAL` or `MASKED`; secret use belongs to capability-bound target operations.

## Dataset context

A dataset rule can bind disclosure to:

```text
dataset
x purpose
x operation
x destination
x agent identity
x lease scope
x row limit
x field/data class
```

The agent, purpose and scope are derived from the active BBM lease. They are not accepted as caller-provided authority fields.

An unregistered dataset is fail-closed with `BBM_DATASET_CLASSIFICATION_REQUIRED`.

## Reveal hardening

Raw `REVEAL` is an explicit exception to the default protected path.

For sensitive `REVEAL`, the reference policy loader requires:

- concrete agent ids (wildcard agent identities are rejected);
- a positive `max_reveal_rows_per_lease` budget;
- an otherwise valid purpose, operation, destination and lease scope.

`max_rows` limits one call. `max_reveal_rows_per_lease` limits cumulative raw-disclosure rows across repeated calls on the same lease. The reservation is atomic in the reference state backend, and a rejected reservation does not consume budget.

The reference `PAYROLL_SUPPORT` example is intentionally bound to `luna-payroll` and one revealed row per lease.

## Privacy Receipt

Every gate decision produces a payload-free receipt with one of four states:

- `VERIFIED_PROTECTED` — BBM observed the path and released no raw or masked values.
- `AUTHORIZED_DISCLOSURE` — the policy explicitly allowed raw or masked data to cross.
- `BLOCKED` — BBM controlled the path but denied the release.
- `UNVERIFIED` — BBM cannot attest that the path was mediated and therefore makes no protection claim.

Receipts contain counts, classes and decision metadata, never row values, handles or ciphertext.

The receipt reports what crossed **the BBM egress gate**. It must not claim that a downstream provider stored nothing unless BBM also controls and verifies that downstream transport/storage property.

## SSMS / grid-reader example

A local SSMS integration may expose a grid-reading tool such as the integration-specific `GetGridResults`.
BlueberryMe does not assume this is a Microsoft-standard API. The relevant security property is whether raw
grid values can reach the agent before BBM mediation.

A conformant integration is:

```text
SQL Server
  -> result grid/resultset
  -> BBM EgressGate
  -> protected/authorized view
  -> agent grid-reading tool
  -> model
```

Not:

```text
SQL Server
  -> raw grid
  -> agent grid-reading tool
  -> BBM afterwards
```

If the host integration cannot intercept the result before agent ingress, the path is `UNVERIFIED` and
must not be represented as protected.

## Reference HR policy

The EU business example contains an `HR.*` dataset rule.

For `SQL_DEBUGGING`:

- employee fields default to `HANDLE`;
- IBAN/health/bank fields are denied;
- salary-like fields are aggregate-only;
- bulk access is capped;
- raw employee values do not cross the gate.

For `PAYROLL_SUPPORT`:

- only an `EMPLOYEE:*` scoped lease is accepted;
- only the concrete `luna-payroll` agent is accepted;
- at most one employee row may be revealed across the entire lease;
- PERSON/IBAN/public fields and salary-like fields may be explicitly revealed;
- health data and secrets remain denied.

This is an example policy, not a universal HR policy.

## Acceptance gates

A structured grid integration should test at least:

1. raw sensitive values never enter the agent payload before the gate;
2. unknown datasets are blocked, not silently allowed;
3. wrong purpose, destination, operation, agent or lease scope is blocked;
4. bulk row limits are enforced before disclosure;
5. a zero-raw flow produces `VERIFIED_PROTECTED`;
6. an explicit raw disclosure produces `AUTHORIZED_DISCLOSURE`;
7. an uncontrolled/bypassed path produces `UNVERIFIED`;
8. receipts contain no source values, handles, secrets or ciphertext.
