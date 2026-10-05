# BBM/1 — Agent Privacy Protocol

Status: **experimental draft 0.4** (reference implementation 0.4.3).

## 1. Objective

BBM/1 defines a vendor-neutral contract for keeping identity, secrets and resolution authority out of an AI agent path whenever the task does not require them.

Normative principle:

> The agent carries references, never values. Authority to resolve them is minted per call, outside the agent, and bound to one target and one operation.

## 2. Trust zones

BBM/1 distinguishes:

1. **Source zone** — authoritative business data; never rewritten by BBM.
2. **Privacy boundary** — policy, handles, references/capsules, evidence.
3. **Agent zone** — untrusted for direct identity, credentials and general decode authority.
4. **Target zone** — trusted adapter that may resolve only under a valid Resolution Intent.

## 3. Agent representation

An agent-visible sensitive reference MUST be random and opaque:

```text
BBM1H.<DATA_CLASS>.<RANDOM>
```

Credentials use:

```text
BBM1C.<RANDOM>
```

The agent-visible reference MUST NOT contain source plaintext or reversible ciphertext.

### 3.1 Linkability

The random part of a handle MUST NOT be derived from the value. Whether two occurrences
share a handle is a policy decision per data class:

- `LEASE` (default): inside one lease, the same value (CAPSULE) or the same source
  pointer (SOURCE) yields the same handle. The agent can reason about "the same
  customer" across records and tool calls. Different leases MUST remain unlinkable.
  Two source records holding an equal value remain two handles: the pointer, not the
  value, is the identity.
- `OCCURRENCE`: every occurrence yields a fresh handle.

An implementation that offers `LEASE` linkability needs a lookup index. That index MUST
be keyed (e.g. HMAC under a dedicated key), scoped to the lease and deleted with it.

## 4. Reference store

A handle resolves inside the privacy boundary to one of:

### SOURCE

```text
source_id
record_key
field
row_version (optional but recommended)
```

### CAPSULE

Encrypted byte/string/structured data that has no stable source, such as user input or a transient external value.

### CAPABILITY

Encrypted secret material plus a fixed target and operation.

The Reference Store is real state. Implementations MUST NOT market it as "no mapping/state". The design goal is **no plaintext identity mapping** and no duplicate shadow source database.

## 5. Leases

A lease binds at least:

```text
tenant
agent
purpose
scope
expiry
allowed target operations
```

Handles are lease-local. Possession of a handle alone grants no resolution authority.

## 6. Resolution Intent

The gateway validates a structured call and mints a signed, short-lived Resolution Intent containing at least:

```text
intent_id
call_id
lease_id
target
operation
purpose
handles
hash(arguments)
policy_version
expiry
```

The intent MUST also bind the declared field-to-data-class map (which fields are
references, which are capabilities). Unsigned call attributes MUST NOT influence
resolution or the lease under which a response is protected.

A conformant target adapter MUST validate audience, operation, payload binding, field
map, expiry, replay state and current policy before resolving.

Consumption is the commit point: an implementation MUST atomically mark the intent as
consumed (first writer wins, across all processes sharing the replay store) **before**
resolving any value. A "check consumed, resolve, then mark" sequence is not conformant
because concurrent requests with one intent could all reach the target.

There is no general model-accessible `decode(handle)` operation.

## 7. Pull resolution

Resolution occurs in the trusted target path. The agent submits handles. A trusted target adapter pulls the corresponding source value/capsule only after validating the per-call intent.

Resolution MUST occur into typed/parameterized fields. Implementations MUST NOT interpolate rehydrated values into arbitrary strings, URLs, SQL or templates.

## 8. Mandatory return path

Every model-visible target success response MUST cross the privacy boundary again. Sensitive response fields become new handles.

Target errors MUST use fixed catalogue codes. Raw exception strings are forbidden on the agent path.

This requirement prevents round-trip laundering:

```text
agent -> target rehydrates -> target stores plaintext -> agent reads target back
```

The read response must be re-tokenised.

### 8.1 Echo guard

Field classification alone does not stop a target from echoing a resolved value inside
an allowed free-text field (`"Letter sent to Max Mustermann"`). Because the trusted path
knows exactly which values it resolved for this call, an implementation SHOULD replace
every occurrence of those values anywhere in the response (values, nested structures,
mapping keys) with the handle the agent already holds, and resolved secrets with a
removal marker. Very short values SHOULD only be replaced as complete leaves.

The echo guard is a deterministic second line; it does not replace a correct response
schema and does not detect transformed or partial echoes.

## 9. Data-flow policy

BBM/1 policy is not only field policy. It includes origin-to-sink permission:

```text
origin_scope × purpose × target × operation
```

An injected instruction cannot authorize a sink that the deterministic data-flow policy denies.

## 10. Data quality and failure classes

BBM/1 separates four failure classes:

### DATA_QUALITY
NULL, empty, malformed syntax, unknown legacy fields. Default: increase protection and continue the safe item/batch where possible.

### INFRASTRUCTURE
State/KMS/policy infrastructure unavailable. Default: closed; never raw passthrough.

### REHYDRATION
Value drift, expired/invalid intent, missing source. Default: isolate the call/item.

### POLICY
Unauthorized target/operation/scope. Default: deny with a fixed error code.

Normative rule:

> Never fail open. Degrade safely.

## 11. Byte/value exactness

BBM must not modify the source of truth. Capsules support raw bytes so invalid UTF-8 and legacy encodings can be preserved without normalization.

Lossy generalisation is not a core source transformation. A deployment may generate an optional derived agent view, but that MUST NOT replace or rewrite the authoritative value.

## 12. Async single jobs

A bounded async job carries references/capsules, **not the original lease**.

Submission:

```text
lease handles -> policy check #1 -> encrypted job envelope -> signed Job Intent
```

Execution:

```text
policy check #2 -> value-drift check -> target operation -> encrypted result
```

Retrieval:

```text
encrypted result -> new lease -> model-visible re-tokenised response
```

The initial lease may expire immediately after submission.

A Job Intent MUST be bound to one job, target, operation, purpose, envelope hash and deadline. the reference implementation caps the reference deadline at 24 hours.

A worker MUST win an atomic, expiring claim before executing a job; a crashed worker's
claim expires and the job may be retried with the same idempotency key.

Result retrieval MUST be bound to the submitting tenant, purpose and agent, and MUST be
single-use atomically. The fresh result lease MUST NOT grant target operations the
submitting lease did not have.

## 13. Idempotency

`job_id` is the target idempotency key. The BBM runtime prevents a completed job from being re-executed by its own worker path. Exactly-once semantics for external side effects still require the target to implement idempotency.

## 14. Value drift

A SOURCE reference SHOULD capture a source version/ETag. Default behavior on mismatch is failure (`BBM_VALUE_DRIFT`). A future policy may allow operation-specific drift, but v0.3 is strict.

## 15. Audit

Normal audit MUST NOT contain:

```text
raw values
resolved values
ciphertext
tokens/handles
secrets
payloads
```

Audit subject references are derived with a tenant + purpose + retention-epoch scoped HMAC key derived from persistent master key material. The master key must not be regenerated on every process start in a persistent deployment.

## 16. Async enrichment

Optional expensive providers may be lazy-loaded only after the synchronous privacy decision. They receive protected payloads only.

> Enforce synchronously, enrich asynchronously.

## 17. Control plane and agent plane

Lease creation is the authority root. A gateway MUST authenticate two distinct planes:

- **control plane** (trusted orchestrator): leases, ingress protection, capabilities,
  evidence;
- **agent plane** (untrusted): job submission, status, cancel, result retrieval.

An agent credential MUST NOT be able to create or widen a lease. The agent identity MUST
come from the authenticated credential, not from a request field. An unconfigured
gateway MUST fail closed.

## 18. Transport bindings

BBM/1 is transport-independent. MCP is the first reference binding. Direct function calling, HTTP tools and A2A can implement the same semantics.


## 19. Execution Boundary

Non-bypassability is a deployment property. A conformant high-safety Agent Zone MUST NOT provide direct source credentials, direct Resolve/KMS credentials or an unmediated route to trusted targets.

Generated code is not a privileged exception. Python, shell, local MCP children and other child processes MUST inherit the same effective boundary as the agent that created them.

BBM/1 does not mandate a sandbox product. An implementation MAY use OS sandboxing, containers, Devcontainers, Kubernetes, VMs or equivalent controls. A reference conformance probe MAY test observable environment, filesystem and network bypass paths.

If an agent process calls an LLM provider directly, that provider is an explicit egress exception. A stronger deployment proxies model traffic through the BBM gateway as well.

## 20. Database-scale data plane

BBM/1 SHOULD scale with active agent interactions, not source-database cardinality.

For structured data, classification SHOULD be schema/registry driven and MAY be compiled once per policy/schema version. Implementations SHOULD process row-level protection in bounded batches.

For large analytical requests that do not require entity-level references, implementations SHOULD prefer source-side filtering, joins and aggregation so that only the minimal privacy-safe result crosses the Agent Boundary.

BBM/1 does not define SQL generation or replace the source analytics engine. Query authorization and output protection remain mandatory regardless of where computation executes.


## 21. Purpose-bound selective disclosure

A conformant implementation MAY expose raw or derived business data to an agent only through an explicit
egress decision. Technical readability does not imply disclosure authority.

For structured result surfaces, policy SHOULD be able to bind at least:

```text
dataset × purpose × operation × destination × agent × lease scope × field/data class
```

A dataset-context egress decision MAY produce:

- `DENY` — no value crosses the Agent Boundary;
- `AGGREGATE` — row-level value remains behind the boundary;
- `HANDLE` — opaque lease-local reference;
- `MASKED` — explicitly authorized partial value;
- `REVEAL` — explicitly authorized raw value.

`SECRET` values MUST NOT be exposed through `MASKED` or `REVEAL`; they remain capability-bound.

The authenticated lease MUST be the authority source for agent identity, purpose and scope. An untrusted
caller MUST NOT widen disclosure by supplying those attributes in the egress request.

Unknown/unclassified datasets SHOULD fail closed until classified.

### 21.1 Privacy receipt

Each mediated egress decision SHOULD emit payload-free evidence with one of:

- `VERIFIED_PROTECTED` — BBM mediated the path and emitted no raw/masked values;
- `AUTHORIZED_DISCLOSURE` — policy explicitly permitted raw or masked disclosure;
- `BLOCKED` — the mediated path was denied;
- `UNVERIFIED` — BBM could not establish that the relevant path was mediated.

`UNVERIFIED` MUST NOT be represented as protected.

A receipt MUST NOT contain source values, handles, secrets, ciphertext or resolved payloads.

### 21.2 Grid and IDE result surfaces

A grid/result reader is conformant only when result mediation occurs before raw values become agent input.
Post-hoc masking after an agent/harness has already received plaintext does not satisfy the egress boundary.

Host-specific tools may bind to this contract, but BBM/1 does not standardize a particular SSMS, IDE or
grid-reader function name.

### 21.3 Reveal budgets and concrete principals

Raw `REVEAL` is a privileged disclosure action, not the default representation.

For sensitive classes, a reference policy SHOULD bind `REVEAL` to concrete agent identities rather than wildcard principals. Implementations SHOULD reject policies that combine sensitive `REVEAL` with unconstrained agent wildcards.

A per-call row limit is insufficient by itself because repeated calls can accumulate disclosure. A conformant high-safety profile SHOULD also enforce a lease-scoped cumulative reveal budget. Budget reservation MUST occur before model-visible release and SHOULD be atomic across workers sharing the same state backend.

A rejected budget reservation MUST NOT release the candidate payload and SHOULD NOT consume budget.


## 22. Privacy compilation

A conformant implementation MAY compile a previously established structured-data privacy decision into a
reusable recipe to avoid repeating expensive classification on every row.

A reusable recipe MUST be bound at least to:

```text
dataset
schema fingerprint
policy version
purpose
operation
destination
```

Changing any of these inputs MUST prevent reuse of the old recipe.

A compiled recipe SHOULD record field classification, disclosure action, provenance and contradictions.
Agent/model-supplied classification MAY increase protection but MUST NOT widen disclosure authority by itself.

Independent contradictory evidence MUST NOT silently promote a recipe to the reusable fast path. A safe
implementation SHOULD choose the stricter applicable disclosure result until the contradiction is resolved.

Hot-path execution MUST continue to enforce current lease and dataset constraints. Compilation is an
optimization of classification/decision reuse, not a bypass around authorization.

Fields absent from the compiled surface MUST fail closed until the surface is recompiled or an explicit
policy handles the change.

Implementations SHOULD use exact-context recipe dispatch rather than scanning a global recipe corpus.


## 23. Persistent key custody

Persistent encrypted state is only as strong as its master-key custody.

A production/default deployment MUST NOT silently create its persistent master key beside the state database. Key material SHOULD come from an external secret manager, KMS/HSM integration, injected environment secret, or an existing key file outside the state directory.

A reference implementation MAY create a local key beside the state database only under an explicit development-mode switch. Without configured persistent key material, production startup MUST fail closed.
