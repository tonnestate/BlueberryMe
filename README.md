<p align="center">
  <img src="docs/assets/blueberryme-header.png" alt="BlueberryMe" width="100%" />
</p>

# BlueberryMe

**Open Agent Privacy Protocol & Sensitive Data Bypass Runtime.**

BlueberryMe keeps identity, secrets and raw sensitive values out of AI-agent context unless an explicitly authorized, policy-bound disclosure is permitted and recorded by a Privacy Receipt.

> **The agent carries references, never values. Authority to resolve them is minted per call, outside the agent, and bound to one target and one operation.**

BlueberryMe v0.4.4 is an experimental reference implementation of **BBM/1**. It provides technical controls that can support privacy-by-design and data-minimisation programs. It is **not** a legal compliance certificate.

## Current architecture

BlueberryMe combines four enforcement layers:

1. **Privacy View** — sensitive source values become opaque lease-local handles.
2. **Data-Flow Policy** — origin, purpose, sink and operation determine whether a flow is allowed.
3. **Resolution Boundary** — plaintext can exist only in a trusted target path under a signed per-call Resolution Intent.
4. **Execution Boundary** — generated code, shell commands and local tools must not have an alternate path around BBM.

v0.4.1 added **purpose-bound selective disclosure** at the structured-data egress boundary. v0.4.2 added **privacy compilation** so repeated classification does not scale with database cardinality. v0.4.3 hardened key custody and raw-disclosure authority. v0.4.4 consolidates the host boundary, free-text handling and repeatable CI without adding a new platform layer.

## v0.4.4 — Boundary consolidation

v0.4.4 closes the remaining core-boundary gaps while keeping BlueberryMe small.

- **Host Capability Boundary.** Agent-visible host functions such as grid readers, IDE file/search APIs, clipboard readers or browser extractors must be denied or mediated before agent ingress.
- **SSMS-style grid readers.** A raw `GetGridResults`-like capability is explicitly non-conformant unless its result is routed through BBM first.
- **Conservative free text.** High-assurance mode is `DENY`; whole text may instead cross as an opaque handle. Detector-based scan mode is available only as bounded assurance and is never reported as zero-disclosure proof.
- **Restart/concurrency coverage.** Reveal budgets and compiled privacy recipes are exercised across persistent-runtime restarts, and reveal budgets are tested under shared-state concurrency.
- **Repeatable CI.** GitHub Actions runs compile checks and the full pytest suite on Python 3.11, 3.12 and 3.13.

Design rule:

> **No feature enters BBM Core if it can be expressed as an adapter, provider or policy.**

The Privacy Compiler, Presidio, sandbox-runtime and host integrations remain optional capabilities around the stable core.

See [Host Capability Boundary](docs/HOST-CAPABILITY-BOUNDARY.md).

## v0.4.3 — Hardening

v0.4.3 tightens production defaults without adding another subsystem.

- **Persistent keys fail closed.** Persistent state now requires `BBM_MASTER_KEY_B64` or an existing `BBM_MASTER_KEY_FILE` outside the state directory. Creating `master.key` beside the state database is permitted only with `BBM_DEV_MODE=1`.
- **Sensitive `REVEAL` needs a concrete agent.** Wildcard agent identities are rejected when a policy can reveal sensitive values.
- **Sensitive `REVEAL` needs a lease budget.** `max_reveal_rows_per_lease` prevents repeated one-row calls from bypassing `max_rows`.
- **Reference payroll policy is narrow.** The example allows disclosure only to the concrete `luna-payroll` agent and one revealed row per lease.
- **Compiler remains optional in the execution path.** Handles, leases, intents, jobs and selective disclosure work without invoking the Privacy Compiler.

Core invariant:

> **No plaintext reaches the agent without an explicitly authorized, bounded and receipted disclosure.**

## v0.4.2 — Compile once, enforce many

The optional `PrivacyRecipeCompiler` capability uses an escalating graph:

```text
compiled recipe
      | hit
      +-----------------------------> enforce
      | miss
      v
declared schema/catalog
      v
structural inference
      v
optional detector
      v
agent suspicion
      v
cross-confirm / contradiction
      v
compile recipe
```

A reusable recipe is bound to:

```text
dataset
+ schema fingerprint
+ policy version
+ purpose
+ operation
+ destination
```

The hot path uses one exact encrypted-state lookup. There is **no global candidate scan**.

Compiled fields carry their data class, disclosure action, evidence and provenance:

```text
DECLARED
STRUCTURAL
DETECTED
AGENT_SUSPECTED
CROSS_CONFIRMED
UNKNOWN
```

Agent hints are evidence only. They can tighten protection but cannot widen disclosure authority. Contradicted or agent-only decisions remain `CANDIDATE` recipes and are not promoted to the reusable `PRIMARY` path.

`EgressGate.protect_compiled_grid()` applies compiled decisions directly and still re-checks active lease purpose, operation, destination, authenticated agent, lease scope, row limit and current policy version. Fields that appear after compilation are denied until recompiled.

See [Privacy Compilation](docs/PRIVACY-COMPILER.md).

## v0.4.1 — Selective disclosure

Structured result surfaces can decide per dataset, purpose, operation, destination, agent, scope, field and data class whether to:

```text
DENY
AGGREGATE
HANDLE
MASKED
REVEAL
```

Every mediated decision creates a payload-free Privacy Receipt:

```text
VERIFIED_PROTECTED
AUTHORIZED_DISCLOSURE
BLOCKED
UNVERIFIED
```

Unknown datasets fail closed. A grid-reader integration is conformant only when BBM mediates the result **before** raw values become agent input.

See [Selective Disclosure](docs/SELECTIVE-DISCLOSURE.md).

## v0.4.0 — Execution boundary and database scale

- `blueberryme zone-check` probes obvious credential, filesystem and network bypass paths.
- `blueberryme run-agent` is a thin reference wrapper around Anthropic sandbox-runtime (`srt`).
- Docker, Devcontainers, Kubernetes, VMs or enterprise endpoint controls can satisfy the same boundary contract.
- Structured schemas can be compiled and processed in bounded batches.
- Large analytical workloads should use source-side filter/join/aggregate pushdown.

Design rule:

> **Enforce synchronously, enrich asynchronously; push computation to the data; keep generated code inside the same constrained Agent Zone.**

## Core data path

```text
                         SOURCE OF TRUTH
                         (never rewritten)
                                |
                                v
+-------------------------------------------------------+
|               BLUEBERRYME PRIVACY BOUNDARY           |
| policy -> handles -> encrypted refs/capsules          |
| dataset egress -> selective disclosure                |
| compiler -> exact-context privacy recipe              |
+---------------------------+---------------------------+
                            |
                            | protected / authorized view
                            v
                       UNTRUSTED AGENT
                            |
                            | structured call with handles
                            v
+-------------------------------------------------------+
|                 BLUEBERRYME GATEWAY                   |
| schema + policy + origin/sink + operation checks      |
+---------------------------+---------------------------+
                            |
                            | signed intent
                            v
+-------------------------------------------------------+
|               TRUSTED TARGET ADAPTER                  |
| just-in-time resolution -> parameterized operation    |
| response/error -> BBM before model return             |
+-------------------------------------------------------+
```

## Source data is never rewritten

BlueberryMe creates a temporary agent view:

```text
Source:       Max Mustermann
Agent sees:   BBM1H.PERSON.YQ4T7CQEMAKN3DWM
```

A source-backed handle can reference:

```text
source_system = claims
record_key    = 4711
field         = name
row_version   = 42
```

The authoritative database remains unchanged.

## Database-scale rule

BlueberryMe should scale with **agent interactions and privacy decisions**, not source-database size.

For a table with millions of rows, classification should normally happen on schema/field structure, compile once, and then run on the fast path. Aggregate requests should stay behind the boundary until reduced.

```text
10,000,000 rows
      |
      +--> schema/privacy compile once
      |
      +--> source-side aggregate when possible
      |
      +--> handles only for entities that actually cross the boundary
```

## Dirty and international data

The core assumes imperfect enterprise data: NULLs, malformed values, Unicode, legacy encodings and unknown fields.

> **Never fail open. Degrade safely.**

| Failure class | Default behaviour |
|---|---|
| Data quality | increase protection / continue safe item |
| Infrastructure | fail closed; never raw passthrough |
| Rehydration | isolate the item/call |
| Policy | deny with a fixed error code |

## Secrets are capabilities

Secrets are not pseudonymised text. They become target- and operation-bound capabilities:

```text
github_pat_...
      |
      v
BBM1C.N7YQ2B5P3HV4K6WM
```

There is no general agent-accessible decode endpoint.

## Async jobs

Bounded async jobs carry encrypted references/capsules, not the original lease. Submission and execution both check current policy. Source pointers can use `row_version`/ETag drift checks, and results are re-tokenised into a fresh lease at retrieval.

The reference implementation intentionally provides bounded single jobs, not a workflow engine.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest -q
blueberryme demo
```

HTTP gateway:

Persistent gateway mode requires master-key material outside the state directory:

```bash
pip install -e .[api]
export BBM_MASTER_KEY_B64="<32-byte key from your secret manager, URL-safe base64>"
export BBM_CONTROL_TOKEN="$(blueberryme gen-token)"
export BBM_AGENT_TOKENS="agent-a=$(blueberryme gen-token)"
blueberryme serve
```

For local development only, `BBM_DEV_MODE=1` permits BlueberryMe to create `.blueberryme/master.key` beside the local state database.

## Reference implementation limits

BlueberryMe currently does **not** claim:

- turnkey deployment into a bank without integration work;
- complete semantic protection of arbitrary transformed free text;
- non-bypassability when the host deliberately leaves alternate DB/network/tool paths open;
- native HA clustering, HSM/KMS, OPA/Cedar, SPIFFE or WORM providers;
- SQLite as the recommended state store for large regulated production deployments;
- exactly-once external side effects unless the target honors the supplied idempotency key;
- complete quasi-identifier analysis against arbitrary external knowledge;
- legal GDPR, DORA or sectoral compliance by itself.

The echo guard remains defense in depth for verbatim echoes; structured egress policy and compiled result mediation are the stronger controls.

## Documentation

1. [BBM/1 protocol](docs/BBM-1.md)
2. [Selective Disclosure](docs/SELECTIVE-DISCLOSURE.md)
3. [Privacy Compilation](docs/PRIVACY-COMPILER.md)
4. [Execution Boundary](docs/EXECUTION-BOUNDARY.md)
5. [Host Capability Boundary](docs/HOST-CAPABILITY-BOUNDARY.md)
6. [Data Plane](docs/DATA-PLANE.md)
7. [Async Jobs](docs/ASYNC-JOBS.md)
8. [MCP Binding](docs/MCP-BINDING.md)
9. [Threat Model](docs/THREAT-MODEL.md)
10. [EU Business Profile](docs/EU-BUSINESS-PROFILE.md)
11. [Enterprise Roadmap](docs/ENTERPRISE-ROADMAP.md)

## License

BlueberryMe is released under **AGPL-3.0-only** (since v0.3.1; earlier versions were GPL-3.0-only). Commercial use is permitted. If you run a modified version as a network service, its users must be able to obtain your modified source. See [COMMERCIAL-LICENSING.md](COMMERCIAL-LICENSING.md).

---

## AI Transparency

This repository contains material created with or materially assisted by generative AI systems. This may include source code, documentation, examples, tests, specifications, project artwork and other visual assets.

AI-generated or AI-assisted material should not be treated as independently verified solely because it appears in this repository. Visual assets may include AI-generated imagery used for illustrative or branding purposes unless explicitly stated otherwise.

This repository-level disclosure is provided for transparency, including with regard to applicable transparency requirements under the EU AI Act. It does not imply that every file or contribution was generated by AI, nor that every item is subject to a specific statutory labeling obligation.
