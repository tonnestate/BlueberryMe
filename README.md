<p align="center">
  <img src="docs/assets/blueberryme-header.png" alt="BlueberryMe" width="100%" />
</p>

# BlueberryMe

**Open Agent Privacy Protocol & Sensitive Data Bypass Runtime.**

BlueberryMe sits between sensitive business data and AI agents. Its design goal is not to rewrite the source of truth and not to ask a model to "forget" data after the fact.

> **The agent carries references, never values. Authority to resolve them is minted per call, outside the agent, and bound to one target and one operation.**

BlueberryMe v0.3.1 is an experimental reference implementation of **BBM/1**. It provides technical controls that can support privacy-by-design and data-minimisation programs in EU business environments. It is **not** a legal compliance certificate.

## Why v0.3 is different

v0.1/v0.2 proved reversible protection, leases, policy and safe degradation. v0.3 moves the differentiator into code:

- **Random lease-local handles only.** No AES-SIV/ciphertext is exposed to the agent.
- **Pointer-first bypass.** Source-backed identifiers are represented as encrypted source references, not copied plaintext values.
- **Encrypted capsules for values without a source.** User input and transient values can still cross an async boundary without plaintext storage.
- **Signed Resolution Intent.** Resolution authority is minted outside the agent and bound to one target, operation, payload and expiry.
- **Pull-model target adapter.** There is no public/general `decode()` API.
- **Mandatory response re-tokenisation.** A target cannot legitimately return raw identity to the model path.
- **Safe error path.** Target exception text is never returned; only catalogue codes cross the boundary.
- **Origin-to-sink data-flow policy.** Field permission alone is not sufficient.
- **Persistent encrypted runtime state.** Leases, handles, references, jobs and audit survive a process restart when the persistent runtime is used.
- **Persistent audit derivation.** Audit references derive from the runtime master key instead of a new process-random key on every start.
- **Bounded async jobs.** A job carries encrypted references/capsules, not a lease. No lease renewal and no workflow engine are required for single jobs up to 24 hours.
- **Double policy check for async.** Once at submit, once at execution.
- **Value-drift check.** A source pointer can bind `row_version`; changed source data fails the item safely.
- **Progressive async loading.** Optional expensive providers are lazy-loaded and see only the already protected view.

## What v0.3.1 adds

A hardening release from an end-to-end review. Same protocol, fewer ways around it, and fast enough for real data volumes.

- **One entity, one handle (per lease).** The same value or source pointer gets the same random handle inside a lease, so an agent can tell that two records concern the same customer. Leases stay unlinkable. Per class `linkability: OCCURRENCE` restores fresh-handle-per-occurrence. See [BBM-1 §3.1](docs/BBM-1.md).
- **Echo guard on the return path.** If a target echoes a resolved name in free text (`"Letter sent to Max Mustermann"`), the agent receives its own handle instead. Echoed secrets are removed.
- **Race-free replay protection.** Intents are burned atomically *before* resolution — also across processes sharing one state file. v0.3.0 had a check-then-mark window.
- **No double execution of async jobs.** Workers win an expiring atomic claim; crashed workers are recovered; a cancel during execution discards the result.
- **Gateway authentication with two planes.** Control-plane token (leases, ingress, capabilities) and per-agent tokens (jobs). Fails closed when unconfigured. v0.3.0 let anyone who reached the port create leases.
- **No authority widening.** Async result leases are bound to the submitting agent and can never exceed the submitting lease's operations; the field map is signed into the intent; responses are always protected under the signed lease.
- **Linear performance.** Lease-owned state is deleted with one indexed operation instead of rewriting a growing handle list on every protect; one SQLite connection with batched transactions; aggregated audit rows. Reference benchmark (1,000 records, 4 fields, SQLite): 51 → ~6,600 records/s, flat at 10,000 records.

## Core architecture

```text
                         SOURCE OF TRUTH
                         (never rewritten)
                                |
                   source pointer / raw ingress
                                v
+-------------------------------------------------------+
|               BLUEBERRYME PRIVACY BOUNDARY           |
|                                                       |
|  Policy -> random handle -> encrypted ref/capsule     |
|  Flow policy -> signed per-call Resolution Intent     |
|  Audit/evidence -> no protected payload               |
+---------------------------+---------------------------+
                            |
                            | handles + allowed semantics
                            v
                       UNTRUSTED AGENT
                            |
                            | structured call with handles
                            v
+-------------------------------------------------------+
|                 BLUEBERRYME GATEWAY                   |
|   schema + policy + origin/sink + operation checks    |
+---------------------------+---------------------------+
                            |
                            | signed intent; handle still opaque
                            v
+-------------------------------------------------------+
|               TRUSTED TARGET ADAPTER                  |
|   resolves just-in-time -> parameterized operation    |
|   response/error -> BlueberryMe before model return   |
+-------------------------------------------------------+
```

The model/harness is treated as untrusted for direct identifiers, credentials and resolution authority.

## Source data is not changed

BlueberryMe never does this:

```sql
UPDATE customer SET name = 'PERSON_17';
```

A source-backed value becomes a temporary view:

```text
Source:       Max Mustermann
Agent sees:   BBM1H.PERSON.YQ4T7CQEMAKN3DWM
```

The encrypted state behind that handle can be a **pointer**:

```text
source_system = claims
record_key    = 4711
field         = name
row_version   = 42
```

The original value is read only inside the trusted target path when a valid per-call intent permits it.

## Dirty and international data

The core assumes enterprise data is imperfect.

```text
NULL
empty values
invalid e-mail/IBAN/date syntax
Unicode names and addresses
Thai / Arabic / Cyrillic / CJK text
invalid UTF-8 bytes
unknown legacy fields
```

The default rule is:

> **Never fail open. Degrade safely.**

| Failure class | Example | Default behaviour |
|---|---|---|
| Data quality | NULL, malformed e-mail, unknown field | more protection / handle / item continues |
| Infrastructure | state store unavailable | closed; never raw passthrough |
| Rehydration | value drift, expired intent | fail that item/call |
| Policy | unauthorized sink or operation | deny with fixed error code |

Invalid sensitive values are protected as opaque handles rather than exposed or used to crash an entire batch. `NULL` remains distinct from empty and invalid.

## Sync call example

```python
call = guard.authorize_tool_call(
    {"case": case_handle},
    lease_id=lease_id,
    target="SOURCE_SYSTEM",
    operation="LOOKUP",
    reference_fields={"case": DataClass.CASE_ID},
)

response = target.execute(
    call,
    handler,
    response_schema={"case": DataClass.CASE_ID},
)
```

The handler sees the real case only inside the trusted target adapter. The model-visible response is tokenised again.

## Async jobs without lease renewal

For a bounded asynchronous call:

```text
Agent -> submit(handles)
          |
          | policy check #1
          | handles -> encrypted pointer/capsule envelope
          v
      trusted Job Store
          |
     original lease may expire
          |
          v
      Target Worker
          |
          | policy check #2
          | row_version check
          | per-job idempotency key
          v
      encrypted Result Store
          |
Agent -> get_result()
          |
          | new lease
          v
      re-tokenised result
```

v0.3 deliberately supports **bounded single jobs**, not a multi-day workflow platform.

Job API semantics:

```text
submit
status
get_result
cancel
```

Maximum reference implementation deadline: 24 hours.

## Progressive async loading

Privacy enforcement remains synchronous. Optional expensive modules can be lazy-loaded afterwards:

```text
FAST PATH (blocking)
policy -> handle -> flow -> intent

ASYNC OPTIONAL PATH
Presidio / deeper risk checks / evidence enrichment / provider warm-up
```

Normative rule:

> **Enforce synchronously, enrich asynchronously.**

Async enrichers receive the protected view only. If an optional provider is not loaded, raw data is never temporarily passed through.

## Persistent state without building a crypto monster

The reference runtime can use an encrypted SQLite state file. This is deliberately a small local/self-hosted baseline, not an HA database platform.

```text
.blueberryme/
  state.db       # encrypted object payloads
  master.key     # local reference key; mode 0600 where supported
```

Production deployments can inject the 32-byte master key through `BBM_MASTER_KEY_B64` or replace the local key source with an approved KMS/HSM integration. BBM/1 does not depend on a specific KMS.

The agent never receives encrypted payloads from the state store; it receives only random handles.

## Policy as code

The bundled policy is intentionally readable YAML:

```yaml
classes:
  PERSON:
    action: TOKENIZE
    linkability: LEASE        # default; OCCURRENCE = fresh handle per occurrence
    rehydrate:
      LETTER_SERVICE: ["DELIVER"]

  IBAN:
    action: TOKENIZE
    rehydrate:
      PAYMENT_SERVICE: ["PAY"]

  HEALTH_DATA:
    action: ALLOW
    allowed_purposes: ["CLAIM_REVIEW"]

flows:
  - origin_scope: "*"
    purposes: ["CLAIM_REVIEW"]
    sinks:
      LETTER_SERVICE: ["DELIVER"]
      PAYMENT_SERVICE: ["PAY"]
```

OPA/Cedar can be future policy providers; they are not mandatory dependencies of the core.

## Secrets are capabilities

A PAT/API key does not become pseudonymous text. It becomes a capability:

```text
github_pat_...
      |
      v
BBM1C.N7YQ2B5P3HV4K6WM
```

It can resolve only for the target + operation for which it was created. There is no public secret-resolution endpoint.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest -q
blueberryme demo
```

Current reference suite:

```text
84 tests passing — including concurrency tests for replay, job double execution and result retrieval
```

HTTP gateway:

```bash
pip install -e .[api]
export BBM_CONTROL_TOKEN="$(blueberryme gen-token)"                 # trusted orchestrator
export BBM_AGENT_TOKENS="agent-a=$(blueberryme gen-token)"          # one token per agent
blueberryme serve
```

| Plane | Credential | Endpoints |
|---|---|---|
| Control (trusted) | `BBM_CONTROL_TOKEN` | leases, `/v1/protect/*`, capabilities, status, evidence |
| Agent (untrusted) | `BBM_AGENT_TOKENS` | `/v1/jobs` submit / status / cancel / result |

Without tokens every request is refused (503). `BBM_INSECURE_DEV=1` disables authentication for local experiments only.

By default the HTTP gateway uses `.blueberryme/state.db` and a persistent local key. Use environment/KMS injection for production key material. Call `runtime.purge_expired()` periodically to compact expired state.

## MCP

MCP is a binding, not the protocol itself.

A model-invoked `protect()` tool is not a sufficient privacy boundary because the raw value may already have entered the model. A conformant deployment mediates MCP traffic before model ingress and routes target responses back through the same privacy boundary.

`stdio` is not inherently forbidden. **Unmediated stdio from the agent zone is.** A stdio broker must also control the child environment, inherited credentials, filesystem access and network egress.

See [`docs/MCP-BINDING.md`](docs/MCP-BINDING.md).

## What v0.3 does not claim

- It does not magically anonymise information that the task genuinely requires the model to read.
- It does not solve every quasi-identifier/re-identification problem in arbitrary free text.
- It does not make a deployment non-bypassable if the agent still has direct network/DB/tool routes around the gateway.
- It does not provide native HSM/KMS, OPA, SPIFFE, WORM or HA clustering.
- SQLite is a reference persistent store, not the recommended HA store for a large regulated production deployment.
- Exactly-once external side effects require the target to honour the supplied `idempotency_key`; BlueberryMe alone cannot undo a remote side effect after a worker crash.
- The echo guard catches verbatim echoes of resolved values, not transformed ones (upper-cased, split, translated, summarised).
- It is not a legal declaration of GDPR, DORA or sectoral compliance.

The intent is a **simple data path with a hard privacy boundary**, not maximum cryptography everywhere.

## Documentation

- [`docs/BBM-1.md`](docs/BBM-1.md) — protocol draft
- [`docs/BOUNDARY.md`](docs/BOUNDARY.md) — enforcement and non-bypassability
- [`docs/ASYNC-JOBS.md`](docs/ASYNC-JOBS.md) — bounded async job model
- [`docs/EU-BUSINESS-PROFILE.md`](docs/EU-BUSINESS-PROFILE.md) — EU business design profile
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — key threats and controls
- [`docs/ENTERPRISE-ROADMAP.md`](docs/ENTERPRISE-ROADMAP.md) — intentionally deferred enterprise providers

## License

BlueberryMe is released under **GPL-3.0-only**. GPLv3 permits commercial use. The project is structured so the copyright holder can later offer separate proprietary/commercial terms; see [`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md).
