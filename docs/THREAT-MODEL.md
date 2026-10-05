# Threat model — v0.3.1

## Primary assets

- source identity and direct identifiers;
- credentials/secrets;
- source pointers that reveal identifiers;
- resolution authority;
- model-visible context;
- audit correlation keys.

## Key threats and controls

### Ciphertext harvesting

**Threat:** reversible ciphertext is copied into model logs/memory and becomes valuable after a future key compromise.

**Control:** model sees random handles only. Ciphertext/reference state stays inside the boundary.

### Round-trip laundering

**Threat:** a target rehydrates a value, then a later read returns plaintext to the agent.

**Control:** mandatory response re-tokenisation and structured error codes.

### Prompt/tool injection

**Threat:** injected instructions route a handle to an attacker-controlled sink.

**Control:** deterministic origin-scope -> sink/operation flow policy; prompt content cannot grant authorization.

### Replay

**Threat:** a stolen intent/handle is replayed.

**Control:** handle possession is insufficient; intents are signed, target/operation/payload/expiry-bound and tracked as consumed.

### Concurrent replay (fixed in 0.3.1)

**Threat:** several requests carrying the same intent race through "is it consumed?" before any of them marks it consumed; the target runs several times.

**Control:** atomic first-writer-wins consumption before resolution, enforced by the shared state store (also across processes).

### Double execution of async jobs (fixed in 0.3.1)

**Threat:** two workers pick up the same queued job (e.g. a payment) and both execute it.

**Control:** expiring atomic worker claim; re-read after claim; cancel during execution discards the result; the job id doubles as target idempotency key.

### Self-minted authority (fixed in 0.3.1)

**Threat:** an agent that can reach the gateway creates its own lease with arbitrary target operations, or asks for wider operations when collecting an async result.

**Control:** separate control-plane and agent-plane credentials, fail-closed when unconfigured; agent identity from the credential; result leases are the intersection with the submitting lease.

### Unsigned call attributes (fixed in 0.3.1)

**Threat:** a guarded call object is modified between gateway and target (different field map, different lease id) so values are resolved differently or the response is tokenised into another agent's lease.

**Control:** field map signed into the intent; response protection always uses the intent's lease; mismatches fail with `BBM_INTENT_INVALID`.

### Echo laundering

**Threat:** a target returns a resolved value inside a field the response schema allows (free text, logs, nested objects, keys).

**Control:** echo guard replaces every resolved value in the response with the agent's handle (secrets with a removal marker). Not a detector for transformed/partial echoes.

### Linkability inside a lease

**Threat:** stable handles let an observer of one lease's context see that two records concern the same entity.

**Control:** this is the intended trade-off for agent reasoning and is scoped to one lease; handles are random, the lookup index is HMAC-keyed and deleted with the lease. Classes where even in-lease linkage is unacceptable use `linkability: OCCURRENCE`.

### Value drift

**Threat:** a source pointer resolves to a value that changed after submission.

**Control:** `row_version`/ETag comparison; v0.3 default is fail-item with `BBM_VALUE_DRIFT`.

### Exception leakage

**Threat:** target or source-adapter exception contains IBAN/name/connection strings/other input.

**Control:** raw exception text is discarded on both the target and the source-read path; fixed error codes only.

### Dirty data causing fail-open

**Threat:** invalid/NULL/foreign data triggers a convenience fallback to raw values.

**Control:** four-class failure model; data quality increases protection, infrastructure failure closes.

### Process restart

**Threat:** audit correlation and async jobs disappear because state/key was process-local.

**Control:** encrypted persistent state provider and persistent master key for gateway mode.

## Explicit non-goals

v0.3 does not claim to protect against:

- root/admin compromise of the trusted BlueberryMe/target host;
- live process-memory scraping;
- hardware side channels;
- source-system compromise;
- inference from business facts the policy intentionally exposes to the model;
- bypass paths deliberately left outside the deployment boundary;
- complete quasi-identifier analysis across arbitrary external knowledge.


### Generated-code bypass

**Threat:** an agent writes Python/shell code or launches an MCP child that reads credentials, filesystem data or direct source routes outside the BBM path.

**Control:** the whole process tree runs in the same constrained Agent Zone. v0.4 provides `zone-check` to probe the tested environment and a thin `srt` launcher as one reference boundary. BlueberryMe does not attempt to classify generated source code as safe or malicious.

### Data-plane amplification

**Threat:** millions of database rows are copied into the Agent Zone, creating unnecessary privacy exposure, state growth and latency even though the task only needs an aggregate.

**Control:** schema-driven classification, bounded batches and source-side pushdown for aggregate analysis. Handles are emitted only for entities that actually need to cross the boundary.
