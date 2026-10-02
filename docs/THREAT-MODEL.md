# Threat model — v0.3

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

### Value drift

**Threat:** a source pointer resolves to a value that changed after submission.

**Control:** `row_version`/ETag comparison; v0.3 default is fail-item with `BBM_VALUE_DRIFT`.

### Exception leakage

**Threat:** target exception contains IBAN/name/other input.

**Control:** raw exception text is discarded; fixed error codes only.

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
