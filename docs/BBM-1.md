# BBM/1 — Agent Privacy Protocol, draft 0.1

Status: experimental reference specification.

## 1. Objective

BBM/1 defines a vendor-neutral privacy contract between sensitive data sources and AI agents. It separates semantic task context from identity, secrets, authorization, and retention.

## 2. Threat model

The agent/model/harness is considered untrusted for direct identifiers and secrets. The BlueberryMe privacy boundary is trusted to enforce policy before model ingress and before re-identification at egress.

## 3. Required context

A privacy lease MUST bind:

```text
agent_id
purpose
scope
lease_id
expires_at
allowed_rehydrate_targets
```

A protected value MUST have a `data_class` and a transformation selected by policy.

## 4. Transformations

- `ALLOW`: value remains visible because policy explicitly permits it for the stated purpose.
- `TOKENIZE`: reversible scoped pseudonym produced with authenticated deterministic encryption.
- `GENERALIZE`: reduce precision, for example a date of birth to an age bucket.
- `DENY`: remove the value from the model-facing representation.

No field may implicitly default to `ALLOW` in strict structured-data mode.

## 5. Scoped reversible tokenization

v0.1 uses AES-SIV with a random 64-byte per-lease key. Associated data binds the ciphertext to BBM protocol version, data class, purpose, and scope.

Properties:

- identical plaintext + identical data class inside one lease -> stable token;
- the same plaintext under a different lease -> different token;
- token decryption after lease destruction -> unavailable because the runtime key no longer exists;
- no persistent plaintext-to-token lookup table is necessary.

Tokens have the wire form:

```text
BBM1.<DATA_CLASS>.<URLSAFE_BASE64_CIPHERTEXT>
```

## 6. Rehydration

Rehydration MUST fail unless all conditions hold:

```text
lease exists
lease active
lease not expired
requested purpose matches lease purpose
requested scope matches lease scope
target is allow-listed
data class is rehydratable by policy
ciphertext authenticates under the lease key and associated data
```

The model itself SHOULD NOT be an allowed rehydration target for direct identifiers.

## 7. Capability handles

Secrets and credentials are not tokenized for model use. They are converted to opaque capability handles:

```text
BBM1-CAP.<opaque-id>
```

The runtime keeps the secret only for the active lease. Resolution requires an allowed target. The returned secret must be delivered directly to the target integration/process, not returned into model context.

## 8. Retention

Lease lifetime, source-data lifetime, audit lifetime, and external-provider retention are distinct concepts. BBM/1 governs the BlueberryMe runtime only.

On lease destruction the implementation MUST remove:

- the lease encryption key;
- active capability secrets;
- temporary protected-context caches owned by the lease.

The audit trail MAY remain if it contains no protected payload.

## 9. Audit

Audit events record control-plane facts only, for example:

```text
event_type
lease_ref
agent_ref
purpose
scope_ref
data_class
count
decision
timestamp
```

Raw values, resolved values, token ciphertext, and credentials MUST NOT appear in the audit payload.

## 10. Fail-closed behavior

In strict structured-data mode, an unclassified field is denied rather than passed through. Detector uncertainty in free text must be surfaced to callers; free-text detection alone is not a compliance guarantee.
