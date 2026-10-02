# BBM/1 — Agent Privacy Protocol, draft 0.2

Status: experimental reference specification.

## 1. Objective

BBM/1 defines a vendor-neutral privacy contract between sensitive data sources and AI agents. It separates semantic task context from identity, secrets, authorization, retention and re-identification capability.

## 2. Trust model

The agent/model/harness is untrusted for direct identifiers and credentials. The BlueberryMe privacy boundary must enforce policy **before model ingress** and **before re-identification at egress**.

## 3. Required privacy context

A privacy lease binds at least:

```text
agent_id
purpose
scope
lease_id
expires_at
allowed target operations
```

A protected value has a `data_class` and a policy transformation.

## 4. Transformations

- `ALLOW`: visible because policy explicitly permits it for the purpose.
- `TOKENIZE`: reversible scoped pseudonym.
- `GENERALIZE`: reduced precision.
- `DENY`: not exposed to the model.

Unknown structured fields must never implicitly default to `ALLOW` in strict mode.

## 5. Data quality semantics

BBM/1 distinguishes source-data quality from privacy-control integrity.

A compliant high-safety implementation should support field-level behavior for:

```text
NULL
EMPTY
INVALID
TRANSFORM_ERROR
UNKNOWN_FIELD
```

The default high-safety behavior is:

```text
NULL             -> KEEP_NULL
EMPTY            -> KEEP_EMPTY
INVALID          -> SUPPRESS
TRANSFORM_ERROR  -> SUPPRESS
UNKNOWN_FIELD    -> SUPPRESS
```

A bad field must not require a whole workflow to fail if the field can be safely withheld.

A privacy-control failure (missing policy, invalid lease, unauthorized target/operation, unauthenticated reference) must never degrade to raw-data exposure.

Normative principle:

> Never fail open. Degrade safely.

## 6. Scoped reversible tokenization

The reference runtime uses AES-SIV authenticated deterministic encryption with a random 64-byte per-lease key. Associated data binds ciphertext to:

```text
BBM protocol version
data class
purpose
scope
```

Two representation modes are defined:

### CRYPTO_TOKEN

```text
BBM1.<DATA_CLASS>.<URLSAFE_BASE64_CIPHERTEXT>
```

### LEASE_HANDLE

```text
BBM1H.<DATA_CLASS>.<SHORT_OPAQUE_ID>
```

A lease handle maps only to an authenticated crypto token, never directly to plaintext.

Properties:

- identical value + class within one lease -> stable reference;
- a different lease -> different reference;
- lease destruction removes short-handle state and the key;
- no persistent plaintext person-to-token lookup is required.

## 7. Structured rehydration

Rehydration is a privileged operation, not a string transformation.

A request must bind:

```text
complete BBM reference
lease
target
operation
expected data class
```

Rehydration must fail unless:

```text
lease exists and is active
target is lease-authorized
operation is lease-authorized
reference is a complete BBM token/handle
reference authenticates under the lease
expected data class matches
class policy authorizes target + operation
```

Implementations must not search arbitrary free text and replace embedded BBM tokens with plaintext.

## 8. Capability handles

Credentials and secrets are represented as opaque capability handles:

```text
BBM1-CAP.<opaque-id>
```

The reference runtime encrypts the underlying secret under the active lease key. Resolution requires the exact target + operation. Secret material must be delivered directly to the target integration/process and must not be returned to model context.

## 9. Retention

Source-data lifetime, privacy-lease lifetime, provider retention and audit lifetime are separate concepts.

On lease destruction the runtime removes:

- lease encryption key;
- short privacy-handle state;
- active capability state;
- lease-owned temporary state.

## 10. Audit and evidence

Audit/evidence may contain control-plane facts such as:

```text
event_type
pseudonymous lease/agent/scope refs
purpose
data_class
decision
count
timestamp
target
operation
```

Raw values, resolved values, ciphertext, tokens, handles and credentials must not be copied into normal audit payloads.

## 11. Proxy placement

A model-callable privacy tool is not sufficient as the only boundary. BlueberryMe should be placed so that sensitive upstream data is transformed before it enters agent/model context.

Tool outputs: protect before returning to model.

Tool inputs requiring real identity: resolve only at declared structured fields immediately before the authorized target operation.
