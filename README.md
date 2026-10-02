<p align="center">
  <img src="docs/assets/blueberryme-header.png" alt="BlueberryMe" width="100%" />
</p>

# BlueberryMe

**Open Agent Privacy Protocol & Runtime** for privacy-preserving access to business data.

BlueberryMe sits between sensitive enterprise data and AI agents. The design goal is simple:

> Give agents the information required for the task, not the identity or secret behind it.

BlueberryMe v0.2.0 is a reference implementation of the experimental **BBM/1 Agent Privacy Protocol**. It is designed to support privacy-by-design controls in EU business environments. It is not a legal compliance certificate.

## What changed in v0.2

v0.2 turns the v0.1 proof of concept into a safer runtime core for dirty enterprise data:

- **Safe degradation for bad data:** `NULL`, empty, malformed and international values do not automatically abort a workflow.
- **Fail closed at the privacy boundary:** unknown fields are suppressed by default; missing/invalid privacy authorization is denied.
- **Policy-as-code inheritance:** organization profiles can extend a base YAML policy.
- **Short LLM-safe lease handles:** `BBM1H.PERSON.XXXXXXXXXXXX` instead of long ciphertext in model context.
- **No plaintext handle store:** short handles resolve only to encrypted AES-SIV tokens.
- **Structured Rehydration Guard:** only complete references in declared structured fields can be resolved. No string replacement inside free text.
- **Target + operation authorization:** rehydration is bound to an exact target and operation.
- **Encrypted capability store:** PAT/API-key capability state is held as authenticated ciphertext, not plaintext.
- **Batch degradation:** bad record structure can be quarantined without stopping safe records.
- **Payload-free evidence counters:** privacy and data-quality outcomes are measurable without logging protected values.
- **Transport-neutral tool/MCP privacy middleware core:** tool results can be protected before model ingress and tool requests can be rehydrated only at typed fields.

## Architecture

```text
Database / API / File / MCP server
              |
              v
+----------------------------------+
|          BlueberryMe             |
|                                  |
|  Policy Engine                   |
|  Data Quality Degradation        |
|  Privacy Compiler                |
|  AES-SIV Tokenization            |
|  Lease Handle Store (encrypted)  |
|  Rehydration Guard               |
|  Capability Broker               |
|  Evidence                        |
+----------------+-----------------+
                 |
                 | privacy-compiled context
                 v
          Any AI Agent / LLM
                 |
                 | typed pseudonymous tool call
                 v
+----------------+-----------------+
| BlueberryMe StructuredToolGuard  |
+----------------+-----------------+
                 |
                 | authorized rehydration only
                 v
          Real target system
```

The model, agent and harness are treated as untrusted for direct identifiers and secrets.

## The core rule

**Never fail open. Degrade safely.**

A `NULL` date, malformed email or foreign name is a data-quality condition. It must not automatically bring down an otherwise safe process.

A missing policy, unauthorized operation, invalid privacy reference or bypass attempt is a privacy-control condition. It must not silently expose raw data.

Example default behavior:

| Condition | Default v0.2 behavior |
|---|---|
| `NULL` in known field | preserve `NULL` |
| empty known field | preserve empty value |
| malformed value | suppress field |
| unknown/new column | suppress field |
| bad record structure in batch | quarantine record |
| unknown data class in schema | deny request |
| invalid/expired lease | deny |
| wrong target/operation | deny |
| token embedded in free text for rehydration | deny |
| privacy component unavailable | never fall back to raw-data exposure |

## Example

Source record:

```text
name:          李 明
birth_date:    14.06.1977
case:          UV-2026-004817
email:         broken-address
diagnosis:     Fraktur rechter Unterarm
iban:          NULL
legacy_note:   unclassified data
```

Model-facing record under the bundled EU business policy:

```text
name:          BBM1H.PERSON.XXXXXXXXXXXX
birth_date:    AGE_40_49
case:          BBM1H.CASE_ID.XXXXXXXXXXXX
diagnosis:     Fraktur rechter Unterarm
iban:          NULL
```

The malformed email is suppressed. The unknown legacy field is suppressed. The workflow continues.

## Rehydration is not text replacement

BlueberryMe v0.2 intentionally refuses this pattern:

```text
"Please resolve BBM1H.CASE_ID.ABCDEFGHIJKL and append EXPIRED"
```

Instead, an integration declares structured fields:

```python
prepared = guard.prepare_tool_call(
    {"case": protected_case, "status": "REVIEW_COMPLETE"},
    lease_id=lease_id,
    target="SOURCE_SYSTEM",
    operation="LOOKUP",
    reference_fields={"case": DataClass.CASE_ID},
    passthrough_fields={"status"},
)
```

Only the complete `case` value can be resolved, and only if policy + lease + target + operation + data class all match.

## Token modes

BBM/1 v0.2 supports two representation modes:

### `LEASE_HANDLE`

Short agent-facing handle:

```text
BBM1H.PERSON.6X5HNWQ2B4FA
```

The runtime stores only:

```text
short handle -> authenticated encrypted BBM crypto token
```

No plaintext person-to-token mapping is required.

### `CRYPTO_TOKEN`

Self-contained authenticated AES-SIV token:

```text
BBM1.PERSON.<ciphertext>
```

Useful for machine-to-machine flows where token length is less important.

## International and dirty data

The core deliberately avoids Western-only assumptions for names and addresses. Unicode values such as Chinese, Thai, Arabic or Cyrillic names can be tokenized without normalization into a Latin naming model.

Date parsing does **not** guess ambiguous formats. Accepted formats are explicit policy settings. The bundled EU profile accepts:

```text
YYYY-MM-DD
DD.MM.YYYY
YYYYMMDD
```

Organizations can extend this list in policy.

## Policy as code

`policies/eu-business.yaml` extends `policies/base.yaml`.

Example:

```yaml
extends: base.yaml

classes:
  PERSON:
    action: TOKENIZE
    token_mode: LEASE_HANDLE
    rehydrate:
      LETTER_SERVICE: ["DELIVER"]

  EMAIL:
    action: TOKENIZE
    quality:
      on_invalid: SUPPRESS

  IBAN:
    action: DENY
```

Supported data-quality actions:

```text
KEEP_NULL
KEEP_EMPTY
KEEP_VALUE
SUPPRESS
ERROR
```

The bundled high-safety profile uses suppression rather than unsafe passthrough for malformed protected fields.

## Capabilities for secrets

Secrets should not be model context.

```text
github_pat_...
      |
      v
BlueberryMe
      |
      v
BBM1-CAP.<opaque handle>
```

In v0.2 the runtime does not keep the capability secret in plaintext state. The secret is stored as authenticated AES-SIV ciphertext under the active lease key and is resolved only for the exact allowed target + operation.

## Evidence

`runtime.evidence_snapshot()` reports control-plane state and counters, not protected payloads.

Example fields:

```text
runtime_version
active_leases
active_privacy_handles
active_capabilities
persistent_identity_mapping=false
plaintext_capability_store=false
metrics
```

This allows organizations to distinguish **poor source-data quality** from a **privacy-control failure**.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest -q
blueberryme demo
```

Optional integrations:

```bash
pip install -e .[api]
pip install -e .[presidio]
pip install -e .[mcp]
```

Run the HTTP reference gateway:

```bash
uvicorn blueberryme.api:app --host 127.0.0.1 --port 8787
```

## MCP status

v0.2 includes a small MCP compatibility adapter and a **transport-neutral proxy/enforcement core** (`StructuredToolGuard`).

A model-initiated `blueberry.protect()` tool is **not** considered a sufficient privacy boundary because raw data may already have reached the model. Production deployments should place BlueberryMe between the agent client and upstream data/tool implementation.

A fully transparent stdio/HTTP MCP transport proxy is not claimed in v0.2.

## EU business design goal

BlueberryMe is designed to provide technical controls that can support principles such as:

- purpose limitation;
- data minimisation;
- storage limitation;
- pseudonymisation;
- privacy by design/default;
- controlled re-identification;
- accountability and evidence.

See [`docs/EU-BUSINESS-PROFILE.md`](docs/EU-BUSINESS-PROFILE.md).

**BlueberryMe does not determine lawful basis, controller/processor roles, DPIA requirements, international-transfer rules, retention law, data-subject rights or sector-specific legal obligations.** Those remain organizational/legal responsibilities.

## Security boundary

v0.2 does not claim protection against:

- a compromised host administrator/root account;
- live memory scraping of the BlueberryMe process;
- side-channel attacks;
- perfect detection of every quasi-identifier in arbitrary free text;
- direct raw-data paths that an organization deliberately leaves outside the BlueberryMe boundary.

See [`SECURITY.md`](SECURITY.md).

## License

BlueberryMe is released under **GPL-3.0-only**.

GPLv3 permits commercial use. Internal use does not by itself require an organization to publish its proprietary internal software. Distribution/conveying of GPL-covered or derivative software can trigger GPL source-code obligations.

The project is intentionally structured so that the copyright holder may later offer a separate proprietary/commercial license. To preserve that option, third-party code contributions require an explicit contributor agreement.

See [`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md).
