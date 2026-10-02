<p align="center">
  <img src="docs/assets/blueberryme-header.png" alt="BlueberryMe" width="100%" />
</p>

# BlueberryMe v0.1.0

**Open Agent Privacy Protocol & Runtime**

BlueberryMe places a privacy boundary between sensitive business data and AI agents. The central rule is simple:

> **Give agents the information required for the task, not the identity behind it.**

BlueberryMe v0.1 is a local-first reference runtime for scoped reversible pseudonymisation, data minimisation, short-lived privacy leases, capability handles for secrets, guarded re-identification, and payload-free audit events.

## What v0.1 proves

```text
Source system
     |
     v
+------------------+
|   BlueberryMe    |
|  Privacy Boundary|
+------------------+
     |
     | privacy-compiled context
     v
Any AI agent / LLM
     |
     | pseudonymous tool request
     v
+------------------+
|   BlueberryMe    |
| Rehydration Guard|
+------------------+
     |
     v
Authorized target system
```

The agent or model is treated as **untrusted**. It does not receive raw credentials and, where the business purpose permits, does not receive direct identifiers.

### Core guarantees targeted by BBM/1

- Direct identifiers can be replaced with reversible, lease-scoped AES-SIV tokens before model exposure.
- The same value is linkable inside one active privacy lease but intentionally unlinkable across different leases.
- Re-identification requires an active lease, the original purpose/scope, an allowed target, and an allowed data class.
- Revoked or expired leases cannot be used for re-identification.
- Secrets such as PATs are represented to an agent as capability handles; the raw secret is only resolved for an explicitly allowed target.
- Audit events contain operation metadata and counts, not source values, tokens, or resolved secrets.
- Unknown structured fields fail closed in strict mode.
- No persistent person-to-token mapping database is required in v0.1.

## Why this is not another PII filter

PII detection is only one input. BlueberryMe separates four concerns:

```text
AUTHORIZATION  -> May this agent access this task/scope?
PRIVACY        -> Which attributes may the model actually see?
CAPABILITY     -> Which real-world operation may be performed?
RETENTION      -> How long may the resolution capability exist?
```

For structured business data, explicit schema policy is preferred over probabilistic detection. Free-text detection can use Microsoft Presidio when installed; the built-in regex detector is deliberately limited and is not represented as complete PII detection.

## BBM/1 protocol concepts

Every protected operation is bound to:

- `agent_id`
- `purpose`
- `scope`
- `lease_id`
- `data_class`
- transformation (`ALLOW`, `TOKENIZE`, `GENERALIZE`, `DENY`)
- permitted rehydration targets
- expiry/revocation state

Example:

```text
raw:       Max Mustermann
class:     PERSON
purpose:   CLAIM_REVIEW
scope:     CLAIM-4711
agent:     external-agent-17

model sees:
BBM1.PERSON.<ciphertext>
```

A second lease produces a different token, even for the same person.

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

Run the MCP adapter after installing the `mcp` extra:

```bash
python -m blueberryme.mcp_adapter
```

## EU business profile

The design goal is to support privacy-by-design controls relevant to EU business processing: purpose limitation, data minimisation, storage limitation, pseudonymisation, access control, and technical separation. See [`docs/EU-BUSINESS-PROFILE.md`](docs/EU-BUSINESS-PROFILE.md).

**BlueberryMe is not a legal compliance certificate.** GDPR compliance depends on the controller/processor roles, lawful basis, purpose, contracts, DPIA where required, retention rules, security measures, and the concrete processing operation. v0.1 supplies technical controls that can support those obligations.

## Security model

The model/agent is outside the trusted privacy boundary. The source system and BlueberryMe runtime are inside it.

v0.1 deliberately does **not** claim protection against a compromised host administrator/root account, memory scraping of the BlueberryMe process, side-channel attacks, or complete recognition of every indirect/quasi-identifier in arbitrary free text. Those belong to later hardened profiles.

See [`SECURITY.md`](SECURITY.md) and [`docs/BBM-1.md`](docs/BBM-1.md).

## License

The reference implementation is released under **GPL-3.0-only**.

GPLv3 permits commercial use. A company may use, modify and commercially distribute the software subject to the GPL conditions. The copyright holder can also offer the same code under a separate proprietary/commercial licence later, provided the necessary copyright rights have been retained.

For that reason BlueberryMe v0.1 does not accept third-party code contributions without an explicit contributor agreement. See [`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
