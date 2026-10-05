# Host Capability Boundary — v0.4.4

BlueberryMe must mediate not only network/database paths but also privileged functions supplied by the host application.

A host-provided function is part of the privacy boundary when it can materialize source values for the agent. Examples include:

- SQL result/grid readers such as an integration-specific `GetGridResults`;
- IDE file/search APIs;
- clipboard readers;
- browser extraction APIs;
- direct database helpers;
- host-native tool functions that return application state.

The rule is:

> **An enabled host capability that can return sensitive values must be denied or BBM-mediated before agent ingress.**

## Declarative conformance

`blueberryme.host_boundary` provides a small manifest evaluator. It does not attempt to scrape an IDE or inspect undocumented UI internals.

A host integration declares each agent-visible capability with:

- surface type: `STRUCTURED`, `FREE_TEXT`, or `NON_SENSITIVE`;
- whether it can return sensitive values;
- mediation mode.

Supported mediation modes are:

- `UNMEDIATED` — non-conformant for sensitive surfaces;
- `DENY` — capability is not allowed to return sensitive values to the agent;
- `BBM_STRUCTURED` — structured result is mediated before agent ingress;
- `BBM_FREE_TEXT_HANDLE` — whole text is replaced by an opaque handle;
- `BBM_FREE_TEXT_SCAN` — text is passed through the configured detector before release.

An unmediated sensitive capability is a hard FAIL.

## SSMS example

A conformant path is:

```text
SQL Server
  -> SSMS result
  -> BBM structured egress
  -> agent-visible grid reader
  -> agent/model
```

An agent-visible native grid reader that receives the raw result first is not conformant, even if BBM processes the text later.

## Free-text egress

Free text is deliberately conservative.

`DENY` is the high-assurance default.

`BBM_FREE_TEXT_HANDLE` preserves referential use but releases no text semantics.

`BBM_FREE_TEXT_SCAN` uses the configured detector and is therefore **detector-bounded**. The result is treated as an `AUTHORIZED_DISCLOSURE`, not as proof that zero sensitive content crossed the boundary. Detector misses remain possible.

The free-text helper persists a payload-free Privacy Receipt for `DENY`, `HANDLE` and `SCAN` decisions. Scan receipts deliberately mark path coverage as `DETECTOR_BOUNDED` and conservatively record that sensitive content may have crossed.

The trusted host integration chooses the mode. An agent request must not be allowed to select or upgrade its own mediation mode.

## What this does not prove

The manifest evaluator proves only the declared host contract. If a host exposes an undocumented or unenumerated privileged API, BlueberryMe cannot attest that path.

For high-assurance deployments the host capability inventory therefore belongs in deployment evidence alongside `zone-check`, network policy and workspace isolation.
