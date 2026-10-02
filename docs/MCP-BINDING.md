# BBM/1 MCP binding notes

MCP is a transport binding for BBM/1, not the privacy protocol itself.

## Required placement

A model-callable anonymisation tool is too late if the model already received raw input. A compliant MCP deployment protects tool results before they become model context and validates tool requests before trusted execution.

## Remote MCP

Preferred enterprise topology:

```text
Agent/MCP client -> BlueberryMe gateway -> upstream MCP server/target adapter
```

All response and error paths return through the gateway.

## stdio MCP

stdio is supportable when a broker launches and controls the child. The broker must mediate more than bytes:

```text
stdin/stdout
process environment
credentials
filesystem access
network egress
```

Direct/unmediated stdio from the agent zone is not conformant with the high-safety profile.

## Async tasks

BBM/1 async semantics are transport-independent. If a specific MCP implementation supports long-running tasks, the binding may map BBM job handles onto that mechanism. Otherwise the portable surface is:

```text
submit
status
get_result
cancel
```
