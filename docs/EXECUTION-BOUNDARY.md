# Execution Boundary — v0.4.4

BlueberryMe does not attempt to understand whether generated Python, shell or MCP code is malicious.
It removes capabilities from the entire agent process tree and verifies the resulting boundary.

> Generated code may do anything — but only inside the same constrained Agent Zone.

## Reference boundary

The reference launcher delegates sandboxing to Anthropic **sandbox-runtime (srt)**. srt is a convenience
implementation, not part of BBM/1. Docker, Podman, Devcontainers, Kubernetes, VMs or corporate endpoint
controls are equally valid if they satisfy the same boundary properties.

`blueberryme run-agent` generates a restrictive srt profile:

- workspace is readable/writable;
- the rest of the home directory is denied by default, with the workspace explicitly re-allowed;
- common credential paths remain denied;
- environment is allowlist-based;
- network is deny-by-default;
- only explicitly configured BBM gateway and optional LLM hosts are allowed.

The wrapper requires an installed `srt` binary. BlueberryMe does not vendor or fork sandbox-runtime.

## Conformance probe

`blueberryme zone-check` runs *inside the zone* and checks observable bypass paths:

- credential-like environment variables;
- SSH/AWS/GitHub/Docker/Kubernetes credential locations;
- Docker socket;
- configured direct source routes;
- configured direct target routes;
- cloud metadata endpoint;
- arbitrary Internet route;
- positive reachability of configured BBM gateway and optional LLM endpoint.

DNS is reported as a warning rather than a false hard guarantee: a pure userspace probe cannot prove
that every resolver path is non-exfiltrating. The deployment sandbox/network policy remains authoritative.

A PASS means the tested paths satisfied the BBM probe at that moment. It is evidence, not proof against
root compromise or an intentionally untested route.

## IDE agents

A terminal command launched through `run-agent` does not sandbox the parent IDE process. If an IDE agent
can read files using built-in IDE capabilities, either the entire IDE/session must run inside a conformant
remote workspace/devcontainer/VM, or sensitive source data must not be mounted in that workspace.

## Host-provided capabilities

Process/network isolation is not sufficient when the parent host application gives the agent privileged functions that can materialize raw data.

Examples include result-grid readers, IDE file/search APIs, clipboard readers, browser extraction helpers and direct database functions. These capabilities are part of the Agent Boundary even if they do not use the network.

An enabled host capability that can return sensitive values must be denied or BBM-mediated before agent ingress. A host-native raw grid reader is therefore non-conformant if it exposes the raw result before BBM sees it.

The lightweight declarative evaluator in `blueberryme.host_boundary` records this deployment contract. It does not claim to discover undocumented host APIs automatically.

See [Host Capability Boundary](HOST-CAPABILITY-BOUNDARY.md).

## Direct LLM egress

v0.4 permits an explicit LLM host in the reference zone because some agents call the model provider directly.
The stronger deployment is to proxy model traffic through the BBM gateway as well, leaving the Agent Zone
with one network destination.
