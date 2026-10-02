# BlueberryMe boundary and non-bypassability

The Python library alone cannot stop an operator from giving an agent a second database credential or unrestricted network access. Non-bypassability is therefore a **deployment property**.

A conformant high-safety deployment should enforce:

```text
Agent zone
  -> network egress only to approved BlueberryMe gateway(s)
  -> no source DB credentials
  -> no Resolve/KMS credentials
  -> no direct trusted-target credentials
```

Target adapters live outside the agent zone. Resolve/materialisation methods are not exposed through the public HTTP gateway.

## MCP

Remote MCP can sit behind the gateway.

stdio can also be mediated, but the broker must launch the MCP child itself and control:

- stdin/stdout;
- inherited environment variables;
- credentials;
- filesystem paths;
- network egress.

A broker that only wraps stdin/stdout but leaves unrestricted credentials/network access is not a privacy boundary.

## Mandatory return path

Every response that can reach the model must pass through response protection, including:

- success payloads;
- target errors;
- retry errors;
- tool metadata that may contain values.

## Logs and observability

BlueberryMe normal audit is allowlist-structured. Deployment components before/inside the trusted boundary must disable body/prompt/DB statement logging where those logs could contain source values. Log redaction is defense in depth, not the primary privacy control.
