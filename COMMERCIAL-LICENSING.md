# Licensing

BlueberryMe is published under **AGPL-3.0-only** (from v0.3.1; v0.3.0 and earlier were GPL-3.0-only).

## Why AGPL

BlueberryMe is typically deployed as a network gateway in front of AI agents. Under the plain GPL, a modified version could be offered to others purely as a hosted service without sharing those modifications. The AGPL closes that gap: section 13 requires that users who interact with a **modified** version over a network can obtain its source code.

## What this means in practice

- Commercial use is permitted. Organizations may run BlueberryMe internally and in production.
- Running an **unmodified** BlueberryMe does not create additional obligations beyond the license itself.
- If you **modify** BlueberryMe and let users interact with it over a network (including agents and orchestrators calling the gateway), you must offer those users the corresponding source of your modified version.
- Integrating BlueberryMe through its HTTP/MCP interfaces does not by itself place your separate applications under the AGPL. Linking or embedding it into your own program is a different case; obtain legal advice for your integration model.

The gateway exposes `GET /source` with the source location and license so that network users can find the code.

## Future licensing options

The copyright holder may later offer separate terms for organizations that need them. To keep that option open, third-party code contributions are accepted only under an explicit contributor agreement (see `CONTRIBUTING.md`). There is no commercial edition at this time.

This document explains project intent. It is not legal advice and not a substitute for the license text in `LICENSE`.
