"""Optional MCP compatibility adapter.

Important: a model-initiated privacy tool is not itself an ingress privacy boundary.
For enforcement, place BlueberryMe's StructuredToolGuard/adapter layer between the
agent client and upstream tool implementation. v0.2 provides the transport-neutral
proxy core; a transparent stdio/HTTP MCP transport proxy is a later hardening slice.
"""

from __future__ import annotations

import os
from pathlib import Path

from .policy import load_policy
from .runtime import BlueberryRuntime


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("Install blueberryme[mcp] to run the MCP adapter") from exc

    policy_path = Path(os.environ.get("BBM_POLICY", Path(__file__).parents[2] / "policies" / "eu-business.yaml"))
    runtime = BlueberryRuntime(load_policy(policy_path))
    server = FastMCP("BlueberryMe")

    @server.tool()
    def status() -> dict:
        return runtime.status()

    @server.tool()
    def protect_text(text: str, agent_id: str, purpose: str, scope: str, ttl_seconds: int = 300) -> dict:
        lease_id = runtime.create_lease(
            agent_id=agent_id,
            purpose=purpose,
            scope=scope,
            ttl_seconds=ttl_seconds,
            allowed_operations={},
        )
        return {"lease_id": lease_id, "text": runtime.protect_text(text, lease_id)}

    @server.tool()
    def destroy_lease(lease_id: str) -> dict:
        runtime.destroy_lease(lease_id)
        return {"destroyed": True}

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
