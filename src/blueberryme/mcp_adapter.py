"""Optional MCP compatibility adapter.

A model-initiated privacy tool is not a privacy boundary. Production MCP traffic must
be mediated before model ingress. stdio is permitted only when a broker launches the
child and controls stdin/stdout, environment, credentials, filesystem and network egress.
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

    root = Path(__file__).parents[2]
    policy_path = Path(os.environ.get("BBM_POLICY", root / "policies" / "eu-business.yaml"))
    state_dir = Path(os.environ.get("BBM_STATE_DIR", ".blueberryme"))
    runtime = BlueberryRuntime(load_policy(policy_path), state_path=state_dir / "state.db")
    server = FastMCP("BlueberryMe")

    @server.tool()
    def status() -> dict:
        return runtime.status()

    @server.tool()
    def destroy_lease(lease_id: str) -> dict:
        runtime.destroy_lease(lease_id)
        return {"destroyed": True}

    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
