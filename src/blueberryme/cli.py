from __future__ import annotations

from pathlib import Path

import typer

from .models import DataClass
from .policy import load_policy
from .proxy import StructuredToolGuard
from .runtime import BlueberryRuntime

app = typer.Typer(add_completion=False, help="BlueberryMe v0.2 reference runtime")


def _runtime() -> BlueberryRuntime:
    policy_path = Path(__file__).parents[2] / "policies" / "eu-business.yaml"
    return BlueberryRuntime(load_policy(policy_path))


@app.command()
def demo() -> None:
    runtime = _runtime()
    guard = StructuredToolGuard(runtime)
    lease_id = runtime.create_lease(
        agent_id="unknown-external-agent",
        purpose="CLAIM_REVIEW",
        scope="DEMO-CLAIM",
        ttl_seconds=300,
        allowed_operations={
            "SOURCE_SYSTEM": ["LOOKUP"],
            "LETTER_SERVICE": ["DELIVER"],
            "GITHUB": ["WRITE_REPO"],
        },
    )
    source = {
        "name": "李 明",
        "case": "UV-2026-004817",
        "birth_date": "14.06.1977",
        "email": "broken-address",
        "diagnosis": "Fraktur rechter Unterarm",
        "iban": None,
        "legacy_note": "unclassified data must not pass",
    }
    schema = {
        "name": DataClass.PERSON,
        "case": DataClass.CASE_ID,
        "birth_date": DataClass.BIRTH_DATE,
        "email": DataClass.EMAIL,
        "diagnosis": DataClass.HEALTH_DATA,
        "iban": DataClass.IBAN,
    }
    protected = runtime.protect_record(source, schema, lease_id)
    typer.echo("MODEL VIEW")
    for key, value in protected.items():
        typer.echo(f"{key}: {value}")

    tool_payload = {"case": protected["case"], "status": "REVIEW_COMPLETE"}
    resolved = guard.prepare_tool_call(
        tool_payload,
        lease_id=lease_id,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
        passthrough_fields={"status"},
    )
    typer.echo(f"\nAUTHORIZED TOOL VIEW: {resolved}")
    runtime.destroy_lease(lease_id)
    typer.echo("LEASE DESTROYED")


@app.command()
def version() -> None:
    typer.echo("0.2.0")


if __name__ == "__main__":
    app()
