from __future__ import annotations

from pathlib import Path

import typer

from .jobs import AsyncJobGateway
from .models import DataClass, SourceReference
from .policy import load_policy
from .proxy import StructuredToolGuard, TargetAdapter
from .references import MemorySourceAdapter
from .runtime import BlueberryRuntime

app = typer.Typer(add_completion=False, help="BlueberryMe v0.3 reference runtime")


def _policy_path() -> Path:
    return Path(__file__).parents[2] / "policies" / "eu-business.yaml"


def _runtime() -> BlueberryRuntime:
    return BlueberryRuntime(load_policy(_policy_path()))


@app.command()
def demo() -> None:
    runtime = _runtime()
    source = MemorySourceAdapter(
        {
            "claim-4711": {
                "name": "李 明",
                "case": "UV-2026-004817",
                "diagnosis": "Fraktur rechter Unterarm",
            }
        },
        versions={"claim-4711": "42"},
    )
    runtime.register_source("claims", source)
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    lease_id = runtime.create_lease(
        agent_id="unknown-external-agent",
        purpose="CLAIM_REVIEW",
        scope="CASE:4711",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )

    model_view = runtime.protect_reference_record(
        {
            "name": SourceReference("claims", "claim-4711", "name", "42"),
            "case": SourceReference("claims", "claim-4711", "case", "42"),
            "diagnosis": SourceReference("claims", "claim-4711", "diagnosis", "42"),
        },
        {"name": DataClass.PERSON, "case": DataClass.CASE_ID, "diagnosis": DataClass.HEALTH_DATA},
        lease_id,
        origin_scope="CASE:4711",
    )
    typer.echo("MODEL VIEW")
    for key, value in model_view.items():
        typer.echo(f"{key}: {value}")

    call = guard.authorize_tool_call(
        {"case": model_view["case"], "status": "REVIEW_COMPLETE"},
        lease_id=lease_id,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
        passthrough_fields={"status"},
    )
    response = target.execute(
        call,
        lambda args: {"case": args["case"], "status": args["status"]},
        response_schema={"case": DataClass.CASE_ID, "status": DataClass.PUBLIC},
    )
    typer.echo(f"\nMODEL-FACING TARGET RESPONSE: {response}")

    # The same guarded call model can be submitted as a bounded async job.
    call2 = guard.authorize_tool_call(
        {"case": model_view["case"]},
        lease_id=lease_id,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(call2, response_schema={"case": DataClass.CASE_ID}, deadline_seconds=60)
    runtime.destroy_lease(lease_id)
    jobs.execute(job, lambda args, idempotency_key=None: {"case": args["case"]})
    retrieved = jobs.get_result(
        job,
        tenant_id="default",
        agent_id="unknown-external-agent",
        purpose="CLAIM_REVIEW",
        scope="CASE:4711:RESULT",
        allowed_operations={"SOURCE_SYSTEM": ["LOOKUP"]},
    )
    typer.echo(f"ASYNC RESULT: {retrieved}")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise typer.BadParameter("Install blueberryme[api] to run the gateway") from exc
    uvicorn.run("blueberryme.api:app", host=host, port=port, reload=False)


@app.command()
def keygen(path: Path = typer.Argument(..., help="Key file to create; keep it outside the state directory.")) -> None:
    """Create a new 32-byte master key file (mode 0600)."""
    from .keys import write_master_key_file

    try:
        written = write_master_key_file(path)
    except FileExistsError as exc:
        raise typer.BadParameter(f"{path} already exists; refusing to overwrite") from exc
    typer.echo(f"Wrote master key to {written}")
    typer.echo(f"Start the gateway with BBM_MASTER_KEY_FILE={written}")


@app.command()
def version() -> None:
    typer.echo("0.3.0")


if __name__ == "__main__":
    app()
