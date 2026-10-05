from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import typer

from .jobs import AsyncJobGateway
from .models import DataClass, SourceReference
from .policy import load_policy
from .proxy import StructuredToolGuard, TargetAdapter
from .references import MemorySourceAdapter
from .runtime import BlueberryRuntime
from .zone import ZoneProfile, run_agent as run_agent_in_zone, zone_check as run_zone_check, zone_check_summary

app = typer.Typer(add_completion=False, help="BlueberryMe v0.4.4 reference runtime")


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
    )
    typer.echo(f"ASYNC RESULT: {retrieved}")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the HTTP gateway. Requires BBM_CONTROL_TOKEN and BBM_AGENT_TOKENS."""
    try:
        import uvicorn
    except ImportError as exc:
        raise typer.BadParameter("Install blueberryme[api] to run the gateway") from exc
    if os.environ.get("BBM_INSECURE_DEV") == "1":
        typer.echo("WARNING: BBM_INSECURE_DEV=1 - gateway authentication is DISABLED. Never use this outside a laptop.", err=True)
    elif not os.environ.get("BBM_CONTROL_TOKEN") or not os.environ.get("BBM_AGENT_TOKENS"):
        typer.echo(
            "BBM_CONTROL_TOKEN and BBM_AGENT_TOKENS are not set: every request will be refused (503).\n"
            "Generate tokens with 'blueberryme gen-token'.",
            err=True,
        )
    uvicorn.run("blueberryme.api:app", host=host, port=port, reload=False)


@app.command("zone-check")
def zone_check_cmd(
    gateway_host: list[str] | None = typer.Option(None, "--gateway-host"),
    llm_host: list[str] | None = typer.Option(None, "--llm-host"),
    source_host: list[str] | None = typer.Option(None, "--source-host"),
    target_host: list[str] | None = typer.Option(None, "--target-host"),
    timeout: float = typer.Option(0.5, min=0.05, max=10.0),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Probe whether the current process zone has an obvious route around BBM."""
    profile = ZoneProfile(
        gateway_hosts=tuple(gateway_host or ()),
        llm_hosts=tuple(llm_host or ()),
        source_hosts=tuple(source_host or ()),
        target_hosts=tuple(target_host or ()),
    )
    summary = zone_check_summary(run_zone_check(profile, timeout=timeout))
    if json_output:
        typer.echo(json.dumps(summary, indent=2, default=str))
    else:
        for probe in summary["probes"]:
            typer.echo(f'{probe["status"]:>4}  {probe["name"]}: {probe["detail"]}')
        typer.echo(f'BOUNDARY CONFORMANCE: {"PASS" if summary["pass"] else "FAIL"}')
    if not summary["pass"]:
        raise typer.Exit(code=1)


@app.command("run-agent", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run_agent_cmd(
    ctx: typer.Context,
    workspace: str = typer.Option(".", "--workspace"),
    gateway_host: list[str] | None = typer.Option(None, "--gateway-host"),
    llm_host: list[str] | None = typer.Option(None, "--llm-host"),
    keep_env: list[str] | None = typer.Option(None, "--keep-env"),
    srt_binary: str = typer.Option("srt", "--srt-binary"),
) -> None:
    """Run an agent command through Anthropic srt using a BBM restrictive profile."""
    if not ctx.args:
        raise typer.BadParameter("Provide the agent command after BBM options")
    profile = ZoneProfile(
        workspace=workspace,
        gateway_hosts=tuple(gateway_host or ()),
        llm_hosts=tuple(llm_host or ()),
        keep_env=tuple(keep_env or ()),
        srt_binary=srt_binary,
    )
    try:
        code = run_agent_in_zone(profile, list(ctx.args))
    except (RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    raise typer.Exit(code=code)


@app.command("gen-token")
def gen_token() -> None:
    """Print a fresh random gateway token (control or agent)."""
    typer.echo(secrets.token_urlsafe(32))


@app.command()
def version() -> None:
    typer.echo("0.4.4")


if __name__ == "__main__":
    app()
