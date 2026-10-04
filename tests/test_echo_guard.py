"""Round-trip laundering: a target echoes resolved plaintext back towards the model."""
from blueberryme.jobs import AsyncJobGateway
from blueberryme.models import DataClass, SourceReference
from blueberryme.proxy import StructuredToolGuard, TargetAdapter
from blueberryme.references import MemorySourceAdapter


def _letter_call(runtime, lease, name="Max Mustermann"):
    person = runtime.protect_value(name, DataClass.PERSON, lease)
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"recipient": person},
        lease_id=lease,
        target="LETTER_SERVICE",
        operation="DELIVER",
        reference_fields={"recipient": DataClass.PERSON},
    )
    return person, call


def test_echo_in_public_free_text_is_replaced_by_agents_handle(runtime, lease):
    person, call = _letter_call(runtime, lease)
    response = TargetAdapter(runtime, target_id="LETTER_SERVICE").execute(
        call,
        lambda args: {"summary": f"Letter sent to {args['recipient']} (Dear {args['recipient']},)"},
        response_schema={"summary": DataClass.PUBLIC},
    )
    assert response["ok"] is True
    assert "Max Mustermann" not in str(response)
    assert response["result"]["summary"] == f"Letter sent to {person} (Dear {person},)"


def test_echo_in_declared_field_returns_the_same_handle(runtime, lease):
    person, call = _letter_call(runtime, lease)
    response = TargetAdapter(runtime, target_id="LETTER_SERVICE").execute(
        call,
        lambda args: {"recipient": args["recipient"], "status": "SENT"},
        response_schema={"recipient": DataClass.PERSON, "status": DataClass.PUBLIC},
    )
    assert response["result"] == {"recipient": person, "status": "SENT"}


def test_echo_in_nested_structures_and_keys(runtime, lease):
    person, call = _letter_call(runtime, lease)
    response = TargetAdapter(runtime, target_id="LETTER_SERVICE").execute(
        call,
        lambda args: {"log": {"lines": [f"to={args['recipient']}"], args["recipient"]: "addressee"}},
        response_schema={"log": DataClass.PUBLIC},
    )
    assert "Max Mustermann" not in str(response)
    assert response["result"]["log"]["lines"] == [f"to={person}"]
    assert response["result"]["log"][person] == "addressee"


def test_short_resolved_values_only_replace_exact_leaves(runtime, lease):
    # "Li" would corrupt "Lieferung" if replaced as a substring.
    person, call = _letter_call(runtime, lease, name="Li")
    response = TargetAdapter(runtime, target_id="LETTER_SERVICE").execute(
        call,
        lambda args: {"status": "Lieferung erfolgt", "who": args["recipient"]},
        response_schema={"status": DataClass.PUBLIC, "who": DataClass.PUBLIC},
    )
    assert response["result"] == {"status": "Lieferung erfolgt", "who": person}


def test_echoed_secret_is_removed_not_tokenised(runtime, lease):
    secret = "github_pat_DO_NOT_LEAK_12345678901234567890"
    cap = runtime.create_capability(secret, lease, target="GITHUB", operation="WRITE_REPO")
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"credential": cap},
        lease_id=lease,
        target="GITHUB",
        operation="WRITE_REPO",
        reference_fields={},
        capability_fields={"credential"},
    )
    response = TargetAdapter(runtime, target_id="GITHUB").execute(
        call,
        lambda args: {"debug": f"auth header was Bearer {args['credential']}"},
        response_schema={"debug": DataClass.PUBLIC},
    )
    assert secret not in str(response)
    assert response["result"]["debug"] == "auth header was Bearer [BBM:SECRET:REMOVED]"


def test_async_echo_is_scrubbed_with_handle_from_new_lease(runtime, lease):
    runtime.register_source("claims", MemorySourceAdapter({"9": {"name": "Erika Musterfrau"}}, versions={"9": "1"}))
    view = runtime.protect_reference_record(
        {"name": SourceReference("claims", "9", "name", "1")}, {"name": DataClass.PERSON}, lease
    )
    call = StructuredToolGuard(runtime).authorize_tool_call(
        {"name": view["name"]},
        lease_id=lease,
        target="LETTER_SERVICE",
        operation="DELIVER",
        reference_fields={"name": DataClass.PERSON},
    )
    jobs = AsyncJobGateway(runtime)
    job = jobs.submit(
        call, response_schema={"name": DataClass.PERSON, "note": DataClass.PUBLIC}, deadline_seconds=60
    )
    jobs.execute(job, lambda args: {"name": args["name"], "note": f"Delivered to {args['name']}"})
    out = jobs.get_result(job, tenant_id="tenant-a", agent_id="agent-test", purpose="CLAIM_REVIEW", scope="R")
    assert "Erika Musterfrau" not in str(out)
    handle = out["result"]["name"]
    assert handle.startswith("BBM1H.PERSON.")
    # One entity, one handle inside the new lease: field and free text agree.
    assert out["result"]["note"] == f"Delivered to {handle}"
