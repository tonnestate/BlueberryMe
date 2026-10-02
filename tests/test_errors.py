from blueberryme.errors import SafeTargetError
from blueberryme.models import DataClass
from blueberryme.proxy import StructuredToolGuard, TargetAdapter


def test_target_exception_text_never_reaches_agent(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="PAYMENT_SERVICE")
    iban = runtime.protect_value("DE89370400440532013000", DataClass.IBAN, lease)
    call = guard.authorize_tool_call(
        {"iban": iban},
        lease_id=lease,
        target="PAYMENT_SERVICE",
        operation="PAY",
        reference_fields={"iban": DataClass.IBAN},
    )

    def handler(args):
        raise ValueError(f"Invalid IBAN {args['iban']}")

    response = target.execute(call, handler, response_schema={})
    assert response["error"]["code"] == "BBM_TARGET_ERROR"
    assert "DE89" not in str(response)


def test_catalog_target_error_only(runtime, lease):
    guard = StructuredToolGuard(runtime)
    target = TargetAdapter(runtime, target_id="SOURCE_SYSTEM")
    case = runtime.protect_value("UV-4711", DataClass.CASE_ID, lease)
    call = guard.authorize_tool_call(
        {"case": case},
        lease_id=lease,
        target="SOURCE_SYSTEM",
        operation="LOOKUP",
        reference_fields={"case": DataClass.CASE_ID},
    )
    response = target.execute(
        call,
        lambda args: (_ for _ in ()).throw(SafeTargetError("CASE_NOT_READY", retryable=True)),
        response_schema={},
    )
    assert response == {"ok": False, "error": {"code": "CASE_NOT_READY", "retryable": True}}
