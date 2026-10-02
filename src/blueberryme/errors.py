from __future__ import annotations

from enum import StrEnum

from .models import FailureClass


class ErrorCode(StrEnum):
    LEASE_UNKNOWN = "BBM_LEASE_UNKNOWN"
    LEASE_REVOKED = "BBM_LEASE_REVOKED"
    LEASE_EXPIRED = "BBM_LEASE_EXPIRED"
    TARGET_DENIED = "BBM_TARGET_DENIED"
    OPERATION_DENIED = "BBM_OPERATION_DENIED"
    POLICY_DENIED = "BBM_POLICY_DENIED"
    HANDLE_INVALID = "BBM_HANDLE_INVALID"
    HANDLE_CLASS_MISMATCH = "BBM_HANDLE_CLASS_MISMATCH"
    CAPABILITY_DENIED = "BBM_CAPABILITY_DENIED"
    DATA_INVALID = "BBM_DATA_INVALID"
    STRUCTURE_DENIED = "BBM_STRUCTURE_DENIED"
    INTENT_INVALID = "BBM_INTENT_INVALID"
    INTENT_EXPIRED = "BBM_INTENT_EXPIRED"
    INTENT_REPLAY = "BBM_INTENT_REPLAY"
    VALUE_DRIFT = "BBM_VALUE_DRIFT"
    SOURCE_UNAVAILABLE = "BBM_SOURCE_UNAVAILABLE"
    TARGET_ERROR = "BBM_TARGET_ERROR"
    INFRASTRUCTURE_UNAVAILABLE = "BBM_INFRASTRUCTURE_UNAVAILABLE"
    PURPOSE_REVOKED = "BBM_PURPOSE_REVOKED"
    JOB_UNKNOWN = "BBM_JOB_UNKNOWN"
    JOB_CANCELLED = "BBM_JOB_CANCELLED"
    JOB_EXPIRED = "BBM_JOB_EXPIRED"
    JOB_NOT_READY = "BBM_JOB_NOT_READY"
    JOB_RESULT_EXPIRED = "BBM_JOB_RESULT_EXPIRED"
    JOB_ALREADY_RUNNING = "BBM_JOB_ALREADY_RUNNING"
    JOB_PURPOSE_MISMATCH = "BBM_JOB_PURPOSE_MISMATCH"
    BAD_REQUEST = "BBM_BAD_REQUEST"


class BlueberryError(RuntimeError):
    code: ErrorCode = ErrorCode.POLICY_DENIED
    failure_class: FailureClass = FailureClass.POLICY

    def __init__(self, message: str = "BlueberryMe request denied", *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    def safe_detail(self) -> dict[str, str]:
        return {"code": self.code.value, "class": self.failure_class.value}


class LeaseDenied(BlueberryError):
    pass


class PolicyDenied(BlueberryError):
    pass


class CapabilityDenied(BlueberryError):
    code = ErrorCode.CAPABILITY_DENIED


class DataQualityError(BlueberryError):
    code = ErrorCode.DATA_INVALID
    failure_class = FailureClass.DATA_QUALITY


class StructureDenied(BlueberryError):
    code = ErrorCode.STRUCTURE_DENIED


class InfrastructureError(BlueberryError):
    code = ErrorCode.INFRASTRUCTURE_UNAVAILABLE
    failure_class = FailureClass.INFRASTRUCTURE


class RehydrationError(BlueberryError):
    code = ErrorCode.HANDLE_INVALID
    failure_class = FailureClass.REHYDRATION


class IntentDenied(RehydrationError):
    code = ErrorCode.INTENT_INVALID


class ValueDriftError(RehydrationError):
    code = ErrorCode.VALUE_DRIFT


class SourceUnavailable(InfrastructureError):
    code = ErrorCode.SOURCE_UNAVAILABLE


class JobError(BlueberryError):
    code = ErrorCode.JOB_UNKNOWN


class SafeTargetError(Exception):
    """Target-visible error carrying only a catalogue code, never target exception text."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
