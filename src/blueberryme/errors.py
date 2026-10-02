from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    LEASE_UNKNOWN = "BBM_LEASE_UNKNOWN"
    LEASE_REVOKED = "BBM_LEASE_REVOKED"
    LEASE_EXPIRED = "BBM_LEASE_EXPIRED"
    TARGET_DENIED = "BBM_TARGET_DENIED"
    OPERATION_DENIED = "BBM_OPERATION_DENIED"
    POLICY_DENIED = "BBM_POLICY_DENIED"
    TOKEN_INVALID = "BBM_TOKEN_INVALID"
    TOKEN_CLASS_MISMATCH = "BBM_TOKEN_CLASS_MISMATCH"
    CAPABILITY_DENIED = "BBM_CAPABILITY_DENIED"
    DATA_INVALID = "BBM_DATA_INVALID"
    STRUCTURE_DENIED = "BBM_STRUCTURE_DENIED"


class BlueberryError(RuntimeError):
    code: ErrorCode = ErrorCode.POLICY_DENIED

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    def safe_detail(self) -> dict[str, str]:
        return {"code": self.code.value, "message": str(self)}


class LeaseDenied(BlueberryError):
    pass


class PolicyDenied(BlueberryError):
    pass


class CapabilityDenied(BlueberryError):
    code = ErrorCode.CAPABILITY_DENIED


class DataQualityError(BlueberryError):
    code = ErrorCode.DATA_INVALID


class StructureDenied(BlueberryError):
    code = ErrorCode.STRUCTURE_DENIED
