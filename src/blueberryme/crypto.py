from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import DataClass

HANDLE_RE = re.compile(r"^BBM1H\.([A-Z_]+)\.([A-Z2-7]{16})$")
CAPABILITY_RE = re.compile(r"^BBM1C\.([A-Z2-7]{16})$")
JOB_HANDLE_RE = re.compile(r"^BBM1J\.([A-Z2-7]{20})$")
REFERENCE_SEARCH_RE = re.compile(r"BBM1(?:H\.[A-Z_]+|C)\.[A-Z2-7]{16}")


class CryptoError(ValueError):
    pass


def _b32(nbytes: int) -> str:
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def random_handle(data_class: DataClass) -> str:
    return f"BBM1H.{data_class.value}.{_b32(10)}"


def random_capability_handle() -> str:
    return f"BBM1C.{_b32(10)}"


def random_job_handle() -> str:
    return f"BBM1J.{_b32(13)[:20]}"


def parse_handle(handle: str) -> DataClass:
    match = HANDLE_RE.fullmatch(handle)
    if not match:
        raise CryptoError("Invalid BBM/1 handle format")
    try:
        return DataClass(match.group(1))
    except ValueError as exc:
        raise CryptoError("Unknown BBM/1 data class") from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def args_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def derive_key(master_key: bytes, label: str, context: bytes = b"") -> bytes:
    if len(master_key) < 32:
        raise CryptoError("Master key must be at least 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"BlueberryMe/0.3/" + label.encode("utf-8") + b"/" + context,
    ).derive(master_key)


def sign_bytes(key: bytes, payload: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(key, payload, hashlib.sha256).digest()).decode("ascii").rstrip("=")


def verify_signature(key: bytes, payload: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign_bytes(key, payload), signature)


def seal(key: bytes, plaintext: bytes, *, aad: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("Authenticated data could not be opened") from exc
