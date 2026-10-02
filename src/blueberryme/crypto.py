from __future__ import annotations

import base64
import hashlib
import hmac
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .models import DataClass, Lease

TOKEN_RE = re.compile(r"^BBM1\.([A-Z_]+)\.([A-Za-z0-9_-]+)$")
HANDLE_RE = re.compile(r"^BBM1H\.([A-Z_]+)\.([A-Z2-7]{12})$")
CAPABILITY_RE = re.compile(r"^BBM1-CAP\.([A-Za-z0-9_-]{16,})$")
REFERENCE_SEARCH_RE = re.compile(r"BBM1(?:H)?\.[A-Z_]+\.[A-Za-z0-9_-]+")


class TokenError(ValueError):
    pass


def _aad(lease: Lease, data_class: DataClass) -> list[bytes]:
    return [
        b"BBM/1",
        data_class.value.encode("utf-8"),
        lease.purpose.encode("utf-8"),
        lease.scope.encode("utf-8"),
    ]


def tokenize(value: str, data_class: DataClass, lease: Lease) -> str:
    cipher = AESSIV(bytes(lease.key))
    encrypted = cipher.encrypt(value.encode("utf-8"), _aad(lease, data_class))
    body = base64.urlsafe_b64encode(encrypted).decode("ascii").rstrip("=")
    return f"BBM1.{data_class.value}.{body}"


def short_handle(token: str, data_class: DataClass, lease: Lease) -> str:
    digest = hmac.new(bytes(lease.key), token.encode("utf-8"), hashlib.sha256).digest()
    body = base64.b32encode(digest).decode("ascii").rstrip("=")[:12]
    return f"BBM1H.{data_class.value}.{body}"


def parse_token(token: str) -> tuple[DataClass, bytes]:
    match = TOKEN_RE.fullmatch(token)
    if not match:
        raise TokenError("Invalid BBM/1 crypto token format")
    try:
        data_class = DataClass(match.group(1))
    except ValueError as exc:
        raise TokenError("Unknown BBM/1 data class") from exc
    body = match.group(2)
    padded = body + "=" * ((4 - len(body) % 4) % 4)
    try:
        ciphertext = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise TokenError("Invalid BBM/1 token encoding") from exc
    return data_class, ciphertext


def parse_handle(handle: str) -> DataClass:
    match = HANDLE_RE.fullmatch(handle)
    if not match:
        raise TokenError("Invalid BBM/1 lease handle format")
    try:
        return DataClass(match.group(1))
    except ValueError as exc:
        raise TokenError("Unknown BBM/1 data class") from exc


def rehydrate(token: str, lease: Lease) -> tuple[DataClass, str]:
    data_class, ciphertext = parse_token(token)
    cipher = AESSIV(bytes(lease.key))
    try:
        plaintext = cipher.decrypt(ciphertext, _aad(lease, data_class))
    except InvalidTag as exc:
        raise TokenError("Token authentication failed for this lease/scope/purpose") from exc
    return data_class, plaintext.decode("utf-8")
