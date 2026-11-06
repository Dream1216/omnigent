"""Canonical, private STS documents shared by the issuer and Volume client."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from saas.production.aliyun_storage import AliyunStorageError
from saas.production.tenant_model_keys import _read_file


def encode_sts_document(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_sts_secrets(value: dict[str, Any]) -> None:
    for name, minimum, maximum in (
        ("access_key_id", 12, 256),
        ("access_key_secret", 16, 512),
        ("security_token", 16, 16384),
    ):
        text = value[name]
        if (
            not isinstance(text, str)
            or not minimum <= len(text) <= maximum
            or any(ord(c) < 33 or ord(c) > 126 for c in text)
        ):
            raise ValueError
    if not value["access_key_id"].startswith("STS."):
        raise ValueError


def validate_sts_document(raw: bytes, *, now: float) -> dict[str, Any]:
    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "issued_at",
                "expires_at",
                "access_key_id",
                "access_key_secret",
                "security_token",
            }
            or raw != encode_sts_document(value)
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["issued_at"]) is not int
            or type(value["expires_at"]) is not int
            or value["issued_at"] > now + 30
            or value["expires_at"] <= now + 30
            or not 1 <= value["expires_at"] - value["issued_at"] <= 3600
        ):
            raise ValueError
        validate_sts_secrets(value)
        return value
    except (ValueError, TypeError, KeyError):
        raise AliyunStorageError("Aliyun volume STS credential is invalid or expired") from None


def read_sts_document(path: Path, *, now: float) -> dict[str, Any]:
    try:
        return validate_sts_document(_read_file(path, private=True, maximum=32768), now=now)
    except (ValueError, OSError):
        raise AliyunStorageError("Aliyun volume STS credential is invalid or expired") from None
