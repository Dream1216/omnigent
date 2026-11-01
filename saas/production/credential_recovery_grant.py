"""Offline recovery authorization; this command never opens a database or provider API."""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from omnigent.server.passwords import hash_password
from saas.control_plane.credential_recovery import (
    RECOVERY_SIGNATURE_DOMAIN,
    CredentialRecoveryKeyring,
    recovery_grant_payload,
)
from saas.control_plane.identity import PasswordCredentialService
from saas.production.server_config import _absolute_regular_file


def issue_grant(
    *,
    request_file: str,
    password_file: str,
    signing_key_file: str,
    key_id: str,
    output_directory: str,
    now: datetime | None = None,
) -> Path:
    """Sign the exact operator-reviewed target and a newly hashed recovery secret."""
    request = json.loads(
        _absolute_regular_file(request_file, name="recovery request", owner_only=True).read_bytes()
    )
    if not isinstance(request, dict) or set(request) != {
        "user_id",
        "receipt_id",
        "expected_security_version",
        "review_reference",
        "reason_code",
    }:
        raise ValueError("recovery request is invalid")
    private_key = load_pem_private_key(
        _absolute_regular_file(
            signing_key_file, name="offline signing key", owner_only=True
        ).read_bytes(),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("recovery signing key must use Ed25519")
    password = (
        _absolute_regular_file(password_file, name="fresh recovery password", owner_only=True)
        .read_text()
        .rstrip("\r\n")
    )
    PasswordCredentialService._validate_new_password(password)
    new_hash = hash_password(password)
    issued_at = now or datetime.now(timezone.utc)
    document = {
        **request,
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "new_password_hash_sha256": sha256(new_hash.encode()).hexdigest(),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
    }
    payload = recovery_grant_payload(document)
    signature = private_key.sign(RECOVERY_SIGNATURE_DOMAIN + payload)
    encoded = [
        base64.urlsafe_b64encode(value).decode().rstrip("=") for value in (payload, signature)
    ]
    token = ".".join(("v1", key_id, *encoded))
    CredentialRecoveryKeyring({key_id: private_key.public_key().public_bytes_raw()}).verify(
        token, now=issued_at
    )
    output = Path(output_directory)
    if not output.is_absolute():
        raise ValueError("recovery output directory must be absolute")
    # A new private directory prevents overwrite, symlink substitution and mixing
    # a grant with the secret from an earlier request.
    output.mkdir(mode=0o700)
    for name, content in (
        ("grant.txt", token + "\n"),
        (
            "secret.json",
            json.dumps({"new_password": password, "new_password_hash": new_hash}) + "\n",
        ),
        ("request.json", json.dumps(document, sort_keys=True, indent=2) + "\n"),
    ):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "request-file",
        "password-file",
        "signing-key-file",
        "key-id",
        "output-directory",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        output = issue_grant(**vars(args))
        print(json.dumps({"output_directory": str(output), "expires_in_seconds": 300}))
    except Exception:  # noqa: BLE001 - keep secret files and key material out of tracebacks.
        print(json.dumps({"error": "credential_recovery_authorization_failed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
