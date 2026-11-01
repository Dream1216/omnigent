"""Sign a server-generated identity return request on an offline review host."""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from saas.control_plane.credential_reconnection import (
    RECONNECTION_REQUEST_FIELDS,
    RECONNECTION_SIGNATURE_DOMAIN,
    CredentialReconnectionKeyring,
)
from saas.control_plane.credential_recovery import recovery_grant_payload
from saas.production.server_config import _absolute_regular_file


def issue_grant(
    *,
    request_file: str,
    signing_key_file: str,
    key_id: str,
    output_directory: str,
    now: datetime | None = None,
) -> Path:
    request = json.loads(
        _absolute_regular_file(
            request_file,
            name="reconnection request",
            owner_only=True,
        ).read_bytes()
    )
    if not isinstance(request, dict) or set(request) != RECONNECTION_REQUEST_FIELDS:
        raise ValueError("reconnection request is invalid")
    key = load_pem_private_key(
        _absolute_regular_file(
            signing_key_file,
            name="offline reconnection signing key",
            owner_only=True,
        ).read_bytes(),
        password=None,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("reconnection signing key must use Ed25519")
    issued = now or datetime.now(timezone.utc)
    document = {
        **request,
        "schema_version": 1,
        "grant_id": str(uuid4()),
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=5)).isoformat(),
    }
    payload = recovery_grant_payload(document)
    encoded = [
        base64.urlsafe_b64encode(value).decode().rstrip("=")
        for value in (
            payload,
            key.sign(RECONNECTION_SIGNATURE_DOMAIN + payload),
        )
    ]
    token = ".".join(("v1", key_id, *encoded))
    CredentialReconnectionKeyring({key_id: key.public_key().public_bytes_raw()}).verify(
        token, now=issued
    )
    output = Path(output_directory)
    if not output.is_absolute():
        raise ValueError("reconnection output directory must be absolute")
    output.mkdir(mode=0o700)
    for name, value in (
        ("grant.txt", token + "\n"),
        ("request.json", json.dumps(document, sort_keys=True, indent=2) + "\n"),
    ):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(value)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("request-file", "signing-key-file", "key-id", "output-directory"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        output = issue_grant(**vars(args))
        print(json.dumps({"output_directory": str(output), "expires_in_seconds": 300}))
    except Exception:  # noqa: BLE001 - offline key and request details stay private.
        print(json.dumps({"error": "credential_reconnection_authorization_failed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
