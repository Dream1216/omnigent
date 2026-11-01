"""Offline dead-letter approval signer; never connects to a database or IdP."""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from saas.control_plane.identity_events import _unique_object
from saas.control_plane.identity_inbox import _utc
from saas.control_plane.identity_replay import (
    IdentityReplayKeyring,
    replay_payload,
    replay_signature_input,
)
from saas.production.server_config import _absolute_regular_file


def issue_grant(
    *,
    review_file: str,
    signing_key_file: str,
    key_id: str,
    review_reference: str,
    reason_code: str,
    output_directory: str,
    now: datetime | None = None,
) -> Path:
    path = _absolute_regular_file(review_file, name="dead-letter review", owner_only=True)
    if not 1 <= path.stat().st_size <= 16384:
        raise ValueError("dead-letter review is invalid")
    request = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    if (
        not isinstance(request, dict)
        or set(request) != {"schema_version", "review", "review_sha256"}
        or type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or not isinstance(request["review"], dict)
        or sha256(replay_payload(request["review"])).hexdigest() != request["review_sha256"]
        or request["review"].get("status") != "dead"
    ):
        raise ValueError("dead-letter review is invalid")
    private = load_pem_private_key(
        _absolute_regular_file(
            signing_key_file, name="offline replay signing key", owner_only=True
        ).read_bytes(),
        password=None,
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("replay signing key must use Ed25519")
    issued = _utc(now)
    document = {
        "schema_version": 1,
        "grant_id": str(uuid4()),
        **{
            name: request["review"][name]
            for name in ("product_revision", "issuer", "organization", "inbox_id")
        },
        "review_sha256": request["review_sha256"],
        "review_reference": review_reference,
        "reason_code": reason_code,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=5)).isoformat(),
    }
    payload = replay_payload(document)
    signature = private.sign(replay_signature_input(key_id, payload))
    token = ".".join(
        (
            "v1",
            key_id,
            *(
                base64.urlsafe_b64encode(value).decode().rstrip("=")
                for value in (payload, signature)
            ),
        )
    )
    IdentityReplayKeyring({key_id: private.public_key().public_bytes_raw()}).verify(
        token, now=issued
    )
    output = Path(output_directory)
    if not output.is_absolute():
        raise ValueError("replay output directory must be absolute")
    output.mkdir(mode=0o700)
    for name, contents in (
        ("grant.txt", token + "\n"),
        ("review.json", json.dumps(request, sort_keys=True) + "\n"),
        ("authorization.json", json.dumps(document, sort_keys=True) + "\n"),
    ):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "review-file",
        "signing-key-file",
        "key-id",
        "review-reference",
        "reason-code",
        "output-directory",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        output = issue_grant(**vars(args))
    except Exception:  # noqa: BLE001 - input files and private keys never enter diagnostics.
        print(json.dumps({"error": "identity_replay_authorization_failed"}))
        return 1
    print(json.dumps({"output_directory": str(output), "expires_in_seconds": 300}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
