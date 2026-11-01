"""One-shot dead-letter review/replay; no online signer or provider authority."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from uuid import UUID

from saas.control_plane.identity_events import _unique_object
from saas.control_plane.identity_inbox import IdentitySyncPolicy
from saas.control_plane.identity_replay import (
    IdentityDeadLetterService,
    IdentityReplayError,
    IdentityReplayKeyring,
)
from saas.production.credential_worker_config import (
    CredentialWorkerDatabaseLimits,
    create_credential_worker_sessions,
    load_credential_maintenance_config,
)
from saas.production.server import verify_installed_build_lineage
from saas.production.server_config import (
    ProductionServerConfigError,
    _absolute_regular_file,
    _required,
)

_KEYS = "OMNIGENT_SAAS_IDENTITY_REPLAY_KEYS_FILE"


def load_identity_replay_config(source: Mapping[str, str]):
    release = load_credential_maintenance_config(source, extra_inputs=frozenset({_KEYS}))
    try:
        path = _absolute_regular_file(_required(source, _KEYS), name=_KEYS, owner_only=True)
        if path.stat().st_size > 8192:
            raise ValueError
        document = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "keys"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["keys"], dict)
            or any(
                not isinstance(value, str) or len(value) != 64 or value != value.lower()
                for value in document["keys"].values()
            )
        ):
            raise ValueError
        keys = IdentityReplayKeyring(
            {key: bytes.fromhex(value) for key, value in document["keys"].items()}
        )
        return release, keys
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ProductionServerConfigError(
            "identity replay verification keys are invalid"
        ) from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="operation", required=True)
    listing = subcommands.add_parser("list")
    listing.add_argument("--limit", type=int, default=50)
    review = subcommands.add_parser("review")
    review.add_argument("--inbox-id", type=UUID, required=True)
    review.add_argument("--output", required=True)
    replay = subcommands.add_parser("replay")
    replay.add_argument("--grant-file", required=True)
    args = parser.parse_args()
    sessions = None
    try:
        release, keys = load_identity_replay_config(os.environ)
        verify_installed_build_lineage(release)
        sessions = create_credential_worker_sessions(
            release, limits=CredentialWorkerDatabaseLimits(pool_size=1)
        )
        service = IdentityDeadLetterService(
            sessions.authenticator,
            policy=IdentitySyncPolicy(
                issuer=release.identity.issuer, organization=release.identity.organization
            ),
            product_revision=release.product_revision,
            verification_keys=keys,
        )
        if args.operation == "list":
            result = {"dead_letters": service.list_dead(limit=args.limit)}
        elif args.operation == "review":
            document = service.review(args.inbox_id)
            output = Path(args.output)
            if not output.is_absolute():
                raise ValueError
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(
                    json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                )
            result = {"review_sha256": document["review_sha256"]}
        else:
            grant = _absolute_regular_file(
                args.grant_file, name="identity replay grant", owner_only=True
            )
            if not 1 <= grant.stat().st_size <= 8193:
                raise ValueError
            result = service.replay(grant.read_text().rstrip("\n"))
        print(
            json.dumps({"schema_version": 1, "status": "pass", "result": result}, sort_keys=True)
        )
        return 0
    except Exception as error:  # noqa: BLE001 - never emit database, review or signature contents.
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "fail",
                    "error": error.code
                    if isinstance(error, IdentityReplayError)
                    else "identity_replay_rejected",
                }
            )
        )
        return 1
    finally:
        if sessions is not None:
            with suppress(Exception):
                sessions.close()


if __name__ == "__main__":
    raise SystemExit(main())
