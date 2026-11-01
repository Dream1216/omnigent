"""Invalidate restored customer authentication state in an isolated maintenance Job."""

from __future__ import annotations

import argparse
import json
import os
from contextlib import suppress
from pathlib import Path
from uuid import UUID

from saas.control_plane.customer_auth_restore import (
    CustomerAuthRestoreService,
    restore_review_sha256,
)
from saas.control_plane.identity_events import _unique_object
from saas.production.credential_worker_config import (
    CredentialWorkerDatabaseLimits,
    create_credential_worker_sessions,
    load_credential_maintenance_config,
)
from saas.production.server import verify_installed_build_lineage
from saas.production.server_config import _absolute_regular_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    review = commands.add_parser("review")
    review.add_argument("--restore-id", type=UUID, required=True)
    review.add_argument("--backup-set-sha256", required=True)
    review.add_argument("--output", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--review-file", required=True)
    apply.add_argument("--review-sha256", required=True)
    apply.add_argument("--review-reference", required=True)
    args = parser.parse_args()
    sessions = None
    try:
        release = load_credential_maintenance_config(os.environ)
        verify_installed_build_lineage(release)
        sessions = create_credential_worker_sessions(
            release, limits=CredentialWorkerDatabaseLimits(pool_size=1)
        )
        service = CustomerAuthRestoreService(
            sessions.authenticator, product_revision=release.product_revision
        )
        if args.operation == "review":
            document = service.review(
                restore_id=args.restore_id, backup_set_sha256=args.backup_set_sha256
            )
            output = Path(args.output)
            if not output.is_absolute():
                raise ValueError
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
            result = {"review_sha256": restore_review_sha256(document)}
        else:
            path = _absolute_regular_file(
                args.review_file, name="customer restore review", owner_only=True
            )
            if not 1 <= path.stat().st_size <= 65536:
                raise ValueError
            document = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
            if not isinstance(document, dict):
                raise ValueError
            result = service.apply(
                document,
                expected_sha256=args.review_sha256,
                review_reference=args.review_reference,
            )
        print(
            json.dumps({"schema_version": 1, "status": "pass", "result": result}, sort_keys=True)
        )
        return 0
    except Exception:  # noqa: BLE001 - private database and reviewed state never enter diagnostics.
        print(
            json.dumps(
                {"schema_version": 1, "status": "fail", "error": "customer_restore_rejected"}
            )
        )
        return 1
    finally:
        if sessions is not None:
            with suppress(Exception):
                sessions.close()


if __name__ == "__main__":
    raise SystemExit(main())
