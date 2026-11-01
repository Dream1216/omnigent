"""Private bounded batches using the release-verified authenticator login only."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import cast
from uuid import UUID

from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationService,
    CredentialMigrationView,
)
from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.credential_reconnection import (
    CredentialReconnectionKeyring,
    CredentialReconnectionService,
)
from saas.control_plane.credential_recovery import (
    CredentialRecoverySecret,
    CredentialRecoveryService,
)
from saas.production.credential_migration import (
    CasdoorCredentialImportProvider,
    load_casdoor_credential_import_config,
    load_credential_recovery_keys,
)
from saas.production.credential_worker_config import (
    create_credential_worker_sessions,
    load_credential_worker_config,
)
from saas.production.server import verify_installed_build_lineage
from saas.production.server_config import _absolute_regular_file


def load_batch(
    path: str, *, prepare: bool, existing_link: bool = False
) -> list[dict[str, object]]:
    try:
        if existing_link and not prepare:
            raise ValueError
        document = json.loads(
            _absolute_regular_file(path, name="credential batch", owner_only=True).read_bytes()
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "items"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["items"], list)
            or not 1 <= len(document["items"]) <= 1000
        ):
            raise ValueError
        seen = set()
        for item in document["items"]:
            fields = (
                {"user_id", "batch_id", "expected_password_version", "idempotency_key"}
                if prepare
                else {"receipt_id"}
            )
            if existing_link:
                fields.add("connection_id")
            if not isinstance(item, dict) or set(item) != fields:
                raise ValueError
            name = "user_id" if prepare else "receipt_id"
            if not isinstance(item[name], str) or str(UUID(item[name])) != item[name]:
                raise ValueError
            if item[name] in seen:
                raise ValueError
            seen.add(item[name])
            if existing_link and (
                not isinstance(item["connection_id"], str)
                or str(UUID(item["connection_id"])) != item["connection_id"]
            ):
                raise ValueError
            if prepare and (
                type(item["expected_password_version"]) is not int
                or item["expected_password_version"] <= 0
                or any(not isinstance(item[key], str) for key in ("batch_id", "idempotency_key"))
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item["batch_id"])
                or not 1 <= len(item["idempotency_key"]) <= 128
            ):
                raise ValueError
        return document["items"]
    except (OSError, UnicodeError, ValueError, TypeError):
        raise CredentialMigrationError("migration_batch_invalid") from None


def _emit(view: CredentialMigrationView) -> None:
    print(json.dumps(asdict(view), default=str, sort_keys=True), flush=True)


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "prepare-linked", "process", "show"):
        command = subcommands.add_parser(action)
        command.add_argument("--batch-file", required=True)
        if action == "process":
            command.add_argument("--cutover", action="store_true")
    command = subcommands.add_parser("recover")
    command.add_argument("--grant-file", required=True)
    command.add_argument("--secret-file", required=True)
    command = subcommands.add_parser("reconnect-request")
    command.add_argument("--user-id", required=True, type=UUID)
    command.add_argument("--receipt-id", required=True, type=UUID)
    command.add_argument("--review-reference", required=True)
    command.add_argument("--output-file", required=True)
    command = subcommands.add_parser("reconnect")
    command.add_argument("--grant-file", required=True)
    args = parser.parse_args()
    # Parse private inputs before opening any database authority.
    batch = None
    if args.action in {"prepare", "prepare-linked", "process", "show"}:
        batch = load_batch(
            args.batch_file,
            prepare=args.action in {"prepare", "prepare-linked"},
            existing_link=args.action == "prepare-linked",
        )
    config = load_credential_worker_config()
    verify_installed_build_lineage(config)
    sessions = create_credential_worker_sessions(config)
    try:
        if args.action == "recover":
            grant = (
                _absolute_regular_file(
                    args.grant_file, name="credential recovery grant", owner_only=True
                )
                .read_text()
                .strip()
            )
            secret = json.loads(
                _absolute_regular_file(
                    args.secret_file, name="credential recovery secret", owner_only=True
                ).read_bytes()
            )
            if (
                not isinstance(secret, dict)
                or set(secret) != {"new_password", "new_password_hash"}
                or any(not isinstance(value, str) for value in secret.values())
            ):
                raise CredentialMigrationError("credential_recovery_secret_mismatch")
            recovery = CredentialRecoveryService(
                sessions.authenticator, verification_keys=load_credential_recovery_keys(os.environ)
            )
            _emit(recovery.recover(signed_grant=grant, secret=CredentialRecoverySecret(**secret)))
            return
        requires_import = args.action == "prepare"
        if args.action == "process":
            assert batch is not None
            with sessions.authenticator() as db:
                requires_import = any(
                    record is not None and record.mode == "hash_import"
                    for item in batch
                    for record in [
                        db.get(CredentialMigrationRecord, UUID(str(item["receipt_id"])))
                    ]
                )
        if args.action == "show":
            assert batch is not None
            with sessions.authenticator() as db:
                for item in batch:
                    record = db.get(CredentialMigrationRecord, UUID(str(item["receipt_id"])))
                    if record is None:
                        raise CredentialMigrationError("migration_receipt_unavailable")
                    _emit(CredentialMigrationService._view(record))
            return
        provider_config = load_casdoor_credential_import_config(
            os.environ, identity=config.identity, require_import_keys=requires_import
        )
        provider = CasdoorCredentialImportProvider(provider_config)
        if args.action in {"reconnect-request", "reconnect"}:
            keys = load_credential_recovery_keys(
                os.environ, key_name="OMNIGENT_SAAS_CREDENTIAL_RECONNECTION_PUBLIC_KEYS_FILE"
            )
            reconnection = CredentialReconnectionService(
                sessions.authenticator,
                policy=provider_config.policy(),
                provider=provider,
                verification_keys=CredentialReconnectionKeyring(keys.public_keys),
            )
            if args.action == "reconnect-request":
                request = reconnection.prepare_request(
                    user_id=args.user_id,
                    receipt_id=args.receipt_id,
                    review_reference=args.review_reference,
                )
                output = Path(args.output_file)
                if not output.is_absolute() or ".." in output.parts:
                    raise CredentialMigrationError("credential_reconnection_request_invalid")
                descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as handle:
                    handle.write(json.dumps(request, sort_keys=True, indent=2) + "\n")
                print(json.dumps({"request_file": str(output)}))
            else:
                token = (
                    _absolute_regular_file(
                        args.grant_file, name="credential reconnection grant", owner_only=True
                    )
                    .read_text()
                    .strip()
                )
                identifier = reconnection.reconnect(signed_grant=token)
                print(json.dumps({"connection_id": str(identifier)}))
            return
        service = CredentialMigrationService(
            sessions.authenticator,
            policy=provider_config.policy(),
            provider=provider,
        )
        assert batch is not None
        failed = False
        for item in batch:
            try:
                if args.action == "prepare-linked":
                    view = service.prepare_existing_link(
                        user_id=UUID(str(item["user_id"])),
                        connection_id=UUID(str(item["connection_id"])),
                        batch_id=str(item["batch_id"]),
                        expected_password_version=cast(int, item["expected_password_version"]),
                        idempotency_key=str(item["idempotency_key"]),
                    )
                elif args.action == "prepare":
                    view = service.prepare(
                        user_id=UUID(str(item["user_id"])),
                        batch_id=str(item["batch_id"]),
                        expected_password_version=cast(int, item["expected_password_version"]),
                        idempotency_key=str(item["idempotency_key"]),
                    )
                elif args.action == "process":
                    view = service.run_once(UUID(str(item["receipt_id"])), cutover=args.cutover)
                else:
                    view = service.get(UUID(str(item["receipt_id"])))
                _emit(view)
                if args.action == "process" and view.status not in {"completed", "imported"}:
                    failed = True
            except CredentialMigrationError as error:
                failed = True
                print(
                    json.dumps(
                        {
                            "error": error.code,
                            "retryable": error.retryable,
                            **{key: item[key] for key in ("user_id", "receipt_id") if key in item},
                        }
                    ),
                    flush=True,
                )
        if failed:
            raise SystemExit(1)
    finally:
        sessions.close()


def main() -> None:
    try:
        _main()
    except CredentialMigrationError as error:
        print(json.dumps({"error": error.code, "retryable": error.retryable}), flush=True)
        raise SystemExit(1) from None
    except Exception:  # noqa: BLE001 - never expose credentials through operator tracebacks.
        print(json.dumps({"error": "credential_migration_execution_failed"}), flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
