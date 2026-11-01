"""Private bounded batches using the release-verified authenticator login only."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict
from typing import cast
from uuid import UUID

from saas.control_plane.credential_migration import (
    CredentialMigrationError,
    CredentialMigrationService,
    CredentialMigrationView,
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
from saas.production.postgresql_migration import verify_production_postgresql_state
from saas.production.server import create_role_session_factories, verify_installed_build_lineage
from saas.production.server_config import (
    _absolute_regular_file,
    load_production_server_config,
)


def load_batch(path: str, *, prepare: bool) -> list[dict[str, object]]:
    try:
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
            if not isinstance(item, dict) or set(item) != fields:
                raise ValueError
            name = "user_id" if prepare else "receipt_id"
            if not isinstance(item[name], str) or str(UUID(item[name])) != item[name]:
                raise ValueError
            if item[name] in seen:
                raise ValueError
            seen.add(item[name])
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
    for action in ("prepare", "process", "show"):
        command = subcommands.add_parser(action)
        command.add_argument("--batch-file", required=True)
        if action == "process":
            command.add_argument("--cutover", action="store_true")
    command = subcommands.add_parser("recover")
    command.add_argument("--grant-file", required=True)
    command.add_argument("--secret-file", required=True)
    args = parser.parse_args()
    # Parse private inputs before opening any database authority.
    batch = None
    if args.action != "recover":
        batch = load_batch(args.batch_file, prepare=args.action == "prepare")
    config = load_production_server_config()
    verify_installed_build_lineage(config)

    def verify(engines, server_config):
        verify_production_postgresql_state(engines=engines, config=server_config)

    sessions = create_role_session_factories(config, verify_state=verify)
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
        provider_config = load_casdoor_credential_import_config(
            os.environ, identity=config.identity
        )
        service = CredentialMigrationService(
            sessions.authenticator,
            policy=provider_config.policy(),
            provider=CasdoorCredentialImportProvider(provider_config),
        )
        assert batch is not None
        failed = False
        for item in batch:
            try:
                if args.action == "prepare":
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
