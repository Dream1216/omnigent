"""Workspace-scoped bootstrap for a durable external Host credential.

The official Host tunnel already persists a digest and expiry for managed
launch tokens.  This adapter deliberately reuses that narrow capability
surface for an existing external Host row, while keeping lifecycle operations
in the downstream SaaS layer.  Raw tokens are read from mounted files only and
never included in receipts or logs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from omnigent.db.db_models import SqlHost, workspace_scope
from omnigent.host.identity import load_host_tunnel_token

_DATABASE_URL_FILE_ENV = "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE"
_MIN_TOKEN_BYTES = 32
_MAX_TOKEN_BYTES = 4096


class ExternalHostCredentialError(RuntimeError):
    """A redacted external Host lifecycle rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"external Host credential rejected: {code}")


@dataclass(frozen=True, slots=True)
class ExternalHostCredentialReceipt:
    """Non-secret result for an arm or revoke operation."""

    status: str
    workspace_id: int
    host_id: str
    token_sha256: str | None
    expires_at: int | None


def _validate_token(token: str) -> str:
    token = token.strip()
    size = len(token.encode("utf-8"))
    if size < _MIN_TOKEN_BYTES or size > _MAX_TOKEN_BYTES:
        raise ExternalHostCredentialError("token_size_invalid")
    return token


def _bind_workspace(session: Session, workspace_id: int) -> None:
    if workspace_id <= 0:
        raise ExternalHostCredentialError("workspace_invalid")
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            sa.text("SELECT set_config('app.runtime_workspace_id', :value, true)"),
            {"value": str(workspace_id)},
        )


def arm_external_host_credential(
    engine: Engine,
    *,
    workspace_id: int,
    host_id: str,
    token: str,
    ttl_seconds: int,
    expected_token_sha256: str | None = None,
    now: int | None = None,
) -> ExternalHostCredentialReceipt:
    """Arm one existing external Host row with compare-and-swap rotation."""

    token = _validate_token(token)
    if ttl_seconds < 3600 or ttl_seconds > 365 * 24 * 3600:
        raise ExternalHostCredentialError("ttl_invalid")
    token_sha256 = hashlib.sha256(token.encode()).hexdigest()
    if expected_token_sha256 is not None and (
        len(expected_token_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_token_sha256)
    ):
        raise ExternalHostCredentialError("expected_digest_invalid")
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + ttl_seconds

    with workspace_scope(workspace_id), Session(engine) as session, session.begin():
        _bind_workspace(session, workspace_id)
        row = session.execute(
            sa.select(SqlHost)
            .where(SqlHost.workspace_id == workspace_id, SqlHost.host_id == host_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise ExternalHostCredentialError("host_not_found")
        if row.sandbox_provider is not None:
            raise ExternalHostCredentialError("managed_host_forbidden")
        if row.token_hash == token_sha256:
            row.token_expires_at = expires_at
            row.updated_at = issued_at
        else:
            if row.token_hash is not None and row.token_hash != expected_token_sha256:
                raise ExternalHostCredentialError("credential_changed")
            if row.token_hash is None and expected_token_sha256 is not None:
                raise ExternalHostCredentialError("credential_changed")
            row.token_hash = token_sha256
            row.token_expires_at = expires_at
            row.updated_at = issued_at

    return ExternalHostCredentialReceipt(
        status="armed",
        workspace_id=workspace_id,
        host_id=host_id,
        token_sha256=token_sha256,
        expires_at=expires_at,
    )


def revoke_external_host_credential(
    engine: Engine,
    *,
    workspace_id: int,
    host_id: str,
    expected_token: str,
    now: int | None = None,
) -> ExternalHostCredentialReceipt:
    """Revoke only the credential identified by the mounted raw token."""

    expected_sha256 = hashlib.sha256(_validate_token(expected_token).encode()).hexdigest()
    revoked_at = int(time.time()) if now is None else now
    with workspace_scope(workspace_id), Session(engine) as session, session.begin():
        _bind_workspace(session, workspace_id)
        row = session.execute(
            sa.select(SqlHost)
            .where(SqlHost.workspace_id == workspace_id, SqlHost.host_id == host_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise ExternalHostCredentialError("host_not_found")
        if row.sandbox_provider is not None:
            raise ExternalHostCredentialError("managed_host_forbidden")
        if row.token_hash != expected_sha256:
            raise ExternalHostCredentialError("credential_changed")
        row.token_hash = None
        row.token_expires_at = None
        row.updated_at = revoked_at

    return ExternalHostCredentialReceipt(
        status="revoked",
        workspace_id=workspace_id,
        host_id=host_id,
        token_sha256=None,
        expires_at=None,
    )


def _database_url_from_file() -> str:
    configured = os.environ.get(_DATABASE_URL_FILE_ENV)
    if not configured:
        raise ExternalHostCredentialError("database_url_file_required")
    value = Path(configured).read_text(encoding="utf-8").strip()
    if not value:
        raise ExternalHostCredentialError("database_url_file_empty")
    return value


def main(argv: list[str] | None = None) -> int:
    """Run the fail-closed bootstrap used by the GitOps activation Job."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("arm", "revoke"))
    parser.add_argument("--workspace-id", required=True, type=int)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--ttl-days", type=int, default=90)
    parser.add_argument("--expected-token-sha256")
    args = parser.parse_args(argv)
    token = load_host_tunnel_token()
    if token is None:
        raise ExternalHostCredentialError("token_file_required")
    engine = sa.create_engine(_database_url_from_file(), pool_pre_ping=True)
    try:
        if args.action == "arm":
            receipt = arm_external_host_credential(
                engine,
                workspace_id=args.workspace_id,
                host_id=args.host_id,
                token=token,
                ttl_seconds=args.ttl_days * 24 * 3600,
                expected_token_sha256=args.expected_token_sha256,
            )
        else:
            receipt = revoke_external_host_credential(
                engine,
                workspace_id=args.workspace_id,
                host_id=args.host_id,
                expected_token=token,
            )
    finally:
        engine.dispose()
    print(json.dumps(asdict(receipt), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
