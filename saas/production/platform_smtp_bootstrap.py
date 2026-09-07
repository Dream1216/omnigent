"""One-shot, fail-closed bootstrap for the first governed Platform SMTP record.

The SMTP password is accepted only on stdin and exists only in process memory.
The database authority and OpenBao token are loaded from owner-only files.  The
ceremony creates two distinct, short-lived Staff identities with cross-assigned
roles and records the explicit external approval reference.  It is available
only while Staff, SMTP configuration, SMTP receipts, and Staff sessions are all
at zero; it never creates a browser session or weakens the Staff IdP contract.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import BinaryIO

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.email_provider import (
    EmailProviderConfigurationService,
    SmtpConfigurationUpdate,
    SmtpTestSenderFactory,
)
from saas.control_plane.platform_models import (
    EmailProviderConfigurationReceiptRecord,
    EmailProviderConfigurationRecord,
)
from saas.control_plane.platform_security import (
    InitialPlatformStaffIdentity,
    PlatformAuthorizationService,
)
from saas.production.onboarding import build_production_secret_cipher
from saas.production.postgresql_migration import (
    PostgreSqlMigrationError,
    _inspect_authority,
    parse_production_postgresql_url,
)
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)

_MAX_PASSWORD_BYTES = 16 * 1024
_ROLE_TTL = timedelta(minutes=30)
_PURPOSE = "onboarding_verification"


class PlatformSmtpBootstrapError(RuntimeError):
    """Stable, content-free rejection for the offline SMTP ceremony."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Platform SMTP bootstrap rejected: {code}")


def _read_password(stream: BinaryIO) -> tuple[str, bytearray]:
    raw = bytearray(stream.read(_MAX_PASSWORD_BYTES + 1))
    if len(raw) > _MAX_PASSWORD_BYTES:
        raw[:] = b"\0" * len(raw)
        raise PlatformSmtpBootstrapError("smtp_password_too_large")
    if raw.endswith(b"\r\n"):
        del raw[-2:]
    elif raw.endswith(b"\n"):
        del raw[-1:]
    if not raw or b"\0" in raw or b"\r" in raw or b"\n" in raw:
        raw[:] = b"\0" * len(raw)
        raise PlatformSmtpBootstrapError("smtp_password_invalid")
    try:
        return raw.decode("utf-8"), raw
    except UnicodeError:
        raw[:] = b"\0" * len(raw)
        raise PlatformSmtpBootstrapError("smtp_password_invalid") from None


def _session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False, class_=Session)


def _zero_smtp_state(sessions: sessionmaker[Session]) -> None:
    with sessions.begin() as db:
        if db.scalar(sa.select(sa.func.count()).select_from(EmailProviderConfigurationRecord)):
            raise PlatformSmtpBootstrapError("smtp_configuration_already_exists")
        if db.scalar(
            sa.select(sa.func.count()).select_from(EmailProviderConfigurationReceiptRecord)
        ):
            raise PlatformSmtpBootstrapError("smtp_receipts_already_exist")


def _safe_receipt_summary(sessions: sessionmaker[Session]) -> list[dict[str, object]]:
    with sessions.begin() as db:
        rows = db.scalars(
            sa.select(EmailProviderConfigurationReceiptRecord).order_by(
                EmailProviderConfigurationReceiptRecord.occurred_at,
                EmailProviderConfigurationReceiptRecord.id,
            )
        ).all()
        return [
            {
                "action": row.action,
                "configuration_version": row.configuration_version,
                "password_rotated": row.password_rotated,
                "recipient_hash": row.recipient_hash,
            }
            for row in rows
        ]


def run_platform_smtp_bootstrap(
    *,
    environ: Mapping[str, str],
    password_stream: BinaryIO,
    approval_ref: str,
    reason: str,
    owner_key_fingerprint: str,
    host: str,
    port: int,
    security: str,
    username: str,
    from_address: str,
    reply_to_address: str | None,
    test_recipient: str,
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url, pool_pre_ping=True
    ),
    cipher_loader: Callable[[Mapping[str, str]], SecretCipher | None] = (
        build_production_secret_cipher
    ),
    smtp_sender_factory: SmtpTestSenderFactory | None = None,
) -> dict[str, object]:
    """Perform the exact zero-state ceremony and return secret-free evidence."""

    if not owner_key_fingerprint.startswith("SHA256:") or len(owner_key_fingerprint) > 128:
        raise PlatformSmtpBootstrapError("owner_key_fingerprint_invalid")
    public_origin = environ.get("OMNIGENT_SAAS_PUBLIC_ORIGIN", "")
    if public_origin != "https://next.jxhh.com":
        raise PlatformSmtpBootstrapError("public_origin_not_admitted")
    try:
        database_url, _parsed, _path = load_production_database_url_file(
            environ, "principal_operator"
        )
        authority = parse_production_postgresql_url(
            database_url,
            kind="principal_operator",
            require_tls=True,
        )
    except (ProductionServerConfigError, PostgreSqlMigrationError):
        raise PlatformSmtpBootstrapError("database_authority_invalid") from None

    password, mutable_password = _read_password(password_stream)
    engine: Engine | None = None
    try:
        engine = engine_factory(database_url)
        try:
            _inspect_authority(engine, authority, require_tls=True)
        except PostgreSqlMigrationError:
            raise PlatformSmtpBootstrapError("database_authority_invalid") from None
        sessions = _session_factory(engine)
        _zero_smtp_state(sessions)
        cipher = cipher_loader(environ)
        if cipher is None:
            raise PlatformSmtpBootstrapError("secret_cipher_unavailable")
        now = datetime.now(timezone.utc)
        authorization = PlatformAuthorizationService(sessions)
        actor = authorization.bootstrap_initial_staff_pair(
            operator=InitialPlatformStaffIdentity(
                identity_connection_ref=(
                    f"ssh-signed-owner-bootstrap:{owner_key_fingerprint}:operator"
                ),
                issuer="urn:omnigent:staff-bootstrap:single-owner-risk-waiver",
                subject=f"{owner_key_fingerprint}:operator",
                display_name="Initial Platform Operator",
                email_normalized=username,
            ),
            auditor=InitialPlatformStaffIdentity(
                identity_connection_ref=(
                    f"ssh-signed-owner-bootstrap:{owner_key_fingerprint}:auditor"
                ),
                issuer="urn:omnigent:staff-bootstrap:single-owner-risk-waiver",
                subject=f"{owner_key_fingerprint}:auditor",
                display_name="Initial Platform Security Auditor",
                email_normalized=username,
            ),
            approval_ref=approval_ref,
            reason=reason,
            expires_at=now + _ROLE_TTL,
            now=now,
        )
        configuration_service = EmailProviderConfigurationService(
            sessions,
            authorization=authorization,
            secret_cipher=cipher,
            public_origin=public_origin,
            smtp_sender_factory=smtp_sender_factory,
        )
        view = configuration_service.update(
            actor,
            expected_version=0,
            configuration=SmtpConfigurationUpdate(
                enabled=True,
                host=host,
                port=port,
                security=security,
                username=username,
                password=password,
                from_address=from_address,
                reply_to_address=reply_to_address,
                timeout_seconds=15.0,
            ),
            now=now,
        )
        configuration_service.send_test(
            actor,
            recipient=test_recipient,
            expected_version=view.version,
            now=now + timedelta(seconds=1),
        )
        return {
            "schema_version": 1,
            "status": "pass",
            "production_authority": False,
            "governance_posture": "single_owner_risk_waiver",
            "browser_staff_login_created": False,
            "purpose": view.purpose,
            "enabled": view.enabled,
            "host": view.host,
            "port": view.port,
            "security": view.security,
            "password_configured": view.password_configured,
            "configuration_version": view.version,
            "test_recipient_hash": sha256(test_recipient.lower().encode()).hexdigest(),
            "role_authority_expires_at": actor.expires_at.isoformat(),
            "receipts": _safe_receipt_summary(sessions),
        }
    finally:
        password = ""
        mutable_password[:] = b"\0" * len(mutable_password)
        if engine is not None:
            engine.dispose()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bootstrap governed Platform SMTP once")
    parser.add_argument("--approval-ref", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--owner-key-fingerprint", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--security", required=True, choices=("tls", "starttls"))
    parser.add_argument("--username", required=True)
    parser.add_argument("--from-address", required=True)
    parser.add_argument("--reply-to-address")
    parser.add_argument("--test-recipient", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_platform_smtp_bootstrap(
            environ=os.environ,
            password_stream=sys.stdin.buffer,
            approval_ref=args.approval_ref,
            reason=args.reason,
            owner_key_fingerprint=args.owner_key_fingerprint,
            host=args.host,
            port=args.port,
            security=args.security,
            username=args.username,
            from_address=args.from_address,
            reply_to_address=args.reply_to_address,
            test_recipient=args.test_recipient,
        )
    except Exception:  # noqa: BLE001 - never expose secret-adjacent backend context.
        print(json.dumps({"schema_version": 1, "status": "fail"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PlatformSmtpBootstrapError",
    "main",
    "run_platform_smtp_bootstrap",
]
