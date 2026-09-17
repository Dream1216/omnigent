from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import SaasBase
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import PlatformSessionService
from saas.production import platform_admin
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)
from saas.scripts import transition_local_platform_operator as transition_script

ORIGIN = "https://staff.example.test"
AUDIENCE = "omnigent-platform-admin"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def _environment() -> dict[str, str]:
    return {
        "OMNIGENT_SAAS_PLATFORM_ADMIN_ENABLED": "true",
        "OMNIGENT_SAAS_PLATFORM_ADMIN_ORIGIN": ORIGIN,
        "OMNIGENT_SAAS_PLATFORM_ADMIN_AUDIENCE": AUDIENCE,
        "OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS": "10.42.0.0/16,fd00:42::/48",
    }


def _engine() -> sa.Engine:
    engine = sa.create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    return engine


def test_production_platform_admin_composes_local_password_login_with_two_roles(
    monkeypatch,
) -> None:
    authenticator_engine = _engine()
    application_engine = _engine()
    factory = sessionmaker(authenticator_engine, expire_on_commit=False, class_=Session)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    principal_id = passwords.provision_account(
        username="staff-admin",
        password="staff-admin-password-2026",
        now=NOW,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=principal_id,
                approval_ref="production-platform-admin-test",
                reason="exercise the production composition",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    bindings = ProductionServiceRoleBindings(
        path=Path("/platform-admin-bindings.json"),
        sha256="a" * 64,
        bindings=(
            ProductionServiceRoleBinding(
                "platform_app", "platform_app_login", "saas_platform_app"
            ),
            ProductionServiceRoleBinding(
                "platform_authenticator",
                "platform_authenticator_login",
                "saas_platform_authenticator",
            ),
        ),
    )
    monkeypatch.setattr(
        platform_admin,
        "_engines",
        lambda _source, services: (
            (
                (authenticator_engine, application_engine),
                bindings,
            )
            if services == ("platform_authenticator", "platform_app")
            else (_ for _ in ()).throw(AssertionError(services))
        ),
    )
    monkeypatch.setattr(platform_admin, "_inspect_service_login", lambda *_args, **_kwargs: None)

    app, engines = platform_admin.build_platform_admin(_environment())
    client = TestClient(app, base_url=ORIGIN)

    assert engines == (authenticator_engine, application_engine)
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/platform-admin/login").status_code == 200
    login = client.post(
        "/v2/platform-admin/session/login",
        headers={"Origin": ORIGIN},
        json={"username": "staff-admin", "password": "staff-admin-password-2026"},
    )
    assert login.status_code == 201
    assert login.json()["authentication_method"] == "password"
    context = client.get("/v2/platform-admin/context")
    assert context.status_code == 200
    assert context.json()["roles"] == ["platform_operator"]
    assert context.json()["realm"] == "staff"

    def drifted(*_args, **_kwargs):
        raise platform_admin.PostgreSqlMigrationError(
            "service_login_authority_drifted", "runtime_verification"
        )

    monkeypatch.setattr(platform_admin, "_inspect_service_login", drifted)
    assert client.get("/healthz").status_code == 503

    for engine in engines:
        engine.dispose()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("OMNIGENT_SAAS_PLATFORM_ADMIN_ENABLED", "false"),
        ("OMNIGENT_SAAS_PLATFORM_ADMIN_ORIGIN", "http://staff.example.test"),
        ("OMNIGENT_SAAS_PLATFORM_ADMIN_ORIGIN", "https://staff.example.test/path"),
        ("OMNIGENT_SAAS_PLATFORM_ADMIN_AUDIENCE", "bad audience"),
    ],
)
def test_production_platform_admin_rejects_ambiguous_realm(field: str, value: str) -> None:
    environment = _environment()
    environment[field] = value
    with pytest.raises(ValueError):
        platform_admin.build_platform_admin(environment)


def test_production_platform_admin_accepts_only_canonical_proxy_networks() -> None:
    assert platform_admin._trusted_proxy_cidrs(_environment()) == [
        "10.42.0.0/16",
        "fd00:42::/48",
    ]
    for value in ("*", "0.0.0.0/0", "10.42.1.1/16", "10.42.0.0/16, 127.0.0.1/32"):
        environment = _environment()
        environment["OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS"] = value
        with pytest.raises(ValueError):
            platform_admin._trusted_proxy_cidrs(environment)


def test_local_operator_transition_cli_reads_private_files_without_echoing_secrets(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    username_path = tmp_path / "username"
    password_path = tmp_path / "password"
    username_path.write_text("staff-admin\n", encoding="utf-8")
    password_path.write_text("staff-admin-password-2026\n", encoding="utf-8")
    username_path.chmod(0o400)
    password_path.chmod(0o400)
    authorizer = UUID("12d89c90-6bf7-49a0-8b16-156e6d339657")
    created = UUID("f7531d7f-d341-4bed-9ea2-d8c58774e0a0")

    def transition(_environ, **kwargs):
        assert kwargs == {
            "username": "staff-admin",
            "password": "staff-admin-password-2026",
            "authorized_by_principal_id": authorizer,
            "approval_ref": "BETA-LOCAL-STAFF-TRANSITION-20260917",
            "reason": "replace temporary bridge",
        }
        return created

    monkeypatch.setattr(transition_script, "transition_local_operator", transition)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "transition_local_platform_operator",
            "--username-file",
            str(username_path),
            "--password-file",
            str(password_path),
            "--authorized-by-principal-id",
            str(authorizer),
            "--approval-ref",
            "BETA-LOCAL-STAFF-TRANSITION-20260917",
            "--reason",
            "replace temporary bridge",
        ],
    )

    assert transition_script.main() == 0
    captured = capsys.readouterr()
    assert str(created) in captured.out
    assert "staff-admin-password-2026" not in captured.out + captured.err
