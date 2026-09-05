from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.stores.credential_store.secret_cipher import SecretContext
from saas.control_plane import (
    EmailProviderConfigurationService,
    PlatformAuthorizationService,
    PlatformHttpConfig,
    PlatformProjectionService,
    PlatformRoleAssignmentRecord,
    PlatformSessionService,
    SaasBase,
    StaffIdentityAssertion,
    create_platform_admin_app,
)
from saas.onboarding_email import SmtpEmailVerificationConfig

_ORIGIN = "https://platform-admin.example.test"
_AUDIENCE = "omnigent-platform-admin"
_PASSWORD = "smtp-secret-never-returned"


class _Cipher:
    def encrypt(self, plaintext: str, *, context: SecretContext) -> str:
        del context
        return f"encrypted::{plaintext[::-1]}"

    def decrypt(self, ciphertext: str, *, context: SecretContext) -> str | None:
        del context
        return ciphertext.removeprefix("encrypted::")[::-1]


class _Sender:
    deliveries: list[tuple[str, int, UUID, str]] = []

    def __init__(self, config: SmtpEmailVerificationConfig) -> None:
        self._config = config

    def send_test(
        self,
        *,
        recipient: str,
        configuration_version: int,
        test_id: UUID,
    ) -> None:
        self.deliveries.append((recipient, configuration_version, test_id, self._config.host))

    def close(self) -> None:
        return None


def _client() -> tuple[PlatformHttpConfig, TestClient, str]:
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=_ORIGIN, audience=_AUDIENCE)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:smtp-operator",
        issuer="https://staff-idp.example.test",
        subject="smtp-operator",
        now=now,
    )
    assigner_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:assigner",
        issuer="https://staff-idp.example.test",
        subject="assigner",
        now=now,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=assigner_id,
                approval_ref="bootstrap",
                reason="test bootstrap",
                created_at=now,
                updated_at=now,
            )
        )
    issued = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="smtp-operator",
            authn_method="webauthn",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    email_configuration = EmailProviderConfigurationService(
        factory,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
        smtp_sender_factory=_Sender,
    )
    config = PlatformHttpConfig(enabled=True, origin=_ORIGIN, audience=_AUDIENCE)
    app = create_platform_admin_app(
        config=config,
        sessions=sessions,
        authorization=authorization,
        projections=PlatformProjectionService(factory),
        email_configuration=email_configuration,
    )
    client = TestClient(app, base_url=_ORIGIN)
    client.cookies.set(config.cookie_name, issued.token)
    return config, client, issued.csrf_token


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "expected_version": 0,
        "enabled": True,
        "host": "smtp.example.test",
        "port": 587,
        "security": "starttls",
        "username": "mailer@example.test",
        "password": _PASSWORD,
        "from_address": "verify@example.test",
        "reply_to_address": "support@example.test",
        "timeout_seconds": 8.0,
    }
    payload.update(overrides)
    return payload


def test_platform_email_configuration_http_never_returns_or_echoes_password() -> None:
    config, client, csrf = _client()
    context = client.get("/v2/platform-admin/context")
    assert context.json()["capabilities"]["email_configuration_enabled"] is True
    page = client.get("/platform-admin")
    assert page.status_code == 200
    assert 'data-testid="email-configuration-form"' in page.text
    assert 'autocomplete="new-password"' in page.text
    javascript = client.get("/platform-admin/assets/platform-admin.js")
    assert "/v2/platform-admin/email-configuration/test" in javascript.text

    empty = client.get("/v2/platform-admin/email-configuration")
    assert empty.status_code == 200
    assert empty.json()["configured"] is False

    saved = client.put(
        "/v2/platform-admin/email-configuration",
        headers={"Origin": config.origin, "X-CSRF-Token": csrf},
        json=_payload(),
    )
    assert saved.status_code == 200
    assert saved.json()["version"] == 1
    assert saved.json()["password_configured"] is True
    assert "password" not in saved.json()
    assert _PASSWORD not in saved.text

    read = client.get("/v2/platform-admin/email-configuration")
    assert read.status_code == 200
    assert read.json()["host"] == "smtp.example.test"
    assert "password" not in read.text.replace("password_configured", "")
    assert _PASSWORD not in read.text

    invalid = client.put(
        "/v2/platform-admin/email-configuration",
        headers={"Origin": config.origin, "X-CSRF-Token": csrf},
        content=(
            '{"expected_version":1,"enabled":true,"host":"bad host",'
            f'"port":587,"security":"starttls","username":"user",'
            f'"password":"{_PASSWORD}","from_address":"verify@example.test",'
            '"timeout_seconds":8.0}'
        ),
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "platform_email_configuration_invalid"
    assert _PASSWORD not in invalid.text


def test_platform_email_configuration_http_preserves_password_and_sends_test() -> None:
    _Sender.deliveries.clear()
    config, client, csrf = _client()
    headers = {"Origin": config.origin, "X-CSRF-Token": csrf}
    assert (
        client.put(
            "/v2/platform-admin/email-configuration", headers=headers, json=_payload()
        ).status_code
        == 200
    )

    updated = client.put(
        "/v2/platform-admin/email-configuration",
        headers=headers,
        json=_payload(expected_version=1, password=None, port=465, security="tls"),
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    tested = client.post(
        "/v2/platform-admin/email-configuration/test",
        headers=headers,
        json={"expected_version": 2, "recipient": "owner@example.test"},
    )
    assert tested.status_code == 202
    assert tested.json()["status"] == "accepted"
    assert len(_Sender.deliveries) == 1
    recipient, configuration_version, test_id, host = _Sender.deliveries[0]
    assert recipient == "owner@example.test"
    assert configuration_version == 2
    assert isinstance(test_id, UUID)
    assert host == "smtp.example.test"

    stale = client.put(
        "/v2/platform-admin/email-configuration",
        headers=headers,
        json=_payload(expected_version=1, password=None),
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "platform_email_configuration_conflict"
