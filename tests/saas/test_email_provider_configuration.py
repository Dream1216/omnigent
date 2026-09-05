from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.stores.credential_store.secret_cipher import SecretContext
from saas.control_plane.db_models import SaasBase
from saas.control_plane.email_provider import (
    EmailProviderConfigurationReader,
    EmailProviderConfigurationService,
    SmtpConfigurationUpdate,
)
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_models import (
    EmailProviderConfigurationReceiptRecord,
    EmailProviderConfigurationRecord,
    PlatformRoleAssignmentRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.onboarding_email import (
    EmailVerificationDeliveryError,
    SmtpEmailVerificationConfig,
)

_NOW = datetime(2026, 9, 5, 5, 0, tzinfo=timezone.utc)
_PASSWORD = "smtp password that must stay secret"


class _Cipher:
    def encrypt(self, plaintext: str, *, context: SecretContext) -> str:
        assert context["provider"] == "smtp"
        return f"encrypted::{plaintext[::-1]}"

    def decrypt(self, ciphertext: str, *, context: SecretContext) -> str | None:
        assert context["account_id"] == "onboarding_verification"
        if not ciphertext.startswith("encrypted::"):
            return None
        return ciphertext.removeprefix("encrypted::")[::-1]


class _TestSender:
    def __init__(
        self,
        config: SmtpEmailVerificationConfig,
        *,
        failure: EmailVerificationDeliveryError | None = None,
    ) -> None:
        self.config = config
        self.failure = failure
        self.deliveries: list[tuple[str, int, UUID]] = []
        self.closed = False

    def send_test(
        self,
        *,
        recipient: str,
        configuration_version: int,
        test_id: UUID,
    ) -> None:
        if self.failure is not None:
            raise self.failure
        self.deliveries.append((recipient, configuration_version, test_id))

    def close(self) -> None:
        self.closed = True


def _configuration(*, password: str | None = _PASSWORD, enabled: bool = True):
    return SmtpConfigurationUpdate(
        enabled=enabled,
        host="smtp.example.test",
        port=587,
        security="starttls",
        username="mailer@example.test",
        password=password,
        from_address="verify@example.test",
        reply_to_address="support@example.test",
        timeout_seconds=8.0,
    )


def _fixture(role: str = "platform_operator"):
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(sessions)
    actor_id = authorization.provision_staff_principal(
        identity_connection_ref=f"staff-idp:{role}",
        issuer="https://staff-idp.example.test",
        subject=role,
        now=_NOW,
    )
    assigner_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:assigner",
        issuer="https://staff-idp.example.test",
        subject="assigner",
        now=_NOW,
    )
    with sessions.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=actor_id,
                role=role,
                status="active",
                version=1,
                assigned_by_principal_id=assigner_id,
                approval_ref="bootstrap",
                reason="test bootstrap",
                created_at=_NOW,
                updated_at=_NOW,
            )
        )
    actor = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=actor_id,
        security_version=1,
        authn_method="webauthn",
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
        roles=frozenset({role}),
        permissions=PLATFORM_ROLE_PERMISSIONS[role],
    )
    return sessions, authorization, actor


def test_platform_smtp_configuration_is_cas_encrypted_and_never_returns_password() -> None:
    sessions, authorization, actor = _fixture()
    service = EmailProviderConfigurationService(
        sessions,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
    )

    assert service.get(actor).version == 0
    with pytest.raises(PlatformSecurityError) as missing:
        service.update(
            actor,
            expected_version=0,
            configuration=_configuration(password=None),
            now=_NOW,
        )
    assert missing.value.code == "platform_email_configuration_invalid"

    created = service.update(
        actor,
        expected_version=0,
        configuration=_configuration(),
        now=_NOW,
    )

    assert created.configured and created.enabled and created.password_configured
    assert created.version == 1
    assert _PASSWORD not in repr(created)
    with sessions.begin() as db:
        stored = db.get(EmailProviderConfigurationRecord, "onboarding_verification")
        assert stored is not None
        assert stored.password_ciphertext == f"encrypted::{_PASSWORD[::-1]}"
        assert _PASSWORD not in stored.password_ciphertext
        receipts = db.scalars(sa.select(EmailProviderConfigurationReceiptRecord)).all()
        assert [(item.action, item.password_rotated) for item in receipts] == [
            ("configured", True)
        ]

    updated = service.update(
        actor,
        expected_version=1,
        configuration=_configuration(password=None),
        now=_NOW + timedelta(seconds=1),
    )
    assert updated.version == 2
    with pytest.raises(PlatformSecurityError) as stale:
        service.update(
            actor,
            expected_version=1,
            configuration=_configuration(password="new-password"),
            now=_NOW + timedelta(seconds=2),
        )
    assert stale.value.code == "platform_email_configuration_conflict"


def test_worker_reader_observes_enabled_updates_and_decrypts_only_at_delivery_boundary() -> None:
    sessions, authorization, actor = _fixture()
    service = EmailProviderConfigurationService(
        sessions,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
    )
    reader = EmailProviderConfigurationReader(
        sessions,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
    )
    service.update(actor, expected_version=0, configuration=_configuration(), now=_NOW)

    active = reader.load()

    assert active is not None
    assert active.host == "smtp.example.test"
    assert active.password == _PASSWORD
    assert _PASSWORD not in repr(active)

    service.update(
        actor,
        expected_version=1,
        configuration=_configuration(password=None, enabled=False),
        now=_NOW + timedelta(seconds=1),
    )
    assert reader.load() is None


def test_platform_smtp_test_records_only_recipient_hash_and_maps_delivery_failure() -> None:
    sessions, authorization, actor = _fixture()
    senders: list[_TestSender] = []

    def sender_factory(config: SmtpEmailVerificationConfig) -> _TestSender:
        sender = _TestSender(config)
        senders.append(sender)
        return sender

    service = EmailProviderConfigurationService(
        sessions,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
        smtp_sender_factory=sender_factory,
    )
    service.update(actor, expected_version=0, configuration=_configuration(), now=_NOW)

    service.send_test(
        actor,
        recipient="owner@example.test",
        expected_version=1,
        now=_NOW + timedelta(seconds=1),
    )

    assert len(senders[0].deliveries) == 1
    recipient, configuration_version, test_id = senders[0].deliveries[0]
    assert recipient == "owner@example.test"
    assert configuration_version == 1
    assert senders[0].closed
    with sessions.begin() as db:
        receipt = db.scalar(
            sa.select(EmailProviderConfigurationReceiptRecord).where(
                EmailProviderConfigurationReceiptRecord.action == "test_succeeded"
            )
        )
        assert receipt is not None
        assert receipt.id == test_id
        assert receipt.recipient_hash is not None
        assert "owner@example.test" not in repr(receipt.recipient_hash)

    failure = EmailVerificationDeliveryError(
        "email_verification_provider_unavailable",
        retryable=True,
        pre_side_effect=False,
    )

    def failing_factory(config: SmtpEmailVerificationConfig) -> _TestSender:
        return _TestSender(config, failure=failure)

    failing = EmailProviderConfigurationService(
        sessions,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
        smtp_sender_factory=failing_factory,
    )
    with pytest.raises(PlatformSecurityError) as raised:
        failing.send_test(
            actor,
            recipient="owner@example.test",
            expected_version=1,
            now=_NOW + timedelta(seconds=2),
        )
    assert raised.value.code == "platform_email_test_unavailable"


def test_email_configuration_permissions_keep_auditor_read_only() -> None:
    sessions, authorization, auditor = _fixture("platform_security_auditor")
    service = EmailProviderConfigurationService(
        sessions,
        authorization=authorization,
        secret_cipher=_Cipher(),
        public_origin="https://next.jxhh.com",
    )

    assert not service.get(auditor).configured
    with pytest.raises(PlatformSecurityError) as raised:
        service.update(
            auditor,
            expected_version=0,
            configuration=_configuration(),
            now=_NOW,
        )
    assert raised.value.code == "platform_permission_denied"
