from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import cast

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.stores.credential_store.secret_cipher import SecretContext
from saas.control_plane.db_models import SaasBase
from saas.control_plane.platform_models import (
    EmailProviderConfigurationReceiptRecord,
    EmailProviderConfigurationRecord,
    PlatformAuthSessionRecord,
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.onboarding_email import SmtpEmailVerificationConfig
from saas.production import platform_smtp_bootstrap


class _Cipher:
    def encrypt(self, plaintext: str, *, context: SecretContext) -> str:
        assert context["provider"] == "smtp"
        return "vault:v1:" + plaintext[::-1]

    def decrypt(self, ciphertext: str, *, context: SecretContext) -> str | None:
        assert context["account_id"] == "onboarding_verification"
        return ciphertext.removeprefix("vault:v1:")[::-1]


class _Sender:
    deliveries: list[tuple[str, int]] = []

    def __init__(self, config: SmtpEmailVerificationConfig) -> None:
        assert config.password == "smtp password"

    def send_test(self, *, recipient: str, configuration_version: int, test_id) -> None:
        self.deliveries.append((recipient, configuration_version))

    def close(self) -> None:
        pass


def test_platform_smtp_bootstrap_reads_stdin_and_emits_only_safe_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'bootstrap.sqlite'}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    monkeypatch.setattr(
        platform_smtp_bootstrap,
        "load_production_database_url_file",
        lambda _source, _role: ("postgresql+psycopg://redacted", None, tmp_path / "dsn"),
    )
    monkeypatch.setattr(
        platform_smtp_bootstrap,
        "parse_production_postgresql_url",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(platform_smtp_bootstrap, "_inspect_authority", lambda *_a, **_k: None)
    _Sender.deliveries.clear()

    result = platform_smtp_bootstrap.run_platform_smtp_bootstrap(
        environ={"OMNIGENT_SAAS_PUBLIC_ORIGIN": "https://next.jxhh.com"},
        password_stream=BytesIO(b"smtp password\n"),
        approval_ref="owner-approved:smtp-bootstrap:2026-09-07",
        reason="single Owner risk waiver; initial SMTP bootstrap only",
        owner_key_fingerprint="SHA256:test-owner-key",
        host="smtp.qiye.aliyun.com",
        port=465,
        security="tls",
        username="postmaster@jxhh.com",
        from_address="postmaster@jxhh.com",
        reply_to_address="postmaster@jxhh.com",
        test_recipient="postmaster@jxhh.com",
        engine_factory=lambda _url: engine,
        cipher_loader=lambda _source: _Cipher(),
        smtp_sender_factory=_Sender,
    )

    encoded = str(result)
    assert result["status"] == "pass"
    assert result["governance_posture"] == "single_owner_risk_waiver"
    assert result["browser_staff_login_created"] is False
    assert "smtp password" not in encoded
    receipts = cast(list[dict[str, object]], result["receipts"])
    assert [row["action"] for row in receipts] == [
        "configured",
        "test_succeeded",
    ]
    assert _Sender.deliveries == [("postmaster@jxhh.com", 1)]

    sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
    with sessions.begin() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformStaffPrincipalRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformRoleAssignmentRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuthSessionRecord)) == 0
        config = db.get(EmailProviderConfigurationRecord, "onboarding_verification")
        assert config is not None
        assert config.password_ciphertext == "vault:v1:drowssap ptms"
        assert (
            db.scalar(
                sa.select(sa.func.count()).select_from(EmailProviderConfigurationReceiptRecord)
            )
            == 2
        )


def test_platform_smtp_bootstrap_password_input_is_bounded_and_single_line() -> None:
    for value in (b"", b"two\nlines\n", b"nul\0byte\n"):
        try:
            platform_smtp_bootstrap._read_password(BytesIO(value))
        except platform_smtp_bootstrap.PlatformSmtpBootstrapError as error:
            assert error.code == "smtp_password_invalid"
        else:
            raise AssertionError("invalid password input was accepted")
