from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.stores.credential_store.secret_cipher import SecretContext
from saas.control_plane import (
    ManagedModelProbeResult,
    ModelProviderConfigurationReader,
    ModelProviderConfigurationReceiptRecord,
    ModelProviderConfigurationService,
    PlatformAuthorizationService,
    PlatformHttpConfig,
    PlatformProjectionService,
    PlatformRoleAssignmentRecord,
    PlatformSessionService,
    SaasBase,
    StaffIdentityAssertion,
    create_platform_admin_app,
)

_ORIGIN = "https://platform-admin.example.test"
_AUDIENCE = "omnigent-platform-admin"
_KEY = "test-managed-model-key-never-returned"


class _Cipher:
    def encrypt(self, plaintext: str, *, context: SecretContext) -> str:
        assert context["provider"] == "deepseek"
        return f"encrypted::{plaintext[::-1]}"

    def decrypt(self, ciphertext: str, *, context: SecretContext) -> str | None:
        assert context["account_id"] == "managed_model"
        return ciphertext.removeprefix("encrypted::")[::-1]


class _Probe:
    calls: list[tuple[str, str, str]] = []

    def __call__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
    ) -> ManagedModelProbeResult:
        self.calls.append((base_url, api_key, model))
        return ManagedModelProbeResult(
            provider_request_id="request-live-1",
            response_model=model,
            latency_millis=37,
            output_observed=True,
        )


class _FailingProbe:
    calls: list[tuple[str, str, str]] = []

    def __call__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
    ) -> ManagedModelProbeResult:
        self.calls.append((base_url, api_key, model))
        raise RuntimeError(f"transport failure with secret {api_key}")


def _client(
    probe: _Probe | _FailingProbe | None = None,
) -> tuple[
    PlatformHttpConfig,
    TestClient,
    str,
    sessionmaker,
    ModelProviderConfigurationReader,
]:
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
        identity_connection_ref="staff-idp:model-operator",
        issuer="https://staff-idp.example.test",
        subject="model-operator",
        now=now,
    )
    assigner_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:model-assigner",
        issuer="https://staff-idp.example.test",
        subject="model-assigner",
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
            subject="model-operator",
            authn_method="webauthn",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    cipher = _Cipher()
    model_provider = ModelProviderConfigurationService(
        factory,
        authorization=authorization,
        secret_cipher=cipher,
        probe=probe or _Probe(),
    )
    config = PlatformHttpConfig(enabled=True, origin=_ORIGIN, audience=_AUDIENCE)
    app = create_platform_admin_app(
        config=config,
        sessions=sessions,
        authorization=authorization,
        projections=PlatformProjectionService(factory),
        model_provider=model_provider,
    )
    client = TestClient(app, base_url=_ORIGIN)
    client.cookies.set(config.cookie_name, issued.token)
    return (
        config,
        client,
        issued.csrf_token,
        factory,
        ModelProviderConfigurationReader(factory, secret_cipher=cipher),
    )


def _payload(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "expected_version": 0,
        "enabled": True,
        "base_url": "https://api.deepseek.com",
        "api_type": "openai_chat_completions",
        "api_key": _KEY,
        "allowed_models": ["deepseek-v4-flash", "deepseek-v4-pro"],
        "default_model": "deepseek-v4-flash",
        "monthly_budget_microusd": 100_000_000,
        "per_tenant_daily_token_limit": 1_000_000,
    }
    value.update(overrides)
    return value


def test_managed_model_http_encrypts_key_and_requires_live_verification() -> None:
    _Probe.calls.clear()
    config, client, csrf, factory, reader = _client()
    headers = {"Origin": config.origin, "X-CSRF-Token": csrf}

    context = client.get("/v2/platform-admin/context")
    assert context.json()["capabilities"]["model_provider_enabled"] is True
    page = client.get("/platform-admin")
    assert page.status_code == 200
    assert 'data-testid="model-provider-form"' in page.text
    assert 'autocomplete="new-password"' in page.text
    assert "预算值是待绑定策略" in page.text
    assert "保存和流式验证都不等于已投产" in page.text

    empty = client.get("/v2/platform-admin/model-provider")
    assert empty.status_code == 200
    assert empty.json()["state"] == "not_configured"

    saved = client.put(
        "/v2/platform-admin/model-provider",
        headers=headers,
        json=_payload(),
    )
    assert saved.status_code == 200
    assert saved.json()["state"] == "configured"
    assert saved.json()["api_key_configured"] is True
    assert _KEY not in saved.text
    assert "api_key" not in saved.text.replace("api_key_configured", "")
    assert reader.load() is None

    verified = client.post(
        "/v2/platform-admin/model-provider/test",
        headers=headers,
        json={"expected_version": 1, "model": "deepseek-v4-flash"},
    )
    assert verified.status_code == 200
    assert verified.json()["state"] == "verified"
    assert verified.json()["verification_status"] == "verified"
    assert _KEY not in verified.text
    assert _Probe.calls == [("https://api.deepseek.com", _KEY, "deepseek-v4-flash")]

    runtime = reader.load()
    assert runtime is not None
    assert runtime.default_model == "deepseek-v4-flash"
    assert runtime.api_key == _KEY
    assert _KEY not in repr(runtime)
    with factory() as db:
        receipts = db.scalars(
            sa.select(ModelProviderConfigurationReceiptRecord).order_by(
                ModelProviderConfigurationReceiptRecord.occurred_at
            )
        ).all()
    assert [receipt.action for receipt in receipts] == [
        "configured",
        "verification_succeeded",
    ]
    assert receipts[1].provider_request_id_hash is not None


def test_managed_model_http_preserves_key_and_rejects_ssrf_or_stale_versions() -> None:
    config, client, csrf, _factory, reader = _client()
    headers = {"Origin": config.origin, "X-CSRF-Token": csrf}
    assert (
        client.put(
            "/v2/platform-admin/model-provider", headers=headers, json=_payload()
        ).status_code
        == 200
    )

    changed = client.put(
        "/v2/platform-admin/model-provider",
        headers=headers,
        json=_payload(
            expected_version=1,
            api_key=None,
            default_model="deepseek-v4-pro",
        ),
    )
    assert changed.status_code == 200
    assert changed.json()["version"] == 2
    assert changed.json()["state"] == "configured"

    verified = client.post(
        "/v2/platform-admin/model-provider/test",
        headers=headers,
        json={"expected_version": 2, "model": None},
    )
    assert verified.status_code == 200
    runtime = reader.load()
    assert runtime is not None and runtime.api_key == _KEY

    ssrf = client.put(
        "/v2/platform-admin/model-provider",
        headers=headers,
        json=_payload(expected_version=2, api_key=None, base_url="https://127.0.0.1"),
    )
    assert ssrf.status_code == 400
    assert ssrf.json()["error"]["code"] == "platform_model_provider_invalid"

    stale = client.put(
        "/v2/platform-admin/model-provider",
        headers=headers,
        json=_payload(expected_version=1, api_key=None),
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "platform_model_provider_conflict"


def test_managed_model_failed_probe_is_redacted_and_persisted_as_failed() -> None:
    _FailingProbe.calls.clear()
    config, client, csrf, factory, _reader = _client(probe=_FailingProbe())
    headers = {"Origin": config.origin, "X-CSRF-Token": csrf}
    assert (
        client.put(
            "/v2/platform-admin/model-provider",
            headers=headers,
            json=_payload(),
        ).status_code
        == 200
    )

    failed = client.post(
        "/v2/platform-admin/model-provider/test",
        headers=headers,
        json={"expected_version": 1, "model": "deepseek-v4-flash"},
    )
    assert failed.status_code == 503
    assert failed.json()["error"] == {
        "code": "platform_model_provider_test_unavailable",
        "message": "Model Provider live verification failed",
    }
    assert _KEY not in failed.text
    state = client.get("/v2/platform-admin/model-provider")
    assert state.json()["state"] == "verification_failed"
    with factory() as db:
        receipts = db.scalars(
            sa.select(ModelProviderConfigurationReceiptRecord).order_by(
                ModelProviderConfigurationReceiptRecord.occurred_at
            )
        ).all()
    assert [receipt.action for receipt in receipts] == [
        "configured",
        "verification_failed",
    ]
    assert receipts[-1].provider_request_id_hash is None


def test_model_provider_permissions_keep_security_auditor_read_only() -> None:
    from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS

    operator = PLATFORM_ROLE_PERMISSIONS["platform_operator"]
    auditor = PLATFORM_ROLE_PERMISSIONS["platform_security_auditor"]
    assert {
        "platform.model_provider.read",
        "platform.model_provider.manage",
        "platform.model_provider.test",
    }.issubset(operator)
    assert "platform.model_provider.read" in auditor
    assert "platform.model_provider.manage" not in auditor
    assert "platform.model_provider.test" not in auditor
