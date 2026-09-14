from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant, TenantMembership
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.model_provider import (
    ModelProviderConfigurationUpdate,
    ModelProviderConfigurationView,
)
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord
from saas.production.platform_model_admin import (
    SingleOwnerModelAdminAuthenticator,
    SingleOwnerModelAdminConfig,
    _trusted_proxy_cidrs,
    build_single_owner_model_admin,
    create_single_owner_model_admin_app,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
)

ORIGIN = "https://next.example.test"
TENANT_ID = UUID("10000000-0000-0000-0000-000000000001")
USER_ID = UUID("20000000-0000-0000-0000-000000000002")
PRINCIPAL_ID = UUID("30000000-0000-0000-0000-000000000003")


class _Provider:
    def __init__(self) -> None:
        self.version = 0
        self.secret: str | None = None
        self.verified = False

    def get(self, _actor) -> ModelProviderConfigurationView:
        return self._view()

    def update(
        self,
        _actor,
        *,
        expected_version: int,
        configuration: ModelProviderConfigurationUpdate,
    ) -> ModelProviderConfigurationView:
        assert expected_version == self.version
        self.version += 1
        self.secret = configuration.api_key
        self.verified = False
        return self._view(configured=True)

    def verify(self, _actor, *, expected_version: int, model: str | None):
        assert expected_version == self.version
        assert model == "deepseek-flash"
        self.verified = True
        return self._view(configured=True)

    def _view(self, *, configured: bool | None = None) -> ModelProviderConfigurationView:
        is_configured = self.version > 0 if configured is None else configured
        return ModelProviderConfigurationView(
            provider_id="deepseek",
            configured=is_configured,
            enabled=is_configured,
            state="verified"
            if self.verified
            else ("configured" if is_configured else "not_configured"),
            base_url="https://api.deepseek.com" if is_configured else None,
            api_type="openai_chat_completions" if is_configured else None,
            allowed_models=("deepseek-flash", "deepseek-v4-pro") if is_configured else (),
            default_model="deepseek-flash" if is_configured else None,
            monthly_budget_microusd=100_000_000 if is_configured else None,
            per_tenant_daily_token_limit=1_000_000 if is_configured else None,
            api_key_configured=self.secret is not None,
            verification_status="verified" if self.verified else "never",
            last_verified_model="deepseek-flash" if self.verified else None,
            last_verified_at=datetime.now(timezone.utc) if self.verified else None,
            version=self.version,
            updated_by_principal_id=PRINCIPAL_ID if is_configured else None,
            updated_at=datetime.now(timezone.utc) if is_configured else None,
        )


def _client() -> tuple[TestClient, _Provider, str]:
    engine = sa.create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        db.add_all(
            [
                GlobalUser(id=USER_ID, status="active", security_version=1),
                Tenant(
                    id=TENANT_ID,
                    slug="single-owner-beta",
                    name="Single Owner Beta",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
                TenantMembership(
                    tenant_id=TENANT_ID,
                    user_id=USER_ID,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=now,
                ),
                PlatformStaffPrincipalRecord(
                    id=PRINCIPAL_ID,
                    identity_connection_ref="single-owner-beta-bridge",
                    issuer="urn:omnigent:single-owner-beta",
                    subject=str(USER_ID),
                    status="active",
                    security_version=1,
                ),
            ]
        )
    lifecycle = MembershipLifecycleService(factory)
    issued = lifecycle.issue_auth_session(
        user_id=USER_ID,
        authn_method="password",
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    config = SingleOwnerModelAdminConfig(
        origin=ORIGIN,
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        platform_principal_id=PRINCIPAL_ID,
    )
    provider = _Provider()
    authenticator = SingleOwnerModelAdminAuthenticator(
        config=config,
        sessions=lifecycle,
        tenant_sessions=factory,
        platform_sessions=factory,
    )
    app = create_single_owner_model_admin_app(
        config=config,
        authenticator=authenticator,
        model_provider=provider,  # type: ignore[arg-type]
    )
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(config.cookie_name, issued.token)
    return client, provider, issued.csrf_token


def test_single_owner_bridge_saves_without_echoing_key_then_runs_real_probe_contract() -> None:
    client, provider, csrf = _client()
    secret = "rotated-provider-secret-never-echoed"
    configuration = client.put(
        "/saas/admin/platform-model-provider/configuration",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={
            "expected_version": 0,
            "enabled": True,
            "base_url": "https://api.deepseek.com",
            "api_type": "openai_chat_completions",
            "api_key": secret,
            "allowed_models": ["deepseek-flash", "deepseek-v4-pro"],
            "default_model": "deepseek-flash",
            "monthly_budget_microusd": 100_000_000,
            "per_tenant_daily_token_limit": 1_000_000,
        },
    )

    assert configuration.status_code == 200
    assert provider.secret == secret
    assert secret not in configuration.text
    assert configuration.json()["state"] == "configured"

    verified = client.post(
        "/saas/admin/platform-model-provider/test",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={"expected_version": 1, "model": "deepseek-flash"},
    )
    assert verified.status_code == 200
    assert verified.json()["state"] == "verified"
    assert secret not in verified.text


def test_single_owner_bridge_revalidates_origin_csrf_user_and_owner() -> None:
    client, _provider, csrf = _client()

    assert client.get("/saas/admin/platform-model-provider/context").status_code == 200
    assert (
        client.put(
            "/saas/admin/platform-model-provider/configuration",
            headers={"Origin": "https://attacker.invalid", "X-CSRF-Token": csrf},
            json={},
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/saas/admin/platform-model-provider/configuration",
            headers={"Origin": ORIGIN},
            json={},
        ).status_code
        == 401
    )


def test_model_admin_assets_are_secret_free_and_use_tenant_csrf_storage() -> None:
    client, _provider, _csrf = _client()

    page = client.get("/saas/admin/platform-model-provider")
    script = client.get("/saas/admin/assets/model-provider-admin.js")

    assert page.status_code == script.status_code == 200
    assert "SINGLE-OWNER BETA" in page.text
    assert "omnigent.saas.csrf" in script.text
    assert "deepseek-flash" in page.text
    assert "sk-" not in page.text + script.text
    assert page.headers["x-governance-mode"] == "single-owner-beta-tenant-bridge"


def test_model_admin_accepts_only_canonical_trusted_proxy_networks() -> None:
    assert _trusted_proxy_cidrs(
        {"OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS": "10.42.0.0/16,fd00:42::/48"}
    ) == ["10.42.0.0/16", "fd00:42::/48"]
    for value in (
        "*",
        "0.0.0.0/0",
        "10.42.1.1/16",
        "10.42.0.0/16, 127.0.0.1/32",
        "10.42.0.0/16,10.42.0.0/16",
        "invalid",
    ):
        try:
            _trusted_proxy_cidrs({"OMNIGENT_SAAS_TRUSTED_PROXY_CIDRS": value})
        except ValueError:
            pass
        else:
            raise AssertionError(f"trusted proxy value was accepted: {value}")


def test_admin_composition_requires_isolated_platform_app_binding(
    tmp_path,
    monkeypatch,
) -> None:
    from saas.production import platform_model_admin as module

    bindings = ProductionServiceRoleBindings(
        path=tmp_path / "platform-model-bindings.json",
        sha256="0" * 64,
        bindings=tuple(
            ProductionServiceRoleBinding(role, f"next_beta_{role}", f"saas_{role}")
            for role in ("app", "authenticator", "platform_app")
        ),
    )
    engines: list[sa.Engine] = []
    real_create_engine = sa.create_engine

    def engine(_url: str, **_kwargs) -> sa.Engine:
        created = real_create_engine("sqlite+pysqlite://")
        engines.append(created)
        return created

    monkeypatch.setattr(module, "load_platform_model_service_role_bindings", lambda _env: bindings)
    monkeypatch.setattr(
        module,
        "load_production_database_url_file",
        lambda _env, role: (
            f"postgresql+psycopg://next_beta_{role}:redacted@example.test/omnigent",
            make_url(f"postgresql+psycopg://next_beta_{role}:redacted@example.test/omnigent"),
            tmp_path / role,
        ),
    )
    monkeypatch.setattr(module.sa, "create_engine", engine)
    monkeypatch.setattr(module, "_inspect_service_login", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "build_production_secret_cipher", lambda _env: object())

    app, built_engines = build_single_owner_model_admin(
        {
            "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_ORIGIN": ORIGIN,
            "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_TENANT_ID": str(TENANT_ID),
            "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_USER_ID": str(USER_ID),
            "OMNIGENT_SAAS_PLATFORM_MODEL_ADMIN_PRINCIPAL_ID": str(PRINCIPAL_ID),
        }
    )

    assert app is not None
    assert built_engines == tuple(engines)
    for built in built_engines:
        built.dispose()
