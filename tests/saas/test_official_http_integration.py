from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import sqlalchemy as sa
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from omnigent.runtime import init as init_runtime
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from omnigent.stores.comment_store.sqlalchemy_store import SqlAlchemyCommentStore
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
from omnigent.stores.file_store.sqlalchemy_store import SqlAlchemyFileStore
from saas.application import create_omnigent_saas_app
from saas.control_plane import (
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    RuntimeCompatibilityPolicy,
    SaasBase,
    SaasCookieConfig,
    SqlAlchemyContextResolver,
    VerifiedIdentityAssertion,
    create_saas_http_integration,
)


def _integration(database_url: str):
    engine = sa.create_engine(database_url)
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    identities = IdentityManagementService(sessions)
    user_id = identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="oidc",
            issuer="https://identity.example.test",
            subject="official-app-user",
            email="official-app@example.test",
            email_verified=True,
        )
    )
    PasswordCredentialService(sessions).set_password(
        user_id=user_id,
        new_password="official-app-password",
        expected_version=None,
        idempotency_key="official-app-password-enrolment",
    )
    resolver = SqlAlchemyContextResolver(
        sessions,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"test-source"}),
            allowed_schema_revisions=frozenset({"test-schema"}),
            adapter_contract_version="0.2.0",
        ),
    )
    integration = create_saas_http_integration(
        lifecycle=MembershipLifecycleService(sessions),
        identities=identities,
        passwords=PasswordCredentialService(sessions),
        context_resolver=resolver,
        cookie_config=SaasCookieConfig(
            name="saas_session",
            secure=False,
            trusted_origins=frozenset({"http://testserver"}),
        ),
    )
    return engine, integration, user_id


def _official_dependencies(database_url: str, tmp_path: Path) -> dict[str, object]:
    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    agent_store = SqlAlchemyAgentStore(database_url)
    conversation_store = SqlAlchemyConversationStore(database_url)
    file_store = SqlAlchemyFileStore(database_url)
    comment_store = SqlAlchemyCommentStore(database_url)
    agent_cache = AgentCache(
        artifact_store=artifact_store,
        cache_dir=tmp_path / "cache",
    )
    init_runtime(
        agent_store=agent_store,
        conversation_store=conversation_store,
        file_store=file_store,
        artifact_store=artifact_store,
        comment_store=comment_store,
        agent_cache=agent_cache,
    )
    return {
        "agent_store": agent_store,
        "file_store": file_store,
        "conversation_store": conversation_store,
        "artifact_store": artifact_store,
        "comment_store": comment_store,
        "agent_cache": agent_cache,
    }


def test_official_app_uses_saas_cookie_identity_for_official_routes(
    db_uri: str,
    tmp_path: Path,
) -> None:
    engine, integration, user_id = _integration(db_uri)
    app = create_omnigent_saas_app(
        integration=integration,
        **_official_dependencies(db_uri, tmp_path),
    )

    with TestClient(app) as client:
        anonymous = client.get("/v1/me")
        assert anonymous.status_code == 401

        logged_in = client.post(
            "/saas/auth/login",
            json={
                "email": "OFFICIAL-APP@example.test",
                "password": "official-app-password",
            },
        )
        assert logged_in.status_code == 200
        assert "HttpOnly" in logged_in.headers["set-cookie"]

        official_me = client.get("/v1/me")
        assert official_me.status_code == 200
        assert official_me.json()["user_id"] == str(user_id)
        assert app.state.saas_http_integration is integration

    engine.dispose()


def test_composition_root_rejects_competing_auth_and_saas_router(
    db_uri: str,
) -> None:
    engine, integration, _user_id = _integration(db_uri)
    try:
        try:
            create_omnigent_saas_app(
                integration=integration,
                auth_provider=object(),
            )
        except ValueError as error:
            assert "independent auth providers" in str(error)
        else:
            raise AssertionError("competing auth provider was accepted")

        try:
            create_omnigent_saas_app(
                integration=integration,
                extra_routers=[(APIRouter(), "/saas", ["duplicate"])],
            )
        except ValueError as error:
            assert "reserved" in str(error)
        else:
            raise AssertionError("duplicate SaaS router was accepted")
    finally:
        engine.dispose()


def test_composition_root_registers_every_saas_owned_router(
    db_uri: str,
    tmp_path: Path,
) -> None:
    engine, integration, _user_id = _integration(db_uri)
    public_router = APIRouter()

    @public_router.get("/composition-probe")
    def composition_probe() -> dict[str, str]:
        return {"status": "registered"}

    integration = replace(integration, public_api_router=public_router)
    app = create_omnigent_saas_app(
        integration=integration,
        **_official_dependencies(db_uri, tmp_path),
    )
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/composition-probe")
            assert response.status_code == 200
            assert response.json() == {"status": "registered"}
    finally:
        engine.dispose()
