from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ApiCredentialError,
    ApiCredentialRecord,
    ApiCredentialService,
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityManagementService,
    MembershipLifecycleService,
    PasswordCredentialService,
    ProjectMembershipRecord,
    ProjectRecord,
    RuntimeCompatibilityPolicy,
    SaasBase,
    SaasCookieConfig,
    ServiceAccountRemovalImpactProvider,
    Space,
    SpaceMembership,
    SqlAlchemyContextResolver,
    Tenant,
    TenantMembership,
    create_saas_http_integration,
)

_NOW = datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc)
_PEPPER = b"api-credential-test-pepper-material-v1!!"


def _fixture() -> tuple[sessionmaker, dict[str, UUID]]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    ids = {
        name: uuid4()
        for name in ("owner", "admin", "steward", "successor", "tenant", "space", "project")
    }
    with sessions.begin() as db:
        db.add_all(
            [
                GlobalUser(id=ids[role], status="active", security_version=1)
                for role in ("owner", "admin", "steward", "successor")
            ]
        )
        db.add(
            Tenant(
                id=ids["tenant"],
                slug="machine-tenant",
                name="Machine Tenant",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=ids["tenant"],
                    user_id=ids[role],
                    role=(
                        "owner" if role == "owner" else ("admin" if role == "admin" else "member")
                    ),
                    status="active",
                    version=1,
                )
                for role in ("owner", "admin", "steward", "successor")
            ]
        )
        db.add(
            Space(
                id=ids["space"],
                tenant_id=ids["tenant"],
                slug="engineering",
                name="Engineering",
                status="active",
            )
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=ids["tenant"],
                    space_id=ids["space"],
                    user_id=ids[role],
                    role=(
                        "owner" if role == "owner" else ("admin" if role == "admin" else "member")
                    ),
                    status="active",
                    version=1,
                )
                for role in ("owner", "admin", "steward", "successor")
            ]
        )
        db.add(
            ProjectRecord(
                id=ids["project"],
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                name="Machine Project",
                visibility="private",
                created_by=ids["owner"],
                status="active",
                authorization_version=1,
            )
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                project_id=ids["project"],
                subject_type="user",
                subject_id=ids["owner"],
                role="owner",
                status="active",
                created_by=ids["owner"],
                version=1,
            )
        )
    return sessions, ids


def _create_account(
    service: ApiCredentialService,
    ids: dict[str, UUID],
    *,
    actor: str = "owner",
    key: str = "create-service-account",
):
    return service.create_service_account(
        actor_id=ids[actor],
        tenant_id=ids["tenant"],
        space_id=ids["space"],
        project_id=ids["project"],
        steward_user_id=ids["steward"],
        name="build-bot",
        description="Project automation",
        authenticated_at=_NOW,
        idempotency_key=key,
        now=_NOW,
    )


def _issue(
    service: ApiCredentialService,
    ids: dict[str, UUID],
    account_id: UUID,
    *,
    key: str = "issue-api-key",
    networks: tuple[str, ...] = ("10.20.0.0/24",),
):
    return service.issue_api_credential(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account_id,
        name="ci-key",
        permission_scopes=("run.create", "project.content.read"),
        allowed_networks=networks,
        expires_at=_NOW + timedelta(days=30),
        authenticated_at=_NOW,
        idempotency_key=key,
        now=_NOW,
    )


def test_api_key_is_one_time_hashed_scope_bound_and_network_bound() -> None:
    sessions, ids = _fixture()
    service = ApiCredentialService(sessions, credential_pepper=_PEPPER)
    account = _create_account(service, ids)
    replay = _create_account(service, ids)
    assert replay.id == account.id
    assert replay.replayed is True

    issued = _issue(service, ids, account.id)
    assert issued.token is not None and issued.token.startswith("omk_")
    replayed = _issue(service, ids, account.id)
    assert replayed.credential_id == issued.credential_id
    assert replayed.token is None
    assert replayed.replayed is True

    with sessions.begin() as db:
        stored = db.get(ApiCredentialRecord, issued.credential_id)
        assert stored is not None
        assert stored.token_hash != issued.token
        assert issued.token not in json.dumps(stored.permission_scopes)
        events = list(db.execute(sa.select(ControlPlaneOutboxEvent)).scalars())
        assert issued.token not in json.dumps([event.payload for event in events])

    principal = service.authenticate(issued.token, source_ip="10.20.0.8", now=_NOW)
    assert principal.service_account_id == account.id
    service.require_permission(
        principal,
        permission="run.create",
        tenant_id=ids["tenant"],
        space_id=ids["space"],
        project_id=ids["project"],
    )
    service.authenticate(
        issued.token,
        source_ip="10.20.0.9",
        now=_NOW + timedelta(minutes=1),
    )
    with sessions.begin() as db:
        coalesced = db.get(ApiCredentialRecord, issued.credential_id)
        assert coalesced is not None
        assert coalesced.last_used_at is not None
        assert coalesced.last_used_at.replace(tzinfo=timezone.utc) == _NOW
        assert coalesced.last_used_ip == "10.20.0.8"
    service.authenticate(
        issued.token,
        source_ip="10.20.0.10",
        now=_NOW + timedelta(minutes=6),
    )
    with sessions.begin() as db:
        refreshed = db.get(ApiCredentialRecord, issued.credential_id)
        assert refreshed is not None
        assert refreshed.last_used_at is not None
        assert refreshed.last_used_at.replace(tzinfo=timezone.utc) == _NOW + timedelta(minutes=6)
        assert refreshed.last_used_ip == "10.20.0.10"
    with pytest.raises(ApiCredentialError, match="source network") as network_error:
        service.authenticate(issued.token, source_ip="192.0.2.5", now=_NOW)
    assert network_error.value.code == "api_credential_network_forbidden"
    with pytest.raises(ApiCredentialError) as scope_error:
        service.require_permission(
            principal,
            permission="run.create",
            tenant_id=ids["tenant"],
            project_id=uuid4(),
        )
    assert scope_error.value.code == "scope_mismatch"


def test_content_blind_admin_cannot_mint_permissions_they_do_not_hold() -> None:
    sessions, ids = _fixture()
    service = ApiCredentialService(sessions, credential_pepper=_PEPPER)
    account = _create_account(service, ids, actor="admin", key="admin-create")
    with pytest.raises(ApiCredentialError) as error:
        service.issue_api_credential(
            actor_id=ids["admin"],
            tenant_id=ids["tenant"],
            service_account_id=account.id,
            name="escalation",
            permission_scopes=("project.content.read",),
            allowed_networks=(),
            expires_at=_NOW + timedelta(days=1),
            authenticated_at=_NOW,
            idempotency_key="admin-escalation",
            now=_NOW,
        )
    assert error.value.code == "permission_escalation_forbidden"


def test_rotation_revocation_and_steward_transfer_invalidate_immediately() -> None:
    sessions, ids = _fixture()
    service = ApiCredentialService(sessions, credential_pepper=_PEPPER)
    account = _create_account(service, ids)
    old = _issue(service, ids, account.id, networks=())
    assert old.token is not None
    replacement = service.rotate_api_credential(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account.id,
        credential_id=old.credential_id,
        expires_at=_NOW + timedelta(days=60),
        authenticated_at=_NOW,
        idempotency_key="rotate-key",
        now=_NOW,
    )
    assert replacement.token is not None
    with pytest.raises(ApiCredentialError):
        service.authenticate(old.token, source_ip="127.0.0.1", now=_NOW)
    assert (
        service.authenticate(replacement.token, source_ip="127.0.0.1", now=_NOW).credential_id
        == replacement.credential_id
    )
    rotation_replay = service.rotate_api_credential(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account.id,
        credential_id=old.credential_id,
        expires_at=_NOW + timedelta(days=60),
        authenticated_at=_NOW,
        idempotency_key="rotate-key",
        now=_NOW,
    )
    assert rotation_replay.token is None

    changed = service.transfer_steward(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account.id,
        to_user_id=ids["successor"],
        expected_security_version=1,
        authenticated_at=_NOW,
        idempotency_key="transfer-steward",
        now=_NOW,
    )
    assert changed.security_version == 2
    assert changed.revoked_credential_count == 1
    with pytest.raises(ApiCredentialError):
        service.authenticate(replacement.token, source_ip="127.0.0.1", now=_NOW)


def test_member_removal_impact_requires_explicit_steward_transfer() -> None:
    sessions, ids = _fixture()
    service = ApiCredentialService(sessions, credential_pepper=_PEPPER)
    account = _create_account(service, ids)
    _issue(service, ids, account.id, networks=())
    impacts = ServiceAccountRemovalImpactProvider(sessions)
    before = impacts.collect(
        tenant_id=ids["tenant"], space_id=ids["space"], user_id=ids["steward"]
    )
    assert before.blocking_count == 1
    facts = before.facts["stewarded_service_accounts"]
    assert isinstance(facts, list) and len(facts[0]["credentials"]) == 1
    service.transfer_steward(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account.id,
        to_user_id=ids["successor"],
        expected_security_version=1,
        authenticated_at=_NOW,
        idempotency_key="impact-transfer",
        now=_NOW,
    )
    after = impacts.collect(tenant_id=ids["tenant"], space_id=ids["space"], user_id=ids["steward"])
    assert after.blocking_count == 0


def test_versioned_http_separates_human_management_from_machine_use() -> None:
    sessions, ids = _fixture()
    service = ApiCredentialService(sessions, credential_pepper=_PEPPER)
    lifecycle = MembershipLifecycleService(sessions)
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=IdentityManagementService(sessions),
        passwords=PasswordCredentialService(sessions),
        context_resolver=SqlAlchemyContextResolver(
            sessions,
            RuntimeCompatibilityPolicy(
                runtime_type="omnigent",
                allowed_runtime_versions=frozenset({"test"}),
                allowed_source_revisions=frozenset({"test"}),
                allowed_schema_revisions=frozenset({"test"}),
                adapter_contract_version="test",
            ),
        ),
        cookie_config=SaasCookieConfig(
            name="saas_session",
            secure=False,
            trusted_origins=frozenset({"http://testserver"}),
        ),
        api_credentials=service,
    )
    app = FastAPI()
    for router, prefix, tags in integration.extra_routers:
        app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    client = TestClient(app)
    http_now = datetime.now(timezone.utc)
    human = lifecycle.issue_auth_session(
        user_id=ids["owner"],
        authn_method="test",
        expires_at=http_now + timedelta(hours=1),
        now=http_now,
    )
    human_headers = {"Authorization": f"Bearer {human.token}"}
    client.cookies.set("saas_session", human.token)
    created = client.post(
        f"/api/v1/tenants/{ids['tenant']}/service-accounts",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": human.csrf_token,
            "Idempotency-Key": "http-account",
        },
        json={
            "space_id": str(ids["space"]),
            "project_id": str(ids["project"]),
            "steward_user_id": str(ids["steward"]),
            "name": "http-bot",
        },
    )
    assert created.status_code == 201, created.text
    account_id = created.json()["id"]
    ambiguous = client.get("/api/v1/auth/whoami", headers=human_headers)
    assert ambiguous.status_code == 400
    assert ambiguous.json()["detail"]["code"] == "ambiguous_authentication"
    client.cookies.clear()
    issued = client.post(
        f"/api/v1/tenants/{ids['tenant']}/service-accounts/{account_id}/api-keys",
        headers={**human_headers, "Idempotency-Key": "http-key"},
        json={
            "name": "http-key",
            "permission_scopes": ["run.create"],
            "allowed_networks": [],
            "expires_at": (http_now + timedelta(days=1)).isoformat(),
        },
    )
    assert issued.status_code == 201, issued.text
    token = issued.json()["token"]
    machine_headers = {"Authorization": f"Bearer {token}"}
    whoami = client.get("/api/v1/auth/whoami", headers=machine_headers)
    assert whoami.status_code == 200
    assert whoami.json()["actor_type"] == "service_account"
    allowed = client.post(
        "/api/v1/auth/authorize",
        headers=machine_headers,
        json={
            "permission": "run.create",
            "tenant_id": str(ids["tenant"]),
            "space_id": str(ids["space"]),
            "project_id": str(ids["project"]),
        },
    )
    assert allowed.status_code == 200
    assert client.get("/saas/auth/me", headers=machine_headers).status_code == 403
    assert (
        client.post(
            f"/api/v1/tenants/{ids['tenant']}/service-accounts",
            headers={**machine_headers, "Idempotency-Key": "machine-must-not-manage"},
            json={
                "space_id": str(ids["space"]),
                "project_id": str(ids["project"]),
                "steward_user_id": str(ids["steward"]),
                "name": "forbidden",
            },
        ).status_code
        == 401
    )
