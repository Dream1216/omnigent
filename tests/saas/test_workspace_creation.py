from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    PasswordCredential,
    Tenant,
    TenantMembership,
)
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.onboarding_models import (
    SelfServiceRegistrationRecord,
    TenantCreationIntentRecord,
    TenantOnboardingRecord,
)
from tests.saas.test_onboarding_http import TRUSTED_ORIGIN, _http_harness, _HttpHarness
from tests.saas.test_onboarding_workflow import (
    _dispatch_one,
    _Harness,
    _seed_active_placement,
)
from tests.saas.test_onboarding_workflow import onboarding_workflow as onboarding_workflow


@pytest.fixture
def workspace_http() -> Iterator[_HttpHarness]:
    harness = _http_harness()
    try:
        yield next(harness)
    finally:
        harness.close()


def _user(sessions, *, verified: bool = True) -> UUID:
    key = uuid4().hex
    user_id = uuid4()
    with sessions.begin() as db:
        db.add(GlobalUser(id=user_id, status="active", security_version=1))
        db.flush()
        db.add(
            IdentityConnection(
                user_id=user_id,
                provider="casdoor",
                issuer="https://auth.example.test",
                subject=key,
                email_normalized=f"workspace-{key}@example.test",
                email_verified=verified,
                status="active",
            )
        )
    return user_id


def _login(harness: _HttpHarness, *, verified: bool = True) -> tuple[UUID, dict[str, str]]:
    actor_id = _user(harness.sessions, verified=verified)
    from datetime import datetime, timezone

    issued = MembershipLifecycleService(harness.sessions).issue_auth_session(
        user_id=actor_id,
        authn_method="oidc:casdoor",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    harness.client.cookies.set("saas_session", issued.token)
    return actor_id, {
        "Origin": TRUSTED_ORIGIN,
        "X-CSRF-Token": issued.csrf_token,
        "Idempotency-Key": "workspace-test",
    }


def _count(harness: _HttpHarness, model) -> int:
    with harness.sessions() as db:
        return db.scalar(sa.select(sa.func.count()).select_from(model)) or 0


def test_authenticated_actor_can_create_two_workspaces_without_registration_or_password(
    workspace_http: _HttpHarness,
) -> None:
    harness = workspace_http
    actor_id, headers = _login(harness)
    responses = []
    for index in range(2):
        response = harness.client.post(
            "/saas/onboarding/workspaces",
            headers={**headers, "Idempotency-Key": f"create-{index}"},
            json={"tenant_name": f"工作空间 {index}"},
        )
        assert response.status_code == 202
        assert response.headers["cache-control"] == "private, no-store"
        assert response.headers["location"] == response.json()["status_url"]
        responses.append(response.json())
    assert responses[0]["id"] != responses[1]["id"]
    assert _count(harness, GlobalUser) == 1
    assert _count(harness, SelfServiceRegistrationRecord) == 0
    assert _count(harness, PasswordCredential) == 0
    assert _count(harness, Tenant) == 0
    assert len(harness.client.get("/saas/onboarding/workspaces").json()) == 2
    pending = harness.client.get(responses[0]["status_url"])
    assert pending.status_code == 200 and pending.json()["state"] == "pending"
    dispatched = harness.dispatcher.dispatch_once()
    assert dispatched.published == 2
    assert _count(harness, Tenant) == 2
    with harness.sessions() as db:
        sagas = list(db.scalars(sa.select(TenantOnboardingRecord)))
        assert len(sagas) == 2
        assert all(s.user_id == actor_id and s.registration_id is None for s in sagas)
        assert {str(s.creation_intent_id) for s in sagas} == {r["id"] for r in responses}
    status = harness.client.get(responses[0]["status_url"])
    assert status.status_code == 200 and status.json()["state"] == "provisioning"
    assert "tenant_id" not in status.json()


def test_workspace_creation_replay_is_bound_to_actor_and_canonical_request(
    workspace_http: _HttpHarness,
) -> None:
    harness = workspace_http
    _, headers = _login(harness)
    first = harness.client.post(
        "/saas/onboarding/workspaces", headers=headers, json={"tenant_name": "First"}
    )
    replay = harness.client.post(
        "/saas/onboarding/workspaces", headers=headers, json={"tenant_name": "First"}
    )
    assert first.status_code == replay.status_code == 202
    assert first.json()["id"] == replay.json()["id"] and replay.json()["replayed"]
    conflict = harness.client.post(
        "/saas/onboarding/workspaces", headers=headers, json={"tenant_name": "Different"}
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "idempotency_conflict"
    assert _count(harness, ControlPlaneOutboxEvent) == 1
    _, other_headers = _login(harness)
    other = harness.client.post(
        "/saas/onboarding/workspaces", headers=other_headers, json={"tenant_name": "First"}
    )
    assert other.status_code == 202 and other.json()["id"] != first.json()["id"]


def test_workspace_status_is_owned_or_requires_an_active_tenant_membership(
    workspace_http: _HttpHarness,
) -> None:
    harness = workspace_http
    _, headers = _login(harness)
    created = harness.client.post(
        "/saas/onboarding/workspaces", headers=headers, json={"tenant_name": "Owned"}
    ).json()
    assert harness.dispatcher.dispatch_once().published == 1
    other_id, _ = _login(harness)
    missing = f"/saas/onboarding/workspaces/{uuid4()}/status"
    denied = harness.client.get(created["status_url"])
    assert denied.status_code == 404
    assert denied.json() == harness.client.get(missing).json()
    assert harness.client.get("/saas/onboarding/workspaces").json() == []
    with harness.sessions.begin() as db:
        intent = db.get(TenantCreationIntentRecord, UUID(created["id"]))
        assert intent is not None
        db.add(
            TenantMembership(
                tenant_id=intent.tenant_id,
                user_id=other_id,
                role="member",
                status="active",
                version=1,
            )
        )
    assert harness.client.get(created["status_url"]).status_code == 200
    with harness.sessions.begin() as db:
        db.execute(
            sa.update(TenantMembership)
            .where(TenantMembership.user_id == other_id)
            .values(status="removed")
        )
    assert harness.client.get(created["status_url"]).status_code == 404


def test_workspace_creation_requires_cookie_csrf_origin_and_server_actor(
    workspace_http: _HttpHarness,
) -> None:
    harness = workspace_http
    endpoint = "/saas/onboarding/workspaces"
    body = {"tenant_name": "Rejected"}
    assert (
        harness.client.post(
            endpoint, json=body, headers={"Idempotency-Key": "anonymous"}
        ).status_code
        == 401
    )
    _, headers = _login(harness)
    assert (
        harness.client.post(
            endpoint, json=body, headers={"Origin": TRUSTED_ORIGIN, "Idempotency-Key": "csrf"}
        ).status_code
        == 401
    )
    assert (
        harness.client.post(
            endpoint, json=body, headers={**headers, "Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        harness.client.post(
            endpoint, json={**body, "actor_id": str(uuid4())}, headers=headers
        ).status_code
        == 422
    )
    assert _count(harness, TenantCreationIntentRecord) == 0


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"tenant_name": "Default"}, "verified_email_required"),
    ],
)
def test_unverified_identity_cannot_create_trial_resources(
    workspace_http: _HttpHarness,
    body: dict,
    expected: str,
) -> None:
    harness = workspace_http
    _, headers = _login(harness, verified=False)
    response = harness.client.post("/saas/onboarding/workspaces", headers=headers, json=body)
    assert response.status_code == 403 and response.json()["detail"]["code"] == expected
    assert _count(harness, TenantCreationIntentRecord) == 0
    assert _count(harness, ControlPlaneOutboxEvent) == 0


@pytest.mark.parametrize("overrides", [{"plan_key": "unreviewed"}, {"home_region": "unknown"}])
def test_workspace_intent_cannot_choose_unreviewed_product_authority(
    workspace_http: _HttpHarness,
    overrides: dict,
) -> None:
    harness = workspace_http
    _, headers = _login(harness)
    response = harness.client.post(
        "/saas/onboarding/workspaces",
        headers=headers,
        json={"tenant_name": "Rejected", **overrides},
    )
    assert response.status_code == 409
    assert _count(harness, TenantCreationIntentRecord) == 0


def test_workspace_creation_limit_does_not_block_idempotent_recovery(
    workspace_http: _HttpHarness,
) -> None:
    harness = workspace_http
    _, headers = _login(harness)
    for index in range(5):
        response = harness.client.post(
            "/saas/onboarding/workspaces",
            headers={**headers, "Idempotency-Key": str(index)},
            json={"tenant_name": "Limited"},
        )
        assert response.status_code == 202
    limited = harness.client.post(
        "/saas/onboarding/workspaces", headers=headers, json={"tenant_name": "Limited"}
    )
    assert limited.status_code == 429
    replay = harness.client.post(
        "/saas/onboarding/workspaces",
        headers={**headers, "Idempotency-Key": "0"},
        json={"tenant_name": "Limited"},
    )
    assert replay.status_code == 202 and replay.json()["replayed"]
    assert _count(harness, TenantCreationIntentRecord) == 5


def test_authenticated_workspaces_share_billing_runtime_project_activation_saga(
    onboarding_workflow: _Harness,
) -> None:
    h = onboarding_workflow
    user_id = _user(h.sessions)
    creation = h.registrations.workspace_creation_service(h.sessions)
    accepted = [
        creation.create(
            actor_id=user_id,
            tenant_name=f"Workspace {n}",
            idempotency_key=f"auth-workspace-{n}",
            now=h.now,
        )
        for n in range(2)
    ]
    _seed_active_placement(h)
    for _ in range(10):
        _dispatch_one(h)
    with h.sessions() as db:
        sagas = list(db.scalars(sa.select(TenantOnboardingRecord)))
        assert {s.id for s in sagas} == {a.onboarding_id for a in accepted}
        assert all(s.status == "active" and s.registration_id is None for s in sagas)
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(SelfServiceRegistrationRecord)) == 0
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(PasswordCredential)) == 0


def test_account_disabled_after_intent_cannot_start_provisioning(onboarding_workflow: _Harness):
    from saas.control_plane.onboarding import OnboardingError

    h = onboarding_workflow
    actor_id = _user(h.sessions)
    accepted = h.registrations.workspace_creation_service(h.sessions).create(
        actor_id=actor_id, tenant_name="Stopped", idempotency_key="disabled-after-request"
    )
    with h.sessions.begin() as db:
        db.execute(
            sa.update(GlobalUser).where(GlobalUser.id == actor_id).values(status="suspended")
        )
    with pytest.raises(OnboardingError, match="active account"):
        h.composition.coordinator.start_intent(
            creation_intent_id=accepted.intent_id, idempotency_key="disabled-start"
        )
    with h.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0
