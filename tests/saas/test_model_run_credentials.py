from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.db_models import ProjectMembershipRecord, RuntimeResourceBindingRecord
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord, TaskRecord
from saas.control_plane.model_routing_models import ModelRunTokenRecord
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production.interactive_runtime import ProductionInteractiveRuntimeFactory
from saas.production.model_run_credentials import ModelRunCredentialService
from saas.production.runner_control import RunnerControlError
from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runtime import _running_lease, _runtime_authority


def _service(f, authority, **kwargs):
    return ModelRunCredentialService(
        app_sessions=f.factory,
        authenticator_sessions=f.factory,
        compatibility=authority._resolver._compatibility_policy,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_credential_binds_real_run_and_persists_no_plaintext(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authorized = await authority.authorize(lease)
    service = _service(f, authority)
    now = datetime.now(timezone.utc)
    issued = service.issue(authorized, lease, now=now)
    assert issued == service.issue(authorized, lease, now=now + timedelta(seconds=1))
    assert issued.expires_at == now + timedelta(hours=8)
    assert issued.value not in repr(issued)
    claims = service.authenticate(issued.value)
    grant = service.authorize(claims)
    assert grant.claims.run_id == lease.run_id
    assert grant.runtime.actor_id == f.runtime.actor_id
    assert grant.runtime.project_id == f.project_id
    assert grant.publication["public_model_id"] == f.marker["public_model_id"]
    with f.factory() as db:
        row = db.scalars(sa.select(ModelRunTokenRecord)).one()
        assert row.token_hash == sha256(issued.value.encode()).hexdigest()
        assert row.actor_id == f.runtime.actor_id and row.capability_id == lease.capability_id
        assert row.expires_at.replace(tzinfo=timezone.utc) == issued.expires_at
        assert (
            grant.customer_pricing_snapshot_id
            == db.get(RunRecord, lease.run_id).customer_pricing_snapshot_id
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
    with pytest.raises(PlatformModelGatewayTokenError):
        service.authenticate("legacy-session-token")
    with pytest.raises(PlatformModelGatewayTokenError):
        service.authenticate("mrt_" + "0" * 64)
    browser = TestClient(f.app)
    try:
        response = browser.get(
            "/saas/auth/me", headers={"Authorization": f"Bearer {issued.value}"}
        )
        assert response.status_code == 401
    finally:
        browser.close()


@pytest.mark.asyncio
async def test_expired_refresh_is_idempotent_and_does_not_replay_a_task(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authorized = await authority.authorize(lease)
    service = _service(f, authority, ttl=timedelta(seconds=10))
    calls_before = list(f.calls)
    now = datetime.now(timezone.utc)
    first = service.issue(authorized, lease, now=now)
    expired = now + timedelta(seconds=11)
    with pytest.raises(PlatformModelGatewayTokenExpired):
        service.authenticate(first.value, now=expired)
    second = service.renew(first.value, now=expired)
    assert second.generation == 1 and second.value != first.value
    assert second == service.renew(first.value, now=expired)
    assert second == service.issue(authorized, lease, now=expired)
    assert service.authenticate(second.value, now=expired).run_id == lease.run_id
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelRunTokenRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
    assert f.calls == calls_before  # Renewal performs no provider call.


@pytest.mark.asyncio
async def test_lost_reply_recovery_at_the_credential_generation_bound(
    interactive_http, monkeypatch
):
    from saas.production import model_run_credentials

    monkeypatch.setattr(model_run_credentials, "_MAX_CHAIN", 2)
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authorized = await authority.authorize(lease)
    service = _service(f, authority, ttl=timedelta(seconds=10))
    now = datetime.now(timezone.utc)
    first = service.issue(authorized, lease, now=now)
    service.renew(first.value, now=now + timedelta(seconds=11))
    latest = service.renew(first.value, now=now + timedelta(seconds=22))
    assert latest.generation == 2
    assert service.renew(first.value, now=now + timedelta(seconds=22)) == latest
    with pytest.raises(PlatformModelGatewayTokenError, match="exceeds its bound"):
        service.renew(first.value, now=now + timedelta(seconds=33))


@pytest.mark.parametrize(
    "drift", ["cancelling", "revoked", "project", "lease", "runtime_project", "session"]
)
@pytest.mark.asyncio
async def test_live_authority_loss_blocks_model_use_and_refresh(interactive_http, drift):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authorized = await authority.authorize(lease)
    service = _service(f, authority)
    issued = service.issue(authorized, lease)
    with f.factory.begin() as db:
        if drift == "cancelling":
            db.get(RunRecord, lease.run_id).status = "cancelling"
        elif drift == "revoked":
            cap = db.get(CapabilityTokenRecord, lease.capability_id)
            cap.revoked_at = datetime.now(timezone.utc)
            cap.revocation_reason = "test revocation"
        elif drift == "project":
            db.execute(sa.update(ProjectMembershipRecord).values(status="revoked"))
        elif drift == "runtime_project":
            db.execute(
                sa.update(RuntimeResourceBindingRecord)
                .where(RuntimeResourceBindingRecord.resource_type == "project")
                .values(runtime_resource_id="d" * 32)
            )
        elif drift == "session":
            session = db.get(ExecutionSessionRecord, db.get(RunRecord, lease.run_id).session_id)
            session.status = "closed"
            session.closed_at = datetime.now(timezone.utc)
        else:
            db.get(RunRecord, lease.run_id).lease_expires_at = datetime.now(
                timezone.utc
            ) - timedelta(seconds=1)
    claims = service.authenticate(issued.value)
    with pytest.raises((PermissionError, PlatformModelGatewayTokenError)):
        service.authorize(claims)
    with pytest.raises((PermissionError, PlatformModelGatewayTokenError)):
        service.renew(issued.value)


@pytest.mark.asyncio
async def test_credential_scope_cannot_borrow_another_run_or_capability(interactive_http):
    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    authorized = await authority.authorize(lease)
    service = _service(f, authority)
    issued = service.issue(authorized, lease)
    claims = service.authenticate(issued.value)
    for change in (
        {"run_id": uuid4()},
        {"capability_id": uuid4()},
        {"fence_token": lease.fence_token + 1},
    ):
        with pytest.raises(PlatformModelGatewayTokenError):
            service.authorize(replace(claims, **change))
    with pytest.raises(PlatformModelGatewayTokenError):
        service.issue(authorized, replace(lease, fence_token=lease.fence_token + 1))


@pytest.mark.parametrize("authentication", ["missing", "app", "separate"])
@pytest.mark.asyncio
async def test_production_issuance_rejects_missing_role_split_or_non_mtls_control(
    interactive_http, authentication
):
    from sqlalchemy.orm import sessionmaker

    f = interactive_http
    lease, connection = _running_lease(f)
    authority = _runtime_authority(f, connection)
    engine = sa.create_engine("sqlite://")
    try:
        factory = ProductionInteractiveRuntimeFactory(
            product_revision="c" * 40,
            image_digest="sha256:" + "a" * 64,
            app_sessions=f.factory,
            authenticator_sessions=(
                None
                if authentication == "missing"
                else f.factory
                if authentication == "app"
                else sessionmaker(engine)
            ),
            compatibility=authority._resolver._compatibility_policy,
            conversation_store=f.delegate,
            permission_store=f.permissions,
        )
        with pytest.raises(RunnerControlError, match="Runtime authority changed"):
            await factory.authorize_model(
                lease=lease,
                identity=authority._identity,
                control=None,
                runner_sessions=f.factory,
                fleet_source={},
            )
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(ModelRunTokenRecord)) == 0
    finally:
        engine.dispose()
