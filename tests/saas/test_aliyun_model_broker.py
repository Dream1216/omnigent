from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from omnigent.db.db_models import workspace_scope
from omnigent.db.utils import now_epoch
from omnigent.server.auth import LEVEL_OWNER
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
from omnigent.stores.host_store import HostStore
from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
from saas.control_plane.http_auth import (
    SaasAuthContextMiddleware,
    SaasAuthProvider,
    SaasCookieConfig,
)
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.production.aliyun_model_broker import (
    AliyunHostModelBroker,
    HostModelAdmissionDenied,
    create_aliyun_host_model_router,
)
from saas.production.aliyun_model_lease import HostModelLeaseAuthority, HostModelLeaseError
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority
from tests.saas.test_control_plane_resolver import (
    COMPATIBILITY_POLICY,
    GlobalUser,
)
from tests.saas.test_control_plane_resolver import (
    control_plane as control_plane,
)


@pytest.fixture
def broker_case(control_plane, db_uri):
    factory, scope = control_plane
    resolver = SqlAlchemyContextResolver(factory, COMPATIBILITY_POLICY)
    request = resolver.resolve_request_context(
        actor_id=scope.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        trace_id="model-broker-test",
    )
    runtime = resolver.resolve_space_allocation(request)
    clock = [now_epoch()]
    host_id, token = uuid4().hex, "t" * 43
    hosts = HostStore(db_uri)
    conversations = SqlAlchemyConversationStore(db_uri)
    permissions = SqlAlchemyPermissionStore(db_uri)
    with workspace_scope(runtime.physical_workspace_id):
        permissions.ensure_user(runtime.runtime_user_key)
        hosts.register_managed_host(
            host_id=host_id,
            name="cloud-model-test",
            user_id=runtime.runtime_user_key,
            token=token,
            provider="e2b",
            sandbox_id="sbx-model-test",
            token_expires_at=now_epoch() + 7200,
        )
        conversation = conversations.create_conversation(
            host_id=host_id, workspace="/home/user/workspace", conversation_id=str(uuid4())
        )
        permissions.grant(runtime.runtime_user_key, conversation.id, LEVEL_OWNER)
    leases = HostModelLeaseAuthority(b"l" * 32)
    lease = leases.issue(
        host_id=host_id, launch_token=token, runtime=runtime, ttl_seconds=5400, now=clock[0]
    )
    authority = PlatformModelGatewayTokenAuthority(
        signing_key=b"m" * 32, tenant_id=runtime.tenant_id
    )

    def build(resolved=resolver, authorities=None):
        return AliyunHostModelBroker(
            leases=leases,
            resolver=resolved,
            host_store=hosts,
            conversation_store=conversations,
            permission_store=permissions,
            authorities=authorities or {runtime.tenant_id: authority},
            clock=lambda: clock[0],
        )

    return SimpleNamespace(
        broker=build(),
        build=build,
        factory=factory,
        runtime=runtime,
        clock=clock,
        host_id=host_id,
        token=token,
        lease=lease,
        session_id=UUID(conversation.id),
        hosts=hosts,
        conversations=conversations,
        permissions=permissions,
        authority=authority,
    )


def _issue(case, **overrides):
    return case.broker.issue(
        **{
            "host_id": case.host_id,
            "launch_token": case.token,
            "lease_token": case.lease,
            "session_id": case.session_id,
            **overrides,
        }
    )


def test_model_bearer_is_tenant_session_bound_and_five_minutes(broker_case):
    c = broker_case
    with workspace_scope(c.runtime.physical_workspace_id):
        issued = _issue(c)
    claims = c.authority.validate(issued.token, now=c.clock[0])
    assert claims.session_id == c.session_id and claims.tenant_id == c.runtime.tenant_id
    assert issued.expires_at == claims.expires_at == c.clock[0] + 300
    assert issued.token not in repr(issued)


def test_gateway_renewal_survives_server_replica_restart(broker_case):
    c = broker_case
    with workspace_scope(c.runtime.physical_workspace_id):
        first = _issue(c)
        c.clock[0] += 301
        c.broker = c.build()
        second = _issue(c)
    assert first.token != second.token
    assert c.authority.validate(second.token, now=c.clock[0]).issued_at == c.clock[0]


@pytest.mark.parametrize("workspace", [0, -1, 92])
def test_untrusted_or_wrong_workspace_cannot_issue_model_credential(broker_case, workspace):
    with workspace_scope(workspace), pytest.raises(HostModelAdmissionDenied):
        _issue(broker_case)


def test_host_token_revocation_stops_further_model_credential_issuance(broker_case):
    c = broker_case
    with workspace_scope(c.runtime.physical_workspace_id):
        c.hosts.revoke_launch_token(c.host_id)
        with pytest.raises(HostModelAdmissionDenied):
            _issue(c)


def test_membership_security_change_stops_renewal_even_with_valid_host_token(broker_case):
    c = broker_case
    with c.factory.begin() as db:
        user = db.get(GlobalUser, c.runtime.actor_id)
        assert user is not None
        user.security_version += 1
    with (
        workspace_scope(c.runtime.physical_workspace_id),
        pytest.raises(ControlPlaneResolutionError),
    ):
        _issue(c)


def test_session_owner_permission_revocation_stops_model_access(broker_case):
    c = broker_case
    with workspace_scope(c.runtime.physical_workspace_id):
        c.permissions.revoke(c.runtime.runtime_user_key, str(c.session_id))
        with pytest.raises(HostModelAdmissionDenied):
            _issue(c)


def test_other_owners_session_on_same_host_cannot_spend_model_budget(broker_case):
    c = broker_case
    with workspace_scope(c.runtime.physical_workspace_id):
        other = c.conversations.create_conversation(
            host_id=c.host_id, workspace="/home/user/workspace", conversation_id=str(uuid4())
        )
        c.permissions.ensure_user("another-owner")
        c.permissions.grant("another-owner", other.id, LEVEL_OWNER)
        with pytest.raises(HostModelAdmissionDenied):
            _issue(c, session_id=UUID(other.id))


def test_model_token_cannot_outlive_its_original_host_lease(broker_case):
    c = broker_case
    c.clock[0] += 5390
    with workspace_scope(c.runtime.physical_workspace_id):
        issued = _issue(c)
    assert c.authority.validate(issued.token, now=c.clock[0]).expires_at == c.clock[0] + 10
    c.clock[0] += 10
    with workspace_scope(c.runtime.physical_workspace_id), pytest.raises(HostModelLeaseError):
        _issue(c)


def test_absent_tenant_authority_does_not_fall_back_to_another_tenant(broker_case):
    c = broker_case
    other = PlatformModelGatewayTokenAuthority(signing_key=b"x" * 32, tenant_id=uuid4())
    c.broker = c.build(authorities={other.tenant_id: other})
    with workspace_scope(c.runtime.physical_workspace_id), pytest.raises(HostModelAdmissionDenied):
        _issue(c)


def test_http_broker_checks_credentials_and_prevents_response_caching(broker_case):
    c = broker_case
    app = FastAPI()
    app.include_router(create_aliyun_host_model_router(c.broker), prefix="/v1")

    @app.middleware("http")
    async def trusted_test_workspace(request, call_next):
        with workspace_scope(c.runtime.physical_workspace_id):
            return await call_next(request)

    path = f"/v1/hosts/{c.host_id}/sessions/{c.session_id}/model-token"
    with TestClient(app) as client:
        result = client.post(path)
        assert result.status_code == 401 and result.headers["Cache-Control"] == "no-store"
        result = client.post(
            path,
            headers={
                "X-Omnigent-Host-Token": c.token,
                "X-Omnigent-Model-Lease": c.lease,
            },
        )
        assert result.status_code == 200 and result.headers["Cache-Control"] == "no-store"
        assert c.authority.validate(result.json()["token"]).session_id == c.session_id
        with workspace_scope(c.runtime.physical_workspace_id):
            c.hosts.revoke_launch_token(c.host_id)
        result = client.post(
            path,
            headers={
                "X-Omnigent-Host-Token": c.token,
                "X-Omnigent-Model-Lease": c.lease,
            },
        )
        assert result.status_code == 403 and c.token not in result.text


@pytest.mark.parametrize("enabled", [False, True])
def test_real_machine_middleware_and_broker_require_opt_in_and_signed_workspace(
    broker_case, enabled
):
    c = broker_case
    app = FastAPI()
    app.include_router(create_aliyun_host_model_router(c.broker), prefix="/v1")
    cookies = SaasCookieConfig()
    app.add_middleware(
        SaasAuthContextMiddleware,
        auth_provider=SaasAuthProvider(MembershipLifecycleService(c.factory), cookies),
        context_resolver=SqlAlchemyContextResolver(c.factory, COMPATIBILITY_POLICY),
        cookie_config=cookies,
        host_model_broker_enabled=enabled,
    )
    path = f"/v1/hosts/{c.host_id}/sessions/{c.session_id.hex}/model-token"
    headers = {
        "X-Omnigent-Host-Token": c.token,
        "X-Omnigent-Model-Lease": c.lease,
        "X-Omnigent-Workspace-Id": str(c.runtime.physical_workspace_id),
    }
    with TestClient(app) as client:
        response = client.post(path, headers=headers)
        assert response.status_code == (200 if enabled else 403)
        if enabled:
            assert c.authority.validate(response.json()["token"]).session_id == c.session_id
        foreign = client.post(
            path,
            headers={
                **headers,
                "X-Omnigent-Workspace-Id": str(c.runtime.physical_workspace_id + 1),
            },
        )
        assert foreign.status_code == 403
        mixed = client.post(path, headers={**headers, "Authorization": "Bearer user-token"})
        assert mixed.status_code == 403
