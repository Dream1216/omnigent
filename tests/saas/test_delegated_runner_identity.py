"""Delegated owner tokens must resolve an alias, never guess that it is a Global User ID."""

from __future__ import annotations

import secrets
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from omnigent.db.db_models import workspace_scope
from omnigent.runner.identity import (
    OMNIGENT_INTERNAL_WS_ORIGIN,
    RUNNER_TUNNEL_TOKEN_HEADER,
    RUNNER_TUNNEL_WORKSPACE_HEADER,
    token_bound_runner_id,
)
from saas.compatibility import bind_runtime_context
from saas.control_plane.db_models import (
    GlobalUser,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
)
from saas.control_plane.http_auth import SaasAuthProvider, SaasCookieConfig
from saas.control_plane.lifecycle import MembershipLifecycleService
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http


def seed_alias(factory, scope, alias, *, workspace="41"):
    placement, partition = uuid4(), uuid4()
    with factory.begin() as db:
        db.add(
            RuntimePlacementRecord(
                id=placement,
                runtime_type="omnigent",
                data_region="cn-east-1",
                failure_domain="isolated-runner-identity",
                database_cluster_ref="isolated-db",
                object_store_ref="isolated-objects",
                kms_key_ref="isolated-kms",
                official_schema_revision="mm1a2b3c4d5e",
                capacity_class="isolated",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition,
                placement_id=placement,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                runtime_type="omnigent",
                runtime_version="0.18.0.dev20261006",
                physical_partition_key=workspace,
                placement_generation=1,
                source_revision="a" * 40,
                adapter_contract_version="0.2.0",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=partition,
                user_id=scope.owner_id,
                runtime_user_key=alias,
                status="active",
            )
        )
    return placement, partition


@pytest.fixture
def identity_case():
    engine = sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    factory, _, scope, _ = _execution_fixture(engine)
    foreign = uuid4()
    with factory.begin() as db:
        db.add(GlobalUser(id=foreign, status="active", security_version=1))
    lifecycle = MembershipLifecycleService(factory)
    auth = SaasAuthProvider(lifecycle, SaasCookieConfig())
    yield SimpleNamespace(**locals())
    engine.dispose()


@pytest.mark.parametrize("uuid_shaped", [False, True])
def test_runtime_alias_mints_for_its_real_actor_not_a_uuid_collision(identity_case, uuid_shaped):
    f = identity_case
    alias = str(f.foreign) if uuid_shaped else "runtime-agent-owner"
    seed_alias(f.factory, f.scope, alias)
    with workspace_scope(41):
        token = f.auth.mint_runner_token(alias, 60)
    assert token is not None
    assert f.auth.validate_token(token).user_id == f.scope.owner_id


@pytest.mark.parametrize("workspace", [41, 42])
def test_unknown_alias_cannot_fall_back_to_an_unrelated_global_user(identity_case, workspace):
    f = identity_case
    with workspace_scope(workspace):
        assert f.auth.mint_runner_token(str(f.foreign), 60) is None


@pytest.mark.parametrize(
    "drift", ["alias", "partition", "placement", "actor", "workspace", "ambiguous"]
)
def test_inactive_or_ambiguous_runtime_identity_cannot_mint(identity_case, drift):
    f = identity_case
    alias = "runtime-agent-owner"
    placement, partition = seed_alias(f.factory, f.scope, alias)
    if drift == "ambiguous":
        seed_alias(f.factory, f.scope, alias)
    else:
        with f.factory.begin() as db:
            if drift == "alias":
                db.get(
                    RuntimeIdentityAliasRecord, (partition, f.scope.owner_id)
                ).status = "suspended"
            elif drift == "partition":
                db.get(RuntimePartitionRecord, partition).status = "draining"
            elif drift == "placement":
                db.get(RuntimePlacementRecord, placement).status = "draining"
            elif drift == "actor":
                db.get(GlobalUser, f.scope.owner_id).status = "suspended"
    with workspace_scope(42 if drift == "workspace" else 41):
        assert f.auth.mint_runner_token(alias, 60) is None


def test_unscoped_global_user_minting_keeps_the_existing_control_plane_contract(identity_case):
    f = identity_case
    with workspace_scope(0):
        token = f.auth.mint_runner_token(str(f.scope.owner_id), 60)
        assert token is not None
        assert f.auth.validate_token(token).user_id == f.scope.owner_id
        assert f.auth.mint_runner_token("not-a-global-user", 60) is None


def test_real_bootstrap_endpoint_keeps_binding_workspace_and_alias_revocation_checks(
    interactive_http,
):
    f = interactive_http
    token = secrets.token_urlsafe(32)
    runner = token_bound_runner_id(token)
    with bind_runtime_context(f.runtime):
        f.delegate.replace_runner_id(f.conversation.id, runner)
    headers = {
        "Origin": OMNIGENT_INTERNAL_WS_ORIGIN,
        RUNNER_TUNNEL_TOKEN_HEADER: token,
        RUNNER_TUNNEL_WORKSPACE_HEADER: "41",
    }
    client = TestClient(f.app)
    try:
        path = f"/v1/runners/{runner}/token"
        positive = client.post(path, headers=headers)
        assert positive.status_code == 200, positive.text
        principal = MembershipLifecycleService(f.factory).validate_auth_session(
            positive.json()["token"]
        )
        assert principal.user_id == f.runtime.actor_id
        assert (
            client.post(
                path, headers={**headers, RUNNER_TUNNEL_TOKEN_HEADER: secrets.token_urlsafe(32)}
            ).status_code
            == 403
        )
        assert (
            client.post(
                path, headers={**headers, RUNNER_TUNNEL_WORKSPACE_HEADER: "42"}
            ).status_code
            == 401
        )
        with f.factory.begin() as db:
            db.get(
                RuntimeIdentityAliasRecord, (f.runtime.runtime_partition_id, f.runtime.actor_id)
            ).status = "suspended"
        assert client.post(path, headers=headers).status_code in {400, 401, 403}
    finally:
        client.close()
