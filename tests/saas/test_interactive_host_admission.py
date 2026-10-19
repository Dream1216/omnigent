"""The trusted Controller pins a profile without weakening ordinary Host admission."""

from __future__ import annotations

import json
from functools import partial
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.db_models import SqlConversationMetadata, workspace_scope
from omnigent.db.utils import get_or_create_engine
from omnigent.errors import OmnigentError
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
from omnigent.stores.host_store import HostStore
from saas.production.interactive_driver import OfficialInteractiveDriver, _LaunchRegistry
from saas.production.runner_control import RunnerControlError


@pytest.fixture
def admission(db_uri):
    host_id = uuid4().hex
    hosts = HostStore(db_uri)
    conversations = SqlAlchemyConversationStore(db_uri)
    publication = {"public_model_id": "synthetic-model", "snapshot_sha256": "a" * 64}
    with workspace_scope(41):
        hosts.upsert_on_connect(host_id, "isolated-controller-host", "alice")
        conversation = conversations.create_conversation(
            host_id=host_id,
            workspace="/workspace",
            inference_snapshot={"managed_execution": publication, "runtime_config": {}},
        )
    authorized = SimpleNamespace(
        session_id=conversation.id,
        conversation=conversation,
        publication=publication,
        launch={"host_type": "external", "host_id": host_id},
        runtime=SimpleNamespace(physical_workspace_id=41),
    )
    delegate = SimpleNamespace(
        launch_authorizer=partial(hosts.admit_launch, require_account_owner=False),
        admit_launch=AsyncMock(),
    )
    registry = _LaunchRegistry(delegate, authorized, None, set())
    connection = SimpleNamespace(
        host_id=host_id, workspace_id=41, owner="alice", account_generation=None
    )
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
async def test_exact_authorized_external_profile_preserves_default_host_rejection(admission):
    a = admission
    with workspace_scope(41):
        with pytest.raises(OmnigentError, match="saved sandbox inference profile"):
            a.hosts.admit_launch(a.host_id, a.conversation.id, "alice", None)
        await a.registry.admit_launch(a.connection, a.conversation.id)
    a.delegate.admit_launch.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["snapshot", "host_owner", "host_binding", "deleted_host"])
async def test_pinned_profile_does_not_skip_locked_host_or_session_checks(admission, drift):
    a = admission
    with workspace_scope(41):
        if drift == "snapshot":
            with Session(get_or_create_engine(a.db_uri)) as db:
                db.execute(
                    sa.update(SqlConversationMetadata)
                    .where(
                        SqlConversationMetadata.workspace_id == 41,
                        SqlConversationMetadata.id == a.conversation.id,
                    )
                    .values(inference_snapshot=json.dumps({"runtime_config": {}}))
                )
                db.commit()
        elif drift == "host_owner":
            a.connection.owner = "mallory"
        elif drift == "host_binding":
            other = uuid4().hex
            a.hosts.upsert_on_connect(other, "other-host", "alice")
            a.conversations.set_host_id(a.conversation.id, other, workspace="/workspace")
        else:
            a.hosts.delete_host(a.host_id)
        with pytest.raises(OmnigentError):
            await a.registry.admit_launch(a.connection, a.conversation.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift", ["session", "host", "workspace", "unbound", "transfer", "publication", "authority"]
)
async def test_controller_rejects_a_different_target_before_store_admission(admission, drift):
    a = admission
    session_id, options = a.conversation.id, {}
    if drift == "session":
        session_id = uuid4().hex
    elif drift == "host":
        a.connection.host_id = uuid4().hex
    elif drift == "workspace":
        a.connection.workspace_id = 42
    elif drift == "unbound":
        options["allow_unbound"] = True
    elif drift == "transfer":
        options["transfer_from_host_id"] = uuid4().hex
    elif drift == "publication":
        a.authorized.publication = {"public_model_id": "foreign-model"}
    else:
        a.delegate.launch_authorizer = None
    with workspace_scope(41), pytest.raises(RunnerControlError):
        await a.registry.admit_launch(a.connection, session_id, **options)


@pytest.mark.asyncio
async def test_managed_host_keeps_official_admission_without_external_profile_override(admission):
    a = admission
    a.authorized.launch["host_type"] = "managed"
    await a.registry.admit_launch(a.connection, a.conversation.id)
    a.delegate.admit_launch.assert_awaited_once_with(
        a.connection, a.conversation.id, allow_unbound=False, transfer_from_host_id=None
    )


@pytest.mark.asyncio
async def test_managed_driver_uses_the_official_app_tracker_before_provisioning(
    admission, monkeypatch
):
    from fastapi import FastAPI

    from omnigent.server.managed_hosts import ManagedLaunchTracker
    from saas.production import interactive_driver as module

    a = admission
    with workspace_scope(41):
        conversation = a.conversations.create_conversation(host_id=None)
    a.authorized.session_id = conversation.id
    a.authorized.runtime.runtime_user_key = "alice"
    a.authorized.launch = {
        "host_type": "managed",
        "workspaces": [],
        "sandbox_provider": "kubernetes",
    }
    app = FastAPI()
    tracker = ManagedLaunchTracker()
    app.state.managed_launches = tracker
    app.state.host_registry, app.state.runner_router, app.state.tunnel_registry = (
        object(),
        object(),
        object(),
    )
    from omnigent.server.managed_hosts import ManagedSandboxConfig, ManagedSandboxDeployment

    app.state.sandbox_config = ManagedSandboxDeployment.single(
        ManagedSandboxConfig(
            server_url="https://next.test",
            launcher_factory=lambda: None,
            token_ttl_s=3600,
            provider="kubernetes",
        )
    )
    official = SimpleNamespace(
        conversation_store=a.conversations, host_store=a.hosts, agent_store=object()
    )
    driver = OfficialInteractiveDriver(app=app, dependencies=official, contract_version="0.2.0")
    driver._adapter = SimpleNamespace(bind=lambda _: workspace_scope(41))

    class ProvisionReached(Exception):
        pass

    provision = AsyncMock(side_effect=ProvisionReached)
    monkeypatch.setattr(module.official, "_run_managed_launch", provision)

    async def checkpoint(_binding):
        pass

    with pytest.raises(ProvisionReached):
        await driver.prepare(
            a.authorized,
            previous=None,
            on_launch=None,
            on_preparation=checkpoint,
            on_resources=checkpoint,
            on_creation=checkpoint,
        )
    provision.assert_awaited_once()
    assert provision.call_args.kwargs["tracker"] is tracker
    assert tracker.get(conversation.id) is not None
