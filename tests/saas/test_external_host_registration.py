"""Credential-to-registration contracts on SQLite and disposable PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from itertools import product

import pytest
import sqlalchemy as sa
from asgiref.testing import ApplicationCommunicator
from fastapi import FastAPI
from sqlalchemy.orm import Session
from starlette.types import Receive, Scope, Send

from omnigent.db.db_models import SqlHost, workspace_scope
from omnigent.host.frames import HostHelloFrame, encode_host_frame
from omnigent.server.host_registry import HostRegistry
from omnigent.server.routes.host_tunnel import create_host_tunnel_router
from omnigent.stores.host_store import Host, HostStore, hash_host_launch_token
from saas.production.external_host_credential import (
    arm_external_host_credential,
    revoke_external_host_credential,
)

_HOST = "11111111222243338444555555555555"
_OTHER_HOST = "66666666777748889999aaaaaaaaaaaa"
_OWNER = "registration-test-owner"
_TOKEN = "registration-test-credential-" + "a" * 32
_ROTATED = "registration-test-credential-" + "b" * 32
_NOW = 1_800_000_000
_WORKSPACE = 41


@pytest.fixture(params=["sqlite", "postgresql"])
def registration_store(
    request: pytest.FixtureRequest, db_uri: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[HostStore]:
    uri = db_uri
    if request.param == "postgresql":
        uri = request.getfixturevalue("isolated_postgres_url")
    monkeypatch.setattr("omnigent.stores.host_store.now_epoch", lambda: _NOW)
    store = HostStore(uri)
    with workspace_scope(_WORKSPACE):
        store.upsert_on_connect(_HOST, "external-test", _OWNER)
        store.set_offline(_HOST)
    arm_external_host_credential(
        store._engine,
        workspace_id=_WORKSPACE,
        host_id=_HOST,
        token=_TOKEN,
        ttl_seconds=3600,
        now=_NOW,
    )
    try:
        yield store
    finally:
        if request.param == "postgresql":
            store._engine.dispose()


def _connect(store: HostStore, token: str = _TOKEN) -> Host:
    return store.upsert_on_connect(
        _HOST,
        "connected-test",
        _OWNER,
        managed_token=token,
        configured_harnesses={"claude-sdk": True},
    )


def _mutate(store: HostStore, **values: object) -> None:
    with workspace_scope(_WORKSPACE), Session(store._engine) as session, session.begin():
        session.execute(
            sa.update(SqlHost)
            .where(SqlHost.workspace_id == _WORKSPACE, SqlHost.host_id == _HOST)
            .values(**values)
        )


def test_external_reconnect_and_rotation_preserve_identity(registration_store: HostStore) -> None:
    store = registration_store
    with workspace_scope(_WORKSPACE):
        assert store.resolve_launch_token(_HOST, _TOKEN) is not None
        first = _connect(store)
        assert first.status == "online"
        store.set_offline(_HOST)
        second = _connect(store)
        assert second.host_id == first.host_id
        assert second.user_id == first.user_id == _OWNER
        assert second.sandbox_provider is None
        assert second.sandbox_id is None
        assert second.terminating_sandbox_id is None
        assert second.configured_harnesses == {"claude-sdk": True}
        store.set_offline(_HOST)
        arm_external_host_credential(
            store._engine,
            workspace_id=_WORKSPACE,
            host_id=_HOST,
            token=_ROTATED,
            ttl_seconds=3600,
            expected_token_sha256=hash_host_launch_token(_TOKEN),
            now=_NOW,
        )
        assert store.resolve_launch_token(_HOST, _TOKEN) is None
        with pytest.raises(ValueError, match="no longer valid"):
            _connect(store)
        assert _connect(store, _ROTATED).status == "online"


@pytest.mark.parametrize("boundary", [_NOW - 1, _NOW, _NOW + 1])
def test_resolution_and_atomic_registration_agree_on_expiry(
    registration_store: HostStore, boundary: int
) -> None:
    store = registration_store
    _mutate(store, token_expires_at=boundary)
    with workspace_scope(_WORKSPACE):
        if boundary > _NOW:
            assert store.resolve_launch_token(_HOST, _TOKEN) is not None
            assert _connect(store).status == "online"
        else:
            assert store.resolve_launch_token(_HOST, _TOKEN) is None
            with pytest.raises(ValueError, match="no longer valid"):
                _connect(store)


@pytest.mark.parametrize("change", ["revoke", "rotate", "expire", "delete"])
def test_atomic_registration_rejects_changes_after_successful_resolution(
    registration_store: HostStore, change: str
) -> None:
    store = registration_store
    with workspace_scope(_WORKSPACE):
        assert store.resolve_launch_token(_HOST, _TOKEN) is not None
        if change == "revoke":
            revoke_external_host_credential(
                store._engine,
                workspace_id=_WORKSPACE,
                host_id=_HOST,
                expected_token=_TOKEN,
                now=_NOW,
            )
        elif change == "rotate":
            _mutate(store, token_hash=hash_host_launch_token(_ROTATED))
        elif change == "expire":
            _mutate(store, token_expires_at=_NOW)
        else:
            _mutate(store, deleted_at=_NOW)
        with pytest.raises(ValueError, match="no longer valid"):
            _connect(store)
        with Session(store._engine) as session:
            row = session.get(SqlHost, (_WORKSPACE, _HOST))
            assert row is not None
            assert row.name == "external-test"
            assert row.status != 1


@pytest.mark.parametrize("invalid", ["workspace", "host", "owner", "token", "unarmed"])
def test_invalid_registration_cannot_mutate_or_create_hosts(
    registration_store: HostStore, invalid: str
) -> None:
    store = registration_store
    if invalid == "unarmed":
        _mutate(store, token_hash=None, token_expires_at=None)
    with workspace_scope(_WORKSPACE + (invalid == "workspace")):
        with pytest.raises(ValueError, match="no longer valid"):
            store.upsert_on_connect(
                _OTHER_HOST if invalid == "host" else _HOST,
                "must-not-be-written",
                "wrong-owner" if invalid == "owner" else _OWNER,
                managed_token=_ROTATED if invalid == "token" else _TOKEN,
            )
    with workspace_scope(_WORKSPACE), Session(store._engine) as session:
        rows = session.execute(sa.select(SqlHost)).scalars().all()
        assert len(rows) == 1
        assert rows[0].name == "external-test"
        assert rows[0].user_id == _OWNER


@pytest.mark.parametrize("provider,sandbox,terminating", list(product([False, True], repeat=3)))
def test_registration_requires_a_complete_lifecycle_tuple(
    registration_store: HostStore, provider: bool, sandbox: bool, terminating: bool
) -> None:
    store = registration_store
    _mutate(
        store,
        sandbox_provider="test-provider" if provider else None,
        sandbox_id="current-generation" if sandbox else None,
        terminating_sandbox_id="previous-generation" if terminating else None,
    )
    valid = (provider and sandbox) or not (provider or sandbox or terminating)
    with workspace_scope(_WORKSPACE):
        if valid:
            assert _connect(store).status == "online"
        else:
            with pytest.raises(ValueError, match="no longer valid"):
                _connect(store)


@pytest.mark.asyncio
async def test_external_hello_registers_then_reconnects_and_revocation_refuses_upgrade(
    registration_store: HostStore,
) -> None:
    store = registration_store
    registry = HostRegistry()
    connected = asyncio.Event()

    async def on_connect(host_id: str, _gateway_base_url: str | None) -> None:
        assert host_id == _HOST
        connected.set()

    app = FastAPI()
    app.include_router(
        create_host_tunnel_router(registry, store, on_host_connect=on_connect), prefix="/v1"
    )

    async def scoped_app(scope: Scope, receive: Receive, send: Send) -> None:
        # Communicator clears caller ContextVars, as a real ASGI request does.
        # Supply the trusted partition inside the application task.
        with workspace_scope(_WORKSPACE):
            await app(scope, receive, send)

    path = f"/v1/hosts/{_HOST}/tunnel"
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [(b"x-omnigent-host-token", _TOKEN.encode("ascii"))],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
        "subprotocols": [],
    }
    with workspace_scope(_WORKSPACE):
        for _attempt in range(2):
            connected.clear()
            comm = ApplicationCommunicator(scoped_app, scope)
            try:
                await comm.send_input({"type": "websocket.connect"})
                assert (await comm.receive_output(timeout=5))["type"] == "websocket.accept"
                await comm.send_input(
                    {
                        "type": "websocket.receive",
                        "text": encode_host_frame(
                            HostHelloFrame(
                                version="test", frame_protocol_version=1, name="external-test"
                            )
                        ),
                    }
                )
                await asyncio.wait_for(connected.wait(), timeout=5)
                assert registry.get(_HOST) is not None
                current = store.get_host(_HOST)
                assert current is not None and current.status == "online"
                await comm.send_input({"type": "websocket.disconnect", "code": 1000})
                await comm.wait(timeout=5)
                assert registry.get(_HOST) is None
                current = store.get_host(_HOST)
                assert current is not None and current.status == "offline"
            finally:
                await comm.wait(timeout=5)
        revoke_external_host_credential(
            store._engine,
            workspace_id=_WORKSPACE,
            host_id=_HOST,
            expected_token=_TOKEN,
            now=_NOW,
        )
        comm = ApplicationCommunicator(scoped_app, scope)
        await comm.send_input({"type": "websocket.connect"})
        refused = await comm.receive_output(timeout=5)
        assert refused["type"] == "websocket.close"
        assert refused["code"] == 4004
        await comm.wait(timeout=5)
