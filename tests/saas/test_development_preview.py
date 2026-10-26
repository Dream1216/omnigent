from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from fastapi import FastAPI, HTTPException
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from omnigent.runner.development_preview import (
    DevelopmentPreviewServices,
    install_development_preview_routes,
)
from saas.control_plane.db_models import DevelopmentPreviewGrantRecord, GlobalUser, Space, Tenant
from saas.control_plane.development_preview import (
    DevelopmentPreviewGrants,
    DevelopmentPreviewScope,
)


def test_required_browser_acceptance_cannot_skip_missing_chromium(monkeypatch):
    from tests.saas import conftest

    monkeypatch.setenv("OMNIGENT_SAAS_REQUIRE_DEVELOPMENT_PREVIEW_BROWSER", "1")
    monkeypatch.setattr(conftest, "_chromium_is_installed", lambda: False)
    with pytest.raises(pytest.UsageError, match="Chromium runtime is missing"):
        conftest.pytest_collection_modifyitems(
            [SimpleNamespace(path=Path("test_development_preview_browser.py"))]
        )


def test_required_browser_acceptance_cannot_skip_missing_vite(monkeypatch, tmp_path):
    from tests.saas.test_development_preview_browser import interactive_preview

    monkeypatch.setenv("OMNIGENT_SAAS_REQUIRE_DEVELOPMENT_PREVIEW_BROWSER", "1")
    monkeypatch.setattr("shutil.which", lambda _: None)
    fixture = interactive_preview.__wrapped__(tmp_path, monkeypatch, SimpleNamespace())
    with pytest.raises(pytest.fail.Exception, match="toolchain is missing"):
        next(fixture)


@pytest.fixture
def grants():
    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for model in (GlobalUser, Tenant, Space, DevelopmentPreviewGrantRecord):
        model.__table__.create(engine)
    yield DevelopmentPreviewGrants(sessionmaker(engine), b"development-preview-test-key-0001")
    engine.dispose()


def scope():
    return DevelopmentPreviewScope(
        id=uuid4(),
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        auth_session_id=uuid4(),
        security_version=1,
        runtime_partition_id=uuid4(),
        release_incarnation="f" * 32,
        session_id="session-a",
        endpoint_id="a" * 32,
    )


def seed_scope(grants, target):
    with grants.sessions.begin() as db:
        db.add(GlobalUser(id=target.actor_id))
        db.add(
            Tenant(
                id=target.tenant_id,
                slug=target.tenant_id.hex,
                name="Preview",
                home_region="cn-east-1",
            )
        )
    with grants.sessions.begin() as db:
        db.add(
            Space(id=target.space_id, tenant_id=target.tenant_id, slug="preview", name="Preview")
        )


def test_preview_handoff_is_one_use_scoped_persisted_and_revocable(grants):
    target = scope()
    seed_scope(grants, target)
    launch = grants.issue(target, int(time.time()) + 3600)
    with pytest.raises(HTTPException):
        grants.exchange(launch, uuid4())
    cookie, redeemed = grants.exchange(launch, target.id)
    assert redeemed == target
    assert cookie != launch
    with pytest.raises(HTTPException):
        grants.exchange(launch, target.id)
    assert grants.authorize(cookie, target.id) == target
    restarted = DevelopmentPreviewGrants(grants.sessions, grants.key)
    assert restarted.authorize(cookie, target.id) == target
    for invalid in (launch, cookie[:-1] + ("a" if cookie[-1] != "a" else "b"), ""):
        with pytest.raises(HTTPException):
            grants.authorize(invalid, target.id)
    with pytest.raises(HTTPException):
        grants.authorize(cookie, uuid4())
    grants.revoke(target)
    with pytest.raises(HTTPException):
        restarted.authorize(cookie, target.id)


def test_expired_preview_handoff_is_rejected(grants):
    target = scope()
    seed_scope(grants, target)
    launch = grants.issue(target, int(time.time()) - 1)
    with pytest.raises(HTTPException):
        grants.exchange(launch, target.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("after_first_chunk", [False, True])
async def test_revocation_finishes_started_http_stream_without_leaking_later_data(
    grants, after_first_chunk
):
    from saas.production.development_preview import DevelopmentPreviewBroker

    target = scope()
    seed_scope(grants, target)
    launch = grants.issue(target, int(time.time()) + 3600)
    cookie, _ = grants.exchange(launch, target.id)
    closed = []

    class RevokingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            if after_first_chunk:
                yield b"authorized-first-chunk"
            await asyncio.to_thread(grants.revoke, target)
            yield b"must-not-leak-after-revocation"

        async def aclose(self):
            closed.append(True)

    def upstream(request):
        assert "cookie" not in request.headers and "authorization" not in request.headers
        return httpx.Response(200, stream=RevokingStream())

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(upstream), base_url="http://runner"
    ) as runner:

        @asynccontextmanager
        async def live(_scope):
            yield runner

        broker = DevelopmentPreviewBroker(
            grants=grants,
            root_domain="preview.example.test",
            primary_origin="https://app.example.net",
            release_incarnation="f" * 32,
            principal=lambda _connection: None,
            live=live,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=broker.gateway),
            base_url=broker.origin(target.id),
            headers={
                "cookie": f"__Host-omnigent_dev_preview={cookie}; platform-session=never-forward",
                "authorization": "Bearer never-forward",
            },
        ) as browser:
            response = await browser.get("/")
            assert response.status_code == 200
            assert response.content == (b"authorized-first-chunk" if after_first_chunk else b"")
            assert closed == [True]
            assert (await browser.get("/")).status_code == 403


@pytest.fixture
def service_process(tmp_path: Path):
    (tmp_path / "index.html").write_text("<html>owned development service</html>")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    process = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Fixture HTTP process failed to start")
        yield process, port
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


@pytest.mark.asyncio
async def test_discovery_uses_real_owned_listeners_and_rejects_other_sessions(service_process):
    process, port = service_process
    services = DevelopmentPreviewServices(
        lambda session: [process.pid] if session == "owner" else []
    )
    discovered = await services.discover("owner")
    assert len(discovered) == 1
    assert discovered[0]["port"] == port and discovered[0]["status"] == "ready"
    assert discovered[0]["kind"] == "web"
    assert await services.discover("other") == []
    endpoint = str(discovered[0]["id"])
    with pytest.raises(HTTPException):
        await services.resolve("other", endpoint)
    app = FastAPI()
    install_development_preview_routes(app, services)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://runner"
    ) as client:
        response = await client.get(
            f"/v1/sessions/owner/resources/development-preview/{endpoint}/http/"
        )
        assert response.status_code == 200, response.text
        assert response.text == "<html>owned development service</html>"
    process.terminate()
    await asyncio.to_thread(process.wait, 5)
    with pytest.raises(HTTPException):
        await services.resolve("owner", endpoint)


def test_real_postgresql_preview_grant_rls_and_immutable_columns(isolated_postgres_url):
    from sqlalchemy import event
    from sqlalchemy.exc import DBAPIError

    from saas.control_plane.db_models import GlobalUser, Space, Tenant
    from tests.saas.test_postgresql_rls import _migrate

    engine = sa.create_engine(isolated_postgres_url)
    root = Path(__file__).resolve().parents[2]
    target = scope()
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql((root / "saas/control_plane/postgresql_roles.sql").read_text())
    with sessionmaker(engine).begin() as db:
        db.add(GlobalUser(id=target.actor_id))
        db.add(
            Tenant(
                id=target.tenant_id,
                slug=target.tenant_id.hex,
                name="Preview",
                home_region="cn-east-1",
            )
        )
    with sessionmaker(engine).begin() as db:
        db.add(
            Space(id=target.space_id, tenant_id=target.tenant_id, slug="preview", name="Preview")
        )
    app = sa.create_engine(isolated_postgres_url)

    @event.listens_for(app, "connect")
    def scoped_login(connection, _record):
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE saas_app")

    store = DevelopmentPreviewGrants(sessionmaker(app), b"development-preview-real-pg-key-0001")
    try:
        launch = store.issue(target, int(time.time()) + 3600)
        cookie, _ = store.exchange(launch, target.id)
        assert store.authorize(cookie, target.id) == target
        for fields in ({"actor_id": uuid4()}, {"tenant_id": uuid4()}, {"space_id": uuid4()}):
            other = target.model_copy(update=fields)
            with sessionmaker(app)() as db:
                store.bind(db, other)
                assert db.get(DevelopmentPreviewGrantRecord, target.id) is None
        with sessionmaker(app)() as db:
            assert db.get(DevelopmentPreviewGrantRecord, target.id) is None
        for statement in (
            "UPDATE saas_development_preview_grants SET context_json='{}'",
            "UPDATE saas_development_preview_grants SET expires_at=now()+interval '1 day'",
            "DELETE FROM saas_development_preview_grants",
        ):
            with pytest.raises(DBAPIError), app.begin() as connection:
                connection.exec_driver_sql(statement)
        store.revoke(target)
        with pytest.raises(HTTPException):
            store.authorize(cookie, target.id)
    finally:
        app.dispose()
        engine.dispose()


@pytest.mark.asyncio
async def test_background_shell_server_retains_kernel_session_ownership(tmp_path):
    import os
    import shlex

    from omnigent.inner.datamodel import OSEnvSandboxSpec, OSEnvSpec
    from omnigent.inner.os_env import create_os_environment

    if not hasattr(os, "getsid"):
        pytest.skip("kernel session ownership applies to POSIX helpers")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    (tmp_path / "index.html").write_text("<html>background server</html>")
    env = create_os_environment(
        OSEnvSpec(type="caller_process", cwd=str(tmp_path), sandbox=OSEnvSandboxSpec(type="none"))
    )
    try:
        result = await env.shell(
            f"{shlex.quote(sys.executable)} -m http.server {port} --bind 127.0.0.1 "
            ">server.log 2>&1 &",
            timeout=10,
        )
        assert result.get("exit_code") == 0
        services = DevelopmentPreviewServices(
            lambda sid: env.owned_process_roots() if sid == "owner" else ()
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            discovered = await services.discover("owner")
            if any(item["port"] == port and item["status"] == "ready" for item in discovered):
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("Background service was not discovered")
        assert await services.discover("other") == []
    finally:
        env.close()
    assert env.owned_process_roots() == ()
    async with httpx.AsyncClient(trust_env=False, timeout=2) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(f"http://127.0.0.1:{port}")
