"Real password/cookie auth, official ownership, Vite HTTP/HMR, and browser handoff."

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.responses import Response
from playwright.sync_api import sync_playwright
from websockets.asyncio.client import connect

from omnigent.runner.development_preview import (
    DevelopmentPreviewServices,
    install_development_preview_routes,
)


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextlib.contextmanager
def _server(app, port, **tls):
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            loop="asyncio",
            http="h11",
            ws="websockets",
            **tls,
        )
    )
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 60
        while not server.started:
            if not worker.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Preview test server did not start")
            time.sleep(0.02)
        yield
    finally:
        server.should_exit = True
        worker.join(15)
        assert not worker.is_alive()


def _tls(tmp):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    (tmp / "tls.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tmp / "tls.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return {"ssl_keyfile": str(tmp / "tls.key"), "ssl_certfile": str(tmp / "tls.crt")}


@pytest.fixture
def interactive_preview(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    node, vite = shutil.which("node"), root / "web/node_modules/vite/bin/vite.js"
    if node is None or not vite.is_file():
        if os.environ.get("OMNIGENT_SAAS_REQUIRE_DEVELOPMENT_PREVIEW_BROWSER") == "1":
            pytest.fail("required development preview browser toolchain is missing")
        pytest.skip("real browser preview requires the locked web toolchain")
    service = tmp_path / "service"
    ui = tmp_path / "ui"
    service.mkdir()
    ui.mkdir()
    source = service / "main.js"
    (service / "index.html").write_text(
        "<html><head><title>Development app</title></head><body><h1><"
        '/h1><label>Preserved input <input></label><script type="modu'
        'le" src="/main.js"></script></body></html>'
    )
    source.write_text(
        'document.querySelector("h1").textContent="Preview version on'
        'e"; if(import.meta.hot) import.meta.hot.accept();'
    )
    (ui / "node_modules").symlink_to(root / "web/node_modules", target_is_directory=True)
    (ui / "package.json").write_text('{"type":"module"}')
    (ui / "index.html").write_text(
        "<html><head><title>Session preview acceptance</title></head>"
        '<body><div id="root"></div><script type="module" src="/entry'
        '.tsx"></script></body></html>'
    )
    component = str(root / "web/src/components/DevelopmentPreviewControl.tsx")
    (ui / "entry.tsx").write_text(
        (
            'import React from "react"; import {createRoot} from "react-d'
            'om/client"; import {QueryClient,QueryClientProvider} from "@'
            'tanstack/react-query"; import {DevelopmentPreviewControl} fr'
            "om "
        )
        + json.dumps(component)
        + (
            '; createRoot(document.getElementById("root")).render(<QueryC'
            "lientProvider client={new QueryClient()}><DevelopmentPreview"
            'Control sessionId="aa00bb11cc22dd33ee44ff5566778899"/></QueryClientProvider>);'
        )
    )
    (ui / "vite.config.mjs").write_text(
        (
            'import {defineConfig} from "vite"; import react from "@vitej'
            's/plugin-react"; export default defineConfig({plugins:[react'
            '()],resolve:{alias:{"@":'
        )
        + json.dumps(str(root / "web/src"))
        + "}},server:{hmr:false,fs:{allow:["
        + json.dumps(str(root))
        + ","
        + json.dumps(str(ui))
        + "]}}});"
    )
    processes = []
    clients = []
    service_port, ui_port, runner_port, https_port = [_port() for _ in range(4)]
    primary_origin = f"https://app.localhost:{https_port}"
    from saas.control_plane.http_auth import SaasCookieConfig
    from tests.saas.test_http_cookie_auth import _build_fastapi_app

    app, account = _build_fastapi_app(
        trusted_origin=primary_origin,
        database_url="sqlite:///" + str(tmp_path / "control-plane.db"),
        cookie_config=SaasCookieConfig(
            name="__Host-omnigent_saas_session",
            secure=True,
            trusted_origins=frozenset({primary_origin}),
        ),
    )
    engine = app.state.saas_test_engine
    sessions = app.state.saas_test_sessions
    auth = app.state.saas_test_auth
    from saas.control_plane.http_auth import SaasAuthContextMiddleware

    resolver = next(
        m.kwargs["context_resolver"]
        for m in app.user_middleware
        if m.cls is SaasAuthContextMiddleware
    )
    try:
        for folder, port in ((service, service_port), (ui, ui_port)):
            log = (tmp_path / (folder.name + ".log")).open("w")
            process = subprocess.Popen(
                [
                    node,
                    str(vite),
                    str(folder),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--strictPort",
                ],
                cwd=folder,
                stdout=log,
                stderr=log,
            )
            processes.append((process, log))
            deadline = time.monotonic() + 60
            while True:
                try:
                    if (
                        httpx.get(
                            f"http://127.0.0.1:{port}", trust_env=False, timeout=1
                        ).status_code
                        == 200
                    ):
                        break
                except httpx.HTTPError:
                    pass
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError((tmp_path / (folder.name + ".log")).read_text())
                time.sleep(0.05)
        services = DevelopmentPreviewServices(
            lambda sid: [processes[0][0].pid] if sid == "aa00bb11cc22dd33ee44ff5566778899" else []
        )
        runner = FastAPI()
        install_development_preview_routes(runner, services)
        from uuid import UUID

        from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
        from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
        from saas.compatibility import bind_runtime_context

        runtime = resolver.resolve_space_allocation(
            resolver.resolve_request_context(
                actor_id=UUID(account["user_id"]),
                tenant_id=UUID(account["tenant_id"]),
                space_id=UUID(account["space_id"]),
                trace_id="browser-preview-acceptance",
            )
        )
        official_db = "sqlite:///" + str(tmp_path / "official.db")
        conversations = SqlAlchemyConversationStore(official_db)
        permissions = SqlAlchemyPermissionStore(official_db)
        with bind_runtime_context(runtime):
            conversations.create_conversation(conversation_id="aa00bb11cc22dd33ee44ff5566778899")
            permissions.ensure_user(runtime.runtime_user_key)
            permissions.grant(runtime.runtime_user_key, "aa00bb11cc22dd33ee44ff5566778899", 4)

        async def runner_client(_session_id, **_kwargs):
            assert _session_id == "aa00bb11cc22dd33ee44ff5566778899"
            client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{runner_port}", trust_env=False)
            clients.append(client)
            return client

        import omnigent.server.routes.development_preview as routes
        import saas.production.development_preview_composition as composition

        monkeypatch.setattr(routes, "_get_runner_client_for_resource_access", runner_client)
        monkeypatch.setattr(composition, "_get_runner_client_for_resource_access", runner_client)
        from fastapi import APIRouter

        router = APIRouter()
        routes.register_development_preview_routes(
            router,
            conversation_store=conversations,
            auth_provider=auth,
            permission_store=permissions,
        )
        app.include_router(router, prefix="/v1")
        composition.install_development_previews(
            app,
            config=SimpleNamespace(
                development_preview_root_domain="preview.localhost",
                secrets=SimpleNamespace(
                    development_preview_key=b"real-browser-preview-test-key-0001"
                ),
                public_origin=primary_origin,
                release_incarnation="f" * 32,
            ),
            sessions=SimpleNamespace(app=sessions, authenticator=sessions),
            official=SimpleNamespace(
                permission_store=permissions, conversation_store=conversations
            ),
            integration=SimpleNamespace(
                auth_provider=auth, context_resolver=resolver, runtime_store_adapter=None
            ),
        )
        broker = app.state.development_preview_broker
        from fastapi.responses import JSONResponse

        from omnigent.errors import OmnigentError

        @app.exception_handler(OmnigentError)
        async def reject(_request, error):
            return JSONResponse({"error": {"code": error.code}}, status_code=error.http_status)

        @asynccontextmanager
        async def lifespan(_app):
            try:
                yield
            finally:
                for client in clients:
                    await client.aclose()

        app.router.lifespan_context = lifespan

        @app.get("/{path:path}")
        async def frontend(path: str, request: Request):
            async with httpx.AsyncClient(trust_env=False) as client:
                result = await client.get(
                    f"http://127.0.0.1:{ui_port}/{path}", params=request.query_params
                )
            return Response(
                result.content,
                status_code=result.status_code,
                headers={"content-type": result.headers.get("content-type", "")},
            )

        import omnigent.runtime

        previous = omnigent.runtime.get_runner_ws_factory()
        omnigent.runtime.set_runner_ws_factory(
            lambda path: connect(f"ws://127.0.0.1:{runner_port}" + path)
        )
        try:
            with _server(runner, runner_port), _server(app, https_port, **_tls(tmp_path)):
                with httpx.Client(verify=False, trust_env=False) as check:
                    response = check.get(
                        f"https://127.0.0.1:{https_port}",
                        headers={"host": f"app.localhost:{https_port}"},
                    )
                    assert response.status_code == 200, response.text
                yield {
                    "port": https_port,
                    "source": source,
                    "origin": f"https://app.localhost:{https_port}",
                    "broker": broker,
                    "process": processes[0][0],
                }
        finally:
            omnigent.runtime.set_runner_ws_factory(previous)
    finally:
        for process, log in reversed(processes):
            if process.poll() is None:
                process.terminate()
            process.wait(10)
            log.close()
        engine.dispose()


@pytest.fixture
def preview_browser_type():
    # End this loop before later synchronous tests call asyncio.run().
    with sync_playwright() as playwright:
        yield playwright.chromium


def test_real_vite_browser_handoff_hmr_revocation(
    preview_browser_type, interactive_preview, tmp_path, caplog
):
    caplog.set_level("DEBUG", logger="saas.production.development_preview")
    fixture = interactive_preview
    rules = "MAP app.localhost 127.0.0.1,MAP *.preview.localhost 127.0.0.1"
    browser = preview_browser_type.launch(
        args=["--host-resolver-rules=" + rules, "--no-proxy-server", "--ignore-certificate-errors"]
    )
    context = browser.new_context(
        ignore_https_errors=True, record_video_dir=str(tmp_path / "video")
    )
    page = context.new_page()
    observed = []
    connected = []

    def observe_page(p):
        def socket(ws):
            observed.append({"websocket": ws.url.split("?")[0]})

            def frame(value):
                if isinstance(value, str):
                    try:
                        kind = json.loads(value).get("type")
                        observed.append({"ws_frame": kind})
                        if kind == "connected":
                            connected.append(ws.url.split("?")[0])
                    except (ValueError, AttributeError):
                        pass

            ws.on("framereceived", frame)
            ws.on("socketerror", lambda _: observed.append({"ws_error": True}))
            ws.on("close", lambda: observed.append({"ws_closed": True}))

        p.on("websocket", socket)

    context.on("page", observe_page)
    context.on(
        "response",
        lambda response: observed.append(
            {"url": response.url.split("?")[0], "status": response.status}
        ),
    )
    try:
        page.goto(fixture["origin"])
        anonymous = page.evaluate("""async () => (await fetch(
            '/v1/sessions/aa00bb11cc22dd33ee44ff5566778899/preview-services')).status""")
        assert anonymous == 401
        page.evaluate("""async () => {
            const response = await fetch('/saas/auth/login', {method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({email:'HTTP@example.com',password:'initial-http-password'})});
            if(!response.ok) throw new Error('fixture login failed');
            const login=await response.json();
            localStorage.setItem('omnigent.saas.csrf',login.csrf_token);
        }""")
        page.reload()
        page.get_by_text("已就绪", exact=False).wait_for()
        with page.expect_popup() as opened:
            page.get_by_role("button", name="打开开发预览").click()
        preview = opened.value
        preview.get_by_role("heading", name="Preview version one").wait_for()
        deadline = time.monotonic() + 10
        while not connected and time.monotonic() < deadline:
            preview.wait_for_timeout(50)
        assert connected, "Vite HMR WebSocket did not connect"
        preview.get_by_role("textbox", name="Preserved input").fill("retained-through-hot-update")
        fixture["source"].write_text(
            'document.querySelector("h1").textContent="Preview version tw'
            'o"; if(import.meta.hot) import.meta.hot.accept();'
        )
        preview.get_by_role("heading", name="Preview version two").wait_for(timeout=15000)
        assert (
            preview.get_by_role("textbox", name="Preserved input").input_value()
            == "retained-through-hot-update"
        )
        preview.screenshot(path=str(tmp_path / "hmr-success.png"))
        visitor = context.browser.new_context(ignore_https_errors=True)
        try:
            outsider = visitor.new_page()
            denied = outsider.goto(preview.url)
            assert denied.status == 403
            outsider.goto(fixture["origin"])
            outsider.evaluate("""async () => {
                const response=await fetch('/saas/auth/login',{method:'POST',
                    headers:{'Content-Type':'application/json'},body:JSON.stringify({
                    email:'member@example.com',password:'initial-member-password'})});
                if(!response.ok)throw new Error('member login failed');
            }""")
            status = outsider.evaluate("""async () => (await fetch(
              '/v1/sessions/aa00bb11cc22dd33ee44ff5566778899/preview-services')).status""")
            assert status == 404
        finally:
            visitor.close()
        closed = sum(bool(x.get("ws_closed")) for x in observed)
        page.get_by_role("button", name="停止预览").click()
        deadline = time.monotonic() + 5
        while (
            sum(bool(x.get("ws_closed")) for x in observed) == closed
            and time.monotonic() < deadline
        ):
            page.wait_for_timeout(50)
        assert sum(bool(x.get("ws_closed")) for x in observed) > closed
        preview.reload()
        preview.get_by_text("Development preview unavailable", exact=False).wait_for()
        assert preview.url.startswith("https://dev-") and "token=" not in preview.url
        with page.expect_popup() as reopened:
            page.get_by_role("button", name="打开开发预览").click()
        second = reopened.value
        second.get_by_role("heading", name="Preview version two").wait_for()
        result = page.evaluate("""async () => (await fetch('/saas/auth/logout',{
          method:'POST',headers:{'X-CSRF-Token':localStorage.getItem('omnigent.saas.csrf')}})).status""")
        assert result == 204
        second.reload()
        second.get_by_text("Development preview unavailable", exact=False).wait_for()

    finally:
        snapshots = []
        for current in context.pages:
            item = {"url": current.url.split("?")[0]}
            try:
                item["text"] = current.locator("body").inner_text(timeout=1000)[:500]
            except Exception as error:
                item["error"] = type(error).__name__
            snapshots.append(item)
        observed.append(
            {
                "pages": snapshots,
                "cookies": [
                    {k: c[k] for k in ("name", "domain", "secure", "httpOnly", "sameSite")}
                    for c in context.cookies()
                ],
            }
        )
        (tmp_path / "observations.json").write_text(json.dumps(observed, indent=2))
        context.close()
        browser.close()
