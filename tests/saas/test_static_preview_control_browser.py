"""Chromium contract for the production React control, with controlled API replies.

Runtime HTTP/SPA and Cookie/project authorization are verified separately. This
fixture deliberately makes no deployment or authenticated handoff claim.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from playwright.async_api import async_playwright

from saas.control_plane.preview_diagnostics import preview_diagnostic


def _toolchain(root: Path) -> tuple[str, Path]:
    node = shutil.which("node")
    vite = root / "web/node_modules/vite/bin/vite.js"
    if node is None or not vite.is_file():
        if os.environ.get("OMNIGENT_SAAS_REQUIRE_STATIC_PREVIEW_BROWSER") == "1":
            pytest.fail("required static preview browser toolchain is missing")
        pytest.skip("static preview control browser requires the locked web toolchain")
    return node, vite


def test_required_static_browser_cannot_skip_missing_toolchain(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNIGENT_SAAS_REQUIRE_STATIC_PREVIEW_BROWSER", "1")
    with pytest.raises(pytest.fail.Exception, match="required static preview"):
        _toolchain(tmp_path)


@asynccontextmanager
async def _control_ui(tmp: Path):
    root = Path(__file__).resolve().parents[2]
    node, vite = _toolchain(root)
    ui = tmp / "control"
    ui.mkdir()
    (ui / "node_modules").symlink_to(root / "web/node_modules", target_is_directory=True)
    (ui / "package.json").write_text('{"type":"module"}')
    (ui / "style.css").write_text(
        "@import "
        + json.dumps(str(root / "web/src/index.css"))
        + "; @source "
        + json.dumps(str(root / "web/src"))
        + '; @source "./entry.tsx";'
    )
    (ui / "index.html").write_text(
        '<html><body><div id="root"></div><script type="module" '
        'src="/entry.tsx"></script></body></html>'
    )
    (ui / "entry.tsx").write_text(
        'import React from "react"; import {createRoot} from "react-dom/client"; '
        'import {QueryClient,QueryClientProvider} from "@tanstack/react-query"; '
        'import "./style.css"; import {PreviewControl} from '
        + json.dumps(str(root / "web/src/components/PreviewControl.tsx"))
        + '; createRoot(document.getElementById("root")).render('
        "<QueryClientProvider client={new QueryClient()}>"
        '<main className="flex min-h-screen items-end justify-end p-8">'
        '<PreviewControl sessionId="static-control-session" enabled={true}/></main>'
        "</QueryClientProvider>);"
    )
    (ui / "vite.config.mjs").write_text(
        'import {defineConfig} from "vite"; import react from "@vitejs/plugin-react"; '
        'import tailwind from "@tailwindcss/vite"; '
        'export default defineConfig({plugins:[react(),tailwind()],resolve:{alias:{"@":'
        + json.dumps(str(root / "web/src"))
        + "}},server:{hmr:false,fs:{allow:["
        + json.dumps(str(root))
        + ","
        + json.dumps(str(ui))
        + "]}}});"
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    with (tmp / "vite.log").open("w") as log:
        process = subprocess.Popen(
            [node, str(vite), str(ui), "--host", "127.0.0.1", "--port", str(port), "--strictPort"],
            cwd=ui,
            stdout=log,
            stderr=log,
        )
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                async with asyncio.timeout(60):
                    while True:
                        try:
                            if (await client.get(origin)).status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        assert process.poll() is None, "Vite exited before readiness"
                        await asyncio.sleep(0.05)
            yield origin
        finally:
            if process.poll() is None:
                process.terminate()
            await asyncio.to_thread(process.wait, 10)


@pytest.mark.asyncio
async def test_static_control_diagnostics_frozen_source_and_live_expiration(tmp_path):
    now = datetime.now(timezone.utc)
    source = {
        "runs": [],
        "preview_enabled": True,
        "preview": None,
        "diagnostic_message": preview_diagnostic("preview_project_binding_missing"),
    }
    state = {
        "preview_id": "static-preview-id",
        "status": "ready",
        "source_run_id": "completed-run-immutable-id",
        "source_sha": "abc123de" * 5,
        "url": "https://opaque.preview.test/__omnigent/bootstrap#token=fixture",
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    }

    async def reply(route):
        session = "/delivery/sessions/" in route.request.url
        await route.fulfill(
            status=200 if session or state["status"] == "ready" else 202,
            json=source if session else state,
            headers={"cache-control": "no-store"},
        )

    async with _control_ui(tmp_path) as origin, async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        context = await browser.new_context(record_video_dir=str(tmp_path / "video"))
        try:
            page = await context.new_page()
            await page.route("**/saas/**", reply)
            await page.clock.install(time=now)
            await page.goto(origin)
            await page.get_by_role("button", name="会话预览", exact=True).click()
            await page.get_by_text(source["diagnostic_message"], exact=True).wait_for()
            assert await page.get_by_role("button", name="启动预览").is_disabled()
            for code in ("preview_scope_unavailable", "preview_source_unavailable"):
                source["diagnostic_message"] = preview_diagnostic(code)
                await page.get_by_role("button", name="刷新", exact=True).click()
                await page.get_by_text(source["diagnostic_message"], exact=True).wait_for()
            source.update(
                runs=[{"id": "newer-run", "tenant_id": "t", "space_id": "s", "project_id": "p"}],
                preview=state["preview_id"],
                diagnostic_message=None,
            )
            await page.get_by_role("button", name="刷新", exact=True).click()
            await page.get_by_role("status").get_by_text("已就绪", exact=True).wait_for()
            await page.get_by_text(state["source_run_id"], exact=True).wait_for()
            await page.get_by_text(state["source_sha"], exact=True).wait_for()
            assert await page.get_by_role("link", name="打开预览").count() == 1
            await page.clock.fast_forward(2000)
            remaining = await page.locator("dd").last.inner_text()
            assert 0 < int(remaining.split()[0]) <= 58
            panel = await page.get_by_role("region", name="会话预览").bounding_box()
            assert panel and panel["x"] >= 0 and panel["y"] >= 0
            assert panel["width"] == 288 and panel["y"] + panel["height"] <= 720
            await page.screenshot(path=str(tmp_path / "static-source-and-ttl.png"))
            await page.clock.fast_forward(60000)
            await page.get_by_role("status").get_by_text("已过期", exact=True).wait_for()
            assert await page.get_by_role("link", name="打开预览").count() == 0
            state.update(
                status="failed",
                expires_at=(now + timedelta(hours=1)).isoformat(),
                failure_message=preview_diagnostic("preview_entry_unavailable"),
            )
            state.pop("url")
            await page.get_by_role("button", name="刷新", exact=True).click()
            await page.get_by_text(state["failure_message"], exact=True).wait_for()
            assert await page.get_by_role("link", name="打开预览").count() == 0
            await page.screenshot(path=str(tmp_path / "static-entry-recovery.png"))
        finally:
            await context.close()
            await browser.close()
