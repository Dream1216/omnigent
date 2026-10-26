"""Drive the real static runtime through a browser and a TCP listener."""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import uvicorn

from saas.runner_adapter.static_web_preview import create_static_web_preview_app


@contextmanager
def _runtime(root: Path):
    app = create_static_web_preview_app(root=root, health_path="/__omnigent_preview_health")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            app, log_level="error", lifespan="on", loop="asyncio", http="h11", ws="none"
        )
    )
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 60
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Static runtime did not start")
            time.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        worker.join(timeout=10)
        listener.close()
        app.close()
        assert not worker.is_alive()


def test_static_preview_spa_deep_link_refresh_and_missing_asset(page, tmp_path):
    (tmp_path / "index.html").write_text(
        '<html><head><title>Static preview</title><script type="module" src="/app.js">'
        '</script></head><body><main></main><a href="/orders/123">Open order</a></body></html>'
    )
    (tmp_path / "app.js").write_text(
        'document.querySelector("main").textContent = "Route: " + location.pathname;'
    )
    with _runtime(tmp_path) as origin:
        page.goto(origin + "/dashboard")
        page.get_by_text("Route: /dashboard", exact=True).wait_for()
        page.get_by_role("link", name="Open order").click()
        page.get_by_text("Route: /orders/123", exact=True).wait_for()
        page.reload()
        page.get_by_text("Route: /orders/123", exact=True).wait_for()
        assert page.title() == "Static preview"
        missing = page.request.get(origin + "/missing.js", headers={"Accept": "text/html"})
        assert missing.status == 404
        assert page.request.get(origin + "/__omnigent_preview_health").status == 200


def test_static_preview_empty_publication_is_unhealthy_over_real_http(tmp_path):
    with _runtime(tmp_path) as origin, httpx.Client(trust_env=False) as client:
        assert client.get(origin + "/__omnigent_preview_health").status_code == 503
        assert client.get(origin + "/").status_code == 404
