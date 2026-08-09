"""Disposable real-browser fixture for the P2 Project Admin acceptance matrix."""

from __future__ import annotations

import os

from tests.saas.test_http_cookie_auth import _build_fastapi_app

ORIGIN = os.environ.get("OMNIGENT_BROWSER_ORIGIN", "http://127.0.0.1:8765")
app, SCOPE = _build_fastapi_app(ORIGIN)


@app.get("/__browser_fixture", include_in_schema=False)
def browser_fixture() -> dict[str, str]:
    return SCOPE
