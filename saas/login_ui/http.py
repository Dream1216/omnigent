"""Serve the exported login page without adding a Node runtime."""

from __future__ import annotations

import json
import re
from importlib.resources import files

from fastapi import HTTPException, Response
from fastapi.responses import HTMLResponse

_ASSET_TYPES = {"js": "text/javascript", "css": "text/css", "woff2": "font/woff2"}


def login_page(headers: dict[str, str]) -> HTMLResponse | None:
    root = files("saas.login_ui").joinpath("static")
    page = root.joinpath("login.html")
    if not page.is_file():
        # Backend-only installs retain the existing functional login page.
        return None
    hashes = json.loads(root.joinpath("script-hashes.json").read_text(encoding="utf-8"))
    if not isinstance(hashes, list) or not all(
        isinstance(value, str) and re.fullmatch(r"'sha256-[A-Za-z0-9+/]{43}='", value)
        for value in hashes
    ):
        raise RuntimeError("Invalid login export CSP manifest; rebuild saas/login_web")
    policy = headers["Content-Security-Policy"].replace(
        "script-src 'self'", "script-src 'self' " + " ".join(hashes)
    )
    return HTMLResponse(
        page.read_text(encoding="utf-8"),
        headers={**headers, "Content-Security-Policy": policy},
    )


def login_asset(path: str) -> Response:
    parts = path.split("/")
    extension = path.rsplit(".", 1)[-1]
    if (
        not path.startswith("_next/static/")
        or any(part in ("", ".", "..") for part in parts)
        or "\\" in path
        or extension not in _ASSET_TYPES
    ):
        raise HTTPException(status_code=404)
    resource = files("saas.login_ui").joinpath("static", *parts)
    if not resource.is_file():
        raise HTTPException(status_code=404)
    return Response(
        resource.read_bytes(),
        media_type=_ASSET_TYPES[extension],
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
        },
    )
