"""The Next.js static export retains the existing authentication boundary."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from saas.control_plane.onboarding_http import create_onboarding_ui_router
from saas.login_ui import http


def test_login_export_is_bound_to_reproducible_image_inputs() -> None:
    repo = Path(__file__).resolve().parents[2]
    config = (repo / "saas/login_web/next.config.mjs").read_text(encoding="utf-8")
    dockerfile = (repo / "deploy/docker/Dockerfile").read_text(encoding="utf-8")

    assert "generateBuildId" in config
    assert "OMNIGENT_SOURCE_REVISION" in config
    assert "OMNIGENT_SOURCE_REVISION=${SOURCE_REVISION}" in dockerfile
    assert "find /login/saas/login_ui/static -depth" in dockerfile
    assert "find /opt/venv /build -depth" in dockerfile


def test_exported_login_assets_and_csp_are_complete() -> None:
    static_root = http.files("saas.login_ui").joinpath("static")
    if (
        os.environ.get("OMNIGENT_SKIP_WEB_UI") == "true"
        and not static_root.joinpath("login.html").is_file()
    ):
        pytest.skip("the generic backend lane intentionally omits the login export")
    app = FastAPI()
    app.include_router(create_onboarding_ui_router())
    with TestClient(app) as client:
        response = client.get("/saas/login?return_to=%2Fsettings%2Faccount")
        assert response.status_code == 200
        assert "__NEXT_DATA__" in response.text, "Run npm ci && npm run build in saas/login_web"
        policy = response.headers["content-security-policy"]
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy
        assert response.headers["cache-control"] == "no-store"
        for script in re.findall(r"<script\b[^>]*>(.*?)</script>", response.text, re.DOTALL):
            if script.strip():
                digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
                assert f"'sha256-{digest}'" in policy
        assets = re.findall(r'(?:src|href)="(/saas/login-assets/[^\"]+)"', response.text)
        assert assets
        for asset in assets:
            result = client.get(asset)
            assert result.status_code == 200, asset
            assert result.headers["x-content-type-options"] == "nosniff"
            assert "immutable" in result.headers["cache-control"]
        assert "onboarding.js" not in response.text
        assert "onboarding.js" in client.get("/signup").text


@pytest.mark.parametrize(
    "path",
    [
        "login.html",
        "script-hashes.json",
        "_next/static/../login.html",
        "_next/static/..\\login.html",
        "_next/static/missing.js",
        "_next/static/chunk.js.map",
    ],
)
def test_export_asset_route_rejects_nonpublic_files(path: str) -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as error:
        http.login_asset(path)
    assert error.value.status_code == 404


def test_backend_only_install_keeps_original_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(http, "files", lambda _: tmp_path)
    app = FastAPI()
    app.include_router(create_onboarding_ui_router())
    with TestClient(app) as client:
        response = client.get("/saas/login")
        assert response.status_code == 200
        assert "onboarding.js" in response.text
        assert "__NEXT_DATA__" not in response.text
