from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from saas.scripts import prepare_litellm_runtime as materials


def _lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = tmp_path / "release.json"
    lock.write_text(
        json.dumps(
            {
                "runtime_patch": {
                    "repository": "https://packages.test",
                    "packages": {
                        "x86_64": {"example.apk": hashlib.sha256(b"package").hexdigest()}
                    },
                }
            }
        )
    )
    monkeypatch.setattr(materials, "_LOCK", lock)


def test_preparation_verifies_bytes_but_does_not_claim_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _lock(tmp_path, monkeypatch)
    client = httpx.Client
    monkeypatch.setattr(
        materials.httpx,
        "Client",
        lambda **kwargs: client(
            **kwargs,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    content=b"package" if request.url.path.endswith(".apk") else b"signed-index",
                )
            ),
        ),
    )
    result = materials.prepare(tmp_path / "bundle")
    assert result["signature_verified"] is False
    assert (tmp_path / "bundle/x86_64/example.apk").read_bytes() == b"package"
    assert "x86_64/example.apk" in (tmp_path / "bundle/x86_64/packages.sha256").read_text()


def test_preparation_rejects_changed_package_before_persisting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _lock(tmp_path, monkeypatch)
    client = httpx.Client
    monkeypatch.setattr(
        materials.httpx,
        "Client",
        lambda **kwargs: client(
            **kwargs,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"changed")),
        ),
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        materials.prepare(tmp_path / "bundle")
    assert not (tmp_path / "bundle/x86_64/example.apk").exists()


def test_runtime_patch_keeps_exact_base_and_no_trust_bypass() -> None:
    root = Path(__file__).resolve().parents[2]
    lock = json.loads((root / "saas/production/litellm_release.json").read_text())
    source = (root / "deploy/litellm/Dockerfile").read_text()
    assert f"ARG LITELLM_BASE_IMAGE={lock['image']}" in source
    assert "--network=none" in source
    assert "--repositories-file /dev/null --repository /runtime" in source
    assert "--allow-untrusted" not in source
    assert "--no-check-certificate" not in source
    assert "apk upgrade" not in source
    assert "FROM scratch AS runtime" in source
    assert "COPY --from=oss-rootfs / /" in source
    assert 'find_spec("litellm_enterprise") is None' in source
    assert lock["license"]["runtime_profile"] == "oss-core"
    for architecture in ("x86_64", "aarch64"):
        assert set(lock["runtime_patch"]["packages"][architecture]) == {
            "libcrypto3-3.6.5-r2.apk",
            "libssl3-3.6.5-r2.apk",
        }
