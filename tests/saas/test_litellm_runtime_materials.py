from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
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
    source = (root / "saas/deployment/litellm/Dockerfile").read_text()
    assert (
        "COPY saas/deployment/litellm/LICENSE.upstream "
        "/usr/share/licenses/omnigent-litellm/LICENSE.upstream"
    ) in source
    assert (root / "saas/deployment/litellm/Dockerfile.dockerignore").read_text().splitlines() == [
        "**",
        "!.litellm-runtime",
        "!.litellm-runtime/**",
        "!saas/",
        "!saas/deployment/",
        "!saas/deployment/litellm/",
        "!saas/deployment/litellm/LICENSE.upstream",
    ]
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
    assert "--no-index --no-deps --no-compile --require-hashes --only-binary=:all:" in source
    installer = lock["runtime_patch"]["python_installer"]
    assert installer["wheels"]["any"]["filename"] in source
    for package, entry in lock["runtime_patch"]["python_packages"].items():
        assert f'"{package}":"{entry["version"]}"' in source
    for architecture in ("x86_64", "aarch64"):
        assert set(lock["runtime_patch"]["packages"][architecture]) == {
            "libcrypto3-3.6.5-r2.apk",
            "libssl3-3.6.5-r2.apk",
        }


def _python_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _lock(tmp_path, monkeypatch)
    document = json.loads(materials._LOCK.read_text())
    document["runtime_patch"]["python_packages"] = {
        "example": {
            "version": "1.0",
            "wheels": {
                "x86_64": {
                    "filename": "example-1.0-cp313-cp313-manylinux_2_28_x86_64.whl",
                    "url": "https://files.pythonhosted.org/packages/test/example-1.0-cp313-cp313-manylinux_2_28_x86_64.whl",
                    "sha256": hashlib.sha256(b"wheel").hexdigest(),
                    "uploaded_at": "2020-01-01T00:00:00Z",
                }
            },
        }
    }
    materials._LOCK.write_text(json.dumps(document))
    config = tmp_path / "uv.toml"
    config.write_text('exclude-newer = "P7D"\n')
    monkeypatch.setattr(materials, "_UV_CONFIG", config, raising=False)
    client = httpx.Client
    monkeypatch.setattr(
        materials.httpx,
        "Client",
        lambda **kwargs: client(
            **kwargs,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    content=b"wheel" if request.url.path.endswith(".whl") else b"package",
                )
            ),
        ),
    )
    return materials._LOCK


def test_python_installer_is_hashed_but_not_installed_in_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = _python_lock(tmp_path, monkeypatch)
    document = json.loads(lock.read_text())
    document["runtime_patch"]["python_installer"] = {
        "version": "26.2",
        "wheels": {
            "any": {
                "filename": "pip-26.2-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/test/pip-26.2-py3-none-any.whl",
                "sha256": hashlib.sha256(b"wheel").hexdigest(),
                "uploaded_at": "2020-01-01T00:00:00Z",
            }
        },
    }
    lock.write_text(json.dumps(document))
    materials.prepare(tmp_path / "bundle")
    assert (tmp_path / "bundle/x86_64/pip-26.2-py3-none-any.whl").read_bytes() == b"wheel"
    assert "pip==" not in (tmp_path / "bundle/x86_64/requirements.txt").read_text()
    assert (
        "x86_64/pip-26.2-py3-none-any.whl"
        in (tmp_path / "bundle/x86_64/packages.sha256").read_text()
    )


def test_preparation_binds_offline_python_wheels_and_requirement_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _python_lock(tmp_path, monkeypatch)
    result = materials.prepare(tmp_path / "bundle")
    filename = "example-1.0-cp313-cp313-manylinux_2_28_x86_64.whl"
    digest = hashlib.sha256(b"wheel").hexdigest()
    assert (tmp_path / "bundle/x86_64" / filename).read_bytes() == b"wheel"
    assert (tmp_path / "bundle/x86_64/requirements.txt").read_text() == (
        f"example==1.0 --hash=sha256:{digest}\n"
    )
    assert (
        f"{digest}  x86_64/{filename}\n"
        in (tmp_path / "bundle/x86_64/packages.sha256").read_text()
    )
    hashes = result["materials"]
    assert isinstance(hashes, dict) and isinstance(hashes["x86_64"], dict)
    assert hashes["x86_64"][filename] == digest
    assert result["signature_verified"] is False


@pytest.mark.parametrize(
    "failure", ["checksum", "cooldown", "future", "architecture", "version", "libc"]
)
def test_python_wheels_fail_closed_before_persisting_unadmitted_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    lock = _python_lock(tmp_path, monkeypatch)
    document = json.loads(lock.read_text())
    wheel = document["runtime_patch"]["python_packages"]["example"]["wheels"]["x86_64"]
    if failure == "checksum":
        wheel["sha256"] = "0" * 64
    elif failure in {"cooldown", "future"}:
        wheel["uploaded_at"] = (
            datetime.now(UTC) + timedelta(days=1 if failure == "future" else -1)
        ).isoformat()
    elif failure == "architecture":
        wheel["filename"] = wheel["filename"].replace("x86_64", "aarch64")
    elif failure == "libc":
        wheel["filename"] = wheel["filename"].replace("manylinux_2_28", "musllinux_1_2")
    else:
        wheel["filename"] = wheel["filename"].replace("1.0", "2.0")
    wheel["url"] = "https://files.pythonhosted.org/packages/test/" + wheel["filename"]
    lock.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        materials.prepare(tmp_path / "bundle")
    assert not list((tmp_path / "bundle").rglob("*.whl"))


def test_python_wheels_use_only_existing_package_specific_cooldown_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _python_lock(tmp_path, monkeypatch)
    document = json.loads(materials._LOCK.read_text())
    document["runtime_patch"]["python_packages"]["example"]["wheels"]["x86_64"]["uploaded_at"] = (
        datetime.now(UTC) - timedelta(days=1)
    ).isoformat()
    materials._LOCK.write_text(json.dumps(document))
    materials._UV_CONFIG.write_text(
        'exclude-newer = "P7D"\nexclude-newer-package = { example = "'
        + datetime.now(UTC).isoformat()
        + '" }\n'
    )
    materials.prepare(tmp_path / "bundle")
    assert (tmp_path / "bundle/x86_64/requirements.txt").is_file()
