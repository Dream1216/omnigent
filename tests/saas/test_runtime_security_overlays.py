from __future__ import annotations

import json
from pathlib import Path

import pytest

from saas.scripts.activate_debian_sid_snapshot import activate


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_wolfi_runtime_materials_are_closed_and_pinned() -> None:
    supply_chain = _root() / "saas/supply_chain"
    runtime = json.loads((supply_chain / "wolfi-runtime-lock.json").read_text())

    assert runtime["production_admission"] is True
    assert runtime["distribution"] == "wolfi"
    assert runtime["image"] == "cgr.dev/chainguard/wolfi-base:latest"
    assert runtime["manifest_digest"].startswith("sha256:")
    assert len(runtime["manifest_digest"]) == 71
    assert runtime["runtime_contract"]["architectures"] == ["amd64", "arm64"]
    assert runtime["runtime_contract"]["venv_builder_image"] == "python:3.12-slim"
    assert runtime["runtime_contract"]["common_packages"]["python-3.12"] == "3.12.15-r3"
    assert runtime["runtime_contract"]["common_packages"]["zlib"] == ("1.3.2.1_rc20260917-r0")
    assert runtime["runtime_contract"]["server_packages"] == {"git": "2.56.0-r0"}
    assert runtime["runtime_contract"]["transient_host_packages"] == {
        "gcc": "16.2.0-r1",
        "make": "4.4.1-r15",
    }


def test_github_cli_security_fix_source_is_closed_and_pinned() -> None:
    path = _root() / "saas/supply_chain/github-cli-source-lock.json"
    source = json.loads(path.read_text())

    assert source["version"] == "2.102.0"
    assert source["source_revision"] == "31778eb069e08d3a4087a1693cda6d9c9ef4aa09"
    assert len(source["source_sha256"]) == 64
    assert source["builder_image"] == "golang:1.27.2-trixie"
    assert source["builder_manifest_digest"].startswith("sha256:")
    assert len(source["builder_manifest_digest"]) == 71
    assert source["runtime_contract"] == {
        "architectures": ["amd64", "arm64"],
        "go_toolchain": "go1.27.2",
        "modules": {"golang.org/x/net": "v0.60.0"},
    }
    assert "GO-2026-6612" in source["resolved_vulnerabilities"]


def test_dockerfile_uses_locked_wolfi_runtime_without_gate_exceptions() -> None:
    dockerfile = (_root() / "deploy/docker/Dockerfile").read_text()

    assert "ARG RUNTIME_IMAGE=cgr.dev/chainguard/wolfi-base:latest" in dockerfile
    assert "FROM ${RUNTIME_IMAGE} AS secured-python-runtime-rootfs" in dockerfile
    assert "FROM scratch AS secured-python-runtime" in dockerfile
    assert "COPY --from=secured-python-runtime-rootfs / /" in dockerfile
    assert "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in dockerfile
    assert "FROM ${RUNTIME_IMAGE} AS runtime-security-builder" not in dockerfile
    assert "COPY --from=runtime-security-builder" not in dockerfile
    workflow = (_root() / ".github/workflows/saas-image-candidate.yml").read_text()
    assert (
        workflow.count(
            "runtime_digest=$(jq -er .manifest_digest saas/supply_chain/wolfi-runtime-lock.json)"
        )
        == 2
    )
    assert workflow.count("RUNTIME_IMAGE=cgr.dev/chainguard/wolfi-base@${runtime_digest}") == 2
    assert (
        workflow.count(
            "go_digest=$(jq -er .builder_manifest_digest "
            "saas/supply_chain/github-cli-source-lock.json)"
        )
        == 2
    )
    assert workflow.count("GO_IMAGE=golang:1.27.2-trixie@${go_digest}") == 2
    assert "RUNTIME_APT_SNAPSHOT" not in workflow
    assert dockerfile.count("FROM secured-python-runtime AS ") == 2
    assert "activate_debian_sid_snapshot.py --snapshot" not in dockerfile
    assert "apk add --no-cache" in dockerfile
    assert "ca-certificates-bundle=20260909-r2" in dockerfile
    assert "libstdc++=16.2.0-r1" in dockerfile
    assert "git=2.56.0-r0" in dockerfile
    assert "gcc=16.2.0-r1" in dockerfile
    assert "apk del --purge make gcc" in dockerfile
    assert "sandbox:x:1000660000:1000660000::/sandbox:/bin/sh" in dockerfile
    assert 'pwd.getpwnam("sandbox")' in dockerfile
    assert "--connect-timeout 30 --max-time 900 -o /tmp/kiro.zip" in dockerfile
    assert "FROM ${GO_IMAGE} AS gh-go-toolchain" in dockerfile
    assert "GOTOOLCHAIN=local" in dockerfile
    assert "RUN --mount=type=cache,target=/root/go/pkg/mod,sharing=locked" in dockerfile
    assert "GOPROXY='https://proxy.golang.org|direct' GOSUMDB=sum.golang.org" in dockerfile
    assert "CGO_ENABLED=0 GOPROXY=off" in dockerfile
    assert "GOFLAGS='-mod=readonly -buildvcs=false'" in dockerfile
    assert "go version -m /opt/gh-export/gh" in dockerfile
    assert "test ! -d /usr/include/c++" in dockerfile
    assert 'pyexpat.EXPAT_VERSION == "expat_2.9.0"' in dockerfile
    assert 'zlib.ZLIB_RUNTIME_VERSION == "1.3.2.1-motley"' in dockerfile
    assert (
        "vulnerability_policy" in (_root() / "saas/supply_chain/release-policy.json").read_text()
    )


def test_sid_snapshot_activation_is_exact_and_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "debian.sources"
    path.write_text(
        "Types: deb\n"
        "# http://snapshot.debian.org/archive/debian/20261005T000000Z\n"
        "URIs: http://deb.debian.org/debian\n"
        "Suites: sid\n"
        "Components: main\n",
        encoding="utf-8",
    )
    uri = activate(path, "20261009T000000Z")
    assert uri == "http://snapshot.debian.org/archive/debian/20261009T000000Z"
    assert f"URIs: {uri}" in path.read_text(encoding="utf-8")
    assert "URIs: http://deb.debian.org/debian" not in path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="invalid Debian snapshot"):
        activate(path, "latest")
    with pytest.raises(ValueError, match="expected one"):
        activate(path, "20261009T000000Z")
