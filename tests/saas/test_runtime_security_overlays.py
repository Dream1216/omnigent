from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from saas.scripts.activate_debian_sid_snapshot import activate
from saas.scripts.check_image_supply_chain import validate_image_material_lock
from tests.saas.test_image_supply_chain import _material_lock_repo


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
    assert runtime["runtime_contract"]["server_packages"] == {
        "cyrus-sasl-heimdal-libs": "2.1.28-r58",
        "git": "2.56.0-r0",
        "heimdal-libs": "7.8.0-r54",
        "keyutils-libs": "1.6.3-r41",
        "krb5-conf": "1.0-r10",
        "krb5-libs": "1.22.2-r5",
        "libcom_err": "1.47.4-r4",
        "libcrypto3": "3.6.5-r5",
        "libcurl-openssl4": "8.23.0-r2",
        "libidn2": "2.3.8-r11",
        "libldap-2.6": "2.6.14-r0",
        "libnghttp2-14": "1.70.0-r6",
        "libpcre2-8-0": "10.49-r1",
        "libpsl": "0.23.3-r3",
        "libssl3": "3.6.5-r5",
        "libunistring": "1.5-r0",
        "libverto": "0.3.2-r10",
        "nghttp3": "1.18.0-r2",
        "ngtcp2": "1.25.0-r6",
    }
    assert runtime["runtime_contract"]["transient_host_packages"] == {
        "binutils": "2.47-r2",
        "gcc": "16.2.0-r1",
        "glibc-2.44-dev": "2.44-r8",
        "isl": "0.28-r5",
        "libatomic": "16.2.0-r1",
        "libgomp": "16.2.0-r1",
        "libquadmath": "16.2.0-r1",
        "libstdc++-dev": "16.2.0-r1",
        "libxcrypt-dev": "4.5.2-r6",
        "linux-headers": "7.3-r0",
        "make": "4.4.1-r15",
        "mpc": "1.4.1-r2",
        "mpfr": "4.2.2-r4",
        "openssf-compiler-options": "20250904-r11",
        "posix-cc-wrappers": "2-r10",
    }

    host_packages = {
        **runtime["runtime_contract"]["host_packages"],
        **runtime["runtime_contract"]["transient_host_packages"],
    }
    assert len(runtime["runtime_contract"]["host_packages"]) == 53
    assert len(host_packages) == 68
    assert (
        hashlib.sha256(
            json.dumps(host_packages, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == "a7c804cdc84cf76eebf5bd9368566af20abf888c96634fa654fd948f608e9c7d"
    )


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
        == 1
    )
    assert workflow.count("RUNTIME_IMAGE=cgr.dev/chainguard/wolfi-base@${runtime_digest}") == 1
    assert (
        workflow.count(
            "go_digest=$(jq -er .builder_manifest_digest "
            "saas/supply_chain/github-cli-source-lock.json)"
        )
        == 1
    )
    assert workflow.count("GO_IMAGE=golang:1.27.2-trixie@${go_digest}") == 1
    publication = workflow.partition("  publish-signed:")[2].partition(
        "  verify-published-source:"
    )[0]
    assert "runtime_digest=" not in publication
    assert "go_digest=" not in publication
    assert "docker/build-push-action" not in publication
    assert 'crane push "${RUNNER_TEMP}/admitted-layouts/server"' in publication
    assert 'crane push "${RUNNER_TEMP}/admitted-layouts/host"' in publication
    assert "RUNTIME_APT_SNAPSHOT" not in workflow
    assert dockerfile.count("FROM secured-python-runtime AS ") == 2
    assert "activate_debian_sid_snapshot.py --snapshot" not in dockerfile
    assert "apk add --no-cache" in dockerfile
    assert dockerfile.count("rm -f /var/cache/ldconfig/aux-cache") == 5
    assert "ca-certificates-bundle=20260909-r3" in dockerfile
    assert "curl=8.23.0-r1" in dockerfile
    assert "libstdc++=16.2.0-r1" in dockerfile
    assert "git=2.56.0-r0" in dockerfile
    assert "gcc=16.2.0-r1" in dockerfile
    assert "apk del --purge make gcc" in dockerfile
    transient = json.loads((_root() / "saas/supply_chain/wolfi-runtime-lock.json").read_text())[
        "runtime_contract"
    ]["transient_host_packages"]
    purges = re.findall(r"apk del --purge ([^\\\r\n&]+)", dockerfile)
    assert len(purges) == 1
    purged_packages = purges[0].split()
    assert len(purged_packages) == len(transient)
    assert set(purged_packages) == set(transient)
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
    assert 'pyexpat.EXPAT_VERSION == "expat_2.9.0", pyexpat.EXPAT_VERSION' in workflow
    assert ('zlib.ZLIB_RUNTIME_VERSION == "1.3.2.1-motley", zlib.ZLIB_RUNTIME_VERSION') in workflow
    assert 'zlib.ZLIB_RUNTIME_VERSION == "1.3.2"' not in workflow
    assert "'test ! -e /usr/bin/perl && test ! -e /usr/local/bin/perl'" in workflow
    assert "--entrypoint /usr/bin/perl" not in workflow
    assert (
        "vulnerability_policy" in (_root() / "saas/supply_chain/release-policy.json").read_text()
    )


@pytest.mark.parametrize(
    ("stage", "target", "replacement", "expected"),
    [
        (
            "host",
            "binutils=2.47-r2",
            "binutils=2.47-r1",
            "Wolfi transient_host_packages pins must be installed exactly",
        ),
        (
            "host",
            "libpcre2-8-0=10.49-r1",
            "libpcre2-8-0",
            "Wolfi host_packages pins must be installed exactly",
        ),
        (
            "runtime",
            "libcurl-openssl4=8.23.0-r2",
            "libcurl-openssl4",
            "Wolfi server_packages pins must be installed exactly",
        ),
    ],
)
def test_wolfi_resolved_package_closure_rejects_drift(
    tmp_path: Path, stage: str, target: str, replacement: str, expected: str
) -> None:
    repo = _material_lock_repo(tmp_path)
    dockerfile = repo / "deploy/docker/Dockerfile"
    source = dockerfile.read_text(encoding="utf-8")
    prefix, separator, rest = source.partition(f"FROM secured-python-runtime AS {stage}\n")
    assert separator
    body, suffix_separator, suffix = rest.partition("\nFROM ")
    assert body.count(target) == 1
    dockerfile.write_text(
        prefix + separator + body.replace(target, replacement, 1) + suffix_separator + suffix,
        encoding="utf-8",
    )
    assert expected in validate_image_material_lock(repo)


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
