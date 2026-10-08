from __future__ import annotations

import json
from pathlib import Path

import pytest

from saas.scripts.activate_debian_sid_snapshot import activate


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_sid_runtime_and_overlay_materials_are_closed_and_pinned() -> None:
    supply_chain = _root() / "saas/supply_chain"
    runtime = json.loads((supply_chain / "debian-sid-runtime-lock.json").read_text())
    zlib = json.loads((supply_chain / "zlib-132-security-lock.json").read_text())
    podlators = json.loads(
        (supply_chain / "podlators-611-security-lock.json").read_text()
    )
    gcc = json.loads((supply_chain / "gcc16-runtime-vex-lock.json").read_text())

    assert runtime["production_admission"] is True
    assert runtime["suite"] == "sid"
    assert runtime["snapshot"] == "20261009T000000Z"
    assert runtime["manifest_digest"].startswith("sha256:")
    assert len(runtime["manifest_digest"]) == 71
    assert runtime["runtime_contract"]["architectures"] == ["amd64", "arm64"]

    assert zlib["production_admission"] is True
    assert zlib["fix_commit"] == "df84af25dc1942490e1d1c899a07619152a46148"
    assert zlib["addresses"] == ["CVE-2026-85091"]
    assert {artifact["role"] for artifact in zlib["artifacts"]} == {
        "upstream",
        "signature",
        "security-fix",
    }

    assert podlators["production_admission"] is True
    assert podlators["addresses"] == ["CVE-2026-82560"]
    assert podlators["runtime_contract"]["version"] == "v6.1.1"
    assert podlators["runtime_contract"]["search_path_precedes_distribution_module"]

    statements = {item["vulnerability"]: item for item in gcc["statements"]}
    assert set(statements) == {"CVE-2026-102010", "CVE-2026-95619"}
    assert {item["status"] for item in statements.values()} == {"not_affected"}
    assert gcc["architectures"] == ["amd64", "arm64"]


def test_dockerfile_builds_and_rechecks_narrow_runtime_overlays() -> None:
    dockerfile = (_root() / "deploy/docker/Dockerfile").read_text()
    script = (_root() / "saas/scripts/build_runtime_security_overlays.sh").read_text()

    assert "ARG RUNTIME_IMAGE=debian:sid-slim" in dockerfile
    assert "ARG RUNTIME_APT_SNAPSHOT=20261009T000000Z" in dockerfile
    assert "FROM ${RUNTIME_IMAGE} AS runtime-security-builder" in dockerfile
    assert "FROM ${RUNTIME_IMAGE} AS secured-python-runtime" in dockerfile
    assert "work=/tmp/runtime-security-build" in script
    assert "work=$(mktemp -d)" not in script
    workflow = (_root() / ".github/workflows/saas-image-candidate.yml").read_text()
    assert workflow.count(
        "runtime_digest=$(jq -er .manifest_digest "
        "saas/supply_chain/debian-sid-runtime-lock.json)"
    ) == 2
    assert workflow.count(
        "runtime_snapshot=$(jq -er .snapshot "
        "saas/supply_chain/debian-sid-runtime-lock.json)"
    ) == 2
    assert "runtime_digest=$(crane digest debian:sid-slim)" not in workflow
    assert dockerfile.count("FROM secured-python-runtime AS ") == 2
    assert dockerfile.count("activate_debian_sid_snapshot.py --snapshot") == 2
    assert "libreadline8t64 libsqlite3-0 libstdc++6 perl zlib1g" in dockerfile
    assert 'sysconfig.get_config_var("MULTIARCH")' in dockerfile
    assert "dpkg-architecture" not in dockerfile
    assert "test ! -d /usr/include/c++" in dockerfile
    assert "/opt/runtime-security/gcc/aligned-new-runtime-boundary" in dockerfile
    assert 'pyexpat.EXPAT_VERSION == "expat_2.9.0"' in dockerfile
    assert 'zlib.ZLIB_RUNTIME_VERSION == "1.3.2"' in dockerfile
    assert "Pod::Text::VERSION eq q(v6.1.1)" in dockerfile

    for value in (
        "d7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3",
        "110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14",
        "709a7dc4a2259683eb2f89e085ec70cf743710d950510e489ec6ddca3eb80c68",
        "b5ad165baca0f2f2ac2a02b6b4b66d68ee890f582df398da9f86399679ca9c29",
        "c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a",
    ):
        assert value in script
    assert "make test" in script
    assert "make check" in script
    assert "python -B -m test -j2 test_pyexpat" in script


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
