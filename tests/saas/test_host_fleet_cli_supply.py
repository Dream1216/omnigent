"""SaaS Host fleet CLI supply-chain contracts."""

import json
from pathlib import Path

from omnigent.onboarding.harness_install import harness_install_spec

_ROOT = Path(__file__).resolve().parents[2]


def test_saas_host_candidate_bakes_pinned_jcode_and_devin() -> None:
    action = (_ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    workflow = (_ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()

    assert "jcode@0.90.1 devin@3000.11.3" in action
    assert (
        "EXTRA_HARNESS_CLIS=${{ inputs.artifact == 'host' && "
        "'jcode@0.90.1 devin@3000.11.3' || '' }}"
    ) in action
    publication = workflow.partition("  publish-signed:")[2].partition(
        "  verify-published-source:"
    )[0]
    assert "EXTRA_HARNESS_CLIS=" not in publication
    assert "name: Promote admitted host OCI without rebuilding" in publication
    assert 'crane push "${RUNNER_TEMP}/admitted-layouts/host"' in publication
    assert "install-saas-harness-cli.sh" in dockerfile
    assert (
        '("anthropic", "openai", "pi", "kiro", "kimi", "qwen", '
        '"opencode", "gemini", "devin", "jcode")'
    ) in workflow


def test_devin_fleet_cli_is_version_and_hash_pinned() -> None:
    script = (_ROOT / "saas/scripts/install-saas-harness-cli.sh").read_text()

    assert 'DEVIN_VERSION="3000.11.3"' in script
    assert "DEVIN_SHA256_AMD64" in script
    assert "DEVIN_SHA256_ARM64" in script
    assert (
        "https://registry.npmjs.org/devin/-/devin-${DEVIN_VERSION}-linux-${target}.tgz" in script
    )
    assert 'echo "$sha  $archive" | sha256sum -c -' in script
    assert 'devin@*) install_devin "${spec#*@}" ;;' in script


def test_managed_opencode_pin_matches_the_supported_runtime() -> None:
    spec = harness_install_spec("opencode")
    assert spec is not None and spec.package is not None
    package, version = spec.package.rsplit("@", 1)
    dependencies = json.loads((_ROOT / ".github/ci-deps/package.json").read_text())["dependencies"]
    assert dependencies[package] == version
    assert "opencode-ai" not in dependencies
    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()
    assert f"ARG OPENCODE_VERSION={version}" in dockerfile
    assert f'"{package}": "${{OPENCODE_VERSION}}"' in dockerfile.replace("\\", "")
    installer = (_ROOT / "saas/scripts/install-saas-harness-cli.sh").read_text()
    assert 'harness_cli_installed("opencode", timeout=30)' in installer
    assert installer.index('harness_cli_installed("opencode", timeout=30)') < installer.index(
        "python -B /tmp/normalize_host_cli_tree.py"
    )


def test_extra_cli_failures_are_fatal_and_sandbox_probe_is_portable() -> None:
    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()
    shared_installer = (_ROOT / "deploy/docker/install-harness-cli.sh").read_text()
    fleet_installer = (_ROOT / "saas/scripts/install-saas-harness-cli.sh").read_text()

    assert 'RUN set -eu; \\\n    if [ -n "${EXTRA_HARNESS_CLIS}" ]' in dockerfile
    assert "command -v runuser" in shared_installer
    assert "command -v su" in shared_installer
    assert "command -v runuser" in fleet_installer
    assert "command -v su" in fleet_installer
    assert "setpriv --reuid=sandbox" not in shared_installer
