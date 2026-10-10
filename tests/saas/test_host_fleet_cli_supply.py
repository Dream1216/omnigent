"""SaaS Host fleet CLI supply-chain contracts."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def test_saas_host_candidate_bakes_pinned_jcode_and_devin() -> None:
    action = (_ROOT / "saas/actions/build-oci-candidate/action.yml").read_text()
    workflow = (_ROOT / ".github/workflows/saas-image-candidate.yml").read_text()
    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()

    assert "jcode@0.90.1 devin@3000.11.3" in action
    assert "EXTRA_HARNESS_CLIS=jcode@0.90.1 devin@3000.11.3" in workflow
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
        "https://static.devin.ai/cli/${DEVIN_VERSION}/devin-${DEVIN_VERSION}-${target}.tar.gz"
        in script
    )
    assert 'echo "$sha  $archive" | sha256sum -c -' in script
    assert 'devin@*) install_devin "${spec#*@}" ;;' in script


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
