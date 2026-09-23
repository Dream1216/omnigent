from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def test_host_login_shell_restores_pinned_harness_cli_path() -> None:
    """Managed launch login shells must retain the prebaked harness CLIs."""

    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()
    profile_path = (
        'export PATH="/opt/venv/bin:'
        '/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin:${PATH}"'
    )
    assert f"RUN echo '{profile_path}' > /etc/profile.d/omnigent-venv.sh" in dockerfile
