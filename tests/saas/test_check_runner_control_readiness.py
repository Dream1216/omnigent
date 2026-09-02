from __future__ import annotations

from pathlib import Path

import pytest

from saas.production.runner_readiness import RunnerReadinessError
from saas.scripts import check_runner_control_readiness as probe


def _environment(tmp_path: Path) -> dict[str, str]:
    ca = tmp_path / "runner-control-ca.crt"
    ca.write_text("public-ca", encoding="ascii")
    ca.chmod(0o644)
    return {
        "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME": (
            "omnigent-saas-runner-control.omnigent-next-beta.svc"
        ),
        "OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_PORT": "9445",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE": str(ca),
    }


def test_local_probe_fixes_connect_host_and_uses_strict_public_identity(tmp_path: Path) -> None:
    environ = _environment(tmp_path)
    environ["OMNIGENT_SAAS_RUNNER_READINESS_HOST"] = "attacker.example"

    readiness = probe.load_local_runner_control_readiness(environ)

    assert readiness.connect_host == "127.0.0.1"
    assert readiness.server_name == ("omnigent-saas-runner-control.omnigent-next-beta.svc")
    assert readiness.port == 9445
    assert readiness.timeout_seconds == 2.0


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME", "localhost"),
        ("OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME", "UPPER.example.svc"),
        ("OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_PORT", "0"),
        ("OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_PORT", "not-a-port"),
        ("OMNIGENT_SAAS_RUNNER_CONTROL_READINESS_TIMEOUT_SECONDS", "20"),
    ],
)
def test_local_probe_rejects_invalid_public_identity(
    tmp_path: Path, name: str, value: str
) -> None:
    environ = _environment(tmp_path)
    environ[name] = value

    with pytest.raises(RunnerReadinessError):
        probe.load_local_runner_control_readiness(environ)


def test_local_probe_rejects_link_or_writable_public_ca(tmp_path: Path) -> None:
    environ = _environment(tmp_path)
    real = Path(environ["OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE"])
    linked = tmp_path / "linked-ca.crt"
    linked.symlink_to(real)
    environ["OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE"] = str(linked)
    with pytest.raises(RunnerReadinessError):
        probe.load_local_runner_control_readiness(environ)

    environ["OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE"] = str(real)
    real.chmod(0o666)
    with pytest.raises(RunnerReadinessError):
        probe.load_local_runner_control_readiness(environ)


class _Readiness:
    def __init__(self, error: RunnerReadinessError | None = None) -> None:
        self.error = error

    def assert_production_ready(self) -> None:
        if self.error is not None:
            raise self.error


def test_probe_main_is_content_blind(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        probe,
        "load_local_runner_control_readiness",
        lambda: _Readiness(RunnerReadinessError("private TLS detail")),
    )

    assert probe.main() == 1
    assert capsys.readouterr().err == "Runner control TLS readiness probe failed\n"
