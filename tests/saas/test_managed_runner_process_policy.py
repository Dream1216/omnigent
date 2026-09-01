from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import saas.runner_adapter.process_policy as process_policy_module
from omnigent.host.connect import HostProcess
from omnigent.host.daemon_lifecycle import DaemonLifecycleLock
from omnigent.host.identity import HostIdentity
from omnigent.runner._zygote import ZYGOTE_ENABLED_ENV_VAR
from saas.runner_adapter import (
    ManagedRunnerProcessPolicyError,
    activate_managed_host_environment,
    build_managed_host_environment,
    require_managed_host_environment,
)
from saas.runner_adapter.metering import (
    ManagedRunnerLaunchAuthority,
    managed_runner_entry_module,
)
from saas.runner_adapter.process_policy import run_managed_host_process


def test_managed_environment_disables_upstream_zygote_without_mutating_base() -> None:
    base = {"PATH": "/usr/bin", "OMNIGENT_RUNNER_ZYGOTE": "false"}

    managed = build_managed_host_environment(base)

    assert managed == {
        "PATH": "/usr/bin",
        ZYGOTE_ENABLED_ENV_VAR: "0",
    }
    assert base[ZYGOTE_ENABLED_ENV_VAR] == "false"


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_managed_environment_rejects_explicit_zygote_enable(value: str) -> None:
    with pytest.raises(ManagedRunnerProcessPolicyError) as error:
        build_managed_host_environment({ZYGOTE_ENABLED_ENV_VAR: value})

    assert error.value.code == "managed_runner_zygote_enabled"


@pytest.mark.parametrize(
    ("environment", "code"),
    [
        ({"OPENAI_API_KEY": "do-not-log-this-value"}, "managed_runner_ambient_credentials"),
        (
            {"SSH_AUTH_SOCK": "/private/tmp/managed-ssh-agent"},
            "managed_runner_ambient_credentials",
        ),
        (
            {"KUBECONFIG": "/private/tmp/managed-kubeconfig"},
            "managed_runner_ambient_credentials",
        ),
        (
            {"OMNIGENT_RUNNER_ENV_PASSTHROUGH": "CUSTOM_PROVIDER_TOKEN"},
            "managed_runner_ambient_passthrough",
        ),
    ],
)
def test_managed_environment_rejects_ambient_secret_paths_without_logging_values(
    environment: dict[str, str], code: str
) -> None:
    with pytest.raises(ManagedRunnerProcessPolicyError) as error:
        build_managed_host_environment(environment)

    assert error.value.code == code
    assert "do-not-log-this-value" not in str(error.value)
    assert "/private/tmp/managed-ssh-agent" not in str(error.value)
    assert "/private/tmp/managed-kubeconfig" not in str(error.value)


def test_activate_policy_makes_official_host_choose_direct_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {"PATH": "/usr/bin"}
    activate_managed_host_environment(environment)
    require_managed_host_environment(environment)
    monkeypatch.setenv(ZYGOTE_ENABLED_ENV_VAR, environment[ZYGOTE_ENABLED_ENV_VAR])

    host = HostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="managed-test"),
        "https://control-plane.invalid",
    )

    assert host._zygote_enabled is False
    assert host._zygote is None
    monkeypatch.setenv("OMNIGENT_RUNNER_ENTRY_MODULE", "untrusted.module")
    assert host._runner_entry_module() == "omnigent.runner._entry"


def test_managed_host_factory_preserves_official_daemon_lifecycle_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    lifecycle_lock = DaemonLifecycleLock.for_target(
        "managed",
        base_dir=tmp_path,
        pid=1234,
    )

    def fake_run_host_process(
        server_url: str,
        config_path: Path | None = None,
        **kwargs: object,
    ) -> None:
        factory = cast(Callable[..., HostProcess], kwargs["host_factory"])
        captured["host"] = factory(
            HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="managed-test"),
            server_url,
            lifecycle_lock=lifecycle_lock,
        )
        captured["config_path"] = config_path
        captured["daemon_target"] = kwargs["daemon_target"]

    monkeypatch.setattr(process_policy_module, "activate_managed_host_environment", lambda: None)
    monkeypatch.setattr(process_policy_module, "run_host_process", fake_run_host_process)

    run_managed_host_process(
        "https://control-plane.invalid",
        tmp_path / "config.yaml",
        daemon_target="managed",
        launch_authority=cast(ManagedRunnerLaunchAuthority, object()),
        envelope_directory=tmp_path / "envelopes",
    )

    host = cast(HostProcess, captured["host"])
    assert host._lifecycle_lock is lifecycle_lock
    assert host._runner_entry_module() == managed_runner_entry_module()
    assert captured["config_path"] == tmp_path / "config.yaml"
    assert captured["daemon_target"] == "managed"


def test_require_policy_rejects_missing_or_noncanonical_switch() -> None:
    with pytest.raises(ManagedRunnerProcessPolicyError) as missing:
        require_managed_host_environment({})
    assert missing.value.code == "managed_runner_zygote_not_disabled"

    with pytest.raises(ManagedRunnerProcessPolicyError) as noncanonical:
        require_managed_host_environment({ZYGOTE_ENABLED_ENV_VAR: "false"})
    assert noncanonical.value.code == "managed_runner_zygote_not_disabled"
