from __future__ import annotations

import pytest

from omnigent.host.connect import HostProcess
from omnigent.host.identity import HostIdentity
from omnigent.runner._zygote import ZYGOTE_ENABLED_ENV_VAR
from saas.runner_adapter import (
    ManagedRunnerProcessPolicyError,
    activate_managed_host_environment,
    build_managed_host_environment,
    require_managed_host_environment,
)


def test_managed_environment_disables_upstream_zygote_without_mutating_base() -> None:
    base = {"PATH": "/usr/bin", "OMNIGENT_RUNNER_ZYGOTE": "false"}

    managed = build_managed_host_environment(base)

    assert managed == {"PATH": "/usr/bin", ZYGOTE_ENABLED_ENV_VAR: "0"}
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


def test_require_policy_rejects_missing_or_noncanonical_switch() -> None:
    with pytest.raises(ManagedRunnerProcessPolicyError) as missing:
        require_managed_host_environment({})
    assert missing.value.code == "managed_runner_zygote_not_disabled"

    with pytest.raises(ManagedRunnerProcessPolicyError) as noncanonical:
        require_managed_host_environment({ZYGOTE_ENABLED_ENV_VAR: "false"})
    assert noncanonical.value.code == "managed_runner_zygote_not_disabled"
