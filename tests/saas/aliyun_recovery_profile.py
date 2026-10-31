"""Opt-in local resilience-lab profile for the Aliyun approval retry setting.

Load with ``-p tests.saas.aliyun_recovery_profile``. The real local Host needs
explicit forwarding because the lab deliberately strips ambient OMNIGENT_ vars.
The managed cloud Host instead injects the fixed setting at Runner spawn;
this plugin does not exercise its credentials, model relay, or cloud network.
"""

from __future__ import annotations

import pytest

from saas.production.aliyun_host import configure_aliyun_runner_recovery
from tests.e2e.resilience.lab.lab import Lab

_PATCH = pytest.StashKey[pytest.MonkeyPatch]()


def pytest_configure(config: pytest.Config) -> None:
    original = Lab._host_side_env
    patch = pytest.MonkeyPatch()

    def host_environment(lab: Lab) -> dict[str, str]:
        environment = original(lab)
        configure_aliyun_runner_recovery(environment)
        names = environment["OMNIGENT_RUNNER_ENV_PASSTHROUGH"].split(",")
        names.append("OMNIGENT_HOOK_MAX_RETRIES")
        environment["OMNIGENT_RUNNER_ENV_PASSTHROUGH"] = ",".join(dict.fromkeys(names))
        return environment

    patch.setattr(Lab, "_host_side_env", host_environment)
    config.stash[_PATCH] = patch


def pytest_unconfigure(config: pytest.Config) -> None:
    if (patch := config.stash.get(_PATCH, None)) is not None:
        patch.undo()
