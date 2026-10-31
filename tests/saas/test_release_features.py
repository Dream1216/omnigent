"""SaaS Server and managed Runner share a closed compatibility-release profile."""

import pytest

from omnigent.server.feature_flags import FEATURES_ENV_VAR, Feature, resolve_feature_flags
from saas.production.release_features import (
    DEFERRED_FEATURES,
    managed_feature_environment,
    production_feature_flags,
)
from saas.runner_adapter.process_policy import (
    ManagedRunnerProcessPolicyError,
    build_managed_host_environment,
    require_managed_host_environment,
)


@pytest.mark.parametrize("feature", sorted(DEFERRED_FEATURES))
def test_deferred_feature_cannot_be_enabled_by_an_operator_override(feature: Feature) -> None:
    source = {FEATURES_ENV_VAR: f"{feature.value},usage_page"}
    server = production_feature_flags(source)
    host = build_managed_host_environment(source)
    runner = resolve_feature_flags(host)

    assert server == runner
    assert not server.enabled_features & DEFERRED_FEATURES
    assert server.enabled(Feature.USAGE_PAGE)
    assert source[FEATURES_ENV_VAR] == f"{feature.value},usage_page"
    require_managed_host_environment(host)


def test_standalone_defaults_are_preserved_and_explicit_disables_survive() -> None:
    standalone = resolve_feature_flags({})
    assert standalone.enabled(Feature.SESSION_ORCHESTRATION)
    assert standalone.enabled(Feature.CODEX_PLAN_AT_LAUNCH)

    environment = {
        FEATURES_ENV_VAR: managed_feature_environment({FEATURES_ENV_VAR: "-claude_osc_status"})
    }
    flags = resolve_feature_flags(environment)
    assert not flags.enabled(Feature.CLAUDE_OSC_STATUS)
    assert not flags.enabled_features & DEFERRED_FEATURES


@pytest.mark.parametrize("value", [None, "session_orchestration", "codex_plan_at_launch"])
def test_host_preflight_rejects_missing_or_reenabled_release_snapshot(value: str | None) -> None:
    environment = {"OMNIGENT_RUNNER_ZYGOTE": "0"}
    if value is not None:
        environment[FEATURES_ENV_VAR] = value
    with pytest.raises(ManagedRunnerProcessPolicyError) as error:
        require_managed_host_environment(environment)
    assert error.value.code == "managed_runner_release_features"


def test_unknown_release_features_fail_before_launch() -> None:
    with pytest.raises(ValueError, match="unknown feature"):
        build_managed_host_environment({FEATURES_ENV_VAR: "unknown_feature"})
