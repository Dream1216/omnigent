"""Immutable feature boundary for the SaaS compatibility release."""

from __future__ import annotations

from collections.abc import Mapping

from omnigent.server.feature_flags import Feature, FeatureFlags, resolve_feature_flags

DEFERRED_FEATURES = frozenset(
    {
        Feature.SANDBOX_PROFILES,
        Feature.SESSION_ORCHESTRATION,
        Feature.CODEX_PLAN_AT_LAUNCH,
        Feature.AUTOMATIONS_V2,
        Feature.GRID_SESSIONS_DISPLAY_UI,
        Feature.SPLITTABLE_TERMINAL_VIEW_UI,
    }
)


def production_feature_flags(environ: Mapping[str, str] | None = None) -> FeatureFlags:
    """Keep existing feature choices while closing deferred execution paths."""
    configured = resolve_feature_flags(environ)
    return FeatureFlags(enabled_features=configured.enabled_features - DEFERRED_FEATURES)


def managed_feature_environment(environ: Mapping[str, str]) -> str:
    """Carry the same snapshot through the official Host/Runner environment."""
    flags = production_feature_flags(environ)
    enabled = flags.enabled_names()
    disabled = tuple(
        "-" + feature.value for feature in sorted(Feature) if not flags.enabled(feature)
    )
    return ",".join((*enabled, *disabled))
