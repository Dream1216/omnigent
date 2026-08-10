from __future__ import annotations

from pathlib import Path

import tomllib

from saas.scripts.check_wheel_contents import REQUIRED_WHEEL_PATHS, find_missing_paths


def test_complete_wheel_member_list_passes() -> None:
    assert find_missing_paths(set(REQUIRED_WHEEL_PATHS)) == []


def test_missing_wheel_artifact_is_reported() -> None:
    names = set(REQUIRED_WHEEL_PATHS) - {"saas/control_plane/alembic.ini"}

    assert find_missing_paths(names) == ["saas/control_plane/alembic.ini"]


def test_privacy_worker_is_a_required_wheel_artifact_and_console_entrypoint() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert "saas/privacy_worker.py" in REQUIRED_WHEEL_PATHS
    assert project["project"]["scripts"]["omnigent-saas-privacy-worker"] == (
        "saas.privacy_worker:main"
    )


def test_notification_runtime_is_required_and_has_console_entrypoints() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert "saas/notification_bootstrap.py" in REQUIRED_WHEEL_PATHS
    assert "saas/approval_scheduler_worker.py" in REQUIRED_WHEEL_PATHS
    assert "saas/notification_runtime.py" in REQUIRED_WHEEL_PATHS
    assert "saas/notification_worker.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/notification-template-catalog.json" in REQUIRED_WHEEL_PATHS
    assert "saas/production/notification-template-manifest.json" in REQUIRED_WHEEL_PATHS
    assert project["project"]["scripts"]["omnigent-saas-notification-bootstrap"] == (
        "saas.notification_bootstrap:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-notification-worker"] == (
        "saas.notification_worker:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-approval-scheduler"] == (
        "saas.approval_scheduler_worker:main"
    )


def test_frozen_public_openapi_is_a_required_wheel_artifact() -> None:
    assert "saas/openapi-v1.json" in REQUIRED_WHEEL_PATHS


def test_scim_schema_catalog_matrix_and_migration_are_required_wheel_artifacts() -> None:
    assert "saas/scim_schema_catalog.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/scim-compliance-matrix.json" in REQUIRED_WHEEL_PATHS
    assert (
        "saas/control_plane/migrations/versions/pc5a00000004_scim_schema_extensions.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/pc5a00000005_scim_token_match_helper.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert "saas/production/runbooks/scim-idp-e2e.md" in REQUIRED_WHEEL_PATHS
