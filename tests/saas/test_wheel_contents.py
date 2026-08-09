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
