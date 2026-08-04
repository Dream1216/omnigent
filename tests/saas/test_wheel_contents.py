from __future__ import annotations

from saas.scripts.check_wheel_contents import REQUIRED_WHEEL_PATHS, find_missing_paths


def test_complete_wheel_member_list_passes() -> None:
    assert find_missing_paths(set(REQUIRED_WHEEL_PATHS)) == []


def test_missing_wheel_artifact_is_reported() -> None:
    names = set(REQUIRED_WHEEL_PATHS) - {"saas/control_plane/alembic.ini"}

    assert find_missing_paths(names) == ["saas/control_plane/alembic.ini"]
