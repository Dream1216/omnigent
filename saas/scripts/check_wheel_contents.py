"""Verify that the built wheel contains the deployable SaaS boundary."""

from __future__ import annotations

import argparse
import sys
import zipfile
from collections.abc import Collection
from pathlib import Path

REQUIRED_WHEEL_PATHS = (
    "saas/application.py",
    "saas/acceptance/p0-p6-evidence.json",
    "saas/acceptance/p1-context-shell-ci-30890178928.json",
    "saas/acceptance/p1-oidc-ci-30887476782.json",
    "saas/acceptance/p2-ci-30883002639.json",
    "saas/acceptance/p2-upstream-sync-ci-30883850613.json",
    "saas/acceptance/p2-upstream-sync-ci-30884588165.json",
    "saas/acceptance/p3-ci-30895599094.json",
    "saas/acceptance/p3-upstream-sync-ci-30897083447.json",
    "saas/acceptance/p4-scheduling-ci-30901594129.json",
    "saas/acceptance/p4-image-candidate-ci-30901594130.json",
    "saas/acceptance/p4-isolation-preview-ci-30918608868.json",
    "saas/acceptance/p4-physical-worktree-ci-30910478415.json",
    "saas/acceptance/p4-worktree-ci-30906291765.json",
    "saas/admin_ui/project_admin.css",
    "saas/admin_ui/project_admin.html",
    "saas/admin_ui/project_admin.js",
    "saas/upstream-baseline.json",
    "saas/compatibility/store_adapter.py",
    "saas/control_plane/authorization.py",
    "saas/control_plane/binding_saga.py",
    "saas/control_plane/bindings.py",
    "saas/control_plane/context_snapshot.py",
    "saas/control_plane/alembic.ini",
    "saas/control_plane/db_models.py",
    "saas/control_plane/execution_models.py",
    "saas/control_plane/execution.py",
    "saas/control_plane/governance.py",
    "saas/control_plane/http_auth.py",
    "saas/control_plane/idempotency.py",
    "saas/control_plane/identity.py",
    "saas/control_plane/isolation.py",
    "saas/control_plane/isolation_models.py",
    "saas/control_plane/lifecycle.py",
    "saas/control_plane/migrations/env.py",
    "saas/control_plane/migrations/script.py.mako",
    "saas/control_plane/migrations/versions/p1a000000001_identity_tenant_placement.py",
    "saas/control_plane/migrations/versions/p1a000000002_identity_lifecycle.py",
    "saas/control_plane/migrations/versions/p1a000000003_auth_governance_outbox.py",
    "saas/control_plane/migrations/versions/p2a000000001_postgresql_rls.py",
    "saas/control_plane/migrations/versions/p2a000000002_project_authorization.py",
    "saas/control_plane/migrations/versions/p2a000000003_binding_saga.py",
    "saas/control_plane/migrations/versions/p2a000000004_force_control_plane_rls.py",
    "saas/control_plane/migrations/versions/p2a000000005_oidc_identity_conflicts.py",
    "saas/control_plane/migrations/versions/p2a000000006_context_shell_actor_rls.py",
    "saas/control_plane/migrations/versions/p2a000000007_runtime_placement_platform_write.py",
    "saas/control_plane/migrations/versions/p3a000000001_execution_authority.py",
    "saas/control_plane/migrations/versions/p4a000000001_runner_scheduling.py",
    "saas/control_plane/migrations/versions/p4b000000001_changeset_worktrees.py",
    "saas/control_plane/migrations/versions/p4c000000001_isolation_secret_preview.py",
    "saas/control_plane/outbox.py",
    "saas/control_plane/permissions.py",
    "saas/control_plane/postgresql_roles.sql",
    "saas/control_plane/project_http.py",
    "saas/control_plane/projects.py",
    "saas/control_plane/removal_impact.py",
    "saas/control_plane/resolver.py",
    "saas/control_plane/rls.py",
    "saas/control_plane/scheduling.py",
    "saas/control_plane/scheduling_models.py",
    "saas/control_plane/worktree_models.py",
    "saas/control_plane/worktrees.py",
    "saas/outbox_worker.py",
    "saas/preview_gateway.py",
    "saas/runtime_rls/__init__.py",
    "saas/runtime_rls/installer.py",
    "saas/runtime_rls/postgresql_roles.sql",
    "saas/runner_adapter/__init__.py",
    "saas/runner_adapter/isolation.py",
    "saas/runner_adapter/worktrees.py",
    "saas/production/baseline.json",
    "saas/production/runbooks/backup-restore.md",
    "saas/production/runbooks/control-plane-degradation.md",
    "saas/production/runbooks/image-release.md",
    "saas/production/runbooks/incident-response.md",
    "saas/scripts/check_image_supply_chain.py",
    "saas/scripts/check_production_baseline.py",
    "saas/scripts/compare_oci_rebuilds.py",
    "saas/supply_chain/release-policy.json",
)


def find_missing_paths(names: Collection[str]) -> list[str]:
    """Return required SaaS artifacts absent from a wheel member list."""

    return sorted(path for path in REQUIRED_WHEEL_PATHS if path not in names)


def _select_wheel(path: Path) -> Path:
    if path.is_file() and path.suffix == ".whl":
        return path
    wheels = sorted(path.glob("omnigent-*.whl")) if path.is_dir() else []
    if len(wheels) != 1:
        raise ValueError("expected exactly one Omnigent wheel")
    return wheels[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", help="wheel file or directory containing one wheel")
    args = parser.parse_args()

    try:
        wheel = _select_wheel(Path(args.wheel))
        with zipfile.ZipFile(wheel) as archive:
            missing = find_missing_paths(set(archive.namelist()))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        sys.stderr.write(f"wheel verification failed: {error}\n")
        return 1

    if missing:
        sys.stderr.write("wheel is missing SaaS artifacts:\n")
        sys.stderr.write("\n".join(missing) + "\n")
        return 1
    sys.stdout.write(f"wheel contains {len(REQUIRED_WHEEL_PATHS)} required SaaS artifacts\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
