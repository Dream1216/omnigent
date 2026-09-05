from __future__ import annotations

from pathlib import Path

import tomllib

from saas.scripts.check_wheel_contents import REQUIRED_WHEEL_PATHS, find_missing_paths


def test_complete_wheel_member_list_passes() -> None:
    assert find_missing_paths(set(REQUIRED_WHEEL_PATHS)) == []


def test_missing_wheel_artifact_is_reported() -> None:
    names = set(REQUIRED_WHEEL_PATHS) - {"saas/control_plane/alembic.ini"}

    assert find_missing_paths(names) == ["saas/control_plane/alembic.ini"]


def test_current_adr_approval_and_ci_evidence_are_required_wheel_artifacts() -> None:
    assert "saas/acceptance/p0-adr-approval-evidence-ci-33667448251.json" in REQUIRED_WHEEL_PATHS
    assert (
        "saas/production/adr-approvals/"
        "omnigent-saas-p0s12-platform-smtp-2026-09-05-8457cc9758444570.json"
        in REQUIRED_WHEEL_PATHS
    )


def test_privacy_worker_is_a_required_wheel_artifact_and_console_entrypoint() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert "saas/privacy_worker.py" in REQUIRED_WHEEL_PATHS
    assert project["project"]["scripts"]["omnigent-saas-privacy-worker"] == (
        "saas.privacy_worker:main"
    )


def test_onboarding_vertical_chain_is_a_required_outbox_worker_dependency() -> None:
    assert "saas/outbox_worker.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/postgresql_database.psql" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/postgresql_roles.psql" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/postgresql_runner_agent_cluster.psql" in (REQUIRED_WHEEL_PATHS)
    assert "saas/control_plane/postgresql_runner_agent_cluster.sql" in (REQUIRED_WHEEL_PATHS)
    assert "saas/n1_outbox_admission.py" in REQUIRED_WHEEL_PATHS
    assert "saas/onboarding_email.py" in REQUIRED_WHEEL_PATHS
    assert "saas/onboarding_composition.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/onboarding_workflow.py" in REQUIRED_WHEEL_PATHS
    assert (
        "saas/control_plane/migrations/versions/p0s000000002_onboarding_vertical_chain.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert "saas/control_plane/onboarding_status.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/runtime_provider.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/runtime_provider_journal.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/postgresql_role_authority.py" in REQUIRED_WHEEL_PATHS
    assert "saas/onboarding_ui/onboarding.html" in REQUIRED_WHEEL_PATHS
    assert "saas/onboarding_ui/onboarding.css" in REQUIRED_WHEEL_PATHS
    assert "saas/onboarding_ui/onboarding.js" in REQUIRED_WHEEL_PATHS
    assert (
        "saas/control_plane/migrations/versions/p0s000000003_outbox_quarantine.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/p0s000000004_runtime_provider_journal.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/p0s000000005_registration_rate_limits.py"
        in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000006_registration_network_rate_limits.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000007_registration_subject_lock_budget.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000008_dispatch_profile_binding.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000009_preview_execution_sessions.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000010_runner_agent_database_authority.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000011_notification_policy_role_scope.py" in REQUIRED_WHEEL_PATHS
    )
    assert (
        "saas/control_plane/migrations/versions/"
        "p0s000000012_platform_smtp_configuration.py" in REQUIRED_WHEEL_PATHS
    )
    assert "saas/control_plane/email_provider.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/preview_models.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/preview_execution.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/preview_sessions.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/preview_tunnel_registration.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/runner_execution_spec.py" in REQUIRED_WHEEL_PATHS


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


def test_production_artifact_admission_boundary_is_required_in_wheel() -> None:
    assert "saas/production/artifact_store.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/artifact_admission.py" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/server/kubernetes.artifact-admission.yaml" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/finalize_artifact_receipt_revision.py" in REQUIRED_WHEEL_PATHS


def test_production_runtime_is_required_and_has_console_entrypoints() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert "saas/production/postgresql_migration.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/server.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/server_config.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/service_bindings.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/worker.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/runner_database_fleet.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/beta_postgresql_data_plane.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/repository_mirror.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/runner_executor.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/runner_readiness.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/preview_execution.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/preview_owner.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/preview_readiness.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/preview_relay.py" in REQUIRED_WHEEL_PATHS
    assert "saas/production/preview_runner_tunnel.py" in REQUIRED_WHEEL_PATHS
    assert "saas/runner_adapter/static_web_preview.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/run_postgresql_migration.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/provision_runner_repositories.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/stage_runner_database_fleet.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/check_worker_health.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/check_runner_control_readiness.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/verify_runner_database_fleet.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/promote_runner_database_fleet.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/render_kubernetes_namespace.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/render_kubernetes_release.py" in REQUIRED_WHEEL_PATHS
    assert "saas/scripts/render_beta_postgresql_data_plane.py" in REQUIRED_WHEEL_PATHS
    assert "saas/control_plane/run_dispatch_projection.py" in REQUIRED_WHEEL_PATHS
    assert "saas/runtime_rls/postgresql_roles.psql" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/server/kubernetes.migration.yaml" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/server/kubernetes.network-policy.yaml" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/server/kubernetes.production.yaml" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/data/__init__.py" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/data/README.md" in REQUIRED_WHEEL_PATHS
    assert "saas/deployment/data/restore-drill-evidence.schema.json" in REQUIRED_WHEEL_PATHS
    assert project["project"]["scripts"]["omnigent-saas-postgresql-migrate"] == (
        "saas.scripts.run_postgresql_migration:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-provision-runner-repositories"] == (
        "saas.scripts.provision_runner_repositories:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-runner-database-fleet-admit"] == (
        "saas.scripts.verify_runner_database_fleet:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-runner-database-fleet-stage"] == (
        "saas.scripts.stage_runner_database_fleet:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-runner-database-fleet-promote"] == (
        "saas.scripts.promote_runner_database_fleet:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-render-next-beta"] == (
        "saas.scripts.render_kubernetes_namespace:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-render-kubernetes-release"] == (
        "saas.scripts.render_kubernetes_release:main"
    )
    assert (
        project["project"]["scripts"]["omnigent-saas-render-beta-postgresql-data-plane"]
        == "saas.scripts.render_beta_postgresql_data_plane:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-server"] == ("saas.production.server:main")
    assert project["project"]["scripts"]["omnigent-saas-production-worker"] == (
        "saas.production.worker:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-worker-health"] == (
        "saas.scripts.check_worker_health:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-runner-control-readiness"] == (
        "saas.scripts.check_runner_control_readiness:main"
    )
    assert project["project"]["scripts"]["omnigent-saas-preview-owner"] == (
        "saas.production.preview_owner:main"
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
