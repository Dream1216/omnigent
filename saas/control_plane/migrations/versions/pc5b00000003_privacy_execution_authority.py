"""Add governed Privacy execution, retry, retention, and DSSE authority.

Revision ID: pc5b00000003
Revises: pc5b00000002
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "pc5b00000003"
down_revision: str | None = "pc5b00000002"
branch_labels: str | None = None
depends_on: str | None = None

_OLD_PLATFORM_ACTIONS = (
    "support_grant_request",
    "support_grant_staff_decision",
    "support_session_issue",
    "support_grant_revoke",
    "audit_export",
)
_PRIVACY_PLATFORM_ACTIONS = (
    "privacy_deletion_start",
    "privacy_deletion_finalize",
    "privacy_surface_replay",
    "privacy_backup_purge_replay",
)
_PRIVACY_EXECUTION_EVENTS = (
    "privacy.execution.backup_dead_lettered",
    "privacy.execution.backup_purged",
    "privacy.execution.backup_retry_scheduled",
    "privacy.execution.retention_attention_required",
    "privacy.execution.retention_completed",
    "privacy.execution.work_dead_lettered",
    "privacy.execution.work_retry_scheduled",
    "privacy.execution.work_succeeded",
)
_NEW_TABLES = (
    "saas_privacy_approval_bindings",
    "saas_privacy_deletion_work_items",
    "saas_privacy_deletion_attempts",
    "saas_privacy_evidence_attestations",
    "saas_privacy_backup_retention_items",
)

_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_TARGET_USER = "NULLIF(current_setting('app.platform_target_user_id', true), '')::uuid"
_TARGET_MANIFEST = "NULLIF(current_setting('app.platform_privacy_manifest_id', true), '')::uuid"
_TARGET_OPERATION = (
    "NULLIF(current_setting('app.platform_target_admin_operation_id', true), '')::uuid"
)
_GOVERNANCE = "pg_has_role(current_user, 'saas_platform_governance', 'member')"
_DISPATCHER = "pg_has_role(current_user, 'saas_privacy_dispatcher', 'member')"
_VERIFIER = "pg_has_role(current_user, 'saas_privacy_verifier', 'member')"
_EMERGENCY = "pg_has_role(current_user, 'saas_platform', 'member')"


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _change_platform_action_constraint(*, include_privacy: bool) -> None:
    values = _OLD_PLATFORM_ACTIONS + (_PRIVACY_PLATFORM_ACTIONS if include_privacy else ())
    with op.batch_alter_table("saas_platform_admin_operations") as batch:
        batch.drop_constraint("ck_platform_admin_operation_action", type_="check")
        batch.create_check_constraint(
            "ck_platform_admin_operation_action",
            f"action IN ({_quoted(values)})",
        )


def _alter_manifest() -> None:
    with op.batch_alter_table("saas_privacy_deletion_manifests") as batch:
        batch.add_column(sa.Column("start_operation_id", sa.Uuid()))
        batch.add_column(sa.Column("completion_operation_id", sa.Uuid()))
        batch.add_column(
            sa.Column(
                "approval_provenance",
                sa.String(32),
                nullable=False,
                server_default=sa.text("'legacy_unverified'"),
            )
        )
        batch.add_column(
            sa.Column(
                "retention_status",
                sa.String(48),
                nullable=False,
                server_default=sa.text("'legacy_reconciliation_required'"),
            )
        )
        batch.add_column(sa.Column("retention_completed_at", sa.DateTime(timezone=True)))
        batch.create_foreign_key(
            "fk_privacy_manifest_start_operation",
            "saas_platform_admin_operations",
            ["start_operation_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_privacy_manifest_completion_operation",
            "saas_platform_admin_operations",
            ["completion_operation_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_unique_constraint(
            "uq_privacy_manifest_start_operation", ["start_operation_id"]
        )
        batch.create_unique_constraint(
            "uq_privacy_manifest_completion_operation", ["completion_operation_id"]
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_approval_provenance",
            "approval_provenance IN ('legacy_unverified', 'governed_operation')",
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_start_operation",
            "(approval_provenance = 'legacy_unverified' AND start_operation_id IS NULL "
            "AND completion_operation_id IS NULL) OR "
            "(approval_provenance = 'governed_operation' AND start_operation_id IS NOT NULL)",
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_completion_operation",
            "completion_operation_id IS NULL OR approval_provenance = 'governed_operation'",
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_governed_completion",
            "approval_provenance <> 'governed_operation' OR status <> 'completed' "
            "OR completion_operation_id IS NOT NULL",
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_retention_status",
            "retention_status IN ('not_applicable', 'pending', 'attention_required', "
            "'completed', 'legacy_reconciliation_required')",
        )
        batch.create_check_constraint(
            "ck_privacy_manifest_retention_completion",
            "(retention_status IN ('completed', 'not_applicable') "
            "AND retention_completed_at IS NOT NULL) OR "
            "(retention_status NOT IN ('completed', 'not_applicable') "
            "AND retention_completed_at IS NULL)",
        )


def _create_approval_bindings() -> None:
    op.create_table(
        "saas_privacy_approval_bindings",
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("phase", sa.String(32), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("manifest_id", sa.Uuid()),
        sa.Column("subject_id", sa.Uuid()),
        sa.Column("expected_target_version", sa.Integer(), nullable=False),
        sa.Column("expected_manifest_version", sa.Integer()),
        sa.Column("impact_snapshot", sa.JSON(), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("authentication_assertion_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "phase IN ('deletion_start', 'deletion_finalize', 'surface_replay', "
            "'backup_purge_replay')",
            name="ck_privacy_approval_binding_phase",
        ),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_privacy_approval_binding_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_approval_binding_target_scope",
        ),
        sa.CheckConstraint(
            "expected_target_version > 0 AND "
            "(expected_manifest_version IS NULL OR expected_manifest_version > 0)",
            name="ck_privacy_approval_binding_versions",
        ),
        sa.CheckConstraint(
            "length(snapshot_hash) = 64 AND length(authentication_assertion_sha256) = 64",
            name="ck_privacy_approval_binding_hashes",
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_privacy_approval_binding_expiry"),
        sa.CheckConstraint(
            "(phase = 'deletion_start' AND manifest_id IS NULL AND subject_id IS NULL "
            "AND expected_manifest_version IS NULL) OR "
            "(phase = 'deletion_finalize' AND manifest_id IS NOT NULL AND subject_id IS NULL "
            "AND expected_manifest_version IS NOT NULL) OR "
            "(phase IN ('surface_replay', 'backup_purge_replay') "
            "AND manifest_id IS NOT NULL AND subject_id IS NOT NULL "
            "AND expected_manifest_version IS NOT NULL)",
            name="ck_privacy_approval_binding_subject",
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["saas_platform_admin_operations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["saas_privacy_deletion_manifests.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("operation_id"),
    )
    op.create_index(
        "ix_privacy_approval_binding_target",
        "saas_privacy_approval_bindings",
        ["target_type", "target_id", "phase", "expires_at"],
    )


def _create_work_items() -> None:
    op.create_table(
        "saas_privacy_deletion_work_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("runtime_partition_id", sa.Uuid()),
        sa.Column("surface", sa.String(96), nullable=False),
        sa.Column("disposition", sa.String(32), nullable=False),
        sa.Column("resource_scope_hmac", sa.String(64), nullable=False),
        sa.Column("adapter_type", sa.String(96), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token_hash", sa.String(64)),
        sa.Column("executor_identity_sha256", sa.String(64)),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("replay_generation", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("last_error_sha256", sa.String(64)),
        sa.Column("outcome_content_sha256", sa.String(64)),
        sa.Column("evidence_attestation_id", sa.Uuid()),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_privacy_work_item_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_work_item_target_scope",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'retry', 'succeeded', 'dead_letter')",
            name="ck_privacy_work_item_status",
        ),
        sa.CheckConstraint(
            "length(surface) > 0 AND length(disposition) > 0 "
            "AND length(resource_scope_hmac) = 64 AND length(adapter_type) > 0",
            name="ck_privacy_work_item_identity",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_privacy_work_item_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_privacy_work_item_generations",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_privacy_work_item_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_sha256 IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_sha256) = 64)",
            name="ck_privacy_work_item_error",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND length(outcome_content_sha256) = 64 "
            "AND evidence_attestation_id IS NOT NULL) OR "
            "(status <> 'succeeded' AND outcome_content_sha256 IS NULL "
            "AND evidence_attestation_id IS NULL)",
            name="ck_privacy_work_item_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["saas_privacy_deletion_manifests.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["runtime_partition_id"], ["saas_runtime_partitions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "manifest_id",
            "surface",
            "resource_scope_hmac",
            name="uq_privacy_work_item_manifest_surface_scope",
        ),
    )
    op.create_index(
        "ix_privacy_work_item_dispatch",
        "saas_privacy_deletion_work_items",
        ["status", "available_at", "lease_expires_at", "id"],
    )
    op.create_index(
        "ix_privacy_work_item_target",
        "saas_privacy_deletion_work_items",
        ["target_type", "target_id", "manifest_id", "id"],
    )


def _create_attempts() -> None:
    op.create_table(
        "saas_privacy_deletion_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("work_item_id", sa.Uuid()),
        sa.Column("backup_retention_item_id", sa.Uuid()),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("surface", sa.String(96), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("replay_generation", sa.Integer(), nullable=False),
        sa.Column("provider_idempotency_sha256", sa.String(64), nullable=False),
        sa.Column("executor_identity_sha256", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(128)),
        sa.Column("error_sha256", sa.String(64)),
        sa.Column("evidence_payload_sha256", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_privacy_attempt_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_attempt_target_scope",
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'retry', 'dead_letter', 'lease_lost')",
            name="ck_privacy_attempt_outcome",
        ),
        sa.CheckConstraint(
            "attempt_number > 0 AND lease_generation > 0 AND replay_generation >= 0",
            name="ck_privacy_attempt_generations",
        ),
        sa.CheckConstraint(
            "length(surface) > 0 AND length(provider_idempotency_sha256) = 64 "
            "AND length(executor_identity_sha256) = 64",
            name="ck_privacy_attempt_identity",
        ),
        sa.CheckConstraint(
            "(work_item_id IS NOT NULL AND backup_retention_item_id IS NULL) OR "
            "(work_item_id IS NULL AND backup_retention_item_id IS NOT NULL "
            "AND surface = 'backups_and_snapshots')",
            name="ck_privacy_attempt_subject_xor",
        ),
        sa.CheckConstraint("completed_at >= started_at", name="ck_privacy_attempt_time"),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND error_code IS NULL AND error_sha256 IS NULL "
            "AND length(evidence_payload_sha256) = 64) OR "
            "(outcome <> 'succeeded' AND length(error_code) > 0 "
            "AND length(error_sha256) = 64 AND evidence_payload_sha256 IS NULL)",
            name="ck_privacy_attempt_result",
        ),
        sa.ForeignKeyConstraint(
            ["work_item_id"], ["saas_privacy_deletion_work_items.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["backup_retention_item_id"],
            ["saas_privacy_backup_retention_items.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["saas_privacy_deletion_manifests.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_privacy_attempt_work_item_generation_number",
        "saas_privacy_deletion_attempts",
        ["work_item_id", "replay_generation", "attempt_number"],
        unique=True,
        sqlite_where=sa.text("work_item_id IS NOT NULL"),
        postgresql_where=sa.text("work_item_id IS NOT NULL"),
    )
    op.create_index(
        "uq_privacy_attempt_backup_generation_number",
        "saas_privacy_deletion_attempts",
        ["backup_retention_item_id", "replay_generation", "attempt_number"],
        unique=True,
        sqlite_where=sa.text("backup_retention_item_id IS NOT NULL"),
        postgresql_where=sa.text("backup_retention_item_id IS NOT NULL"),
    )
    op.create_index(
        "ix_privacy_attempt_manifest",
        "saas_privacy_deletion_attempts",
        ["manifest_id", "surface", "replay_generation", "attempt_number"],
    )


def _create_attestations() -> None:
    op.create_table(
        "saas_privacy_evidence_attestations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("execution_attempt_id", sa.Uuid()),
        sa.Column("attempt_number", sa.Integer()),
        sa.Column("lease_generation", sa.Integer()),
        sa.Column("replay_generation", sa.Integer()),
        sa.Column("surface", sa.String(96)),
        sa.Column("payload_type", sa.String(256), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("envelope_sha256", sa.String(64), nullable=False),
        sa.Column("envelope", sa.JSON(), nullable=False),
        sa.Column("envelope_uri", sa.String(2048), nullable=False),
        sa.Column("immutability_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("kms_audit_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("signature_algorithm", sa.String(32), nullable=False),
        sa.Column("signer_key_id", sa.String(256), nullable=False),
        sa.Column("workflow_identity", sa.String(512), nullable=False),
        sa.Column("attestor_role", sa.String(32)),
        sa.Column("actor_identity_hmac", sa.String(64)),
        sa.Column("record_sha256", sa.String(64)),
        sa.Column("product_revision", sa.String(40), nullable=False),
        sa.Column("upstream_revision", sa.String(40), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.Column("adapter_contract_version", sa.String(64), nullable=False),
        sa.Column("verifier_policy_version", sa.String(64), nullable=False),
        sa.Column("verifier_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_privacy_attestation_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_attestation_target_scope",
        ),
        sa.CheckConstraint(
            "subject_kind IN ('surface', 'backup', 'manifest', 'production_admission')",
            name="ck_privacy_attestation_subject_kind",
        ),
        sa.CheckConstraint(
            "((subject_kind IN ('surface', 'backup')) AND length(surface) > 0) OR "
            "(subject_kind IN ('manifest', 'production_admission') AND surface IS NULL)",
            name="ck_privacy_attestation_surface",
        ),
        sa.CheckConstraint(
            "length(payload_type) > 0 AND length(payload_sha256) = 64 "
            "AND length(envelope_sha256) = 64 AND length(envelope_uri) > 0 "
            "AND length(immutability_receipt_sha256) = 64 "
            "AND length(kms_audit_receipt_sha256) = 64 "
            "AND length(verifier_receipt_sha256) = 64",
            name="ck_privacy_attestation_envelope",
        ),
        sa.CheckConstraint(
            "(subject_kind IN ('surface', 'backup') "
            "AND execution_attempt_id IS NOT NULL AND attempt_number > 0 "
            "AND lease_generation > 0 AND replay_generation >= 0) OR "
            "(subject_kind IN ('manifest', 'production_admission') "
            "AND execution_attempt_id IS NULL AND attempt_number IS NULL "
            "AND lease_generation IS NULL AND replay_generation IS NULL)",
            name="ck_privacy_attestation_execution",
        ),
        sa.CheckConstraint(
            "signature_algorithm = 'ed25519' AND length(signer_key_id) > 0 "
            "AND length(workflow_identity) > 0",
            name="ck_privacy_attestation_signer",
        ),
        sa.CheckConstraint(
            "length(product_revision) = 40 AND length(upstream_revision) = 40 "
            "AND length(schema_revision) > 0 AND length(adapter_contract_version) > 0 "
            "AND length(verifier_policy_version) > 0",
            name="ck_privacy_attestation_revisions",
        ),
        sa.CheckConstraint(
            "(subject_kind = 'manifest' "
            "AND attestor_role IN ('privacy', 'security', 'data_owner') "
            "AND length(actor_identity_hmac) = 64 AND length(record_sha256) = 64) OR "
            "(subject_kind <> 'manifest' AND attestor_role IS NULL "
            "AND actor_identity_hmac IS NULL AND record_sha256 IS NULL)",
            name="ck_privacy_attestation_manifest_actor",
        ),
        sa.CheckConstraint(
            "observed_at <= signed_at AND verified_at >= signed_at",
            name="ck_privacy_attestation_time",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["saas_privacy_deletion_manifests.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("envelope_sha256"),
    )
    op.create_index(
        "uq_privacy_attestation_execution_attempt",
        "saas_privacy_evidence_attestations",
        ["execution_attempt_id"],
        unique=True,
        sqlite_where=sa.text("subject_kind IN ('surface', 'backup')"),
        postgresql_where=sa.text("subject_kind IN ('surface', 'backup')"),
    )
    op.create_index(
        "uq_privacy_attestation_manifest_role",
        "saas_privacy_evidence_attestations",
        ["manifest_id", "subject_id", "attestor_role"],
        unique=True,
        sqlite_where=sa.text("subject_kind = 'manifest'"),
        postgresql_where=sa.text("subject_kind = 'manifest'"),
    )
    op.create_index(
        "ix_privacy_attestation_manifest",
        "saas_privacy_evidence_attestations",
        ["manifest_id", "subject_kind", "subject_id", "verified_at"],
    )


def _create_backup_retention() -> None:
    op.create_table(
        "saas_privacy_backup_retention_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("runtime_partition_id", sa.Uuid()),
        sa.Column("provider", sa.String(96), nullable=False),
        sa.Column("backup_data_class", sa.String(32), nullable=False),
        sa.Column("backup_locator_hmac", sa.String(64), nullable=False),
        sa.Column("resource_handle_ref", sa.String(512)),
        sa.Column("catalog_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("tombstone_sha256", sa.String(64), nullable=False),
        sa.Column("object_lock_until", sa.DateTime(timezone=True)),
        sa.Column("purge_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token_hash", sa.String(64)),
        sa.Column("executor_identity_sha256", sa.String(64)),
        sa.Column("lease_generation", sa.Integer(), nullable=False),
        sa.Column("replay_generation", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("last_error_sha256", sa.String(64)),
        sa.Column("purge_evidence_sha256", sa.String(64)),
        sa.Column("evidence_attestation_id", sa.Uuid()),
        sa.Column("purged_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "target_type IN ('global_user', 'tenant')",
            name="ck_privacy_backup_retention_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'tenant' AND tenant_id = target_id) OR "
            "(target_type = 'global_user' AND tenant_id IS NULL)",
            name="ck_privacy_backup_retention_target_scope",
        ),
        sa.CheckConstraint(
            "status IN ('retention_wait', 'held', 'leased', 'retry', 'dead_letter', "
            "'purged', 'legacy_reconciliation_required')",
            name="ck_privacy_backup_retention_status",
        ),
        sa.CheckConstraint(
            "length(provider) > 0 AND length(backup_data_class) > 0 "
            "AND length(backup_locator_hmac) = 64 "
            "AND length(catalog_snapshot_sha256) = 64 AND length(tombstone_sha256) = 64",
            name="ck_privacy_backup_retention_identity",
        ),
        sa.CheckConstraint(
            "(status = 'legacy_reconciliation_required' AND resource_handle_ref IS NULL) OR "
            "(status <> 'legacy_reconciliation_required' AND length(resource_handle_ref) > 0)",
            name="ck_privacy_backup_retention_resource",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 32 "
            "AND attempt_count <= max_attempts",
            name="ck_privacy_backup_retention_attempt_budget",
        ),
        sa.CheckConstraint(
            "lease_generation >= 0 AND replay_generation >= 0 AND version > 0",
            name="ck_privacy_backup_retention_generations",
        ),
        sa.CheckConstraint(
            "object_lock_until IS NULL OR purge_due_at >= object_lock_until",
            name="ck_privacy_backup_retention_lock_order",
        ),
        sa.CheckConstraint(
            "(status = 'leased' AND leased_at IS NOT NULL AND lease_expires_at > leased_at "
            "AND length(lease_token_hash) = 64 AND length(executor_identity_sha256) = 64) OR "
            "(status <> 'leased' AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND lease_token_hash IS NULL AND executor_identity_sha256 IS NULL)",
            name="ck_privacy_backup_retention_lease",
        ),
        sa.CheckConstraint(
            "(last_error_code IS NULL AND last_error_sha256 IS NULL) OR "
            "(length(last_error_code) > 0 AND length(last_error_sha256) = 64)",
            name="ck_privacy_backup_retention_error",
        ),
        sa.CheckConstraint(
            "(status = 'purged' AND purged_at IS NOT NULL "
            "AND purged_at >= purge_due_at AND length(purge_evidence_sha256) = 64 "
            "AND evidence_attestation_id IS NOT NULL) OR "
            "(status <> 'purged' AND purged_at IS NULL AND purge_evidence_sha256 IS NULL "
            "AND evidence_attestation_id IS NULL)",
            name="ck_privacy_backup_retention_result",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["saas_privacy_deletion_manifests.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["runtime_partition_id"], ["saas_runtime_partitions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "manifest_id",
            "backup_locator_hmac",
            name="uq_privacy_backup_retention_manifest_locator",
        ),
    )
    op.create_index(
        "ix_privacy_backup_retention_dispatch",
        "saas_privacy_backup_retention_items",
        ["status", "purge_due_at", "available_at", "lease_expires_at", "id"],
    )
    op.create_index(
        "ix_privacy_backup_retention_target",
        "saas_privacy_backup_retention_items",
        ["target_type", "target_id", "manifest_id", "id"],
    )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _time(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _valid_hash(value: object) -> str | None:
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return None


def _new_database_uuid(bind: sa.Connection) -> object:
    value = uuid4()
    return value.hex if bind.dialect.name == "sqlite" else value


def _backfill_legacy_manifests() -> None:
    """Project legacy aggregate evidence without upgrading its trust level."""

    bind = op.get_bind()
    metadata = sa.MetaData()
    manifests = sa.Table("saas_privacy_deletion_manifests", metadata, autoload_with=bind)
    work_items = sa.Table("saas_privacy_deletion_work_items", metadata, autoload_with=bind)
    backup_items = sa.Table("saas_privacy_backup_retention_items", metadata, autoload_with=bind)
    rows = bind.execute(
        sa.select(
            manifests.c.id,
            manifests.c.target_type,
            manifests.c.target_id,
            manifests.c.tenant_id,
            manifests.c.surface_outcomes,
            manifests.c.started_at,
            manifests.c.updated_at,
        )
    ).mappings()
    work_values: list[dict[str, object]] = []
    backup_values: list[dict[str, object]] = []
    for row in rows:
        outcomes = _mapping(row["surface_outcomes"])
        started_at = row["started_at"]
        updated_at = row["updated_at"]
        for surface, raw_outcome in outcomes.items():
            if not isinstance(surface, str) or not surface:
                continue
            outcome = _mapping(raw_outcome)
            disposition = outcome.get("disposition")
            if not isinstance(disposition, str) or not disposition:
                disposition = "legacy_unknown"
            recorded = outcome.get("status") not in {None, "pending"}
            work_values.append(
                {
                    "id": _new_database_uuid(bind),
                    "manifest_id": row["id"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "tenant_id": row["tenant_id"],
                    "runtime_partition_id": None,
                    "surface": surface[:96],
                    "disposition": disposition[:32],
                    "resource_scope_hmac": _canonical_digest(
                        ["legacy", str(row["id"]), surface, "aggregate"]
                    ),
                    "adapter_type": "legacy_manifest_projection",
                    "status": "dead_letter" if recorded else "pending",
                    "attempt_count": 0,
                    "max_attempts": 8,
                    "available_at": started_at,
                    "leased_at": None,
                    "lease_expires_at": None,
                    "lease_token_hash": None,
                    "executor_identity_sha256": None,
                    "lease_generation": 0,
                    "replay_generation": 0,
                    "last_error_code": "privacy_legacy_evidence_unverified" if recorded else None,
                    "last_error_sha256": (
                        _canonical_digest("privacy_legacy_evidence_unverified")
                        if recorded
                        else None
                    ),
                    "outcome_content_sha256": None,
                    "evidence_attestation_id": None,
                    "version": 1,
                    "created_at": started_at,
                    "updated_at": updated_at,
                }
            )
        backup = _mapping(outcomes.get("backups_and_snapshots"))
        retention_until = _time(backup.get("retention_until"))
        purge_due_at = retention_until or (started_at + timedelta(days=35))
        backup_values.append(
            {
                "id": _new_database_uuid(bind),
                "manifest_id": row["id"],
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "tenant_id": row["tenant_id"],
                "runtime_partition_id": None,
                "provider": "legacy_unverified",
                "backup_data_class": "unknown",
                "backup_locator_hmac": _canonical_digest(
                    ["legacy", str(row["id"]), "backups_and_snapshots"]
                ),
                "resource_handle_ref": None,
                "catalog_snapshot_sha256": _canonical_digest(backup),
                "tombstone_sha256": _valid_hash(backup.get("tombstone_sha256"))
                or _canonical_digest(["legacy", str(row["id"]), "missing-tombstone"]),
                "object_lock_until": retention_until,
                "purge_due_at": purge_due_at,
                "status": "legacy_reconciliation_required",
                "attempt_count": 0,
                "max_attempts": 8,
                "available_at": started_at,
                "leased_at": None,
                "lease_expires_at": None,
                "lease_token_hash": None,
                "executor_identity_sha256": None,
                "lease_generation": 0,
                "replay_generation": 0,
                "last_error_code": None,
                "last_error_sha256": None,
                "purge_evidence_sha256": None,
                "evidence_attestation_id": None,
                "purged_at": None,
                "version": 1,
                "created_at": started_at,
                "updated_at": updated_at,
            }
        )
    if work_values:
        bind.execute(work_items.insert(), work_values)
    if backup_values:
        bind.execute(backup_items.insert(), backup_values)


def _active_staff(roles: str) -> str:
    return (
        f"({_GOVERNANCE} AND {_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments pc5_execution_assignment "
        f"WHERE pc5_execution_assignment.principal_id = {_PRINCIPAL} "
        f"AND pc5_execution_assignment.role IN ({roles}) "
        "AND pc5_execution_assignment.status = 'active' "
        "AND (pc5_execution_assignment.expires_at IS NULL "
        "OR pc5_execution_assignment.expires_at > CURRENT_TIMESTAMP)))"
    )


def _target() -> str:
    return (
        f"((target_type = 'tenant' AND target_id = {_TARGET_TENANT}) OR "
        f"(target_type = 'global_user' AND target_id = {_TARGET_USER}))"
    )


def _install_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    actor = _active_staff("'platform_operator', 'compliance_operator'")
    auditor = _active_staff(
        "'platform_operator', 'platform_security_auditor', 'compliance_operator'"
    )
    compliance = _active_staff("'compliance_operator'")
    operator = _active_staff("'platform_operator'")
    target = _target()
    privacy_action = f"action IN ({_quoted(_PRIVACY_PLATFORM_ACTIONS)})"

    # Extend, but do not replace, PC3's support-operation policies.
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_privacy_insert" '
        "ON saas_platform_admin_operations FOR INSERT WITH CHECK ("
        f"{_EMERGENCY} OR ({compliance} AND id = {_TARGET_OPERATION} "
        f"AND requested_by_principal_id = {_PRINCIPAL} AND {privacy_action}))"
    )
    # PC3's permissive INSERT policy was created when only support actions
    # existed. This restrictive guard keeps that old policy intact while
    # preventing it from admitting a Privacy action for a non-compliance role.
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_privacy_insert_guard" '
        "ON saas_platform_admin_operations AS RESTRICTIVE FOR INSERT WITH CHECK ("
        f"NOT ({privacy_action}) OR {_EMERGENCY} OR ({compliance} "
        f"AND id = {_TARGET_OPERATION} AND requested_by_principal_id = {_PRINCIPAL}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_privacy_update" '
        "ON saas_platform_admin_operations FOR UPDATE USING ("
        f"{_EMERGENCY} OR ({operator} AND id = {_TARGET_OPERATION} AND {privacy_action})) "
        "WITH CHECK ("
        f"{_EMERGENCY} OR ({operator} AND id = {_TARGET_OPERATION} AND {privacy_action}))"
    )
    op.execute(
        'CREATE POLICY "rls_platform_admin_operation_privacy_update_guard" '
        "ON saas_platform_admin_operations AS RESTRICTIVE FOR UPDATE USING ("
        f"NOT ({privacy_action}) OR {_EMERGENCY} OR "
        f"({operator} AND id = {_TARGET_OPERATION})) WITH CHECK ("
        f"NOT ({privacy_action}) OR {_EMERGENCY} OR "
        f"({operator} AND id = {_TARGET_OPERATION}))"
    )

    for table in _NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    approval = "saas_privacy_approval_bindings"
    exact_approval_insert = f"({target} AND operation_id = {_TARGET_OPERATION})"
    approval_read = (
        f"({target} AND ({_TARGET_OPERATION} IS NULL OR operation_id = {_TARGET_OPERATION}))"
    )
    op.execute(
        f"CREATE POLICY rls_{approval}_platform_insert ON {approval} FOR INSERT "
        f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_approval_insert}))"
    )
    op.execute(
        f"CREATE POLICY rls_{approval}_staff_read ON {approval} FOR SELECT "
        f"USING ({_EMERGENCY} OR ({auditor} AND {approval_read}))"
    )

    exact_manifest = f"({target} AND manifest_id = {_TARGET_MANIFEST})"
    manifest_executor = f"({target} AND id = {_TARGET_MANIFEST})"
    op.execute(
        "CREATE POLICY rls_privacy_manifests_executor_read "
        "ON saas_privacy_deletion_manifests FOR SELECT "
        f"USING ({_DISPATCHER} AND {manifest_executor})"
    )
    op.execute(
        "CREATE POLICY rls_privacy_manifests_executor_update "
        "ON saas_privacy_deletion_manifests FOR UPDATE "
        f"USING ({_DISPATCHER} AND {manifest_executor}) "
        f"WITH CHECK ({_DISPATCHER} AND {manifest_executor})"
    )
    op.execute(
        "CREATE POLICY rls_privacy_legal_holds_executor_read "
        "ON saas_privacy_legal_holds FOR SELECT "
        f"USING ({_DISPATCHER} AND {target})"
    )
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_deletion_attempts",
        "saas_privacy_evidence_attestations",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(
            f"CREATE POLICY rls_{table}_platform ON {table} FOR ALL "
            f"USING ({_EMERGENCY} OR ({actor} AND {exact_manifest})) "
            f"WITH CHECK ({_EMERGENCY} OR ({actor} AND {exact_manifest}))"
        )
        op.execute(
            f"CREATE POLICY rls_{table}_auditor_read ON {table} FOR SELECT "
            f"USING ({auditor} AND {exact_manifest})"
        )

    # The dispatcher can claim mutable work and append attempts, but cannot issue
    # verifier-owned attestations. A separate login/role writes those receipts.
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(
            f"CREATE POLICY rls_{table}_dispatcher_read ON {table} FOR SELECT "
            f"USING ({_DISPATCHER} AND {exact_manifest})"
        )
        op.execute(
            f"CREATE POLICY rls_{table}_dispatcher_update ON {table} FOR UPDATE "
            f"USING ({_DISPATCHER} AND {exact_manifest}) "
            f"WITH CHECK ({_DISPATCHER} AND {exact_manifest})"
        )
    for table in (
        "saas_privacy_deletion_attempts",
        "saas_privacy_evidence_attestations",
    ):
        op.execute(
            f"CREATE POLICY rls_{table}_executor_read ON {table} FOR SELECT "
            f"USING ({_DISPATCHER} AND {exact_manifest})"
        )
    op.execute(
        "CREATE POLICY rls_saas_privacy_deletion_attempts_executor_insert "
        "ON saas_privacy_deletion_attempts FOR INSERT "
        f"WITH CHECK ({_DISPATCHER} AND {exact_manifest})"
    )
    op.execute(
        "CREATE POLICY rls_saas_privacy_evidence_attestations_verifier_read "
        "ON saas_privacy_evidence_attestations FOR SELECT "
        f"USING ({_VERIFIER} AND {exact_manifest})"
    )
    op.execute(
        "CREATE POLICY rls_saas_privacy_evidence_attestations_verifier_insert "
        "ON saas_privacy_evidence_attestations FOR INSERT "
        f"WITH CHECK ({_VERIFIER} AND {exact_manifest} "
        "AND subject_kind IN ('surface', 'backup') "
        "AND execution_attempt_id IS NOT NULL)"
    )
    for table in (
        "saas_privacy_deletion_manifests",
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(
            f"CREATE POLICY rls_{table}_verifier_read ON {table} FOR SELECT "
            f"USING ({_VERIFIER} AND "
            + (manifest_executor if table == "saas_privacy_deletion_manifests" else exact_manifest)
            + ")"
        )
    op.execute(
        "CREATE POLICY rls_runtime_partitions_privacy_verifier_read "
        "ON saas_runtime_partitions FOR SELECT USING ("
        f"{_VERIFIER} AND (({_TARGET_TENANT} IS NOT NULL "
        f"AND tenant_id = {_TARGET_TENANT}) OR ({_TARGET_USER} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_privacy_deletion_work_items privacy_impact "
        f"WHERE privacy_impact.manifest_id = {_TARGET_MANIFEST} "
        "AND privacy_impact.runtime_partition_id = saas_runtime_partitions.id))))"
    )
    op.execute(
        "CREATE POLICY rls_saas_privacy_backup_retention_items_dispatcher_insert "
        "ON saas_privacy_backup_retention_items FOR INSERT "
        f"WITH CHECK ({_DISPATCHER} AND {exact_manifest})"
    )
    outbox_target = (
        "((payload ->> 'target_type' = 'tenant' "
        f"AND tenant_id = {_TARGET_TENANT}) OR "
        "(payload ->> 'target_type' = 'global_user' AND tenant_id IS NULL "
        f"AND {_TARGET_USER} IS NOT NULL))"
    )
    exact_payload_keys = (
        "ARRAY(SELECT jsonb_object_keys(payload::jsonb) ORDER BY 1) = "
        "ARRAY['attempt_id','attempt_number','available_at','content_sha256','error_code',"
        "'item_id','manifest_id','replay_generation','schema_version','status','surface',"
        "'target_locator_hmac','target_type']::text[]"
    )
    uuid_pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    hex_pattern = "^[0-9a-f]{64}$"
    op.execute(
        "CREATE POLICY rls_outbox_privacy_dispatcher_insert "
        "ON saas_control_plane_outbox FOR INSERT WITH CHECK ("
        f"{_DISPATCHER} AND aggregate_type = 'privacy_manifest' "
        f"AND aggregate_key = ({_TARGET_MANIFEST})::text "
        f"AND event_type IN ({_quoted(_PRIVACY_EXECUTION_EVENTS)}) "
        f"AND {exact_payload_keys} "
        "AND jsonb_typeof(payload::jsonb -> 'schema_version') = 'number' "
        "AND payload ->> 'schema_version' = '1' "
        f"AND payload ->> 'manifest_id' = ({_TARGET_MANIFEST})::text "
        f"AND payload ->> 'manifest_id' ~ '{uuid_pattern}' "
        f"AND payload ->> 'item_id' ~ '{uuid_pattern}' "
        f"AND payload ->> 'attempt_id' ~ '{uuid_pattern}' "
        f"AND payload ->> 'content_sha256' ~ '{hex_pattern}' "
        f"AND payload ->> 'target_locator_hmac' ~ '{hex_pattern}' "
        "AND payload ->> 'target_locator_hmac' = "
        "NULLIF(current_setting('app.privacy_locator_hash', true), '') "
        "AND jsonb_typeof(payload::jsonb -> 'attempt_number') = 'number' "
        "AND payload ->> 'attempt_number' ~ '^[1-9][0-9]*$' "
        "AND jsonb_typeof(payload::jsonb -> 'replay_generation') = 'number' "
        "AND payload ->> 'replay_generation' ~ '^(0|[1-9][0-9]*)$' "
        "AND jsonb_typeof(payload::jsonb -> 'surface') = 'string' "
        "AND length(payload ->> 'surface') BETWEEN 1 AND 96 "
        "AND ((event_type IN ('privacy.execution.work_succeeded', "
        "'privacy.execution.backup_purged', 'privacy.execution.retention_completed') "
        "AND payload::jsonb -> 'error_code' = 'null'::jsonb "
        "AND payload::jsonb -> 'available_at' = 'null'::jsonb) OR "
        "(event_type IN ('privacy.execution.work_retry_scheduled', "
        "'privacy.execution.backup_retry_scheduled') "
        "AND jsonb_typeof(payload::jsonb -> 'error_code') = 'string' "
        "AND jsonb_typeof(payload::jsonb -> 'available_at') = 'string') OR "
        "(event_type IN ('privacy.execution.work_dead_lettered', "
        "'privacy.execution.backup_dead_lettered', "
        "'privacy.execution.retention_attention_required') "
        "AND jsonb_typeof(payload::jsonb -> 'error_code') = 'string' "
        "AND payload::jsonb -> 'available_at' = 'null'::jsonb)) "
        f"AND {outbox_target})"
    )

    op.execute(
        "CREATE OR REPLACE FUNCTION reject_privacy_execution_fact_mutation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'privacy execution facts are append-only' USING ERRCODE = '55000'; "
        "END; $$"
    )
    for table in (
        "saas_privacy_approval_bindings",
        "saas_privacy_deletion_attempts",
        "saas_privacy_evidence_attestations",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_privacy_execution_fact_mutation()"
        )
    op.execute(
        "CREATE OR REPLACE FUNCTION reject_privacy_execution_fact_delete() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'privacy execution state cannot be deleted' USING ERRCODE = '55000'; "
        "END; $$"
    )
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_nodelete BEFORE DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_privacy_execution_fact_delete()"
        )
    op.execute(
        "CREATE OR REPLACE FUNCTION enforce_privacy_dispatcher_transition() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        f"IF NOT ({_DISPATCHER}) THEN RETURN NEW; END IF; "
        "IF TG_TABLE_NAME = 'saas_privacy_deletion_work_items' THEN "
        "IF NOT ((OLD.status IN ('pending', 'retry') AND NEW.status = 'leased') OR "
        "(OLD.status = 'leased' AND NEW.status IN "
        "('leased', 'retry', 'dead_letter', 'succeeded'))) THEN "
        "RAISE EXCEPTION 'invalid Privacy Work Item transition' USING ERRCODE = '55000'; "
        "END IF; "
        "IF NEW.status = 'succeeded' AND NOT EXISTS (SELECT 1 "
        "FROM saas_privacy_evidence_attestations receipt WHERE "
        "receipt.id = NEW.evidence_attestation_id AND receipt.manifest_id = NEW.manifest_id "
        "AND receipt.target_type = NEW.target_type AND receipt.target_id = NEW.target_id "
        "AND receipt.tenant_id IS NOT DISTINCT FROM NEW.tenant_id "
        "AND receipt.subject_kind = 'surface' AND receipt.subject_id = NEW.id "
        "AND receipt.surface = NEW.surface AND receipt.attempt_number = NEW.attempt_count "
        "AND receipt.lease_generation = NEW.lease_generation "
        "AND receipt.replay_generation = NEW.replay_generation "
        "AND receipt.payload_sha256 = NEW.outcome_content_sha256 "
        "AND length(receipt.verifier_receipt_sha256) = 64) THEN "
        "RAISE EXCEPTION 'Privacy success requires an independent verifier receipt' "
        "USING ERRCODE = '55000'; END IF; "
        "ELSE "
        "IF NOT ((OLD.status IN ('retention_wait', 'held', 'retry') "
        "AND NEW.status IN ('leased', 'held')) OR "
        "(OLD.status = 'leased' AND NEW.status IN "
        "('leased', 'held', 'retention_wait', 'retry', 'dead_letter', 'purged'))) THEN "
        "RAISE EXCEPTION 'invalid Privacy Backup transition' USING ERRCODE = '55000'; "
        "END IF; "
        "IF NEW.status = 'purged' AND NOT EXISTS (SELECT 1 "
        "FROM saas_privacy_evidence_attestations receipt WHERE "
        "receipt.id = NEW.evidence_attestation_id AND receipt.manifest_id = NEW.manifest_id "
        "AND receipt.target_type = NEW.target_type AND receipt.target_id = NEW.target_id "
        "AND receipt.tenant_id IS NOT DISTINCT FROM NEW.tenant_id "
        "AND receipt.subject_kind = 'backup' AND receipt.subject_id = NEW.id "
        "AND receipt.surface = 'backups_and_snapshots' "
        "AND receipt.attempt_number = NEW.attempt_count "
        "AND receipt.lease_generation = NEW.lease_generation "
        "AND receipt.replay_generation = NEW.replay_generation "
        "AND receipt.payload_sha256 = NEW.purge_evidence_sha256 "
        "AND length(receipt.verifier_receipt_sha256) = 64) THEN "
        "RAISE EXCEPTION 'Privacy purge requires an independent verifier receipt' "
        "USING ERRCODE = '55000'; END IF; END IF; RETURN NEW; END; $$"
    )
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_dispatcher_transition BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION enforce_privacy_dispatcher_transition()"
        )


def _require_no_new_facts() -> None:
    bind = op.get_bind()
    counts = {
        table: bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one()
        for table in _NEW_TABLES
    }
    privacy_operations = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_platform_admin_operations "
            f"WHERE action IN ({_quoted(_PRIVACY_PLATFORM_ACTIONS)})"
        )
    ).scalar_one()
    governed_manifests = bind.execute(
        sa.text(
            "SELECT count(*) FROM saas_privacy_deletion_manifests "
            "WHERE start_operation_id IS NOT NULL OR completion_operation_id IS NOT NULL "
            "OR approval_provenance <> 'legacy_unverified' "
            "OR retention_status <> 'legacy_reconciliation_required' "
            "OR retention_completed_at IS NOT NULL"
        )
    ).scalar_one()
    if any(counts.values()) or privacy_operations or governed_manifests:
        raise RuntimeError(
            "pc5b00000003 downgrade refused: Privacy execution, approval, retention, "
            "attestation, or production-admission facts exist; reconcile by a reviewed "
            "forward migration instead"
        )


def _drop_postgresql_security() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP POLICY IF EXISTS rls_privacy_legal_holds_executor_read "
        "ON saas_privacy_legal_holds"
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_platform_admin_operation_privacy_update_guard" '
        "ON saas_platform_admin_operations"
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_platform_admin_operation_privacy_update" '
        "ON saas_platform_admin_operations"
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_platform_admin_operation_privacy_insert_guard" '
        "ON saas_platform_admin_operations"
    )
    op.execute(
        'DROP POLICY IF EXISTS "rls_platform_admin_operation_privacy_insert" '
        "ON saas_platform_admin_operations"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_privacy_manifests_executor_update "
        "ON saas_privacy_deletion_manifests"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_privacy_manifests_executor_read "
        "ON saas_privacy_deletion_manifests"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_privacy_approval_bindings_staff_read "
        "ON saas_privacy_approval_bindings"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_privacy_approval_bindings_platform_insert "
        "ON saas_privacy_approval_bindings"
    )
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_dispatcher_transition ON {table}")
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_dispatcher_update ON {table}")
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_dispatcher_read ON {table}")
    op.execute(
        "DROP POLICY IF EXISTS "
        "rls_saas_privacy_backup_retention_items_dispatcher_insert "
        "ON saas_privacy_backup_retention_items"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_outbox_privacy_dispatcher_insert "
        "ON saas_control_plane_outbox"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_privacy_deletion_attempts_executor_insert "
        "ON saas_privacy_deletion_attempts"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_privacy_evidence_attestations_verifier_insert "
        "ON saas_privacy_evidence_attestations"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_saas_privacy_evidence_attestations_verifier_read "
        "ON saas_privacy_evidence_attestations"
    )
    op.execute(
        "DROP POLICY IF EXISTS rls_runtime_partitions_privacy_verifier_read "
        "ON saas_runtime_partitions"
    )
    for table in (
        "saas_privacy_deletion_manifests",
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_verifier_read ON {table}")
    for table in (
        "saas_privacy_deletion_attempts",
        "saas_privacy_evidence_attestations",
    ):
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_executor_read ON {table}")
    for table in _NEW_TABLES:
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_auditor_read ON {table}")
        op.execute(f"DROP POLICY IF EXISTS rls_{table}_platform ON {table}")
    for table in (
        "saas_privacy_approval_bindings",
        "saas_privacy_deletion_attempts",
        "saas_privacy_evidence_attestations",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable ON {table}")
    for table in (
        "saas_privacy_deletion_work_items",
        "saas_privacy_backup_retention_items",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_nodelete ON {table}")
    op.execute("DROP FUNCTION IF EXISTS reject_privacy_execution_fact_mutation()")
    op.execute("DROP FUNCTION IF EXISTS reject_privacy_execution_fact_delete()")
    op.execute("DROP FUNCTION IF EXISTS enforce_privacy_dispatcher_transition()")


def _drop_tables() -> None:
    op.drop_index(
        "ix_privacy_attestation_manifest",
        table_name="saas_privacy_evidence_attestations",
    )
    op.drop_index(
        "uq_privacy_attestation_manifest_role",
        table_name="saas_privacy_evidence_attestations",
    )
    op.drop_index(
        "uq_privacy_attestation_execution_attempt",
        table_name="saas_privacy_evidence_attestations",
    )
    op.drop_table("saas_privacy_evidence_attestations")
    op.drop_index("ix_privacy_attempt_manifest", table_name="saas_privacy_deletion_attempts")
    op.drop_index(
        "uq_privacy_attempt_backup_generation_number",
        table_name="saas_privacy_deletion_attempts",
    )
    op.drop_index(
        "uq_privacy_attempt_work_item_generation_number",
        table_name="saas_privacy_deletion_attempts",
    )
    op.drop_table("saas_privacy_deletion_attempts")
    op.drop_index(
        "ix_privacy_backup_retention_target",
        table_name="saas_privacy_backup_retention_items",
    )
    op.drop_index(
        "ix_privacy_backup_retention_dispatch",
        table_name="saas_privacy_backup_retention_items",
    )
    op.drop_table("saas_privacy_backup_retention_items")
    op.drop_index("ix_privacy_work_item_target", table_name="saas_privacy_deletion_work_items")
    op.drop_index("ix_privacy_work_item_dispatch", table_name="saas_privacy_deletion_work_items")
    op.drop_table("saas_privacy_deletion_work_items")
    op.drop_index(
        "ix_privacy_approval_binding_target",
        table_name="saas_privacy_approval_bindings",
    )
    op.drop_table("saas_privacy_approval_bindings")


def _restore_manifest() -> None:
    with op.batch_alter_table("saas_privacy_deletion_manifests") as batch:
        batch.drop_constraint("ck_privacy_manifest_retention_completion", type_="check")
        batch.drop_constraint("ck_privacy_manifest_retention_status", type_="check")
        batch.drop_constraint("ck_privacy_manifest_governed_completion", type_="check")
        batch.drop_constraint("ck_privacy_manifest_completion_operation", type_="check")
        batch.drop_constraint("ck_privacy_manifest_start_operation", type_="check")
        batch.drop_constraint("ck_privacy_manifest_approval_provenance", type_="check")
        batch.drop_constraint("uq_privacy_manifest_completion_operation", type_="unique")
        batch.drop_constraint("uq_privacy_manifest_start_operation", type_="unique")
        batch.drop_constraint("fk_privacy_manifest_completion_operation", type_="foreignkey")
        batch.drop_constraint("fk_privacy_manifest_start_operation", type_="foreignkey")
        batch.drop_column("retention_completed_at")
        batch.drop_column("retention_status")
        batch.drop_column("approval_provenance")
        batch.drop_column("completion_operation_id")
        batch.drop_column("start_operation_id")


def upgrade() -> None:
    _change_platform_action_constraint(include_privacy=True)
    _alter_manifest()
    _create_approval_bindings()
    _create_work_items()
    _create_backup_retention()
    _create_attempts()
    _create_attestations()
    _backfill_legacy_manifests()
    _install_postgresql_security()


def downgrade() -> None:
    _require_no_new_facts()
    _drop_postgresql_security()
    _drop_tables()
    _restore_manifest()
    _change_platform_action_constraint(include_privacy=False)
