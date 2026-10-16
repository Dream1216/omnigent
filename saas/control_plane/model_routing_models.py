"""Platform-owned connections, immutable credentials, and projection receipts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from saas.control_plane.db_models import SaasBase, _hex64


class ModelConnectionRecord(SaasBase):
    __tablename__ = "saas_model_connections"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    provider_id: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False)
    credential_generation: Mapped[int] = mapped_column(nullable=False)
    updated_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("provider_id = 'deepseek'", name="ck_model_connection_provider"),
        sa.CheckConstraint(
            "base_url = 'https://api.deepseek.com'", name="ck_model_connection_url"
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_connection_name"
        ),
        sa.CheckConstraint(
            "version > 0 AND credential_generation > 0", name="ck_model_connection_version"
        ),
    )


class ModelCredentialVersionRecord(SaasBase):
    """Append-only canonical secret; no plaintext or public fingerprint."""

    __tablename__ = "saas_model_credential_versions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    connection_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_connections.id", ondelete="RESTRICT"), nullable=False
    )
    generation: Mapped[int] = mapped_column(nullable=False)
    credential_name: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    api_key_ciphertext: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("connection_id", "generation", name="uq_model_credential_generation"),
        sa.UniqueConstraint("connection_id", "id", name="uq_model_credential_connection"),
        sa.CheckConstraint("generation > 0", name="ck_model_credential_generation"),
        sa.CheckConstraint(
            "length(api_key_ciphertext) > 0", name="ck_model_credential_ciphertext"
        ),
        sa.CheckConstraint(
            "length(credential_name) BETWEEN 1 AND 128", name="ck_model_credential_name"
        ),
    )


class ModelProjectionOperationRecord(SaasBase):
    """Durable admission; external completion is never inferred from a conflict."""

    __tablename__ = "saas_model_projection_operations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    connection_id: Mapped[UUID] = mapped_column(nullable=False)
    credential_version_id: Mapped[UUID] = mapped_column(nullable=False)
    deployment_version_id: Mapped[UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    version: Mapped[int] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id"],
            ["saas_model_credential_versions.connection_id", "saas_model_credential_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id", "deployment_version_id"],
            [
                "saas_model_deployment_versions.connection_id",
                "saas_model_deployment_versions.credential_version_id",
                "saas_model_deployment_versions.id",
            ],
            name="fk_model_projection_deployment_scope",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "actor_principal_id", "idempotency_key", name="uq_model_projection_idempotency"
        ),
        sa.CheckConstraint(
            "action IN ('create_connection', 'rotate_credential', "
            "'create_deployment', 'verify_deployment')",
            name="ck_model_projection_action",
        ),
        sa.CheckConstraint(
            "(action IN ('create_connection', 'rotate_credential') "
            "AND deployment_version_id IS NULL) "
            "OR (action IN ('create_deployment', 'verify_deployment') "
            "AND deployment_version_id IS NOT NULL)",
            name="ck_model_projection_deployment_scope",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'applying', 'applied', 'verified', 'failed', 'uncertain')",
            name="ck_model_projection_status",
        ),
        sa.CheckConstraint(_hex64("request_hash"), name="ck_model_projection_request_hash"),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_projection_idempotency"
        ),
        sa.CheckConstraint("version > 0", name="ck_model_projection_version"),
        sa.Index("ix_model_projection_status", "status", "created_at"),
    )


class ModelProjectionTransitionRecord(SaasBase):
    """Append-only domain receipt written with its operation's state change."""

    __tablename__ = "saas_model_projection_transitions"

    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_projection_operations.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    version: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_control_plane_outbox.id", ondelete="RESTRICT"),
        nullable=False,
    )
    actor_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    previous_status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.CheckConstraint("version > 1", name="ck_model_projection_transition_version"),
        sa.CheckConstraint(
            "(previous_status = 'requested' AND status IN ('applying', 'failed')) OR "
            "(previous_status = 'applying' "
            "AND status IN ('applied', 'verified', 'failed', 'uncertain'))",
            name="ck_model_projection_transition_edge",
        ),
    )


class ModelDeploymentVersionRecord(SaasBase):
    """Append-only draft; external acknowledgement is separate from verification."""

    __tablename__ = "saas_model_deployment_versions"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    public_model_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    provider_model: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    connection_id: Mapped[UUID] = mapped_column(nullable=False)
    credential_version_id: Mapped[UUID] = mapped_column(nullable=False)
    generation: Mapped[int] = mapped_column(nullable=False)
    deployment_alias: Mapped[str] = mapped_column(sa.String(128), nullable=False, unique=True)
    wire_api: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    max_output_tokens: Mapped[int] = mapped_column(nullable=False)
    configuration_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    canonical_configuration: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_by_principal_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_platform_staff_principals.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["connection_id", "credential_version_id"],
            ["saas_model_credential_versions.connection_id", "saas_model_credential_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "public_model_id", "generation", name="uq_model_deployment_generation"
        ),
        sa.UniqueConstraint(
            "connection_id", "credential_version_id", "id", name="uq_model_deployment_scope"
        ),
        sa.CheckConstraint(
            "public_model_id = provider_model AND public_model_id LIKE 'deepseek-%' "
            "AND length(public_model_id) BETWEEN 10 AND 128",
            name="ck_model_deployment_model",
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_deployment_name"
        ),
        sa.CheckConstraint("generation > 0", name="ck_model_deployment_generation"),
        sa.CheckConstraint(
            "deployment_alias = 'platform-model-' || replace(CAST(id AS TEXT), '-', '')",
            name="ck_model_deployment_alias",
        ),
        sa.CheckConstraint(
            "wire_api IN ('openai_chat_completions', 'openai_responses')",
            name="ck_model_deployment_wire_api",
        ),
        sa.CheckConstraint(
            "max_output_tokens BETWEEN 1 AND 65536", name="ck_model_deployment_output_limit"
        ),
        sa.CheckConstraint(_hex64("configuration_sha256"), name="ck_model_deployment_hash"),
        sa.CheckConstraint(
            "length(canonical_configuration) BETWEEN 1 AND 16384",
            name="ck_model_deployment_configuration",
        ),
    )


class ModelVerificationCommandRecord(SaasBase):
    """Append-only approved cost and funding snapshot for one bounded test."""

    __tablename__ = "saas_model_verification_commands"

    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_projection_operations.id", ondelete="RESTRICT"), primary_key=True
    )
    provider_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    configuration_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    canonical_price: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    price_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    pricing_revision: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    funding_policy_version: Mapped[int] = mapped_column(nullable=False)
    requested_microusd: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    requested_tokens: Mapped[int] = mapped_column(nullable=False)
    output_token_limit: Mapped[int] = mapped_column(nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("provider_id", "funding_policy_version"),
            (
                "saas_model_test_funding_policies.provider_id",
                "saas_model_test_funding_policies.version",
            ),
            name="fk_model_verification_funding",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "operation_id",
            "configuration_sha256",
            "funding_policy_version",
            name="uq_model_verification_command_scope",
        ),
        sa.CheckConstraint(
            "provider_id = 'deepseek' AND funding_policy_version > 0",
            name="ck_model_verification_funding",
        ),
        sa.CheckConstraint(
            _hex64("configuration_sha256") + " AND " + _hex64("price_sha256"),
            name="ck_model_verification_command_hashes",
        ),
        sa.CheckConstraint(
            "requested_microusd > 0 AND requested_tokens BETWEEN 1 AND 1056 "
            "AND output_token_limit BETWEEN 1 AND 32 "
            "AND length(canonical_price) BETWEEN 1 AND 8192 "
            "AND length(pricing_revision) BETWEEN 1 AND 32",
            name="ck_model_verification_command_bounds",
        ),
    )


class ModelVerificationBudgetBindingRecord(SaasBase):
    """Append-only binding to a real platform-test hold before external effects."""

    __tablename__ = "saas_model_verification_budget_bindings"

    operation_id: Mapped[UUID] = mapped_column(primary_key=True)
    budget_reservation_id: Mapped[UUID] = mapped_column(nullable=False, unique=True)
    configuration_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    funding_policy_version: Mapped[int] = mapped_column(nullable=False)
    admitted_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("operation_id", "configuration_sha256", "funding_policy_version"),
            (
                "saas_model_verification_commands.operation_id",
                "saas_model_verification_commands.configuration_sha256",
                "saas_model_verification_commands.funding_policy_version",
            ),
            name="fk_model_verification_binding_command",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            (
                "operation_id",
                "budget_reservation_id",
                "configuration_sha256",
                "funding_policy_version",
            ),
            (
                "saas_model_provider_budget_reservations.test_operation_id",
                "saas_model_provider_budget_reservations.id",
                "saas_model_provider_budget_reservations.test_configuration_sha256",
                "saas_model_provider_budget_reservations.test_policy_version",
            ),
            name="fk_model_verification_binding_budget",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "operation_id", "budget_reservation_id", name="uq_model_verification_budget_binding"
        ),
    )


class ModelVerificationReceiptRecord(SaasBase):
    """Immutable protocol evidence; financial resolution may resume without inference."""

    __tablename__ = "saas_model_verification_receipts"

    operation_id: Mapped[UUID] = mapped_column(
        sa.ForeignKey("saas_model_verification_commands.operation_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    budget_reservation_id: Mapped[UUID | None] = mapped_column()
    outcome: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    actual_microusd: Mapped[int | None] = mapped_column(sa.BigInteger)
    request_attempts: Mapped[int] = mapped_column(nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.String(128))
    canonical_evidence: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ("operation_id", "budget_reservation_id"),
            (
                "saas_model_verification_budget_bindings.operation_id",
                "saas_model_verification_budget_bindings.budget_reservation_id",
            ),
            name="fk_model_verification_receipt_budget",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "request_attempts IN (0, 1) "
            "AND (actual_microusd IS NULL OR actual_microusd >= 0) "
            "AND length(canonical_evidence) BETWEEN 1 AND 8192",
            name="ck_model_verification_receipt_bounds",
        ),
        sa.CheckConstraint(
            "(outcome = 'passed' AND error_code IS NULL AND request_attempts = 1 "
            "AND actual_microusd IS NOT NULL AND actual_microusd > 0 "
            "AND budget_reservation_id IS NOT NULL) OR "
            "(outcome IN ('failed', 'uncertain') AND error_code IS NOT NULL "
            "AND length(error_code) > 0)",
            name="ck_model_verification_receipt_outcome",
        ),
        sa.CheckConstraint(_hex64("evidence_sha256"), name="ck_model_verification_receipt_hash"),
    )
