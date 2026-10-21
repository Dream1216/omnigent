"""Migration-owned schema metadata for the P0 application compatibility window.

No runtime ORM classes or business services are imported. An application that
registers the complete routing metadata keeps its own ordinary drift checks.
"""

from __future__ import annotations

import sqlalchemy as sa

_MODEL_TABLES = frozenset(
    (
        "saas_model_connections",
        "saas_model_credential_versions",
        "saas_model_deployment_versions",
        "saas_model_gateway_evidence",
        "saas_model_projection_operations",
        "saas_model_projection_transitions",
        "saas_model_publication_commands",
        "saas_model_publication_disablements",
        "saas_model_publication_revocations",
        "saas_model_publication_versions",
        "saas_model_run_tokens",
        "saas_model_test_funding_policies",
        "saas_model_verification_budget_bindings",
        "saas_model_verification_commands",
        "saas_model_verification_receipts",
    )
)


def control_plane_migration_metadata(base: sa.MetaData) -> sa.MetaData:
    declared = _MODEL_TABLES.intersection(base.tables)
    if declared:
        if declared != _MODEL_TABLES:
            raise ValueError("incomplete application model schema metadata")
        return base
    metadata = sa.MetaData(naming_convention=base.naming_convention)
    for source in base.tables.values():
        source.to_metadata(metadata)
    sa.Table(
        "saas_model_connections",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("provider_id", sa.String(32), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("credential_generation", sa.Integer(), nullable=False),
        sa.Column(
            "updated_by_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "base_url = 'https://api.deepseek.com'", name="ck_model_connection_url"
        ),
        sa.CheckConstraint("provider_id = 'deepseek'", name="ck_model_connection_provider"),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_connection_name"
        ),
        sa.CheckConstraint(
            "version > 0 AND credential_generation > 0", name="ck_model_connection_version"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    sa.Index(
        "ix_model_connection_page",
        metadata.tables["saas_model_connections"].c["created_at"],
        metadata.tables["saas_model_connections"].c["id"],
        unique=False,
    )
    sa.Table(
        "saas_model_credential_versions",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("connection_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("credential_name", sa.String(128), nullable=False),
        sa.Column("api_key_ciphertext", sa.LargeBinary(16383), nullable=False),
        sa.Column(
            "created_by_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("generation > 0", name="ck_model_credential_generation"),
        sa.CheckConstraint(
            "length(api_key_ciphertext) BETWEEN 8 AND 16383", name="ck_model_credential_ciphertext"
        ),
        sa.CheckConstraint(
            "length(credential_name) BETWEEN 1 AND 128", name="ck_model_credential_name"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connection_id", "generation", name="uq_model_credential_generation"),
        sa.UniqueConstraint("connection_id", "id", name="uq_model_credential_connection"),
        sa.UniqueConstraint("credential_name"),
    )
    sa.Table(
        "saas_model_deployment_versions",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("provider_model", sa.String(128), nullable=False),
        sa.Column("connection_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column(
            "credential_version_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("deployment_alias", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_configuration", sa.LargeBinary(16383), nullable=False),
        sa.Column(
            "created_by_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "deployment_alias = 'platform-model-' || replace(CAST(id AS TEXT), '-', '')",
            name="ck_model_deployment_alias",
        ),
        sa.CheckConstraint(
            "hex(substr(canonical_configuration, 1, 7)) = '4F474D44010000'",
            name="ck_model_deployment_document_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "length(configuration_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(configuration_sh"
            "a256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', "
            "''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', "
            "''), 'e', ''), 'f', '') = ''",
            name="ck_model_deployment_hash",
        ),
        sa.CheckConstraint(
            "public_model_id = provider_model AND public_model_id LIKE 'deepseek-%' "
            "AND length(public_model_id) BETWEEN 10 AND 128",
            name="ck_model_deployment_model",
        ),
        sa.CheckConstraint(
            "substring(canonical_configuration from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_deployment_document_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            "wire_api IN ('openai_chat_completions', 'openai_responses')",
            name="ck_model_deployment_wire_api",
        ),
        sa.CheckConstraint("generation > 0", name="ck_model_deployment_generation"),
        sa.CheckConstraint(
            "length(canonical_configuration) BETWEEN 8 AND 16383",
            name="ck_model_deployment_configuration",
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 128", name="ck_model_deployment_name"
        ),
        sa.CheckConstraint(
            "max_output_tokens BETWEEN 1 AND 65536", name="ck_model_deployment_output_limit"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connection_id", "credential_version_id", "id", name="uq_model_deployment_scope"
        ),
        sa.UniqueConstraint("deployment_alias"),
        sa.UniqueConstraint(
            "public_model_id", "generation", name="uq_model_deployment_generation"
        ),
    )
    sa.Index(
        "ix_model_deployment_page",
        metadata.tables["saas_model_deployment_versions"].c["created_at"],
        metadata.tables["saas_model_deployment_versions"].c["id"],
        unique=False,
    )
    sa.Table(
        "saas_model_gateway_evidence",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("reservation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("budget_version", sa.Integer(), nullable=False),
        sa.Column("canonical_evidence", sa.LargeBinary(16383), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "hex(substr(canonical_evidence, 1, 7)) = '4F474D44010000'",
            name="ck_model_gateway_evidence_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "length(evidence_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(evidence_sha256, "
            "'0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = ''",
            name="ck_model_gateway_evidence_hash",
        ),
        sa.CheckConstraint(
            "phase IN ('request', 'in_flight', 'uncertain', 'settled', 'released', 'expired')",
            name="ck_model_gateway_evidence_phase",
        ),
        sa.CheckConstraint(
            "substring(canonical_evidence from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_gateway_evidence_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint("budget_version > 0", name="ck_model_gateway_evidence_version"),
        sa.CheckConstraint(
            "length(canonical_evidence) BETWEEN 8 AND 16383",
            name="ck_model_gateway_evidence_bound",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "reservation_id", "budget_version", name="uq_model_gateway_evidence_version"
        ),
        sa.UniqueConstraint("reservation_id", "phase", name="uq_model_gateway_evidence_phase"),
    )
    sa.Table(
        "saas_model_projection_operations",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("connection_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column(
            "credential_version_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("deployment_version_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(action IN ('create_connection', 'rotate_credential') AND "
            "deployment_version_id IS NULL) OR (action IN ('create_deployment', "
            "'verify_deployment', 'publish_deployment') AND deployment_version_id IS "
            "NOT NULL)",
            name="ck_model_projection_deployment_scope",
        ),
        sa.CheckConstraint(
            "action IN ('create_connection', 'rotate_credential', "
            "'create_deployment', 'verify_deployment', 'publish_deployment')",
            name="ck_model_projection_action",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND replace(replace(replace(replace(replace(re"
            "place(replace(replace(replace(replace(replace(replace(replace(replace(re"
            "place(replace(request_hash, '0', ''), '1', ''), '2', ''), '3', ''), '4', "
            "''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', "
            "''), 'c', ''), 'd', ''), 'e', ''), 'f', '') = ''",
            name="ck_model_projection_request_hash",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'applying', 'applied', 'verified', 'failed', 'uncertain')",
            name="ck_model_projection_status",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_projection_idempotency"
        ),
        sa.CheckConstraint("version > 0", name="ck_model_projection_version"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "actor_principal_id", "idempotency_key", name="uq_model_projection_idempotency"
        ),
    )
    sa.Index(
        "ix_model_projection_credential_state",
        metadata.tables["saas_model_projection_operations"].c["credential_version_id"],
        metadata.tables["saas_model_projection_operations"].c["status"],
        metadata.tables["saas_model_projection_operations"].c["action"],
        metadata.tables["saas_model_projection_operations"].c["id"],
        unique=False,
    )
    sa.Index(
        "ix_model_projection_deployment_page",
        metadata.tables["saas_model_projection_operations"].c["deployment_version_id"],
        metadata.tables["saas_model_projection_operations"].c["action"],
        metadata.tables["saas_model_projection_operations"].c["created_at"],
        metadata.tables["saas_model_projection_operations"].c["id"],
        unique=False,
    )
    sa.Table(
        "saas_model_projection_transitions",
        metadata,
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("previous_status", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(previous_status = 'requested' AND status IN ('applying', 'failed')) OR "
            "(previous_status = 'applying' AND status IN ('applied', 'verified', "
            "'failed', 'uncertain'))",
            name="ck_model_projection_transition_edge",
        ),
        sa.CheckConstraint("version > 1", name="ck_model_projection_transition_version"),
        sa.PrimaryKeyConstraint("operation_id", "version"),
    )
    sa.Table(
        "saas_model_publication_commands",
        metadata,
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column(
            "verification_operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("expected_generation", sa.Integer(), nullable=False),
        sa.Column("staff_session_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("staff_security_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "expected_generation >= 0 AND staff_security_version > 0",
            name="ck_model_publication_command_versions",
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_model_publication_command_expiry"),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint(
            "operation_id", "tenant_id", name="uq_model_publication_command_scope"
        ),
    )
    sa.Table(
        "saas_model_publication_disablements",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("through_generation", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("staff_session_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("staff_security_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND replace(replace(replace(replace(replace(re"
            "place(replace(replace(replace(replace(replace(replace(replace(replace(re"
            "place(replace(request_hash, '0', ''), '1', ''), '2', ''), '3', ''), '4', "
            "''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', "
            "''), 'c', ''), 'd', ''), 'e', ''), 'f', '') = ''",
            name="ck_model_disablement_hash",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_disablement_key"
        ),
        sa.CheckConstraint(
            "through_generation > 0 AND staff_security_version > 0",
            name="ck_model_disablement_generation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("principal_id", "idempotency_key", name="uq_model_disablement_key"),
        sa.UniqueConstraint(
            "tenant_id",
            "public_model_id",
            "wire_api",
            "through_generation",
            name="uq_model_disablement_cutoff",
        ),
    )
    sa.Table(
        "saas_model_publication_revocations",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("disablement_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("through_generation", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("staff_session_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("staff_security_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND replace(replace(replace(replace(replace(re"
            "place(replace(replace(replace(replace(replace(replace(replace(replace(re"
            "place(replace(request_hash, '0', ''), '1', ''), '2', ''), '3', ''), '4', "
            "''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', "
            "''), 'c', ''), 'd', ''), 'e', ''), 'f', '') = ''",
            name="ck_model_revocation_hash",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 128", name="ck_model_revocation_key"
        ),
        sa.CheckConstraint(
            "through_generation>0 AND staff_security_version>0",
            name="ck_model_revocation_generation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("disablement_id", name="uq_model_revocation_cutoff"),
        sa.UniqueConstraint("principal_id", "idempotency_key", name="uq_model_revocation_key"),
    )
    sa.Table(
        "saas_model_publication_versions",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column(
            "deployment_version_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("price_sha256", sa.String(64), nullable=False),
        sa.Column("inventory_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_snapshot", sa.LargeBinary(16383), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_readiness", sa.LargeBinary(16383), nullable=False),
        sa.Column("readiness_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "hex(substr(canonical_readiness, 1, 7)) = '4F474D44010000'",
            name="ck_model_publication_readiness_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "hex(substr(canonical_snapshot, 1, 7)) = '4F474D44010000'",
            name="ck_model_publication_snapshot_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "length(configuration_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(configuration_sh"
            "a256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', "
            "''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', "
            "''), 'e', ''), 'f', '') = '' AND length(price_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(price_sha256, "
            "'0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = '' AND length(inventory_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(inventory_sha256"
            ", '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = '' AND length(snapshot_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(snapshot_sha256, "
            "'0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = '' AND length(readiness_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(readiness_sha256"
            ", '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = ''",
            name="ck_model_publication_hashes",
        ),
        sa.CheckConstraint(
            "substring(canonical_readiness from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_publication_readiness_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            "substring(canonical_snapshot from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_publication_snapshot_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            "wire_api IN ('openai_chat_completions', 'openai_responses')",
            name="ck_model_publication_wire_api",
        ),
        sa.CheckConstraint("generation > 0", name="ck_model_publication_generation"),
        sa.CheckConstraint(
            "length(canonical_snapshot) BETWEEN 8 AND 16383 AND "
            "length(canonical_readiness) BETWEEN 8 AND 16383",
            name="ck_model_publication_documents",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "public_model_id",
            "wire_api",
            "generation",
            name="uq_model_publication_generation",
        ),
    )
    sa.Index(
        "ix_model_publication_page",
        metadata.tables["saas_model_publication_versions"].c["created_at"],
        metadata.tables["saas_model_publication_versions"].c["id"],
        unique=False,
    )
    sa.Index(
        "ix_model_publication_tenant_page",
        metadata.tables["saas_model_publication_versions"].c["tenant_id"],
        metadata.tables["saas_model_publication_versions"].c["created_at"],
        metadata.tables["saas_model_publication_versions"].c["id"],
        unique=False,
    )
    sa.Table(
        "saas_model_run_tokens",
        metadata,
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("space_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("project_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("actor_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("run_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("capability_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("fence_token", sa.BigInteger(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("parent_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(token_hash) = 64 AND replace(replace(replace(replace(replace(repl"
            "ace(replace(replace(replace(replace(replace(replace(replace(replace(repl"
            "ace(replace(token_hash, '0', ''), '1', ''), '2', ''), '3', ''), '4', "
            "''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', "
            "''), 'c', ''), 'd', ''), 'e', ''), 'f', '') = ''",
            name="ck_model_run_token_hash",
        ),
        sa.CheckConstraint(
            "(generation=0 AND parent_id IS NULL) OR (generation>0 AND parent_id IS NOT NULL)",
            name="ck_model_run_token_parent",
        ),
        sa.CheckConstraint("expires_at > issued_at", name="ck_model_run_token_expiry"),
        sa.CheckConstraint(
            "fence_token > 0 AND generation BETWEEN 0 AND 256",
            name="ck_model_run_token_generation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("parent_id"),
        sa.UniqueConstraint(
            "run_id", "fence_token", "generation", name="uq_model_run_token_generation"
        ),
        sa.UniqueConstraint("token_hash"),
    )
    sa.Table(
        "saas_model_test_funding_policies",
        metadata,
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("monthly_budget_microusd", sa.BigInteger(), nullable=False),
        sa.Column("daily_test_budget_microusd", sa.BigInteger(), nullable=False),
        sa.Column("daily_test_token_limit", sa.BigInteger(), nullable=False),
        sa.Column("max_test_microusd", sa.BigInteger(), nullable=False),
        sa.Column("max_test_tokens", sa.Integer(), nullable=False),
        sa.Column("daily_test_attempt_limit", sa.Integer(), nullable=False),
        sa.Column("actor_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND replace(replace(replace(replace(replace(re"
            "place(replace(replace(replace(replace(replace(replace(replace(replace(re"
            "place(replace(request_hash, '0', ''), '1', ''), '2', ''), '3', ''), '4', "
            "''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', "
            "''), 'c', ''), 'd', ''), 'e', ''), 'f', '') = ''",
            name="ck_model_test_policy_hash",
        ),
        sa.CheckConstraint(
            "provider_id = 'deepseek' AND version > 0", name="ck_model_test_policy_identity"
        ),
        sa.CheckConstraint(
            "monthly_budget_microusd BETWEEN 1 AND 1000000000000000 AND "
            "daily_test_budget_microusd BETWEEN 1 AND monthly_budget_microusd AND "
            "max_test_microusd BETWEEN 1 AND daily_test_budget_microusd AND "
            "daily_test_token_limit BETWEEN 1 AND 1000000000 AND max_test_tokens "
            "BETWEEN 1 AND 2048 AND max_test_tokens <= daily_test_token_limit AND "
            "daily_test_attempt_limit BETWEEN 1 AND 1000",
            name="ck_model_test_policy_limits",
        ),
        sa.PrimaryKeyConstraint("provider_id", "version"),
    )
    sa.Table(
        "saas_model_verification_budget_bindings",
        metadata,
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column(
            "budget_reservation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False
        ),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("funding_policy_version", sa.Integer(), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint("budget_reservation_id"),
        sa.UniqueConstraint(
            "operation_id", "budget_reservation_id", name="uq_model_verification_budget_binding"
        ),
    )
    sa.Table(
        "saas_model_verification_commands",
        metadata,
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_price", sa.LargeBinary(8199), nullable=False),
        sa.Column("price_sha256", sa.String(64), nullable=False),
        sa.Column("pricing_revision", sa.String(32), nullable=False),
        sa.Column("funding_policy_version", sa.Integer(), nullable=False),
        sa.Column("requested_microusd", sa.BigInteger(), nullable=False),
        sa.Column("requested_tokens", sa.Integer(), nullable=False),
        sa.Column("output_token_limit", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "hex(substr(canonical_price, 1, 7)) = '4F474D44010000'",
            name="ck_model_verification_price_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "length(configuration_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(configuration_sh"
            "a256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', "
            "''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', "
            "''), 'e', ''), 'f', '') = '' AND length(price_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(price_sha256, "
            "'0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = ''",
            name="ck_model_verification_command_hashes",
        ),
        sa.CheckConstraint(
            "provider_id = 'deepseek' AND funding_policy_version > 0",
            name="ck_model_verification_funding",
        ),
        sa.CheckConstraint(
            "substring(canonical_price from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_verification_price_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            "requested_microusd > 0 AND requested_tokens BETWEEN 1 AND 1056 AND "
            "output_token_limit BETWEEN 1 AND 32 AND length(canonical_price) BETWEEN "
            "8 AND 8199 AND length(pricing_revision) BETWEEN 1 AND 32",
            name="ck_model_verification_command_bounds",
        ),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint(
            "operation_id",
            "configuration_sha256",
            "funding_policy_version",
            name="uq_model_verification_command_scope",
        ),
    )
    sa.Table(
        "saas_model_verification_receipts",
        metadata,
        sa.Column("operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=False),
        sa.Column("budget_reservation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("actual_microusd", sa.BigInteger(), nullable=True),
        sa.Column("request_attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("canonical_evidence", sa.LargeBinary(8199), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(outcome = 'passed' AND error_code IS NULL AND request_attempts = 1 AND "
            "actual_microusd IS NOT NULL AND actual_microusd > 0 AND "
            "budget_reservation_id IS NOT NULL) OR (outcome IN ('failed', "
            "'uncertain') AND error_code IS NOT NULL AND length(error_code) > 0)",
            name="ck_model_verification_receipt_outcome",
        ),
        sa.CheckConstraint(
            "hex(substr(canonical_evidence, 1, 7)) = '4F474D44010000'",
            name="ck_model_verification_evidence_format",
        ).ddl_if(dialect="sqlite"),
        sa.CheckConstraint(
            "length(evidence_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(evidence_sha256, "
            "'0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), "
            "'7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), "
            "'e', ''), 'f', '') = ''",
            name="ck_model_verification_receipt_hash",
        ),
        sa.CheckConstraint(
            "substring(canonical_evidence from 1 for 7) = decode('4f474d44010000', 'hex')",
            name="ck_model_verification_evidence_format",
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            "request_attempts IN (0, 1) AND (actual_microusd IS NULL OR "
            "actual_microusd >= 0) AND length(canonical_evidence) BETWEEN 8 AND 8199",
            name="ck_model_verification_receipt_bounds",
        ),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.UniqueConstraint("evidence_sha256"),
    )
    table = metadata.tables["saas_execution_sessions"]
    if "customer_pricing_frozen" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column(
            "customer_pricing_frozen",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        )
    )
    if "customer_pricing_snapshot_id" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column(
            "customer_pricing_snapshot_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "customer_pricing_frozen OR customer_pricing_snapshot_id IS NULL",
            name="ck_session_customer_pricing",
        )
    )
    table = metadata.tables["saas_model_provider_budget_reservations"]
    if "purpose" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column("purpose", sa.String(16), nullable=False, server_default="tenant_run")
    )
    if "test_operation_id" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column("test_operation_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True)
    )
    if "test_actor_principal_id" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column(
            "test_actor_principal_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True
        )
    )
    if "test_policy_version" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(sa.Column("test_policy_version", sa.Integer(), nullable=True))
    if "test_configuration_sha256" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(sa.Column("test_configuration_sha256", sa.String(64), nullable=True))
    if "outcome_evidence_sha256" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(sa.Column("outcome_evidence_sha256", sa.String(64), nullable=True))
    if table.c["tenant_id"].nullable is not False:
        raise ValueError("unexpected legacy model nullability")
    table.c["tenant_id"].nullable = True
    if table.c["run_id"].nullable is not False:
        raise ValueError("unexpected legacy model nullability")
    table.c["run_id"].nullable = True
    previous = [
        c for c in table.constraints if c.name == "ck_model_provider_budget_reservation_state"
    ]
    if len(previous) != 1:
        raise ValueError("unexpected legacy model constraint")
    table.constraints.remove(previous[0])
    previous = [
        c
        for c in table.constraints
        if c.name == "ck_model_provider_budget_reservation_conservation"
    ]
    if len(previous) != 1:
        raise ValueError("unexpected legacy model constraint")
    table.constraints.remove(previous[0])
    previous = [
        c for c in table.constraints if c.name == "ck_model_provider_budget_reservation_status"
    ]
    if len(previous) != 1:
        raise ValueError("unexpected legacy model constraint")
    table.constraints.remove(previous[0])
    table.append_constraint(
        sa.CheckConstraint(
            "(purpose = 'tenant_run' AND tenant_id IS NOT NULL AND run_id IS NOT NULL "
            "AND test_operation_id IS NULL AND test_actor_principal_id IS NULL AND "
            "test_policy_version IS NULL AND test_configuration_sha256 IS NULL) OR "
            "(purpose = 'platform_test' AND tenant_id IS NULL AND run_id IS NULL AND "
            "test_operation_id IS NOT NULL AND test_actor_principal_id IS NOT NULL "
            "AND test_policy_version IS NOT NULL AND test_configuration_sha256 IS NOT "
            "NULL AND test_policy_version > 0 AND length(test_configuration_sha256) = "
            "64 AND replace(replace(replace(replace(replace(replace(replace(replace(r"
            "eplace(replace(replace(replace(replace(replace(replace(replace(test_conf"
            "iguration_sha256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', "
            "''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', "
            "''), 'd', ''), 'e', ''), 'f', '') = '')",
            name="ck_model_budget_funding_scope",
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "(status IN ('reserved', 'in_flight', 'uncertain') AND admitted_microusd "
            "= requested_microusd AND admitted_tokens = requested_tokens AND "
            "released_microusd = 0 AND released_tokens = 0 AND rejection_code IS "
            "NULL) OR (status = 'settled' AND settled_microusd > 0 AND settled_tokens "
            "> 0 AND rejection_code IS NULL) OR (status IN ('released', 'expired') "
            "AND admitted_microusd > 0 AND admitted_tokens > 0 AND rejection_code IS "
            "NULL) OR (status = 'rejected' AND admitted_microusd = 0 AND "
            "admitted_tokens = 0 AND rejection_code IS NOT NULL)",
            name="ck_model_provider_budget_reservation_state",
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "outcome_evidence_sha256 IS NULL OR (status IN ('settled', 'released') "
            "AND length(outcome_evidence_sha256) = 64 AND "
            "replace(replace(replace(replace(replace(replace(replace(replace(replace("
            "replace(replace(replace(replace(replace(replace(replace(outcome_evidence"
            "_sha256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), "
            "'6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), "
            "'d', ''), 'e', ''), 'f', '') = '')",
            name="ck_model_provider_budget_outcome_evidence",
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "settled_microusd >= 0 AND released_microusd >= 0 AND settled_tokens >= 0 "
            "AND released_tokens >= 0 AND ((status IN ('reserved', 'in_flight', "
            "'uncertain') AND released_microusd = 0 AND released_tokens = 0 AND "
            "settled_microusd <= admitted_microusd AND settled_tokens <= "
            "admitted_tokens) OR (status NOT IN ('reserved', 'in_flight', "
            "'uncertain') AND settled_microusd + released_microusd = "
            "admitted_microusd AND settled_tokens + released_tokens = "
            "admitted_tokens))",
            name="ck_model_provider_budget_reservation_conservation",
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "status IN ('reserved', 'in_flight', 'uncertain', 'settled', 'released', "
            "'rejected', 'expired')",
            name="ck_model_provider_budget_reservation_status",
        )
    )
    table.append_constraint(
        sa.UniqueConstraint(
            "test_operation_id",
            "id",
            "test_configuration_sha256",
            "test_policy_version",
            name="uq_model_budget_verification_binding",
        )
    )
    table.append_constraint(
        sa.UniqueConstraint("test_operation_id", name="uq_model_budget_test_operation")
    )
    sa.Index(
        "ix_model_budget_admitted_test_day",
        table.c["provider_id"],
        table.c["purpose"],
        table.c["usage_date"],
        table.c["id"],
        unique=False,
        postgresql_where=sa.text("admitted_microusd > 0"),
        sqlite_where=sa.text("admitted_microusd > 0"),
    )
    table = metadata.tables["saas_run_dispatches"]
    if "physical_recovery_fence" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(sa.Column("physical_recovery_fence", sa.BigInteger(), nullable=True))
    table.append_constraint(
        sa.CheckConstraint(
            "physical_recovery_fence IS NULL OR physical_recovery_fence > 0",
            name="ck_run_dispatch_physical_recovery_fence",
        )
    )
    table = metadata.tables["saas_runs"]
    if "customer_pricing_frozen" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column(
            "customer_pricing_frozen",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        )
    )
    if "customer_pricing_snapshot_id" in table.c:
        raise ValueError("incomplete application model column metadata")
    table.append_column(
        sa.Column(
            "customer_pricing_snapshot_id", sa.Uuid(as_uuid=True, native_uuid=True), nullable=True
        )
    )
    table.append_constraint(
        sa.CheckConstraint(
            "customer_pricing_frozen OR customer_pricing_snapshot_id IS NULL",
            name="ck_run_customer_pricing",
        )
    )
    return metadata
