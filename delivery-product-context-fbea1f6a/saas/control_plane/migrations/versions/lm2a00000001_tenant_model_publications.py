"""Append tenant-scoped model publication commands and immutable release versions.

Revision ID: lm2a00000001
Revises: lm1f00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from saas.control_plane.db_models import _hex64

revision = "lm2a00000001"
down_revision = "lm1f00000001"
branch_labels = None
depends_on = None

_OPS = "saas_model_projection_operations"
_COMMANDS = "saas_model_publication_commands"
_VERSIONS = "saas_model_publication_versions"
_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_BUDGET_COLUMNS = (
    "id, purpose, test_operation_id, test_configuration_sha256, test_policy_version, "
    "status, outcome_evidence_sha256, settled_microusd, settled_tokens"
)
_SESSION_COLUMNS = "id, principal_id, security_version, authenticated_at, expires_at, revoked_at"
_TENANT_ACTOR_ROLES = (
    "saas_app, saas_authenticator, saas_governance, saas_billing, saas_public_api, "
    "saas_platform, saas_platform_governance, saas_privacy_executor, "
    "saas_approval_scheduler_enterprise, saas_onboarding, saas_onboarding_status"
)


def _operation_constraints(publication: bool) -> None:
    actions = "'create_connection', 'rotate_credential', 'create_deployment', 'verify_deployment'"
    drafts = "'create_deployment', 'verify_deployment'"
    if publication:
        actions += ", 'publish_deployment'"
        drafts += ", 'publish_deployment'"
    with op.batch_alter_table(_OPS) as batch:
        batch.drop_constraint("ck_model_projection_action", type_="check")
        batch.drop_constraint("ck_model_projection_deployment_scope", type_="check")
        batch.create_check_constraint("ck_model_projection_action", f"action IN ({actions})")
        batch.create_check_constraint(
            "ck_model_projection_deployment_scope",
            "(action IN ('create_connection', 'rotate_credential') "
            "AND deployment_version_id IS NULL) "
            f"OR (action IN ({drafts}) AND deployment_version_id IS NOT NULL)",
        )


def _tables() -> None:
    op.create_table(
        _COMMANDS,
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("verification_operation_id", sa.Uuid(), nullable=False),
        sa.Column("expected_generation", sa.Integer(), nullable=False),
        sa.Column("staff_session_id", sa.Uuid(), nullable=False),
        sa.Column("staff_security_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("operation_id"),
        sa.ForeignKeyConstraint(["operation_id"], [f"{_OPS}.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id"], ["saas_tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["verification_operation_id"],
            ["saas_model_verification_receipts.operation_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["staff_session_id"], ["saas_platform_auth_sessions.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "operation_id", "tenant_id", name="uq_model_publication_command_scope"
        ),
        sa.CheckConstraint(
            "expected_generation >= 0 AND staff_security_version > 0",
            name="ck_model_publication_command_versions",
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_model_publication_command_expiry"),
    )
    op.create_table(
        _VERSIONS,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_version_id", sa.Uuid(), nullable=False),
        sa.Column("public_model_id", sa.String(128), nullable=False),
        sa.Column("wire_api", sa.String(32), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        *(
            sa.Column(name, sa.String(64), nullable=False)
            for name in (
                "configuration_sha256",
                "price_sha256",
                "inventory_sha256",
                "snapshot_sha256",
                "readiness_sha256",
            )
        ),
        sa.Column("canonical_snapshot", sa.Text(), nullable=False),
        sa.Column("canonical_readiness", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
        sa.ForeignKeyConstraint(
            ["operation_id", "tenant_id"],
            [f"{_COMMANDS}.operation_id", f"{_COMMANDS}.tenant_id"],
            ondelete="RESTRICT",
            name="fk_model_publication_version_scope",
        ),
        sa.ForeignKeyConstraint(
            ["deployment_version_id"], ["saas_model_deployment_versions.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "public_model_id",
            "wire_api",
            "generation",
            name="uq_model_publication_generation",
        ),
        sa.CheckConstraint("generation > 0", name="ck_model_publication_generation"),
        sa.CheckConstraint(
            "wire_api IN ('openai_chat_completions', 'openai_responses')",
            name="ck_model_publication_wire_api",
        ),
        sa.CheckConstraint(
            " AND ".join(
                _hex64(name)
                for name in (
                    "configuration_sha256",
                    "price_sha256",
                    "inventory_sha256",
                    "snapshot_sha256",
                    "readiness_sha256",
                )
            ),
            name="ck_model_publication_hashes",
        ),
        sa.CheckConstraint(
            "length(canonical_snapshot) BETWEEN 1 AND 16384 "
            "AND length(canonical_readiness) BETWEEN 1 AND 16384",
            name="ck_model_publication_documents",
        ),
    )


def _authority() -> None:
    # Staff/Projection must not gain membership reads to evaluate an unrelated tenant policy.
    op.execute(f"ALTER POLICY rls_tenants_actor_select ON saas_tenants TO {_TENANT_ACTOR_ROLES}")
    for table in (_COMMANDS, _VERSIONS):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY rls_model_publication_staff_read ON {table} "
            "FOR SELECT TO saas_platform_app USING (EXISTS ("
            "SELECT 1 FROM saas_platform_role_assignments assignment "
            f"WHERE assignment.principal_id = {_PRINCIPAL} "
            "AND assignment.role IN ('platform_operator', 'platform_security_auditor') "
            "AND assignment.status = 'active' AND (assignment.expires_at IS NULL "
            "OR assignment.expires_at > CURRENT_TIMESTAMP)))"
        )
        op.execute(
            f"CREATE POLICY rls_model_publication_worker_read ON {table} "
            "FOR SELECT TO saas_model_projection USING (true)"
        )
        op.execute(
            f"CREATE POLICY rls_model_publication_recovery ON {table} "
            "FOR SELECT TO saas_platform, saas_platform_governance USING (true)"
        )
        op.execute(
            f"GRANT SELECT ON {table} TO saas_platform_app, saas_model_projection, "
            "saas_platform, saas_platform_governance"
        )
    op.execute(f"GRANT INSERT ON {_COMMANDS} TO saas_platform_app")
    op.execute(f"GRANT INSERT ON {_VERSIONS} TO saas_model_projection")
    op.execute(
        f"CREATE POLICY rls_model_publication_command_insert ON {_COMMANDS} "
        "FOR INSERT TO saas_platform_app WITH CHECK (EXISTS ("
        f"SELECT 1 FROM {_OPS} operation WHERE operation.id = operation_id "
        "AND operation.action = 'publish_deployment' AND operation.status = 'requested' "
        f"AND operation.actor_principal_id = {_PRINCIPAL} "
        "AND expires_at > operation.created_at "
        "AND expires_at <= operation.created_at + interval '5 minutes'))"
    )
    op.execute(
        f"CREATE POLICY rls_model_publication_version_insert ON {_VERSIONS} "
        "FOR INSERT TO saas_model_projection WITH CHECK (EXISTS ("
        f"SELECT 1 FROM {_OPS} operation JOIN {_COMMANDS} command "
        "ON command.operation_id = operation.id "
        f"WHERE operation.id = {_VERSIONS}.operation_id "
        f"AND operation.deployment_version_id = {_VERSIONS}.deployment_version_id "
        f"AND command.tenant_id = {_VERSIONS}.tenant_id "
        "AND operation.action = 'publish_deployment' AND operation.status = 'applying'))"
    )
    op.execute(
        "GRANT SELECT (id, status) ON saas_tenants TO saas_platform_app, saas_model_projection"
    )
    op.execute(
        "CREATE POLICY rls_model_publication_staff_tenant_read ON saas_tenants "
        "FOR SELECT TO saas_platform_app USING (EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments assignment "
        f"WHERE assignment.principal_id = {_PRINCIPAL} "
        "AND assignment.role IN ('platform_operator', 'platform_security_auditor') "
        "AND assignment.status = 'active' AND (assignment.expires_at IS NULL "
        "OR assignment.expires_at > CURRENT_TIMESTAMP)))"
    )
    op.execute(
        "CREATE POLICY rls_model_publication_worker_tenant_read ON saas_tenants "
        "FOR SELECT TO saas_model_projection USING (EXISTS ("
        f"SELECT 1 FROM {_COMMANDS} command JOIN {_OPS} operation "
        "ON operation.id = command.operation_id WHERE command.tenant_id = saas_tenants.id "
        "AND operation.status IN ('requested', 'applying')))"
    )
    op.execute(
        f"GRANT SELECT ({_SESSION_COLUMNS}) ON saas_platform_auth_sessions "
        "TO saas_model_projection"
    )
    op.execute(
        "CREATE POLICY rls_model_publication_session_read ON saas_platform_auth_sessions "
        "FOR SELECT TO saas_model_projection USING (EXISTS ("
        f"SELECT 1 FROM {_COMMANDS} command JOIN {_OPS} operation "
        "ON operation.id = command.operation_id "
        "WHERE command.staff_session_id = saas_platform_auth_sessions.id "
        "AND operation.status IN ('requested', 'applying')))"
    )
    op.execute(
        "GRANT SELECT (security_version) ON saas_platform_staff_principals "
        "TO saas_model_projection"
    )
    op.execute(
        f"GRANT SELECT ({_BUDGET_COLUMNS}) ON saas_model_provider_budget_reservations "
        "TO saas_platform_app"
    )
    op.execute(
        "CREATE POLICY rls_model_publication_staff_budget_read "
        "ON saas_model_provider_budget_reservations FOR SELECT TO saas_platform_app "
        "USING (purpose = 'platform_test' AND EXISTS ("
        "SELECT 1 FROM saas_model_verification_receipts receipt "
        "WHERE receipt.budget_reservation_id = saas_model_provider_budget_reservations.id))"
    )
    envelope = (
        "tenant_id IS NULL AND aggregate_type = 'platform_model' "
        "AND event_type = 'platform.model_publication.requested' "
        "AND payload->>'event_type' = event_type "
        "AND payload::jsonb->'schema_version' = '1'::jsonb "
        "AND payload::jsonb - ARRAY['event_type','operation_id',"
        "'credential_version_id','schema_version']::text[] = '{}'::jsonb "
        f"AND EXISTS (SELECT 1 FROM {_OPS} operation JOIN {_COMMANDS} command "
        "ON command.operation_id = operation.id WHERE operation.id::text = aggregate_key "
        "AND operation.id::text = payload->>'operation_id' "
        "AND operation.credential_version_id::text = payload->>'credential_version_id' "
        "AND operation.action = 'publish_deployment' "
        "AND operation.request_hash = saas_control_plane_outbox.request_hash"
    )
    op.execute(
        "CREATE POLICY rls_outbox_model_publication_insert ON saas_control_plane_outbox "
        f"FOR INSERT TO saas_platform_app WITH CHECK ({envelope} "
        f"AND operation.actor_principal_id = {_PRINCIPAL} AND operation.status = 'requested'))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_model_publication_read ON saas_control_plane_outbox "
        f"FOR SELECT TO saas_model_projection USING ({envelope}))"
    )


def _guards() -> None:
    op.execute(f"""
CREATE FUNCTION public.saas_model_publication_version_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog SET lock_timeout = '500ms' AS $$
DECLARE actual_generation integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text || ':' || NEW.public_model_id || ':' || NEW.wire_api, 0));
    SELECT COALESCE(max(generation), 0) INTO actual_generation FROM public.{_VERSIONS}
        WHERE tenant_id = NEW.tenant_id AND public_model_id = NEW.public_model_id
        AND wire_api = NEW.wire_api;
    IF NEW.generation <> actual_generation + 1 OR NOT EXISTS (
        SELECT 1 FROM public.{_COMMANDS} command
        JOIN public.{_OPS} operation ON operation.id = command.operation_id
        JOIN public.saas_model_deployment_versions draft
            ON draft.id = operation.deployment_version_id
        JOIN public.{_OPS} verification ON verification.id = command.verification_operation_id
        JOIN public.saas_model_verification_commands test ON test.operation_id = verification.id
        JOIN public.saas_model_verification_receipts receipt
            ON receipt.operation_id = verification.id
        JOIN public.saas_model_provider_budget_reservations budget
            ON budget.id = receipt.budget_reservation_id
        JOIN public.saas_model_connections connection ON connection.id = draft.connection_id
        JOIN public.saas_model_credential_versions credential
            ON credential.id = draft.credential_version_id
        JOIN public.saas_tenants tenant ON tenant.id = command.tenant_id
        JOIN public.saas_platform_auth_sessions session ON session.id = command.staff_session_id
        JOIN public.saas_platform_staff_principals principal
            ON principal.id = operation.actor_principal_id
        WHERE command.operation_id = NEW.operation_id AND command.tenant_id = NEW.tenant_id
        AND command.expected_generation = actual_generation
        AND command.expires_at > clock_timestamp()
        AND tenant.status IN ('trial', 'active') AND operation.status = 'applying'
        AND operation.action = 'publish_deployment' AND principal.status = 'active'
        AND principal.security_version = command.staff_security_version
        AND session.principal_id = principal.id
        AND session.security_version = principal.security_version
        AND session.revoked_at IS NULL AND session.expires_at > clock_timestamp()
        AND session.authenticated_at > clock_timestamp() - interval '5 minutes'
        AND session.authenticated_at <= clock_timestamp()
        AND EXISTS (SELECT 1 FROM public.saas_platform_role_assignments assignment
            WHERE assignment.principal_id = principal.id AND assignment.role = 'platform_operator'
            AND assignment.status = 'active' AND (assignment.expires_at IS NULL
            OR assignment.expires_at > clock_timestamp()))
        AND draft.id = NEW.deployment_version_id AND draft.public_model_id = NEW.public_model_id
        AND draft.wire_api = NEW.wire_api AND draft.configuration_sha256 = NEW.configuration_sha256
        AND verification.status = 'verified' AND verification.action = 'verify_deployment'
        AND verification.deployment_version_id = draft.id AND receipt.outcome = 'passed'
        AND test.configuration_sha256 = draft.configuration_sha256
        AND test.price_sha256 = NEW.price_sha256
        AND operation.credential_version_id = credential.id
        AND verification.credential_version_id = credential.id
        AND connection.credential_generation = credential.generation
        AND budget.purpose = 'platform_test' AND budget.test_operation_id = verification.id
        AND budget.status = 'settled' AND budget.settled_microusd = receipt.actual_microusd
        AND budget.settled_tokens =
            (receipt.canonical_evidence::jsonb->'usage'->>'total_tokens')::bigint
        AND budget.outcome_evidence_sha256 = receipt.evidence_sha256
        AND encode(sha256(convert_to(NEW.canonical_snapshot, 'UTF8')), 'hex') = NEW.snapshot_sha256
        AND encode(sha256(convert_to(NEW.canonical_readiness, 'UTF8')), 'hex')
            = NEW.readiness_sha256
        AND NEW.canonical_snapshot::jsonb->>'tenant_id' = NEW.tenant_id::text
        AND NEW.canonical_snapshot::jsonb->>'deployment_id' = draft.id::text
        AND NEW.canonical_snapshot::jsonb->>'public_model_id' = NEW.public_model_id
        AND NEW.canonical_snapshot::jsonb->>'wire_api' = NEW.wire_api
        AND NEW.canonical_snapshot::jsonb->>'configuration_sha256' = NEW.configuration_sha256
        AND (NEW.canonical_snapshot::jsonb->>'generation')::integer = NEW.generation
        AND NEW.canonical_snapshot::jsonb->'provider_cost' = test.canonical_price::jsonb
        AND NEW.canonical_readiness::jsonb->>'scope' =
            'stored_credentials_and_visible_replica_routes_not_hidden_replica_memory'
        AND NEW.canonical_readiness::jsonb->>'contract' =
            'litellm-1.105.1-replica-routes-and-storage-v1'
        AND NEW.canonical_readiness::jsonb->>'deployment_id' = draft.id::text
        AND NEW.canonical_readiness::jsonb->>'credential_version_id' =
            operation.credential_version_id::text
        AND NEW.canonical_readiness::jsonb->>'configuration_sha256' = draft.configuration_sha256
        AND NEW.canonical_readiness::jsonb->>'inventory_sha256' = NEW.inventory_sha256
        AND jsonb_array_length(NEW.canonical_readiness::jsonb->'replicas') BETWEEN 2 AND 16
        AND (NEW.canonical_readiness::jsonb->>'started_at')::timestamptz >=
            clock_timestamp() - interval '30 seconds'
        AND (NEW.canonical_readiness::jsonb->>'completed_at')::timestamptz <= clock_timestamp()
        AND (NEW.canonical_readiness::jsonb->>'completed_at')::timestamptz >=
            (NEW.canonical_readiness::jsonb->>'started_at')::timestamptz
    ) THEN RAISE EXCEPTION 'model publication proof rejected' USING ERRCODE = '23514'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_model_publication_version_guard BEFORE INSERT ON public.{_VERSIONS}
FOR EACH ROW EXECUTE FUNCTION public.saas_model_publication_version_guard();
CREATE FUNCTION public.saas_model_publication_transition_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN
    IF NEW.action = 'publish_deployment' AND NEW.status = 'applied' AND NOT EXISTS (
        SELECT 1 FROM public.{_VERSIONS} version WHERE version.operation_id = NEW.id
    ) THEN RAISE EXCEPTION 'model publication receipt required' USING ERRCODE = '23514'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_model_publication_transition_guard BEFORE UPDATE ON public.{_OPS}
FOR EACH ROW EXECUTE FUNCTION public.saas_model_publication_transition_guard();
REVOKE ALL ON FUNCTION public.saas_model_publication_version_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.saas_model_publication_transition_guard() FROM PUBLIC;
""")


def upgrade() -> None:
    _tables()
    _operation_constraints(True)
    if op.get_bind().dialect.name == "postgresql":
        _authority()
        _guards()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"LOCK TABLE {_COMMANDS}, {_VERSIONS}, {_OPS} IN ACCESS EXCLUSIVE MODE")
        for table in (_COMMANDS, _VERSIONS):
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    if any(
        bind.scalar(sa.text(f"SELECT EXISTS (SELECT 1 FROM {table})"))
        for table in (_COMMANDS, _VERSIONS)
    ) or bind.scalar(
        sa.text(f"SELECT EXISTS (SELECT 1 FROM {_OPS} WHERE action='publish_deployment')")
    ):
        raise RuntimeError("cannot remove model publication schema with retained evidence")
    if bind.dialect.name == "postgresql":
        op.execute("ALTER POLICY rls_tenants_actor_select ON saas_tenants TO PUBLIC")
        op.execute(f"DROP TRIGGER trg_model_publication_transition_guard ON {_OPS}")
        op.execute("DROP FUNCTION public.saas_model_publication_transition_guard()")
        op.execute(f"DROP TRIGGER trg_model_publication_version_guard ON {_VERSIONS}")
        op.execute("DROP FUNCTION public.saas_model_publication_version_guard()")
        for table, policy in (
            ("saas_tenants", "rls_model_publication_staff_tenant_read"),
            ("saas_tenants", "rls_model_publication_worker_tenant_read"),
            ("saas_platform_auth_sessions", "rls_model_publication_session_read"),
            ("saas_model_provider_budget_reservations", "rls_model_publication_staff_budget_read"),
            ("saas_control_plane_outbox", "rls_outbox_model_publication_insert"),
            ("saas_control_plane_outbox", "rls_outbox_model_publication_read"),
        ):
            op.execute(f"DROP POLICY {policy} ON {table}")
        op.execute(
            "REVOKE SELECT (id, status) ON saas_tenants "
            "FROM saas_platform_app, saas_model_projection"
        )
        op.execute(
            f"REVOKE SELECT ({_SESSION_COLUMNS}) ON saas_platform_auth_sessions "
            "FROM saas_model_projection"
        )
        op.execute(
            "REVOKE SELECT (security_version) ON saas_platform_staff_principals "
            "FROM saas_model_projection"
        )
        op.execute(
            f"REVOKE SELECT ({_BUDGET_COLUMNS}) ON saas_model_provider_budget_reservations "
            "FROM saas_platform_app"
        )
    _operation_constraints(False)
    op.drop_table(_VERSIONS)
    op.drop_table(_COMMANDS)
