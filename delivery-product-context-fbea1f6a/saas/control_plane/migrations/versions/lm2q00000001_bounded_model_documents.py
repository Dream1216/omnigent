"""Keep canonical model metadata in byte-bounded, versioned binary storage.

Revision ID: lm2q00000001
Revises: lm2p00000001

Stop model admission and drain the old model consumers before applying this
schema and its matching application. Canonical bytes and hashes are preserved;
there is no inference, re-signing, truncation or silent repair. Rollback stops
the same consumers, restores TEXT and the old guards, then starts old readers.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2q00000001"
down_revision = "lm2p00000001"
branch_labels = None
depends_on = None

_PREFIX = b"OGMD\x01\x00\x00"
_COLUMNS = (
    ("saas_model_deployment_versions", "id", (("canonical_configuration", 16376),)),
    ("saas_model_verification_commands", "operation_id", (("canonical_price", 8192),)),
    ("saas_model_verification_receipts", "operation_id", (("canonical_evidence", 8192),)),
    (
        "saas_model_publication_versions",
        "id",
        (("canonical_snapshot", 16376), ("canonical_readiness", 16376)),
    ),
    ("saas_model_gateway_evidence", "id", (("canonical_evidence", 16376),)),
)
_BOUNDS = (
    (
        "ck_model_deployment_configuration",
        "length(canonical_configuration) BETWEEN 1 AND 16384",
        "length(canonical_configuration) BETWEEN 8 AND 16383",
    ),
    (
        "ck_model_verification_command_bounds",
        "requested_microusd > 0 AND requested_tokens BETWEEN 1 AND 1056 "
        "AND output_token_limit BETWEEN 1 AND 32 AND length(canonical_price) BETWEEN 1 AND 8192 "
        "AND length(pricing_revision) BETWEEN 1 AND 32",
        "requested_microusd > 0 AND requested_tokens BETWEEN 1 AND 1056 "
        "AND output_token_limit BETWEEN 1 AND 32 AND length(canonical_price) BETWEEN 8 AND 8199 "
        "AND length(pricing_revision) BETWEEN 1 AND 32",
    ),
    (
        "ck_model_verification_receipt_bounds",
        "request_attempts IN (0, 1) AND (actual_microusd IS NULL OR actual_microusd >= 0) "
        "AND length(canonical_evidence) BETWEEN 1 AND 8192",
        "request_attempts IN (0, 1) AND (actual_microusd IS NULL OR actual_microusd >= 0) "
        "AND length(canonical_evidence) BETWEEN 8 AND 8199",
    ),
    (
        "ck_model_publication_documents",
        "length(canonical_snapshot) BETWEEN 1 AND 16384 "
        "AND length(canonical_readiness) BETWEEN 1 AND 16384",
        "length(canonical_snapshot) BETWEEN 8 AND 16383 "
        "AND length(canonical_readiness) BETWEEN 8 AND 16383",
    ),
    (
        "ck_model_gateway_evidence_bound",
        "length(canonical_evidence) BETWEEN 1 AND 16384",
        "length(canonical_evidence) BETWEEN 8 AND 16383",
    ),
)
_FORMATS = (
    ("ck_model_deployment_document_format",),
    ("ck_model_verification_price_format",),
    ("ck_model_verification_evidence_format",),
    ("ck_model_publication_snapshot_format", "ck_model_publication_readiness_format"),
    ("ck_model_gateway_evidence_format",),
)


def _format(column: str, *, postgresql: bool) -> str:
    if postgresql:
        return f"substring({column} from 1 for 7)=decode('{_PREFIX.hex()}','hex')"
    return f"hex(substr({column},1,7))='{_PREFIX.hex().upper()}'"


def _sqlite_rewrite(table_name: str, pk: str, columns, *, binary: bool) -> None:
    table = sa.table(table_name, sa.column(pk), *(sa.column(name) for name, _limit in columns))
    cursor = None
    while True:
        query = sa.select(table).order_by(table.c[pk]).limit(256)
        if cursor is not None:
            query = query.where(table.c[pk] > cursor)
        rows = op.get_bind().execute(query).all()
        if not rows:
            return
        for row in rows:
            values = {}
            for (name, limit), raw in zip(columns, row[1:], strict=True):
                if not isinstance(raw, bytes):
                    raise RuntimeError("model document migration refused")
                if binary:
                    if not 0 < len(raw) <= limit:
                        raise RuntimeError("model document exceeds byte cap")
                    payload = raw
                else:
                    if not 7 < len(raw) <= limit + 7 or not raw.startswith(_PREFIX):
                        raise RuntimeError("model document cannot be downgraded")
                    payload = raw[7:]
                try:
                    text = payload.decode("utf-8")
                except UnicodeError:
                    raise RuntimeError("model document migration refused") from None
                values[name] = _PREFIX + payload if binary else text
            updated = op.get_bind().execute(
                table.update().where(table.c[pk] == row[0]).values(**values)
            )
            if updated.rowcount != 1:
                raise RuntimeError("model document migration refused")
            cursor = row[0]


def _relationships(*, remove: bool) -> None:
    postgresql = op.get_bind().dialect.name == "postgresql"
    order = _RELATION_ORDER if remove else reversed(_RELATION_ORDER)
    convention = {
        "fk": "fk_model_migration_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
    }
    for table in order:
        definitions = [row for row in _RELATIONS if row[0] == table]
        if postgresql:
            for _table, name, _sqlite_name, columns, target, references in definitions:
                if remove:
                    op.drop_constraint(name, table, type_="foreignkey")
                else:
                    op.create_foreign_key(
                        name, table, target, list(columns), list(references), ondelete="RESTRICT"
                    )
        elif remove:
            with op.batch_alter_table(table, naming_convention=convention) as batch:
                for _table, _name, sqlite_name, columns, target, _references in definitions:
                    name = sqlite_name or f"fk_model_migration_{table}_{columns[0]}_{target}"
                    batch.drop_constraint(name, type_="foreignkey")
        else:
            constraints = []
            for _table, _name, sqlite_name, columns, target, references in definitions:
                # Self references follow the replacement table, never the table being dropped.
                target = ("_alembic_tmp_" + table)[:50] if target == table else target
                referent = sa.Table(
                    target, sa.MetaData(), *(sa.Column(column, sa.Uuid()) for column in references)
                )
                constraints.append(
                    sa.ForeignKeyConstraint(
                        columns,
                        [referent.c[column] for column in references],
                        name=sqlite_name,
                        ondelete="RESTRICT",
                    )
                )
            with op.batch_alter_table(table, recreate="always", table_args=tuple(constraints)):
                pass


def _budget_relationship_guard(*, binary: bool) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    bound = (
        "EXISTS (SELECT 1 FROM saas_model_verification_budget_bindings binding "
        "WHERE binding.operation_id=saas_model_provider_budget_reservations.test_operation_id "
        "AND binding.budget_reservation_id=saas_model_provider_budget_reservations.id)"
    )
    pending = (
        "EXISTS (SELECT 1 FROM saas_model_verification_commands command "
        "JOIN saas_model_projection_operations operation ON operation.id=command.operation_id "
        "WHERE command.operation_id=saas_model_provider_budget_reservations.test_operation_id "
        "AND command.configuration_sha256="
        "saas_model_provider_budget_reservations.test_configuration_sha256 "
        "AND command.funding_policy_version="
        "saas_model_provider_budget_reservations.test_policy_version "
        "AND operation.action='verify_deployment' AND operation.status='applying')"
    )
    readable = f"({bound} OR {pending})" if binary else bound
    op.execute(
        "ALTER POLICY rls_model_verification_budget_read "
        "ON saas_model_provider_budget_reservations USING (purpose='platform_test' AND "
        + readable
        + ")"
    )
    if binary:
        scope = (
            "EXISTS (SELECT 1 FROM saas_model_verification_commands command "
            "JOIN saas_model_projection_operations operation ON operation.id=command.operation_id "
            "JOIN saas_model_provider_budget_reservations budget "
            "ON budget.id=saas_model_verification_budget_bindings.budget_reservation_id "
            "WHERE command.operation_id=saas_model_verification_budget_bindings.operation_id "
            "AND command.configuration_sha256="
            "saas_model_verification_budget_bindings.configuration_sha256 "
            "AND command.funding_policy_version="
            "saas_model_verification_budget_bindings.funding_policy_version "
            "AND budget.purpose='platform_test' AND budget.test_operation_id=command.operation_id "
            "AND budget.test_configuration_sha256=command.configuration_sha256 "
            "AND budget.test_policy_version=command.funding_policy_version "
            "AND operation.action='verify_deployment' AND operation.status='applying')"
        )
    else:
        scope = (
            "EXISTS (SELECT 1 FROM saas_model_projection_operations operation "
            "WHERE operation.id=saas_model_verification_budget_bindings.operation_id "
            "AND operation.action='verify_deployment' AND operation.status='applying')"
        )
    op.execute(
        "ALTER POLICY rls_model_verification_insert ON "
        "saas_model_verification_budget_bindings WITH CHECK (" + scope + ")"
    )


def _convert(*, binary: bool) -> None:
    bind = op.get_bind()
    postgresql = bind.dialect.name == "postgresql"
    if postgresql:
        names = ", ".join(table for table, _pk, _columns in _COLUMNS)
        op.execute(f"LOCK TABLE {names} IN ACCESS EXCLUSIVE MODE")
        op.execute(
            "DROP TRIGGER trg_model_gateway_evidence_v1_insert ON saas_model_gateway_evidence"
        )
    elif bind.dialect.name == "sqlite":
        if getattr(bind.connection.driver_connection, "in_transaction", True) is False:
            bind.exec_driver_sql("BEGIN")
    else:
        raise RuntimeError("model document migration requires PostgreSQL or SQLite")
    if binary:
        _relationships(remove=True)
    for (table, pk, columns), (bound, old, new), formats in zip(
        _COLUMNS, _BOUNDS, _FORMATS, strict=True
    ):
        if postgresql:
            if not binary:
                for (column, limit), name in zip(columns, formats, strict=True):
                    validation = name + "_rollback"
                    op.create_check_constraint(
                        validation,
                        table,
                        f"length({column}) BETWEEN 8 AND {limit + 7} "
                        f"AND {_format(column, postgresql=True)}",
                    )
                    op.drop_constraint(validation, table, type_="check")
                    op.drop_constraint(name, table, type_="check")
            op.drop_constraint(bound, table, type_="check")
            for column, limit in columns:
                op.alter_column(
                    table,
                    column,
                    existing_nullable=False,
                    existing_type=sa.Text() if binary else sa.LargeBinary(limit + 7),
                    type_=sa.LargeBinary(limit + 7) if binary else sa.Text(),
                    postgresql_using=(
                        f"decode('{_PREFIX.hex()}','hex') || convert_to({column},'UTF8')"
                        if binary
                        else f"convert_from(substring({column} from 8),'UTF8')"
                    ),
                )
            op.create_check_constraint(bound, table, new if binary else old)
            if binary:
                for (column, _limit), name in zip(columns, formats, strict=True):
                    op.create_check_constraint(name, table, _format(column, postgresql=True))
        else:
            with op.batch_alter_table(table) as batch:
                batch.drop_constraint(bound, type_="check")
                if not binary:
                    for name in formats:
                        batch.drop_constraint(name, type_="check")
                if binary:
                    for column, limit in columns:
                        batch.alter_column(
                            column,
                            existing_type=sa.Text(),
                            type_=sa.LargeBinary(limit + 7),
                            existing_nullable=False,
                        )
            _sqlite_rewrite(table, pk, columns, binary=binary)
            with op.batch_alter_table(table) as batch:
                if not binary:
                    for column, limit in columns:
                        batch.alter_column(
                            column,
                            existing_type=sa.LargeBinary(limit + 7),
                            type_=sa.Text(),
                            existing_nullable=False,
                        )
                batch.create_check_constraint(bound, new if binary else old)
                if binary:
                    for (column, _limit), name in zip(columns, formats, strict=True):
                        batch.create_check_constraint(name, _format(column, postgresql=False))
    if not binary:
        _relationships(remove=False)
    if postgresql:
        for sql in _NEW_FUNCTIONS if binary else _OLD_FUNCTIONS:
            op.execute(sql)
        _budget_relationship_guard(binary=binary)
        document = (
            "convert_from(substring(NEW.canonical_evidence from 8),'UTF8')"
            if binary
            else "NEW.canonical_evidence"
        )
        op.execute(
            "CREATE TRIGGER trg_model_gateway_evidence_v1_insert BEFORE INSERT ON "
            "saas_model_gateway_evidence FOR EACH ROW WHEN "
            f"(COALESCE({document}::jsonb->>'contract','')<>'platform-model-gateway-evidence-v2') "
            "EXECUTE FUNCTION public.saas_model_gateway_evidence_guard()"
        )


def upgrade() -> None:
    _convert(binary=True)


def downgrade() -> None:
    _convert(binary=False)


_RELATION_ORDER = (
    "saas_model_gateway_evidence",
    "saas_model_projection_transitions",
    "saas_model_publication_revocations",
    "saas_model_run_tokens",
    "saas_model_publication_disablements",
    "saas_model_publication_versions",
    "saas_model_publication_commands",
    "saas_model_verification_receipts",
    "saas_model_verification_budget_bindings",
    "saas_model_provider_budget_reservations",
    "saas_model_verification_commands",
    "saas_model_projection_operations",
    "saas_model_test_funding_policies",
    "saas_model_deployment_versions",
    "saas_model_credential_versions",
    "saas_model_connections",
)
_RELATIONS = (
    (
        "saas_model_connections",
        "saas_model_connections_updated_by_principal_id_fkey",
        None,
        ("updated_by_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_credential_versions",
        "saas_model_credential_versions_connection_id_fkey",
        None,
        ("connection_id",),
        "saas_model_connections",
        ("id",),
    ),
    (
        "saas_model_credential_versions",
        "saas_model_credential_versions_created_by_principal_id_fkey",
        None,
        ("created_by_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_deployment_versions",
        "saas_model_deployment_version_connection_id_credential_ver_fkey",
        None,
        ("connection_id", "credential_version_id"),
        "saas_model_credential_versions",
        ("connection_id", "id"),
    ),
    (
        "saas_model_deployment_versions",
        "saas_model_deployment_versions_created_by_principal_id_fkey",
        None,
        ("created_by_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_gateway_evidence",
        "fk_model_gateway_evidence_budget",
        "fk_model_gateway_evidence_budget",
        ("tenant_id", "reservation_id"),
        "saas_model_provider_budget_reservations",
        ("tenant_id", "id"),
    ),
    (
        "saas_model_projection_operations",
        "fk_model_projection_deployment_scope",
        "fk_model_projection_deployment_scope",
        ("connection_id", "credential_version_id", "deployment_version_id"),
        "saas_model_deployment_versions",
        ("connection_id", "credential_version_id", "id"),
    ),
    (
        "saas_model_projection_operations",
        "saas_model_projection_operati_connection_id_credential_ver_fkey",
        None,
        ("connection_id", "credential_version_id"),
        "saas_model_credential_versions",
        ("connection_id", "id"),
    ),
    (
        "saas_model_projection_operations",
        "saas_model_projection_operations_actor_principal_id_fkey",
        None,
        ("actor_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_projection_transitions",
        "saas_model_projection_transitions_actor_principal_id_fkey",
        None,
        ("actor_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_projection_transitions",
        "saas_model_projection_transitions_event_id_fkey",
        None,
        ("event_id",),
        "saas_control_plane_outbox",
        ("id",),
    ),
    (
        "saas_model_projection_transitions",
        "saas_model_projection_transitions_operation_id_fkey",
        None,
        ("operation_id",),
        "saas_model_projection_operations",
        ("id",),
    ),
    (
        "saas_model_provider_budget_reservations",
        "fk_model_budget_test_actor",
        "fk_model_budget_test_actor",
        ("test_actor_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_provider_budget_reservations",
        "fk_model_budget_test_policy",
        "fk_model_budget_test_policy",
        ("provider_id", "test_policy_version"),
        "saas_model_test_funding_policies",
        ("provider_id", "version"),
    ),
    (
        "saas_model_publication_commands",
        "saas_model_publication_commands_operation_id_fkey",
        None,
        ("operation_id",),
        "saas_model_projection_operations",
        ("id",),
    ),
    (
        "saas_model_publication_commands",
        "saas_model_publication_commands_staff_session_id_fkey",
        None,
        ("staff_session_id",),
        "saas_platform_auth_sessions",
        ("id",),
    ),
    (
        "saas_model_publication_commands",
        "saas_model_publication_commands_tenant_id_fkey",
        None,
        ("tenant_id",),
        "saas_tenants",
        ("id",),
    ),
    (
        "saas_model_publication_commands",
        "saas_model_publication_commands_verification_operation_id_fkey",
        None,
        ("verification_operation_id",),
        "saas_model_verification_receipts",
        ("operation_id",),
    ),
    (
        "saas_model_publication_disablements",
        "fk_model_disablement_publication",
        "fk_model_disablement_publication",
        ("tenant_id", "public_model_id", "wire_api", "through_generation"),
        "saas_model_publication_versions",
        ("tenant_id", "public_model_id", "wire_api", "generation"),
    ),
    (
        "saas_model_publication_disablements",
        "saas_model_publication_disablements_principal_id_fkey",
        None,
        ("principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_publication_disablements",
        "saas_model_publication_disablements_staff_session_id_fkey",
        None,
        ("staff_session_id",),
        "saas_platform_auth_sessions",
        ("id",),
    ),
    (
        "saas_model_publication_revocations",
        "saas_model_publication_revocations_disablement_id_fkey",
        None,
        ("disablement_id",),
        "saas_model_publication_disablements",
        ("id",),
    ),
    (
        "saas_model_publication_revocations",
        "saas_model_publication_revocations_principal_id_fkey",
        None,
        ("principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_publication_revocations",
        "saas_model_publication_revocations_staff_session_id_fkey",
        None,
        ("staff_session_id",),
        "saas_platform_auth_sessions",
        ("id",),
    ),
    (
        "saas_model_publication_versions",
        "fk_model_publication_version_scope",
        "fk_model_publication_version_scope",
        ("operation_id", "tenant_id"),
        "saas_model_publication_commands",
        ("operation_id", "tenant_id"),
    ),
    (
        "saas_model_publication_versions",
        "saas_model_publication_versions_deployment_version_id_fkey",
        None,
        ("deployment_version_id",),
        "saas_model_deployment_versions",
        ("id",),
    ),
    (
        "saas_model_run_tokens",
        "fk_model_run_token_scope",
        "fk_model_run_token_scope",
        ("run_id", "tenant_id", "space_id", "project_id"),
        "saas_runs",
        ("id", "tenant_id", "space_id", "project_id"),
    ),
    (
        "saas_model_run_tokens",
        "saas_model_run_tokens_actor_id_fkey",
        None,
        ("actor_id",),
        "saas_global_users",
        ("id",),
    ),
    (
        "saas_model_run_tokens",
        "saas_model_run_tokens_capability_id_fkey",
        None,
        ("capability_id",),
        "saas_capability_tokens",
        ("id",),
    ),
    (
        "saas_model_run_tokens",
        "saas_model_run_tokens_parent_id_fkey",
        None,
        ("parent_id",),
        "saas_model_run_tokens",
        ("id",),
    ),
    (
        "saas_model_test_funding_policies",
        "saas_model_test_funding_policies_actor_principal_id_fkey",
        None,
        ("actor_principal_id",),
        "saas_platform_staff_principals",
        ("id",),
    ),
    (
        "saas_model_verification_budget_bindings",
        "fk_model_verification_binding_budget",
        "fk_model_verification_binding_budget",
        (
            "operation_id",
            "budget_reservation_id",
            "configuration_sha256",
            "funding_policy_version",
        ),
        "saas_model_provider_budget_reservations",
        ("test_operation_id", "id", "test_configuration_sha256", "test_policy_version"),
    ),
    (
        "saas_model_verification_budget_bindings",
        "fk_model_verification_binding_command",
        "fk_model_verification_binding_command",
        ("operation_id", "configuration_sha256", "funding_policy_version"),
        "saas_model_verification_commands",
        ("operation_id", "configuration_sha256", "funding_policy_version"),
    ),
    (
        "saas_model_verification_commands",
        "fk_model_verification_funding",
        "fk_model_verification_funding",
        ("provider_id", "funding_policy_version"),
        "saas_model_test_funding_policies",
        ("provider_id", "version"),
    ),
    (
        "saas_model_verification_commands",
        "saas_model_verification_commands_operation_id_fkey",
        None,
        ("operation_id",),
        "saas_model_projection_operations",
        ("id",),
    ),
    (
        "saas_model_verification_receipts",
        "fk_model_verification_receipt_budget",
        "fk_model_verification_receipt_budget",
        ("operation_id", "budget_reservation_id"),
        "saas_model_verification_budget_bindings",
        ("operation_id", "budget_reservation_id"),
    ),
    (
        "saas_model_verification_receipts",
        "saas_model_verification_receipts_operation_id_fkey",
        None,
        ("operation_id",),
        "saas_model_verification_commands",
        ("operation_id",),
    ),
)


# Frozen predecessors preserve exact downgrade authority; new reads select keys first.
_OLD_FUNCTIONS = (
    """CREATE OR REPLACE FUNCTION public.saas_model_projection_transition_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ BEGIN IF NEW.version <> OLD.version + 1 OR NOT ((OLD.status = 'requested' AND NEW.status IN ('applying', 'failed')) OR (OLD.status = 'applying' AND NEW.status IN ('applied', 'verified', 'failed', 'uncertain'))) OR (NEW.status IN ('applying', 'applied', 'verified') AND NEW.error_code IS NOT NULL) OR (NEW.status IN ('failed', 'uncertain') AND (NEW.error_code IS NULL OR length(NEW.error_code) = 0)) THEN RAISE EXCEPTION 'model projection transition rejected' USING ERRCODE = '23514'; END IF; IF NEW.status = 'verified' AND (NEW.action <> 'verify_deployment' OR NOT EXISTS (SELECT 1 FROM public.saas_model_verification_receipts receipt JOIN public.saas_model_provider_budget_reservations budget ON budget.id = receipt.budget_reservation_id WHERE receipt.operation_id = NEW.id AND receipt.outcome = 'passed' AND budget.purpose = 'platform_test' AND budget.test_operation_id = NEW.id AND budget.status = 'settled' AND budget.settled_microusd = receipt.actual_microusd AND budget.settled_tokens = (receipt.canonical_evidence::jsonb->'usage'->>'total_tokens')::bigint AND budget.outcome_evidence_sha256 = receipt.evidence_sha256)) THEN RAISE EXCEPTION 'model verification settlement rejected' USING ERRCODE = '23514'; END IF; IF NEW.action = 'verify_deployment' AND NEW.status = 'applied' THEN RAISE EXCEPTION 'model verification transition rejected' USING ERRCODE = '23514'; END IF; RETURN NEW; END $$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_model_publication_version_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog SET lock_timeout = '500ms' AS $$
DECLARE actual_generation integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text || ':' || NEW.public_model_id || ':' || NEW.wire_api, 0));
    SELECT COALESCE(max(generation), 0) INTO actual_generation FROM public.saas_model_publication_versions
        WHERE tenant_id = NEW.tenant_id AND public_model_id = NEW.public_model_id
        AND wire_api = NEW.wire_api;
    IF NEW.generation <> actual_generation + 1 OR NOT EXISTS (
        SELECT 1 FROM public.saas_model_publication_commands command
        JOIN public.saas_model_projection_operations operation ON operation.id = command.operation_id
        JOIN public.saas_model_deployment_versions draft
            ON draft.id = operation.deployment_version_id
        JOIN public.saas_model_projection_operations verification ON verification.id = command.verification_operation_id
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
END $$;""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """
    CREATE OR REPLACE FUNCTION public.saas_model_gateway_evidence_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
    DECLARE
        budget public.saas_model_provider_budget_reservations%ROWTYPE;
        original public.saas_model_gateway_evidence%ROWTYPE;
        value jsonb;
        usage jsonb;
        request jsonb;
        prior_version integer;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'gateway evidence is immutable' USING ERRCODE = '23514';
        END IF;
        SELECT * INTO STRICT budget FROM public.saas_model_provider_budget_reservations WHERE id = NEW.reservation_id;
        value := NEW.canonical_evidence::jsonb;
        IF jsonb_typeof(value) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(value)) <> 16
           OR value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v1'
           OR value->>'phase' IS DISTINCT FROM NEW.phase
           OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
           OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
           OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
           OR value->>'session_id' IS DISTINCT FROM budget.run_id::text
           OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
           OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
           OR value->>'budget_version' IS DISTINCT FROM budget.version::text
           OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
           OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
           OR NEW.budget_version <> budget.version OR budget.purpose <> 'tenant_run'
           OR value->>'status' IS DISTINCT FROM budget.status
           OR value->'admission' IS DISTINCT FROM jsonb_build_object(
               'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
               'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
           OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
           OR encode(sha256(convert_to(NEW.canonical_evidence, 'UTF8')), 'hex')
              <> NEW.evidence_sha256
        THEN RAISE EXCEPTION 'gateway evidence binding rejected' USING ERRCODE = '23514'; END IF;
        IF NEW.phase = 'request' THEN
            request := value->'request';
            IF budget.version <> 1 OR budget.status NOT IN ('reserved', 'rejected')
               OR NEW.created_at IS DISTINCT FROM budget.created_at
               OR jsonb_typeof(request) <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request)) <> 5
               OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
                                       'model_price','output_token_limit']
               OR (request->>'public_model_id') !~ '^[!-~]{1,128}$'
               OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
               OR request->>'wire_api' NOT IN ('openai_chat_completions','openai_responses')
               OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
               OR (request->>'pricing_revision') !~ '^[!-~]{1,32}$'
               OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
               OR (request->>'output_token_limit') !~ '^[1-9][0-9]{0,5}$'
               OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
               OR (request->>'output_token_limit')::integer > 65536
               OR jsonb_typeof(request->'model_price') <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request->'model_price')) <> 7
               OR NOT (request->'model_price') ?& ARRAY['model_sha256',
                   'peak_input_cache_hit_microusd_per_million_tokens',
                   'peak_input_cache_miss_microusd_per_million_tokens',
                   'peak_output_microusd_per_million_tokens',
                   'off_peak_input_cache_hit_microusd_per_million_tokens',
                   'off_peak_input_cache_miss_microusd_per_million_tokens',
                   'off_peak_output_microusd_per_million_tokens']
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND (jsonb_typeof(pair.value) <> 'number'
                     OR pair.value::text !~ '^[1-9][0-9]{0,12}$'))
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND pair.value::text::numeric > 1000000000000)
               OR request->'model_price'->>'model_sha256' IS DISTINCT FROM
                  encode(sha256(convert_to(request->>'public_model_id','UTF8')), 'hex')
               OR value->'usage' IS DISTINCT FROM 'null'::jsonb
               OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
               OR value->'reason' IS DISTINCT FROM 'null'::jsonb
            THEN RAISE EXCEPTION 'gateway request evidence rejected' USING ERRCODE = '23514';
            END IF;
        ELSE
            SELECT * INTO STRICT original FROM public.saas_model_gateway_evidence
            WHERE reservation_id = budget.id AND phase = 'request';
            IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
               OR value->'admission' IS DISTINCT FROM
                  original.canonical_evidence::jsonb->'admission'
               OR value->'request' IS DISTINCT FROM 'null'::jsonb
               OR NEW.phase <> budget.status
            THEN RAISE EXCEPTION 'gateway transition evidence rejected' USING ERRCODE = '23514';
            END IF;
            SELECT max(budget_version) INTO prior_version FROM public.saas_model_gateway_evidence
            WHERE reservation_id = budget.id;
            IF NEW.budget_version <> prior_version + 1
               OR (NEW.phase = 'in_flight' AND prior_version <> 1)
               OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
                   SELECT 1 FROM public.saas_model_gateway_evidence WHERE reservation_id = budget.id
                   AND phase = 'in_flight'))
            THEN RAISE EXCEPTION 'gateway evidence sequence rejected' USING ERRCODE = '23514';
            END IF;
            usage := value->'usage';
            IF usage IS DISTINCT FROM 'null'::jsonb THEN
                IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage) <> 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(usage)) <> 5
                   OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
                       'input_cache_miss_tokens','output_tokens','total_tokens']
                   OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair
                              WHERE jsonb_typeof(pair.value) <> 'number'
                              OR pair.value::text !~ '^[0-9]{1,19}$')
                   OR (usage->>'total_tokens')::numeric <> budget.settled_tokens
                   OR (usage->>'input_tokens')::numeric + (usage->>'output_tokens')::numeric
                      <> budget.settled_tokens
                   OR (usage->>'input_cache_hit_tokens')::numeric
                      + (usage->>'input_cache_miss_tokens')::numeric
                      <> (usage->>'input_tokens')::numeric
                   OR (usage->>'output_tokens')::numeric >
                      (original.canonical_evidence::jsonb->'request'->>'output_token_limit')::integer
                   OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
                   OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
                   OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
                   OR value->'reason' IS DISTINCT FROM 'null'::jsonb
                   OR NOT EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence
                       WHERE reservation_id = budget.id AND phase = 'in_flight')
                THEN RAISE EXCEPTION 'gateway usage evidence rejected' USING ERRCODE = '23514';
                END IF;
            ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR (budget.status = 'in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
               OR (budget.status = 'uncertain' AND COALESCE(value->>'reason','') NOT IN
                   ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
               OR (budget.status IN ('released','expired')
                   AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version <> 1))
               OR budget.status NOT IN ('in_flight','uncertain','released','expired')
            THEN RAISE EXCEPTION 'gateway pending evidence rejected' USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_audit_model_gateway_evidence_v1(source_event_id uuid,expected_payload jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    source public.saas_control_plane_outbox%ROWTYPE;
    evidence public.saas_model_gateway_evidence%ROWTYPE;
    head public.saas_platform_audit_chain_heads%ROWTYPE;
    prior public.saas_platform_audit_events%ROWTYPE;
    audit_payload jsonb;
    payload_digest text;
    occurred text;
    event_material jsonb;
    event_digest text;
    system_actor constant uuid := '21bb9380-44ca-51a9-8f87-c914945e332a';
BEGIN
    SELECT * INTO source FROM public.saas_control_plane_outbox WHERE id = source_event_id;
    IF NOT FOUND OR source.aggregate_type <> 'model_gateway_budget'
       OR source.event_type <> 'model_gateway.evidence_retained'
       OR source.payload::jsonb IS DISTINCT FROM expected_payload
       OR jsonb_typeof(expected_payload) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(expected_payload)) <> 5
       OR expected_payload->>'event_type' IS DISTINCT FROM source.event_type
       OR expected_payload->>'tenant_id' IS DISTINCT FROM source.tenant_id::text
       OR expected_payload->>'reservation_id' IS DISTINCT FROM source.aggregate_key
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO evidence FROM public.saas_model_gateway_evidence
    WHERE id::text = expected_payload->>'evidence_id';
    IF NOT FOUND OR evidence.tenant_id IS DISTINCT FROM source.tenant_id
       OR evidence.reservation_id::text IS DISTINCT FROM source.aggregate_key
       OR evidence.evidence_sha256 IS DISTINCT FROM source.request_hash
       OR evidence.evidence_sha256 IS DISTINCT FROM expected_payload->>'evidence_sha256'
       OR evidence.evidence_sha256 IS DISTINCT FROM
          encode(sha256(convert_to(evidence.canonical_evidence,'UTF8')),'hex')
       OR source.idempotency_key IS DISTINCT FROM
          'model-gateway-evidence:' || replace(evidence.id::text,'-','')
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT head FROM public.saas_platform_audit_chain_heads
    WHERE partition_key = 'platform' FOR UPDATE;
    IF (head.last_sequence = 0 AND (head.last_event_hash <> repeat('0',64)
        OR EXISTS (SELECT 1 FROM public.saas_platform_audit_events)))
       OR (head.last_sequence > 0 AND NOT EXISTS (
           SELECT 1 FROM public.saas_platform_audit_events
           WHERE sequence_no = head.last_sequence AND event_hash = head.last_event_hash))
    THEN RAISE EXCEPTION 'model_gateway_audit_chain_unavailable' USING ERRCODE = '23514';
    END IF;
    audit_payload := expected_payload || jsonb_build_object(
        'source_event_id',source.id::text,'phase',evidence.phase,
        'budget_version',evidence.budget_version);
    payload_digest := public.saas_canonical_json_sha256_v1(audit_payload);
    occurred := to_char(evidence.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')
        || CASE WHEN to_char(evidence.created_at AT TIME ZONE 'UTC','US') = '000000'
                THEN '' ELSE '.' || to_char(evidence.created_at AT TIME ZONE 'UTC','US') END
        || '+00:00';
    SELECT * INTO prior FROM public.saas_platform_audit_events WHERE id = source.id;
    IF FOUND THEN
        event_material := jsonb_build_object(
            'sequence_no',prior.sequence_no,'tenant_id',source.tenant_id::text,
            'actor_type','system','actor_id',system_actor::text,
            'event_type',source.event_type,'target_type',source.aggregate_type,
            'target_id',evidence.reservation_id::text,'operation_id',NULL,
            'payload_hash',payload_digest,'previous_hash',prior.previous_hash,
            'occurred_at',occurred);
        IF prior.sequence_no > head.last_sequence
           OR prior.tenant_id IS DISTINCT FROM source.tenant_id
           OR prior.actor_type <> 'system' OR prior.actor_id <> system_actor
           OR prior.event_type <> source.event_type OR prior.target_type <> source.aggregate_type
           OR prior.target_id <> evidence.reservation_id OR prior.operation_id IS NOT NULL
           OR prior.payload::jsonb IS DISTINCT FROM audit_payload
           OR prior.payload_hash <> payload_digest OR prior.occurred_at <> evidence.created_at
           OR prior.event_hash <> public.saas_canonical_json_sha256_v1(event_material)
        THEN RAISE EXCEPTION 'model_gateway_audit_replay_conflict' USING ERRCODE = '23514';
        END IF;
        RETURN false;
    END IF;
    event_material := jsonb_build_object(
        'sequence_no',head.last_sequence + 1,'tenant_id',source.tenant_id::text,
        'actor_type','system','actor_id',system_actor::text,
        'event_type',source.event_type,'target_type',source.aggregate_type,
        'target_id',evidence.reservation_id::text,'operation_id',NULL,
        'payload_hash',payload_digest,'previous_hash',head.last_event_hash,
        'occurred_at',occurred);
    event_digest := public.saas_canonical_json_sha256_v1(event_material);
    INSERT INTO public.saas_platform_audit_events(
        id,sequence_no,tenant_id,actor_type,actor_id,event_type,target_type,target_id,
        operation_id,payload,payload_hash,previous_hash,event_hash,occurred_at,created_at)
    VALUES(source.id,head.last_sequence + 1,source.tenant_id,'system',system_actor,
        source.event_type,source.aggregate_type,evidence.reservation_id,NULL,audit_payload,
        payload_digest,head.last_event_hash,event_digest,evidence.created_at,statement_timestamp());
    UPDATE public.saas_platform_audit_chain_heads
    SET last_sequence = head.last_sequence + 1,last_event_hash = event_digest,
        updated_at = statement_timestamp() WHERE partition_key = 'platform';
    RETURN true;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_run_binding_v2(requested_tenant uuid,requested_run uuid,request jsonb,requested_at timestamptz) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $function$
SELECT EXISTS (
    SELECT 1 FROM public.saas_model_run_tokens t
    JOIN public.saas_runs r ON r.id=t.run_id
    JOIN public.saas_capability_tokens c ON c.id=t.capability_id
    JOIN public.saas_run_dispatches d ON d.run_id=r.id
    JOIN public.saas_runner_registrations runner ON runner.id=c.runner_id
    JOIN public.saas_model_publication_versions p ON p.tenant_id=r.tenant_id
       AND p.public_model_id=request->>'public_model_id' AND p.wire_api=request->>'wire_api'
       AND p.generation::text=request->'run_binding'->>'publication_generation'
    WHERE r.id=requested_run AND r.tenant_id=requested_tenant
      AND t.id::text=request->'run_binding'->>'model_token_id'
      AND (t.tenant_id,t.space_id,t.project_id,t.actor_id,t.fence_token)
          =(r.tenant_id,r.space_id,r.project_id,r.created_by,r.fence_token)
      AND t.issued_at<=requested_at AND t.expires_at>statement_timestamp()
      AND r.id::text=request->'run_binding'->>'run_id'
      AND r.session_id::text=request->'run_binding'->>'session_id'
      AND r.space_id::text=request->'run_binding'->>'space_id'
      AND r.project_id::text=request->'run_binding'->>'project_id'
      AND r.created_by::text=request->'run_binding'->>'actor_id'
      AND r.fence_token::text=request->'run_binding'->>'fence_token'
      AND r.customer_pricing_snapshot_id::text=request->'run_binding'->>'customer_pricing_snapshot_id'
      AND r.customer_pricing_frozen AND r.created_by_service_account_id IS NULL
      AND r.queue_class='managed_interactive' AND r.status='running'
      AND r.lease_expires_at>statement_timestamp() AND r.lease_owner=c.runner_id::text
      AND c.id::text=request->'run_binding'->>'capability_id'
      AND (c.run_id,c.tenant_id,c.space_id,c.project_id,c.fence_token)
          =(r.id,r.tenant_id,r.space_id,r.project_id,r.fence_token)
      AND c.revoked_at IS NULL AND c.expires_at>statement_timestamp()
      AND c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb
      AND jsonb_array_length(c.allowed_actions::jsonb)=2
      AND d.status='leased' AND d.selected_runner_id=c.runner_id
      AND d.dispatch_generation=c.dispatch_generation
      AND runner.connection_generation=c.runner_connection_generation
      AND runner.status IN ('online','draining')
      AND p.snapshot_sha256=request->'run_binding'->>'publication_snapshot_sha256'
      AND encode(sha256(convert_to(p.canonical_snapshot,'UTF8')),'hex')=p.snapshot_sha256
      AND r.input::jsonb->'execution'->'model_publication'=jsonb_build_object(
          'schema_version',1,'public_model_id',p.public_model_id,'wire_api',p.wire_api,
          'generation',p.generation,'snapshot_sha256',p.snapshot_sha256)
      AND p.canonical_snapshot::jsonb->'provider_cost'->'price'=request->'model_price'
      AND p.canonical_snapshot::jsonb->'provider_cost'->>'pricing_revision'=request->>'pricing_revision'
      AND (request->>'output_token_limit')::integer BETWEEN 1
          AND (p.canonical_snapshot::jsonb->>'max_output_tokens')::integer
      AND requested_at<=statement_timestamp()+interval '5 seconds'
      AND requested_at>=statement_timestamp()-interval '5 minutes'
)
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_run_evidence_guard_v2() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    value jsonb;
    request jsonb;
    binding jsonb;
    usage jsonb;
    prior_version integer;
BEGIN
    SELECT * INTO STRICT budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NEW.reservation_id;
    value := NEW.canonical_evidence::jsonb;
    IF NEW.phase<>'request' THEN
        SELECT * INTO STRICT original FROM public.saas_model_gateway_evidence
        WHERE reservation_id=budget.id AND phase='request';
        IF value->>'contract' IS DISTINCT FROM original.canonical_evidence::jsonb->>'contract'
        THEN RAISE EXCEPTION 'gateway evidence contract changed' USING ERRCODE='23514'; END IF;
    END IF;
    IF value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2' THEN
        RETURN NEW;
    END IF;
    IF jsonb_typeof(value)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(value))<>16
       OR NOT value ?& ARRAY['contract','phase','reservation_id','tenant_id','run_id',
           'provider_id','configuration_version','budget_version','status','admission','request',
           'request_evidence_sha256','usage','actual_microusd','reason','occurred_at']
       OR value->>'phase' IS DISTINCT FROM NEW.phase
       OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
       OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
       OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
       OR value->>'run_id' IS DISTINCT FROM budget.run_id::text
       OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
       OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
       OR value->>'budget_version' IS DISTINCT FROM budget.version::text
       OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
       OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
       OR NEW.budget_version<>budget.version OR budget.purpose<>'tenant_run'
       OR value->>'status' IS DISTINCT FROM budget.status
       OR value->'admission' IS DISTINCT FROM jsonb_build_object(
           'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
           'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
       OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
       OR encode(sha256(convert_to(NEW.canonical_evidence,'UTF8')),'hex')<>NEW.evidence_sha256
    THEN RAISE EXCEPTION 'gateway Run evidence binding rejected' USING ERRCODE='23514'; END IF;
    IF NEW.phase='request' THEN
        request := value->'request';
        binding := request->'run_binding';
        IF budget.version<>1 OR budget.status NOT IN ('reserved','rejected')
           OR NEW.created_at IS DISTINCT FROM budget.created_at
           OR jsonb_typeof(request) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(request))<>6
           OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
               'model_price','output_token_limit','run_binding']
           OR jsonb_typeof(binding) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(binding))<>11
           OR NOT binding ?& ARRAY['run_id','session_id','space_id','project_id','actor_id',
               'capability_id','model_token_id','customer_pricing_snapshot_id','fence_token',
               'publication_generation','publication_snapshot_sha256']
           OR EXISTS (SELECT 1 FROM jsonb_each(binding) pair
               WHERE pair.key IN ('run_id','session_id','space_id','project_id','actor_id',
                   'capability_id','model_token_id','customer_pricing_snapshot_id')
               AND (jsonb_typeof(pair.value)<>'string' OR (pair.value#>>'{}') !~
                   '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
           OR jsonb_typeof(binding->'fence_token') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_generation') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_snapshot_sha256') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
           OR (request->>'output_token_limit') !~ '^[1-9][0-9]{0,5}$'
           OR value->'usage' IS DISTINCT FROM 'null'::jsonb
           OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
           OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)
        THEN RAISE EXCEPTION 'gateway Run request authority rejected' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    request := original.canonical_evidence::jsonb->'request';
    IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR value->'admission' IS DISTINCT FROM original.canonical_evidence::jsonb->'admission'
       OR value->'request' IS DISTINCT FROM 'null'::jsonb OR NEW.phase<>budget.status
    THEN RAISE EXCEPTION 'gateway Run transition rejected' USING ERRCODE='23514'; END IF;
    SELECT max(budget_version) INTO prior_version FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id;
    IF NEW.budget_version<>prior_version+1
       OR (NEW.phase='in_flight' AND (prior_version<>1 OR NOT
           public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)))
       OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
           SELECT 1 FROM public.saas_model_gateway_evidence WHERE reservation_id=budget.id
           AND phase='in_flight'))
    THEN RAISE EXCEPTION 'gateway Run sequence rejected' USING ERRCODE='23514'; END IF;
    usage := value->'usage';
    IF usage IS DISTINCT FROM 'null'::jsonb THEN
        IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage)<>'object'
           OR (SELECT count(*) FROM jsonb_object_keys(usage))<>5
           OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
               'input_cache_miss_tokens','output_tokens','total_tokens']
           OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair WHERE jsonb_typeof(pair.value)<>'number'
               OR pair.value::text !~ '^[0-9]{1,19}$')
           OR (usage->>'total_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_tokens')::numeric+(usage->>'output_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_cache_hit_tokens')::numeric+(usage->>'input_cache_miss_tokens')::numeric
               <>(usage->>'input_tokens')::numeric
           OR (usage->>'output_tokens')::numeric>(request->>'output_token_limit')::integer
           OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
           OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
           OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence
               WHERE reservation_id=budget.id AND phase='in_flight')
        THEN RAISE EXCEPTION 'gateway Run usage evidence rejected' USING ERRCODE='23514'; END IF;
    ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
       OR (budget.status='in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
       OR (budget.status='uncertain' AND COALESCE(value->>'reason','') NOT IN
           ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
       OR (budget.status IN ('released','expired')
           AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version<>1))
       OR budget.status NOT IN ('in_flight','uncertain','released','expired')
    THEN RAISE EXCEPTION 'gateway Run pending evidence rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_customer_usage_guard_v1() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    u public.saas_usage_events%ROWTYPE;
    r public.saas_runs%ROWTYPE;
    c public.saas_capability_tokens%ROWTYPE;
    certificate public.saas_runner_certificates%ROWTYPE;
    runner public.saas_runner_registrations%ROWTYPE;
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    sent public.saas_model_gateway_evidence%ROWTYPE;
    outcome public.saas_model_gateway_evidence%ROWTYPE;
    price public.saas_pricing_snapshots%ROWTYPE;
    receipt public.saas_billing_metering_receipts%ROWTYPE;
    binding jsonb;
    request jsonb;
    usage jsonb;
    attrs jsonb;
    body jsonb;
    rate jsonb;
    expected_quantity numeric;
    expected_key text;
    expected_hash text;
    expected_outbox_key text;
    happened text;
BEGIN
    IF TG_TABLE_NAME='saas_usage_events' THEN
        u := NEW;
    ELSIF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        SELECT * INTO u FROM public.saas_usage_events WHERE id=NEW.usage_event_id;
    ELSE
        IF NEW.event_type<>'billing.usage.recorded' OR NEW.aggregate_type<>'billing' THEN
            RETURN NEW;
        END IF;
        SELECT * INTO u FROM public.saas_usage_events WHERE id::text=NEW.payload->>'usage_event_id';
        IF NOT FOUND THEN
            SELECT * INTO r FROM public.saas_runs WHERE id::text=NEW.payload->>'run_id';
            IF r.queue_class='managed_interactive' THEN
                RAISE EXCEPTION 'gateway Usage is missing' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    IF u.run_id IS NULL THEN RETURN NEW; END IF;
    SELECT * INTO r FROM public.saas_runs WHERE id=u.run_id;
    IF r.queue_class IS DISTINCT FROM 'managed_interactive' THEN RETURN NEW; END IF;
    IF NOT pg_has_role(session_user,'saas_metering','member') THEN
        RAISE EXCEPTION 'gateway customer usage requires machine metering' USING ERRCODE='23514';
    END IF;
    SELECT * INTO c FROM public.saas_capability_tokens
    WHERE token_hash=NULLIF(current_setting('app.capability_token_hash',true),'');
    SELECT * INTO certificate FROM public.saas_runner_certificates
    WHERE fingerprint_sha256=NULLIF(current_setting('app.presented_certificate_fingerprint',true),'')
      AND purpose='billing_metering';
    SELECT * INTO runner FROM public.saas_runner_registrations WHERE id=c.runner_id;
    SELECT * INTO budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NULLIF(current_setting('app.model_budget_reservation_id',true),'')::uuid;
    IF c.id IS NULL OR certificate.id IS NULL OR runner.id IS NULL OR budget.id IS NULL
       OR NULLIF(current_setting('app.presented_certificate_purpose',true),'') IS DISTINCT FROM 'billing_metering'
       OR NOT (c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb)
       OR jsonb_array_length(c.allowed_actions::jsonb)<>2
       OR (c.tenant_id,c.space_id,c.project_id,c.run_id)<>(r.tenant_id,r.space_id,r.project_id,r.id)
       OR (u.tenant_id,u.space_id,u.project_id)<>(r.tenant_id,r.space_id,r.project_id)
       OR certificate.runner_id<>c.runner_id
       OR certificate.runner_connection_generation<>c.runner_connection_generation
       OR runner.connection_generation<>c.runner_connection_generation
       OR runner.status NOT IN ('online','draining')
       OR certificate.certificate_not_before>statement_timestamp()
       OR certificate.certificate_not_after<=statement_timestamp()
       OR NOT (certificate.status='active' OR
          (certificate.status='retiring' AND certificate.retire_at>statement_timestamp()))
       OR budget.tenant_id<>r.tenant_id OR budget.run_id<>r.id OR budget.purpose<>'tenant_run'
       OR budget.provider_id<>'deepseek' OR budget.status NOT IN ('settled','released')
       OR budget.outcome_evidence_sha256 IS NULL
    THEN RAISE EXCEPTION 'gateway machine scope rejected' USING ERRCODE='23514'; END IF;
    SELECT * INTO original FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='request';
    SELECT * INTO sent FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='in_flight';
    SELECT * INTO outcome FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase=budget.status;
    IF original.id IS NULL OR sent.id IS NULL OR outcome.id IS NULL
       OR EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence e WHERE e.id IN
          (original.id,sent.id,outcome.id) AND (
             encode(sha256(convert_to(e.canonical_evidence,'UTF8')),'hex')<>e.evidence_sha256
             OR e.canonical_evidence::jsonb->>'contract'<>'platform-model-gateway-evidence-v2'))
       OR sent.canonical_evidence::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR outcome.canonical_evidence::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR budget.outcome_evidence_sha256<>outcome.evidence_sha256
       OR outcome.budget_version<>budget.version
       OR original.created_at<c.issued_at OR sent.created_at<original.created_at
       OR sent.created_at>=c.expires_at OR outcome.created_at<sent.created_at
       OR (c.revoked_at IS NOT NULL AND c.revoked_at<=sent.created_at)
    THEN RAISE EXCEPTION 'gateway metering evidence rejected' USING ERRCODE='23514'; END IF;
    request := original.canonical_evidence::jsonb->'request';
    binding := request->'run_binding';
    usage := outcome.canonical_evidence::jsonb->'usage';
    IF binding->>'capability_id' IS DISTINCT FROM c.id::text
       OR binding->>'fence_token' IS DISTINCT FROM c.fence_token::text
       OR binding->>'run_id' IS DISTINCT FROM r.id::text
       OR binding->>'space_id' IS DISTINCT FROM r.space_id::text
       OR binding->>'project_id' IS DISTINCT FROM r.project_id::text
       OR binding->>'session_id' IS DISTINCT FROM r.session_id::text
       OR binding->>'actor_id' IS DISTINCT FROM r.created_by::text
       OR binding->>'customer_pricing_snapshot_id' IS DISTINCT FROM r.customer_pricing_snapshot_id::text
       OR NOT r.customer_pricing_frozen OR r.created_by_service_account_id IS NOT NULL
       OR NOT (c.resource_scope::jsonb @> jsonb_build_object(
          'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
          'run_id',r.id::text,'runner_id',c.runner_id::text,'session_id',r.session_id::text))
       OR u.meter NOT IN ('llm.input_tokens','llm.output_tokens')
       OR u.unit<>'tokens' OR u.provider<>'deepseek'
       OR u.pricing_snapshot_id IS DISTINCT FROM r.customer_pricing_snapshot_id
       OR u.session_id IS DISTINCT FROM r.session_id OR u.user_id IS DISTINCT FROM r.created_by
       OR u.service_account_id IS NOT NULL
       OR u.occurred_at IS DISTINCT FROM original.created_at
       OR u.provider_request_id IS DISTINCT FROM 'model-gateway:'||budget.id::text
       OR (usage->>'total_tokens')::numeric IS DISTINCT FROM budget.settled_tokens::numeric
       OR (outcome.canonical_evidence::jsonb->>'actual_microusd')::numeric IS DISTINCT FROM budget.settled_microusd::numeric
    THEN RAISE EXCEPTION 'gateway customer binding rejected' USING ERRCODE='23514'; END IF;
    expected_quantity := (usage->>(CASE u.meter WHEN 'llm.input_tokens' THEN 'input_tokens' ELSE 'output_tokens' END))::numeric;
    expected_key := 'model-gateway:'||budget.id::text||':'||CASE u.meter WHEN 'llm.input_tokens' THEN 'input' ELSE 'output' END;
    attrs := jsonb_build_object('model',request->>'public_model_id','operation',
       CASE request->>'wire_api' WHEN 'openai_responses' THEN 'responses.create' ELSE 'chat.completions.create' END,
       'request_class','managed_gateway');
    SELECT * INTO price FROM public.saas_pricing_snapshots
    WHERE id=r.customer_pricing_snapshot_id AND tenant_id=r.tenant_id;
    rate := price.rates::jsonb->u.meter;
    IF expected_quantity IS NULL OR expected_quantity<=0 OR u.quantity IS DISTINCT FROM expected_quantity
       OR u.idempotency_key IS DISTINCT FROM expected_key OR u.attributes::jsonb IS DISTINCT FROM attrs
       OR price.id IS NULL OR u.currency IS DISTINCT FROM price.currency
       OR rate->>'unit' IS DISTINCT FROM 'tokens' OR (rate->>'unit_size')::numeric<=0
       OR (rate->>'minor_per_unit') !~ '^[1-9][0-9]{0,18}$'
       OR u.customer_charge_minor IS DISTINCT FROM
          ceil(expected_quantity/(rate->>'unit_size')::numeric*(rate->>'minor_per_unit')::numeric)::bigint
       OR NOT EXISTS (SELECT 1 FROM public.saas_billing_subscriptions s
           WHERE s.tenant_id=r.tenant_id AND s.status IN ('active','trialing'))
    THEN RAISE EXCEPTION 'gateway customer quantity or price rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_usage_events' THEN RETURN NEW; END IF;
    happened := original.canonical_evidence::jsonb->>'occurred_at';
    body := jsonb_build_object(
       'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
       'session_id',r.session_id::text,'run_id',r.id::text,'actor_kind','user','user_id',r.created_by::text,
       'service_account_id',NULL,'runner_id',c.runner_id::text,'pricing_snapshot_id',price.id::text,
       'meter',u.meter,'quantity',u.quantity::bigint::text,'unit',u.unit,'provider',u.provider,
       'provider_request_id',u.provider_request_id,'occurred_at',happened,'attributes',attrs,
       'model_budget_reservation_id',budget.id::text);
    expected_hash := public.saas_canonical_json_sha256_v1(body);
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        receipt := NEW;
    ELSE
        SELECT * INTO receipt FROM public.saas_billing_metering_receipts
        WHERE id::text=NEW.payload->>'metering_receipt_id';
    END IF;
    IF receipt.id IS NULL OR receipt.usage_event_id<>u.id
       OR (receipt.tenant_id,receipt.space_id,receipt.project_id,receipt.run_id,receipt.runner_id)
          <>(r.tenant_id,r.space_id,r.project_id,r.id,c.runner_id)
       OR receipt.runner_certificate_id<>certificate.id
       OR receipt.certificate_fingerprint_sha256<>certificate.fingerprint_sha256
       OR receipt.capability_id<>c.id OR receipt.fence_token<>c.fence_token
       OR receipt.runner_connection_generation<>c.runner_connection_generation
       OR receipt.dispatch_generation<>c.dispatch_generation
       OR receipt.idempotency_key<>expected_key OR receipt.request_hash<>expected_hash
       OR receipt.model_budget_reservation_id IS DISTINCT FROM budget.id
    THEN RAISE EXCEPTION 'gateway customer receipt rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN RETURN NEW; END IF;
    expected_outbox_key := encode(sha256(convert_to('billing-metering','UTF8')||decode('00','hex')||
       convert_to(r.tenant_id::text,'UTF8')||decode('00','hex')||convert_to(expected_key,'UTF8')),'hex');
    IF NEW.tenant_id<>r.tenant_id OR NEW.aggregate_key<>u.id::text OR NEW.request_hash<>expected_hash
       OR NEW.idempotency_key<>expected_outbox_key
       OR NEW.payload::jsonb IS DISTINCT FROM body||jsonb_build_object(
          'usage_event_id',u.id::text,'metering_receipt_id',receipt.id::text,'capability_id',c.id::text,
          'runner_connection_generation',c.runner_connection_generation,'dispatch_generation',c.dispatch_generation,
          'fence_token',c.fence_token,'currency',price.currency,'customer_charge_minor',u.customer_charge_minor)
    THEN RAISE EXCEPTION 'gateway customer outbox rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
)

_NEW_FUNCTIONS = (
    """CREATE OR REPLACE FUNCTION public.saas_model_projection_transition_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ DECLARE
receipt record;
budget record;
BEGIN IF NEW.version <> OLD.version + 1 OR NOT ((OLD.status = 'requested' AND NEW.status IN ('applying', 'failed')) OR (OLD.status = 'applying' AND NEW.status IN ('applied', 'verified', 'failed', 'uncertain'))) OR (NEW.status IN ('applying', 'applied', 'verified') AND NEW.error_code IS NOT NULL) OR (NEW.status IN ('failed', 'uncertain') AND (NEW.error_code IS NULL OR length(NEW.error_code) = 0)) THEN RAISE EXCEPTION 'model projection transition rejected' USING ERRCODE = '23514'; END IF; IF NEW.status='verified' THEN
    SELECT operation_id,budget_reservation_id,outcome,actual_microusd,canonical_evidence,evidence_sha256
        INTO receipt FROM public.saas_model_verification_receipts WHERE operation_id=NEW.id;
    SELECT id,purpose,test_operation_id,status,settled_microusd,settled_tokens,outcome_evidence_sha256
        INTO budget FROM public.saas_model_provider_budget_reservations WHERE id=receipt.budget_reservation_id;
    IF (NEW.action='verify_deployment' AND receipt.operation_id=NEW.id
        AND receipt.outcome='passed' AND budget.purpose='platform_test'
        AND budget.test_operation_id=NEW.id AND budget.status='settled'
        AND budget.settled_microusd=receipt.actual_microusd
        AND budget.settled_tokens=(convert_from(substring(receipt.canonical_evidence from 8),'UTF8')::jsonb->'usage'->>'total_tokens')::bigint
        AND budget.outcome_evidence_sha256=receipt.evidence_sha256) IS NOT TRUE THEN
        RAISE EXCEPTION 'model verification settlement rejected' USING ERRCODE='23514';
    END IF;
END IF;
IF NEW.action = 'verify_deployment' AND NEW.status = 'applied' THEN RAISE EXCEPTION 'model verification transition rejected' USING ERRCODE = '23514'; END IF; RETURN NEW; END $$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_model_publication_version_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog SET lock_timeout = '500ms' AS $$
DECLARE actual_generation integer; proof record;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text || ':' || NEW.public_model_id || ':' || NEW.wire_api, 0));
    SELECT COALESCE(max(generation), 0) INTO actual_generation FROM public.saas_model_publication_versions
        WHERE tenant_id = NEW.tenant_id AND public_model_id = NEW.public_model_id
        AND wire_api = NEW.wire_api;
SELECT receipt.canonical_evidence AS canonical_evidence,
        test.canonical_price AS canonical_price, budget.settled_tokens AS settled_tokens,
        draft.id AS deployment_id, operation.credential_version_id AS credential_version_id
        INTO proof FROM public.saas_model_publication_commands command
        JOIN public.saas_model_projection_operations operation ON operation.id = command.operation_id
        JOIN public.saas_model_deployment_versions draft
            ON draft.id = operation.deployment_version_id
        JOIN public.saas_model_projection_operations verification ON verification.id = command.verification_operation_id
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
        AND budget.outcome_evidence_sha256 = receipt.evidence_sha256;
    IF (NEW.generation=actual_generation+1 AND FOUND AND (proof.settled_tokens=(convert_from(substring(proof.canonical_evidence from 8),'UTF8')::jsonb->'usage'->>'total_tokens')::bigint AND encode(sha256(substring(NEW.canonical_snapshot from 8)), 'hex') = NEW.snapshot_sha256
        AND encode(sha256(substring(NEW.canonical_readiness from 8)), 'hex')
            = NEW.readiness_sha256
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'tenant_id' = NEW.tenant_id::text
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'deployment_id' = proof.deployment_id::text
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'public_model_id' = NEW.public_model_id
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'wire_api' = NEW.wire_api
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'configuration_sha256' = NEW.configuration_sha256
        AND (convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->>'generation')::integer = NEW.generation
        AND convert_from(substring(NEW.canonical_snapshot from 8),'UTF8')::jsonb->'provider_cost' = convert_from(substring(proof.canonical_price from 8),'UTF8')::jsonb
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'scope' =
            'stored_credentials_and_visible_replica_routes_not_hidden_replica_memory'
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'contract' =
            'litellm-1.105.1-replica-routes-and-storage-v1'
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'deployment_id' = proof.deployment_id::text
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'credential_version_id' =
            proof.credential_version_id::text
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'configuration_sha256' = NEW.configuration_sha256
        AND convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'inventory_sha256' = NEW.inventory_sha256
        AND jsonb_array_length(convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->'replicas') BETWEEN 2 AND 16
        AND (convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'started_at')::timestamptz >=
            clock_timestamp() - interval '30 seconds'
        AND (convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'completed_at')::timestamptz <= clock_timestamp()
        AND (convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'completed_at')::timestamptz >=
            (convert_from(substring(NEW.canonical_readiness from 8),'UTF8')::jsonb->>'started_at')::timestamptz)) IS NOT TRUE THEN
        RAISE EXCEPTION 'model publication proof rejected' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """
    CREATE OR REPLACE FUNCTION public.saas_model_gateway_evidence_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
    DECLARE
        budget public.saas_model_provider_budget_reservations%ROWTYPE;
        original public.saas_model_gateway_evidence%ROWTYPE;
        value jsonb;
        usage jsonb;
        request jsonb;
        prior_version integer;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'gateway evidence is immutable' USING ERRCODE = '23514';
        END IF;
        SELECT * INTO STRICT budget FROM public.saas_model_provider_budget_reservations WHERE id = NEW.reservation_id;
        value := convert_from(substring(NEW.canonical_evidence from 8),'UTF8')::jsonb;
        IF jsonb_typeof(value) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(value)) <> 16
           OR value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v1'
           OR value->>'phase' IS DISTINCT FROM NEW.phase
           OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
           OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
           OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
           OR value->>'session_id' IS DISTINCT FROM budget.run_id::text
           OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
           OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
           OR value->>'budget_version' IS DISTINCT FROM budget.version::text
           OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
           OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
           OR NEW.budget_version <> budget.version OR budget.purpose <> 'tenant_run'
           OR value->>'status' IS DISTINCT FROM budget.status
           OR value->'admission' IS DISTINCT FROM jsonb_build_object(
               'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
               'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
           OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
           OR encode(sha256(substring(NEW.canonical_evidence from 8)), 'hex')
              <> NEW.evidence_sha256
        THEN RAISE EXCEPTION 'gateway evidence binding rejected' USING ERRCODE = '23514'; END IF;
        IF NEW.phase = 'request' THEN
            request := value->'request';
            IF budget.version <> 1 OR budget.status NOT IN ('reserved', 'rejected')
               OR NEW.created_at IS DISTINCT FROM budget.created_at
               OR jsonb_typeof(request) <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request)) <> 5
               OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
                                       'model_price','output_token_limit']
               OR (request->>'public_model_id') !~ '^[!-~]{1,128}$'
               OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
               OR request->>'wire_api' NOT IN ('openai_chat_completions','openai_responses')
               OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
               OR (request->>'pricing_revision') !~ '^[!-~]{1,32}$'
               OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
               OR (request->>'output_token_limit') !~ '^[1-9][0-9]{0,5}$'
               OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
               OR (request->>'output_token_limit')::integer > 65536
               OR jsonb_typeof(request->'model_price') <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(request->'model_price')) <> 7
               OR NOT (request->'model_price') ?& ARRAY['model_sha256',
                   'peak_input_cache_hit_microusd_per_million_tokens',
                   'peak_input_cache_miss_microusd_per_million_tokens',
                   'peak_output_microusd_per_million_tokens',
                   'off_peak_input_cache_hit_microusd_per_million_tokens',
                   'off_peak_input_cache_miss_microusd_per_million_tokens',
                   'off_peak_output_microusd_per_million_tokens']
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND (jsonb_typeof(pair.value) <> 'number'
                     OR pair.value::text !~ '^[1-9][0-9]{0,12}$'))
               OR EXISTS (SELECT 1 FROM jsonb_each(request->'model_price') pair
                   WHERE pair.key <> 'model_sha256' AND pair.value::text::numeric > 1000000000000)
               OR request->'model_price'->>'model_sha256' IS DISTINCT FROM
                  encode(sha256(convert_to(request->>'public_model_id','UTF8')), 'hex')
               OR value->'usage' IS DISTINCT FROM 'null'::jsonb
               OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
               OR value->'reason' IS DISTINCT FROM 'null'::jsonb
            THEN RAISE EXCEPTION 'gateway request evidence rejected' USING ERRCODE = '23514';
            END IF;
        ELSE
            SELECT * INTO STRICT original FROM public.saas_model_gateway_evidence
            WHERE reservation_id = budget.id AND phase = 'request';
            IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
               OR value->'admission' IS DISTINCT FROM
                  convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->'admission'
               OR value->'request' IS DISTINCT FROM 'null'::jsonb
               OR NEW.phase <> budget.status
            THEN RAISE EXCEPTION 'gateway transition evidence rejected' USING ERRCODE = '23514';
            END IF;
            SELECT max(budget_version) INTO prior_version FROM public.saas_model_gateway_evidence
            WHERE reservation_id = budget.id;
            IF NEW.budget_version <> prior_version + 1
               OR (NEW.phase = 'in_flight' AND prior_version <> 1)
               OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
                   SELECT 1 FROM public.saas_model_gateway_evidence WHERE reservation_id = budget.id
                   AND phase = 'in_flight'))
            THEN RAISE EXCEPTION 'gateway evidence sequence rejected' USING ERRCODE = '23514';
            END IF;
            usage := value->'usage';
            IF usage IS DISTINCT FROM 'null'::jsonb THEN
                IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage) <> 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(usage)) <> 5
                   OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
                       'input_cache_miss_tokens','output_tokens','total_tokens']
                   OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair
                              WHERE jsonb_typeof(pair.value) <> 'number'
                              OR pair.value::text !~ '^[0-9]{1,19}$')
                   OR (usage->>'total_tokens')::numeric <> budget.settled_tokens
                   OR (usage->>'input_tokens')::numeric + (usage->>'output_tokens')::numeric
                      <> budget.settled_tokens
                   OR (usage->>'input_cache_hit_tokens')::numeric
                      + (usage->>'input_cache_miss_tokens')::numeric
                      <> (usage->>'input_tokens')::numeric
                   OR (usage->>'output_tokens')::numeric >
                      (convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->'request'->>'output_token_limit')::integer
                   OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
                   OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
                   OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
                   OR value->'reason' IS DISTINCT FROM 'null'::jsonb
                   OR NOT EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence
                       WHERE reservation_id = budget.id AND phase = 'in_flight')
                THEN RAISE EXCEPTION 'gateway usage evidence rejected' USING ERRCODE = '23514';
                END IF;
            ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
               OR (budget.status = 'in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
               OR (budget.status = 'uncertain' AND COALESCE(value->>'reason','') NOT IN
                   ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
               OR (budget.status IN ('released','expired')
                   AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version <> 1))
               OR budget.status NOT IN ('in_flight','uncertain','released','expired')
            THEN RAISE EXCEPTION 'gateway pending evidence rejected' USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END $$
    """,  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_audit_model_gateway_evidence_v1(source_event_id uuid,expected_payload jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    source public.saas_control_plane_outbox%ROWTYPE;
    evidence public.saas_model_gateway_evidence%ROWTYPE;
    head public.saas_platform_audit_chain_heads%ROWTYPE;
    prior public.saas_platform_audit_events%ROWTYPE;
    audit_payload jsonb;
    payload_digest text;
    occurred text;
    event_material jsonb;
    event_digest text;
    system_actor constant uuid := '21bb9380-44ca-51a9-8f87-c914945e332a';
BEGIN
    SELECT * INTO source FROM public.saas_control_plane_outbox WHERE id = source_event_id;
    IF NOT FOUND OR source.aggregate_type <> 'model_gateway_budget'
       OR source.event_type <> 'model_gateway.evidence_retained'
       OR source.payload::jsonb IS DISTINCT FROM expected_payload
       OR jsonb_typeof(expected_payload) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(expected_payload)) <> 5
       OR expected_payload->>'event_type' IS DISTINCT FROM source.event_type
       OR expected_payload->>'tenant_id' IS DISTINCT FROM source.tenant_id::text
       OR expected_payload->>'reservation_id' IS DISTINCT FROM source.aggregate_key
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO evidence FROM public.saas_model_gateway_evidence
    WHERE id::text = expected_payload->>'evidence_id';
    IF NOT FOUND OR evidence.tenant_id IS DISTINCT FROM source.tenant_id
       OR evidence.reservation_id::text IS DISTINCT FROM source.aggregate_key
       OR evidence.evidence_sha256 IS DISTINCT FROM source.request_hash
       OR evidence.evidence_sha256 IS DISTINCT FROM expected_payload->>'evidence_sha256'
       OR evidence.evidence_sha256 IS DISTINCT FROM
          encode(sha256(substring(evidence.canonical_evidence from 8)),'hex')
       OR source.idempotency_key IS DISTINCT FROM
          'model-gateway-evidence:' || replace(evidence.id::text,'-','')
    THEN RAISE EXCEPTION 'model_gateway_audit_evidence_rejected' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT head FROM public.saas_platform_audit_chain_heads
    WHERE partition_key = 'platform' FOR UPDATE;
    IF (head.last_sequence = 0 AND (head.last_event_hash <> repeat('0',64)
        OR EXISTS (SELECT 1 FROM public.saas_platform_audit_events)))
       OR (head.last_sequence > 0 AND NOT EXISTS (
           SELECT 1 FROM public.saas_platform_audit_events
           WHERE sequence_no = head.last_sequence AND event_hash = head.last_event_hash))
    THEN RAISE EXCEPTION 'model_gateway_audit_chain_unavailable' USING ERRCODE = '23514';
    END IF;
    audit_payload := expected_payload || jsonb_build_object(
        'source_event_id',source.id::text,'phase',evidence.phase,
        'budget_version',evidence.budget_version);
    payload_digest := public.saas_canonical_json_sha256_v1(audit_payload);
    occurred := to_char(evidence.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')
        || CASE WHEN to_char(evidence.created_at AT TIME ZONE 'UTC','US') = '000000'
                THEN '' ELSE '.' || to_char(evidence.created_at AT TIME ZONE 'UTC','US') END
        || '+00:00';
    SELECT * INTO prior FROM public.saas_platform_audit_events WHERE id = source.id;
    IF FOUND THEN
        event_material := jsonb_build_object(
            'sequence_no',prior.sequence_no,'tenant_id',source.tenant_id::text,
            'actor_type','system','actor_id',system_actor::text,
            'event_type',source.event_type,'target_type',source.aggregate_type,
            'target_id',evidence.reservation_id::text,'operation_id',NULL,
            'payload_hash',payload_digest,'previous_hash',prior.previous_hash,
            'occurred_at',occurred);
        IF prior.sequence_no > head.last_sequence
           OR prior.tenant_id IS DISTINCT FROM source.tenant_id
           OR prior.actor_type <> 'system' OR prior.actor_id <> system_actor
           OR prior.event_type <> source.event_type OR prior.target_type <> source.aggregate_type
           OR prior.target_id <> evidence.reservation_id OR prior.operation_id IS NOT NULL
           OR prior.payload::jsonb IS DISTINCT FROM audit_payload
           OR prior.payload_hash <> payload_digest OR prior.occurred_at <> evidence.created_at
           OR prior.event_hash <> public.saas_canonical_json_sha256_v1(event_material)
        THEN RAISE EXCEPTION 'model_gateway_audit_replay_conflict' USING ERRCODE = '23514';
        END IF;
        RETURN false;
    END IF;
    event_material := jsonb_build_object(
        'sequence_no',head.last_sequence + 1,'tenant_id',source.tenant_id::text,
        'actor_type','system','actor_id',system_actor::text,
        'event_type',source.event_type,'target_type',source.aggregate_type,
        'target_id',evidence.reservation_id::text,'operation_id',NULL,
        'payload_hash',payload_digest,'previous_hash',head.last_event_hash,
        'occurred_at',occurred);
    event_digest := public.saas_canonical_json_sha256_v1(event_material);
    INSERT INTO public.saas_platform_audit_events(
        id,sequence_no,tenant_id,actor_type,actor_id,event_type,target_type,target_id,
        operation_id,payload,payload_hash,previous_hash,event_hash,occurred_at,created_at)
    VALUES(source.id,head.last_sequence + 1,source.tenant_id,'system',system_actor,
        source.event_type,source.aggregate_type,evidence.reservation_id,NULL,audit_payload,
        payload_digest,head.last_event_hash,event_digest,evidence.created_at,statement_timestamp());
    UPDATE public.saas_platform_audit_chain_heads
    SET last_sequence = head.last_sequence + 1,last_event_hash = event_digest,
        updated_at = statement_timestamp() WHERE partition_key = 'platform';
    RETURN true;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_run_binding_v2(requested_tenant uuid,requested_run uuid,request jsonb,requested_at timestamptz) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE proof record;
BEGIN
SELECT p.canonical_snapshot,p.snapshot_sha256 INTO proof FROM public.saas_model_run_tokens t
    JOIN public.saas_runs r ON r.id=t.run_id
    JOIN public.saas_capability_tokens c ON c.id=t.capability_id
    JOIN public.saas_run_dispatches d ON d.run_id=r.id
    JOIN public.saas_runner_registrations runner ON runner.id=c.runner_id
    JOIN public.saas_model_publication_versions p ON p.tenant_id=r.tenant_id
       AND p.public_model_id=request->>'public_model_id' AND p.wire_api=request->>'wire_api'
       AND p.generation=(request->'run_binding'->>'publication_generation')::integer
    WHERE r.id=requested_run AND r.tenant_id=requested_tenant
      AND t.id::text=request->'run_binding'->>'model_token_id'
      AND (t.tenant_id,t.space_id,t.project_id,t.actor_id,t.fence_token)
          =(r.tenant_id,r.space_id,r.project_id,r.created_by,r.fence_token)
      AND t.issued_at<=requested_at AND t.expires_at>statement_timestamp()
      AND r.id::text=request->'run_binding'->>'run_id'
      AND r.session_id::text=request->'run_binding'->>'session_id'
      AND r.space_id::text=request->'run_binding'->>'space_id'
      AND r.project_id::text=request->'run_binding'->>'project_id'
      AND r.created_by::text=request->'run_binding'->>'actor_id'
      AND r.fence_token::text=request->'run_binding'->>'fence_token'
      AND r.customer_pricing_snapshot_id::text=request->'run_binding'->>'customer_pricing_snapshot_id'
      AND r.customer_pricing_frozen AND r.created_by_service_account_id IS NULL
      AND r.queue_class='managed_interactive' AND r.status='running'
      AND r.lease_expires_at>statement_timestamp() AND r.lease_owner=c.runner_id::text
      AND c.id::text=request->'run_binding'->>'capability_id'
      AND (c.run_id,c.tenant_id,c.space_id,c.project_id,c.fence_token)
          =(r.id,r.tenant_id,r.space_id,r.project_id,r.fence_token)
      AND c.revoked_at IS NULL AND c.expires_at>statement_timestamp()
      AND c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb
      AND jsonb_array_length(c.allowed_actions::jsonb)=2
      AND d.status='leased' AND d.selected_runner_id=c.runner_id
      AND d.dispatch_generation=c.dispatch_generation
      AND runner.connection_generation=c.runner_connection_generation
      AND runner.status IN ('online','draining')
      AND p.snapshot_sha256=request->'run_binding'->>'publication_snapshot_sha256'
      AND r.input::jsonb->'execution'->'model_publication'=jsonb_build_object(
          'schema_version',1,'public_model_id',p.public_model_id,'wire_api',p.wire_api,
          'generation',p.generation,'snapshot_sha256',p.snapshot_sha256)
      AND requested_at<=statement_timestamp()+interval '5 seconds'
      AND requested_at>=statement_timestamp()-interval '5 minutes';
    IF NOT FOUND THEN RETURN false; END IF;
    RETURN (encode(sha256(substring(proof.canonical_snapshot from 8)),'hex')=proof.snapshot_sha256
        AND convert_from(substring(proof.canonical_snapshot from 8),'UTF8')::jsonb->'provider_cost'->'price'=request->'model_price'
        AND convert_from(substring(proof.canonical_snapshot from 8),'UTF8')::jsonb->'provider_cost'->>'pricing_revision'=request->>'pricing_revision'
        AND (request->>'output_token_limit')::integer BETWEEN 1
            AND (convert_from(substring(proof.canonical_snapshot from 8),'UTF8')::jsonb->>'max_output_tokens')::integer) IS TRUE;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_run_evidence_guard_v2() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $function$
DECLARE
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    value jsonb;
    request jsonb;
    binding jsonb;
    usage jsonb;
    prior_version integer;
BEGIN
    SELECT * INTO STRICT budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NEW.reservation_id;
    value := convert_from(substring(NEW.canonical_evidence from 8),'UTF8')::jsonb;
    IF NEW.phase<>'request' THEN
        SELECT * INTO STRICT original FROM public.saas_model_gateway_evidence
        WHERE reservation_id=budget.id AND phase='request';
        IF value->>'contract' IS DISTINCT FROM convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->>'contract'
        THEN RAISE EXCEPTION 'gateway evidence contract changed' USING ERRCODE='23514'; END IF;
    END IF;
    IF value->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2' THEN
        RETURN NEW;
    END IF;
    IF jsonb_typeof(value)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(value))<>16
       OR NOT value ?& ARRAY['contract','phase','reservation_id','tenant_id','run_id',
           'provider_id','configuration_version','budget_version','status','admission','request',
           'request_evidence_sha256','usage','actual_microusd','reason','occurred_at']
       OR value->>'phase' IS DISTINCT FROM NEW.phase
       OR value->>'reservation_id' IS DISTINCT FROM budget.id::text
       OR value->>'tenant_id' IS DISTINCT FROM budget.tenant_id::text
       OR NEW.tenant_id IS DISTINCT FROM budget.tenant_id
       OR value->>'run_id' IS DISTINCT FROM budget.run_id::text
       OR value->>'provider_id' IS DISTINCT FROM budget.provider_id
       OR value->>'configuration_version' IS DISTINCT FROM budget.configuration_version::text
       OR value->>'budget_version' IS DISTINCT FROM budget.version::text
       OR jsonb_typeof(value->'configuration_version') IS DISTINCT FROM 'number'
       OR jsonb_typeof(value->'budget_version') IS DISTINCT FROM 'number'
       OR NEW.budget_version<>budget.version OR budget.purpose<>'tenant_run'
       OR value->>'status' IS DISTINCT FROM budget.status
       OR value->'admission' IS DISTINCT FROM jsonb_build_object(
           'requested_microusd',budget.requested_microusd,'requested_tokens',budget.requested_tokens,
           'admitted_microusd',budget.admitted_microusd,'admitted_tokens',budget.admitted_tokens)
       OR (value->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.created_at
       OR encode(sha256(substring(NEW.canonical_evidence from 8)),'hex')<>NEW.evidence_sha256
    THEN RAISE EXCEPTION 'gateway Run evidence binding rejected' USING ERRCODE='23514'; END IF;
    IF NEW.phase='request' THEN
        request := value->'request';
        binding := request->'run_binding';
        IF budget.version<>1 OR budget.status NOT IN ('reserved','rejected')
           OR NEW.created_at IS DISTINCT FROM budget.created_at
           OR jsonb_typeof(request) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(request))<>6
           OR NOT request ?& ARRAY['public_model_id','wire_api','pricing_revision',
               'model_price','output_token_limit','run_binding']
           OR jsonb_typeof(binding) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(binding))<>11
           OR NOT binding ?& ARRAY['run_id','session_id','space_id','project_id','actor_id',
               'capability_id','model_token_id','customer_pricing_snapshot_id','fence_token',
               'publication_generation','publication_snapshot_sha256']
           OR EXISTS (SELECT 1 FROM jsonb_each(binding) pair
               WHERE pair.key IN ('run_id','session_id','space_id','project_id','actor_id',
                   'capability_id','model_token_id','customer_pricing_snapshot_id')
               AND (jsonb_typeof(pair.value)<>'string' OR (pair.value#>>'{}') !~
                   '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
           OR jsonb_typeof(binding->'fence_token') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_generation') IS DISTINCT FROM 'number'
           OR jsonb_typeof(binding->'publication_snapshot_sha256') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'public_model_id') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'wire_api') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'pricing_revision') IS DISTINCT FROM 'string'
           OR jsonb_typeof(request->'output_token_limit') IS DISTINCT FROM 'number'
           OR (request->>'output_token_limit') !~ '^[1-9][0-9]{0,5}$'
           OR value->'usage' IS DISTINCT FROM 'null'::jsonb
           OR value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
           OR value->'request_evidence_sha256' IS DISTINCT FROM 'null'::jsonb
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)
        THEN RAISE EXCEPTION 'gateway Run request authority rejected' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    request := convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->'request';
    IF value->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR value->'admission' IS DISTINCT FROM convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->'admission'
       OR value->'request' IS DISTINCT FROM 'null'::jsonb OR NEW.phase<>budget.status
    THEN RAISE EXCEPTION 'gateway Run transition rejected' USING ERRCODE='23514'; END IF;
    SELECT max(budget_version) INTO prior_version FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id;
    IF NEW.budget_version<>prior_version+1
       OR (NEW.phase='in_flight' AND (prior_version<>1 OR NOT
           public.saas_gateway_run_binding_v2(budget.tenant_id,budget.run_id,request,budget.created_at)))
       OR (NEW.phase IN ('uncertain','settled') AND NOT EXISTS (
           SELECT 1 FROM public.saas_model_gateway_evidence WHERE reservation_id=budget.id
           AND phase='in_flight'))
    THEN RAISE EXCEPTION 'gateway Run sequence rejected' USING ERRCODE='23514'; END IF;
    usage := value->'usage';
    IF usage IS DISTINCT FROM 'null'::jsonb THEN
        IF budget.status NOT IN ('settled','released') OR jsonb_typeof(usage)<>'object'
           OR (SELECT count(*) FROM jsonb_object_keys(usage))<>5
           OR NOT usage ?& ARRAY['input_tokens','input_cache_hit_tokens',
               'input_cache_miss_tokens','output_tokens','total_tokens']
           OR EXISTS (SELECT 1 FROM jsonb_each(usage) pair WHERE jsonb_typeof(pair.value)<>'number'
               OR pair.value::text !~ '^[0-9]{1,19}$')
           OR (usage->>'total_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_tokens')::numeric+(usage->>'output_tokens')::numeric<>budget.settled_tokens
           OR (usage->>'input_cache_hit_tokens')::numeric+(usage->>'input_cache_miss_tokens')::numeric
               <>(usage->>'input_tokens')::numeric
           OR (usage->>'output_tokens')::numeric>(request->>'output_token_limit')::integer
           OR value->>'actual_microusd' IS DISTINCT FROM budget.settled_microusd::text
           OR jsonb_typeof(value->'actual_microusd') IS DISTINCT FROM 'number'
           OR budget.outcome_evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256
           OR value->'reason' IS DISTINCT FROM 'null'::jsonb
           OR NOT EXISTS (SELECT 1 FROM public.saas_model_gateway_evidence
               WHERE reservation_id=budget.id AND phase='in_flight')
        THEN RAISE EXCEPTION 'gateway Run usage evidence rejected' USING ERRCODE='23514'; END IF;
    ELSIF value->'actual_microusd' IS DISTINCT FROM 'null'::jsonb
       OR (budget.status='in_flight' AND value->'reason' IS DISTINCT FROM 'null'::jsonb)
       OR (budget.status='uncertain' AND COALESCE(value->>'reason','') NOT IN
           ('provider_outcome_unknown','provider_rejected','provider_unreachable','stream_incomplete','settlement_unavailable'))
       OR (budget.status IN ('released','expired')
           AND (value->>'reason' IS DISTINCT FROM 'not_sent' OR prior_version<>1))
       OR budget.status NOT IN ('in_flight','uncertain','released','expired')
    THEN RAISE EXCEPTION 'gateway Run pending evidence rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
    """CREATE OR REPLACE FUNCTION public.saas_gateway_customer_usage_guard_v1() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    u public.saas_usage_events%ROWTYPE;
    r public.saas_runs%ROWTYPE;
    c public.saas_capability_tokens%ROWTYPE;
    certificate public.saas_runner_certificates%ROWTYPE;
    runner public.saas_runner_registrations%ROWTYPE;
    budget public.saas_model_provider_budget_reservations%ROWTYPE;
    original public.saas_model_gateway_evidence%ROWTYPE;
    sent public.saas_model_gateway_evidence%ROWTYPE;
    outcome public.saas_model_gateway_evidence%ROWTYPE;
    price public.saas_pricing_snapshots%ROWTYPE;
    receipt public.saas_billing_metering_receipts%ROWTYPE;
    binding jsonb;
    request jsonb;
    usage jsonb;
    attrs jsonb;
    body jsonb;
    rate jsonb;
    expected_quantity numeric;
    expected_key text;
    expected_hash text;
    expected_outbox_key text;
    happened text;
BEGIN
    IF TG_TABLE_NAME='saas_usage_events' THEN
        u := NEW;
    ELSIF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        SELECT * INTO u FROM public.saas_usage_events WHERE id=NEW.usage_event_id;
    ELSE
        IF NEW.event_type<>'billing.usage.recorded' OR NEW.aggregate_type<>'billing' THEN
            RETURN NEW;
        END IF;
        SELECT * INTO u FROM public.saas_usage_events WHERE id::text=NEW.payload->>'usage_event_id';
        IF NOT FOUND THEN
            SELECT * INTO r FROM public.saas_runs WHERE id::text=NEW.payload->>'run_id';
            IF r.queue_class='managed_interactive' THEN
                RAISE EXCEPTION 'gateway Usage is missing' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    IF u.run_id IS NULL THEN RETURN NEW; END IF;
    SELECT * INTO r FROM public.saas_runs WHERE id=u.run_id;
    IF r.queue_class IS DISTINCT FROM 'managed_interactive' THEN RETURN NEW; END IF;
    IF NOT pg_has_role(session_user,'saas_metering','member') THEN
        RAISE EXCEPTION 'gateway customer usage requires machine metering' USING ERRCODE='23514';
    END IF;
    SELECT * INTO c FROM public.saas_capability_tokens
    WHERE token_hash=NULLIF(current_setting('app.capability_token_hash',true),'');
    SELECT * INTO certificate FROM public.saas_runner_certificates
    WHERE fingerprint_sha256=NULLIF(current_setting('app.presented_certificate_fingerprint',true),'')
      AND purpose='billing_metering';
    SELECT * INTO runner FROM public.saas_runner_registrations WHERE id=c.runner_id;
    SELECT * INTO budget FROM public.saas_model_provider_budget_reservations
    WHERE id=NULLIF(current_setting('app.model_budget_reservation_id',true),'')::uuid;
    IF c.id IS NULL OR certificate.id IS NULL OR runner.id IS NULL OR budget.id IS NULL
       OR NULLIF(current_setting('app.presented_certificate_purpose',true),'') IS DISTINCT FROM 'billing_metering'
       OR NOT (c.allowed_actions::jsonb @> '["run.execute","runtime.interactive.execute"]'::jsonb)
       OR jsonb_array_length(c.allowed_actions::jsonb)<>2
       OR (c.tenant_id,c.space_id,c.project_id,c.run_id)<>(r.tenant_id,r.space_id,r.project_id,r.id)
       OR (u.tenant_id,u.space_id,u.project_id)<>(r.tenant_id,r.space_id,r.project_id)
       OR certificate.runner_id<>c.runner_id
       OR certificate.runner_connection_generation<>c.runner_connection_generation
       OR runner.connection_generation<>c.runner_connection_generation
       OR runner.status NOT IN ('online','draining')
       OR certificate.certificate_not_before>statement_timestamp()
       OR certificate.certificate_not_after<=statement_timestamp()
       OR NOT (certificate.status='active' OR
          (certificate.status='retiring' AND certificate.retire_at>statement_timestamp()))
       OR budget.tenant_id<>r.tenant_id OR budget.run_id<>r.id OR budget.purpose<>'tenant_run'
       OR budget.provider_id<>'deepseek' OR budget.status NOT IN ('settled','released')
       OR budget.outcome_evidence_sha256 IS NULL
    THEN RAISE EXCEPTION 'gateway machine scope rejected' USING ERRCODE='23514'; END IF;
    SELECT * INTO original FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='request';
    SELECT * INTO sent FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase='in_flight';
    SELECT * INTO outcome FROM public.saas_model_gateway_evidence
    WHERE reservation_id=budget.id AND phase=budget.status;
    IF original.id IS NULL OR sent.id IS NULL OR outcome.id IS NULL
       OR encode(sha256(substring(original.canonical_evidence from 8)),'hex') IS DISTINCT FROM original.evidence_sha256
       OR convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2'
       OR encode(sha256(substring(sent.canonical_evidence from 8)),'hex') IS DISTINCT FROM sent.evidence_sha256
       OR convert_from(substring(sent.canonical_evidence from 8),'UTF8')::jsonb->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2'
       OR encode(sha256(substring(outcome.canonical_evidence from 8)),'hex') IS DISTINCT FROM outcome.evidence_sha256
       OR convert_from(substring(outcome.canonical_evidence from 8),'UTF8')::jsonb->>'contract' IS DISTINCT FROM 'platform-model-gateway-evidence-v2'
       OR convert_from(substring(sent.canonical_evidence from 8),'UTF8')::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR convert_from(substring(outcome.canonical_evidence from 8),'UTF8')::jsonb->>'request_evidence_sha256' IS DISTINCT FROM original.evidence_sha256
       OR budget.outcome_evidence_sha256<>outcome.evidence_sha256
       OR outcome.budget_version<>budget.version
       OR original.created_at<c.issued_at OR sent.created_at<original.created_at
       OR sent.created_at>=c.expires_at OR outcome.created_at<sent.created_at
       OR (c.revoked_at IS NOT NULL AND c.revoked_at<=sent.created_at)
    THEN RAISE EXCEPTION 'gateway metering evidence rejected' USING ERRCODE='23514'; END IF;
    request := convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->'request';
    binding := request->'run_binding';
    usage := convert_from(substring(outcome.canonical_evidence from 8),'UTF8')::jsonb->'usage';
    IF binding->>'capability_id' IS DISTINCT FROM c.id::text
       OR binding->>'fence_token' IS DISTINCT FROM c.fence_token::text
       OR binding->>'run_id' IS DISTINCT FROM r.id::text
       OR binding->>'space_id' IS DISTINCT FROM r.space_id::text
       OR binding->>'project_id' IS DISTINCT FROM r.project_id::text
       OR binding->>'session_id' IS DISTINCT FROM r.session_id::text
       OR binding->>'actor_id' IS DISTINCT FROM r.created_by::text
       OR binding->>'customer_pricing_snapshot_id' IS DISTINCT FROM r.customer_pricing_snapshot_id::text
       OR NOT r.customer_pricing_frozen OR r.created_by_service_account_id IS NOT NULL
       OR NOT (c.resource_scope::jsonb @> jsonb_build_object(
          'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
          'run_id',r.id::text,'runner_id',c.runner_id::text,'session_id',r.session_id::text))
       OR u.meter NOT IN ('llm.input_tokens','llm.output_tokens')
       OR u.unit<>'tokens' OR u.provider<>'deepseek'
       OR u.pricing_snapshot_id IS DISTINCT FROM r.customer_pricing_snapshot_id
       OR u.session_id IS DISTINCT FROM r.session_id OR u.user_id IS DISTINCT FROM r.created_by
       OR u.service_account_id IS NOT NULL
       OR u.occurred_at IS DISTINCT FROM original.created_at
       OR u.provider_request_id IS DISTINCT FROM 'model-gateway:'||budget.id::text
       OR (usage->>'total_tokens')::numeric IS DISTINCT FROM budget.settled_tokens::numeric
       OR (convert_from(substring(outcome.canonical_evidence from 8),'UTF8')::jsonb->>'actual_microusd')::numeric IS DISTINCT FROM budget.settled_microusd::numeric
    THEN RAISE EXCEPTION 'gateway customer binding rejected' USING ERRCODE='23514'; END IF;
    expected_quantity := (usage->>(CASE u.meter WHEN 'llm.input_tokens' THEN 'input_tokens' ELSE 'output_tokens' END))::numeric;
    expected_key := 'model-gateway:'||budget.id::text||':'||CASE u.meter WHEN 'llm.input_tokens' THEN 'input' ELSE 'output' END;
    attrs := jsonb_build_object('model',request->>'public_model_id','operation',
       CASE request->>'wire_api' WHEN 'openai_responses' THEN 'responses.create' ELSE 'chat.completions.create' END,
       'request_class','managed_gateway');
    SELECT * INTO price FROM public.saas_pricing_snapshots
    WHERE id=r.customer_pricing_snapshot_id AND tenant_id=r.tenant_id;
    rate := price.rates::jsonb->u.meter;
    IF expected_quantity IS NULL OR expected_quantity<=0 OR u.quantity IS DISTINCT FROM expected_quantity
       OR u.idempotency_key IS DISTINCT FROM expected_key OR u.attributes::jsonb IS DISTINCT FROM attrs
       OR price.id IS NULL OR u.currency IS DISTINCT FROM price.currency
       OR rate->>'unit' IS DISTINCT FROM 'tokens' OR (rate->>'unit_size')::numeric<=0
       OR (rate->>'minor_per_unit') !~ '^[1-9][0-9]{0,18}$'
       OR u.customer_charge_minor IS DISTINCT FROM
          ceil(expected_quantity/(rate->>'unit_size')::numeric*(rate->>'minor_per_unit')::numeric)::bigint
       OR NOT EXISTS (SELECT 1 FROM public.saas_billing_subscriptions s
           WHERE s.tenant_id=r.tenant_id AND s.status IN ('active','trialing'))
    THEN RAISE EXCEPTION 'gateway customer quantity or price rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_usage_events' THEN RETURN NEW; END IF;
    happened := convert_from(substring(original.canonical_evidence from 8),'UTF8')::jsonb->>'occurred_at';
    body := jsonb_build_object(
       'tenant_id',r.tenant_id::text,'space_id',r.space_id::text,'project_id',r.project_id::text,
       'session_id',r.session_id::text,'run_id',r.id::text,'actor_kind','user','user_id',r.created_by::text,
       'service_account_id',NULL,'runner_id',c.runner_id::text,'pricing_snapshot_id',price.id::text,
       'meter',u.meter,'quantity',u.quantity::bigint::text,'unit',u.unit,'provider',u.provider,
       'provider_request_id',u.provider_request_id,'occurred_at',happened,'attributes',attrs,
       'model_budget_reservation_id',budget.id::text);
    expected_hash := public.saas_canonical_json_sha256_v1(body);
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN
        receipt := NEW;
    ELSE
        SELECT * INTO receipt FROM public.saas_billing_metering_receipts
        WHERE id::text=NEW.payload->>'metering_receipt_id';
    END IF;
    IF receipt.id IS NULL OR receipt.usage_event_id<>u.id
       OR (receipt.tenant_id,receipt.space_id,receipt.project_id,receipt.run_id,receipt.runner_id)
          <>(r.tenant_id,r.space_id,r.project_id,r.id,c.runner_id)
       OR receipt.runner_certificate_id<>certificate.id
       OR receipt.certificate_fingerprint_sha256<>certificate.fingerprint_sha256
       OR receipt.capability_id<>c.id OR receipt.fence_token<>c.fence_token
       OR receipt.runner_connection_generation<>c.runner_connection_generation
       OR receipt.dispatch_generation<>c.dispatch_generation
       OR receipt.idempotency_key<>expected_key OR receipt.request_hash<>expected_hash
       OR receipt.model_budget_reservation_id IS DISTINCT FROM budget.id
    THEN RAISE EXCEPTION 'gateway customer receipt rejected' USING ERRCODE='23514'; END IF;
    IF TG_TABLE_NAME='saas_billing_metering_receipts' THEN RETURN NEW; END IF;
    expected_outbox_key := encode(sha256(convert_to('billing-metering','UTF8')||decode('00','hex')||
       convert_to(r.tenant_id::text,'UTF8')||decode('00','hex')||convert_to(expected_key,'UTF8')),'hex');
    IF NEW.tenant_id<>r.tenant_id OR NEW.aggregate_key<>u.id::text OR NEW.request_hash<>expected_hash
       OR NEW.idempotency_key<>expected_outbox_key
       OR NEW.payload::jsonb IS DISTINCT FROM body||jsonb_build_object(
          'usage_event_id',u.id::text,'metering_receipt_id',receipt.id::text,'capability_id',c.id::text,
          'runner_connection_generation',c.runner_connection_generation,'dispatch_generation',c.dispatch_generation,
          'fence_token',c.fence_token,'currency',price.currency,'customer_charge_minor',u.customer_charge_minor)
    THEN RAISE EXCEPTION 'gateway customer outbox rejected' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
$function$""",  # noqa: E501 - Preserve source-bound SQL bytes.
)
