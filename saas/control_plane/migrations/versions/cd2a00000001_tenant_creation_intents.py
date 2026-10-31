"""Unify authenticated workspace creation and retained registration onboarding."""

from __future__ import annotations

import json
import re

import sqlalchemy as sa
from alembic import op

revision = "cd2a00000001"
down_revision = "cd1c00000001"
branch_labels = None
depends_on = None

_TABLE = "saas_tenant_creation_intents"
_ACTOR = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_REGISTRATION = "NULLIF(current_setting('app.registration_id', true), '')::uuid"
_INTENT = (
    "COALESCE(NULLIF(current_setting('app.creation_intent_id', true), ''), "
    "NULLIF(current_setting('app.registration_id', true), ''))::uuid"
)
_COPY_FIELDS = (
    "user_id",
    "tenant_name",
    "tenant_slug",
    "default_space_name",
    "default_space_slug",
    "plan_key",
    "plan_policy_revision",
    "home_region",
    "plan_snapshot",
    "plan_snapshot_hash",
    "tenant_id",
    "space_id",
    "subscription_id",
    "pricing_snapshot_id",
    "entitlement_id",
    "runtime_partition_id",
    "default_project_id",
    "runtime_binding_id",
    "onboarding_id",
    "idempotency_key",
    "request_hash",
    "created_at",
)
_RESOURCE_IDS = (
    "tenant_id",
    "space_id",
    "subscription_id",
    "pricing_snapshot_id",
    "entitlement_id",
    "runtime_partition_id",
    "default_project_id",
    "runtime_binding_id",
    "onboarding_id",
)
_BRIDGE_TAG = "tenant-creation-intent-bridge-v1"


def _owner(table: str) -> str:
    return (
        "current_user = pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class "
        f"WHERE oid = 'public.{table}'::regclass))"
    )


def _create_table() -> None:
    columns = [
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("saas_global_users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "registration_id",
            sa.Uuid(),
            sa.ForeignKey("saas_self_service_registrations.id", ondelete="RESTRICT"),
            unique=True,
        ),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("plan_snapshot", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        *[
            sa.Column(name, sa.String(length), nullable=False)
            for name, length in (
                ("tenant_name", 256),
                ("tenant_slug", 128),
                ("default_space_name", 256),
                ("default_space_slug", 128),
                ("plan_key", 64),
                ("plan_policy_revision", 128),
                ("home_region", 64),
                ("plan_snapshot_hash", 64),
                ("idempotency_key", 64),
                ("request_hash", 64),
            )
        ],
        *[sa.Column(name, sa.Uuid(), nullable=False, unique=True) for name in _RESOURCE_IDS],
    ]
    op.create_table(
        _TABLE,
        *columns,
        sa.UniqueConstraint("tenant_slug", name="uq_creation_intent_slug"),
        sa.UniqueConstraint("idempotency_key", name="uq_creation_intent_idempotency"),
        sa.UniqueConstraint("id", "onboarding_id", name="uq_creation_intent_onboarding_scope"),
        sa.CheckConstraint("status IN ('ready', 'revoked')", name="ck_creation_intent_status"),
        sa.CheckConstraint(
            "(source = 'registration' AND registration_id IS NOT NULL AND id = registration_id) "
            "OR (source = 'authenticated' AND registration_id IS NULL)",
            name="ck_creation_intent_source",
        ),
        sa.CheckConstraint(
            "length(tenant_name) BETWEEN 1 AND 256 AND length(default_space_name) "
            "BETWEEN 1 AND 256 AND "
            "length(tenant_slug) BETWEEN 1 AND 128 AND tenant_slug = lower(tenant_slug) AND "
            "length(default_space_slug) BETWEEN 1 AND 128 AND default_space_slug = "
            "lower(default_space_slug)",
            name="ck_creation_intent_names",
        ),
        sa.CheckConstraint(
            "length(plan_key) BETWEEN 1 AND 64 AND length(plan_policy_revision) BETWEEN "
            "1 AND 128 AND "
            "length(home_region) BETWEEN 1 AND 64 AND length(plan_snapshot_hash) = 64 AND "
            "length(CAST(plan_snapshot AS TEXT)) > 2 AND length(idempotency_key) = 64 "
            "AND length(request_hash) = 64",
            name="ck_creation_intent_snapshot",
        ),
    )
    op.create_index("ix_creation_intent_actor_created", _TABLE, ["user_id", "created_at", "id"])


def _translate(expression: str | None) -> str | None:
    if expression is None:
        return None
    translated = expression.replace("saas_self_service_registrations", _TABLE)
    translated = re.sub(r"\bregistration_id\b", "creation_intent_id", translated)
    translated = translated.replace("'verified'::text", "'ready'::text")
    return translated.replace(
        "NULLIF(current_setting('app.creation_intent_id'::text, true), ''::text)",
        "COALESCE(NULLIF(current_setting('app.creation_intent_id'::text, true), ''::text), "
        "NULLIF(current_setting('app.registration_id'::text, true), ''::text))",
    )


def _bridge_policies() -> None:
    bind = op.get_bind()
    quote = bind.dialect.identifier_preparer.quote
    policies = (
        bind.execute(
            sa.text(
                "SELECT c.relname, p.polname, pg_get_expr(p.polqual, p.polrelid) AS qual, "
                "pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr, "
                "obj_description(p.oid, 'pg_policy') AS comment FROM pg_policy p "
                "JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public' AND 'saas_onboarding'::regrole=ANY(p.polroles) "
                "AND c.relname NOT IN ('saas_self_service_registrations', "
                "'saas_tenant_creation_intents') "
                "ORDER BY c.relname, p.polname"
            )
        )
        .mappings()
        .all()
    )
    for row in policies:
        clauses = []
        changed = False
        for key, clause in (("qual", "USING"), ("check_expr", "WITH CHECK")):
            original = row[key]
            translated = _translate(original)
            changed |= translated != original
            if original is not None:
                clauses.append(f"{clause} (({original}) OR ({translated}))")
        if not changed:
            continue
        target = f"{quote(row['polname'])} ON public.{quote(row['relname'])}"
        op.execute(f"ALTER POLICY {target} " + " ".join(clauses))
        receipt = json.dumps(
            {
                "tag": _BRIDGE_TAG,
                "qual": row["qual"],
                "check": row["check_expr"],
                "comment": row["comment"],
            }
        )
        literal = "'" + receipt.replace("'", "''") + "'"
        op.execute(f"COMMENT ON POLICY {target} IS {literal}")


def _install_authority() -> None:
    op.execute(
        "CREATE POLICY rls_auth_session_scope_migration_read ON saas_auth_sessions "
        "FOR SELECT USING (active_tenant_id IS NOT NULL AND "
        f"{_owner('saas_auth_sessions')})"
    )
    op.execute(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_creation_intent_migration_read ON {_TABLE} FOR SELECT USING "
        f"({_owner(_TABLE)})"
    )
    actor_read = (
        f"user_id = {_ACTOR} OR EXISTS (SELECT 1 FROM saas_tenant_memberships m "
        f"WHERE m.tenant_id = {_TABLE}.tenant_id AND m.user_id = {_ACTOR} AND m.status = 'active')"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_actor_read ON {_TABLE} FOR SELECT TO "
        f"saas_authenticator, saas_onboarding_status USING ({actor_read})"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_worker_read ON {_TABLE} FOR SELECT TO "
        f"saas_onboarding USING (id = {_INTENT})"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_worker_lock ON {_TABLE} FOR UPDATE TO "
        f"saas_onboarding USING (id = {_INTENT} AND status = 'ready') "
        f"WITH CHECK (id = {_INTENT} AND status = 'ready')"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_registration_read ON {_TABLE} FOR SELECT TO "
        f"saas_registration USING (registration_id = {_REGISTRATION})"
    )
    verified = (
        f"user_id = {_ACTOR} AND source = 'authenticated' AND registration_id IS NULL "
        f"AND status = 'ready' "
        f"AND EXISTS (SELECT 1 FROM saas_global_users u WHERE u.id = {_ACTOR} AND "
        f"u.status = 'active') "
        f"AND EXISTS (SELECT 1 FROM saas_identity_connections i WHERE i.user_id = {_ACTOR} "
        "AND i.status = 'active' AND i.email_verified AND i.email_normalized IS NOT NULL)"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_actor_insert ON {_TABLE} FOR INSERT TO "
        f"saas_authenticator WITH CHECK ({verified})"
    )
    same_fields = " AND ".join(
        f"r.{field} = {_TABLE}.{field}"
        for field in _COPY_FIELDS
        if field not in {"plan_snapshot", "created_at"}
    )
    legacy = (
        f"source = 'registration' AND status = 'ready' AND id = registration_id "
        f"AND registration_id = {_REGISTRATION} AND EXISTS (SELECT 1 FROM "
        "saas_self_service_registrations r WHERE r.id = registration_id "
        f"AND r.status = 'verified' AND {same_fields})"
    )
    op.execute(
        f"CREATE POLICY rls_creation_intent_legacy_insert ON {_TABLE} FOR INSERT TO "
        f"saas_registration, saas_onboarding WITH CHECK ({legacy})"
    )
    outbox = (
        "event_type <> 'onboarding.tenant.requested' OR (tenant_id IS NULL "
        "AND aggregate_type = 'tenant_onboarding' AND EXISTS (SELECT 1 "
        f"FROM {_TABLE} i WHERE i.id::text = payload->>'creation_intent_id' "
        f"AND i.user_id = {_ACTOR} AND i.source = 'authenticated' AND i.status = 'ready' "
        "AND i.onboarding_id::text = aggregate_key AND i.user_id::text = payload->>'user_id' "
        "AND i.tenant_id::text = payload->>'tenant_id'))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_creation_intent ON saas_control_plane_outbox AS "
        "RESTRICTIVE FOR INSERT TO saas_authenticator WITH CHECK (" + outbox + ")"
    )
    status_read = (
        f"EXISTS (SELECT 1 FROM {_TABLE} i WHERE i.id = creation_intent_id "
        f"AND (i.user_id = {_ACTOR} OR EXISTS (SELECT 1 FROM saas_tenant_memberships m "
        f"WHERE m.tenant_id = i.tenant_id AND m.user_id = {_ACTOR} AND m.status = 'active')))"
    )
    op.execute(
        "CREATE POLICY rls_onboarding_creation_intent_status ON saas_tenant_onboardings "
        "FOR SELECT TO saas_onboarding_status USING (" + status_read + ")"
    )
    _bridge_policies()


def upgrade() -> None:
    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    _create_table()
    with op.batch_alter_table("saas_auth_sessions") as batch:
        batch.add_column(sa.Column("active_tenant_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("active_space_id", sa.Uuid(), nullable=True))
        batch.create_check_constraint(
            "ck_auth_session_active_scope",
            "(active_tenant_id IS NULL AND active_space_id IS NULL) OR "
            "(active_tenant_id IS NOT NULL AND active_space_id IS NOT NULL)",
        )
        batch.create_foreign_key(
            "fk_auth_session_active_scope",
            "saas_spaces",
            ["active_tenant_id", "active_space_id"],
            ["tenant_id", "id"],
            ondelete="RESTRICT",
        )
    if postgres:
        for table in ("saas_self_service_registrations", "saas_tenant_onboardings"):
            op.execute(
                f"CREATE POLICY rls_creation_intent_backfill ON {table} FOR ALL USING "
                f"({_owner(table)}) WITH CHECK ({_owner(table)})"
            )
    columns = ", ".join(_COPY_FIELDS)
    op.execute(
        f"INSERT INTO {_TABLE} (id, registration_id, source, status, {columns}) "
        "SELECT id, id, 'registration', CASE WHEN status = 'verified' THEN 'ready' "
        f"ELSE 'revoked' END, {columns} FROM saas_self_service_registrations r "
        "WHERE status = 'verified' OR EXISTS (SELECT 1 FROM saas_tenant_onboardings s "
        "WHERE s.registration_id = r.id)"
    )
    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.add_column(sa.Column("creation_intent_id", sa.Uuid(), nullable=True))
        batch.alter_column("registration_id", existing_type=sa.Uuid(), nullable=True)
        batch.create_unique_constraint(
            "uq_tenant_onboarding_creation_intent", ["creation_intent_id"]
        )
        batch.create_foreign_key(
            "fk_tenant_onboarding_creation_intent",
            _TABLE,
            ["creation_intent_id", "id"],
            ["id", "onboarding_id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_creation_source",
            "registration_id IS NOT NULL OR creation_intent_id IS NOT NULL",
        )
    op.execute("UPDATE saas_tenant_onboardings SET creation_intent_id = registration_id")
    if postgres:
        for table in ("saas_self_service_registrations", "saas_tenant_onboardings"):
            op.execute(f"DROP POLICY rls_creation_intent_backfill ON {table}")
        _install_authority()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT id FROM {_TABLE} LIMIT 1")).first() is not None:
        raise RuntimeError("retained workspace intents require application-only rollback")
    if (
        bind.execute(
            sa.text("SELECT id FROM saas_auth_sessions WHERE active_tenant_id IS NOT NULL LIMIT 1")
        ).first()
        is not None
    ):
        raise RuntimeError("retained workspace selections require application-only rollback")
    if bind.dialect.name == "postgresql":
        quote = bind.dialect.identifier_preparer.quote
        rows = (
            bind.execute(
                sa.text(
                    "SELECT c.relname, p.polname, obj_description(p.oid, 'pg_policy') AS receipt "
                    "FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
                    "AND obj_description(p.oid, 'pg_policy') LIKE "
                    "'%tenant-creation-intent-bridge-v1%'"
                )
            )
            .mappings()
            .all()
        )
        for row in rows:
            receipt = json.loads(row["receipt"])
            if receipt["tag"] != _BRIDGE_TAG:
                raise RuntimeError("creation intent rollback policy receipt is invalid")
            target = f"{quote(row['polname'])} ON public.{quote(row['relname'])}"
            clauses = [
                f"{clause} ({receipt[key]})"
                for key, clause in (("qual", "USING"), ("check", "WITH CHECK"))
                if receipt[key] is not None
            ]
            op.execute(f"ALTER POLICY {target} " + " ".join(clauses))
            comment = receipt["comment"]
            literal = "NULL" if comment is None else "'" + comment.replace("'", "''") + "'"
            op.execute(f"COMMENT ON POLICY {target} IS {literal}")
        op.execute("DROP POLICY rls_outbox_creation_intent ON saas_control_plane_outbox")
        op.execute("DROP POLICY rls_onboarding_creation_intent_status ON saas_tenant_onboardings")
        op.execute("DROP POLICY rls_auth_session_scope_migration_read ON saas_auth_sessions")
    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.drop_constraint("fk_tenant_onboarding_creation_intent", type_="foreignkey")
        batch.drop_constraint("uq_tenant_onboarding_creation_intent", type_="unique")
        batch.drop_constraint("ck_tenant_onboarding_creation_source", type_="check")
        batch.drop_column("creation_intent_id")
        batch.alter_column("registration_id", existing_type=sa.Uuid(), nullable=False)
    op.drop_table(_TABLE)
    with op.batch_alter_table("saas_auth_sessions") as batch:
        batch.drop_constraint("fk_auth_session_active_scope", type_="foreignkey")
        batch.drop_constraint("ck_auth_session_active_scope", type_="check")
        batch.drop_column("active_tenant_id")
        batch.drop_column("active_space_id")
