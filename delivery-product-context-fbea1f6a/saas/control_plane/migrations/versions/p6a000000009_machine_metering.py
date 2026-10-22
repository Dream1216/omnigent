"""Bind billing Usage to current Runner certificate, capability, and Run fence.

Revision ID: p6a000000009
Revises: p6a000000008
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "p6a000000009"
down_revision: str | None = "p6a000000008"
branch_labels: str | None = None
depends_on: str | None = None

_METERING = "pg_has_role(current_user, 'saas_metering', 'member')"
_BILLING = "pg_has_role(current_user, 'saas_billing', 'member')"
_PLATFORM = "pg_has_role(current_user, 'saas_platform', 'member')"
_EXECUTOR = "pg_has_role(current_user, 'saas_executor', 'member')"
_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
_CAPABILITY_HASH = "NULLIF(current_setting('app.capability_token_hash', true), '')"
_FINGERPRINT = "NULLIF(current_setting('app.presented_certificate_fingerprint', true), '')"
_PURPOSE = "NULLIF(current_setting('app.presented_certificate_purpose', true), '')"
_IDEMPOTENCY = "NULLIF(current_setting('app.metering_idempotency_key', true), '')"
_PROVIDER = "NULLIF(current_setting('app.metering_provider', true), '')"
_PROVIDER_REQUEST = "NULLIF(current_setting('app.metering_provider_request_id', true), '')"
_METER = "NULLIF(current_setting('app.metering_meter', true), '')"


def _replace_certificate_purpose_constraint(*, include_metering: bool) -> None:
    purposes = "'preview_tunnel', 'secret_broker'"
    if include_metering:
        purposes += ", 'billing_metering'"
    with op.batch_alter_table("saas_runner_certificates") as batch:
        batch.drop_constraint("ck_runner_certificate_purpose", type_="check")
        batch.create_check_constraint(
            "ck_runner_certificate_purpose",
            f"purpose IN ({purposes})",
        )


def _create_receipt_table() -> None:
    op.create_table(
        "saas_billing_metering_receipts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("usage_event_id", sa.Uuid(), nullable=False),
        sa.Column("runner_id", sa.Uuid(), nullable=False),
        sa.Column("runner_connection_generation", sa.BigInteger(), nullable=False),
        sa.Column("runner_certificate_id", sa.Uuid(), nullable=False),
        sa.Column("certificate_fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("capability_id", sa.Uuid(), nullable=False),
        sa.Column("dispatch_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_token", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "runner_connection_generation > 0",
            name="ck_billing_metering_receipt_runner_generation",
        ),
        sa.CheckConstraint(
            "dispatch_generation > 0",
            name="ck_billing_metering_receipt_dispatch_generation",
        ),
        sa.CheckConstraint("fence_token > 0", name="ck_billing_metering_receipt_fence"),
        sa.CheckConstraint(
            "length(certificate_fingerprint_sha256) = 64",
            name="ck_billing_metering_receipt_fingerprint",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0",
            name="ck_billing_metering_receipt_idempotency",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_billing_metering_receipt_request_hash",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "space_id", "project_id", "run_id"],
            ["saas_runs.tenant_id", "saas_runs.space_id", "saas_runs.project_id", "saas_runs.id"],
            name="fk_billing_metering_receipt_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "usage_event_id"],
            ["saas_usage_events.tenant_id", "saas_usage_events.id"],
            name="fk_billing_metering_receipt_usage",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["runner_id"],
            ["saas_runner_registrations.id"],
            name="fk_billing_metering_receipt_runner",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["runner_certificate_id"],
            ["saas_runner_certificates.id"],
            name="fk_billing_metering_receipt_certificate",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["capability_id"],
            ["saas_capability_tokens.id"],
            name="fk_billing_metering_receipt_capability",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_billing_metering_receipt_scope"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_billing_metering_receipt_idempotency",
        ),
        sa.UniqueConstraint("usage_event_id", name="uq_billing_metering_receipt_usage"),
    )
    op.create_index(
        "ix_billing_metering_receipt_run",
        "saas_billing_metering_receipts",
        ["tenant_id", "run_id", "recorded_at"],
    )
    op.create_index(
        "ix_billing_metering_receipt_runner",
        "saas_billing_metering_receipts",
        ["runner_id", "runner_connection_generation", "recorded_at"],
    )


def _capability_exists(alias: str, *, row_tenant: str | None = None) -> str:
    tenant_clause = ""
    if row_tenant is not None:
        tenant_clause = f" AND {alias}.tenant_id = {row_tenant}"
    return (
        f"EXISTS (SELECT 1 FROM saas_capability_tokens {alias} "
        f"WHERE {alias}.token_hash = {_CAPABILITY_HASH}{tenant_clause})"
    )


def _install_postgresql_policies() -> None:
    billing_scope = f"({_PLATFORM} OR ({_BILLING} AND tenant_id = {_TENANT}))"
    for table in (
        "saas_billing_subscriptions",
        "saas_pricing_snapshots",
        "saas_usage_events",
    ):
        op.execute(f'DROP POLICY "rls_{table}_tenant" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant" ON "{table}" FOR ALL '
            f"USING ({billing_scope}) WITH CHECK ({billing_scope})"
        )

    execution_scope = f"({_PLATFORM} OR {_EXECUTOR})"
    for table in ("saas_run_dispatches", "saas_capability_tokens"):
        op.execute(f'DROP POLICY "rls_{table}_scope" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({execution_scope}) WITH CHECK ({execution_scope})"
        )

    op.execute(
        'CREATE POLICY "rls_capability_tokens_metering_exact" '
        'ON "saas_capability_tokens" FOR SELECT USING ('
        f"{_METERING} AND token_hash = {_CAPABILITY_HASH})"
    )
    op.execute(
        'CREATE POLICY "rls_capability_tokens_metering_lock" '
        'ON "saas_capability_tokens" FOR UPDATE USING ('
        f"{_METERING} AND token_hash = {_CAPABILITY_HASH}) WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_runner_certificates_metering_exact" '
        'ON "saas_runner_certificates" FOR SELECT USING ('
        f"{_METERING} AND purpose = 'billing_metering' "
        f"AND {_PURPOSE} = 'billing_metering' AND fingerprint_sha256 = {_FINGERPRINT} "
        "AND certificate_not_before <= CURRENT_TIMESTAMP "
        "AND certificate_not_after > CURRENT_TIMESTAMP "
        "AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP)))"
    )
    op.execute(
        'CREATE POLICY "rls_runner_certificates_metering_lock" '
        'ON "saas_runner_certificates" FOR UPDATE USING ('
        f"{_METERING} AND purpose = 'billing_metering' "
        f"AND {_PURPOSE} = 'billing_metering' AND fingerprint_sha256 = {_FINGERPRINT} "
        "AND certificate_not_before <= CURRENT_TIMESTAMP "
        "AND certificate_not_after > CURRENT_TIMESTAMP "
        "AND (status = 'active' OR (status = 'retiring' AND retire_at > CURRENT_TIMESTAMP))) "
        "WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_runner_registrations_metering_exact" '
        'ON "saas_runner_registrations" FOR SELECT USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_runner_certificates certificate "
        "WHERE certificate.runner_id = saas_runner_registrations.id "
        "AND certificate.runner_connection_generation = "
        "saas_runner_registrations.connection_generation "
        f"AND certificate.fingerprint_sha256 = {_FINGERPRINT} "
        "AND certificate.purpose = 'billing_metering' "
        f"AND {_PURPOSE} = 'billing_metering'))"
    )
    op.execute(
        'CREATE POLICY "rls_runner_registrations_metering_lock" '
        'ON "saas_runner_registrations" FOR UPDATE USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_runner_certificates certificate "
        "WHERE certificate.runner_id = saas_runner_registrations.id "
        "AND certificate.runner_connection_generation = "
        "saas_runner_registrations.connection_generation "
        f"AND certificate.fingerprint_sha256 = {_FINGERPRINT} "
        "AND certificate.purpose = 'billing_metering' "
        f"AND {_PURPOSE} = 'billing_metering')) WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_runs_metering_exact" ON "saas_runs" FOR SELECT USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.run_id = saas_runs.id "
        f"AND capability.token_hash = {_CAPABILITY_HASH}))"
    )
    op.execute(
        'CREATE POLICY "rls_runs_metering_lock" ON "saas_runs" FOR UPDATE USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.run_id = saas_runs.id "
        f"AND capability.token_hash = {_CAPABILITY_HASH})) WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_run_dispatches_metering_exact" '
        'ON "saas_run_dispatches" FOR SELECT USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.run_id = saas_run_dispatches.run_id "
        f"AND capability.token_hash = {_CAPABILITY_HASH}))"
    )
    op.execute(
        'CREATE POLICY "rls_run_dispatches_metering_lock" '
        'ON "saas_run_dispatches" FOR UPDATE USING ('
        f"{_METERING} AND EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.run_id = saas_run_dispatches.run_id "
        f"AND capability.token_hash = {_CAPABILITY_HASH})) WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_billing_subscriptions_metering_exact" '
        'ON "saas_billing_subscriptions" FOR SELECT USING ('
        f"{_METERING} AND "
        f"{_capability_exists('capability', row_tenant='saas_billing_subscriptions.tenant_id')})"
    )
    op.execute(
        'CREATE POLICY "rls_billing_subscriptions_metering_lock" '
        'ON "saas_billing_subscriptions" FOR UPDATE USING ('
        f"{_METERING} AND "
        f"{_capability_exists('capability', row_tenant='saas_billing_subscriptions.tenant_id')}) "
        "WITH CHECK (false)"
    )
    op.execute(
        'CREATE POLICY "rls_pricing_snapshots_metering_exact" '
        'ON "saas_pricing_snapshots" FOR SELECT USING ('
        f"{_METERING} AND "
        f"{_capability_exists('capability', row_tenant='saas_pricing_snapshots.tenant_id')})"
    )

    usage_capability = (
        "EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.token_hash = "
        f"{_CAPABILITY_HASH} AND capability.tenant_id = saas_usage_events.tenant_id "
        "AND capability.space_id = saas_usage_events.space_id "
        "AND capability.project_id = saas_usage_events.project_id "
        "AND capability.run_id = saas_usage_events.run_id)"
    )
    usage_exact_request = (
        f"(idempotency_key = {_IDEMPOTENCY} OR "
        f"(provider = {_PROVIDER} AND provider_request_id = {_PROVIDER_REQUEST} "
        f"AND meter = {_METER}))"
    )
    op.execute(
        'CREATE POLICY "rls_usage_events_metering_select" '
        'ON "saas_usage_events" FOR SELECT USING ('
        f"{_METERING} AND {usage_capability} AND {usage_exact_request})"
    )
    usage_insert = (
        "EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.token_hash = "
        f"{_CAPABILITY_HASH} AND capability.tenant_id = saas_usage_events.tenant_id "
        "AND capability.space_id = saas_usage_events.space_id "
        "AND capability.project_id = saas_usage_events.project_id "
        "AND capability.run_id = saas_usage_events.run_id) "
        "AND saas_usage_events.session_id IS NOT DISTINCT FROM "
        "NULLIF(current_setting('app.metering_session_id', true), '')::uuid "
        "AND saas_usage_events.user_id = "
        "NULLIF(current_setting('app.metering_user_id', true), '')::uuid"
    )
    op.execute(
        'CREATE POLICY "rls_usage_events_metering_insert" '
        'ON "saas_usage_events" FOR INSERT WITH CHECK ('
        f"{_METERING} AND {usage_insert} AND idempotency_key = {_IDEMPOTENCY} "
        f"AND provider = {_PROVIDER} AND provider_request_id = {_PROVIDER_REQUEST} "
        f"AND meter = {_METER})"
    )

    op.execute('ALTER TABLE "saas_billing_metering_receipts" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "saas_billing_metering_receipts" FORCE ROW LEVEL SECURITY')
    receipt_billing_scope = f"({_PLATFORM} OR ({_BILLING} AND tenant_id = {_TENANT}))"
    op.execute(
        'CREATE POLICY "rls_billing_metering_receipts_billing" '
        'ON "saas_billing_metering_receipts" FOR ALL '
        f"USING ({receipt_billing_scope}) WITH CHECK ({receipt_billing_scope})"
    )
    receipt_capability = (
        "EXISTS (SELECT 1 FROM saas_capability_tokens capability "
        "WHERE capability.token_hash = "
        f"{_CAPABILITY_HASH} "
        "AND capability.id = saas_billing_metering_receipts.capability_id "
        "AND capability.tenant_id = saas_billing_metering_receipts.tenant_id "
        "AND capability.space_id = saas_billing_metering_receipts.space_id "
        "AND capability.project_id = saas_billing_metering_receipts.project_id "
        "AND capability.run_id = saas_billing_metering_receipts.run_id "
        "AND capability.runner_id = saas_billing_metering_receipts.runner_id "
        "AND capability.runner_connection_generation = "
        "saas_billing_metering_receipts.runner_connection_generation "
        "AND capability.dispatch_generation = "
        "saas_billing_metering_receipts.dispatch_generation "
        "AND capability.fence_token = saas_billing_metering_receipts.fence_token)"
    )
    receipt_certificate = (
        "EXISTS (SELECT 1 FROM saas_runner_certificates certificate "
        "WHERE certificate.id = saas_billing_metering_receipts.runner_certificate_id "
        "AND certificate.runner_id = saas_billing_metering_receipts.runner_id "
        "AND certificate.runner_connection_generation = "
        "saas_billing_metering_receipts.runner_connection_generation "
        "AND certificate.purpose = 'billing_metering' "
        f"AND certificate.fingerprint_sha256 = {_FINGERPRINT} "
        "AND certificate.fingerprint_sha256 = "
        "saas_billing_metering_receipts.certificate_fingerprint_sha256)"
    )
    op.execute(
        'CREATE POLICY "rls_billing_metering_receipts_metering_select" '
        'ON "saas_billing_metering_receipts" FOR SELECT USING ('
        f"{_METERING} AND idempotency_key = {_IDEMPOTENCY} AND {receipt_capability})"
    )
    op.execute(
        'CREATE POLICY "rls_billing_metering_receipts_metering_insert" '
        'ON "saas_billing_metering_receipts" FOR INSERT WITH CHECK ('
        f"{_METERING} AND idempotency_key = {_IDEMPOTENCY} "
        f"AND {receipt_capability} AND {receipt_certificate})"
    )
    op.execute(
        'CREATE TRIGGER "trg_saas_billing_metering_receipts_immutable" '
        'BEFORE UPDATE OR DELETE ON "saas_billing_metering_receipts" '
        "FOR EACH ROW EXECUTE FUNCTION saas_reject_billing_fact_mutation()"
    )

    op.execute('DROP POLICY "rls_outbox_insert" ON "saas_control_plane_outbox"')
    op.execute(
        'CREATE POLICY "rls_outbox_insert" ON "saas_control_plane_outbox" '
        "FOR INSERT WITH CHECK ("
        f"NOT {_METERING} AND ("
        "pg_has_role(current_user, 'saas_dispatcher', 'member') OR "
        "pg_has_role(current_user, 'saas_webhook_dispatcher', 'member') OR "
        f"{_PLATFORM} OR tenant_id = {_TENANT} OR "
        "((pg_has_role(current_user, 'saas_authenticator', 'member') OR "
        "pg_has_role(current_user, 'saas_governance', 'member')) AND tenant_id IS NULL)))"
    )
    op.execute(
        'CREATE POLICY "rls_outbox_metering_insert" '
        'ON "saas_control_plane_outbox" FOR INSERT WITH CHECK ('
        f"{_METERING} AND tenant_id = {_TENANT} AND aggregate_type = 'billing' "
        "AND event_type = 'billing.usage.recorded' "
        "AND aggregate_key = payload ->> 'usage_event_id' "
        "AND length(payload ->> 'metering_receipt_id') > 0 "
        "AND length(payload ->> 'capability_id') > 0 "
        "AND payload ->> 'tenant_id' = tenant_id::text)"
    )


def _restore_postgresql_policies() -> None:
    op.execute('DROP POLICY "rls_outbox_metering_insert" ON "saas_control_plane_outbox"')
    op.execute('DROP POLICY "rls_outbox_insert" ON "saas_control_plane_outbox"')
    op.execute(
        'CREATE POLICY "rls_outbox_insert" ON "saas_control_plane_outbox" '
        "FOR INSERT WITH CHECK ("
        "pg_has_role(current_user, 'saas_dispatcher', 'member') OR "
        "pg_has_role(current_user, 'saas_webhook_dispatcher', 'member') OR "
        f"{_PLATFORM} OR tenant_id = {_TENANT} OR "
        "((pg_has_role(current_user, 'saas_authenticator', 'member') OR "
        "pg_has_role(current_user, 'saas_governance', 'member')) AND tenant_id IS NULL))"
    )
    op.execute(
        'DROP TRIGGER "trg_saas_billing_metering_receipts_immutable" '
        'ON "saas_billing_metering_receipts"'
    )
    for policy in (
        "rls_billing_metering_receipts_metering_insert",
        "rls_billing_metering_receipts_metering_select",
        "rls_billing_metering_receipts_billing",
    ):
        op.execute(f'DROP POLICY "{policy}" ON "saas_billing_metering_receipts"')
    for policy, table in (
        ("rls_usage_events_metering_insert", "saas_usage_events"),
        ("rls_usage_events_metering_select", "saas_usage_events"),
        ("rls_pricing_snapshots_metering_exact", "saas_pricing_snapshots"),
        ("rls_billing_subscriptions_metering_lock", "saas_billing_subscriptions"),
        ("rls_billing_subscriptions_metering_exact", "saas_billing_subscriptions"),
        ("rls_run_dispatches_metering_lock", "saas_run_dispatches"),
        ("rls_run_dispatches_metering_exact", "saas_run_dispatches"),
        ("rls_runs_metering_lock", "saas_runs"),
        ("rls_runs_metering_exact", "saas_runs"),
        ("rls_runner_registrations_metering_lock", "saas_runner_registrations"),
        ("rls_runner_registrations_metering_exact", "saas_runner_registrations"),
        ("rls_runner_certificates_metering_lock", "saas_runner_certificates"),
        ("rls_runner_certificates_metering_exact", "saas_runner_certificates"),
        ("rls_capability_tokens_metering_lock", "saas_capability_tokens"),
        ("rls_capability_tokens_metering_exact", "saas_capability_tokens"),
    ):
        op.execute(f'DROP POLICY "{policy}" ON "{table}"')

    legacy_execution_scope = (
        f"({_PLATFORM} OR {_EXECUTOR} OR (tenant_id = {_TENANT} "
        "AND space_id = NULLIF(current_setting('app.space_id', true), '')::uuid))"
    )
    for table in ("saas_run_dispatches", "saas_capability_tokens"):
        op.execute(f'DROP POLICY "rls_{table}_scope" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_scope" ON "{table}" FOR ALL '
            f"USING ({legacy_execution_scope}) WITH CHECK ({legacy_execution_scope})"
        )

    legacy_billing_scope = f"({_PLATFORM} OR tenant_id = {_TENANT})"
    for table in (
        "saas_billing_subscriptions",
        "saas_pricing_snapshots",
        "saas_usage_events",
    ):
        op.execute(f'DROP POLICY "rls_{table}_tenant" ON "{table}"')
        op.execute(
            f'CREATE POLICY "rls_{table}_tenant" ON "{table}" FOR ALL '
            f"USING ({legacy_billing_scope}) WITH CHECK ({legacy_billing_scope})"
        )


def upgrade() -> None:
    _replace_certificate_purpose_constraint(include_metering=True)
    _create_receipt_table()
    if op.get_bind().dialect.name == "postgresql":
        _install_postgresql_policies()


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        _restore_postgresql_policies()
    op.drop_index(
        "ix_billing_metering_receipt_runner",
        table_name="saas_billing_metering_receipts",
    )
    op.drop_index(
        "ix_billing_metering_receipt_run",
        table_name="saas_billing_metering_receipts",
    )
    op.drop_table("saas_billing_metering_receipts")
    # The previous schema has no purpose capable of representing these
    # certificates. A p6a9 downgrade is explicitly destructive for machine
    # metering, so remove its now-unusable credentials before restoring the
    # narrower purpose constraint.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE saas_runner_certificates "
            "DISABLE TRIGGER trg_reject_runner_certificate_delete"
        )
    op.execute(sa.text("DELETE FROM saas_runner_certificates WHERE purpose = 'billing_metering'"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE saas_runner_certificates "
            "ENABLE TRIGGER trg_reject_runner_certificate_delete"
        )
    _replace_certificate_purpose_constraint(include_metering=False)
