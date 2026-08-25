"""Add P0 self-service registration and durable Tenant onboarding.

Revision ID: p0s000000001
Revises: pc5a00000005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000001"
down_revision: str | None = "pc5a00000005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REGISTRATION_ROLE = "pg_has_role(current_user, 'saas_registration', 'member')"
_ONBOARDING_ROLE = "pg_has_role(current_user, 'saas_onboarding', 'member')"
_PLATFORM_ROLE = "pg_has_role(current_user, 'saas_platform', 'member')"
_REGISTRATION_ID = "NULLIF(current_setting('app.registration_id', true), '')::uuid"
_REGISTRATION_TOKEN_HASH = "NULLIF(current_setting('app.registration_token_hash', true), '')"
_REGISTRATION_EMAIL_HASH = "NULLIF(current_setting('app.registration_email_hash', true), '')"
_REGISTRATION_IDEMPOTENCY_KEY = (
    "NULLIF(current_setting('app.registration_idempotency_key', true), '')"
)
_ONBOARDING_ID = "NULLIF(current_setting('app.onboarding_id', true), '')::uuid"
_ACTOR_ID = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_TENANT_ID = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

_NEW_TABLES = (
    "saas_self_service_registrations",
    "saas_email_verification_challenges",
    "saas_tenant_onboardings",
    "saas_self_service_events",
)


def _preflight_postgresql_principals() -> None:
    """Require operator-owned principals without granting Alembic CREATEROLE."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    rows = {
        str(row["rolname"]): row
        for row in bind.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles "
                "WHERE rolname IN ('saas_registration', 'saas_onboarding')"
            )
        ).mappings()
    }
    unsafe = []
    for role_name in ("saas_registration", "saas_onboarding"):
        row = rows.get(role_name)
        if row is None or (
            bool(row["rolcanlogin"]),
            bool(row["rolsuper"]),
            bool(row["rolcreatedb"]),
            bool(row["rolcreaterole"]),
            bool(row["rolreplication"]),
            bool(row["rolbypassrls"]),
            bool(row["rolinherit"]),
            int(row["rolconnlimit"]),
            row["rolconfig"] is None,
        ) != (False, False, False, False, False, False, True, -1, True):
            unsafe.append(role_name)
    outgoing_memberships = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "WHERE member.rolname IN ('saas_registration', 'saas_onboarding')"
        )
    ).scalar_one()
    if outgoing_memberships:
        unsafe.append("fixed membership graph")
    if unsafe:
        raise RuntimeError(
            "cannot apply p0s000000001: PostgreSQL principal preflight rejected; "
            "run postgresql_principals.psql before Alembic"
        )


def _replace_authority_checks(*, include_onboarding: bool) -> None:
    tenant_statuses = (
        "'provisioning', 'trial', 'active', 'suspended', 'pending_deletion', 'deleted'"
        if include_onboarding
        else "'trial', 'active', 'suspended', 'pending_deletion', 'deleted'"
    )
    tombstone_kinds = (
        "'oidc_subject', 'scim_user', 'password_email'"
        if include_onboarding
        else "'oidc_subject', 'scim_user'"
    )
    with op.batch_alter_table("saas_tenants") as batch:
        batch.drop_constraint("ck_tenant_status", type_="check")
        batch.create_check_constraint("ck_tenant_status", f"status IN ({tenant_statuses})")
    with op.batch_alter_table("saas_privacy_identity_tombstones") as batch:
        batch.drop_constraint("ck_privacy_tombstone_kind", type_="check")
        batch.create_check_constraint(
            "ck_privacy_tombstone_kind",
            f"locator_kind IN ({tombstone_kinds})",
        )


def _create_registration_table() -> None:
    op.create_table(
        "saas_self_service_registrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("email_hash", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(256)),
        sa.Column("tenant_name", sa.String(256), nullable=False),
        sa.Column("tenant_slug", sa.String(128), nullable=False),
        sa.Column("default_space_name", sa.String(256), nullable=False),
        sa.Column("default_space_slug", sa.String(128), nullable=False),
        sa.Column("plan_key", sa.String(64), nullable=False),
        sa.Column("plan_policy_revision", sa.String(128), nullable=False),
        sa.Column("home_region", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("challenge_generation", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_partition_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending_verification', 'suppressed', 'verified', 'expired', 'revoked')",
            name="ck_self_service_registration_status",
        ),
        sa.CheckConstraint("length(email_hash) = 64", name="ck_self_service_email_hash"),
        sa.CheckConstraint(
            "length(idempotency_key) = 64",
            name="ck_self_service_idempotency_key",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_self_service_request_hash",
        ),
        sa.CheckConstraint(
            "length(tenant_name) BETWEEN 1 AND 256",
            name="ck_self_service_tenant_name",
        ),
        sa.CheckConstraint(
            "length(tenant_slug) BETWEEN 1 AND 128 AND tenant_slug = lower(tenant_slug)",
            name="ck_self_service_tenant_slug",
        ),
        sa.CheckConstraint(
            "length(default_space_name) BETWEEN 1 AND 256",
            name="ck_self_service_space_name",
        ),
        sa.CheckConstraint(
            "length(default_space_slug) BETWEEN 1 AND 128 "
            "AND default_space_slug = lower(default_space_slug)",
            name="ck_self_service_space_slug",
        ),
        sa.CheckConstraint(
            "length(plan_key) BETWEEN 1 AND 64",
            name="ck_self_service_plan_key",
        ),
        sa.CheckConstraint(
            "length(plan_policy_revision) BETWEEN 1 AND 128",
            name="ck_self_service_plan_policy_revision",
        ),
        sa.CheckConstraint(
            "length(home_region) BETWEEN 1 AND 64",
            name="ck_self_service_home_region",
        ),
        sa.CheckConstraint(
            "challenge_generation > 0",
            name="ck_self_service_challenge_generation",
        ),
        sa.CheckConstraint("version > 0", name="ck_self_service_version"),
        sa.CheckConstraint("expires_at > created_at", name="ck_self_service_expiry"),
        sa.CheckConstraint(
            "(status = 'pending_verification' AND verified_at IS NULL "
            "AND terminal_at IS NULL) OR "
            "(status = 'verified' AND verified_at IS NOT NULL "
            "AND terminal_at = verified_at) OR "
            "(status IN ('suppressed', 'expired', 'revoked') "
            "AND verified_at IS NULL AND terminal_at IS NOT NULL)",
            name="ck_self_service_terminal_state",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("onboarding_id", name="uq_self_service_registration_onboarding_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_self_service_registration_idempotency"),
        sa.UniqueConstraint("user_id", name="uq_self_service_registration_user"),
        sa.UniqueConstraint("tenant_id", name="uq_self_service_registration_tenant"),
        sa.UniqueConstraint("space_id", name="uq_self_service_registration_space"),
        sa.UniqueConstraint(
            "subscription_id",
            name="uq_self_service_registration_subscription",
        ),
        sa.UniqueConstraint(
            "runtime_partition_id",
            name="uq_self_service_registration_partition",
        ),
        sa.UniqueConstraint(
            "id",
            "onboarding_id",
            name="uq_self_service_registration_onboarding_scope",
        ),
    )
    op.create_index(
        "uq_open_self_service_email",
        "saas_self_service_registrations",
        ["email_hash"],
        unique=True,
        sqlite_where=sa.text("status IN ('pending_verification', 'suppressed', 'verified')"),
        postgresql_where=sa.text("status IN ('pending_verification', 'suppressed', 'verified')"),
    )
    op.create_index(
        "uq_open_self_service_tenant_slug",
        "saas_self_service_registrations",
        ["tenant_slug"],
        unique=True,
        sqlite_where=sa.text("status IN ('pending_verification', 'verified')"),
        postgresql_where=sa.text("status IN ('pending_verification', 'verified')"),
    )
    op.create_index(
        "ix_self_service_registration_expiry",
        "saas_self_service_registrations",
        ["status", "expires_at"],
    )


def _create_challenge_table() -> None:
    op.create_table(
        "saas_email_verification_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("registration_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("delivery_status", sa.String(32), nullable=False),
        sa.Column("delivery_attempts", sa.Integer(), nullable=False),
        sa.Column("delivery_idempotency_key", sa.String(64), nullable=False),
        sa.Column("last_delivery_error_code", sa.String(128)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("expired_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'consumed', 'expired', 'revoked')",
            name="ck_email_verification_challenge_status",
        ),
        sa.CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed', 'suppressed')",
            name="ck_email_verification_delivery_status",
        ),
        sa.CheckConstraint(
            "length(token_hash) = 64",
            name="ck_email_challenge_token_hash",
        ),
        sa.CheckConstraint(
            "length(delivery_idempotency_key) = 64",
            name="ck_email_verification_delivery_key",
        ),
        sa.CheckConstraint("generation > 0", name="ck_email_verification_generation"),
        sa.CheckConstraint(
            "delivery_attempts >= 0",
            name="ck_email_verification_delivery_attempts",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_email_verification_expiry",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND consumed_at IS NULL AND expired_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'consumed' AND consumed_at IS NOT NULL AND expired_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'expired' AND consumed_at IS NULL AND expired_at IS NOT NULL "
            "AND revoked_at IS NULL) OR "
            "(status = 'revoked' AND consumed_at IS NULL AND expired_at IS NULL "
            "AND revoked_at IS NOT NULL)",
            name="ck_email_verification_terminal_state",
        ),
        sa.CheckConstraint(
            "(delivery_status = 'sent' AND delivered_at IS NOT NULL) OR "
            "(delivery_status <> 'sent' AND delivered_at IS NULL)",
            name="ck_email_verification_delivery_result",
        ),
        sa.ForeignKeyConstraint(
            ("registration_id",),
            ("saas_self_service_registrations.id",),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_email_verification_token_hash"),
        sa.UniqueConstraint(
            "registration_id",
            "generation",
            name="uq_email_verification_generation",
        ),
        sa.UniqueConstraint(
            "registration_id",
            "delivery_idempotency_key",
            name="uq_email_verification_delivery_key",
        ),
    )
    op.create_index(
        "uq_pending_email_verification_challenge",
        "saas_email_verification_challenges",
        ["registration_id"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_email_verification_expiry",
        "saas_email_verification_challenges",
        ["status", "expires_at"],
    )


def _create_onboarding_table() -> None:
    op.create_table(
        "saas_tenant_onboardings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("registration_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("space_id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Uuid(), nullable=False),
        sa.Column("runtime_partition_id", sa.Uuid(), nullable=False),
        sa.Column("plan_key", sa.String(64), nullable=False),
        sa.Column("plan_policy_revision", sa.String(128), nullable=False),
        sa.Column("home_region", sa.String(64), nullable=False),
        sa.Column("trial_days", sa.Integer(), nullable=False),
        sa.Column("trial_started_at", sa.DateTime(timezone=True)),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("claim_token", sa.Uuid()),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("last_error_detail", sa.String(2048)),
        sa.Column("billing_ready_at", sa.DateTime(timezone=True)),
        sa.Column("runtime_ready_at", sa.DateTime(timezone=True)),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("compensated_at", sa.DateTime(timezone=True)),
        sa.Column("last_transition_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('tenant_created', 'billing_ready', 'runtime_ready', 'active', "
            "'compensating', 'compensated', 'manual_review')",
            name="ck_tenant_onboarding_status",
        ),
        sa.CheckConstraint(
            "length(plan_key) BETWEEN 1 AND 64",
            name="ck_tenant_onboarding_plan_key",
        ),
        sa.CheckConstraint(
            "length(plan_policy_revision) BETWEEN 1 AND 128",
            name="ck_tenant_onboarding_plan_policy_revision",
        ),
        sa.CheckConstraint(
            "length(home_region) BETWEEN 1 AND 64",
            name="ck_tenant_onboarding_region",
        ),
        sa.CheckConstraint(
            "trial_days BETWEEN 1 AND 90 AND "
            "((trial_started_at IS NULL AND trial_ends_at IS NULL) OR "
            "(trial_started_at IS NOT NULL AND trial_ends_at > trial_started_at))",
            name="ck_tenant_onboarding_trial",
        ),
        sa.CheckConstraint(
            "length(idempotency_key) = 64",
            name="ck_tenant_onboarding_idempotency_key",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_tenant_onboarding_request_hash",
        ),
        sa.CheckConstraint("version > 0", name="ck_tenant_onboarding_version"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_tenant_onboarding_attempts"),
        sa.CheckConstraint(
            "(claim_token IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL) OR "
            "(claim_token IS NOT NULL AND claimed_at IS NOT NULL "
            "AND lease_expires_at > claimed_at)",
            name="ck_tenant_onboarding_lease",
        ),
        sa.CheckConstraint(
            "(status = 'tenant_created' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NULL "
            "AND runtime_ready_at IS NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'billing_ready' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'runtime_ready' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'active' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND activated_at IS NOT NULL "
            "AND compensated_at IS NULL) OR "
            "(status IN ('compensating', 'manual_review') AND activated_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'compensated' AND activated_at IS NULL "
            "AND compensated_at IS NOT NULL)",
            name="ck_tenant_onboarding_state_evidence",
        ),
        sa.ForeignKeyConstraint(
            ("registration_id", "id"),
            (
                "saas_self_service_registrations.id",
                "saas_self_service_registrations.onboarding_id",
            ),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_preallocated_id",
        ),
        sa.ForeignKeyConstraint(
            ("user_id",),
            ("saas_global_users.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id",),
            ("saas_tenants.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "space_id"),
            ("saas_spaces.tenant_id", "saas_spaces.id"),
            ondelete="RESTRICT",
            name="fk_tenant_onboarding_space",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("registration_id", name="uq_tenant_onboarding_registration"),
        sa.UniqueConstraint("idempotency_key", name="uq_tenant_onboarding_idempotency"),
        sa.UniqueConstraint("tenant_id", name="uq_tenant_onboarding_tenant"),
        sa.UniqueConstraint("space_id", name="uq_tenant_onboarding_space"),
        sa.UniqueConstraint(
            "subscription_id",
            name="uq_tenant_onboarding_subscription",
        ),
        sa.UniqueConstraint(
            "runtime_partition_id",
            name="uq_tenant_onboarding_runtime_partition",
        ),
    )
    op.create_index(
        "ix_tenant_onboarding_dispatch",
        "saas_tenant_onboardings",
        ["status", "available_at", "claimed_at"],
    )
    op.create_index(
        "ix_tenant_onboarding_user",
        "saas_tenant_onboardings",
        ["user_id", "created_at"],
    )


def _create_event_table() -> None:
    op.create_table(
        "saas_self_service_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("aggregate_type", sa.String(32), nullable=False),
        sa.Column("aggregate_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("user_id", sa.Uuid()),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("from_status", sa.String(32)),
        sa.Column("to_status", sa.String(32)),
        sa.Column("facts", sa.JSON(), nullable=False),
        sa.Column("facts_hash", sa.String(64), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "aggregate_type IN ('registration', 'tenant_onboarding')",
            name="ck_self_service_event_aggregate_type",
        ),
        sa.CheckConstraint("sequence > 0", name="ck_self_service_event_sequence"),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 128",
            name="ck_self_service_event_type",
        ),
        sa.CheckConstraint(
            "(from_status IS NULL AND to_status IS NULL) OR "
            "(from_status IS NOT NULL AND to_status IS NOT NULL)",
            name="ck_self_service_event_transition",
        ),
        sa.CheckConstraint(
            "length(facts_hash) = 64",
            name="ck_self_service_event_facts_hash",
        ),
        sa.CheckConstraint(
            "length(previous_hash) = 64",
            name="ck_self_service_event_previous_hash",
        ),
        sa.CheckConstraint(
            "length(event_hash) = 64",
            name="ck_self_service_event_hash",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_hash", name="uq_self_service_event_hash"),
        sa.UniqueConstraint(
            "aggregate_type",
            "aggregate_id",
            "sequence",
            name="uq_self_service_event_sequence",
        ),
    )
    op.create_index(
        "ix_self_service_event_replay",
        "saas_self_service_events",
        ["aggregate_type", "aggregate_id", "sequence"],
    )
    op.create_index(
        "ix_self_service_event_tenant",
        "saas_self_service_events",
        ["tenant_id", "occurred_at"],
    )
    op.create_index(
        "ix_self_service_event_user",
        "saas_self_service_events",
        ["user_id", "occurred_at"],
    )


def _install_new_table_policies() -> None:
    for table in _NEW_TABLES:
        op.execute(
            f"CREATE POLICY rls_{table}_platform ON {table} FOR ALL "
            f"USING ({_PLATFORM_ROLE}) WITH CHECK ({_PLATFORM_ROLE})"
        )
    registration_exact = (
        f"({_REGISTRATION_ROLE} AND id = {_REGISTRATION_ID} AND {_REGISTRATION_ID} IS NOT NULL)"
    )
    registration_replay = (
        f"({_REGISTRATION_ROLE} AND email_hash = {_REGISTRATION_EMAIL_HASH} "
        f"AND idempotency_key = {_REGISTRATION_IDEMPOTENCY_KEY} "
        f"AND {_REGISTRATION_EMAIL_HASH} IS NOT NULL "
        f"AND {_REGISTRATION_IDEMPOTENCY_KEY} IS NOT NULL)"
    )
    onboarding_registration_bootstrap = (
        f"({_ONBOARDING_ROLE} AND id = {_REGISTRATION_ID} "
        f"AND status = 'verified' AND {_REGISTRATION_ID} IS NOT NULL)"
    )
    registration_insert = (
        f"({_REGISTRATION_ROLE} AND id = {_REGISTRATION_ID} "
        f"AND email_hash = {_REGISTRATION_EMAIL_HASH} "
        f"AND idempotency_key = {_REGISTRATION_IDEMPOTENCY_KEY} "
        "AND status IN ('pending_verification', 'suppressed') "
        f"AND {_REGISTRATION_ID} IS NOT NULL "
        f"AND {_REGISTRATION_EMAIL_HASH} IS NOT NULL "
        f"AND {_REGISTRATION_IDEMPOTENCY_KEY} IS NOT NULL)"
    )
    op.execute(
        "CREATE POLICY rls_self_service_registrations_select "
        "ON saas_self_service_registrations FOR SELECT TO saas_registration "
        f"USING ({registration_exact} OR {registration_replay})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_registrations_onboarding_bootstrap "
        "ON saas_self_service_registrations FOR SELECT TO saas_onboarding "
        f"USING ({onboarding_registration_bootstrap})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_registrations_insert "
        "ON saas_self_service_registrations FOR INSERT TO saas_registration "
        f"WITH CHECK ({registration_insert})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_registrations_update "
        "ON saas_self_service_registrations FOR UPDATE TO saas_registration "
        f"USING ({registration_exact}) WITH CHECK ({registration_exact})"
    )

    challenge_exact = (
        f"({_REGISTRATION_ROLE} AND registration_id = {_REGISTRATION_ID} "
        f"AND {_REGISTRATION_ID} IS NOT NULL)"
    )
    challenge_insert = (
        f"({challenge_exact} AND token_hash = {_REGISTRATION_TOKEN_HASH} "
        f"AND {_REGISTRATION_TOKEN_HASH} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        f"WHERE registration_scope.id = {_REGISTRATION_ID} "
        "AND registration_scope.id = registration_id "
        "AND registration_scope.challenge_generation = generation "
        "AND registration_scope.status IN ('pending_verification', 'suppressed')))"
    )
    op.execute(
        "CREATE POLICY rls_email_verification_challenges_select "
        "ON saas_email_verification_challenges FOR SELECT TO saas_registration "
        f"USING ({challenge_exact})"
    )
    op.execute(
        "CREATE POLICY rls_email_verification_challenges_insert "
        "ON saas_email_verification_challenges FOR INSERT TO saas_registration "
        f"WITH CHECK ({challenge_insert})"
    )
    op.execute(
        "CREATE POLICY rls_email_verification_challenges_update "
        "ON saas_email_verification_challenges FOR UPDATE TO saas_registration "
        f"USING ({challenge_exact}) WITH CHECK ({challenge_exact})"
    )

    onboarding_exact = (
        f"({_ONBOARDING_ROLE} AND id = {_ONBOARDING_ID} "
        f"AND registration_id = {_REGISTRATION_ID} AND user_id = {_ACTOR_ID} "
        f"AND tenant_id = {_TENANT_ID} AND {_ONBOARDING_ID} IS NOT NULL "
        f"AND {_REGISTRATION_ID} IS NOT NULL AND {_ACTOR_ID} IS NOT NULL "
        f"AND {_TENANT_ID} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        "WHERE registration_scope.id = saas_tenant_onboardings.registration_id "
        "AND registration_scope.onboarding_id = saas_tenant_onboardings.id "
        "AND registration_scope.status = 'verified' "
        "AND registration_scope.user_id = saas_tenant_onboardings.user_id "
        "AND registration_scope.tenant_id = saas_tenant_onboardings.tenant_id "
        "AND registration_scope.space_id = saas_tenant_onboardings.space_id "
        "AND registration_scope.subscription_id = saas_tenant_onboardings.subscription_id "
        "AND registration_scope.runtime_partition_id = "
        "saas_tenant_onboardings.runtime_partition_id "
        "AND registration_scope.plan_key = saas_tenant_onboardings.plan_key "
        "AND registration_scope.plan_policy_revision = "
        "saas_tenant_onboardings.plan_policy_revision "
        "AND registration_scope.home_region = saas_tenant_onboardings.home_region))"
    )
    onboarding_insert = (
        f"({onboarding_exact} AND status = 'tenant_created' "
        "AND trial_started_at IS NULL AND trial_ends_at IS NULL "
        "AND billing_ready_at IS NULL AND runtime_ready_at IS NULL "
        "AND activated_at IS NULL AND compensated_at IS NULL)"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_select "
        "ON saas_tenant_onboardings FOR SELECT TO saas_onboarding "
        f"USING ({onboarding_exact})"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_insert "
        "ON saas_tenant_onboardings FOR INSERT TO saas_onboarding "
        f"WITH CHECK ({onboarding_insert})"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_update "
        "ON saas_tenant_onboardings FOR UPDATE TO saas_onboarding "
        f"USING ({onboarding_exact}) WITH CHECK ({onboarding_exact})"
    )

    registration_event = (
        f"({_REGISTRATION_ROLE} AND aggregate_type = 'registration' "
        f"AND aggregate_id = {_REGISTRATION_ID} AND {_REGISTRATION_ID} IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM saas_self_service_registrations registration_scope "
        "WHERE registration_scope.id = aggregate_id "
        "AND (saas_self_service_events.tenant_id IS NULL OR "
        "saas_self_service_events.tenant_id = registration_scope.tenant_id) "
        "AND (saas_self_service_events.user_id IS NULL OR "
        "saas_self_service_events.user_id = registration_scope.user_id)))"
    )
    onboarding_event = (
        f"({_ONBOARDING_ROLE} AND aggregate_type = 'tenant_onboarding' "
        f"AND aggregate_id = {_ONBOARDING_ID} AND tenant_id = {_TENANT_ID} "
        f"AND user_id = {_ACTOR_ID} AND {_ONBOARDING_ID} IS NOT NULL "
        "AND EXISTS (SELECT 1 FROM saas_tenant_onboardings onboarding_scope "
        "WHERE onboarding_scope.id = aggregate_id "
        f"AND onboarding_scope.registration_id = {_REGISTRATION_ID} "
        "AND onboarding_scope.tenant_id = saas_self_service_events.tenant_id "
        "AND onboarding_scope.user_id = saas_self_service_events.user_id))"
    )
    op.execute(
        "CREATE POLICY rls_self_service_events_registration_select "
        "ON saas_self_service_events FOR SELECT TO saas_registration "
        f"USING ({registration_event})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_events_registration_insert "
        "ON saas_self_service_events FOR INSERT TO saas_registration "
        f"WITH CHECK ({registration_event})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_events_onboarding_select "
        "ON saas_self_service_events FOR SELECT TO saas_onboarding "
        f"USING ({onboarding_event})"
    )
    op.execute(
        "CREATE POLICY rls_self_service_events_onboarding_insert "
        "ON saas_self_service_events FOR INSERT TO saas_onboarding "
        f"WITH CHECK ({onboarding_event})"
    )


def _install_registration_core_policies() -> None:
    exact_registration = (
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        f"WHERE registration_scope.id = {_REGISTRATION_ID} "
        f"AND {_REGISTRATION_ID} IS NOT NULL"
    )
    verified_user = (
        f"({_REGISTRATION_ROLE} AND EXISTS ({exact_registration} "
        "AND registration_scope.status = 'verified' "
        "AND registration_scope.user_id = saas_global_users.id))"
    )
    op.execute(
        "CREATE POLICY rls_global_users_registration_select ON saas_global_users "
        f"FOR SELECT TO saas_registration USING ({verified_user})"
    )
    op.execute(
        "CREATE POLICY rls_global_users_registration_insert ON saas_global_users "
        f"FOR INSERT TO saas_registration WITH CHECK ({verified_user} AND status = 'active' "
        "AND security_version = 1)"
    )

    exact_identity_email = (
        f"({_REGISTRATION_ROLE} AND EXISTS ({exact_registration} "
        "AND registration_scope.email_normalized = "
        "saas_identity_connections.email_normalized))"
    )
    verified_identity = (
        f"({_REGISTRATION_ROLE} AND EXISTS ({exact_registration} "
        "AND registration_scope.status = 'verified' "
        "AND registration_scope.user_id = saas_identity_connections.user_id "
        "AND registration_scope.email_normalized = "
        "saas_identity_connections.email_normalized) "
        "AND provider = 'password' "
        "AND issuer = 'urn:omnigent:self-service-email' "
        "AND email_verified IS TRUE AND status = 'active')"
    )
    op.execute(
        "CREATE POLICY rls_identity_connections_registration_select "
        "ON saas_identity_connections FOR SELECT TO saas_registration "
        f"USING ({exact_identity_email})"
    )
    op.execute(
        "CREATE POLICY rls_identity_connections_registration_insert "
        "ON saas_identity_connections FOR INSERT TO saas_registration "
        f"WITH CHECK ({verified_identity})"
    )

    exact_password_email = (
        f"({_REGISTRATION_ROLE} AND EXISTS ({exact_registration} "
        "AND registration_scope.email_normalized = "
        "saas_password_credentials.login_email_normalized))"
    )
    verified_password = (
        f"({_REGISTRATION_ROLE} AND EXISTS ({exact_registration} "
        "AND registration_scope.status = 'verified' "
        "AND registration_scope.user_id = saas_password_credentials.user_id "
        "AND registration_scope.email_normalized = "
        "saas_password_credentials.login_email_normalized) "
        "AND password_version = 1 AND failed_attempts = 0 "
        "AND locked_until IS NULL)"
    )
    op.execute(
        "CREATE POLICY rls_password_credentials_registration_select "
        "ON saas_password_credentials FOR SELECT TO saas_registration "
        f"USING ({exact_password_email})"
    )
    op.execute(
        "CREATE POLICY rls_password_credentials_registration_insert "
        "ON saas_password_credentials FOR INSERT TO saas_registration "
        f"WITH CHECK ({verified_password})"
    )
    op.execute(
        "CREATE POLICY rls_privacy_tombstone_registration_locator "
        "ON saas_privacy_identity_tombstones FOR SELECT TO saas_registration USING ("
        f"{_REGISTRATION_ROLE} AND locator_kind = 'password_email' "
        f"AND locator_hash = {_REGISTRATION_EMAIL_HASH} "
        f"AND {_REGISTRATION_EMAIL_HASH} IS NOT NULL)"
    )

    registration_outbox = (
        f"({_REGISTRATION_ROLE} AND tenant_id IS NULL "
        f"AND {_REGISTRATION_ID} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        f"WHERE registration_scope.id = {_REGISTRATION_ID} AND (("
        "aggregate_type = 'self_service_registration' "
        "AND aggregate_key = registration_scope.id::text "
        "AND event_type = 'onboarding.email_verification.requested') OR ("
        "registration_scope.status = 'verified' "
        "AND aggregate_type = 'tenant_onboarding' "
        "AND aggregate_key = registration_scope.onboarding_id::text "
        "AND event_type = 'onboarding.tenant.requested'))))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_registration_insert ON saas_control_plane_outbox "
        f"FOR INSERT TO saas_registration WITH CHECK ({registration_outbox})"
    )
    op.execute(
        "CREATE POLICY rls_outbox_registration_select ON saas_control_plane_outbox "
        f"FOR SELECT TO saas_registration USING ({registration_outbox})"
    )


def _install_onboarding_core_policies() -> None:
    registration_match = (
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        f"WHERE registration_scope.id = {_REGISTRATION_ID} "
        f"AND registration_scope.onboarding_id = {_ONBOARDING_ID} "
        f"AND registration_scope.user_id = {_ACTOR_ID} "
        f"AND registration_scope.tenant_id = {_TENANT_ID} "
        "AND registration_scope.status = 'verified' "
        f"AND {_REGISTRATION_ID} IS NOT NULL AND {_ONBOARDING_ID} IS NOT NULL "
        f"AND {_ACTOR_ID} IS NOT NULL AND {_TENANT_ID} IS NOT NULL"
    )
    tenant_exact = (
        f"({_ONBOARDING_ROLE} AND EXISTS ({registration_match} "
        "AND registration_scope.tenant_id = saas_tenants.id "
        "AND registration_scope.tenant_slug = saas_tenants.slug "
        "AND registration_scope.tenant_name = saas_tenants.name "
        "AND registration_scope.plan_key = saas_tenants.plan "
        "AND registration_scope.home_region = saas_tenants.home_region))"
    )
    _install_exact_onboarding_policy(
        table="saas_tenants",
        predicate=tenant_exact,
        initial="status = 'provisioning' AND lifecycle_version = 1",
    )

    space_exact = (
        f"({_ONBOARDING_ROLE} AND EXISTS ({registration_match} "
        "AND registration_scope.tenant_id = saas_spaces.tenant_id "
        "AND registration_scope.space_id = saas_spaces.id "
        "AND registration_scope.default_space_slug = saas_spaces.slug "
        "AND registration_scope.default_space_name = saas_spaces.name))"
    )
    _install_exact_onboarding_policy(
        table="saas_spaces",
        predicate=space_exact,
        initial="status = 'suspended'",
    )

    tenant_member_exact = (
        f"({_ONBOARDING_ROLE} AND EXISTS ({registration_match} "
        "AND registration_scope.tenant_id = saas_tenant_memberships.tenant_id "
        "AND registration_scope.user_id = saas_tenant_memberships.user_id) "
        "AND role = 'owner' AND status = 'active' AND version = 1)"
    )
    _install_exact_onboarding_policy(
        table="saas_tenant_memberships",
        predicate=tenant_member_exact,
        initial="role = 'owner' AND status = 'active' AND version = 1",
    )

    space_member_exact = (
        f"({_ONBOARDING_ROLE} AND EXISTS ({registration_match} "
        "AND registration_scope.tenant_id = saas_space_memberships.tenant_id "
        "AND registration_scope.space_id = saas_space_memberships.space_id "
        "AND registration_scope.user_id = saas_space_memberships.user_id) "
        "AND role = 'owner' AND status = 'active' AND version = 1)"
    )
    _install_exact_onboarding_policy(
        table="saas_space_memberships",
        predicate=space_member_exact,
        initial="role = 'owner' AND status = 'active' AND version = 1",
    )

    onboarding_outbox = (
        f"({_ONBOARDING_ROLE} AND tenant_id = {_TENANT_ID} "
        "AND aggregate_type = 'tenant_onboarding' "
        f"AND aggregate_key = ({_ONBOARDING_ID})::text "
        "AND event_type = 'onboarding.billing.requested' "
        f"AND {_ONBOARDING_ID} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_tenant_onboardings onboarding_scope "
        f"WHERE onboarding_scope.id = {_ONBOARDING_ID} "
        f"AND onboarding_scope.registration_id = {_REGISTRATION_ID} "
        f"AND onboarding_scope.user_id = {_ACTOR_ID} "
        f"AND onboarding_scope.tenant_id = {_TENANT_ID}))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_onboarding_insert ON saas_control_plane_outbox "
        f"FOR INSERT TO saas_onboarding WITH CHECK ({onboarding_outbox})"
    )
    op.execute(
        "CREATE POLICY rls_outbox_onboarding_select ON saas_control_plane_outbox "
        f"FOR SELECT TO saas_onboarding USING ({onboarding_outbox})"
    )
    op.execute(
        "CREATE POLICY rls_outbox_onboarding_restrictive "
        "ON saas_control_plane_outbox AS RESTRICTIVE FOR INSERT TO saas_onboarding "
        f"WITH CHECK ({onboarding_outbox})"
    )


def _install_exact_onboarding_policy(
    *,
    table: str,
    predicate: str,
    initial: str,
) -> None:
    op.execute(
        f"CREATE POLICY rls_{table}_onboarding_exact ON {table} "
        "FOR ALL TO saas_onboarding "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute(
        f"CREATE POLICY rls_{table}_onboarding_restrictive ON {table} "
        "AS RESTRICTIVE FOR ALL TO saas_onboarding "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute(
        f"CREATE POLICY rls_{table}_onboarding_initial ON {table} "
        "AS RESTRICTIVE FOR INSERT TO saas_onboarding "
        f"WITH CHECK ({predicate} AND {initial})"
    )


def _install_immutable_event_trigger() -> None:
    op.execute(
        "CREATE FUNCTION saas_reject_self_service_event_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'self-service events are immutable'; END; $$"
    )
    op.execute(
        "CREATE TRIGGER trg_self_service_event_immutable BEFORE UPDATE OR DELETE "
        "ON saas_self_service_events FOR EACH ROW "
        "EXECUTE FUNCTION saas_reject_self_service_event_mutation()"
    )


def _install_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    _install_new_table_policies()
    _install_registration_core_policies()
    _install_onboarding_core_policies()
    _install_immutable_event_trigger()


def _drop_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    core_policies = {
        "saas_global_users": (
            "rls_global_users_registration_select",
            "rls_global_users_registration_insert",
        ),
        "saas_identity_connections": (
            "rls_identity_connections_registration_select",
            "rls_identity_connections_registration_insert",
        ),
        "saas_password_credentials": (
            "rls_password_credentials_registration_select",
            "rls_password_credentials_registration_insert",
        ),
        "saas_privacy_identity_tombstones": ("rls_privacy_tombstone_registration_locator",),
        "saas_tenants": (
            "rls_saas_tenants_onboarding_exact",
            "rls_saas_tenants_onboarding_restrictive",
            "rls_saas_tenants_onboarding_initial",
        ),
        "saas_spaces": (
            "rls_saas_spaces_onboarding_exact",
            "rls_saas_spaces_onboarding_restrictive",
            "rls_saas_spaces_onboarding_initial",
        ),
        "saas_tenant_memberships": (
            "rls_saas_tenant_memberships_onboarding_exact",
            "rls_saas_tenant_memberships_onboarding_restrictive",
            "rls_saas_tenant_memberships_onboarding_initial",
        ),
        "saas_space_memberships": (
            "rls_saas_space_memberships_onboarding_exact",
            "rls_saas_space_memberships_onboarding_restrictive",
            "rls_saas_space_memberships_onboarding_initial",
        ),
        "saas_control_plane_outbox": (
            "rls_outbox_registration_insert",
            "rls_outbox_registration_select",
            "rls_outbox_onboarding_insert",
            "rls_outbox_onboarding_select",
            "rls_outbox_onboarding_restrictive",
        ),
    }
    for table, policies in core_policies.items():
        for policy in policies:
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_self_service_event_immutable ON saas_self_service_events"
    )
    op.execute("DROP FUNCTION IF EXISTS saas_reject_self_service_event_mutation()")


def _assert_downgrade_safe() -> None:
    bind = op.get_bind()
    for table in _NEW_TABLES:
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:
            raise RuntimeError(
                "cannot downgrade P0 self-service onboarding while authority records exist"
            )
    if (
        bind.execute(
            sa.text("SELECT 1 FROM saas_tenants WHERE status = 'provisioning' LIMIT 1")
        ).first()
        is not None
    ):
        raise RuntimeError("cannot downgrade while a provisioning Tenant exists")
    if (
        bind.execute(
            sa.text(
                "SELECT 1 FROM saas_privacy_identity_tombstones "
                "WHERE locator_kind = 'password_email' LIMIT 1"
            )
        ).first()
        is not None
    ):
        raise RuntimeError("cannot downgrade while password-email tombstones exist")


def _drop_tables() -> None:
    op.drop_index("ix_self_service_event_user", table_name="saas_self_service_events")
    op.drop_index("ix_self_service_event_tenant", table_name="saas_self_service_events")
    op.drop_index("ix_self_service_event_replay", table_name="saas_self_service_events")
    op.drop_table("saas_self_service_events")

    op.drop_index("ix_tenant_onboarding_user", table_name="saas_tenant_onboardings")
    op.drop_index("ix_tenant_onboarding_dispatch", table_name="saas_tenant_onboardings")
    op.drop_table("saas_tenant_onboardings")

    op.drop_index(
        "ix_email_verification_expiry",
        table_name="saas_email_verification_challenges",
    )
    op.drop_index(
        "uq_pending_email_verification_challenge",
        table_name="saas_email_verification_challenges",
    )
    op.drop_table("saas_email_verification_challenges")

    op.drop_index(
        "ix_self_service_registration_expiry",
        table_name="saas_self_service_registrations",
    )
    op.drop_index(
        "uq_open_self_service_tenant_slug",
        table_name="saas_self_service_registrations",
    )
    op.drop_index(
        "uq_open_self_service_email",
        table_name="saas_self_service_registrations",
    )
    op.drop_table("saas_self_service_registrations")


def upgrade() -> None:
    """Create hash-only verification credentials and a staged onboarding Saga."""

    _preflight_postgresql_principals()
    _replace_authority_checks(include_onboarding=True)
    _create_registration_table()
    _create_challenge_table()
    _create_onboarding_table()
    _create_event_table()
    _install_postgresql_authority()


def downgrade() -> None:
    """Remove the authority only when no durable onboarding fact would be lost."""

    _assert_downgrade_safe()
    _drop_postgresql_authority()
    _drop_tables()
    _replace_authority_checks(include_onboarding=False)
