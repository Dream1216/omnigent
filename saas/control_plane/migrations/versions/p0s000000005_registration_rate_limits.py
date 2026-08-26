"""Add fail-closed registration abuse controls and Privacy erasure.

Revision ID: p0s000000005
Revises: p0s000000004
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000005"
down_revision: str | None = "p0s000000004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRIVACY_ROLE = "pg_has_role(current_user, 'saas_privacy_executor', 'member')"
_PRIVACY_PRINCIPAL = "NULLIF(current_setting('app.platform_principal_id', true), '')::uuid"
_PRIVACY_TARGET_USER = "NULLIF(current_setting('app.platform_target_user_id', true), '')::uuid"
_PRIVACY_TARGET_TENANT = "NULLIF(current_setting('app.platform_target_tenant_id', true), '')::uuid"
_PRIVACY_MANIFEST = "NULLIF(current_setting('app.platform_privacy_manifest_id', true), '')::uuid"
_ACTIONS = (
    "registration.request",
    "registration.resend",
    "registration.verify",
)
_SUBJECT_KINDS = ("email", "registration")
_POLICY_REVISION = "registration-rate-limit-v1"
_POLICIES = (
    ("registration.request", "email", 5, 900, 86400, 1_000_000),
    ("registration.resend", "email", 3, 900, 86400, 1_000_000),
    ("registration.verify", "registration", 10, 900, 86400, 1_000_000),
)


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {column} = lower({column}) AND {remainder} = ''"


def _preflight_postgresql_principal() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    role = (
        bind.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles WHERE rolname = 'saas_registration'"
            )
        )
        .mappings()
        .one_or_none()
    )
    inherited_roles = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "WHERE member.rolname = 'saas_registration'"
        )
    ).scalar_one()
    if role is None or (
        bool(role["rolcanlogin"]),
        bool(role["rolsuper"]),
        bool(role["rolcreatedb"]),
        bool(role["rolcreaterole"]),
        bool(role["rolreplication"]),
        bool(role["rolbypassrls"]),
        bool(role["rolinherit"]),
        int(role["rolconnlimit"]),
        role["rolconfig"] is None,
        int(inherited_roles),
    ) != (False, False, False, False, False, False, True, -1, True, 0):
        raise RuntimeError(
            "cannot apply p0s000000005: PostgreSQL principal preflight rejected; "
            "run postgresql_principals.psql before Alembic"
        )


def _add_registration_privacy_erasure() -> None:
    with op.batch_alter_table("saas_self_service_registrations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "deletion_manifest_id",
                sa.Uuid(),
                nullable=True,
                server_default=sa.text("NULL"),
            )
        )
        batch_op.create_foreign_key(
            "fk_self_service_registration_deletion_manifest",
            "saas_privacy_deletion_manifests",
            ["deletion_manifest_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            "ck_self_service_registration_deletion_manifest",
            "deletion_manifest_id IS NULL OR status = 'revoked'",
        )
    if op.get_bind().dialect.name != "postgresql":
        return

    privacy_actor = (
        f"{_PRIVACY_ROLE} AND {_PRIVACY_PRINCIPAL} IS NOT NULL AND EXISTS ("
        "SELECT 1 FROM saas_platform_role_assignments privacy_registration_assignment "
        f"WHERE privacy_registration_assignment.principal_id = {_PRIVACY_PRINCIPAL} "
        "AND privacy_registration_assignment.role IN "
        "('platform_operator', 'compliance_operator') "
        "AND privacy_registration_assignment.status = 'active' "
        "AND (privacy_registration_assignment.expires_at IS NULL OR "
        "privacy_registration_assignment.expires_at > CURRENT_TIMESTAMP))"
    )
    privacy_user_context = (
        f"{_PRIVACY_MANIFEST} IS NOT NULL "
        f"AND {_PRIVACY_TARGET_USER} IS NOT NULL "
        f"AND {_PRIVACY_TARGET_TENANT} IS NULL AND EXISTS ("
        "SELECT 1 FROM saas_privacy_deletion_manifests privacy_registration_manifest "
        f"WHERE privacy_registration_manifest.id = {_PRIVACY_MANIFEST} "
        "AND privacy_registration_manifest.status = 'executing' "
        "AND privacy_registration_manifest.target_type = 'global_user' "
        f"AND privacy_registration_manifest.target_id = {_PRIVACY_TARGET_USER} "
        "AND privacy_registration_manifest.tenant_id IS NULL)"
    )
    privacy_tenant_context = (
        f"{_PRIVACY_MANIFEST} IS NOT NULL "
        f"AND {_PRIVACY_TARGET_TENANT} IS NOT NULL "
        f"AND {_PRIVACY_TARGET_USER} IS NULL AND EXISTS ("
        "SELECT 1 FROM saas_privacy_deletion_manifests privacy_registration_manifest "
        f"WHERE privacy_registration_manifest.id = {_PRIVACY_MANIFEST} "
        "AND privacy_registration_manifest.status = 'executing' "
        "AND privacy_registration_manifest.target_type = 'tenant' "
        f"AND privacy_registration_manifest.target_id = {_PRIVACY_TARGET_TENANT} "
        f"AND privacy_registration_manifest.tenant_id = {_PRIVACY_TARGET_TENANT})"
    )
    privacy_user_original = (
        f"{privacy_user_context} AND deletion_manifest_id IS NULL "
        f"AND user_id = {_PRIVACY_TARGET_USER}"
    )
    privacy_tenant_original = (
        f"{privacy_tenant_context} AND deletion_manifest_id IS NULL "
        f"AND tenant_id = {_PRIVACY_TARGET_TENANT}"
    )

    def privacy_hash(label: str) -> str:
        return (
            "encode(sha256(convert_to("
            f"{_PRIVACY_MANIFEST}::text || '|' || id::text || '|{label}', "
            "'UTF8')), 'hex')"
        )

    locator = privacy_hash("locator")
    email_hash = f"encode(sha256(convert_to({locator} || '|email_hash', 'UTF8')), 'hex')"
    idempotency_hash = (
        f"encode(sha256(convert_to({locator} || '|idempotency_key', 'UTF8')), 'hex')"
    )
    request_hash = f"encode(sha256(convert_to({locator} || '|request_hash', 'UTF8')), 'hex')"
    privacy_anonymized = (
        f"deletion_manifest_id = {_PRIVACY_MANIFEST} AND status = 'revoked' "
        "AND verified_at IS NULL AND terminal_at IS NOT NULL "
        "AND display_name IS NULL AND tenant_name = 'Deleted Tenant' "
        "AND default_space_name = 'Deleted Space' "
        f"AND email_normalized = 'deleted-' || {locator} || '@invalid' "
        f"AND email_hash = {email_hash} "
        f"AND tenant_slug = 'deleted-' || substr({locator}, 1, 24) "
        f"AND default_space_slug = 'deleted-' || substr({locator}, 25, 24) "
        f"AND idempotency_key = {idempotency_hash} "
        f"AND request_hash = {request_hash} "
        f"AND user_id = substr({privacy_hash('user_id')}, 1, 32)::uuid "
        f"AND tenant_id = substr({privacy_hash('tenant_id')}, 1, 32)::uuid"
    )
    privacy_user_anonymized = f"{privacy_user_context} AND {privacy_anonymized}"
    privacy_tenant_anonymized = f"{privacy_tenant_context} AND {privacy_anonymized}"
    op.execute(
        "CREATE POLICY rls_self_service_registrations_privacy_target "
        "ON saas_self_service_registrations FOR SELECT TO saas_privacy_executor "
        f"USING ({privacy_actor} AND (({privacy_user_original}) "
        f"OR ({privacy_user_anonymized}) OR ({privacy_tenant_original}) "
        f"OR ({privacy_tenant_anonymized})))"
    )
    op.execute(
        "CREATE POLICY rls_self_service_registrations_privacy_anonymize "
        "ON saas_self_service_registrations FOR UPDATE TO saas_privacy_executor "
        f"USING ({privacy_actor} AND (({privacy_user_original}) "
        f"OR ({privacy_tenant_original}))) "
        f"WITH CHECK ({privacy_actor} AND (({privacy_user_anonymized}) "
        f"OR ({privacy_tenant_anonymized})))"
    )

    def trigger_privacy_hash(label: str) -> str:
        return (
            "encode(sha256(convert_to("
            f"{_PRIVACY_MANIFEST}::text || '|' || NEW.id::text || '|{label}', "
            "'UTF8')), 'hex')"
        )

    op.execute(
        "CREATE FUNCTION saas_guard_self_service_registration_privacy_erasure() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF OLD.deletion_manifest_id IS NOT NULL THEN "
        "RAISE EXCEPTION 'self-service registration erasure is immutable' "
        "USING ERRCODE = '55000'; END IF; "
        "IF NEW.deletion_manifest_id IS NULL THEN RETURN NEW; END IF; "
        f"IF OLD.deletion_manifest_id IS NULL AND {_PRIVACY_ROLE} AND (("
        f"{_PRIVACY_TARGET_USER} IS NOT NULL AND {_PRIVACY_TARGET_TENANT} IS NULL "
        f"AND OLD.user_id = {_PRIVACY_TARGET_USER} "
        f"AND NEW.deletion_manifest_id = {_PRIVACY_MANIFEST} "
        f"AND NEW.user_id = substr({trigger_privacy_hash('user_id')}, 1, 32)::uuid "
        f"AND NEW.tenant_id = substr({trigger_privacy_hash('tenant_id')}, 1, 32)::uuid "
        "AND EXISTS (SELECT 1 FROM saas_privacy_deletion_manifests "
        "privacy_registration_manifest "
        f"WHERE privacy_registration_manifest.id = {_PRIVACY_MANIFEST} "
        "AND privacy_registration_manifest.status = 'executing' "
        "AND privacy_registration_manifest.target_type = 'global_user' "
        f"AND privacy_registration_manifest.target_id = {_PRIVACY_TARGET_USER} "
        "AND privacy_registration_manifest.tenant_id IS NULL)) OR ("
        f"{_PRIVACY_TARGET_TENANT} IS NOT NULL AND {_PRIVACY_TARGET_USER} IS NULL "
        f"AND OLD.tenant_id = {_PRIVACY_TARGET_TENANT} "
        f"AND NEW.deletion_manifest_id = {_PRIVACY_MANIFEST} "
        f"AND NEW.user_id = substr({trigger_privacy_hash('user_id')}, 1, 32)::uuid "
        f"AND NEW.tenant_id = substr({trigger_privacy_hash('tenant_id')}, 1, 32)::uuid "
        "AND EXISTS (SELECT 1 FROM saas_privacy_deletion_manifests "
        "privacy_registration_manifest "
        f"WHERE privacy_registration_manifest.id = {_PRIVACY_MANIFEST} "
        "AND privacy_registration_manifest.status = 'executing' "
        "AND privacy_registration_manifest.target_type = 'tenant' "
        f"AND privacy_registration_manifest.target_id = {_PRIVACY_TARGET_TENANT} "
        f"AND privacy_registration_manifest.tenant_id = {_PRIVACY_TARGET_TENANT}))) "
        "THEN RETURN NEW; END IF; "
        "RAISE EXCEPTION 'self-service registration erasure is immutable' "
        "USING ERRCODE = '55000'; END; $$"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION "
        "saas_guard_self_service_registration_privacy_erasure() FROM PUBLIC"
    )
    op.execute(
        "CREATE TRIGGER trg_self_service_registration_privacy_erasure "
        "BEFORE UPDATE ON saas_self_service_registrations FOR EACH ROW "
        "EXECUTE FUNCTION saas_guard_self_service_registration_privacy_erasure()"
    )


def _install_registration_rate_limit_functions() -> None:
    owner_policy = (
        "current_user = pg_catalog.pg_get_userbyid((SELECT catalog.relowner "
        "FROM pg_catalog.pg_class AS catalog WHERE catalog.oid = %s::pg_catalog.regclass))"
    )
    policy_owner = owner_policy % "'public.saas_registration_rate_limit_policies'"
    counter_owner = owner_policy % "'public.saas_registration_rate_limits'"
    op.execute(
        "CREATE POLICY rls_registration_rate_limit_policies_owner "
        "ON public.saas_registration_rate_limit_policies FOR ALL TO PUBLIC "
        f"USING ({policy_owner}) WITH CHECK ({policy_owner})"
    )
    op.execute(
        "CREATE POLICY rls_registration_rate_limits_owner "
        "ON public.saas_registration_rate_limits FOR ALL TO PUBLIC "
        f"USING ({counter_owner}) WITH CHECK ({counter_owner})"
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_consume_registration_rate_limit(
            p_action text,
            p_subject_kind text,
            p_active_key_id text,
            p_active_subject_hmac text,
            p_previous_key_id text,
            p_previous_subject_hmac text,
            p_anchor_key_id text,
            p_write_key_id text
        ) RETURNS TABLE(
            allowed boolean,
            retry_after_seconds integer,
            remaining integer,
            policy_revision text
        )
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '250ms'
        AS $function$
        DECLARE
            v_now timestamptz := pg_catalog.clock_timestamp();
            v_limit_count integer;
            v_window_seconds integer;
            v_retention_seconds integer;
            v_max_rows integer;
            v_current_rows integer;
            v_policy_revision text;
            v_anchor_hmac text;
            v_write_hmac text;
            v_pruned integer := 0;
            v_alias_rows integer := 0;
            v_count bigint := 0;
            v_window_started_at timestamptz;
            v_created_at timestamptz;
            v_version integer := 0;
            v_saturated_count integer;
            v_allowed boolean;
            v_retry_after integer := 0;
        BEGIN
            IF p_action IS NULL OR pg_catalog.length(p_action) NOT BETWEEN 1 AND 64
               OR p_subject_kind IS NULL
               OR pg_catalog.length(p_subject_kind) NOT BETWEEN 1 AND 32
               OR p_active_key_id IS NULL
               OR p_active_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
               OR p_active_subject_hmac IS NULL
               OR p_active_subject_hmac !~ '^[0-9a-f]{64}$'
               OR p_anchor_key_id IS NULL
               OR p_anchor_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
               OR p_write_key_id IS NULL
               OR p_write_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
               OR ((p_previous_key_id IS NULL) <> (p_previous_subject_hmac IS NULL))
               OR (p_previous_key_id IS NOT NULL AND (
                    p_previous_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
                    OR p_previous_subject_hmac !~ '^[0-9a-f]{64}$'
                    OR p_previous_key_id = p_active_key_id
                    OR p_previous_subject_hmac = p_active_subject_hmac
               )) THEN
                RAISE EXCEPTION 'registration rate-limit input rejected' USING ERRCODE = '22023';
            END IF;

            IF p_anchor_key_id = p_active_key_id THEN
                v_anchor_hmac := p_active_subject_hmac;
            ELSIF p_previous_key_id IS NOT NULL AND p_anchor_key_id = p_previous_key_id THEN
                v_anchor_hmac := p_previous_subject_hmac;
            ELSE
                RAISE EXCEPTION 'registration rate-limit anchor rejected' USING ERRCODE = '22023';
            END IF;
            IF p_write_key_id = p_active_key_id THEN
                v_write_hmac := p_active_subject_hmac;
            ELSIF p_previous_key_id IS NOT NULL AND p_write_key_id = p_previous_key_id THEN
                v_write_hmac := p_previous_subject_hmac;
            ELSE
                RAISE EXCEPTION 'registration rate-limit write key rejected'
                    USING ERRCODE = '22023';
            END IF;

            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended(
                    'registration-rate-limit|' || p_action || '|' || p_subject_kind || '|'
                    || p_anchor_key_id || '|' || v_anchor_hmac,
                    0
                )
            );
            SELECT policy.limit_count, policy.window_seconds, policy.retention_seconds,
                   policy.max_rows, policy.current_rows, policy.policy_revision
              INTO v_limit_count, v_window_seconds, v_retention_seconds,
                   v_max_rows, v_current_rows, v_policy_revision
              FROM public.saas_registration_rate_limit_policies AS policy
             WHERE policy.action = p_action AND policy.subject_kind = p_subject_kind
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'registration rate-limit policy unavailable'
                    USING ERRCODE = '55000';
            END IF;

            WITH victims AS (
                SELECT target.ctid
                  FROM public.saas_registration_rate_limits AS target
                 WHERE target.action = p_action
                   AND target.subject_kind = p_subject_kind
                   AND target.expires_at <= v_now
                 ORDER BY target.expires_at
                 LIMIT 32
                 FOR UPDATE
            ), removed AS (
                DELETE FROM public.saas_registration_rate_limits AS target
                 USING victims
                 WHERE target.ctid = victims.ctid
                 RETURNING 1
            )
            SELECT pg_catalog.count(*)::integer INTO v_pruned FROM removed;
            v_current_rows := GREATEST(0, v_current_rows - v_pruned);

            PERFORM 1
              FROM public.saas_registration_rate_limits AS target
             WHERE target.action = p_action
               AND target.subject_kind = p_subject_kind
               AND ((target.key_id = p_active_key_id
                     AND target.subject_hmac = p_active_subject_hmac)
                    OR (p_previous_key_id IS NOT NULL
                        AND target.key_id = p_previous_key_id
                        AND target.subject_hmac = p_previous_subject_hmac))
             FOR UPDATE;
            SELECT COALESCE(pg_catalog.sum(
                       CASE WHEN v_now < target.window_started_at
                                         + pg_catalog.make_interval(secs => v_window_seconds)
                            THEN target.request_count ELSE 0 END
                   ), 0),
                   pg_catalog.min(
                       CASE WHEN v_now < target.window_started_at
                                         + pg_catalog.make_interval(secs => v_window_seconds)
                            THEN target.window_started_at END
                   ),
                   pg_catalog.min(target.created_at),
                   COALESCE(pg_catalog.max(target.version), 0)
              INTO v_count, v_window_started_at, v_created_at, v_version
              FROM public.saas_registration_rate_limits AS target
             WHERE target.action = p_action
               AND target.subject_kind = p_subject_kind
               AND ((target.key_id = p_active_key_id
                     AND target.subject_hmac = p_active_subject_hmac)
                    OR (p_previous_key_id IS NOT NULL
                        AND target.key_id = p_previous_key_id
                        AND target.subject_hmac = p_previous_subject_hmac));
            DELETE FROM public.saas_registration_rate_limits AS target
             WHERE target.action = p_action
               AND target.subject_kind = p_subject_kind
               AND ((target.key_id = p_active_key_id
                     AND target.subject_hmac = p_active_subject_hmac)
                    OR (p_previous_key_id IS NOT NULL
                        AND target.key_id = p_previous_key_id
                        AND target.subject_hmac = p_previous_subject_hmac));
            GET DIAGNOSTICS v_alias_rows = ROW_COUNT;
            v_current_rows := GREATEST(0, v_current_rows - v_alias_rows);
            IF v_current_rows >= v_max_rows THEN
                RAISE EXCEPTION 'registration rate-limit capacity exhausted'
                    USING ERRCODE = '54000';
            END IF;

            IF v_window_started_at IS NULL THEN
                v_window_started_at := v_now;
                v_created_at := v_now;
                v_count := 0;
            END IF;
            v_allowed := v_count < v_limit_count;
            v_saturated_count := LEAST(v_limit_count::bigint, v_count + 1)::integer;
            INSERT INTO public.saas_registration_rate_limits(
                action, subject_kind, key_id, subject_hmac, window_started_at,
                request_count, expires_at, policy_revision, version, created_at, updated_at
            ) VALUES (
                p_action, p_subject_kind, p_write_key_id, v_write_hmac,
                v_window_started_at, v_saturated_count,
                v_window_started_at
                    + pg_catalog.make_interval(secs => v_retention_seconds),
                v_policy_revision, v_version + 1,
                COALESCE(v_created_at, v_now), v_now
            );
            UPDATE public.saas_registration_rate_limit_policies AS policy
               SET current_rows = v_current_rows + 1, updated_at = v_now
             WHERE policy.action = p_action AND policy.subject_kind = p_subject_kind;

            IF NOT v_allowed THEN
                v_retry_after := GREATEST(
                    1,
                    pg_catalog.ceil(pg_catalog.date_part(
                        'epoch',
                        (
                            v_window_started_at
                            + pg_catalog.make_interval(secs => v_window_seconds)
                            - v_now
                        )
                    ))::integer
                );
            END IF;
            RETURN QUERY SELECT v_allowed, v_retry_after,
                                GREATEST(0, v_limit_count - v_saturated_count),
                                v_policy_revision;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_prune_registration_rate_limits(
            p_action text,
            p_subject_kind text,
            p_batch_size integer
        ) RETURNS integer
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET lock_timeout = '500ms'
        AS $function$
        DECLARE
            v_now timestamptz := pg_catalog.clock_timestamp();
            v_deleted integer := 0;
        BEGIN
            IF p_action IS NULL OR pg_catalog.length(p_action) NOT BETWEEN 1 AND 64
               OR p_subject_kind IS NULL
               OR pg_catalog.length(p_subject_kind) NOT BETWEEN 1 AND 32
               OR p_batch_size IS NULL
               OR p_batch_size NOT BETWEEN 1 AND 1000 THEN
                RAISE EXCEPTION 'registration rate-limit prune batch rejected'
                    USING ERRCODE = '22023';
            END IF;
            PERFORM 1 FROM public.saas_registration_rate_limit_policies AS policy
             WHERE policy.action = p_action AND policy.subject_kind = p_subject_kind
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'registration rate-limit policy unavailable'
                    USING ERRCODE = '55000';
            END IF;
            WITH victims AS (
                SELECT target.ctid
                  FROM public.saas_registration_rate_limits AS target
                 WHERE target.action = p_action
                   AND target.subject_kind = p_subject_kind
                   AND target.expires_at <= v_now
                 ORDER BY target.expires_at
                 LIMIT p_batch_size
                 FOR UPDATE
            ), removed AS (
                DELETE FROM public.saas_registration_rate_limits AS target
                 USING victims
                 WHERE target.ctid = victims.ctid
                 RETURNING 1
            )
            SELECT pg_catalog.count(*)::integer INTO v_deleted FROM removed;
            UPDATE public.saas_registration_rate_limit_policies AS policy
               SET current_rows = GREATEST(0, policy.current_rows - v_deleted),
                   updated_at = v_now
             WHERE policy.action = p_action AND policy.subject_kind = p_subject_kind;
            RETURN v_deleted;
        END
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.saas_registration_rate_limit_status()
        RETURNS TABLE(
            action text,
            subject_kind text,
            limit_count integer,
            window_seconds integer,
            retention_seconds integer,
            max_rows integer,
            current_rows integer,
            policy_revision text,
            expired_rows bigint
        )
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $function$
            SELECT policy.action::text, policy.subject_kind::text, policy.limit_count,
                   policy.window_seconds, policy.retention_seconds, policy.max_rows,
                   policy.current_rows, policy.policy_revision::text,
                   (SELECT pg_catalog.count(*)
                      FROM public.saas_registration_rate_limits AS target
                     WHERE target.action = policy.action
                       AND target.subject_kind = policy.subject_kind
                       AND target.expires_at <= pg_catalog.clock_timestamp())
              FROM public.saas_registration_rate_limit_policies AS policy
             ORDER BY policy.action, policy.subject_kind
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_consume_registration_rate_limit("
        "text, text, text, text, text, text, text, text) "
        "FROM PUBLIC, saas_registration, saas_platform"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_prune_registration_rate_limits("
        "text, text, integer) FROM PUBLIC, saas_registration, saas_platform"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.saas_registration_rate_limit_status() "
        "FROM PUBLIC, saas_registration, saas_platform"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.saas_consume_registration_rate_limit("
        "text, text, text, text, text, text, text, text) TO saas_registration"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.saas_prune_registration_rate_limits("
        "text, text, integer) TO saas_platform"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.saas_registration_rate_limit_status() TO saas_platform"
    )


def upgrade() -> None:
    _preflight_postgresql_principal()
    quoted_actions = ", ".join(f"'{action}'" for action in _ACTIONS)
    quoted_subject_kinds = ", ".join(f"'{kind}'" for kind in _SUBJECT_KINDS)
    policies = op.create_table(
        "saas_registration_rate_limit_policies",
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("limit_count", sa.Integer(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("retention_seconds", sa.Integer(), nullable=False),
        sa.Column("max_rows", sa.Integer(), nullable=False),
        sa.Column("current_rows", sa.Integer(), nullable=False),
        sa.Column("policy_revision", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            f"action IN ({quoted_actions})", name="ck_registration_rate_limit_policy_action"
        ),
        sa.CheckConstraint(
            f"subject_kind IN ({quoted_subject_kinds})",
            name="ck_registration_rate_limit_policy_subject_kind",
        ),
        sa.CheckConstraint(
            "limit_count BETWEEN 1 AND 1000", name="ck_registration_rate_limit_policy_limit"
        ),
        sa.CheckConstraint(
            "window_seconds BETWEEN 60 AND 86400",
            name="ck_registration_rate_limit_policy_window",
        ),
        sa.CheckConstraint(
            "retention_seconds BETWEEN window_seconds AND 604800",
            name="ck_registration_rate_limit_policy_retention",
        ),
        sa.CheckConstraint(
            "max_rows BETWEEN 1 AND 10000000",
            name="ck_registration_rate_limit_policy_max_rows",
        ),
        sa.CheckConstraint(
            "current_rows BETWEEN 0 AND max_rows",
            name="ck_registration_rate_limit_policy_current_rows",
        ),
        sa.CheckConstraint(
            "length(policy_revision) BETWEEN 1 AND 128",
            name="ck_registration_rate_limit_policy_revision",
        ),
        sa.PrimaryKeyConstraint("action", "subject_kind"),
    )
    op.bulk_insert(
        policies,
        [
            {
                "action": action,
                "subject_kind": subject_kind,
                "limit_count": limit_count,
                "window_seconds": window_seconds,
                "retention_seconds": retention_seconds,
                "max_rows": max_rows,
                "current_rows": 0,
                "policy_revision": _POLICY_REVISION,
            }
            for (
                action,
                subject_kind,
                limit_count,
                window_seconds,
                retention_seconds,
                max_rows,
            ) in _POLICIES
        ],
    )
    op.create_table(
        "saas_registration_rate_limits",
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("subject_hmac", sa.String(64), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_revision", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            f"action IN ({quoted_actions})", name="ck_registration_rate_limit_action"
        ),
        sa.CheckConstraint(
            f"subject_kind IN ({quoted_subject_kinds})",
            name="ck_registration_rate_limit_subject_kind",
        ),
        sa.CheckConstraint(
            "length(key_id) BETWEEN 1 AND 64", name="ck_registration_rate_limit_key_id"
        ),
        sa.CheckConstraint(_hex64("subject_hmac"), name="ck_registration_rate_limit_subject_hmac"),
        sa.CheckConstraint("request_count > 0", name="ck_registration_rate_limit_count"),
        sa.CheckConstraint(
            "expires_at > window_started_at", name="ck_registration_rate_limit_expiry"
        ),
        sa.CheckConstraint(
            "length(policy_revision) BETWEEN 1 AND 128",
            name="ck_registration_rate_limit_revision",
        ),
        sa.CheckConstraint("version > 0", name="ck_registration_rate_limit_version"),
        sa.ForeignKeyConstraint(
            ["action", "subject_kind"],
            [
                "saas_registration_rate_limit_policies.action",
                "saas_registration_rate_limit_policies.subject_kind",
            ],
            name="fk_registration_rate_limit_policy",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("action", "subject_kind", "key_id", "subject_hmac"),
    )
    op.create_index(
        "ix_registration_rate_limit_expiry",
        "saas_registration_rate_limits",
        ["action", "subject_kind", "expires_at"],
    )
    _add_registration_privacy_erasure()
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE public.saas_registration_rate_limit_policies, "
        "public.saas_registration_rate_limits FROM PUBLIC, saas_registration, saas_platform"
    )
    for table in (
        "saas_registration_rate_limit_policies",
        "saas_registration_rate_limits",
    ):
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    _install_registration_rate_limit_functions()


def _assert_p0s5_downgrade_safe() -> None:
    bind = op.get_bind()
    is_postgresql = bind.dialect.name == "postgresql"
    if is_postgresql:
        op.execute(
            "LOCK TABLE public.saas_registration_rate_limit_policies, "
            "public.saas_registration_rate_limits, "
            "public.saas_self_service_registrations IN ACCESS EXCLUSIVE MODE"
        )
        op.execute("ALTER TABLE public.saas_registration_rate_limits NO FORCE ROW LEVEL SECURITY")
        op.execute(
            "ALTER TABLE public.saas_self_service_registrations NO FORCE ROW LEVEL SECURITY"
        )
    try:
        has_erasure_evidence = (
            bind.execute(
                sa.text(
                    "SELECT 1 FROM saas_self_service_registrations "
                    "WHERE deletion_manifest_id IS NOT NULL LIMIT 1"
                )
            ).first()
            is not None
        )
        has_rate_limit_counters = (
            bind.execute(sa.text("SELECT 1 FROM saas_registration_rate_limits LIMIT 1")).first()
            is not None
        )
    finally:
        if is_postgresql:
            op.execute("ALTER TABLE public.saas_registration_rate_limits FORCE ROW LEVEL SECURITY")
            op.execute(
                "ALTER TABLE public.saas_self_service_registrations FORCE ROW LEVEL SECURITY"
            )
    if has_erasure_evidence:
        raise RuntimeError("cannot downgrade p0s000000005 with anonymized registration evidence")
    if has_rate_limit_counters:
        raise RuntimeError("cannot downgrade p0s000000005 with registration rate-limit counters")


def _drop_registration_privacy_erasure() -> None:
    is_postgresql = op.get_bind().dialect.name == "postgresql"
    if is_postgresql:
        op.execute(
            "DROP TRIGGER IF EXISTS trg_self_service_registration_privacy_erasure "
            "ON saas_self_service_registrations"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS saas_guard_self_service_registration_privacy_erasure()"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_self_service_registrations_privacy_anonymize "
            "ON saas_self_service_registrations"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_self_service_registrations_privacy_target "
            "ON saas_self_service_registrations"
        )
    with op.batch_alter_table("saas_self_service_registrations") as batch_op:
        batch_op.drop_constraint(
            "ck_self_service_registration_deletion_manifest",
            type_="check",
        )
        batch_op.drop_constraint(
            "fk_self_service_registration_deletion_manifest",
            type_="foreignkey",
        )
        batch_op.drop_column("deletion_manifest_id")


def downgrade() -> None:
    _assert_p0s5_downgrade_safe()
    _drop_registration_privacy_erasure()
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS public.saas_registration_rate_limit_status()")
        op.execute(
            "DROP FUNCTION IF EXISTS public.saas_prune_registration_rate_limits("
            "text, text, integer)"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS public.saas_consume_registration_rate_limit("
            "text, text, text, text, text, text, text, text)"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_registration_rate_limits_owner "
            "ON public.saas_registration_rate_limits"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_registration_rate_limit_policies_owner "
            "ON public.saas_registration_rate_limit_policies"
        )
    op.drop_index(
        "ix_registration_rate_limit_expiry",
        table_name="saas_registration_rate_limits",
    )
    op.drop_table("saas_registration_rate_limits")
    op.drop_table("saas_registration_rate_limit_policies")
