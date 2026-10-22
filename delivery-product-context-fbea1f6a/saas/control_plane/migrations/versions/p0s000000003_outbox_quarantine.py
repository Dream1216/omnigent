"""Add Outbox quarantine evidence and actor-owned onboarding status reads.

Revision ID: p0s000000003
Revises: p0s000000002
"""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000003"
down_revision: str | None = "p0s000000002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ONBOARDING_STATUS_COLUMNS = (
    "id",
    "user_id",
    "tenant_id",
    "space_id",
    "default_project_id",
    "status",
    "version",
    "trial_ends_at",
    "last_transition_at",
    "created_at",
)
_OUTBOX_QUARANTINE_COLUMNS = frozenset({"last_error_code", "last_error_digest", "quarantined_at"})
_COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
_N1_OUTBOX_COMPAT_ROLE = "saas_dispatcher_n1_compat"
_N1_OUTBOX_SELECT_COLUMNS = (
    "id",
    "published_at",
    "available_at",
    "claimed_at",
    "created_at",
    "claim_token",
    "event_type",
    "aggregate_type",
    "aggregate_key",
    "payload",
    "attempt_count",
)
_N1_OUTBOX_UPDATE_COLUMNS = (
    "attempt_count",
    "available_at",
    "claimed_at",
    "claim_token",
    "last_error",
    "published_at",
)


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def _revoke_all_column_privileges(table: str, role: str) -> None:
    """Remove column ACL drift before installing an exact PostgreSQL grant set."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    preparer = bind.dialect.identifier_preparer
    quoted_columns = ", ".join(
        preparer.quote(str(column["name"])) for column in sa.inspect(bind).get_columns(table)
    )
    if not quoted_columns:
        raise RuntimeError(f"cannot converge privileges for columnless table {table}")
    quoted_table = preparer.quote(table)
    quoted_role = preparer.quote(role)
    for privilege in _COLUMN_PRIVILEGES:
        op.execute(f"REVOKE {privilege} ({quoted_columns}) ON {quoted_table} FROM {quoted_role}")


def _preflight_postgresql_principals() -> None:
    """Require operator-owned roles while Alembic remains NOCREATEROLE."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    required_roles = (
        "saas_dispatcher",
        _N1_OUTBOX_COMPAT_ROLE,
        "saas_onboarding_status",
    )
    rows = {
        str(row["rolname"]): row
        for row in bind.execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles "
                "WHERE rolname IN ('saas_dispatcher', 'saas_dispatcher_n1_compat', "
                "'saas_onboarding_status')"
            )
        ).mappings()
    }
    unsafe = []
    for role_name in required_roles:
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
    unexpected_memberships = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "WHERE member.rolname IN ('saas_dispatcher', 'saas_onboarding_status')"
        )
    ).scalar_one()
    if unexpected_memberships:
        unsafe.append("fixed membership graph")
    if unsafe:
        raise RuntimeError(
            "cannot apply p0s000000003: PostgreSQL principal preflight rejected; "
            "run postgresql_principals.psql before Alembic"
        )


def _preflight_n1_compat_role_isolated() -> None:
    """Reject role drift without expanding p0s3's Outbox-only lock boundary."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    unsafe_memberships = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
            "WHERE member.rolname = :role AND granted.rolname <> 'saas_dispatcher'"
        ),
        {"role": _N1_OUTBOX_COMPAT_ROLE},
    ).scalar_one()
    incoming_members = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
            "WHERE granted.rolname = :role "
            "AND (NOT membership.admin_option "
            "OR COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true) "
            "OR COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true))"
        ),
        {"role": _N1_OUTBOX_COMPAT_ROLE},
    ).scalar_one()
    fixed_membership = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
            "WHERE member.rolname = :role AND granted.rolname = 'saas_dispatcher' "
            "AND NOT membership.admin_option "
            "AND NOT COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true) "
            "AND NOT COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true)"
        ),
        {"role": _N1_OUTBOX_COMPAT_ROLE},
    ).scalar_one()
    unsafe_relations = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "JOIN pg_roles AS owner ON owner.oid = relation.relowner "
            "WHERE namespace.nspname = 'public' "
            "AND relation.relkind IN ('r', 'p') "
            "AND (owner.rolname = :role OR (left(relation.relname, 5) = 'saas_' "
            "AND relation.relname <> 'saas_control_plane_outbox' AND ("
            "has_table_privilege(:role, relation.oid, 'SELECT,INSERT,UPDATE,DELETE,"
            "TRUNCATE,REFERENCES,TRIGGER') OR "
            "has_any_column_privilege(:role, relation.oid, "
            "'SELECT,INSERT,UPDATE,REFERENCES'))))"
        ),
        {"role": _N1_OUTBOX_COMPAT_ROLE},
    ).scalar_one()
    if unsafe_memberships or incoming_members or fixed_membership != 1 or unsafe_relations:
        raise RuntimeError(
            "cannot apply p0s000000003: pre-existing N-1 compatibility role "
            "has incoming/outgoing membership, missing fixed membership, ownership, "
            "or non-Outbox table privilege drift"
        )


def _lock_and_expose_owner_rows(*tables: str) -> None:
    """Freeze writers, then let the schema owner inspect every FORCE-RLS row.

    PostgreSQL retains both the locks and the temporary ``NO FORCE`` posture
    until the surrounding Alembic transaction commits or rolls back.  Callers
    must pass tables in the global lock order; p0s3 always uses Outbox before
    its quarantine ledger.
    """

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    preparer = bind.dialect.identifier_preparer
    for table in tables:
        quoted_table = preparer.quote(table)
        op.execute(f"LOCK TABLE public.{quoted_table} IN ACCESS EXCLUSIVE MODE")
    for table in tables:
        quoted_table = preparer.quote(table)
        op.execute(f"ALTER TABLE public.{quoted_table} NO FORCE ROW LEVEL SECURITY")


def _restore_force_rls(table: str) -> None:
    """Restore owner-enforced RLS on the successful transaction path."""

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    quoted_table = bind.dialect.identifier_preparer.quote(table)
    op.execute(f"ALTER TABLE public.{quoted_table} FORCE ROW LEVEL SECURITY")


def _extend_outbox() -> None:
    bind = op.get_bind()
    existing_columns = {
        str(column["name"]) for column in sa.inspect(bind).get_columns("saas_control_plane_outbox")
    }
    present_quarantine_columns = existing_columns & _OUTBOX_QUARANTINE_COLUMNS
    if present_quarantine_columns and present_quarantine_columns != _OUTBOX_QUARANTINE_COLUMNS:
        raise RuntimeError("cannot apply p0s000000003 over a partial Outbox quarantine column set")
    if not present_quarantine_columns:
        op.add_column(
            "saas_control_plane_outbox",
            sa.Column("last_error_code", sa.String(128), server_default=sa.text("NULL")),
        )
        op.add_column(
            "saas_control_plane_outbox",
            sa.Column("last_error_digest", sa.String(64), server_default=sa.text("NULL")),
        )
        op.add_column(
            "saas_control_plane_outbox",
            sa.Column(
                "quarantined_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("NULL"),
            ),
        )
    dirty_terminal = bind.execute(
        sa.text(
            "SELECT id FROM saas_control_plane_outbox "
            "WHERE quarantined_at IS NOT NULL AND "
            "(available_at IS NOT NULL OR claimed_at IS NOT NULL OR claim_token IS NOT NULL) "
            "LIMIT 1"
        )
    ).scalar_one_or_none()
    if dirty_terminal is not None:
        raise RuntimeError(
            "cannot apply p0s000000003: an existing quarantined Outbox row "
            "retains dispatch scheduling or lease state"
        )
    legacy_errors = bind.execute(
        sa.text(
            "SELECT id, last_error FROM saas_control_plane_outbox WHERE last_error IS NOT NULL"
        )
    ).mappings()
    for row in legacy_errors:
        # Legacy error text may contain secrets.  Bind migration evidence to
        # the source event without retaining, hashing, or otherwise deriving
        # data from the unsafe text itself.
        digest = sha256(b"legacy_delivery_error\0" + str(row["id"]).encode()).hexdigest()
        bind.execute(
            sa.text(
                "UPDATE saas_control_plane_outbox SET last_error = NULL, "
                "last_error_code = 'legacy_delivery_error', "
                "last_error_digest = :digest WHERE id = :event_id"
            ),
            {"digest": digest, "event_id": row["id"]},
        )
    with op.batch_alter_table("saas_control_plane_outbox") as batch_op:
        batch_op.drop_constraint("ck_outbox_request_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_outbox_request_hash",
            _hex64("request_hash"),
        )
        batch_op.create_check_constraint(
            "ck_outbox_legacy_error_null",
            "last_error IS NULL",
        )
        batch_op.create_check_constraint(
            "ck_outbox_terminal_exclusive",
            "published_at IS NULL OR quarantined_at IS NULL",
        )
        batch_op.create_check_constraint(
            "ck_outbox_quarantine_dispatch_clear",
            "quarantined_at IS NULL OR "
            "(available_at IS NULL AND claimed_at IS NULL AND claim_token IS NULL)",
        )
        batch_op.create_check_constraint(
            "ck_outbox_safe_error_pair",
            "(last_error_code IS NULL AND last_error_digest IS NULL) OR "
            "(length(last_error_code) BETWEEN 1 AND 128 AND last_error_digest IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            "ck_outbox_safe_error_digest",
            f"last_error_digest IS NULL OR ({_hex64('last_error_digest')})",
        )
    op.create_index(
        "ix_outbox_dispatchable_v2",
        "saas_control_plane_outbox",
        ["quarantined_at", "published_at", "available_at", "claimed_at"],
    )


def _create_quarantine_ledger() -> None:
    op.create_table(
        "saas_outbox_quarantine_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_event_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("source_request_hash", sa.String(64), nullable=False),
        sa.Column("source_attempt_count", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(128), nullable=False),
        sa.Column("error_digest", sa.String(64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("action IN ('quarantined')", name="ck_outbox_quarantine_action"),
        sa.CheckConstraint("source_attempt_count > 0", name="ck_outbox_quarantine_attempt_count"),
        sa.CheckConstraint(
            "length(error_code) BETWEEN 1 AND 128",
            name="ck_outbox_quarantine_error_code",
        ),
        sa.CheckConstraint(_hex64("source_request_hash"), name="ck_outbox_quarantine_source_hash"),
        sa.CheckConstraint(_hex64("error_digest"), name="ck_outbox_quarantine_error_digest"),
        sa.CheckConstraint("sequence > 0", name="ck_outbox_quarantine_sequence"),
        sa.CheckConstraint(_hex64("previous_hash"), name="ck_outbox_quarantine_previous_hash"),
        sa.CheckConstraint(_hex64("event_hash"), name="ck_outbox_quarantine_event_hash"),
        sa.ForeignKeyConstraint(
            ("source_event_id",),
            ("saas_control_plane_outbox.id",),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(("tenant_id",), ("saas_tenants.id",), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_hash", name="uq_outbox_quarantine_event_hash"),
        sa.UniqueConstraint(
            "source_event_id",
            "sequence",
            name="uq_outbox_quarantine_source_sequence",
        ),
    )
    op.create_index(
        "uq_outbox_quarantine_once",
        "saas_outbox_quarantine_events",
        ["source_event_id"],
        unique=True,
        sqlite_where=sa.text("action = 'quarantined'"),
        postgresql_where=sa.text("action = 'quarantined'"),
    )
    op.create_index(
        "ix_outbox_quarantine_tenant_created",
        "saas_outbox_quarantine_events",
        ["tenant_id", "created_at", "id"],
    )


def _install_immutable_trigger() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE FUNCTION saas_reject_outbox_quarantine_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
            "'outbox quarantine events are immutable' USING ERRCODE = '55000'; END $$"
        )
        op.execute(
            "CREATE TRIGGER trg_outbox_quarantine_immutable BEFORE UPDATE OR DELETE "
            "ON saas_outbox_quarantine_events FOR EACH ROW "
            "EXECUTE FUNCTION saas_reject_outbox_quarantine_mutation()"
        )
        return
    if bind.dialect.name == "sqlite":
        op.execute(
            "CREATE TRIGGER trg_outbox_quarantine_update_immutable "
            "BEFORE UPDATE ON saas_outbox_quarantine_events BEGIN "
            "SELECT RAISE(ABORT, 'outbox quarantine events are immutable'); END"
        )
        op.execute(
            "CREATE TRIGGER trg_outbox_quarantine_delete_immutable "
            "BEFORE DELETE ON saas_outbox_quarantine_events BEGIN "
            "SELECT RAISE(ABORT, 'outbox quarantine events are immutable'); END"
        )


def _install_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # Converge dispatcher authority in the same transaction that adds the new
    # quarantine columns.  A later role-bootstrap replay remains defence in
    # depth, but is not required to remove a historical table-level UPDATE or
    # an unexpected column ACL.
    op.execute("REVOKE ALL PRIVILEGES ON saas_control_plane_outbox FROM saas_dispatcher")
    _revoke_all_column_privileges("saas_control_plane_outbox", "saas_dispatcher")
    op.execute("GRANT SELECT ON saas_control_plane_outbox TO saas_dispatcher")
    op.execute(
        "GRANT UPDATE (attempt_count, available_at, claimed_at, claim_token, "
        "last_error_code, last_error_digest, published_at, quarantined_at) "
        "ON saas_control_plane_outbox TO saas_dispatcher"
    )
    op.execute("ALTER TABLE saas_outbox_quarantine_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE saas_outbox_quarantine_events FORCE ROW LEVEL SECURITY")
    exact_source = (
        "pg_has_role(current_user, 'saas_dispatcher', 'member') "
        "AND saas_outbox_quarantine_events.action = 'quarantined' "
        "AND EXISTS (SELECT 1 FROM saas_control_plane_outbox source "
        "WHERE source.id = saas_outbox_quarantine_events.source_event_id "
        "AND source.request_hash = saas_outbox_quarantine_events.source_request_hash "
        "AND source.tenant_id IS NOT DISTINCT FROM "
        "saas_outbox_quarantine_events.tenant_id "
        "AND source.attempt_count = "
        "saas_outbox_quarantine_events.source_attempt_count "
        "AND source.last_error_code = saas_outbox_quarantine_events.error_code "
        "AND source.last_error_digest = saas_outbox_quarantine_events.error_digest "
        "AND source.quarantined_at = saas_outbox_quarantine_events.created_at "
        "AND source.published_at IS NULL "
        "AND saas_outbox_quarantine_events.sequence = 1 "
        "AND saas_outbox_quarantine_events.previous_hash = repeat('0', 64))"
    )
    op.execute(
        "CREATE POLICY rls_outbox_quarantine_dispatcher_select "
        "ON saas_outbox_quarantine_events FOR SELECT TO saas_dispatcher "
        f"USING ({exact_source})"
    )
    op.execute(
        "CREATE POLICY rls_outbox_quarantine_dispatcher_insert "
        "ON saas_outbox_quarantine_events FOR INSERT TO saas_dispatcher "
        f"WITH CHECK ({exact_source})"
    )
    op.execute("REVOKE ALL ON saas_outbox_quarantine_events FROM PUBLIC")
    op.execute("GRANT SELECT, INSERT ON saas_outbox_quarantine_events TO saas_dispatcher")
    op.execute(
        "CREATE FUNCTION saas_enforce_outbox_quarantine_receipt() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ DECLARE matching_receipts integer; BEGIN "
        "IF NEW.quarantined_at IS NULL THEN "
        "IF TG_OP = 'UPDATE' AND OLD.quarantined_at IS NOT NULL THEN "
        "RAISE EXCEPTION 'outbox quarantine is terminal' USING ERRCODE = '23514'; "
        "END IF; RETURN NULL; END IF; "
        "SELECT count(*) INTO matching_receipts "
        "FROM public.saas_outbox_quarantine_events AS receipt WHERE "
        "receipt.source_event_id = NEW.id "
        "AND receipt.tenant_id IS NOT DISTINCT FROM NEW.tenant_id "
        "AND receipt.source_request_hash = NEW.request_hash "
        "AND receipt.source_attempt_count = NEW.attempt_count "
        "AND receipt.action = 'quarantined' "
        "AND receipt.error_code = NEW.last_error_code "
        "AND receipt.error_digest = NEW.last_error_digest "
        "AND receipt.sequence = 1 AND receipt.previous_hash = repeat('0', 64) "
        "AND receipt.created_at = NEW.quarantined_at; "
        "IF NEW.published_at IS NOT NULL OR NEW.available_at IS NOT NULL "
        "OR NEW.claimed_at IS NOT NULL OR NEW.claim_token IS NOT NULL "
        "OR matching_receipts <> 1 THEN "
        "RAISE EXCEPTION 'outbox quarantine requires one exact receipt and "
        "cleared dispatch state' "
        "USING ERRCODE = '23514'; END IF; RETURN NULL; END $$"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER trg_outbox_quarantine_receipt_exact "
        "AFTER INSERT OR UPDATE ON saas_control_plane_outbox "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "EXECUTE FUNCTION saas_enforce_outbox_quarantine_receipt()"
    )


def _install_n1_outbox_compatibility() -> None:
    """Admit the pinned N-1 dispatcher without persisting its raw errors.

    The security-patched N-1 worker omits its legacy table-privilege verifier,
    runs this bridge's catalog admission instead, and includes ``last_error``
    in claim, acknowledgement, and failure statements.  It receives only the
    fixed SELECT and six operational UPDATE columns used by 9451a64; a future
    Outbox column is therefore not inherited through a table grant.  Deployment
    gives the patched image a login that inherits this narrow compatibility
    role.  The compatibility role is a non-inheriting member of
    ``saas_dispatcher`` so RLS membership predicates still match, while none of
    the p0s3 dispatcher's quarantine/planning privileges flow to the old image.

    A restrictive policy hides terminal quarantine rows that N-1 cannot
    understand.  A BEFORE trigger rejects changes outside N-1's historical
    operational columns and discards every raw error before constraints or
    storage see the row, replacing it with content-blind event/attempt evidence.
    The legacy NULL check remains the final at-rest invariant.
    """

    if op.get_bind().dialect.name != "postgresql":
        return
    _preflight_n1_compat_role_isolated()
    # The old Outbox RLS expression references these Staff authority tables,
    # so PostgreSQL requires planning-time column privileges even though the
    # dispatcher branch does not consume their rows.  A role-specific
    # restrictive false policy makes those grants provably zero-row and
    # remains effective even if another permissive policy is added later.
    op.execute(
        "CREATE POLICY rls_n1_compat_role_assignments_deny "
        "ON saas_platform_role_assignments AS RESTRICTIVE FOR SELECT "
        f"TO {_N1_OUTBOX_COMPAT_ROLE} USING (false)"
    )
    op.execute(
        "CREATE POLICY rls_n1_compat_support_sessions_deny "
        "ON saas_platform_support_sessions AS RESTRICTIVE FOR SELECT "
        f"TO {_N1_OUTBOX_COMPAT_ROLE} USING (false)"
    )
    op.execute(
        "CREATE POLICY rls_outbox_n1_compat_dispatchable "
        "ON saas_control_plane_outbox AS RESTRICTIVE FOR ALL "
        f"TO {_N1_OUTBOX_COMPAT_ROLE} USING (quarantined_at IS NULL) "
        "WITH CHECK (quarantined_at IS NULL)"
    )
    op.execute(
        "CREATE FUNCTION saas_bridge_n1_outbox_update() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog AS $$ "
        "DECLARE is_claim boolean; is_ack boolean; is_failure boolean; BEGIN "
        f"IF NOT pg_has_role(current_user, '{_N1_OUTBOX_COMPAT_ROLE}', 'member') THEN "
        "RETURN NEW; END IF; "
        "IF NEW.id IS DISTINCT FROM OLD.id "
        "OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id "
        "OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type "
        "OR NEW.aggregate_key IS DISTINCT FROM OLD.aggregate_key "
        "OR NEW.event_type IS DISTINCT FROM OLD.event_type "
        "OR to_jsonb(NEW.payload) IS DISTINCT FROM to_jsonb(OLD.payload) "
        "OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key "
        "OR NEW.request_hash IS DISTINCT FROM OLD.request_hash "
        "OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code "
        "OR NEW.last_error_digest IS DISTINCT FROM OLD.last_error_digest "
        "OR NEW.quarantined_at IS DISTINCT FROM OLD.quarantined_at "
        "OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN "
        "RAISE EXCEPTION 'N-1 Outbox compatibility update exceeds its operational boundary' "
        "USING ERRCODE = '42501'; END IF; "
        "is_claim := OLD.published_at IS NULL AND NEW.published_at IS NULL "
        "AND NEW.attempt_count = OLD.attempt_count + 1 "
        "AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at "
        "AND NEW.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at "
        "AND NEW.claim_token IS NOT NULL AND NEW.claim_token IS DISTINCT FROM OLD.claim_token "
        "AND NEW.last_error IS NULL; "
        "is_ack := OLD.published_at IS NULL AND NEW.published_at IS NOT NULL "
        "AND NEW.attempt_count = OLD.attempt_count "
        "AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at "
        "AND OLD.claimed_at IS NOT NULL AND OLD.claim_token IS NOT NULL "
        "AND NEW.claimed_at IS NULL AND NEW.claim_token IS NULL "
        "AND NEW.last_error IS NULL; "
        "is_failure := OLD.published_at IS NULL AND NEW.published_at IS NULL "
        "AND NEW.attempt_count = OLD.attempt_count "
        "AND OLD.claimed_at IS NOT NULL AND OLD.claim_token IS NOT NULL "
        "AND NEW.claimed_at IS NULL AND NEW.claim_token IS NULL "
        "AND NEW.available_at IS NOT NULL AND NEW.available_at > OLD.claimed_at "
        "AND NEW.available_at IS DISTINCT FROM OLD.available_at "
        "AND NEW.last_error IS NOT NULL; "
        "IF NOT (is_claim OR is_ack OR is_failure) THEN "
        "RAISE EXCEPTION 'N-1 Outbox compatibility transition is not claim, ack, or failure' "
        "USING ERRCODE = '42501'; END IF; "
        "IF is_failure THEN "
        "NEW.last_error := NULL; "
        "NEW.last_error_code := 'n1_compat_delivery_error'; "
        "NEW.last_error_digest := encode(sha256(convert_to("
        "'omnigent:n1-outbox:error:v1:' || NEW.id::text || ':' || NEW.request_hash "
        "|| ':' || NEW.attempt_count::text, 'UTF8')), 'hex'); "
        "ELSE "
        "NEW.last_error_code := NULL; NEW.last_error_digest := NULL; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute("REVOKE ALL ON FUNCTION saas_bridge_n1_outbox_update() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER trg_outbox_n1_compatibility BEFORE UPDATE "
        "ON saas_control_plane_outbox FOR EACH ROW "
        "EXECUTE FUNCTION saas_bridge_n1_outbox_update()"
    )
    # The fixed column grants are installed last, only after both independent
    # guards exist.  Schema migrations must drain this worker before any Outbox
    # DDL and must rerun catalog admission before restart; a schema signature
    # mismatch fails closed even when all old columns remain present.
    op.execute(f"REVOKE ALL PRIVILEGES ON saas_control_plane_outbox FROM {_N1_OUTBOX_COMPAT_ROLE}")
    _revoke_all_column_privileges("saas_control_plane_outbox", _N1_OUTBOX_COMPAT_ROLE)
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {_N1_OUTBOX_COMPAT_ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_N1_OUTBOX_COMPAT_ROLE}")
    select_columns = ", ".join(_N1_OUTBOX_SELECT_COLUMNS)
    update_columns = ", ".join(_N1_OUTBOX_UPDATE_COLUMNS)
    op.execute(
        f"GRANT SELECT ({select_columns}) ON saas_control_plane_outbox TO {_N1_OUTBOX_COMPAT_ROLE}"
    )
    op.execute(
        f"GRANT UPDATE ({update_columns}) ON saas_control_plane_outbox TO {_N1_OUTBOX_COMPAT_ROLE}"
    )


def _install_outbox_producer_initial_state_policy() -> None:
    """Prevent ordinary producers from fabricating dispatcher state or outcomes."""

    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "CREATE POLICY rls_outbox_producer_initial_state "
        "ON saas_control_plane_outbox AS RESTRICTIVE FOR INSERT TO PUBLIC "
        "WITH CHECK (pg_has_role(current_user, 'saas_platform', 'member') OR ("
        "attempt_count = 0 AND claimed_at IS NULL AND claim_token IS NULL "
        "AND last_error IS NULL AND last_error_code IS NULL "
        "AND last_error_digest IS NULL AND published_at IS NULL "
        "AND quarantined_at IS NULL))"
    )


def _install_customer_status_authority() -> None:
    """Install a dedicated actor-owned, read-only onboarding status authority."""

    if op.get_bind().dialect.name != "postgresql":
        return
    columns = ", ".join(_ONBOARDING_STATUS_COLUMNS)
    actor_id = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
    op.execute("REVOKE ALL PRIVILEGES ON saas_tenant_onboardings FROM saas_app")
    _revoke_all_column_privileges("saas_tenant_onboardings", "saas_app")
    for table in (
        "saas_tenant_onboardings",
        "saas_tenant_memberships",
        "saas_platform_role_assignments",
        "saas_platform_support_sessions",
    ):
        op.execute(f"REVOKE ALL PRIVILEGES ON {table} FROM saas_onboarding_status")
        _revoke_all_column_privileges(table, "saas_onboarding_status")
    op.execute(
        "CREATE POLICY rls_tenant_memberships_onboarding_status "
        "ON saas_tenant_memberships FOR SELECT TO saas_onboarding_status USING ("
        "pg_has_role(current_user, 'saas_onboarding_status', 'member') AND "
        f"{actor_id} IS NOT NULL AND user_id = {actor_id} AND status = 'active')"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_customer_status "
        "ON saas_tenant_onboardings FOR SELECT TO saas_onboarding_status USING ("
        "pg_has_role(current_user, 'saas_onboarding_status', 'member') AND "
        f"{actor_id} IS NOT NULL AND user_id = {actor_id} AND "
        "EXISTS (SELECT 1 FROM saas_tenant_memberships membership "
        "WHERE membership.tenant_id = saas_tenant_onboardings.tenant_id "
        f"AND membership.user_id = {actor_id} AND membership.status = 'active'))"
    )
    op.execute(
        "GRANT SELECT (tenant_id, user_id, status) "
        "ON saas_tenant_memberships TO saas_onboarding_status"
    )
    op.execute(
        "GRANT SELECT (principal_id, role, status, expires_at) "
        "ON saas_platform_role_assignments TO saas_onboarding_status"
    )
    op.execute(
        "GRANT SELECT (principal_id, token_hash, revoked_at, expires_at) "
        "ON saas_platform_support_sessions TO saas_onboarding_status"
    )
    op.execute(f"GRANT SELECT ({columns}) ON saas_tenant_onboardings TO saas_onboarding_status")


def upgrade() -> None:
    # The preceding revision already FORCEs Outbox RLS.  Acquire the strongest
    # lock before temporarily exempting only the table owner so legacy rows are
    # fully visible and no dispatcher can race the scrub or constraint checks.
    # A failed migration rolls both the lock-protected DDL and NO FORCE back.
    _preflight_postgresql_principals()
    _preflight_n1_compat_role_isolated()
    _lock_and_expose_owner_rows("saas_control_plane_outbox")
    _extend_outbox()
    _create_quarantine_ledger()
    _install_immutable_trigger()
    _install_postgresql_authority()
    _install_n1_outbox_compatibility()
    _install_outbox_producer_initial_state_policy()
    _install_customer_status_authority()
    _restore_force_rls("saas_control_plane_outbox")


def downgrade() -> None:
    bind = op.get_bind()
    # Use the same fixed order as quarantine writes: source Outbox first, then
    # Receipt ledger.  ACCESS EXCLUSIVE prevents evidence from appearing after
    # the preflight.  NO FORCE exposes every row to the owning migration role;
    # any raised preflight error relies on transaction rollback to restore both
    # FORCE postures and release both locks.
    _lock_and_expose_owner_rows(
        "saas_control_plane_outbox",
        "saas_outbox_quarantine_events",
    )
    quarantine_evidence = bind.execute(
        sa.text("SELECT 1 FROM saas_outbox_quarantine_events LIMIT 1")
    ).first()
    delivery_evidence = bind.execute(
        sa.text(
            "SELECT 1 FROM saas_control_plane_outbox WHERE "
            "last_error_code IS NOT NULL OR last_error_digest IS NOT NULL "
            "OR quarantined_at IS NOT NULL LIMIT 1"
        )
    ).first()
    if quarantine_evidence is not None or delivery_evidence is not None:
        raise RuntimeError("cannot downgrade p0s000000003 with durable Outbox delivery evidence")
    if bind.dialect.name == "postgresql":
        columns = ", ".join(_ONBOARDING_STATUS_COLUMNS)
        op.execute(
            f"REVOKE ALL PRIVILEGES ON saas_control_plane_outbox FROM {_N1_OUTBOX_COMPAT_ROLE}"
        )
        _revoke_all_column_privileges("saas_control_plane_outbox", _N1_OUTBOX_COMPAT_ROLE)
        op.execute(
            "REVOKE SELECT (principal_id, role, status, expires_at) "
            f"ON saas_platform_role_assignments FROM {_N1_OUTBOX_COMPAT_ROLE}"
        )
        op.execute(
            "REVOKE SELECT (principal_id, token_hash, revoked_at, expires_at) "
            f"ON saas_platform_support_sessions FROM {_N1_OUTBOX_COMPAT_ROLE}"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_n1_compat_role_assignments_deny "
            "ON saas_platform_role_assignments"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_n1_compat_support_sessions_deny "
            "ON saas_platform_support_sessions"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_outbox_n1_compat_dispatchable ON saas_control_plane_outbox"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_outbox_n1_compatibility ON saas_control_plane_outbox"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_bridge_n1_outbox_update()")
        op.execute(
            "DROP POLICY IF EXISTS rls_outbox_producer_initial_state ON saas_control_plane_outbox"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_tenant_onboardings_customer_status "
            "ON saas_tenant_onboardings"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_tenant_memberships_onboarding_status "
            "ON saas_tenant_memberships"
        )
        op.execute(
            f"REVOKE SELECT ({columns}) ON saas_tenant_onboardings FROM saas_onboarding_status"
        )
        op.execute(
            "REVOKE SELECT (tenant_id, user_id, status) "
            "ON saas_tenant_memberships FROM saas_onboarding_status"
        )
        op.execute(
            "REVOKE SELECT (principal_id, role, status, expires_at) "
            "ON saas_platform_role_assignments FROM saas_onboarding_status"
        )
        op.execute(
            "REVOKE SELECT (principal_id, token_hash, revoked_at, expires_at) "
            "ON saas_platform_support_sessions FROM saas_onboarding_status"
        )
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_outbox_quarantine_immutable "
            "ON saas_outbox_quarantine_events"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_reject_outbox_quarantine_mutation()")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_outbox_quarantine_receipt_exact "
            "ON saas_control_plane_outbox"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_enforce_outbox_quarantine_receipt()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_outbox_quarantine_update_immutable")
        op.execute("DROP TRIGGER IF EXISTS trg_outbox_quarantine_delete_immutable")
    op.drop_index(
        "ix_outbox_quarantine_tenant_created",
        table_name="saas_outbox_quarantine_events",
    )
    op.drop_index("uq_outbox_quarantine_once", table_name="saas_outbox_quarantine_events")
    op.drop_table("saas_outbox_quarantine_events")
    op.drop_index("ix_outbox_dispatchable_v2", table_name="saas_control_plane_outbox")
    with op.batch_alter_table("saas_control_plane_outbox") as batch_op:
        batch_op.drop_constraint("ck_outbox_legacy_error_null", type_="check")
        batch_op.drop_constraint("ck_outbox_request_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_outbox_request_hash",
            "length(request_hash) = 64",
        )
        batch_op.drop_constraint("ck_outbox_safe_error_digest", type_="check")
        batch_op.drop_constraint("ck_outbox_safe_error_pair", type_="check")
        batch_op.drop_constraint("ck_outbox_quarantine_dispatch_clear", type_="check")
        batch_op.drop_constraint("ck_outbox_terminal_exclusive", type_="check")
        batch_op.drop_column("quarantined_at")
        batch_op.drop_column("last_error_digest")
        batch_op.drop_column("last_error_code")
    if bind.dialect.name == "postgresql":
        # Restore the exact p0s2/N-1 authority.  In particular, last_error must
        # remain writable by the old dispatcher until a later upgrade converges
        # the role back to p0s3's eight operational UPDATE columns.
        op.execute("REVOKE ALL PRIVILEGES ON saas_control_plane_outbox FROM saas_dispatcher")
        _revoke_all_column_privileges("saas_control_plane_outbox", "saas_dispatcher")
        op.execute("GRANT SELECT, UPDATE ON saas_control_plane_outbox TO saas_dispatcher")
        _restore_force_rls("saas_control_plane_outbox")
