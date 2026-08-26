"""Add the durable PostgreSQL Runtime Provider operation journal.

Revision ID: p0s000000004
Revises: p0s000000003
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000004"
down_revision: str | None = "p0s000000003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JOURNAL_ROLE = "saas_runtime_provider_journal"
_OPERATIONS = (
    "allocate_partition",
    "provision_default_project",
    "compensate_default_project",
    "compensate_partition",
)
_LEGACY_TARGET_ERROR_CODE = "legacy_runtime_target_binding_unavailable"
_LEGACY_TARGET_EVENT_TYPE = "tenant_onboarding.legacy_runtime_target_manual_review"
_ZERO_HASH = "0" * 64
_PROVIDER_CALLING_ONBOARDING_STATUSES = (
    "billing_ready",
    "runtime_ready",
    "project_ready",
    "compensating",
)


def _hex64(column: str) -> str:
    remainder = column
    for value in "0123456789abcdef":
        remainder = f"replace({remainder}, '{value}', '')"
    return f"length({column}) = 64 AND {remainder} = ''"


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _preflight_postgresql_role() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    role = (
        bind.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                "FROM pg_roles WHERE rolname = :role"
            ),
            {"role": _JOURNAL_ROLE},
        )
        .mappings()
        .one_or_none()
    )
    if role is None:
        raise RuntimeError(
            "cannot apply p0s000000004: saas_runtime_provider_journal principal "
            "must be bootstrapped before the schema migration"
        )
    if (
        tuple(
            bool(role[column])
            for column in (
                "rolcanlogin",
                "rolsuper",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolbypassrls",
                "rolinherit",
            )
        )
        != (False, False, False, False, False, False, True)
        or int(role["rolconnlimit"]) != -1
        or role["rolconfig"] is not None
    ):
        raise RuntimeError(
            "cannot apply p0s000000004: saas_runtime_provider_journal role facts are unsafe"
        )
    inherited_roles = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_auth_members AS membership "
            "JOIN pg_roles AS member ON member.oid = membership.member "
            "WHERE member.rolname = :role"
        ),
        {"role": _JOURNAL_ROLE},
    ).scalar_one()
    if inherited_roles:
        raise RuntimeError(
            "cannot apply p0s000000004: saas_runtime_provider_journal must not inherit roles"
        )
    public_has_temporary = bind.execute(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM pg_database AS database "
            "CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, "
            "acldefault('d', database.datdba))) AS privilege "
            "WHERE database.datname = current_database() "
            "AND privilege.grantee = 0 "
            "AND privilege.privilege_type = 'TEMPORARY')"
        )
    ).scalar_one()
    if public_has_temporary:
        raise RuntimeError(
            "cannot apply p0s000000004: PUBLIC TEMPORARY database authority "
            "must be revoked before the schema migration"
        )


def _create_immutability_trigger() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "CREATE FUNCTION saas_guard_runtime_provider_journal() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$ "
        "BEGIN "
        "IF TG_OP = 'DELETE' THEN "
        "RAISE EXCEPTION 'Runtime Provider journal rows are immutable'; "
        "END IF; "
        "IF ROW(NEW.id, NEW.provider_type, NEW.operation_kind, NEW.placement_id, "
        "NEW.binding_revision, NEW.binding_hash, NEW.target_hash, NEW.idempotency_hash, "
        "NEW.request_hash, NEW.created_at) IS DISTINCT FROM "
        "ROW(OLD.id, OLD.provider_type, OLD.operation_kind, OLD.placement_id, "
        "OLD.binding_revision, OLD.binding_hash, OLD.target_hash, OLD.idempotency_hash, "
        "OLD.request_hash, OLD.created_at) THEN "
        "RAISE EXCEPTION 'Runtime Provider journal fence is immutable'; "
        "END IF; "
        "IF OLD.response_hash IS NOT NULL THEN "
        "RAISE EXCEPTION 'Runtime Provider journal response is immutable'; "
        "END IF; "
        "IF NEW.receipt_hash IS NULL OR NEW.attributes_hash IS NULL "
        "OR NEW.response_hash IS NULL OR NEW.receipt_json IS NULL "
        "OR NEW.attributes_json IS NULL THEN "
        "RAISE EXCEPTION 'Runtime Provider journal response must be atomic'; "
        "END IF; "
        "NEW.verified_at := statement_timestamp(); "
        "RETURN NEW; "
        "END; $$"
    )
    op.execute("REVOKE ALL ON FUNCTION saas_guard_runtime_provider_journal() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER trg_runtime_provider_journal_immutable "
        "BEFORE UPDATE OR DELETE ON saas_runtime_provider_operation_journal "
        "FOR EACH ROW EXECUTE FUNCTION saas_guard_runtime_provider_journal()"
    )


def _fail_closed_legacy_runtime_targets() -> None:
    """Fence pre-binding snapshots without guessing a current Provider.

    Version-1 targets predate the immutable ``provider_binding`` snapshot.  A
    non-terminal Saga may already have caused an external effect immediately
    before losing its acknowledgement, so replaying it against today's binding
    is unsafe.  Active/completed and already-terminal Sagas never call a
    Provider and retain their historical target unchanged.
    """

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    # Follow the workflow's write order: lock the Saga before its append-only
    # audit chain.  Outbox is deliberately absent from this migration: old
    # wake rows, including their original schedule/lease facts, are immutable
    # delivery evidence and become harmless through the Saga status/version
    # CAS rather than physical mutation.
    op.execute(
        "LOCK TABLE public.saas_tenant_onboardings, "
        "public.saas_self_service_events IN ACCESS EXCLUSIVE MODE"
    )
    op.execute("ALTER TABLE public.saas_tenant_onboardings NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.saas_self_service_events NO FORCE ROW LEVEL SECURITY")
    status_list = ", ".join(f"'{status}'" for status in _PROVIDER_CALLING_ONBOARDING_STATUSES)
    affected = list(
        bind.execute(
            sa.text(
                "SELECT id, tenant_id, user_id, status "
                "FROM public.saas_tenant_onboardings "
                f"WHERE status IN ({status_list}) "
                "AND runtime_target_snapshot IS NOT NULL "
                "AND runtime_target_snapshot ->> 'schema_version' = '1' "
                "ORDER BY id FOR UPDATE"
            )
        ).mappings()
    )
    transitioned_at = _stored_time(
        bind.execute(sa.text("SELECT statement_timestamp()")).scalar_one()
    )
    affected_ids = [row["id"] for row in affected]
    if affected_ids:
        bind.execute(
            sa.text(
                "UPDATE public.saas_tenant_onboardings SET "
                "status = 'manual_review', "
                "failure_stage = CASE "
                "WHEN status = 'compensating' THEN failure_stage ELSE status END, "
                "compensation_cursor = CASE "
                "WHEN status = 'billing_ready' THEN 'runtime' "
                "WHEN status IN ('runtime_ready', 'project_ready') THEN 'project' "
                "ELSE compensation_cursor END, "
                "claim_token = NULL, claimed_at = NULL, lease_expires_at = NULL, "
                "last_error_code = :error_code, "
                "last_error_detail = 'legacy runtime target requires operator reconciliation', "
                "available_at = :transitioned_at, "
                "last_transition_at = :transitioned_at, "
                "updated_at = :transitioned_at, version = version + 1 "
                "WHERE id = ANY(:affected_ids)"
            ),
            {
                "affected_ids": affected_ids,
                "error_code": _LEGACY_TARGET_ERROR_CODE,
                "transitioned_at": transitioned_at,
            },
        )
    for row in affected:
        aggregate_id = UUID(str(row["id"]))
        previous = (
            bind.execute(
                sa.text(
                    "SELECT sequence, event_hash FROM public.saas_self_service_events "
                    "WHERE aggregate_type = 'tenant_onboarding' "
                    "AND aggregate_id = :aggregate_id "
                    "ORDER BY sequence DESC LIMIT 1"
                ),
                {"aggregate_id": aggregate_id},
            )
            .mappings()
            .one_or_none()
        )
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hash = _ZERO_HASH if previous is None else str(previous["event_hash"])
        facts: dict[str, object] = {
            "error_code": _LEGACY_TARGET_ERROR_CODE,
            "migration_revision": revision,
            "provider_binding_action": "not_rebound",
            "recovery_wake_action": "preserved_stale_cas",
            "runtime_target_schema_version": 1,
        }
        facts_hash = _digest(facts)
        event_hash = _digest(
            {
                "aggregate_type": "tenant_onboarding",
                "aggregate_id": str(aggregate_id),
                "sequence": sequence,
                "event_type": _LEGACY_TARGET_EVENT_TYPE,
                "from_status": str(row["status"]),
                "to_status": "manual_review",
                "facts_hash": facts_hash,
                "previous_hash": previous_hash,
                "occurred_at": transitioned_at.isoformat(),
            }
        )
        bind.execute(
            sa.text(
                "INSERT INTO public.saas_self_service_events ("
                "id, aggregate_type, aggregate_id, tenant_id, user_id, sequence, "
                "event_type, from_status, to_status, facts, facts_hash, previous_hash, "
                "event_hash, occurred_at) VALUES ("
                ":id, 'tenant_onboarding', :aggregate_id, :tenant_id, :user_id, "
                ":sequence, :event_type, :from_status, 'manual_review', "
                "CAST(:facts AS json), :facts_hash, :previous_hash, :event_hash, "
                ":occurred_at)"
            ),
            {
                "id": uuid4(),
                "aggregate_id": aggregate_id,
                "tenant_id": row["tenant_id"],
                "user_id": row["user_id"],
                "sequence": sequence,
                "event_type": _LEGACY_TARGET_EVENT_TYPE,
                "from_status": str(row["status"]),
                "facts": json.dumps(facts, sort_keys=True, separators=(",", ":")),
                "facts_hash": facts_hash,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "occurred_at": transitioned_at,
            },
        )
    remaining = bind.execute(
        sa.text(
            "SELECT count(*) FROM public.saas_tenant_onboardings "
            f"WHERE status IN ({status_list}) "
            "AND runtime_target_snapshot IS NOT NULL "
            "AND runtime_target_snapshot ->> 'schema_version' = '1'"
        )
    ).scalar_one()
    if remaining:
        raise RuntimeError(
            "cannot apply p0s000000004: an unsafe v1 Runtime target remains dispatchable"
        )
    op.execute("ALTER TABLE public.saas_tenant_onboardings FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.saas_self_service_events FORCE ROW LEVEL SECURITY")


def upgrade() -> None:
    # PostgreSQL operators must run postgresql_principals.psql before Alembic;
    # migrations deliberately have no CREATEROLE dependency.
    _preflight_postgresql_role()
    _fail_closed_legacy_runtime_targets()
    quoted_operations = ", ".join(f"'{value}'" for value in _OPERATIONS)
    op.create_table(
        "saas_runtime_provider_operation_journal",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_type", sa.String(128), nullable=False),
        sa.Column("operation_kind", sa.String(64), nullable=False),
        sa.Column("placement_id", sa.Uuid(), nullable=False),
        sa.Column("binding_revision", sa.String(128), nullable=False),
        sa.Column("binding_hash", sa.String(64), nullable=False),
        sa.Column("target_hash", sa.String(64), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("receipt_hash", sa.String(64), nullable=True),
        sa.Column("attributes_hash", sa.String(64), nullable=True),
        sa.Column("response_hash", sa.String(64), nullable=True),
        sa.Column("receipt_json", sa.Text(), nullable=True),
        sa.Column("attributes_json", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            f"operation_kind IN ({quoted_operations})",
            name="ck_runtime_provider_journal_operation",
        ),
        sa.CheckConstraint(
            "length(provider_type) > 0",
            name="ck_runtime_provider_journal_provider",
        ),
        sa.CheckConstraint(
            "length(binding_revision) > 0",
            name="ck_runtime_provider_journal_revision",
        ),
        sa.CheckConstraint(
            _hex64("binding_hash"),
            name="ck_runtime_provider_journal_binding_hash",
        ),
        sa.CheckConstraint(
            _hex64("target_hash"),
            name="ck_runtime_provider_journal_target_hash",
        ),
        sa.CheckConstraint(
            _hex64("idempotency_hash"),
            name="ck_runtime_provider_journal_idempotency_hash",
        ),
        sa.CheckConstraint(
            _hex64("request_hash"),
            name="ck_runtime_provider_journal_request_hash",
        ),
        sa.CheckConstraint(
            "(receipt_hash IS NULL AND attributes_hash IS NULL AND response_hash IS NULL "
            "AND receipt_json IS NULL AND attributes_json IS NULL AND verified_at IS NULL) OR "
            "(receipt_hash IS NOT NULL AND attributes_hash IS NOT NULL "
            "AND response_hash IS NOT NULL AND receipt_json IS NOT NULL "
            "AND attributes_json IS NOT NULL AND verified_at IS NOT NULL)",
            name="ck_runtime_provider_journal_response_atomic",
        ),
        sa.CheckConstraint(
            f"receipt_hash IS NULL OR ({_hex64('receipt_hash')})",
            name="ck_runtime_provider_journal_receipt_hash",
        ),
        sa.CheckConstraint(
            f"attributes_hash IS NULL OR ({_hex64('attributes_hash')})",
            name="ck_runtime_provider_journal_attributes_hash",
        ),
        sa.CheckConstraint(
            f"response_hash IS NULL OR ({_hex64('response_hash')})",
            name="ck_runtime_provider_journal_response_hash",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider_type",
            "operation_kind",
            "idempotency_hash",
            name="uq_runtime_provider_journal_identity",
        ),
        sa.UniqueConstraint(
            "request_hash",
            name="uq_runtime_provider_journal_request_hash",
        ),
    )
    op.create_index(
        "ix_runtime_provider_journal_pending",
        "saas_runtime_provider_operation_journal",
        ["created_at"],
        unique=False,
        postgresql_where=sa.text("response_hash IS NULL"),
        sqlite_where=sa.text("response_hash IS NULL"),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("REVOKE ALL PRIVILEGES ON saas_runtime_provider_operation_journal FROM PUBLIC")
        op.execute("ALTER TABLE saas_runtime_provider_operation_journal ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE saas_runtime_provider_operation_journal FORCE ROW LEVEL SECURITY")
        predicate = "pg_has_role(current_user, 'saas_runtime_provider_journal', 'member')"
        op.execute(
            "CREATE POLICY rls_runtime_provider_journal_select "
            "ON saas_runtime_provider_operation_journal FOR SELECT "
            f"TO {_JOURNAL_ROLE} USING ({predicate})"
        )
        op.execute(
            "CREATE POLICY rls_runtime_provider_journal_insert "
            "ON saas_runtime_provider_operation_journal FOR INSERT "
            f"TO {_JOURNAL_ROLE} WITH CHECK ({predicate})"
        )
        op.execute(
            "CREATE POLICY rls_runtime_provider_journal_update "
            "ON saas_runtime_provider_operation_journal FOR UPDATE "
            f"TO {_JOURNAL_ROLE} USING ({predicate}) WITH CHECK ({predicate})"
        )
        _create_immutability_trigger()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Keep the evidence preflight and FORCE relaxation in this Alembic
        # transaction.  A rejected downgrade rolls both DDLs back.
        op.execute("LOCK TABLE saas_tenant_onboardings IN ACCESS EXCLUSIVE MODE")
        op.execute("LOCK TABLE saas_runtime_provider_operation_journal IN ACCESS EXCLUSIVE MODE")
        op.execute("ALTER TABLE saas_tenant_onboardings NO FORCE ROW LEVEL SECURITY")
        op.execute(
            "ALTER TABLE saas_runtime_provider_operation_journal NO FORCE ROW LEVEL SECURITY"
        )
    legacy_transition = bind.execute(
        sa.text(
            "SELECT 1 FROM saas_tenant_onboardings WHERE last_error_code = :error_code LIMIT 1"
        ),
        {"error_code": _LEGACY_TARGET_ERROR_CODE},
    ).first()
    if legacy_transition is not None:
        raise RuntimeError(
            "cannot downgrade p0s000000004 with fail-closed legacy Runtime target evidence"
        )
    evidence = bind.execute(
        sa.text("SELECT 1 FROM saas_runtime_provider_operation_journal LIMIT 1")
    ).first()
    if evidence is not None:
        raise RuntimeError(
            "cannot downgrade p0s000000004 with durable Runtime Provider operation evidence"
        )
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE saas_tenant_onboardings FORCE ROW LEVEL SECURITY")
        op.execute(
            "DROP TRIGGER IF EXISTS trg_runtime_provider_journal_immutable "
            "ON saas_runtime_provider_operation_journal"
        )
        op.execute("DROP FUNCTION IF EXISTS saas_guard_runtime_provider_journal()")
        op.execute(
            "DROP POLICY IF EXISTS rls_runtime_provider_journal_update "
            "ON saas_runtime_provider_operation_journal"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_runtime_provider_journal_insert "
            "ON saas_runtime_provider_operation_journal"
        )
        op.execute(
            "DROP POLICY IF EXISTS rls_runtime_provider_journal_select "
            "ON saas_runtime_provider_operation_journal"
        )
        op.execute(
            "ALTER TABLE saas_runtime_provider_operation_journal DISABLE ROW LEVEL SECURITY"
        )
    op.drop_index(
        "ix_runtime_provider_journal_pending",
        table_name="saas_runtime_provider_operation_journal",
    )
    op.drop_table("saas_runtime_provider_operation_journal")
