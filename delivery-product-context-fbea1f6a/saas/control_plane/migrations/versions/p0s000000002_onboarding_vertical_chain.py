"""Extend self-service onboarding through the first normally admitted Run.

Revision ID: p0s000000002
Revises: p0s000000001
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "p0s000000002"
down_revision: str | None = "p0s000000001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ONBOARDING_ROLE = "pg_has_role(current_user, 'saas_onboarding', 'member')"
_REGISTRATION_ID = "NULLIF(current_setting('app.registration_id', true), '')::uuid"
_ONBOARDING_ID = "NULLIF(current_setting('app.onboarding_id', true), '')::uuid"
_ACTOR_ID = "NULLIF(current_setting('app.actor_id', true), '')::uuid"
_TENANT_ID = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

_PREALLOCATED_COLUMNS = (
    "default_project_id",
    "pricing_snapshot_id",
    "entitlement_id",
    "runtime_binding_id",
)
_ONBOARDING_REQUEST_EVENTS = (
    "onboarding.billing.requested",
    "onboarding.runtime.requested",
    "onboarding.project.requested",
    "onboarding.activation.requested",
    "onboarding.compensation.requested",
)
_NEXT_EVENT_BY_STATUS = {
    "tenant_created": "onboarding.billing.requested",
    "billing_ready": "onboarding.runtime.requested",
    "runtime_ready": "onboarding.project.requested",
    "project_ready": "onboarding.activation.requested",
    "compensating": "onboarding.compensation.requested",
}
_FAILURE_STAGES = (
    "tenant_created",
    "billing_ready",
    "runtime_ready",
    "project_ready",
    "active",
    "legacy_billing_ready",
    "legacy_runtime_ready",
    "legacy_active",
)
_COMPENSATION_CURSORS = ("billing", "runtime", "project")


def _canonical_snapshot(
    plan_key: str, policy_revision: str, trial_days: int
) -> tuple[dict[str, object], str]:
    snapshot: dict[str, object] = {
        "schema_version": 1,
        "key": plan_key,
        "policy_revision": policy_revision,
        "trial_days": trial_days,
        "currency": "USD",
        "trial_run_limit": 100,
        "trial_concurrency_limit": 2,
        "runtime_type": "omnigent",
        "capacity_class": "starter",
        "default_project_name": "Getting Started",
        "default_project_visibility": "private",
        "quota_resource": "interactive_runs",
        "quota_limit": 100,
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return snapshot, sha256(canonical.encode("utf-8")).hexdigest()


def _add_columns() -> None:
    with op.batch_alter_table("saas_self_service_registrations") as batch:
        for column in _PREALLOCATED_COLUMNS:
            batch.add_column(sa.Column(column, sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("plan_snapshot", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("plan_snapshot_hash", sa.String(64), nullable=True))

    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        for column in _PREALLOCATED_COLUMNS:
            batch.add_column(sa.Column(column, sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("plan_snapshot", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("plan_snapshot_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("project_ready_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("first_run_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("failure_stage", sa.String(64), nullable=True))
        batch.add_column(sa.Column("compensation_cursor", sa.String(64), nullable=True))
        batch.add_column(sa.Column("runtime_placement_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("runtime_target_snapshot", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("runtime_request_hash", sa.String(64), nullable=True))


def _relax_legacy_state_for_upgrade() -> None:
    """Allow legacy success states to fail closed before the new checks."""

    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.drop_constraint("ck_tenant_onboarding_state_evidence", type_="check")


def _backfill_existing_authority() -> None:
    registration = sa.table(
        "saas_self_service_registrations",
        sa.column("id", sa.Uuid()),
        sa.column("plan_key", sa.String()),
        sa.column("plan_policy_revision", sa.String()),
        *(sa.column(column, sa.Uuid()) for column in _PREALLOCATED_COLUMNS),
        sa.column("plan_snapshot", sa.JSON()),
        sa.column("plan_snapshot_hash", sa.String()),
    )
    onboarding = sa.table(
        "saas_tenant_onboardings",
        sa.column("registration_id", sa.Uuid()),
        sa.column("status", sa.String()),
        sa.column("trial_days", sa.Integer()),
        sa.column("trial_started_at", sa.DateTime(timezone=True)),
        sa.column("trial_ends_at", sa.DateTime(timezone=True)),
        sa.column("billing_ready_at", sa.DateTime(timezone=True)),
        sa.column("runtime_ready_at", sa.DateTime(timezone=True)),
        sa.column("activated_at", sa.DateTime(timezone=True)),
        sa.column("last_transition_at", sa.DateTime(timezone=True)),
        *(sa.column(column, sa.Uuid()) for column in _PREALLOCATED_COLUMNS),
        sa.column("plan_snapshot", sa.JSON()),
        sa.column("plan_snapshot_hash", sa.String()),
        sa.column("project_ready_at", sa.DateTime(timezone=True)),
        sa.column("failure_stage", sa.String()),
        sa.column("compensation_cursor", sa.String()),
    )
    bind = op.get_bind()
    trial_days_by_registration = {
        str(row["registration_id_text"]): int(row["trial_days"])
        for row in bind.execute(
            sa.select(
                sa.cast(onboarding.c.registration_id, sa.String()).label("registration_id_text"),
                onboarding.c.trial_days,
            )
        ).mappings()
    }
    rows = bind.execute(
        sa.select(
            sa.cast(registration.c.id, sa.String()).label("registration_id_text"),
            registration.c.plan_key,
            registration.c.plan_policy_revision,
        ).order_by(sa.cast(registration.c.id, sa.String()))
    ).mappings()
    for row in rows:
        registration_id_text = str(row["registration_id_text"])
        snapshot, snapshot_hash = _canonical_snapshot(
            str(row["plan_key"]),
            str(row["plan_policy_revision"]),
            trial_days_by_registration.get(registration_id_text, 14),
        )
        values: dict[str, object] = {column: uuid4() for column in _PREALLOCATED_COLUMNS}
        values.update(
            {
                "plan_snapshot": snapshot,
                "plan_snapshot_hash": snapshot_hash,
            }
        )
        bind.execute(
            registration.update()
            .where(sa.cast(registration.c.id, sa.String()) == registration_id_text)
            .values(**values)
        )
        bind.execute(
            onboarding.update()
            .where(sa.cast(onboarding.c.registration_id, sa.String()) == registration_id_text)
            .values(**values)
        )

    bind.execute(
        onboarding.update()
        .where(onboarding.c.status == "active")
        .values(
            project_ready_at=sa.func.coalesce(
                onboarding.c.project_ready_at,
                onboarding.c.activated_at,
                onboarding.c.runtime_ready_at,
                onboarding.c.last_transition_at,
            )
        )
    )
    bind.execute(
        onboarding.update()
        .where(onboarding.c.status == "compensating")
        .values(
            failure_stage=sa.case(
                (onboarding.c.runtime_ready_at.is_not(None), "runtime_ready"),
                (onboarding.c.billing_ready_at.is_not(None), "billing_ready"),
                else_="tenant_created",
            ),
            compensation_cursor=sa.case(
                (onboarding.c.runtime_ready_at.is_not(None), "runtime"),
                else_="billing",
            ),
        )
    )
    bind.execute(
        onboarding.update()
        .where(onboarding.c.status == "manual_review")
        .values(
            failure_stage=sa.case(
                (onboarding.c.runtime_ready_at.is_not(None), "runtime_ready"),
                (onboarding.c.billing_ready_at.is_not(None), "billing_ready"),
                else_="tenant_created",
            ),
            compensation_cursor=sa.case(
                (onboarding.c.runtime_ready_at.is_not(None), "runtime"),
                else_="billing",
            ),
        )
    )
    bind.execute(
        onboarding.update()
        .where(onboarding.c.status == "compensated")
        .values(
            failure_stage=sa.case(
                (onboarding.c.runtime_ready_at.is_not(None), "runtime_ready"),
                (onboarding.c.billing_ready_at.is_not(None), "billing_ready"),
                else_="tenant_created",
            ),
            compensation_cursor=None,
        )
    )
    legacy_cursors = {
        "billing_ready": "billing",
        "runtime_ready": "runtime",
        "active": "project",
    }
    for legacy_status in ("billing_ready", "runtime_ready", "active"):
        values: dict[str, object] = {
            "status": "manual_review",
            "failure_stage": f"legacy_{legacy_status}",
            "compensation_cursor": legacy_cursors[legacy_status],
        }
        bind.execute(
            onboarding.update().where(onboarding.c.status == legacy_status).values(**values)
        )


def _backfill_pending_outbox_payloads() -> None:
    """Make unpublished p0s1 billing intents sufficient to resume under exact RLS."""

    onboarding = sa.table(
        "saas_tenant_onboardings",
        sa.column("id", sa.Uuid()),
        sa.column("registration_id", sa.Uuid()),
        sa.column("user_id", sa.Uuid()),
        sa.column("tenant_id", sa.Uuid()),
        sa.column("space_id", sa.Uuid()),
        sa.column("default_project_id", sa.Uuid()),
        sa.column("version", sa.Integer()),
    )
    outbox = sa.table(
        "saas_control_plane_outbox",
        sa.column("id", sa.Uuid()),
        sa.column("aggregate_type", sa.String()),
        sa.column("aggregate_key", sa.String()),
        sa.column("event_type", sa.String()),
        sa.column("payload", sa.JSON()),
        sa.column("request_hash", sa.String()),
        sa.column("published_at", sa.DateTime(timezone=True)),
    )
    bind = op.get_bind()
    sagas = {
        str(row.id): row
        for row in bind.execute(
            sa.select(
                onboarding.c.id,
                onboarding.c.registration_id,
                onboarding.c.user_id,
                onboarding.c.tenant_id,
                onboarding.c.space_id,
                onboarding.c.default_project_id,
                onboarding.c.version,
            )
        )
    }
    events = bind.execute(
        sa.select(
            sa.cast(outbox.c.id, sa.String()).label("outbox_id_text"),
            outbox.c.aggregate_key,
            outbox.c.payload,
        ).where(
            outbox.c.aggregate_type == "tenant_onboarding",
            outbox.c.event_type == "onboarding.billing.requested",
            outbox.c.published_at.is_(None),
        )
    ).mappings()
    for event in events:
        saga = sagas.get(str(event["aggregate_key"]))
        if saga is None or not isinstance(event["payload"], Mapping):
            continue
        payload = dict(event["payload"])
        payload.update(
            {
                "onboarding_id": str(saga.id),
                "registration_id": str(saga.registration_id),
                "tenant_id": str(saga.tenant_id),
                "user_id": str(saga.user_id),
                "space_id": str(saga.space_id),
                "default_project_id": str(saga.default_project_id),
                "expected_status": "tenant_created",
                "version": int(saga.version),
            }
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        bind.execute(
            outbox.update()
            .where(sa.cast(outbox.c.id, sa.String()) == str(event["outbox_id_text"]))
            .values(
                payload=payload,
                request_hash=sha256(canonical.encode("utf-8")).hexdigest(),
            )
        )


def _ensure_recovery_wakes() -> None:
    """Leave every safely resumable Saga with one current unpublished wake.

    A p0s1 Billing intent may already have been acknowledged by a message-bus
    publisher without advancing the local Saga. Updating only unpublished old
    intents would therefore strand that Tenant forever. Reuse an unpublished
    current-stage event when one exists; otherwise append a deterministic
    migration wake. Legacy states whose evidence is insufficient for the new
    state machine have already been moved to ``manual_review`` above.
    """

    onboarding = sa.table(
        "saas_tenant_onboardings",
        sa.column("id", sa.Uuid()),
        sa.column("registration_id", sa.Uuid()),
        sa.column("user_id", sa.Uuid()),
        sa.column("tenant_id", sa.Uuid()),
        sa.column("space_id", sa.Uuid()),
        sa.column("default_project_id", sa.Uuid()),
        sa.column("status", sa.String()),
        sa.column("version", sa.Integer()),
        sa.column("available_at", sa.DateTime(timezone=True)),
    )
    outbox = sa.table(
        "saas_control_plane_outbox",
        sa.column("id", sa.Uuid()),
        sa.column("tenant_id", sa.Uuid()),
        sa.column("aggregate_type", sa.String()),
        sa.column("aggregate_key", sa.String()),
        sa.column("event_type", sa.String()),
        sa.column("payload", sa.JSON()),
        sa.column("idempotency_key", sa.String()),
        sa.column("request_hash", sa.String()),
        sa.column("attempt_count", sa.Integer()),
        sa.column("available_at", sa.DateTime(timezone=True)),
        sa.column("claimed_at", sa.DateTime(timezone=True)),
        sa.column("claim_token", sa.Uuid()),
        sa.column("last_error", sa.String()),
        sa.column("published_at", sa.DateTime(timezone=True)),
    )
    bind = op.get_bind()
    sagas = bind.execute(
        sa.select(
            onboarding.c.id,
            onboarding.c.registration_id,
            onboarding.c.user_id,
            onboarding.c.tenant_id,
            onboarding.c.space_id,
            onboarding.c.default_project_id,
            onboarding.c.status,
            onboarding.c.version,
            onboarding.c.available_at,
        )
        .where(onboarding.c.status.in_(tuple(_NEXT_EVENT_BY_STATUS)))
        .order_by(sa.cast(onboarding.c.id, sa.String()))
    ).mappings()
    for saga in sagas:
        status = str(saga["status"])
        event_type = _NEXT_EVENT_BY_STATUS[status]
        aggregate_key = str(saga["id"])
        payload: dict[str, object] = {
            "onboarding_id": aggregate_key,
            "registration_id": str(saga["registration_id"]),
            "user_id": str(saga["user_id"]),
            "tenant_id": str(saga["tenant_id"]),
            "space_id": str(saga["space_id"]),
            "default_project_id": str(saga["default_project_id"]),
            "expected_status": status,
            "version": int(saga["version"]),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        request_hash = sha256(canonical.encode("utf-8")).hexdigest()
        migration_key = sha256(
            (f"p0s000000002:{aggregate_key}:{event_type}:{int(saga['version'])}").encode()
        ).hexdigest()
        unpublished_id_texts = list(
            bind.scalars(
                sa.select(sa.cast(outbox.c.id, sa.String()))
                .where(
                    outbox.c.aggregate_type == "tenant_onboarding",
                    outbox.c.aggregate_key == aggregate_key,
                    outbox.c.event_type == event_type,
                    outbox.c.published_at.is_(None),
                )
                .order_by(sa.cast(outbox.c.id, sa.String()))
            )
        )
        migration_event = (
            bind.execute(
                sa.select(
                    sa.cast(outbox.c.id, sa.String()).label("id_text"),
                    outbox.c.tenant_id,
                    outbox.c.aggregate_type,
                    outbox.c.aggregate_key,
                    outbox.c.event_type,
                )
                .where(outbox.c.idempotency_key == migration_key)
                .limit(1)
            )
            .mappings()
            .one_or_none()
        )
        if migration_event is not None and (
            str(migration_event["tenant_id"]) != str(saga["tenant_id"])
            or migration_event["aggregate_type"] != "tenant_onboarding"
            or migration_event["aggregate_key"] != aggregate_key
            or migration_event["event_type"] != event_type
        ):
            raise RuntimeError(
                "p0s000000002 recovery-wake idempotency key is bound to a different scope"
            )
        migration_candidate = (
            str(migration_event["id_text"]) if migration_event is not None else None
        )
        candidate_id_text = migration_candidate or (
            str(unpublished_id_texts[0]) if unpublished_id_texts else None
        )
        duplicate_id_texts = [
            str(event_id)
            for event_id in unpublished_id_texts
            if str(event_id) != candidate_id_text
        ]
        if duplicate_id_texts:
            # Unpublished rows have no durable dispatch receipt. Retaining more
            # than one current-stage intent would create concurrent effective
            # wakes after the upgrade, so collapse them into the canonical row.
            bind.execute(
                outbox.delete().where(
                    sa.cast(outbox.c.id, sa.String()).in_(tuple(duplicate_id_texts))
                )
            )
        values: dict[str, object] = {
            "tenant_id": saga["tenant_id"],
            "aggregate_type": "tenant_onboarding",
            "aggregate_key": aggregate_key,
            "event_type": event_type,
            "payload": payload,
            "idempotency_key": migration_key,
            "request_hash": request_hash,
            "attempt_count": 0,
            "available_at": saga["available_at"],
            "claimed_at": None,
            "claim_token": None,
            "last_error": None,
            "published_at": None,
        }
        if candidate_id_text is not None:
            bind.execute(
                outbox.update()
                .where(sa.cast(outbox.c.id, sa.String()) == candidate_id_text)
                .values(**values)
            )
            continue
        bind.execute(
            outbox.insert().values(
                id=uuid4(),
                **values,
            )
        )


def _finalize_constraints() -> None:
    failure_stages = ", ".join(f"'{value}'" for value in _FAILURE_STAGES)
    compensation_cursors = ", ".join(f"'{value}'" for value in _COMPENSATION_CURSORS)
    with op.batch_alter_table("saas_self_service_registrations") as batch:
        for column in _PREALLOCATED_COLUMNS:
            batch.alter_column(column, existing_type=sa.Uuid(), nullable=False)
        batch.alter_column("plan_snapshot", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("plan_snapshot_hash", existing_type=sa.String(64), nullable=False)
        batch.create_check_constraint(
            "ck_self_service_plan_snapshot_nonempty",
            "length(CAST(plan_snapshot AS TEXT)) > 2",
        )
        batch.create_check_constraint(
            "ck_self_service_plan_snapshot_hash", "length(plan_snapshot_hash) = 64"
        )
        batch.create_unique_constraint(
            "uq_self_service_registration_project", ["default_project_id"]
        )
        batch.create_unique_constraint(
            "uq_self_service_registration_pricing_snapshot", ["pricing_snapshot_id"]
        )
        batch.create_unique_constraint(
            "uq_self_service_registration_entitlement", ["entitlement_id"]
        )
        batch.create_unique_constraint(
            "uq_self_service_registration_runtime_binding", ["runtime_binding_id"]
        )

    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.drop_constraint("ck_tenant_onboarding_status", type_="check")
        for column in _PREALLOCATED_COLUMNS:
            batch.alter_column(column, existing_type=sa.Uuid(), nullable=False)
        batch.alter_column("plan_snapshot", existing_type=sa.JSON(), nullable=False)
        batch.alter_column("plan_snapshot_hash", existing_type=sa.String(64), nullable=False)
        batch.create_check_constraint(
            "ck_tenant_onboarding_plan_snapshot_nonempty",
            "length(CAST(plan_snapshot AS TEXT)) > 2",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_plan_snapshot_hash", "length(plan_snapshot_hash) = 64"
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_failure_stage",
            f"failure_stage IS NULL OR failure_stage IN ({failure_stages})",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_compensation_cursor",
            f"compensation_cursor IS NULL OR compensation_cursor IN ({compensation_cursors})",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_runtime_request",
            "(runtime_placement_id IS NULL AND runtime_target_snapshot IS NULL "
            "AND runtime_request_hash IS NULL) OR "
            "(runtime_placement_id IS NOT NULL "
            "AND runtime_target_snapshot IS NOT NULL "
            "AND runtime_request_hash IS NOT NULL "
            "AND length(CAST(runtime_target_snapshot AS TEXT)) > 2 "
            "AND length(runtime_request_hash) = 64)",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_initial_placement",
            "status <> 'tenant_created' OR runtime_placement_id IS NULL",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_ready_placement",
            "status NOT IN ('runtime_ready', 'project_ready', 'active', 'completed') "
            "OR runtime_placement_id IS NOT NULL",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_status",
            "status IN ('tenant_created', 'billing_ready', 'runtime_ready', "
            "'project_ready', 'active', 'completed', 'compensating', "
            "'compensated', 'manual_review')",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_state_evidence",
            "(status = 'tenant_created' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NULL "
            "AND runtime_ready_at IS NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'billing_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'runtime_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'project_ready' AND trial_started_at IS NULL "
            "AND trial_ends_at IS NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'active' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NOT NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL "
            "AND compensated_at IS NULL) OR "
            "(status = 'completed' AND trial_started_at IS NOT NULL "
            "AND trial_ends_at IS NOT NULL AND billing_ready_at IS NOT NULL "
            "AND runtime_ready_at IS NOT NULL AND project_ready_at IS NOT NULL "
            "AND activated_at IS NOT NULL AND first_run_id IS NOT NULL "
            "AND completed_at IS NOT NULL AND completed_at >= activated_at "
            "AND compensated_at IS NULL) OR "
            "(status = 'compensating' AND activated_at IS NULL "
            "AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'manual_review' AND first_run_id IS NULL "
            "AND completed_at IS NULL AND compensated_at IS NULL) OR "
            "(status = 'compensated' AND activated_at IS NULL "
            "AND first_run_id IS NULL AND completed_at IS NULL "
            "AND compensated_at IS NOT NULL)",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_failure_evidence",
            "(status IN ('tenant_created', 'billing_ready', 'runtime_ready', "
            "'project_ready', 'active', 'completed') "
            "AND failure_stage IS NULL AND compensation_cursor IS NULL) OR "
            "(status = 'compensating' AND failure_stage IS NOT NULL "
            "AND compensation_cursor IS NOT NULL) OR "
            "(status = 'manual_review' AND failure_stage IS NOT NULL "
            "AND compensation_cursor IS NOT NULL) OR "
            "(status = 'compensated' AND failure_stage IS NOT NULL "
            "AND compensation_cursor IS NULL)",
        )
        batch.create_unique_constraint(
            "uq_tenant_onboarding_default_project", ["default_project_id"]
        )
        batch.create_unique_constraint(
            "uq_tenant_onboarding_pricing_snapshot", ["pricing_snapshot_id"]
        )
        batch.create_unique_constraint("uq_tenant_onboarding_entitlement", ["entitlement_id"])
        batch.create_unique_constraint(
            "uq_tenant_onboarding_runtime_binding", ["runtime_binding_id"]
        )
        batch.create_unique_constraint("uq_tenant_onboarding_first_run", ["first_run_id"])
        batch.create_foreign_key(
            "fk_tenant_onboarding_runtime_placement",
            "saas_runtime_placements",
            ["runtime_placement_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_tenant_onboarding_first_run_scope",
            "saas_runs",
            ["first_run_id", "tenant_id", "space_id", "default_project_id"],
            ["id", "tenant_id", "space_id", "project_id"],
            ondelete="RESTRICT",
        )


def _registration_match() -> str:
    return (
        "SELECT 1 FROM saas_self_service_registrations registration_scope "
        f"WHERE registration_scope.id = {_REGISTRATION_ID} "
        f"AND registration_scope.onboarding_id = {_ONBOARDING_ID} "
        f"AND registration_scope.user_id = {_ACTOR_ID} "
        f"AND registration_scope.tenant_id = {_TENANT_ID} "
        "AND registration_scope.status = 'verified' "
        f"AND {_REGISTRATION_ID} IS NOT NULL AND {_ONBOARDING_ID} IS NOT NULL "
        f"AND {_ACTOR_ID} IS NOT NULL AND {_TENANT_ID} IS NOT NULL"
    )


def _saga_match(extra: str) -> str:
    return (
        f"({_ONBOARDING_ROLE} AND EXISTS (SELECT 1 "
        "FROM saas_tenant_onboardings onboarding_scope "
        "WHERE onboarding_scope.id = "
        f"{_ONBOARDING_ID} AND onboarding_scope.registration_id = {_REGISTRATION_ID} "
        f"AND onboarding_scope.user_id = {_ACTOR_ID} "
        f"AND onboarding_scope.tenant_id = {_TENANT_ID} AND {extra}))"
    )


def _install_exact_policy(*, table: str, predicate: str, operations: str = "ALL") -> None:
    base = f"rls_{table.removeprefix('saas_')}_onboarding_vertical"
    op.execute(
        f"CREATE POLICY {base} ON {table} FOR {operations} TO saas_onboarding "
        f"USING ({predicate}) WITH CHECK ({predicate})"
        if operations != "SELECT"
        else f"CREATE POLICY {base} ON {table} FOR SELECT TO saas_onboarding USING ({predicate})"
    )
    op.execute(
        f"CREATE POLICY {base}_restrictive ON {table} AS RESTRICTIVE "
        f"FOR {operations} TO saas_onboarding USING ({predicate}) WITH CHECK ({predicate})"
        if operations != "SELECT"
        else f"CREATE POLICY {base}_restrictive ON {table} AS RESTRICTIVE "
        f"FOR SELECT TO saas_onboarding USING ({predicate})"
    )


def _drop_exact_policy(*, table: str) -> None:
    base = f"rls_{table.removeprefix('saas_')}_onboarding_vertical"
    op.execute(f"DROP POLICY IF EXISTS {base}_restrictive ON {table}")
    op.execute(f"DROP POLICY IF EXISTS {base} ON {table}")


def _replace_saga_policies(*, vertical: bool) -> None:
    for policy in (
        "rls_tenant_onboardings_select",
        "rls_tenant_onboardings_insert",
        "rls_tenant_onboardings_update",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON saas_tenant_onboardings")

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
    )
    if vertical:
        onboarding_exact += (
            "AND registration_scope.default_project_id = "
            "saas_tenant_onboardings.default_project_id "
            "AND registration_scope.pricing_snapshot_id = "
            "saas_tenant_onboardings.pricing_snapshot_id "
            "AND registration_scope.entitlement_id = saas_tenant_onboardings.entitlement_id "
            "AND registration_scope.runtime_binding_id = "
            "saas_tenant_onboardings.runtime_binding_id "
            "AND registration_scope.plan_snapshot_hash = "
            "saas_tenant_onboardings.plan_snapshot_hash "
        )
    onboarding_exact += (
        "AND registration_scope.plan_key = saas_tenant_onboardings.plan_key "
        "AND registration_scope.plan_policy_revision = "
        "saas_tenant_onboardings.plan_policy_revision "
        "AND registration_scope.home_region = saas_tenant_onboardings.home_region))"
    )
    onboarding_insert = (
        f"({onboarding_exact} AND status = 'tenant_created' "
        "AND trial_started_at IS NULL AND trial_ends_at IS NULL "
        "AND billing_ready_at IS NULL AND runtime_ready_at IS NULL "
    )
    if vertical:
        onboarding_insert += (
            "AND project_ready_at IS NULL AND first_run_id IS NULL "
            "AND completed_at IS NULL AND failure_stage IS NULL "
            "AND compensation_cursor IS NULL AND runtime_placement_id IS NULL "
            "AND runtime_target_snapshot IS NULL AND runtime_request_hash IS NULL "
        )
    onboarding_insert += "AND activated_at IS NULL AND compensated_at IS NULL)"

    op.execute(
        "CREATE POLICY rls_tenant_onboardings_select ON saas_tenant_onboardings "
        f"FOR SELECT TO saas_onboarding USING ({onboarding_exact})"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_insert ON saas_tenant_onboardings "
        f"FOR INSERT TO saas_onboarding WITH CHECK ({onboarding_insert})"
    )
    op.execute(
        "CREATE POLICY rls_tenant_onboardings_update ON saas_tenant_onboardings "
        f"FOR UPDATE TO saas_onboarding USING ({onboarding_exact}) "
        f"WITH CHECK ({onboarding_exact})"
    )


def _replace_outbox_policies(*, vertical: bool) -> None:
    for policy in (
        "rls_outbox_onboarding_insert",
        "rls_outbox_onboarding_select",
        "rls_outbox_onboarding_restrictive",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON saas_control_plane_outbox")
    event_predicate = (
        "event_type IN (" + ", ".join(f"'{event}'" for event in _ONBOARDING_REQUEST_EVENTS) + ")"
        if vertical
        else "event_type = 'onboarding.billing.requested'"
    )
    onboarding_outbox = (
        f"({_ONBOARDING_ROLE} AND tenant_id = {_TENANT_ID} "
        "AND aggregate_type = 'tenant_onboarding' "
        f"AND aggregate_key = ({_ONBOARDING_ID})::text AND {event_predicate} "
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


def _install_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # These legacy metering policies were created TO PUBLIC even though their
    # predicates admit only saas_metering.  PostgreSQL still privilege-checks
    # their capability-token subqueries for other roles, which would force the
    # onboarding worker to read machine credentials.  Narrowing the policy
    # target is authorization-equivalent for metering and preserves least
    # privilege for the new worker.
    for table, policy, roles in (
        (
            "saas_billing_subscriptions",
            "rls_billing_subscriptions_metering_exact",
            "saas_metering",
        ),
        (
            "saas_billing_subscriptions",
            "rls_billing_subscriptions_metering_lock",
            "saas_metering",
        ),
        ("saas_pricing_snapshots", "rls_pricing_snapshots_metering_exact", "saas_metering"),
        (
            "saas_runtime_placements",
            "rls_runtime_placements_scope",
            "saas_platform, saas_app",
        ),
        (
            "saas_runtime_partitions",
            "rls_runtime_partitions_privacy_verifier_read",
            "saas_privacy_verifier",
        ),
        (
            "saas_project_memberships",
            "rls_saas_project_memberships_privacy_target",
            "saas_platform, saas_platform_governance",
        ),
    ):
        op.execute(f"ALTER POLICY {policy} ON {table} TO {roles}")
    _replace_saga_policies(vertical=True)
    _replace_outbox_policies(vertical=True)

    tenant_registration = (
        f"EXISTS ({_registration_match()} AND registration_scope.tenant_id = saas_tenants.id)"
    )
    activation_saga = _saga_match("onboarding_scope.status = 'project_ready'")
    compensation_saga = _saga_match("onboarding_scope.status = 'compensating'")
    op.execute(
        "CREATE POLICY rls_tenants_onboarding_activation ON saas_tenants "
        "AS RESTRICTIVE FOR UPDATE TO saas_onboarding "
        f"USING ({_ONBOARDING_ROLE} AND {tenant_registration} "
        "AND status = 'provisioning' AND lifecycle_version = 1 "
        f"AND ({activation_saga} OR {compensation_saga})) "
        f"WITH CHECK ({_ONBOARDING_ROLE} AND {tenant_registration} AND (("
        f"{activation_saga} AND status = 'trial' AND lifecycle_version = 2) OR ("
        f"{compensation_saga} AND status = 'suspended' AND lifecycle_version = 2)))"
    )
    space_registration = (
        f"EXISTS ({_registration_match()} "
        "AND registration_scope.tenant_id = saas_spaces.tenant_id "
        "AND registration_scope.space_id = saas_spaces.id)"
    )
    op.execute(
        "CREATE POLICY rls_spaces_onboarding_activation ON saas_spaces "
        "AS RESTRICTIVE FOR UPDATE TO saas_onboarding "
        f"USING ({_ONBOARDING_ROLE} AND {space_registration} "
        "AND status = 'suspended' "
        f"AND ({activation_saga} OR {compensation_saga})) "
        f"WITH CHECK ({_ONBOARDING_ROLE} AND {space_registration} AND (("
        f"{activation_saga} AND status = 'active') OR ("
        f"{compensation_saga} AND status = 'suspended')))"
    )

    policies: tuple[tuple[str, str, str], ...] = (
        (
            "saas_billing_subscriptions",
            _saga_match(
                "saas_billing_subscriptions.id = onboarding_scope.subscription_id "
                "AND saas_billing_subscriptions.tenant_id = onboarding_scope.tenant_id "
                "AND saas_billing_subscriptions.plan_key = onboarding_scope.plan_key "
                "AND saas_billing_subscriptions.updated_by = onboarding_scope.user_id"
            ),
            "ALL",
        ),
        (
            "saas_pricing_snapshots",
            _saga_match(
                "saas_pricing_snapshots.id = onboarding_scope.pricing_snapshot_id "
                "AND saas_pricing_snapshots.tenant_id = onboarding_scope.tenant_id "
                "AND saas_pricing_snapshots.plan_key = onboarding_scope.plan_key "
                "AND saas_pricing_snapshots.currency = "
                "upper(onboarding_scope.plan_snapshot ->> 'currency') "
                "AND saas_pricing_snapshots.created_by = onboarding_scope.user_id"
            ),
            "ALL",
        ),
        (
            "saas_billing_entitlements",
            _saga_match(
                "saas_billing_entitlements.id = onboarding_scope.entitlement_id "
                "AND saas_billing_entitlements.tenant_id = onboarding_scope.tenant_id "
                "AND saas_billing_entitlements.subscription_id = onboarding_scope.subscription_id "
                "AND saas_billing_entitlements.scope_type = 'tenant' "
                "AND saas_billing_entitlements.scope_key = onboarding_scope.tenant_id::text "
                "AND saas_billing_entitlements.updated_by = onboarding_scope.user_id"
            ),
            "ALL",
        ),
        (
            "saas_billing_balances",
            _saga_match(
                "saas_billing_balances.tenant_id = onboarding_scope.tenant_id "
                "AND saas_billing_balances.currency = "
                "upper(onboarding_scope.plan_snapshot ->> 'currency')"
            ),
            "ALL",
        ),
        (
            "saas_runtime_placements",
            _saga_match(
                "((onboarding_scope.runtime_placement_id IS NULL "
                "AND saas_runtime_placements.runtime_type = "
                "onboarding_scope.plan_snapshot ->> 'runtime_type' "
                "AND saas_runtime_placements.data_region = onboarding_scope.home_region "
                "AND saas_runtime_placements.capacity_class = "
                "onboarding_scope.plan_snapshot ->> 'capacity_class' "
                "AND saas_runtime_placements.status = 'active') OR ("
                "onboarding_scope.runtime_placement_id = saas_runtime_placements.id "
                "AND onboarding_scope.runtime_target_snapshot ->> 'placement_id' = "
                "saas_runtime_placements.id::text "
                "AND onboarding_scope.runtime_target_snapshot ->> 'runtime_type' = "
                "saas_runtime_placements.runtime_type "
                "AND onboarding_scope.runtime_target_snapshot ->> 'data_region' = "
                "saas_runtime_placements.data_region "
                "AND onboarding_scope.runtime_target_snapshot ->> 'failure_domain' = "
                "saas_runtime_placements.failure_domain "
                "AND onboarding_scope.runtime_target_snapshot ->> "
                "'official_schema_revision' = "
                "saas_runtime_placements.official_schema_revision "
                "AND onboarding_scope.runtime_target_snapshot ->> 'capacity_class' = "
                "saas_runtime_placements.capacity_class "
                "AND length(onboarding_scope.runtime_request_hash) = 64))"
            ),
            "SELECT",
        ),
        (
            "saas_runtime_partitions",
            _saga_match(
                "saas_runtime_partitions.id = onboarding_scope.runtime_partition_id "
                "AND saas_runtime_partitions.tenant_id = onboarding_scope.tenant_id "
                "AND saas_runtime_partitions.space_id = onboarding_scope.space_id "
                "AND onboarding_scope.runtime_placement_id IS NOT NULL "
                "AND saas_runtime_partitions.placement_id = onboarding_scope.runtime_placement_id "
                "AND onboarding_scope.runtime_target_snapshot ->> 'placement_id' = "
                "saas_runtime_partitions.placement_id::text "
                "AND saas_runtime_partitions.runtime_type = "
                "onboarding_scope.plan_snapshot ->> 'runtime_type' "
                "AND onboarding_scope.runtime_target_snapshot ->> 'runtime_type' = "
                "saas_runtime_partitions.runtime_type "
                "AND length(onboarding_scope.runtime_request_hash) = 64"
            ),
            "ALL",
        ),
        (
            "saas_runtime_identity_aliases",
            _saga_match(
                "saas_runtime_identity_aliases.runtime_partition_id = "
                "onboarding_scope.runtime_partition_id "
                "AND saas_runtime_identity_aliases.user_id = onboarding_scope.user_id"
            ),
            "ALL",
        ),
        (
            "saas_projects",
            _saga_match(
                "saas_projects.id = onboarding_scope.default_project_id "
                "AND saas_projects.tenant_id = onboarding_scope.tenant_id "
                "AND saas_projects.space_id = onboarding_scope.space_id "
                "AND saas_projects.created_by = onboarding_scope.user_id "
                "AND saas_projects.name = "
                "onboarding_scope.plan_snapshot ->> 'default_project_name' "
                "AND saas_projects.visibility = "
                "onboarding_scope.plan_snapshot ->> 'default_project_visibility'"
            ),
            "ALL",
        ),
        (
            "saas_project_memberships",
            _saga_match(
                "saas_project_memberships.project_id = onboarding_scope.default_project_id "
                "AND saas_project_memberships.tenant_id = onboarding_scope.tenant_id "
                "AND saas_project_memberships.space_id = onboarding_scope.space_id "
                "AND saas_project_memberships.subject_type = 'user' "
                "AND saas_project_memberships.subject_id = onboarding_scope.user_id "
                "AND saas_project_memberships.role = 'owner' "
                "AND saas_project_memberships.created_by = onboarding_scope.user_id"
            ),
            "ALL",
        ),
        (
            "saas_runtime_resource_bindings",
            _saga_match(
                "saas_runtime_resource_bindings.id = onboarding_scope.runtime_binding_id "
                "AND saas_runtime_resource_bindings.runtime_partition_id = "
                "onboarding_scope.runtime_partition_id "
                "AND saas_runtime_resource_bindings.tenant_id = onboarding_scope.tenant_id "
                "AND saas_runtime_resource_bindings.space_id = onboarding_scope.space_id "
                "AND saas_runtime_resource_bindings.project_id = "
                "onboarding_scope.default_project_id "
                "AND saas_runtime_resource_bindings.resource_type = 'project' "
                "AND saas_runtime_resource_bindings.saas_resource_id = "
                "onboarding_scope.default_project_id"
            ),
            "ALL",
        ),
        (
            "saas_admission_quotas",
            _saga_match(
                "saas_admission_quotas.tenant_id = onboarding_scope.tenant_id "
                "AND saas_admission_quotas.space_id = onboarding_scope.space_id "
                "AND saas_admission_quotas.project_id = onboarding_scope.default_project_id "
                "AND saas_admission_quotas.resource = "
                "onboarding_scope.plan_snapshot ->> 'quota_resource' "
                "AND saas_admission_quotas.limit_units = "
                "(onboarding_scope.plan_snapshot ->> 'quota_limit')::bigint"
            ),
            "ALL",
        ),
    )
    for table, predicate, operations in policies:
        _install_exact_policy(table=table, predicate=predicate, operations=operations)


def _remove_postgresql_authority() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in reversed(
        (
            "saas_billing_subscriptions",
            "saas_pricing_snapshots",
            "saas_billing_entitlements",
            "saas_billing_balances",
            "saas_runtime_placements",
            "saas_runtime_partitions",
            "saas_runtime_identity_aliases",
            "saas_projects",
            "saas_project_memberships",
            "saas_runtime_resource_bindings",
            "saas_admission_quotas",
        )
    ):
        _drop_exact_policy(table=table)
    op.execute("DROP POLICY IF EXISTS rls_spaces_onboarding_activation ON saas_spaces")
    op.execute("DROP POLICY IF EXISTS rls_tenants_onboarding_activation ON saas_tenants")
    _replace_outbox_policies(vertical=False)
    _replace_saga_policies(vertical=False)
    for table, policy in (
        ("saas_billing_subscriptions", "rls_billing_subscriptions_metering_exact"),
        ("saas_billing_subscriptions", "rls_billing_subscriptions_metering_lock"),
        ("saas_pricing_snapshots", "rls_pricing_snapshots_metering_exact"),
        ("saas_runtime_placements", "rls_runtime_placements_scope"),
        ("saas_runtime_partitions", "rls_runtime_partitions_privacy_verifier_read"),
        ("saas_project_memberships", "rls_saas_project_memberships_privacy_target"),
    ):
        op.execute(f"ALTER POLICY {policy} ON {table} TO PUBLIC")


def _drop_columns_and_restore_constraints() -> None:
    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.drop_constraint("fk_tenant_onboarding_runtime_placement", type_="foreignkey")
        batch.drop_constraint("fk_tenant_onboarding_first_run_scope", type_="foreignkey")
        batch.drop_constraint("uq_tenant_onboarding_first_run", type_="unique")
        batch.drop_constraint("uq_tenant_onboarding_runtime_binding", type_="unique")
        batch.drop_constraint("uq_tenant_onboarding_entitlement", type_="unique")
        batch.drop_constraint("uq_tenant_onboarding_pricing_snapshot", type_="unique")
        batch.drop_constraint("uq_tenant_onboarding_default_project", type_="unique")
        batch.drop_constraint("ck_tenant_onboarding_compensation_cursor", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_failure_stage", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_initial_placement", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_runtime_request", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_plan_snapshot_hash", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_plan_snapshot_nonempty", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_status", type_="check")
        for column in (
            "compensation_cursor",
            "failure_stage",
            "completed_at",
            "first_run_id",
            "project_ready_at",
            "runtime_request_hash",
            "runtime_target_snapshot",
            "runtime_placement_id",
            "plan_snapshot_hash",
            "plan_snapshot",
            "runtime_binding_id",
            "entitlement_id",
            "pricing_snapshot_id",
            "default_project_id",
        ):
            batch.drop_column(column)
        batch.create_check_constraint(
            "ck_tenant_onboarding_status",
            "status IN ('tenant_created', 'billing_ready', 'runtime_ready', 'active', "
            "'compensating', 'compensated', 'manual_review')",
        )
        batch.create_check_constraint(
            "ck_tenant_onboarding_state_evidence",
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
        )

    with op.batch_alter_table("saas_self_service_registrations") as batch:
        batch.drop_constraint("uq_self_service_registration_runtime_binding", type_="unique")
        batch.drop_constraint("uq_self_service_registration_entitlement", type_="unique")
        batch.drop_constraint("uq_self_service_registration_pricing_snapshot", type_="unique")
        batch.drop_constraint("uq_self_service_registration_project", type_="unique")
        batch.drop_constraint("ck_self_service_plan_snapshot_hash", type_="check")
        batch.drop_constraint("ck_self_service_plan_snapshot_nonempty", type_="check")
        for column in (
            "plan_snapshot_hash",
            "plan_snapshot",
            "runtime_binding_id",
            "entitlement_id",
            "pricing_snapshot_id",
            "default_project_id",
        ):
            batch.drop_column(column)


def _prepare_legacy_state_for_downgrade() -> None:
    """Translate additive states back to the p0s1 state machine on every dialect."""

    with op.batch_alter_table("saas_tenant_onboardings") as batch:
        batch.drop_constraint("ck_tenant_onboarding_state_evidence", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_failure_evidence", type_="check")
        batch.drop_constraint("ck_tenant_onboarding_ready_placement", type_="check")

    onboarding = sa.table(
        "saas_tenant_onboardings",
        sa.column("id", sa.Uuid()),
        sa.column("status", sa.String()),
        sa.column("trial_days", sa.Integer()),
        sa.column("trial_started_at", sa.DateTime(timezone=True)),
        sa.column("trial_ends_at", sa.DateTime(timezone=True)),
        sa.column("billing_ready_at", sa.DateTime(timezone=True)),
        sa.column("runtime_ready_at", sa.DateTime(timezone=True)),
        sa.column("project_ready_at", sa.DateTime(timezone=True)),
        sa.column("activated_at", sa.DateTime(timezone=True)),
        sa.column("failure_stage", sa.String()),
        sa.column("compensation_cursor", sa.String()),
        sa.column("last_transition_at", sa.DateTime(timezone=True)),
    )
    bind = op.get_bind()
    bind.execute(
        onboarding.update()
        .where(
            onboarding.c.status == "manual_review",
            onboarding.c.failure_stage != "legacy_active",
        )
        .values(activated_at=None)
    )
    for legacy_status in ("billing_ready", "runtime_ready", "active"):
        restored: dict[str, object] = {
            "status": legacy_status,
            "failure_stage": None,
            "compensation_cursor": None,
        }
        if legacy_status == "active":
            restored["activated_at"] = sa.func.coalesce(
                onboarding.c.activated_at,
                onboarding.c.project_ready_at,
                onboarding.c.last_transition_at,
            )
        bind.execute(
            onboarding.update()
            .where(
                onboarding.c.status == "manual_review",
                onboarding.c.failure_stage == f"legacy_{legacy_status}",
            )
            .values(**restored)
        )
    bind.execute(
        onboarding.update()
        .where(onboarding.c.status == "project_ready")
        .values(status="runtime_ready")
    )
    bind.execute(
        onboarding.update().where(onboarding.c.status == "completed").values(status="active")
    )
    rows = bind.execute(
        sa.select(
            sa.cast(onboarding.c.id, sa.String()).label("onboarding_id_text"),
            onboarding.c.status,
            onboarding.c.trial_days,
            onboarding.c.trial_started_at,
            onboarding.c.trial_ends_at,
            onboarding.c.billing_ready_at,
            onboarding.c.runtime_ready_at,
            onboarding.c.project_ready_at,
            onboarding.c.activated_at,
            onboarding.c.last_transition_at,
        ).where(onboarding.c.status.in_(("billing_ready", "runtime_ready", "active")))
    ).mappings()
    for row in rows:
        started_at = row["trial_started_at"] or next(
            value
            for value in (
                row["activated_at"],
                row["project_ready_at"],
                row["runtime_ready_at"],
                row["billing_ready_at"],
                row["last_transition_at"],
            )
            if value is not None
        )
        bind.execute(
            onboarding.update()
            .where(sa.cast(onboarding.c.id, sa.String()) == str(row["onboarding_id_text"]))
            .values(
                trial_started_at=started_at,
                trial_ends_at=row["trial_ends_at"]
                or started_at + timedelta(days=int(row["trial_days"])),
            )
        )


def upgrade() -> None:
    """Preallocate the full vertical chain and install exact worker authority."""

    _add_columns()
    _relax_legacy_state_for_upgrade()
    _backfill_existing_authority()
    _backfill_pending_outbox_payloads()
    _ensure_recovery_wakes()
    _finalize_constraints()
    _install_postgresql_authority()


def downgrade() -> None:
    """Remove the additive vertical-chain authority and restore P0 foundation policy."""

    _remove_postgresql_authority()
    _prepare_legacy_state_for_downgrade()
    _drop_columns_and_restore_constraints()
