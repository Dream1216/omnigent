"""Consume retained model security intent through the existing Executor authority."""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.query_context import query_name_scope
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.interactive_run_route import INTERACTIVE_QUEUE_CLASS
from saas.control_plane.model_revocations import revoked_run_publication
from saas.control_plane.model_routing_models import ModelPublicationRevocationRecord as Revocation
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord as Publication
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling import SchedulingControlPlane


class ModelRevocationRunCanceller:
    def __init__(self, sessions: sessionmaker[Session]):
        self._sessions = sessions

    def cancel_pending(self, *, limit: int = 100, now: datetime | None = None):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("model_revocation_batch_invalid")
        at = now or datetime.now(timezone.utc)
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("model_revocation_clock_invalid")
        matching = (
            sa.select(sa.literal(1))
            .select_from(Revocation, Publication)
            .where(revoked_run_publication(RunRecord))
            .correlate(RunRecord)
            .exists()
        )
        with (
            query_name_scope("saas.model_revocation_execution.cancel_affected_runs"),
            self._sessions.begin() as db,
        ):
            query = (
                sa.select(RunRecord)
                .where(
                    RunRecord.queue_class == INTERACTIVE_QUEUE_CLASS,
                    RunRecord.status.in_(
                        (
                            "created",
                            "queued",
                            "leased",
                            "starting",
                            "running",
                            "waiting_input",
                            "waiting_approval",
                        )
                    ),
                    matching,
                )
                .order_by(RunRecord.created_at, RunRecord.id)
                .limit(limit)
            )
            if db.get_bind().dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True, of=RunRecord)
            mutations = []
            for run in db.scalars(query):
                apply_rls_context(
                    db,
                    RlsContext(
                        tenant_id=run.tenant_id, space_id=run.space_id, project_id=run.project_id
                    ),
                )
                identifier = db.scalar(
                    sa.select(Revocation.id)
                    .select_from(Revocation, Publication, RunRecord)
                    .where(RunRecord.id == run.id, revoked_run_publication(RunRecord))
                    .order_by(Revocation.created_at, Revocation.id)
                    .limit(1)
                )
                if identifier is None:
                    raise RuntimeError("model_revocation_authority_changed")
                mutations.append(
                    ExecutionControlPlane._cancel_in_session(
                        db,
                        run,
                        requested_at=at,
                        payload={
                            "reason": "managed_model_security_revocation",
                            "model_revocation_id": str(identifier),
                        },
                        trace_id=f"model-revocation:{identifier}",
                    )
                )
                db.flush()
            return tuple(mutations)


class ModelRevocationSchedulerRecovery:
    """Apply bounded security cancellation before normal expired-lease recovery."""

    def __init__(self, sessions: sessionmaker[Session], scheduling: SchedulingControlPlane):
        self._cancellations = ModelRevocationRunCanceller(sessions)
        self._scheduling = scheduling

    def recover_expired_dispatches(self, *, max_fence_token: int = 3, limit: int = 100):
        self._cancellations.cancel_pending(limit=limit)
        return self._scheduling.recover_expired_dispatches(
            max_fence_token=max_fence_token, limit=limit
        )
