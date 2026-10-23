"""Retain a Staff security command without granting Staff execution authority."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_connections import (
    _IDEMPOTENCY,
    authorize_platform_model_operation,
    lock_model_operation_idempotency,
)
from saas.control_plane.model_routing_models import (
    ModelPublicationDisablementRecord as Cutoff,
)
from saas.control_plane.model_routing_models import (
    ModelPublicationRevocationRecord as Revocation,
)
from saas.control_plane.model_routing_models import (
    ModelPublicationVersionRecord as Publication,
)
from saas.control_plane.model_verification_contract import canonical_verification_document
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)

REVOCATION_EVENT = "platform.model_publication.revocation_requested"


def _error(code: str) -> PlatformSecurityError:
    return PlatformSecurityError(code, "Model security revocation is unavailable or changed")


def lock_model_security_scope(
    db: Session, *, tenant_id: UUID, public_model_id: str, wire_api: str
):
    """Serialize intent admission with managed terminal transitions, not model traffic."""
    if db.get_bind().dialect.name != "postgresql":
        return
    if (
        db.scalar(sa.text("SELECT pg_catalog.current_setting('transaction_isolation')"))
        != "read committed"
    ):
        raise _error("platform_model_revocation_isolation_unavailable")
    scope = canonical_verification_document(
        {"tenant_id": str(tenant_id), "public_model_id": public_model_id, "wire_api": wire_api}
    )
    key = int.from_bytes(
        sha256(("managed-model-security:" + scope).encode("ascii")).digest()[:8],
        "big",
        signed=True,
    )
    db.execute(sa.text("SELECT pg_catalog.pg_advisory_xact_lock(:key)"), {"key": key})


def revoked_run_publication(run):
    """Match only the immutable tenant/model/protocol/version selected by this Run."""
    marker = run.input["execution"]["model_publication"]
    return sa.and_(
        Revocation.tenant_id == run.tenant_id,
        Publication.tenant_id == run.tenant_id,
        Publication.public_model_id == Revocation.public_model_id,
        Publication.wire_api == Revocation.wire_api,
        Publication.generation <= Revocation.through_generation,
        Publication.public_model_id == marker["public_model_id"].as_string(),
        Publication.wire_api == marker["wire_api"].as_string(),
        sa.cast(Publication.generation, sa.String)
        == sa.cast(marker["generation"].as_string(), sa.String),
        Publication.snapshot_sha256 == marker["snapshot_sha256"].as_string(),
    )


def run_security_revoked(db: Session, run_id: UUID) -> bool:
    from saas.control_plane.execution_models import RunRecord

    return bool(
        db.scalar(
            sa.select(
                sa.select(sa.literal(1))
                .select_from(Revocation, Publication, RunRecord)
                .where(RunRecord.id == run_id, revoked_run_publication(RunRecord))
                .exists()
            )
        )
    )


def executor_run_revocation(db: Session, run_id: UUID) -> UUID | None:
    from saas.control_plane.execution_models import RunRecord

    return db.scalar(
        sa.select(Revocation.id)
        .select_from(Revocation, Publication, RunRecord)
        .where(RunRecord.id == run_id, revoked_run_publication(RunRecord))
        .order_by(Revocation.created_at, Revocation.id)
        .limit(1)
    )


class ModelSecurityRevocationService:
    def __init__(self, engine: sa.Engine, *, authorization: PlatformAuthorizationService):
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_revocations", immediate=True
        )
        self._authorization = authorization

    @staticmethod
    def _view(row: Revocation) -> dict[str, object]:
        return {
            "revocation_id": row.id,
            "disablement_id": row.disablement_id,
            "tenant_id": row.tenant_id,
            "public_model_id": row.public_model_id,
            "wire_api": row.wire_api,
            "through_generation": row.through_generation,
            "created_at": row.created_at.replace(tzinfo=timezone.utc)
            if row.created_at.tzinfo is None
            else row.created_at.astimezone(timezone.utc),
            "revocation_requested": True,
            "execution_complete": False,
        }

    def request(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        disablement_id: UUID,
        expected_generation: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        if (
            not isinstance(disablement_id, UUID)
            or not disablement_id.int
            or type(expected_generation) is not int
            or not 1 <= expected_generation < 2**31
            or not isinstance(idempotency_key, str)
            or _IDEMPOTENCY.fullmatch(idempotency_key) is None
        ):
            raise _error("platform_model_revocation_invalid")
        digest = sha256(
            canonical_verification_document(
                {
                    "action": "security_revoke_publication",
                    "disablement_id": str(disablement_id),
                    "expected_generation": expected_generation,
                }
            ).encode("ascii")
        ).hexdigest()
        now = datetime.now(timezone.utc)
        with self._session("retain_security_revocation") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.publish", now
            )
            lock_model_operation_idempotency(db, actor.principal_id)
            prior = db.scalar(
                sa.select(Revocation).where(
                    Revocation.principal_id == actor.principal_id,
                    Revocation.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if prior.request_hash != digest:
                    raise _error("platform_model_revocation_conflict")
                return self._view(prior)
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.select(
                        sa.func.pg_advisory_xact_lock(
                            sa.func.hashtextextended(
                                "model-security-revocation:" + str(disablement_id), 0
                            )
                        )
                    )
                )
            cutoff = db.get(Cutoff, disablement_id)
            if cutoff is None or cutoff.through_generation != expected_generation:
                raise _error("platform_model_revocation_conflict")
            lock_model_security_scope(
                db,
                tenant_id=cutoff.tenant_id,
                public_model_id=cutoff.public_model_id,
                wire_api=cutoff.wire_api,
            )
            if db.scalar(
                sa.select(Revocation.id).where(Revocation.disablement_id == disablement_id)
            ):
                raise _error("platform_model_revocation_conflict")
            at = (
                db.scalar(sa.select(sa.func.clock_timestamp()))
                if db.get_bind().dialect.name == "postgresql"
                else now
            )
            row = Revocation(
                id=uuid4(),
                disablement_id=cutoff.id,
                tenant_id=cutoff.tenant_id,
                public_model_id=cutoff.public_model_id,
                wire_api=cutoff.wire_api,
                through_generation=cutoff.through_generation,
                principal_id=actor.principal_id,
                staff_session_id=actor.session_id,
                staff_security_version=actor.security_version,
                idempotency_key=idempotency_key,
                request_hash=digest,
                created_at=at,
            )
            db.add(row)
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=None,
                    aggregate_type="platform_model",
                    aggregate_key=str(row.id),
                    event_type=REVOCATION_EVENT,
                    idempotency_key="model-revocation:" + str(row.id),
                    request_hash=digest,
                    payload={
                        "event_type": REVOCATION_EVENT,
                        "schema_version": 1,
                        "revocation_id": str(row.id),
                    },
                )
            )
            return self._view(row)

    def receipt(self, actor: ValidatedPlatformPrincipal, revocation_id: UUID):
        with self._session("read_security_revocation_receipt") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            row = db.get(Revocation, revocation_id)
            if row is None:
                raise _error("platform_model_revocation_not_found")
            return self._view(row)

    def find(self, actor: ValidatedPlatformPrincipal, *, idempotency_key: str):
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise _error("platform_model_revocation_invalid")
        with self._session("find_security_revocation_receipt") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            row = db.scalar(
                sa.select(Revocation).where(
                    Revocation.principal_id == actor.principal_id,
                    Revocation.idempotency_key == idempotency_key,
                )
            )
            return None if row is None else self._view(row)
