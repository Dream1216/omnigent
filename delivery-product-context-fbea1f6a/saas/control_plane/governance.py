"""High-risk membership governance: ownership transfer and removal preflight."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol, cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    MemberRemovalPreflightRecord,
    OwnershipTransferRecord,
    ProjectMembershipRecord,
    ProjectRecord,
    ResourceGrantRecord,
    SpaceMembership,
    TenantMembership,
)
from saas.control_plane.enterprise_models import (
    EnterpriseGroupMembershipRecord,
    EnterpriseGroupRoleAssignmentRecord,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.rls import RlsContext, apply_rls_context

_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_PREFLIGHT_TTL = timedelta(minutes=15)


@dataclass(frozen=True, slots=True)
class RemovalImpact:
    """Server-collected resource facts that can block member removal."""

    facts: dict[str, object]
    blocking_count: int

    def validate(self) -> None:
        if self.blocking_count < 0:
            raise ValueError("Removal impact blocking_count cannot be negative")
        try:
            json.dumps(self.facts, sort_keys=True)
        except (TypeError, ValueError) as error:
            raise ValueError("Removal impact facts must be JSON serializable") from error


class RemovalImpactProvider(Protocol):
    """Trusted resource repository adapter used immediately before removal."""

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact: ...


class UnavailableRemovalImpactProvider:
    """Fail closed until a deployment wires all resource repositories."""

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        del tenant_id, space_id, user_id
        raise LifecycleError(
            "removal_impact_provider_unavailable",
            "member removal is disabled until resource impact repositories are wired",
        )


@dataclass(frozen=True, slots=True)
class OwnershipTransferred:
    """Committed ownership transfer versions."""

    transfer_id: UUID
    scope: str
    source_version: int
    target_version: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class RemovalPreflight:
    """Persisted resource impact decision."""

    preflight_id: UUID
    status: str
    blocking_count: int
    snapshot_hash: str
    expires_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class MemberRemoved:
    """Committed logical removal and authorization invalidation versions."""

    scope: str
    membership_version: int
    removed_space_memberships: int
    security_version: int
    revoked_session_count: int
    revoked_project_memberships: int
    revoked_resource_grants: int
    changed_project_authorizations: int
    revoked_group_memberships: int
    changed_group_project_authorizations: int
    replayed: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _comparable(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _require_fresh_auth(reauthenticated_at: datetime, now: datetime) -> None:
    comparable = _comparable(reauthenticated_at)
    if comparable > now or now - comparable > _FRESH_AUTH_WINDOW:
        raise LifecycleError(
            "fresh_authentication_required",
            "high-risk membership operation requires authentication within five minutes",
        )


def _require_reason(reason: str) -> str:
    cleaned = reason.strip()
    if not cleaned or len(cleaned) > 1024:
        raise LifecycleError("reason_required", "a reason of 1 to 1024 characters is required")
    return cleaned


def _require_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")


def _invalidate_sessions(db: Session, user_id: UUID, changed_at: datetime) -> tuple[int, int]:
    version = db.execute(
        sa.update(GlobalUser)
        .where(GlobalUser.id == user_id, GlobalUser.status == "active")
        .values(security_version=GlobalUser.security_version + 1)
        .returning(GlobalUser.security_version)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    if version is None:
        raise LifecycleError("user_inactive", "active target user is required")
    result = cast(
        CursorResult[tuple[object]],
        db.execute(
            sa.update(AuthSessionRecord)
            .where(
                AuthSessionRecord.user_id == user_id,
                AuthSessionRecord.revoked_at.is_(None),
            )
            .values(revoked_at=changed_at)
        ),
    )
    return version, result.rowcount


def _add_event(
    db: Session,
    *,
    tenant_id: UUID,
    aggregate_type: str,
    aggregate_key: str,
    event_type: str,
    idempotency_key: str,
    request_hash: str,
    payload: dict[str, object],
) -> None:
    db.add(
        ControlPlaneOutboxEvent(
            tenant_id=tenant_id,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            event_type=event_type,
            idempotency_key=scoped_idempotency_key("tenant", tenant_id, idempotency_key),
            request_hash=request_hash,
            payload=payload,
            attempt_count=0,
        )
    )


class MembershipGovernanceService:
    """Execute security-sensitive membership operations under explicit gates."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        impact_provider: RemovalImpactProvider | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._impact_provider = impact_provider or UnavailableRemovalImpactProvider()

    def transfer_ownership(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        from_user_id: UUID,
        to_user_id: UUID,
        source_expected_version: int,
        target_expected_version: int,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        space_id: UUID | None = None,
        now: datetime | None = None,
    ) -> OwnershipTransferred:
        """Atomically hand one Owner role to an active member in the same scope."""

        changed_at = now or _now()
        _require_idempotency_key(idempotency_key)
        _require_fresh_auth(reauthenticated_at, changed_at)
        cleaned_reason = _require_reason(reason)
        if actor_id != from_user_id or from_user_id == to_user_id:
            raise LifecycleError(
                "ownership_transfer_forbidden", "the current Owner must initiate transfer"
            )
        if min(source_expected_version, target_expected_version) < 1:
            raise LifecycleError("membership_version_invalid", "membership versions are invalid")
        scope = "space" if space_id else "tenant"
        request_hash = _digest(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "from_user_id": str(from_user_id),
                "to_user_id": str(to_user_id),
                "source_expected_version": source_expected_version,
                "target_expected_version": target_expected_version,
                "reason": cleaned_reason,
            }
        )
        event_type = f"{scope}.ownership.transferred"
        receipt_key = scoped_idempotency_key("tenant", tenant_id, idempotency_key)
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash or receipt.event_type != event_type:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return OwnershipTransferred(
                    transfer_id=UUID(cast(str, receipt.payload["transfer_id"])),
                    scope=scope,
                    source_version=cast(int, receipt.payload["source_version"]),
                    target_version=cast(int, receipt.payload["target_version"]),
                    replayed=True,
                )

            source, target = self._lock_transfer_memberships(
                db,
                tenant_id=tenant_id,
                space_id=space_id,
                from_user_id=from_user_id,
                to_user_id=to_user_id,
            )
            if source.role != "owner" or source.status != "active":
                raise LifecycleError("owner_required", "source member is not an active Owner")
            if target.status != "active" or target.role == "owner":
                raise LifecycleError(
                    "target_member_invalid", "target must be an active non-Owner member"
                )
            if (
                source.version != source_expected_version
                or target.version != target_expected_version
            ):
                raise LifecycleError(
                    "membership_version_conflict", "ownership memberships changed concurrently"
                )

            source_after = source.version + 1
            target_after = target.version + 1
            source.role = "admin"
            source.version = source_after
            target.role = "owner"
            target.version = target_after
            _, source_revoked = _invalidate_sessions(db, from_user_id, changed_at)
            _, target_revoked = _invalidate_sessions(db, to_user_id, changed_at)

            transfer_id = uuid4()
            db.add(
                OwnershipTransferRecord(
                    id=transfer_id,
                    tenant_id=tenant_id,
                    space_id=space_id,
                    from_user_id=from_user_id,
                    to_user_id=to_user_id,
                    requested_by=actor_id,
                    reason=cleaned_reason,
                    status="completed",
                    source_version_before=source_expected_version,
                    target_version_before=target_expected_version,
                    source_version_after=source_after,
                    target_version_after=target_after,
                    completed_at=changed_at,
                )
            )
            payload: dict[str, object] = {
                "transfer_id": str(transfer_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "from_user_id": str(from_user_id),
                "to_user_id": str(to_user_id),
                "source_version": source_after,
                "target_version": target_after,
                "revoked_session_count": source_revoked + target_revoked,
                "reason": cleaned_reason,
            }
            _add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type=f"{scope}_ownership",
                aggregate_key=str(space_id or tenant_id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return OwnershipTransferred(
                transfer_id=transfer_id,
                scope=scope,
                source_version=source_after,
                target_version=target_after,
                replayed=False,
            )

    def create_removal_preflight(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        idempotency_key: str,
        space_id: UUID | None = None,
        now: datetime | None = None,
    ) -> RemovalPreflight:
        """Persist a trusted, time-limited impact snapshot for one membership."""

        created_at = now or _now()
        _require_idempotency_key(idempotency_key)
        scope = "space" if space_id else "tenant"
        request_hash = _digest(
            {
                "actor_id": str(actor_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "user_id": str(user_id),
            }
        )
        event_type = f"{scope}.membership.removal.preflighted"
        receipt_key = scoped_idempotency_key("tenant", tenant_id, idempotency_key)
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            self._require_removal_admin(db, tenant_id, space_id, actor_id)
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash or receipt.event_type != event_type:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return self._preflight_result(receipt.payload, replayed=True)
            membership = self._membership(db, tenant_id, space_id, user_id)
            if membership.status not in ("active", "suspended"):
                raise LifecycleError("membership_not_removable", "membership is not removable")
            if membership.role == "owner":
                raise LifecycleError(
                    "ownership_transfer_required",
                    "Owner must transfer ownership before removal",
                )
        external = self._impact_provider.collect(
            tenant_id=tenant_id, space_id=space_id, user_id=user_id
        )
        external.validate()
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash or receipt.event_type != event_type:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return self._preflight_result(receipt.payload, replayed=True)

            self._require_removal_admin(db, tenant_id, space_id, actor_id)
            membership = self._membership(db, tenant_id, space_id, user_id)
            if membership.status not in ("active", "suspended"):
                raise LifecycleError("membership_not_removable", "membership is not removable")
            if membership.role == "owner":
                raise LifecycleError(
                    "ownership_transfer_required", "Owner must transfer ownership before removal"
                )
            active_spaces: list[str] = []
            if space_id is None:
                active_spaces = [
                    str(value)
                    for value in db.execute(
                        sa.select(SpaceMembership.space_id).where(
                            SpaceMembership.tenant_id == tenant_id,
                            SpaceMembership.user_id == user_id,
                            SpaceMembership.status.in_(("active", "suspended")),
                        )
                    ).scalars()
                ]
            snapshot: dict[str, object] = {
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "user_id": str(user_id),
                "membership_version": membership.version,
                "active_space_memberships": sorted(active_spaces),
                "resource_impacts": external.facts,
                "blocking_count": external.blocking_count,
            }
            snapshot_hash = _digest(snapshot)
            status = "ready" if external.blocking_count == 0 else "blocked"
            expires_at = created_at + _PREFLIGHT_TTL
            preflight_id = uuid4()
            db.add(
                MemberRemovalPreflightRecord(
                    id=preflight_id,
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=user_id,
                    requested_by=actor_id,
                    membership_version=membership.version,
                    impact_snapshot=snapshot,
                    snapshot_hash=snapshot_hash,
                    blocking_count=external.blocking_count,
                    status=status,
                    expires_at=expires_at,
                )
            )
            payload: dict[str, object] = {
                "preflight_id": str(preflight_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "user_id": str(user_id),
                "status": status,
                "blocking_count": external.blocking_count,
                "snapshot_hash": snapshot_hash,
                "expires_at": expires_at.isoformat(),
            }
            _add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="member_removal_preflight",
                aggregate_key=str(preflight_id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return RemovalPreflight(
                preflight_id=preflight_id,
                status=status,
                blocking_count=external.blocking_count,
                snapshot_hash=snapshot_hash,
                expires_at=expires_at,
                replayed=False,
            )

    def execute_member_removal(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        preflight_id: UUID,
        reason: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> MemberRemoved:
        """Execute removal only if membership and every impact fact still match."""

        removed_at = now or _now()
        _require_idempotency_key(idempotency_key)
        _require_fresh_auth(reauthenticated_at, removed_at)
        cleaned_reason = _require_reason(reason)
        with self._session_factory() as db, db.begin():
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            snapshot_row = db.get(MemberRemovalPreflightRecord, preflight_id)
            if snapshot_row is None or snapshot_row.tenant_id != tenant_id:
                raise LifecycleError("preflight_not_found", "removal preflight does not exist")
            space_id = snapshot_row.space_id
            user_id = snapshot_row.user_id
            self._require_removal_admin(db, tenant_id, space_id, actor_id)
            scope = "space" if space_id else "tenant"
            request_hash = _digest(
                {
                    "actor_id": str(actor_id),
                    "preflight_id": str(preflight_id),
                    "reason": cleaned_reason,
                }
            )
            event_type = f"{scope}.membership.removed"
            receipt_key = scoped_idempotency_key("tenant", tenant_id, idempotency_key)
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash or receipt.event_type != event_type:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return self._removed_result(receipt.payload, replayed=True)
        external = self._impact_provider.collect(
            tenant_id=tenant_id, space_id=space_id, user_id=user_id
        )
        external.validate()

        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash or receipt.event_type != event_type:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key belongs to another request"
                    )
                return self._removed_result(receipt.payload, replayed=True)
            self._require_removal_admin(db, tenant_id, space_id, actor_id)
            preflight = db.get(MemberRemovalPreflightRecord, preflight_id)
            if preflight is None or preflight.status != "ready":
                raise LifecycleError("preflight_not_ready", "removal preflight is not ready")
            if _comparable(preflight.expires_at) <= removed_at:
                raise LifecycleError("preflight_expired", "removal preflight has expired")

            membership = self._membership(db, tenant_id, space_id, user_id)
            active_spaces: list[str] = []
            if space_id is None:
                active_spaces = [
                    str(value)
                    for value in db.execute(
                        sa.select(SpaceMembership.space_id).where(
                            SpaceMembership.tenant_id == tenant_id,
                            SpaceMembership.user_id == user_id,
                            SpaceMembership.status.in_(("active", "suspended")),
                        )
                    ).scalars()
                ]
            current_snapshot: dict[str, object] = {
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "user_id": str(user_id),
                "membership_version": membership.version,
                "active_space_memberships": sorted(active_spaces),
                "resource_impacts": external.facts,
                "blocking_count": external.blocking_count,
            }
            if (
                membership.version != preflight.membership_version
                or external.blocking_count != 0
                or _digest(current_snapshot) != preflight.snapshot_hash
            ):
                raise LifecycleError(
                    "preflight_stale", "membership or resource impact changed after preflight"
                )

            revoked_project_memberships, revoked_resource_grants, changed_projects = (
                self._revoke_project_access(db, tenant_id, space_id, user_id)
            )
            revoked_group_memberships, changed_group_projects = (
                self._revoke_enterprise_group_access(db, tenant_id, space_id, user_id)
            )
            membership.version += 1
            membership.status = "removed"
            removed_spaces = 0
            if space_id is None:
                result = cast(
                    CursorResult[tuple[object]],
                    db.execute(
                        sa.update(SpaceMembership)
                        .where(
                            SpaceMembership.tenant_id == tenant_id,
                            SpaceMembership.user_id == user_id,
                            SpaceMembership.status.in_(("active", "suspended")),
                        )
                        .values(
                            status="removed",
                            version=SpaceMembership.version + 1,
                        )
                    ),
                )
                removed_spaces = result.rowcount
            security_version, revoked_count = _invalidate_sessions(db, user_id, removed_at)
            preflight.status = "executed"
            preflight.executed_at = removed_at
            payload: dict[str, object] = {
                "scope": scope,
                "preflight_id": str(preflight_id),
                "tenant_id": str(tenant_id),
                "space_id": str(space_id) if space_id else None,
                "user_id": str(user_id),
                "membership_version": membership.version,
                "removed_space_memberships": removed_spaces,
                "security_version": security_version,
                "revoked_session_count": revoked_count,
                "revoked_project_memberships": revoked_project_memberships,
                "revoked_resource_grants": revoked_resource_grants,
                "changed_project_authorizations": changed_projects,
                "revoked_group_memberships": revoked_group_memberships,
                "changed_group_project_authorizations": changed_group_projects,
                "reason": cleaned_reason,
                "removed_by": str(actor_id),
            }
            _add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type=f"{scope}_membership",
                aggregate_key=f"{space_id or tenant_id}:{user_id}",
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=payload,
            )
            return self._removed_result(payload, replayed=False)

    @staticmethod
    def _revoke_project_access(
        db: Session,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> tuple[int, int, int]:
        membership_filters = [
            ProjectMembershipRecord.tenant_id == tenant_id,
            ProjectMembershipRecord.subject_type == "user",
            ProjectMembershipRecord.subject_id == user_id,
            ProjectMembershipRecord.status == "active",
        ]
        grant_filters = [
            ResourceGrantRecord.tenant_id == tenant_id,
            ResourceGrantRecord.subject_type == "user",
            ResourceGrantRecord.subject_id == user_id,
            ResourceGrantRecord.status == "active",
        ]
        if space_id is not None:
            membership_filters.append(ProjectMembershipRecord.space_id == space_id)
            grant_filters.append(ResourceGrantRecord.space_id == space_id)
        memberships = list(
            db.execute(
                sa.select(ProjectMembershipRecord).where(*membership_filters).with_for_update()
            ).scalars()
        )
        grants = list(
            db.execute(
                sa.select(ResourceGrantRecord).where(*grant_filters).with_for_update()
            ).scalars()
        )
        if any(membership.role == "owner" for membership in memberships):
            raise LifecycleError(
                "preflight_stale", "Project ownership must be transferred before removal"
            )
        affected_projects = {
            *(membership.project_id for membership in memberships),
            *(grant.project_id for grant in grants),
        }
        for membership in memberships:
            membership.status = "revoked"
            membership.version += 1
        for grant in grants:
            grant.status = "revoked"
            grant.version += 1
        if affected_projects:
            projects = db.execute(
                sa.select(ProjectRecord)
                .where(
                    ProjectRecord.tenant_id == tenant_id,
                    ProjectRecord.id.in_(affected_projects),
                )
                .with_for_update()
            ).scalars()
            for project in projects:
                project.authorization_version += 1
        return len(memberships), len(grants), len(affected_projects)

    @staticmethod
    def _revoke_enterprise_group_access(
        db: Session,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> tuple[int, int]:
        if space_id is not None:
            return 0, 0
        memberships = list(
            db.execute(
                sa.select(EnterpriseGroupMembershipRecord)
                .where(
                    EnterpriseGroupMembershipRecord.tenant_id == tenant_id,
                    EnterpriseGroupMembershipRecord.user_id == user_id,
                    EnterpriseGroupMembershipRecord.status == "active",
                )
                .with_for_update()
            ).scalars()
        )
        if not memberships:
            return 0, 0
        group_ids = tuple(membership.group_id for membership in memberships)
        affected_projects = tuple(
            db.execute(
                sa.select(EnterpriseGroupRoleAssignmentRecord.project_id)
                .where(
                    EnterpriseGroupRoleAssignmentRecord.tenant_id == tenant_id,
                    EnterpriseGroupRoleAssignmentRecord.group_id.in_(group_ids),
                    EnterpriseGroupRoleAssignmentRecord.status == "active",
                )
                .distinct()
            ).scalars()
        )
        for membership in memberships:
            membership.status = "removed"
            membership.expires_at = None
            membership.version += 1
        if affected_projects:
            projects = db.execute(
                sa.select(ProjectRecord)
                .where(
                    ProjectRecord.tenant_id == tenant_id,
                    ProjectRecord.id.in_(affected_projects),
                )
                .with_for_update()
            ).scalars()
            for project in projects:
                project.authorization_version += 1
        return len(memberships), len(affected_projects)

    @staticmethod
    def _lock_transfer_memberships(
        db: Session,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        from_user_id: UUID,
        to_user_id: UUID,
    ) -> tuple[TenantMembership | SpaceMembership, TenantMembership | SpaceMembership]:
        model = SpaceMembership if space_id else TenantMembership
        filters = [model.tenant_id == tenant_id, model.user_id.in_((from_user_id, to_user_id))]
        if space_id is not None:
            filters.append(SpaceMembership.space_id == space_id)
        query = sa.select(model).where(*filters).order_by(model.user_id).with_for_update()
        rows = {row.user_id: row for row in db.execute(query).scalars()}
        source = rows.get(from_user_id)
        target = rows.get(to_user_id)
        if source is None or target is None:
            raise LifecycleError(
                "membership_not_found", "both ownership-transfer memberships must exist"
            )
        return source, target

    @staticmethod
    def _require_removal_admin(
        db: Session, tenant_id: UUID, space_id: UUID | None, actor_id: UUID
    ) -> None:
        tenant_actor = db.get(TenantMembership, (tenant_id, actor_id))
        if (
            tenant_actor is not None
            and tenant_actor.status == "active"
            and tenant_actor.role in ("owner", "admin")
        ):
            return
        if space_id is not None:
            space_actor = db.get(SpaceMembership, (tenant_id, space_id, actor_id))
            if (
                space_actor is not None
                and space_actor.status == "active"
                and space_actor.role in ("owner", "admin")
            ):
                return
        raise LifecycleError("forbidden", "active membership administrator is required")

    @staticmethod
    def _membership(
        db: Session, tenant_id: UUID, space_id: UUID | None, user_id: UUID
    ) -> TenantMembership | SpaceMembership:
        membership = (
            db.get(SpaceMembership, (tenant_id, space_id, user_id))
            if space_id is not None
            else db.get(TenantMembership, (tenant_id, user_id))
        )
        if membership is None:
            raise LifecycleError("membership_not_found", "membership does not exist")
        return membership

    @staticmethod
    def _preflight_result(payload: dict[str, object], *, replayed: bool) -> RemovalPreflight:
        return RemovalPreflight(
            preflight_id=UUID(cast(str, payload["preflight_id"])),
            status=cast(str, payload["status"]),
            blocking_count=cast(int, payload["blocking_count"]),
            snapshot_hash=cast(str, payload["snapshot_hash"]),
            expires_at=datetime.fromisoformat(cast(str, payload["expires_at"])),
            replayed=replayed,
        )

    @staticmethod
    def _removed_result(payload: dict[str, object], *, replayed: bool) -> MemberRemoved:
        return MemberRemoved(
            scope=cast(str, payload["scope"]),
            membership_version=cast(int, payload["membership_version"]),
            removed_space_memberships=cast(int, payload["removed_space_memberships"]),
            security_version=cast(int, payload["security_version"]),
            revoked_session_count=cast(int, payload["revoked_session_count"]),
            revoked_project_memberships=cast(int, payload.get("revoked_project_memberships", 0)),
            revoked_resource_grants=cast(int, payload.get("revoked_resource_grants", 0)),
            changed_project_authorizations=cast(
                int, payload.get("changed_project_authorizations", 0)
            ),
            revoked_group_memberships=cast(int, payload.get("revoked_group_memberships", 0)),
            changed_group_project_authorizations=cast(
                int, payload.get("changed_group_project_authorizations", 0)
            ),
            replayed=replayed,
        )
