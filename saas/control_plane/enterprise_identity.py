"""Convergent SCIM provisioning with replay and deprovision precedence."""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.db_models import (
    AuthSessionRecord,
    ControlPlaneOutboxEvent,
    GlobalUser,
    ProjectMembershipRecord,
    ResourceGrantRecord,
    SpaceMembership,
    TenantMembership,
)
from saas.control_plane.enterprise_identity_models import (
    EnterpriseScimDirectoryRecord,
    EnterpriseScimEventRecord,
    EnterpriseScimGroupRecord,
    EnterpriseScimUserRecord,
)
from saas.control_plane.enterprise_models import (
    EnterpriseGroupMembershipRecord,
    EnterpriseGroupRecord,
)
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import TENANT_ROLE_PERMISSIONS
from saas.control_plane.rls import RlsContext, apply_rls_context


@dataclass(frozen=True, slots=True)
class IssuedScimDirectory:
    id: UUID
    tenant_id: UUID
    display_name: str
    token_prefix: str
    status: str
    version: int
    bearer_token: str | None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ScimUserView:
    id: UUID
    directory_id: UUID
    tenant_id: UUID
    user_id: UUID | None
    external_id: str
    user_name: str
    display_name: str | None
    active: bool
    version: int
    source_version: int
    membership_status: str | None
    requires_owner_recovery: bool
    revoked_session_count: int
    disposition: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ScimGroupView:
    id: UUID
    directory_id: UUID
    tenant_id: UUID
    enterprise_group_id: UUID
    external_id: str
    display_name: str
    active: bool
    version: int
    source_version: int
    active_member_count: int
    member_scim_user_ids: tuple[UUID, ...]
    blocked_external_ids: tuple[str, ...]
    disposition: str
    replayed: bool = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash(payload: Mapping[str, object]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _clean(value: str, *, maximum: int, code: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise LifecycleError(code, "value is invalid")
    return cleaned


def _normalize_user_name(value: str) -> str:
    return _clean(value, maximum=320, code="scim_user_name_invalid").casefold()


def _integer(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise LifecycleError("scim_receipt_invalid", f"{key} is invalid")
    return value


def _require_fresh_auth(reauthenticated_at: datetime, now: datetime) -> None:
    authenticated = (
        reauthenticated_at
        if reauthenticated_at.tzinfo is not None
        else reauthenticated_at.replace(tzinfo=timezone.utc)
    )
    current = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    if authenticated > current or current - authenticated > timedelta(minutes=5):
        raise LifecycleError("fresh_auth_required", "recent authentication is required")


class EnterpriseScimService:
    """Own one-way SCIM convergence without treating email as identity proof."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def issue_directory(
        self,
        request: RequestContext,
        *,
        display_name: str,
        reauthenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedScimDirectory:
        issued_at = now or _utcnow()
        _require_fresh_auth(reauthenticated_at, issued_at)
        name = _clean(display_name, maximum=128, code="scim_directory_name_invalid")
        key = _clean(idempotency_key, maximum=128, code="invalid_idempotency_key")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "display_name": name,
        }
        request_hash = _hash(payload)
        receipt_key = f"scim-directory:{request.tenant_id}:{_digest(key)[:48]}"
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            self._require_manage(db, request)
            receipt = db.execute(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if receipt is not None:
                if receipt.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key has a different request"
                    )
                return self._issued_directory(receipt.payload, bearer_token=None, replayed=True)

            raw_token = f"omniscim_{secrets.token_urlsafe(8)}_{secrets.token_urlsafe(32)}"
            token_hash = _digest(raw_token)
            directory = EnterpriseScimDirectoryRecord(
                id=uuid4(),
                tenant_id=request.tenant_id,
                display_name=name,
                token_hash=token_hash,
                token_prefix=raw_token[:24],
                status="active",
                version=1,
                configured_by=request.actor_id,
            )
            db.add(directory)
            db.flush()
            result: dict[str, object] = {
                **payload,
                "directory_id": str(directory.id),
                "token_prefix": directory.token_prefix,
                "status": directory.status,
                "version": directory.version,
            }
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=request.tenant_id,
                    aggregate_type="enterprise_scim_directory",
                    aggregate_key=str(directory.id),
                    event_type="enterprise.scim_directory.issued",
                    payload=result,
                    idempotency_key=receipt_key,
                    request_hash=request_hash,
                )
            )
            return self._issued_directory(result, bearer_token=raw_token, replayed=False)

    def upsert_user(
        self,
        bearer_token: str,
        *,
        event_id: str,
        external_id: str,
        user_name: str,
        display_name: str | None,
        active: bool,
        source_version: int,
    ) -> ScimUserView:
        event_key = _clean(event_id, maximum=256, code="scim_event_id_invalid")
        external = _clean(external_id, maximum=256, code="scim_external_id_invalid")
        normalized = _normalize_user_name(user_name)
        shown_name = (
            _clean(display_name, maximum=256, code="scim_display_name_invalid")
            if display_name is not None
            else None
        )
        if source_version < 1:
            raise LifecycleError("scim_source_version_invalid", "source version is invalid")
        payload: dict[str, object] = {
            "resource_type": "User",
            "external_id": external,
            "user_name": normalized,
            "display_name": shown_name,
            "active": active,
            "source_version": source_version,
        }
        request_hash = _hash(payload)
        state_hash = _hash(
            {key: value for key, value in payload.items() if key != "resource_type"}
        )
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            replay = self._event_replay(db, directory.id, event_key, request_hash)
            if replay is not None:
                return self._user_result(replay.result, replayed=True)

            user = db.execute(
                sa.select(EnterpriseScimUserRecord)
                .where(
                    EnterpriseScimUserRecord.directory_id == directory.id,
                    EnterpriseScimUserRecord.external_id == external,
                )
                .with_for_update()
            ).scalar_one_or_none()
            now = _utcnow()
            if user is not None and source_version < user.source_version:
                result = self._user_payload(
                    db,
                    user,
                    disposition="stale",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "User",
                    user.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._user_result(result)
            if user is not None and source_version == user.source_version:
                if state_hash != user.source_state_hash:
                    raise LifecycleError(
                        "scim_version_conflict",
                        "source version already represents a different User state",
                    )
                result = self._user_payload(
                    db,
                    user,
                    disposition="stale",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "User",
                    user.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._user_result(result)

            if user is None:
                global_user = (
                    self._create_global_user(db, normalized, shown_name) if active else None
                )
                if global_user is not None:
                    db.add(
                        TenantMembership(
                            tenant_id=directory.tenant_id,
                            user_id=global_user.id,
                            role="member",
                            status="active",
                            version=1,
                            joined_at=now,
                        )
                    )
                user = EnterpriseScimUserRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    directory_id=directory.id,
                    external_id=external,
                    user_id=global_user.id if global_user else None,
                    user_name_normalized=normalized,
                    display_name=shown_name,
                    active=active,
                    version=1,
                    source_version=source_version,
                    source_state_hash=state_hash,
                    deprovisioned_at=None if active else now,
                )
                db.add(user)
                db.flush()
                result = self._user_payload(
                    db,
                    user,
                    disposition="applied",
                    requires_owner_recovery=False,
                    revoked_session_count=0,
                )
            else:
                revoked_sessions = 0
                owner_recovery = False
                user.user_name_normalized = normalized
                user.display_name = shown_name
                user.source_version = source_version
                user.source_state_hash = state_hash
                user.version += 1
                if active:
                    if user.user_id is None:
                        user.user_id = self._create_global_user(db, normalized, shown_name).id
                    membership = db.get(TenantMembership, (directory.tenant_id, user.user_id))
                    if membership is None:
                        db.add(
                            TenantMembership(
                                tenant_id=directory.tenant_id,
                                user_id=user.user_id,
                                role="member",
                                status="active",
                                version=1,
                                joined_at=now,
                            )
                        )
                    else:
                        membership.status = "active"
                        membership.version += 1
                        membership.joined_at = membership.joined_at or now
                    user.active = True
                    user.deprovisioned_at = None
                else:
                    user.active = False
                    user.deprovisioned_at = now
                    if user.user_id is not None:
                        owner_recovery, revoked_sessions = self._deprovision_user(
                            db, directory.tenant_id, user.user_id, now
                        )
                db.flush()
                result = self._user_payload(
                    db,
                    user,
                    disposition="blocked" if owner_recovery else "applied",
                    requires_owner_recovery=owner_recovery,
                    revoked_session_count=revoked_sessions,
                )
            disposition = str(result["disposition"])
            self._record_event(
                db,
                directory,
                event_key,
                request_hash,
                "User",
                user.id,
                source_version,
                disposition,
                result,
            )
            return self._user_result(result)

    def get_user(self, bearer_token: str, *, scim_user_id: UUID) -> ScimUserView:
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            user = db.execute(
                sa.select(EnterpriseScimUserRecord).where(
                    EnterpriseScimUserRecord.directory_id == directory.id,
                    EnterpriseScimUserRecord.id == scim_user_id,
                )
            ).scalar_one_or_none()
            if user is None:
                raise LifecycleError("scim_resource_not_found", "SCIM User was not found")
            membership = (
                db.get(TenantMembership, (directory.tenant_id, user.user_id))
                if user.user_id is not None
                else None
            )
            result = self._user_payload(
                db,
                user,
                disposition="applied",
                requires_owner_recovery=bool(
                    not user.active
                    and membership is not None
                    and membership.role == "owner"
                    and membership.status == "suspended"
                ),
                revoked_session_count=0,
            )
            return self._user_result(result)

    def sync_group(
        self,
        bearer_token: str,
        *,
        event_id: str,
        external_id: str,
        display_name: str,
        member_external_ids: list[str],
        active: bool,
        source_version: int,
    ) -> ScimGroupView:
        event_key = _clean(event_id, maximum=256, code="scim_event_id_invalid")
        external = _clean(external_id, maximum=256, code="scim_external_id_invalid")
        name = _clean(display_name, maximum=128, code="scim_group_name_invalid")
        if source_version < 1:
            raise LifecycleError("scim_source_version_invalid", "source version is invalid")
        if len(member_external_ids) > 1000:
            raise LifecycleError("scim_group_members_invalid", "too many group members")
        members = tuple(
            sorted(
                {
                    _clean(item, maximum=256, code="scim_external_id_invalid")
                    for item in member_external_ids
                }
            )
        )
        payload: dict[str, object] = {
            "resource_type": "Group",
            "external_id": external,
            "display_name": name,
            "members": list(members),
            "active": active,
            "source_version": source_version,
        }
        request_hash = _hash(payload)
        state_hash = _hash(
            {key: value for key, value in payload.items() if key != "resource_type"}
        )
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            replay = self._event_replay(db, directory.id, event_key, request_hash)
            if replay is not None:
                return self._group_result(replay.result, replayed=True)
            group = db.execute(
                sa.select(EnterpriseScimGroupRecord)
                .where(
                    EnterpriseScimGroupRecord.directory_id == directory.id,
                    EnterpriseScimGroupRecord.external_id == external,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if group is not None and source_version < group.source_version:
                result = self._group_payload(db, group, (), "stale")
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "Group",
                    group.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._group_result(result)
            if group is not None and source_version == group.source_version:
                if state_hash != group.source_state_hash:
                    raise LifecycleError(
                        "scim_version_conflict",
                        "source version already represents a different Group state",
                    )
                result = self._group_payload(db, group, (), "stale")
                self._record_event(
                    db,
                    directory,
                    event_key,
                    request_hash,
                    "Group",
                    group.id,
                    source_version,
                    "stale",
                    result,
                )
                return self._group_result(result)

            if group is None:
                enterprise_group = EnterpriseGroupRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    name=name,
                    description="Managed by SCIM",
                    status="active" if active else "archived",
                    version=1,
                    created_by=directory.configured_by,
                    archived_at=None if active else _utcnow(),
                    archived_by=None if active else directory.configured_by,
                    archive_reason=None if active else "SCIM Group disabled",
                )
                db.add(enterprise_group)
                db.flush()
                group = EnterpriseScimGroupRecord(
                    id=uuid4(),
                    tenant_id=directory.tenant_id,
                    directory_id=directory.id,
                    external_id=external,
                    enterprise_group_id=enterprise_group.id,
                    display_name=name,
                    active=active,
                    version=1,
                    source_version=source_version,
                    source_state_hash=state_hash,
                )
                db.add(group)
                db.flush()
            else:
                enterprise_group = db.get(EnterpriseGroupRecord, group.enterprise_group_id)
                if enterprise_group is None:
                    raise LifecycleError("scim_group_not_found", "SCIM Group mapping is invalid")
                group.display_name = name
                group.active = active
                group.version += 1
                group.source_version = source_version
                group.source_state_hash = state_hash
                enterprise_group.name = name
                enterprise_group.version += 1
                if active:
                    enterprise_group.status = "active"
                    enterprise_group.archived_at = None
                    enterprise_group.archived_by = None
                    enterprise_group.archive_reason = None
                else:
                    enterprise_group.status = "archived"
                    enterprise_group.archived_at = _utcnow()
                    enterprise_group.archived_by = directory.configured_by
                    enterprise_group.archive_reason = "SCIM Group disabled"

            blocked = self._converge_group_members(
                db,
                directory=directory,
                group=group,
                desired_external_ids=members if active else (),
            )
            db.flush()
            result = self._group_payload(db, group, blocked, "blocked" if blocked else "applied")
            disposition = str(result["disposition"])
            self._record_event(
                db,
                directory,
                event_key,
                request_hash,
                "Group",
                group.id,
                source_version,
                disposition,
                result,
            )
            return self._group_result(result)

    def get_group(self, bearer_token: str, *, scim_group_id: UUID) -> ScimGroupView:
        with self._session_factory.begin() as db:
            directory = self._authenticate(db, bearer_token)
            group = db.execute(
                sa.select(EnterpriseScimGroupRecord).where(
                    EnterpriseScimGroupRecord.directory_id == directory.id,
                    EnterpriseScimGroupRecord.id == scim_group_id,
                )
            ).scalar_one_or_none()
            if group is None:
                raise LifecycleError("scim_resource_not_found", "SCIM Group was not found")
            return self._group_result(self._group_payload(db, group, (), "applied"))

    def _authenticate(self, db: Session, bearer_token: str) -> EnterpriseScimDirectoryRecord:
        token = _clean(bearer_token, maximum=256, code="scim_authentication_failed")
        token_hash = _digest(token)
        apply_rls_context(db, RlsContext(scim_token_hash=token_hash))
        directory = db.execute(
            sa.select(EnterpriseScimDirectoryRecord).where(
                EnterpriseScimDirectoryRecord.token_hash == token_hash,
                EnterpriseScimDirectoryRecord.status == "active",
            )
        ).scalar_one_or_none()
        if directory is None:
            raise LifecycleError("scim_authentication_failed", "SCIM credential is invalid")
        apply_rls_context(
            db,
            RlsContext(tenant_id=directory.tenant_id, scim_token_hash=token_hash),
        )
        return directory

    @staticmethod
    def _apply_request_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            ),
        )

    @staticmethod
    def _require_manage(db: Session, request: RequestContext) -> None:
        membership = db.get(TenantMembership, (request.tenant_id, request.actor_id))
        if (
            membership is None
            or membership.status != "active"
            or "enterprise_identity.manage" not in TENANT_ROLE_PERMISSIONS[membership.role]
        ):
            raise LifecycleError(
                "enterprise_identity_manage_forbidden",
                "enterprise identity management permission is required",
            )

    @staticmethod
    def _create_global_user(db: Session, user_name: str, display_name: str | None) -> GlobalUser:
        user = GlobalUser(
            id=uuid4(),
            status="active",
            display_name=display_name,
            primary_email_normalized=user_name if "@" in user_name else None,
            security_version=1,
        )
        db.add(user)
        db.flush()
        return user

    @staticmethod
    def _deprovision_user(
        db: Session, tenant_id: UUID, user_id: UUID, now: datetime
    ) -> tuple[bool, int]:
        membership = db.get(TenantMembership, (tenant_id, user_id))
        requires_owner_recovery = membership is not None and membership.role == "owner"
        if membership is not None:
            membership.status = "suspended" if requires_owner_recovery else "removed"
            membership.version += 1
        db.execute(
            sa.update(SpaceMembership)
            .where(
                SpaceMembership.tenant_id == tenant_id,
                SpaceMembership.user_id == user_id,
                SpaceMembership.status != "removed",
            )
            .values(status="removed", version=SpaceMembership.version + 1)
        )
        db.execute(
            sa.update(ProjectMembershipRecord)
            .where(
                ProjectMembershipRecord.tenant_id == tenant_id,
                ProjectMembershipRecord.subject_type == "user",
                ProjectMembershipRecord.subject_id == user_id,
                ProjectMembershipRecord.status != "revoked",
            )
            .values(status="revoked", version=ProjectMembershipRecord.version + 1)
        )
        db.execute(
            sa.update(ResourceGrantRecord)
            .where(
                ResourceGrantRecord.tenant_id == tenant_id,
                ResourceGrantRecord.subject_type == "user",
                ResourceGrantRecord.subject_id == user_id,
                ResourceGrantRecord.status == "active",
            )
            .values(status="revoked", version=ResourceGrantRecord.version + 1)
        )
        db.execute(
            sa.update(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == tenant_id,
                EnterpriseGroupMembershipRecord.user_id == user_id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
            .values(status="removed", version=EnterpriseGroupMembershipRecord.version + 1)
        )
        revoked = cast(
            CursorResult[tuple[object]],
            db.execute(
                sa.update(AuthSessionRecord)
                .where(
                    AuthSessionRecord.user_id == user_id,
                    AuthSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            ),
        ).rowcount
        global_user = db.get(GlobalUser, user_id)
        if global_user is not None:
            global_user.security_version += 1
        return requires_owner_recovery, int(revoked or 0)

    @staticmethod
    def _converge_group_members(
        db: Session,
        *,
        directory: EnterpriseScimDirectoryRecord,
        group: EnterpriseScimGroupRecord,
        desired_external_ids: tuple[str, ...],
    ) -> tuple[str, ...]:
        users = db.execute(
            sa.select(EnterpriseScimUserRecord).where(
                EnterpriseScimUserRecord.directory_id == directory.id,
                EnterpriseScimUserRecord.external_id.in_(desired_external_ids or ("",)),
            )
        ).scalars()
        by_external = {user.external_id: user for user in users}
        desired_user_ids: set[UUID] = set()
        blocked: list[str] = []
        for external_id in desired_external_ids:
            user = by_external.get(external_id)
            if user is None or not user.active or user.user_id is None:
                blocked.append(external_id)
            else:
                desired_user_ids.add(user.user_id)

        existing = {
            membership.user_id: membership
            for membership in db.execute(
                sa.select(EnterpriseGroupMembershipRecord).where(
                    EnterpriseGroupMembershipRecord.tenant_id == directory.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                )
            ).scalars()
        }
        for user_id, membership in existing.items():
            if user_id not in desired_user_ids and membership.status == "active":
                membership.status = "removed"
                membership.version += 1
        for user_id in desired_user_ids:
            membership = existing.get(user_id)
            if membership is None:
                db.add(
                    EnterpriseGroupMembershipRecord(
                        tenant_id=directory.tenant_id,
                        group_id=group.enterprise_group_id,
                        user_id=user_id,
                        status="active",
                        version=1,
                        created_by=directory.configured_by,
                    )
                )
            elif membership.status != "active":
                membership.status = "active"
                membership.version += 1
        return tuple(blocked)

    @staticmethod
    def _event_replay(
        db: Session, directory_id: UUID, event_id: str, request_hash: str
    ) -> EnterpriseScimEventRecord | None:
        event = db.execute(
            sa.select(EnterpriseScimEventRecord).where(
                EnterpriseScimEventRecord.directory_id == directory_id,
                EnterpriseScimEventRecord.event_id == event_id,
            )
        ).scalar_one_or_none()
        if event is not None and event.request_hash != request_hash:
            raise LifecycleError("scim_event_conflict", "SCIM event ID has a different request")
        return event

    @staticmethod
    def _record_event(
        db: Session,
        directory: EnterpriseScimDirectoryRecord,
        event_id: str,
        request_hash: str,
        resource_type: str,
        resource_id: UUID,
        source_version: int,
        disposition: str,
        result: dict[str, object],
    ) -> None:
        db.add(
            EnterpriseScimEventRecord(
                id=uuid4(),
                tenant_id=directory.tenant_id,
                directory_id=directory.id,
                event_id=event_id,
                resource_type=resource_type,
                resource_id=resource_id,
                source_version=source_version,
                request_hash=request_hash,
                disposition=disposition,
                result=result,
            )
        )
        db.add(
            ControlPlaneOutboxEvent(
                id=uuid4(),
                tenant_id=directory.tenant_id,
                aggregate_type=f"enterprise_scim_{resource_type.casefold()}",
                aggregate_key=str(resource_id),
                event_type=f"enterprise.scim_{resource_type.casefold()}.{disposition}",
                payload={
                    "directory_id": str(directory.id),
                    "resource_id": str(resource_id),
                    "resource_type": resource_type,
                    "source_version": source_version,
                    "disposition": disposition,
                },
                idempotency_key=f"scim:{directory.id}:{_digest(event_id)[:48]}",
                request_hash=request_hash,
            )
        )

    @staticmethod
    def _issued_directory(
        payload: dict[str, object], *, bearer_token: str | None, replayed: bool
    ) -> IssuedScimDirectory:
        return IssuedScimDirectory(
            id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            display_name=str(payload["display_name"]),
            token_prefix=str(payload["token_prefix"]),
            status=str(payload["status"]),
            version=_integer(payload, "version"),
            bearer_token=bearer_token,
            replayed=replayed,
        )

    @staticmethod
    def _user_payload(
        db: Session,
        user: EnterpriseScimUserRecord,
        *,
        disposition: str,
        requires_owner_recovery: bool,
        revoked_session_count: int,
    ) -> dict[str, object]:
        membership = (
            db.get(TenantMembership, (user.tenant_id, user.user_id))
            if user.user_id is not None
            else None
        )
        return {
            "scim_user_id": str(user.id),
            "directory_id": str(user.directory_id),
            "tenant_id": str(user.tenant_id),
            "user_id": str(user.user_id) if user.user_id else None,
            "external_id": user.external_id,
            "user_name": user.user_name_normalized,
            "display_name": user.display_name,
            "active": user.active,
            "version": user.version,
            "source_version": user.source_version,
            "membership_status": membership.status if membership else None,
            "requires_owner_recovery": requires_owner_recovery,
            "revoked_session_count": revoked_session_count,
            "disposition": disposition,
        }

    @staticmethod
    def _user_result(payload: dict[str, object], replayed: bool = False) -> ScimUserView:
        return ScimUserView(
            id=UUID(str(payload["scim_user_id"])),
            directory_id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            user_id=UUID(str(payload["user_id"])) if payload.get("user_id") else None,
            external_id=str(payload["external_id"]),
            user_name=str(payload["user_name"]),
            display_name=(
                str(payload["display_name"]) if payload.get("display_name") is not None else None
            ),
            active=bool(payload["active"]),
            version=_integer(payload, "version"),
            source_version=_integer(payload, "source_version"),
            membership_status=(
                str(payload["membership_status"])
                if payload.get("membership_status") is not None
                else None
            ),
            requires_owner_recovery=bool(payload["requires_owner_recovery"]),
            revoked_session_count=_integer(payload, "revoked_session_count"),
            disposition=str(payload["disposition"]),
            replayed=replayed,
        )

    @staticmethod
    def _group_payload(
        db: Session,
        group: EnterpriseScimGroupRecord,
        blocked: tuple[str, ...],
        disposition: str,
    ) -> dict[str, object]:
        active_count = db.scalar(
            sa.select(sa.func.count())
            .select_from(EnterpriseGroupMembershipRecord)
            .where(
                EnterpriseGroupMembershipRecord.tenant_id == group.tenant_id,
                EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                EnterpriseGroupMembershipRecord.status == "active",
            )
        )
        member_scim_user_ids = tuple(
            db.scalars(
                sa.select(EnterpriseScimUserRecord.id)
                .join(
                    EnterpriseGroupMembershipRecord,
                    sa.and_(
                        EnterpriseGroupMembershipRecord.tenant_id
                        == EnterpriseScimUserRecord.tenant_id,
                        EnterpriseGroupMembershipRecord.user_id
                        == EnterpriseScimUserRecord.user_id,
                    ),
                )
                .where(
                    EnterpriseGroupMembershipRecord.tenant_id == group.tenant_id,
                    EnterpriseGroupMembershipRecord.group_id == group.enterprise_group_id,
                    EnterpriseGroupMembershipRecord.status == "active",
                    EnterpriseScimUserRecord.directory_id == group.directory_id,
                    EnterpriseScimUserRecord.active.is_(True),
                )
                .order_by(EnterpriseScimUserRecord.id)
            )
        )
        return {
            "scim_group_id": str(group.id),
            "directory_id": str(group.directory_id),
            "tenant_id": str(group.tenant_id),
            "enterprise_group_id": str(group.enterprise_group_id),
            "external_id": group.external_id,
            "display_name": group.display_name,
            "active": group.active,
            "version": group.version,
            "source_version": group.source_version,
            "active_member_count": int(active_count or 0),
            "member_scim_user_ids": [str(item) for item in member_scim_user_ids],
            "blocked_external_ids": list(blocked),
            "disposition": disposition,
        }

    @staticmethod
    def _group_result(payload: dict[str, object], replayed: bool = False) -> ScimGroupView:
        raw_blocked = payload.get("blocked_external_ids")
        blocked = tuple(str(item) for item in raw_blocked) if isinstance(raw_blocked, list) else ()
        raw_members = payload.get("member_scim_user_ids")
        member_ids = (
            tuple(UUID(str(item)) for item in raw_members) if isinstance(raw_members, list) else ()
        )
        return ScimGroupView(
            id=UUID(str(payload["scim_group_id"])),
            directory_id=UUID(str(payload["directory_id"])),
            tenant_id=UUID(str(payload["tenant_id"])),
            enterprise_group_id=UUID(str(payload["enterprise_group_id"])),
            external_id=str(payload["external_id"]),
            display_name=str(payload["display_name"]),
            active=bool(payload["active"]),
            version=_integer(payload, "version"),
            source_version=_integer(payload, "source_version"),
            active_member_count=_integer(payload, "active_member_count"),
            member_scim_user_ids=member_ids,
            blocked_external_ids=blocked,
            disposition=str(payload["disposition"]),
            replayed=replayed,
        )
