"""Project-aware member-removal impact collection for the P2 control plane."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ProjectMembershipRecord, ResourceGrantRecord
from saas.control_plane.governance import RemovalImpact
from saas.control_plane.rls import RlsContext, apply_rls_context


class ProjectRemovalImpactProvider:
    """Report Project ownership blockers and access that removal will revoke."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        checked_at = datetime.now(timezone.utc)
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(actor_id=user_id, tenant_id=tenant_id, space_id=space_id),
            )
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
                db.execute(sa.select(ProjectMembershipRecord).where(*membership_filters)).scalars()
            )
            grants = list(
                db.execute(sa.select(ResourceGrantRecord).where(*grant_filters)).scalars()
            )
        owned_projects = sorted(
            str(membership.project_id)
            for membership in memberships
            if membership.role == "owner"
            and (
                membership.expires_at is None
                or self._comparable(membership.expires_at) > checked_at
            )
        )
        facts: dict[str, object] = {
            "owned_project_ids": owned_projects,
            "project_memberships": sorted(
                f"{membership.project_id}:{membership.role}" for membership in memberships
            ),
            "resource_grant_ids": sorted(str(grant.id) for grant in grants),
        }
        return RemovalImpact(facts=facts, blocking_count=len(owned_projects))

    @staticmethod
    def _comparable(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
