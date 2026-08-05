"""Project-aware member-removal impact collection for the P2 control plane."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.db_models import ProjectMembershipRecord, ResourceGrantRecord
from saas.control_plane.execution_models import TERMINAL_RUN_STATUSES, RunRecord
from saas.control_plane.governance import RemovalImpact, RemovalImpactProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.worktree_models import (
    ACTIVE_WORKTREE_STATUSES,
    ChangeSetRecord,
    WorktreeInstanceRecord,
)


class CompositeRemovalImpactProvider:
    """Collect every configured resource domain into one stable snapshot."""

    def __init__(
        self,
        providers: Mapping[str, RemovalImpactProvider],
        *,
        required_domains: frozenset[str] = frozenset(),
    ) -> None:
        cleaned = {name.strip(): provider for name, provider in providers.items() if name.strip()}
        if len(cleaned) != len(providers):
            raise ValueError("removal impact domain names must be non-empty and unique")
        missing = required_domains - cleaned.keys()
        if missing:
            raise LifecycleError(
                "removal_impact_provider_unavailable",
                f"member removal impact domains are not wired: {', '.join(sorted(missing))}",
            )
        self._providers = tuple(sorted(cleaned.items()))

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        facts: dict[str, object] = {}
        blocking_count = 0
        for domain, provider in self._providers:
            impact = provider.collect(
                tenant_id=tenant_id,
                space_id=space_id,
                user_id=user_id,
            )
            impact.validate()
            facts[domain] = impact.facts
            blocking_count += impact.blocking_count
        return RemovalImpact(facts=facts, blocking_count=blocking_count)


class ExecutionRemovalImpactProvider:
    """Block member removal while their non-terminal Runs still exist."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(actor_id=user_id, tenant_id=tenant_id, space_id=space_id),
            )
            filters = [
                RunRecord.tenant_id == tenant_id,
                RunRecord.created_by == user_id,
                RunRecord.status.not_in(TERMINAL_RUN_STATUSES),
            ]
            if space_id is not None:
                filters.append(RunRecord.space_id == space_id)
            runs = tuple(
                db.execute(
                    sa.select(RunRecord.id, RunRecord.status)
                    .where(*filters)
                    .order_by(RunRecord.id)
                ).all()
            )
        facts: dict[str, object] = {
            "active_runs": [{"run_id": str(run_id), "status": status} for run_id, status in runs]
        }
        return RemovalImpact(facts=facts, blocking_count=len(runs))


class WorktreeRemovalImpactProvider:
    """Block removal while the member owns open changes or retained Worktree state."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(actor_id=user_id, tenant_id=tenant_id, space_id=space_id),
            )
            change_filters = [
                ChangeSetRecord.tenant_id == tenant_id,
                ChangeSetRecord.created_by == user_id,
                ChangeSetRecord.status.in_({"open", "checkpointed", "quarantined"}),
            ]
            worktree_filters = [
                WorktreeInstanceRecord.tenant_id == tenant_id,
                WorktreeInstanceRecord.created_by == user_id,
                WorktreeInstanceRecord.status.in_(
                    ACTIVE_WORKTREE_STATUSES | {"rebuild_pending", "quarantined"}
                ),
            ]
            if space_id is not None:
                change_filters.append(ChangeSetRecord.space_id == space_id)
                worktree_filters.append(WorktreeInstanceRecord.space_id == space_id)
            change_sets = tuple(
                db.execute(
                    sa.select(ChangeSetRecord.id, ChangeSetRecord.status)
                    .where(*change_filters)
                    .order_by(ChangeSetRecord.id)
                ).all()
            )
            worktrees = tuple(
                db.execute(
                    sa.select(
                        WorktreeInstanceRecord.id,
                        WorktreeInstanceRecord.change_set_id,
                        WorktreeInstanceRecord.status,
                        WorktreeInstanceRecord.dirty,
                    )
                    .where(*worktree_filters)
                    .order_by(WorktreeInstanceRecord.id)
                ).all()
            )
        facts: dict[str, object] = {
            "open_change_sets": [
                {"change_set_id": str(change_set_id), "status": status}
                for change_set_id, status in change_sets
            ],
            "retained_worktrees": [
                {
                    "worktree_id": str(worktree_id),
                    "change_set_id": str(change_set_id),
                    "status": status,
                    "dirty": dirty,
                }
                for worktree_id, change_set_id, status, dirty in worktrees
            ],
        }
        return RemovalImpact(
            facts=facts,
            blocking_count=len(change_sets) + len(worktrees),
        )


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


class ServiceAccountRemovalImpactProvider:
    """Block removal until explicit Service Account stewardship is transferred."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def collect(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        user_id: UUID,
    ) -> RemovalImpact:
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(actor_id=user_id, tenant_id=tenant_id, space_id=space_id),
            )
            filters = [
                ServiceAccountRecord.tenant_id == tenant_id,
                ServiceAccountRecord.steward_user_id == user_id,
                ServiceAccountRecord.status.in_(("active", "suspended")),
            ]
            if space_id is not None:
                filters.append(ServiceAccountRecord.space_id == space_id)
            accounts = tuple(
                db.execute(
                    sa.select(ServiceAccountRecord).where(*filters).order_by(ServiceAccountRecord.id)
                ).scalars()
            )
            account_ids = [account.id for account in accounts]
            credential_rows = (
                tuple(
                    db.execute(
                        sa.select(
                            ApiCredentialRecord.id,
                            ApiCredentialRecord.service_account_id,
                            ApiCredentialRecord.status,
                            ApiCredentialRecord.expires_at,
                        )
                        .where(
                            ApiCredentialRecord.tenant_id == tenant_id,
                            ApiCredentialRecord.service_account_id.in_(account_ids),
                        )
                        .order_by(ApiCredentialRecord.service_account_id, ApiCredentialRecord.id)
                    ).all()
                )
                if account_ids
                else ()
            )
        credentials_by_account: dict[UUID, list[dict[str, object]]] = {
            account_id: [] for account_id in account_ids
        }
        for credential_id, account_id, status, expires_at in credential_rows:
            credentials_by_account[account_id].append(
                {
                    "credential_id": str(credential_id),
                    "status": status,
                    "expires_at": self._comparable(expires_at).isoformat(),
                }
            )
        facts: dict[str, object] = {
            "stewarded_service_accounts": [
                {
                    "service_account_id": str(account.id),
                    "space_id": str(account.space_id) if account.space_id else None,
                    "project_id": str(account.project_id) if account.project_id else None,
                    "status": account.status,
                    "credentials": credentials_by_account[account.id],
                }
                for account in accounts
            ]
        }
        return RemovalImpact(facts=facts, blocking_count=len(accounts))

    @staticmethod
    def _comparable(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
