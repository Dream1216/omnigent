"""Resolve storage authority from real Sessions and fresh SaaS resource bindings."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

from omnigent.db.db_models import current_workspace_id
from omnigent.db.utils import NamedManagedSessionMaker
from omnigent.debug_logging import current_session_id
from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.permissions import check_session_access
from omnigent.stores import ConversationStore
from omnigent.stores.permission_store import PermissionStore
from saas.compatibility.runtime_partition import RuntimeContext, current_runtime_context
from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.production.aliyun_storage import (
    AliyunOssSession,
    AliyunOssStorageConfig,
    AliyunSessionVolumeManager,
    AliyunStorageError,
    AliyunVolumeControl,
)


class AliyunStorageSessionAuthorizer:
    def __init__(
        self,
        *,
        sessions: NamedManagedSessionMaker,
        resolver: SqlAlchemyContextResolver,
        conversations: ConversationStore,
        permissions: PermissionStore,
    ) -> None:
        self._sessions = sessions
        self._resolver = resolver
        self._conversations = conversations
        self._permissions = permissions

    def __call__(self, session_id: UUID) -> RuntimeContext:
        return self._authorize(session_id, project_action="run.create")

    def read(self, session_id: UUID) -> RuntimeContext:
        """Authorize existing output bytes without granting execution or Volume creation."""
        return self._authorize(session_id, project_action="run.read_content")

    def _authorize(self, session_id: UUID, *, project_action: str) -> RuntimeContext:
        try:
            return self._admit(session_id, project_action=project_action)
        except (ControlPlaneResolutionError, SQLAlchemyError):
            raise AliyunStorageError("Aliyun storage session authority is unavailable") from None

    def _admit(self, session_id: UUID, *, project_action: str) -> RuntimeContext:
        runtime = current_runtime_context()
        if (
            not isinstance(session_id, UUID)
            or session_id.int == 0
            or current_workspace_id() != runtime.physical_workspace_id
            or runtime.physical_workspace_id <= 0
        ):
            raise AliyunStorageError("Aliyun storage session scope is invalid")
        self._resolver.revalidate_runtime_scope(runtime, project_action=project_action)
        conversation = self._conversations.get_conversation(session_id.hex)
        if conversation is None or not check_session_access(
            runtime.runtime_user_key,
            session_id.hex,
            LEVEL_OWNER,
            self._permissions,
            self._conversations,
            conversation=conversation,
        ):
            raise AliyunStorageError("Aliyun storage session is unavailable")
        selectors = [
            sa.and_(
                RuntimeResourceBindingRecord.resource_type.in_(("session", "conversation")),
                sa.func.lower(RuntimeResourceBindingRecord.runtime_resource_id).in_(
                    (session_id.hex, str(session_id))
                ),
            )
        ]
        if conversation.project_id is not None:
            try:
                project = UUID(conversation.project_id)
            except (ValueError, TypeError, AttributeError):
                raise AliyunStorageError("Aliyun storage Project is invalid") from None
            selectors.append(
                sa.and_(
                    RuntimeResourceBindingRecord.resource_type == "project",
                    sa.func.lower(RuntimeResourceBindingRecord.runtime_resource_id).in_(
                        (project.hex, str(project))
                    ),
                )
            )
        with self._sessions("admit_session_mounts") as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=runtime.actor_id,
                    tenant_id=runtime.tenant_id,
                    space_id=runtime.space_id,
                    project_id=runtime.project_id,
                ),
            )
            # Binding inventory is Space-scoped. Include inactive rows so a
            # retired or moved resource cannot fall back to an unbound Session.
            rows = list(
                db.scalars(
                    sa.select(RuntimeResourceBindingRecord)
                    .where(
                        RuntimeResourceBindingRecord.tenant_id == runtime.tenant_id,
                        RuntimeResourceBindingRecord.space_id == runtime.space_id,
                        sa.or_(*selectors),
                    )
                    .limit(5)
                )
            )
            session_rows = [r for r in rows if r.resource_type != "project"]
            project_rows = [r for r in rows if r.resource_type == "project"]
            if len(session_rows) > 1 or len(project_rows) > 1:
                raise AliyunStorageError("Aliyun storage binding is ambiguous")
            if runtime.project_id is not None and not rows:
                raise AliyunStorageError("Aliyun storage Project binding is unavailable")
            effective_runtime = runtime
            if project_action == "run.read_content" and runtime.project_id is None and rows:
                projects = {row.project_id for row in rows}
                if len(projects) != 1:
                    raise AliyunStorageError("Aliyun storage Project binding is ambiguous")
                effective_runtime = replace(runtime, project_id=next(iter(projects)))
            bindings = [
                (row.resource_type, row.saas_resource_id, row.project_id)
                for row in rows
                if row.status == "active"
                and row.runtime_partition_id == runtime.runtime_partition_id
                and row.partition_generation == runtime.placement_generation
                and row.binding_generation >= 1
                and row.project_id == effective_runtime.project_id
                and (
                    row.resource_type != "project"
                    or row.saas_resource_id == effective_runtime.project_id
                )
            ]
            if len(bindings) != len(rows):
                raise AliyunStorageError("Aliyun storage binding scope changed")
        if effective_runtime != runtime:
            self._resolver.revalidate_runtime_scope(
                effective_runtime, project_action=project_action
            )
        request = replace(
            self._resolver.resolve_request_context(
                actor_id=runtime.actor_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                trace_id=runtime.trace_id,
            ),
            project_id=effective_runtime.project_id,
        )
        for kind, logical_id, _ in bindings:
            resolved = self._resolver.resolve_existing_resource(
                request,
                resource_type=kind,
                saas_resource_id=logical_id,
                action=project_action,
            )
            if (
                replace(resolved, binding_generation=runtime.binding_generation)
                != effective_runtime
            ):
                raise AliyunStorageError("Aliyun storage binding identity changed")
        if current_runtime_context() != runtime:
            raise AliyunStorageError("Aliyun storage runtime changed")
        return effective_runtime if project_action == "run.read_content" else runtime


class AliyunCurrentSessionStorage:
    """Select an admitted manager from the request context; never guess a Session."""

    def __init__(
        self,
        configs: tuple[AliyunOssStorageConfig, ...],
        control: AliyunVolumeControl,
        *,
        authorize: Callable[[UUID], RuntimeContext],
    ) -> None:
        if not configs or len({c.tenant_id for c in configs}) != len(configs):
            raise AliyunStorageError("Aliyun storage tenant allowlist is invalid")
        self._managers = {
            config.tenant_id: AliyunSessionVolumeManager(config, control, authorize=authorize)
            for config in configs
        }

    def _current(self) -> tuple[AliyunSessionVolumeManager, UUID]:
        runtime = current_runtime_context()
        manager = self._managers.get(runtime.tenant_id)
        hint = current_session_id()
        try:
            session_id = UUID(hint) if isinstance(hint, str) else None
        except ValueError:
            session_id = None
        if (
            manager is None
            or session_id is None
            or session_id.int == 0
            or hint not in (session_id.hex, str(session_id))
        ):
            raise AliyunStorageError("Aliyun storage requires an admitted Session")
        return manager, session_id

    def admit(self) -> AliyunOssSession:
        manager, session_id = self._current()
        return manager.admit(session_id)

    def ensure(self) -> AliyunOssSession:
        manager, session_id = self._current()
        return manager.ensure(session_id)
