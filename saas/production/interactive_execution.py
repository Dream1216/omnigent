"""Conversation-store composition for managed interactive message admission."""

from __future__ import annotations

import asyncio
from typing import Any

from omnigent.entities import Conversation
from omnigent.errors import ErrorCode, OmnigentError
from omnigent.server.schemas import SessionEventInput
from saas.compatibility import current_runtime_context
from saas.control_plane.authorization import ProjectAuthorizationError
from saas.control_plane.execution import ExecutionControlPlaneError
from saas.control_plane.interactive_execution import (
    MANAGED_EXECUTION_SNAPSHOT_KEY,
    InteractiveExecutionError,
    RuntimeSessionRunAdmission,
)
from saas.control_plane.interactive_run_route import InteractiveRunRouteError
from saas.control_plane.tenant_model_catalog import TenantModelCatalogError


class InteractiveConversationStore:
    """Preserve official persistence and intercept only marked execution channels."""

    def __init__(self, delegate: Any, admission: RuntimeSessionRunAdmission) -> None:
        self._delegate = delegate
        self._admission = admission

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    @staticmethod
    def owns_session_input(conversation: Conversation) -> bool:
        return MANAGED_EXECUTION_SNAPSHOT_KEY in (conversation.inference_snapshot or {})

    async def dispatch_session_input(
        self,
        session_id: str,
        conversation: Conversation,
        event: SessionEventInput,
        *,
        created_by: str | None,
        input_policy_checked: bool,
    ) -> dict[str, bool | str] | None:
        if not self.owns_session_input(conversation) or event.type.startswith("external_"):
            return None
        if session_id != conversation.id or (event.type == "message" and not input_policy_checked):
            raise OmnigentError(
                "Interactive input requires policy admission", code=ErrorCode.FORBIDDEN
            )
        try:
            runtime = current_runtime_context()
        except RuntimeError:
            raise OmnigentError(
                "Interactive input requires an authenticated context", code=ErrorCode.FORBIDDEN
            ) from None
        try:
            return await asyncio.to_thread(
                self._admission.dispatch,
                runtime,
                conversation,
                event,
                created_by=created_by,
            )
        except (
            InteractiveExecutionError,
            InteractiveRunRouteError,
            ExecutionControlPlaneError,
            TenantModelCatalogError,
        ) as error:
            code = getattr(error, "code", "interactive_model_publication_unavailable")
            raise OmnigentError(code, code=ErrorCode.INVALID_INPUT) from None
        except ProjectAuthorizationError:
            raise OmnigentError(
                "Interactive execution is not accessible", code=ErrorCode.FORBIDDEN
            ) from None
