"""Conversation-store composition for managed interactive message admission."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from fastapi import Request

from omnigent.db.db_models import uuid_to_bytes
from omnigent.entities import Conversation
from omnigent.errors import ErrorCode, OmnigentError
from omnigent.harness_aliases import canonicalize_harness
from omnigent.harness_availability import harness_launch_availability
from omnigent.server.auth import LEVEL_EDIT, LEVEL_OWNER
from omnigent.server.routes._auth_helpers import require_access_and_level
from omnigent.server.routes.sandbox_inference import actual_harness
from omnigent.server.schemas import SessionEventInput
from omnigent.stores.conversation_store import ConversationAlreadyExistsError
from saas.compatibility import current_runtime_context
from saas.control_plane.authorization import ProjectAuthorizationError
from saas.control_plane.execution import ExecutionControlPlaneError
from saas.control_plane.interactive_execution import (
    MANAGED_EXECUTION_SNAPSHOT_KEY,
    InteractiveExecutionError,
    RuntimeSessionRunAdmission,
)
from saas.control_plane.interactive_launch import (
    MANAGED_LAUNCH_SNAPSHOT_KEY,
    decode_interactive_launch,
)
from saas.control_plane.interactive_run_route import (
    InteractiveRunRouteError,
    interactive_session_identity,
)
from saas.control_plane.tenant_model_catalog import TenantModelCatalogError
from saas.production.interactive_model_channel import model_channel_configuration
from saas.production.runner_control import RunnerControlError

if TYPE_CHECKING:
    from saas.production.tenant_model_catalog import ModelSelectionTarget


class InteractiveConversationStore:
    """Preserve official persistence and intercept only marked execution channels."""

    def __init__(
        self,
        delegate: Any,
        admission: RuntimeSessionRunAdmission,
        *,
        permission_store: Any,
        agent_cache: Any = None,
        public_origin: str | None = None,
        runtime_enabled: bool = False,
    ) -> None:
        self._delegate = delegate
        self._admission = admission
        self._permissions = permission_store
        self._agent_cache = agent_cache
        self._public_origin = public_origin
        self._runtime_enabled = runtime_enabled
        self.runtime_status_observer = None
        self.session_stop_handler = None
        self.runtime_readiness_check: Callable[[], None] | None = None

    async def preview_model_selection(
        self,
        request: Request,
        models: list[dict[str, Any]],
        target: ModelSelectionTarget,
        *,
        check_pricing: Callable[[UUID], None] | None,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Explain selection readiness, never authorize a Run or provision a target."""
        runtime = current_runtime_context()

        def unavailable(reason: str) -> tuple[list[dict[str, Any]], bool]:
            return [
                {**model, "available": False, "unavailable_reason": reason} for model in models
            ], self._runtime_enabled

        if not self._runtime_enabled:
            return unavailable("runtime_not_enabled")
        if self.runtime_readiness_check is None:
            return unavailable("runtime_unavailable")
        try:
            await asyncio.to_thread(self.runtime_readiness_check)
        except Exception:  # noqa: BLE001 - controller details are not customer metadata.
            return unavailable("runtime_unavailable")
        if not target.project_id:
            return unavailable("project_required")
        try:
            await asyncio.to_thread(
                self._admission.require_selection_project, runtime, target.project_id
            )
        except (InteractiveExecutionError, ProjectAuthorizationError):
            return unavailable("project_not_accessible")
        state = request.app.state
        agent = await asyncio.to_thread(state.agent_store.get, target.agent_id)
        if agent is None or self._agent_cache is None:
            return unavailable("model_harness_unsupported")
        if agent.session_id:
            try:
                await require_access_and_level(
                    runtime.runtime_user_key,
                    agent.session_id,
                    LEVEL_EDIT,
                    self._permissions,
                    self._delegate,
                )
            except OmnigentError:
                return unavailable("model_harness_unsupported")
        try:
            spec = (
                await asyncio.to_thread(
                    self._agent_cache.load,
                    agent.id,
                    agent.bundle_location,
                    expand_env=agent.session_id is None,
                )
            ).spec
        except (KeyError, ValueError):
            return unavailable("model_harness_unsupported")
        harness = canonicalize_harness(actual_harness(spec, target.harness))
        if spec.executor.auth is not None or spec.executor.profile or harness == "auto":
            return unavailable("model_harness_unsupported")
        if target.host_type == "external":
            host = await asyncio.to_thread(state.host_store.get_host, target.host_id)
            connection = state.host_registry.get(host.host_id) if host is not None else None
            if (
                host is None
                or host.user_id != runtime.runtime_user_key
                or connection is None
                or connection.owner != runtime.runtime_user_key
            ):
                return unavailable("host_unavailable")
            ready, reason = harness_launch_availability(harness, host.configured_harnesses)
            if ready is not True and reason != "needs-auth":
                return unavailable("host_unavailable")
        else:
            deployment = getattr(state, "sandbox_config", None)
            configured = deployment.for_provider(target.sandbox_provider) if deployment else None
            if (
                configured is None
                or not configured.managed_launch_supported
                or configured.provider not in {"kubernetes", "agent_sandbox"}
                or harness != "openai-agents"
            ):
                # Native harnesses need a target-specific binary/readiness proof.
                return unavailable("sandbox_unavailable")
        if check_pricing is None:
            return unavailable("pricing_unavailable")
        from saas.control_plane.billing_metering import BillingMeteringError

        try:
            await asyncio.to_thread(check_pricing, runtime.tenant_id)
        except BillingMeteringError:
            return unavailable("pricing_unavailable")
        return [
            {
                **model,
                "available": self._supports_model_harness(model["wire_api"], harness),
                "unavailable_reason": None
                if self._supports_model_harness(model["wire_api"], harness)
                else "model_harness_unsupported",
            }
            for model in models
        ], True

    @staticmethod
    def _supports_model_harness(wire_api: object, harness: str | None) -> bool:
        if wire_api == "openai_responses":
            return harness in {"codex", "codex-native", "openai-agents"}
        return wire_api == "openai_chat_completions" and harness in {
            "qwen",
            "jcode",
            "opencode-native",
            "openai-agents",
        }

    async def stop_archived_session(self, conversation: Conversation) -> bool:
        if not self.owns_session_input(conversation):
            return False
        await self.dispatch_session_input(
            conversation.id,
            conversation,
            SessionEventInput(type="stop_session", data={}),
            created_by=current_runtime_context().runtime_user_key,
            input_policy_checked=True,
        )
        return True

    async def observe_session_runtime_status(self, conversation: Conversation, data: dict) -> None:
        if self.owns_session_input(conversation) and self.runtime_status_observer is not None:
            self.runtime_status_observer(conversation, data)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    async def prepare_session_inference(
        self,
        request: Any,
        body: Any,
        spec: Any,
        user_id: str | None,
        *,
        harness_override: str | None,
        model_override: str | None,
    ) -> tuple[dict[str, Any], str] | None:
        """Freeze an explicitly selected publication without calling a supplier."""
        revision = body.inference_configuration_revision
        if not isinstance(revision, str) or not revision.startswith("managed-model:"):
            return None
        if not self._runtime_enabled:
            raise OmnigentError("interactive_runtime_disabled", code=ErrorCode.RUNNER_UNAVAILABLE)
        try:
            runtime = current_runtime_context()
        except RuntimeError:
            raise OmnigentError("interactive_context_required", code=ErrorCode.FORBIDDEN) from None
        if (
            user_id != runtime.runtime_user_key
            or model_override is None
            or body.parent_session_id is not None
            or body.sub_agent_name is not None
            or body.cost_control_mode_override == "on"
            or harness_override == "auto"
            or spec.executor.auth is not None
            or spec.executor.profile
        ):
            raise OmnigentError("interactive_selection_invalid", code=ErrorCode.INVALID_INPUT)
        existing = None
        create_token = body.labels.get("omnigent.client_create_token")
        if create_token:
            candidate = await asyncio.to_thread(self._delegate.get_conversation, create_token)
            if candidate is not None and self.owns_session_input(candidate):
                if self._permissions is None:
                    raise OmnigentError("interactive_context_required", code=ErrorCode.FORBIDDEN)
                await require_access_and_level(
                    user_id,
                    create_token,
                    LEVEL_EDIT,
                    self._permissions,
                    self._delegate,
                )
                existing = candidate
        try:
            marker = await asyncio.to_thread(
                self._admission.prepare_selection,
                runtime,
                runtime_project_id=body.project_id,
                model_id=model_override,
                configuration_revision=revision,
                existing=existing,
            )
        except (InteractiveExecutionError, TenantModelCatalogError):
            raise OmnigentError(
                "interactive_selection_unavailable", code=ErrorCode.INVALID_INPUT
            ) from None
        except ProjectAuthorizationError:
            raise OmnigentError(
                "interactive_selection_not_accessible", code=ErrorCode.FORBIDDEN
            ) from None
        harness = actual_harness(spec, harness_override)
        canonical = canonicalize_harness(harness)
        if not self._supports_model_harness(marker["wire_api"], canonical):
            raise OmnigentError(
                "interactive_model_harness_unsupported", code=ErrorCode.INVALID_INPUT
            )
        provider = None
        if body.host_type == "managed":
            deployment = getattr(request.app.state, "sandbox_config", None)
            selected_provider = body.sandbox_provider
            if selected_provider is None and existing is not None:
                previous_target = decode_interactive_launch(
                    (existing.inference_snapshot or {}).get(MANAGED_LAUNCH_SNAPSHOT_KEY)
                )
                selected_provider = previous_target["sandbox_provider"]
            target = deployment.for_provider(selected_provider) if deployment else None
            if deployment is None or target is None or not target.managed_launch_supported:
                raise OmnigentError(
                    "interactive_sandbox_unavailable", code=ErrorCode.INVALID_INPUT
                )
            provider = target.provider
            if len(
                body.managed_repo_workspaces()
            ) > 1 and not deployment.provider_ui_capabilities().get(provider, {}).get(
                "multi_repo", False
            ):
                raise OmnigentError(
                    "interactive_sandbox_multi_repo_unsupported", code=ErrorCode.INVALID_INPUT
                )
        elif body.host_id is None:
            raise OmnigentError("interactive_host_required", code=ErrorCode.INVALID_INPUT)
        return {
            "version": 1,
            "configuration_revision": revision,
            "target_id": revision,
            "owner_id": user_id,
            "runtime_config": {},
            "harness": harness,
            "catalog": {
                "models": [
                    {
                        "id": model_override,
                        "model": model_override,
                        "displayName": model_override,
                        "isDefault": True,
                        "source": {
                            "kind": "gateway",
                            "label": "Platform models",
                            "name": "platform-deepseek",
                        },
                    }
                ],
                "configured": True,
                "configuration_revision": revision,
                "provider_label": "Platform models",
                "default_model": model_override,
                "status": "ready",
            },
            MANAGED_EXECUTION_SNAPSHOT_KEY: marker,
            MANAGED_LAUNCH_SNAPSHOT_KEY: {
                "schema_version": 1,
                "host_type": body.host_type,
                "host_id": body.host_id,
                "sandbox_provider": provider,
                "workspaces": body.managed_repo_workspaces()
                if body.host_type == "managed"
                else [],
                "harness": harness,
            },
        }, model_override

    def create_conversation(self, **kwargs: Any) -> Conversation:
        """Complete the target using canonical values accepted by official creation."""
        snapshot = kwargs.get("inference_snapshot")
        if isinstance(snapshot, dict) and MANAGED_EXECUTION_SNAPSHOT_KEY in snapshot:
            snapshot = copy.deepcopy(snapshot)
            launch = snapshot.get(MANAGED_LAUNCH_SNAPSHOT_KEY)
            if not isinstance(launch, dict):
                raise OmnigentError("interactive_launch_invalid", code=ErrorCode.INVALID_INPUT)
            managed = launch.get("host_type") == "managed"
            launch.update(
                {
                    "host_id": None if managed else uuid_to_bytes(kwargs["host_id"]).hex(),
                    "agent_id": kwargs.get("agent_id"),
                    "workspace": None if managed else kwargs.get("workspace"),
                    "git_branch": None if managed else kwargs.get("git_branch"),
                    "reasoning_effort": kwargs.get("reasoning_effort"),
                    "terminal_launch_args": kwargs.get("terminal_launch_args"),
                }
            )
            decode_interactive_launch(launch)
            if self._public_origin is not None:
                session_id = uuid_to_bytes(kwargs.get("conversation_id") or uuid4().hex).hex()
                kwargs["conversation_id"] = session_id
                runtime = current_runtime_context()
                snapshot["runtime_config"] = model_channel_configuration(
                    session_id=interactive_session_identity(
                        runtime.tenant_id,
                        runtime.space_id,
                        runtime.runtime_partition_id,
                        session_id,
                    ),
                    harness=launch["harness"],
                    publication=self._admission.publication_configuration(
                        runtime, snapshot[MANAGED_EXECUTION_SNAPSHOT_KEY]
                    ),
                    public_origin=self._public_origin,
                )
            kwargs["inference_snapshot"] = snapshot
        try:
            return self._delegate.create_conversation(**kwargs)
        except ConversationAlreadyExistsError:
            existing = self._delegate.get_conversation(kwargs.get("conversation_id"))
            previous = existing.inference_snapshot if existing is not None else None
            if (existing is not None and self.owns_session_input(existing)) or (
                isinstance(snapshot, dict) and MANAGED_EXECUTION_SNAPSHOT_KEY in snapshot
            ):
                if (
                    existing is None
                    or not isinstance(previous, dict)
                    or not isinstance(snapshot, dict)
                    or previous.get(MANAGED_EXECUTION_SNAPSHOT_KEY)
                    != snapshot.get(MANAGED_EXECUTION_SNAPSHOT_KEY)
                    or previous.get(MANAGED_LAUNCH_SNAPSHOT_KEY)
                    != snapshot.get(MANAGED_LAUNCH_SNAPSHOT_KEY)
                    or existing.project_id != kwargs.get("project_id")
                    or existing.model_override != kwargs.get("model_override")
                ):
                    raise OmnigentError(
                        "interactive_create_conflict", code=ErrorCode.CONFLICT
                    ) from None
            raise

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
        if event.type == "message" and not self._runtime_enabled:
            raise OmnigentError("interactive_runtime_disabled", code=ErrorCode.RUNNER_UNAVAILABLE)
        try:
            runtime = current_runtime_context()
        except RuntimeError:
            raise OmnigentError(
                "Interactive input requires an authenticated context", code=ErrorCode.FORBIDDEN
            ) from None
        try:
            if event.type == "stop_session":
                if self._permissions is None:
                    raise OmnigentError("interactive_owner_required", code=ErrorCode.FORBIDDEN)
                await require_access_and_level(
                    runtime.runtime_user_key,
                    conversation.id,
                    LEVEL_OWNER,
                    self._permissions,
                    self._delegate,
                )
                if created_by != runtime.runtime_user_key or event.created_by is not None:
                    raise OmnigentError("interactive_actor_required", code=ErrorCode.FORBIDDEN)
                if self.session_stop_handler is None:
                    raise RunnerControlError("interactive_stop_unavailable", "Stop unavailable")

                async def cancel_inputs():
                    return await asyncio.to_thread(
                        self._admission.dispatch,
                        runtime,
                        conversation,
                        SessionEventInput(type="interrupt", data={}),
                        created_by=created_by,
                    )

                return await self.session_stop_handler(conversation, runtime, cancel_inputs)
            return await asyncio.to_thread(
                self._admission.dispatch,
                runtime,
                conversation,
                event,
                created_by=created_by,
            )
        except RunnerControlError:
            raise OmnigentError(
                "interactive_stop_unavailable", code=ErrorCode.RUNNER_UNAVAILABLE
            ) from None
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
