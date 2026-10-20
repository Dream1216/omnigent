"""Tenant-scoped composition of the reviewed managed Sandbox launchers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from functools import partial
from typing import Any
from uuid import UUID

from omnigent.db.db_models import current_workspace_id
from omnigent.onboarding.sandboxes.agent_sandbox_warm_pool import AgentSandboxWarmPoolLauncher
from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher
from omnigent.server.managed_hosts import ManagedSandboxDeployment, parse_sandbox_config
from saas.compatibility.runtime_partition import current_runtime_context
from saas.production.tenant_model_keys import TenantModelKeyBinding

_WORKSPACE_ENV = "OMNIGENT_HOST_WORKSPACE_ID"
_TENANT_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID"
_IDENTITY_ENV = (_WORKSPACE_ENV, _TENANT_ENV)


class _RuntimeIdentity:
    """Resolve launch identity inside the background task's copied context."""

    _env_names: tuple[str, ...] | None
    _model_scope_required = False
    _model_tenant_id: UUID | None = None

    def _resolve_sandbox_env(self) -> dict[str, str]:
        runtime = current_runtime_context()
        workspace_id = runtime.physical_workspace_id
        if (
            self._env_names != _IDENTITY_ENV
            or isinstance(workspace_id, bool)
            or not isinstance(workspace_id, int)
            or workspace_id <= 0
            or workspace_id != current_workspace_id()
            or not isinstance(runtime.tenant_id, UUID)
            or runtime.tenant_id.int == 0
            or (self._model_scope_required and runtime.tenant_id != self._model_tenant_id)
        ):
            raise ValueError("Sandbox runtime identity is invalid")
        return {_WORKSPACE_ENV: str(workspace_id), _TENANT_ENV: str(runtime.tenant_id)}


class _TenantKubernetesLauncher(_RuntimeIdentity, KubernetesSandboxLauncher):
    """Keep the official Job lifecycle and replace only launch identity."""


class _TenantAgentSandboxLauncher(_RuntimeIdentity, AgentSandboxWarmPoolLauncher):
    """Keep the official retained-Sandbox lifecycle and tenant isolation."""


def _launcher(
    launcher_type: Any,
    kwargs: dict[str, Any],
    bindings: tuple[TenantModelKeyBinding, ...],
    legacy_tenant_id: UUID | None,
) -> Any:
    values = deepcopy(kwargs)
    tenant_id = None
    if bindings:
        try:
            runtime = current_runtime_context()
        except RuntimeError:
            runtime = None  # Cleanup must not require an interactive request.
        if runtime is not None:
            tenant_id = runtime.tenant_id
            binding = next((b for b in bindings if b.tenant_id == tenant_id), None)
            if binding is None and tenant_id != legacy_tenant_id:
                raise ValueError("Sandbox tenant has no model authority")
            if binding is not None:
                if runtime.physical_workspace_id != binding.workspace_id:
                    raise ValueError("Sandbox tenant model workspace is invalid")
                values["secret_mounts"] = [
                    {
                        "secret_name": binding.sandbox_secret_name,
                        "mount_path": "/credentials/omnigent-platform-model",
                    }
                ]
    launcher = launcher_type(**values)
    launcher._model_scope_required = bool(bindings)
    launcher._model_tenant_id = tenant_id
    return launcher


def parse_tenant_sandbox_config(
    raw: Any,
    *,
    model_bindings: tuple[TenantModelKeyBinding, ...] = (),
    legacy_tenant_id: UUID | None = None,
) -> ManagedSandboxDeployment | None:
    """Compose an already production-reviewed profile with scoped launchers."""

    parsed = parse_sandbox_config(raw)
    if parsed is None:
        return None
    kwargs = deepcopy(raw.get("kubernetes"))
    if not isinstance(kwargs, dict) or kwargs.get("env") != list(_IDENTITY_ENV):
        raise ValueError("Sandbox runtime identity environment is invalid")
    launchers = {
        "agent_sandbox": _TenantAgentSandboxLauncher,
        "kubernetes": _TenantKubernetesLauncher,
    }
    configs = []
    for entry in parsed.configs:
        launcher = launchers.get(entry.provider or "")
        if launcher is None:
            raise ValueError("Sandbox provider is not reviewed for tenant identity")
        configs.append(
            replace(
                entry,
                launcher_factory=partial(
                    _launcher, launcher, kwargs, model_bindings, legacy_tenant_id
                ),
            )
        )
    return replace(parsed, configs=tuple(configs))
