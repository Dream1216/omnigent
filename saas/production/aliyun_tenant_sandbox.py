"""Explicit tenant allowlist and lifecycle composition for the Aliyun provider."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

from omnigent.db.db_models import current_workspace_id
from omnigent.server.managed_hosts import ManagedSandboxConfig
from saas.compatibility.runtime_partition import current_runtime_context
from saas.production.aliyun_model_client import validated_server_origin
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from saas.production.aliyun_sandbox import AliyunSandboxLauncher, AliyunSandboxScope


@dataclass(frozen=True)
class AliyunManagedSandbox:
    template: str
    credential_file: Path
    server_url: str
    model_gateway_url: str
    scopes: tuple[AliyunSandboxScope, ...]
    model_leases: HostModelLeaseAuthority = field(repr=False)
    lifetime_s: int = 1800

    def __post_init__(self) -> None:
        if (
            not isinstance(self.scopes, tuple)
            or not 1 <= len(self.scopes) <= 32
            or any(not isinstance(scope, AliyunSandboxScope) for scope in self.scopes)
            or len({scope.tenant_id for scope in self.scopes}) != len(self.scopes)
            or len({scope.workspace_id for scope in self.scopes}) != len(self.scopes)
        ):
            raise ValueError("Aliyun sandbox tenant allowlist is invalid")
        validated_server_origin(self.server_url)


def build_aliyun_managed_config(
    settings: AliyunManagedSandbox, *, host_config: dict[str, object] | None
) -> ManagedSandboxConfig:
    """Append only when Server composition has admitted its explicit release profile."""

    by_tenant = {scope.tenant_id: scope for scope in settings.scopes}
    by_workspace = {scope.workspace_id: scope for scope in settings.scopes}

    def admit(scope: AliyunSandboxScope) -> AliyunSandboxScope:
        if by_tenant.get(scope.tenant_id) != scope:
            raise ValueError("Aliyun launch tenant or workspace is not admitted")
        return scope

    def cleanup_scope(workspace_id: int) -> AliyunSandboxScope:
        if type(workspace_id) is not int or workspace_id <= 0:
            raise ValueError("Aliyun cleanup requires a configured workspace")
        scope = by_workspace.get(workspace_id)
        if scope is None:
            raise ValueError("Aliyun cleanup requires a configured workspace")
        return scope

    def resolve_scope() -> AliyunSandboxScope:
        try:
            current_runtime_context()
        except RuntimeError:
            # The reaper binds each persisted Host row's workspace before teardown.
            return cleanup_scope(current_workspace_id())
        return admit(AliyunSandboxScope.from_runtime())

    def launcher(
        scope: AliyunSandboxScope | Callable[[], AliyunSandboxScope],
    ) -> AliyunSandboxLauncher:
        return AliyunSandboxLauncher(
            template=settings.template,
            credential_file=settings.credential_file,
            scope=scope,
            lifetime_s=settings.lifetime_s,
            model_leases=settings.model_leases,
            model_gateway_url=settings.model_gateway_url,
        )

    def factory() -> AliyunSandboxLauncher:
        try:
            current_runtime_context()
        except RuntimeError:
            workspace = current_workspace_id()
            if type(workspace) is int and workspace > 0:
                return launcher(lambda: cleanup_scope(workspace))
            return launcher(resolve_scope)  # Public capabilities do not select a tenant.
        scope = AliyunSandboxScope.from_runtime()
        return launcher(lambda: admit(scope))

    # Validate all static inputs now; /v1/info may later read capabilities without scope.
    checked = launcher(settings.scopes[0])
    return ManagedSandboxConfig(
        server_url=settings.server_url,
        launcher_factory=factory,
        token_ttl_s=checked.token_ttl_s,
        provider="e2b",
        host_config=deepcopy(host_config),
    )
