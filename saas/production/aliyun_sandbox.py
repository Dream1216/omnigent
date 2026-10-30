"""Explicit, tenant-scoped Aliyun transport for the managed E2B lifecycle."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import click
import httpx

from omnigent.db.db_models import current_workspace_id
from omnigent.onboarding.sandboxes.e2b import E2BSandboxLauncher
from saas.compatibility.runtime_partition import current_runtime_context
from saas.production.tenant_model_keys import _read_file

if TYPE_CHECKING:
    from e2b import Sandbox
    from e2b.sandbox.sandbox_api import SandboxInfo

ALIYUN_API_URL = "https://api.cn-hangzhou.sandbox.aliyuncs.com"
ALIYUN_DOMAIN = "cn-hangzhou.sandbox.aliyuncs.com"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


@dataclass(frozen=True)
class AliyunSandboxScope:
    tenant_id: UUID
    workspace_id: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tenant_id, UUID)
            or self.tenant_id.int == 0
            or type(self.workspace_id) is not int
            or not 0 < self.workspace_id < 2**63
        ):
            raise ValueError("Aliyun sandbox identity is invalid")

    @classmethod
    def from_runtime(cls) -> AliyunSandboxScope:
        runtime = current_runtime_context()
        scope = cls(runtime.tenant_id, runtime.physical_workspace_id)
        if scope.workspace_id != current_workspace_id():
            raise ValueError("Aliyun sandbox workspace context is invalid")
        return scope

    def check_context(self, *, required: bool = False) -> None:
        try:
            current_runtime_context()
        except RuntimeError:
            if required:
                raise
            return  # A cleanup job retains its explicit, trusted launch scope.
        if type(self).from_runtime() != self:
            raise ValueError("Aliyun sandbox runtime identity changed")

    def metadata(self) -> dict[str, str]:
        return {
            "omnigent-provider": "aliyun-e2b-v1",
            "omnigent-tenant": str(self.tenant_id),
            "omnigent-workspace": str(self.workspace_id),
        }


class AliyunSandboxLauncher(E2BSandboxLauncher):
    """Reuse command/file transport while bounding cloud authority and lifetime.

    A factory must obtain scope from the authorized Runtime Partition (or a
    persisted launch for cleanup). Management credentials stay on the server.
    This transport alone does not admit a SaaS production provider.
    """

    def __init__(
        self,
        *,
        template: str,
        credential_file: Path,
        scope: AliyunSandboxScope,
        lifetime_s: int = 1800,
    ) -> None:
        if (
            not isinstance(template, str)
            or not 1 <= len(template) <= 64
            or _IDENTIFIER.fullmatch(template) is None
            or type(lifetime_s) is not int
            or not 60 <= lifetime_s <= 3600
            or not isinstance(scope, AliyunSandboxScope)
        ):
            raise ValueError("Aliyun sandbox configuration is invalid")
        super().__init__(template=template, env=())
        self._credential_file = credential_file
        self.scope = scope
        self.lifetime_s = lifetime_s

    def _sdk_options(self) -> dict[str, Any]:
        raw = _read_file(self._credential_file, private=True, maximum=512)
        try:
            key = raw.rstrip(b"\r\n").decode("ascii")
        except UnicodeError:
            raise ValueError("Aliyun sandbox credential is invalid") from None
        if re.fullmatch(r"e2b_[A-Za-z0-9_-]{16,256}", key) is None:
            raise ValueError("Aliyun sandbox credential is invalid")
        return {
            "api_key": key,
            "api_url": ALIYUN_API_URL,
            "domain": ALIYUN_DOMAIN,
            "request_timeout": 45,
        }

    def prepare(self) -> None:
        from e2b import Sandbox  # noqa: F401 - optional dependency preflight

        self._sdk_options()

    def _resolve_sandbox_env(self) -> dict[str, str]:
        self.scope.check_context(required=True)
        return {
            "OMNIGENT_HOST_WORKSPACE_ID": str(self.scope.workspace_id),
            "OMNIGENT_SAAS_PLATFORM_MODEL_TENANT_ID": str(self.scope.tenant_id),
        }

    def provision(self, name: str) -> str:
        from e2b import Sandbox
        from e2b.exceptions import AuthenticationException, SandboxException

        env = self._resolve_sandbox_env()
        if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
            raise ValueError("Aliyun sandbox launch name is invalid")
        try:
            handle = Sandbox.create(
                template=self._resolved_template(),
                timeout=self.lifetime_s,
                metadata={**self.scope.metadata(), "omnigent-name": name},
                envs=env,
                **self._sdk_options(),
            )
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox creation failed") from None
        sandbox_id = str(handle.sandbox_id)
        self._sandboxes[sandbox_id] = handle
        return sandbox_id

    def _scoped_handle(self, sandbox_id: str, *, missing_ok: bool = False) -> Sandbox | None:
        from e2b import Sandbox
        from e2b.exceptions import AuthenticationException, NotFoundException, SandboxException

        self.scope.check_context()
        if not isinstance(sandbox_id, str) or _IDENTIFIER.fullmatch(sandbox_id) is None:
            raise ValueError("Aliyun sandbox identifier is invalid")
        options = self._sdk_options()
        try:
            handle = self._sandboxes.get(sandbox_id)
            if handle is None:
                handle = Sandbox.connect(sandbox_id, **options)
            info: SandboxInfo = handle.get_info(**options)
        except NotFoundException:
            self._sandboxes.pop(sandbox_id, None)
            if missing_ok:
                return None
            raise click.ClickException("Aliyun sandbox is no longer available") from None
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox ownership lookup failed") from None
        if any((info.metadata or {}).get(k) != v for k, v in self.scope.metadata().items()):
            raise ValueError("Aliyun sandbox ownership does not match")
        self._sandboxes[sandbox_id] = handle
        return handle

    def _resolve(self, sandbox_id: str) -> Sandbox:
        handle = self._scoped_handle(sandbox_id)
        assert handle is not None
        return handle

    def keep_alive(self, sandbox_id: str) -> None:
        from e2b.exceptions import AuthenticationException, SandboxException

        handle = self._resolve(sandbox_id)
        try:
            handle.set_timeout(self.lifetime_s, **self._sdk_options())
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox lifetime renewal failed") from None

    def terminate(self, sandbox_id: str) -> None:
        from e2b.exceptions import AuthenticationException, NotFoundException, SandboxException

        handle = self._scoped_handle(sandbox_id, missing_ok=True)
        if handle is None:
            return
        try:
            handle.kill(**self._sdk_options())
        except NotFoundException:
            pass
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox termination failed") from None
        finally:
            self._sandboxes.pop(sandbox_id, None)
