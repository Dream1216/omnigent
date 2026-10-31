"""Explicit, tenant-scoped Aliyun transport for the managed E2B lifecycle."""

from __future__ import annotations

import math
import re
import secrets
import shlex
import threading
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import click
import httpx

from omnigent.db.db_models import current_workspace_id
from omnigent.host.identity import (
    HOST_ID_ENV_VAR,
    HOST_NAME_ENV_VAR,
    HOST_TOKEN_FILE_ENV_VAR,
    HOST_WORKSPACE_ID_ENV_VAR,
)
from omnigent.onboarding.sandboxes.base import (
    RemoteCommandResult,
    render_host_config_write_command,
)
from omnigent.onboarding.sandboxes.e2b import E2BSandboxLauncher
from omnigent.onboarding.sandboxes.types import RepoWorkspace, SandboxCapabilities, clone_dir_names
from saas.compatibility.runtime_partition import current_runtime_context
from saas.production.aliyun_host import (
    MODEL_GATEWAY_URL_ENV,
    MODEL_LEASE_FILE_ENV,
    MODEL_TENANT_ENV,
    SERVER_URL_ENV,
)
from saas.production.aliyun_model_client import validated_server_origin
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from saas.production.aliyun_sdk import (
    attach_running_sandbox,
    read_sandbox_details,
    require_qualified_sdk,
)
from saas.production.platform_model_relay import validated_model_gateway_url
from saas.production.tenant_model_keys import _read_file

if TYPE_CHECKING:
    from e2b import Sandbox
    from e2b.api.client.models import SandboxDetail

ALIYUN_API_URL = "https://api.cn-hangzhou.sandbox.aliyuncs.com"
ALIYUN_DOMAIN = "cn-hangzhou.sandbox.aliyuncs.com"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_LIFETIME_METADATA = "omnigent-lifetime-seconds"


def _now() -> datetime:
    return datetime.now(UTC)


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
        scope: AliyunSandboxScope | Callable[[], AliyunSandboxScope],
        lifetime_s: int = 1800,
        model_leases: HostModelLeaseAuthority | None = None,
        model_gateway_url: str | None = None,
    ) -> None:
        if (
            not isinstance(template, str)
            or not 1 <= len(template) <= 64
            or _IDENTIFIER.fullmatch(template) is None
            or type(lifetime_s) is not int
            or not 60 <= lifetime_s <= 3600
            or not (isinstance(scope, AliyunSandboxScope) or callable(scope))
        ):
            raise ValueError("Aliyun sandbox configuration is invalid")
        super().__init__(template=template, env=())
        self._credential_file = credential_file
        self._scope_source = scope
        self._scope_lock = threading.Lock()
        self._launch_scope: AliyunSandboxScope | None = (
            scope if isinstance(scope, AliyunSandboxScope) else None
        )
        self.lifetime_s = lifetime_s
        if (model_leases is None) != (model_gateway_url is None) or (
            model_leases is not None and not isinstance(model_leases, HostModelLeaseAuthority)
        ):
            raise ValueError("Aliyun Host model configuration is incomplete")
        if model_gateway_url is not None:
            model_gateway_url = validated_model_gateway_url(model_gateway_url)
            if not model_gateway_url.startswith("https://"):
                raise ValueError("Aliyun Host model gateway requires TLS")
        self._model_leases = model_leases
        self._model_gateway_url = model_gateway_url

    @property
    def scope(self) -> AliyunSandboxScope:
        """Resolve once from the launch or persisted cleanup workspace; then freeze."""

        with self._scope_lock:
            if self._launch_scope is None:
                source = self._scope_source
                resolved = source() if callable(source) else source
                if not isinstance(resolved, AliyunSandboxScope):
                    raise ValueError("Aliyun sandbox scope resolver is invalid")
                self._launch_scope = resolved
            return self._launch_scope

    @property
    def capabilities(self) -> SandboxCapabilities:
        return replace(super().capabilities, multi_repo=True, git_clone_options=True)

    @property
    def token_ttl_s(self) -> int:
        return self.lifetime_s + 3600

    def run(self, sandbox_id: str, command: str, *, check: bool = True) -> RemoteCommandResult:
        try:
            return super().run(sandbox_id, command, check=check)
        except click.ClickException:
            raise click.ClickException("Aliyun sandbox command failed") from None

    def start_host(
        self,
        sandbox_id: str,
        *,
        token: str,
        host_id: str,
        host_name: str,
        server_url: str,
        repos: Sequence[RepoWorkspace] = (),
        host_config: dict[str, object] | None = None,
        on_stage: Callable[[str], None] | None = None,
    ) -> str:
        """Keep workspace transport, but launch the file-authenticated cloud Host."""

        self.scope.check_context(required=True)
        if self._model_leases is None or self._model_gateway_url is None:
            raise ValueError("Aliyun Host model authority is unavailable")
        server_url = validated_server_origin(server_url)
        if (
            UUID(host_id).int == 0
            or UUID(host_id).hex != host_id
            or not host_name
            or host_name != host_name.strip()
            or len(host_name) > 128
        ):
            raise ValueError("Aliyun Host identity is invalid")
        if any(ord(c) < 32 or ord(c) == 127 for c in host_name):
            raise ValueError("Aliyun Host name is invalid")
        info = self._scoped_info(sandbox_id)
        assert info is not None
        self._remaining_lifetime(info)
        admitted_lifetime = self._admitted_lifetime_s(info)
        lease = self._model_leases.issue(
            host_id=host_id,
            launch_token=token,
            runtime=current_runtime_context(),
            ttl_seconds=admitted_lifetime,
            now=int(info.started_at.timestamp()),
        )
        home = self.run(sandbox_id, 'printf %s "$HOME"').stdout.strip()
        if home != "/home/user":
            raise ValueError("Aliyun Host image HOME is not the qualified path")
        workspace = f"{home}/workspace"
        self.run(sandbox_id, f"mkdir -p -- {shlex.quote(workspace)}")
        if repos:
            if on_stage is not None:
                on_stage("cloning")
            checkouts = [
                self.materialize_workspace(
                    sandbox_id,
                    workspace=workspace,
                    repo_url=repo.url,
                    repo_branch=repo.branch,
                    repo_name=directory,
                    git_clone=repo.git_clone,
                )
                for repo, directory in zip(repos, clone_dir_names(repos), strict=True)
            ]
            workspace = checkouts[0] if len(checkouts) == 1 else workspace
        if host_config is not None:
            self.run(sandbox_id, render_host_config_write_command(host_config))
        private = f"{home}/.omnigent/runtime/aliyun-host-{host_id}-{secrets.token_hex(12)}"
        prepare = (
            "import sys; from pathlib import Path; "
            "from saas.production.aliyun_host import prepare_aliyun_host_directory; "
            "prepare_aliyun_host_directory(Path(sys.argv[1]))"
        )
        self.run(sandbox_id, shlex.join(["/opt/venv/bin/python", "-I", "-c", prepare, private]))
        token_path, lease_path = f"{private}/host-token", f"{private}/model-lease"
        try:
            handle = self._resolve(sandbox_id)
            try:
                handle.files.write(token_path, token, user="user", request_timeout=45)
                handle.files.write(lease_path, lease, user="user", request_timeout=45)
            except Exception:  # noqa: BLE001 - SDK errors must not echo credential payloads.
                raise click.ClickException("Aliyun Host credential delivery failed") from None
            self.run(sandbox_id, shlex.join(["chmod", "0400", "--", token_path, lease_path]))
            if on_stage is not None:
                on_stage("starting")
            environment = {
                HOST_ID_ENV_VAR: host_id,
                HOST_NAME_ENV_VAR: host_name,
                HOST_TOKEN_FILE_ENV_VAR: token_path,
                HOST_WORKSPACE_ID_ENV_VAR: str(self.scope.workspace_id),
                SERVER_URL_ENV: server_url,
                MODEL_LEASE_FILE_ENV: lease_path,
                MODEL_GATEWAY_URL_ENV: self._model_gateway_url,
                MODEL_TENANT_ENV: str(self.scope.tenant_id),
            }
            command = " ".join(f"{k}={shlex.quote(v)}" for k, v in environment.items())
            self.run_background(
                sandbox_id,
                f"{command} /opt/venv/bin/python -I -m saas.production.aliyun_host",
                log_path=f"{private}/host.log",
            )
        except BaseException:
            with suppress(Exception):
                self.run(sandbox_id, shlex.join(["rm", "-rf", "--", private]), check=False)
            raise
        return workspace

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
            "debug": False,
        }

    def prepare(self) -> None:
        require_qualified_sdk()
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
                metadata={
                    **self.scope.metadata(),
                    "omnigent-name": name,
                    _LIFETIME_METADATA: str(self.lifetime_s),
                },
                envs=env,
                **self._sdk_options(),
            )
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox creation failed") from None
        sandbox_id = str(handle.sandbox_id)
        self._sandboxes[sandbox_id] = handle
        return sandbox_id

    def _scoped_info(self, sandbox_id: str, *, missing_ok: bool = False) -> SandboxDetail | None:
        from e2b.exceptions import AuthenticationException, NotFoundException, SandboxException

        self.scope.check_context()
        if not isinstance(sandbox_id, str) or _IDENTIFIER.fullmatch(sandbox_id) is None:
            raise ValueError("Aliyun sandbox identifier is invalid")
        try:
            # Connecting can resume a VM, so ownership must use the read-only API first.
            info = read_sandbox_details(sandbox_id, self._sdk_options())
        except NotFoundException:
            self._sandboxes.pop(sandbox_id, None)
            if missing_ok:
                return None
            raise click.ClickException("Aliyun sandbox is no longer available") from None
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox ownership lookup failed") from None
        metadata = info.metadata if isinstance(info.metadata, dict) else {}
        if info.sandbox_id != sandbox_id or any(
            metadata.get(k) != v for k, v in self.scope.metadata().items()
        ):
            raise ValueError("Aliyun sandbox ownership does not match")
        return info

    def _admitted_lifetime_s(self, info: SandboxDetail) -> int:
        metadata = info.metadata if isinstance(info.metadata, dict) else {}
        raw = metadata.get(_LIFETIME_METADATA)
        if (
            not isinstance(raw, str)
            or re.fullmatch(r"[1-9][0-9]{1,3}", raw) is None
            or not 60 <= int(raw) <= 3600
            or not isinstance(info.started_at, datetime)
            or info.started_at.tzinfo is None
            or info.started_at.utcoffset() is None
        ):
            raise ValueError("Aliyun sandbox lifetime evidence is invalid")
        return min(self.lifetime_s, int(raw))

    def _remaining_lifetime(self, info: SandboxDetail) -> int:
        lifetime = self._admitted_lifetime_s(info)
        elapsed = (_now() - info.started_at).total_seconds()
        if elapsed < -30:
            raise ValueError("Aliyun sandbox start time is invalid")
        remaining = math.floor(lifetime - max(0, elapsed))
        if remaining <= 0:
            raise click.ClickException("Aliyun sandbox absolute lifetime has expired")
        if info.state != "running":
            raise click.ClickException("Aliyun sandbox is not running")
        return remaining

    def _resolve(self, sandbox_id: str) -> Sandbox:
        info = self._scoped_info(sandbox_id)
        assert info is not None
        self._remaining_lifetime(info)
        handle = self._sandboxes.get(sandbox_id)
        if handle is None:
            handle = attach_running_sandbox(info, self._sdk_options())
            self._sandboxes[sandbox_id] = handle
        return handle

    def keep_alive(self, sandbox_id: str) -> None:
        # Heartbeats verify availability without extending the cloud creation timeout.
        info = self._scoped_info(sandbox_id)
        assert info is not None
        self._remaining_lifetime(info)

    def terminate(self, sandbox_id: str) -> None:
        from e2b import Sandbox
        from e2b.exceptions import AuthenticationException, NotFoundException, SandboxException

        if self._scoped_info(sandbox_id, missing_ok=True) is None:
            return
        try:
            Sandbox.kill(sandbox_id, **self._sdk_options())
        except NotFoundException:
            pass
        except (AuthenticationException, SandboxException, httpx.HTTPError):
            raise click.ClickException("Aliyun sandbox termination failed") from None
        finally:
            self._sandboxes.pop(sandbox_id, None)
