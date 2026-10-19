"""Checkpoint real managed resource bindings before the SDK may create them."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from threading import Event
from typing import Any, cast
from urllib.parse import urlsplit

from omnigent.onboarding.sandboxes.agent_sandbox import AgentSandboxLauncher
from omnigent.onboarding.sandboxes.agent_sandbox_warm_pool import AgentSandboxWarmPoolLauncher
from omnigent.onboarding.sandboxes.base import SandboxHostLauncher
from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher
from omnigent.server.managed_hosts import ManagedSandboxDeployment
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import ManagedPreparationBinding

_CHECKPOINT_TIMEOUT_SECONDS = 10


def _binding(launcher: KubernetesSandboxLauncher, resource: str, host_id: str):
    launcher._load_clients()
    client = launcher._api_client
    if client is None:
        raise _unavailable()
    configuration = client.configuration
    server = urlsplit(configuration.host)
    ca = configuration.ssl_ca_cert
    if (
        configuration.verify_ssl is not True
        or configuration.assert_hostname is False
        or server.scheme != "https"
        or not server.hostname
        or server.username is not None
        or server.password is not None
        or server.query
        or server.fragment
        or not isinstance(ca, str)
        or not 0 < Path(ca).stat().st_size <= 1024 * 1024
    ):
        raise _unavailable()
    identity = {
        "server": configuration.host.rstrip("/"),
        "ca_sha256": sha256(Path(ca).read_bytes()).hexdigest(),
        "assert_hostname": configuration.assert_hostname,
        "tls_server_name": getattr(configuration, "tls_server_name", None),
    }
    return ManagedPreparationBinding(
        provider=launcher.provider,
        namespace=launcher._resolve_namespace(),
        resource_name=resource,
        host_id=host_id,
        cluster_sha256=sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        image_reference_sha256=sha256(launcher._resolve_image().encode()).hexdigest(),
    )


class _CheckpointedLauncher:
    def __init__(self, delegate, *, host_store, owner, checkpoint, stopping, loop):
        self._delegate, self._host_store, self._owner = delegate, host_store, owner
        self._checkpoint, self._stopping, self._loop = checkpoint, stopping, loop

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def start_host(self, sandbox_id: str, *, host_id: str, **kwargs):
        try:
            if self._stopping.is_set():
                raise _unavailable()
            binding = _binding(self._delegate, sandbox_id, host_id)
            host = self._host_store.get_host(host_id)
            if (
                host is None
                or host.host_id != host_id
                or host.user_id != self._owner
                or host.sandbox_provider != binding.provider
                or host.sandbox_id != sandbox_id
            ):
                raise _unavailable()

            async def persist():
                await self._checkpoint(binding)

            operation = persist()
            try:
                acknowledged = asyncio.run_coroutine_threadsafe(operation, self._loop)
            except RuntimeError:
                operation.close()
                raise _unavailable() from None
            try:
                acknowledged.result(timeout=_CHECKPOINT_TIMEOUT_SECONDS)
            except FutureTimeoutError:
                acknowledged.cancel()
                raise _unavailable() from None
            if self._stopping.is_set():
                raise _unavailable()
            return self._delegate.start_host(sandbox_id, host_id=host_id, **kwargs)
        finally:
            self._delegate._close_clients()


def bind_managed_preparation(
    deployment: ManagedSandboxDeployment,
    *,
    provider: str,
    host_store: Any,
    owner: str,
    checkpoint: Callable[[ManagedPreparationBinding], Awaitable[None]],
    stopping: Event,
    loop: asyncio.AbstractEventLoop,
) -> ManagedSandboxDeployment:
    selected = deployment.for_provider(provider)
    expected = {
        "kubernetes": (KubernetesSandboxLauncher,),
        "agent_sandbox": (AgentSandboxLauncher, AgentSandboxWarmPoolLauncher),
    }
    if provider not in expected or selected is None or not selected.managed_launch_supported:
        raise _unavailable()

    def factory():
        delegate = selected.launcher_factory()
        if (
            type(delegate) not in expected[provider]
            or delegate.provider != provider
            or (
                isinstance(delegate, AgentSandboxWarmPoolLauncher)
                and delegate._warm_pool is not None
            )
        ):
            raise _unavailable()
        return cast(
            SandboxHostLauncher,
            _CheckpointedLauncher(
                delegate,
                host_store=host_store,
                owner=owner,
                checkpoint=checkpoint,
                stopping=stopping,
                loop=loop,
            ),
        )

    return replace(
        deployment,
        configs=(replace(selected, launcher_factory=factory),),
    )
