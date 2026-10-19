"""Checkpoint real managed resource bindings before the SDK may create them."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from threading import Event, Lock
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import uuid4

from omnigent.host.identity import HOST_TOKEN_ENV_VAR
from omnigent.onboarding.sandboxes.agent_sandbox import AgentSandboxLauncher
from omnigent.onboarding.sandboxes.agent_sandbox_warm_pool import AgentSandboxWarmPoolLauncher
from omnigent.onboarding.sandboxes.base import SandboxHostLauncher
from omnigent.onboarding.sandboxes.kubernetes import KubernetesSandboxLauncher, _token_secret_name
from omnigent.server.managed_hosts import ManagedSandboxDeployment
from omnigent.stores.host_store import hash_host_launch_token
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import (
    InteractiveRecoveryRecord,
    ManagedCreationIntent,
    ManagedPreparationBinding,
    ManagedResourceBinding,
)
from saas.production.interactive_resources import (
    CREATION_ANNOTATION,
    INPUT_TEMPLATE_ANNOTATION,
    TERMINATION_FINALIZER,
    _creation_metadata,
    _secret_uid,
    _template,
    _template_sha256,
    read_managed_resources,
)

_CHECKPOINT_TIMEOUT_SECONDS = 10


def _direct_launcher(selected, provider: str) -> KubernetesSandboxLauncher:
    from saas.production.interactive_managed_lifecycle import ControlledManagedLauncher

    expected = {
        "kubernetes": (KubernetesSandboxLauncher,),
        "agent_sandbox": (AgentSandboxLauncher, AgentSandboxWarmPoolLauncher),
    }
    if provider not in expected or selected is None or not selected.managed_launch_supported:
        raise _unavailable()
    delegate = selected.launcher_factory()
    if type(delegate) is ControlledManagedLauncher:
        delegate = delegate.delegate
    if (
        type(delegate) not in expected[provider]
        or delegate.provider != provider
        or (isinstance(delegate, AgentSandboxWarmPoolLauncher) and delegate._warm_pool is not None)
    ):
        raise _unavailable()
    return cast(KubernetesSandboxLauncher, delegate)


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
        or getattr(configuration, "retries", None) not in (None, 0)
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
    def __init__(
        self,
        delegate,
        *,
        host_store,
        owner,
        checkpoint,
        checkpoint_resources,
        checkpoint_creation,
        stopping,
        loop,
    ):
        self._delegate, self._host_store, self._owner = delegate, host_store, owner
        self._checkpoint, self._stopping, self._loop = checkpoint, stopping, loop
        self._checkpoint_resources = checkpoint_resources
        self._checkpoint_creation = checkpoint_creation
        self._intent = None
        self._start_lock = Lock()
        self._started = self._submitted = False

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def terminate(self, sandbox_id):
        del sandbox_id
        raise _unavailable()

    def resume(self, sandbox_id):
        del sandbox_id
        raise _unavailable()

    def _persist(self, callback, value):
        async def persist():
            await callback(value)

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

    def start_host(self, sandbox_id: str, *, host_id: str, **kwargs):
        with self._start_lock:
            if self._started:
                raise _unavailable()
            self._started = True
        try:
            if self._stopping.is_set():
                raise _unavailable()
            binding = _binding(self._delegate, sandbox_id, host_id)
            token = kwargs.get("token")
            if not isinstance(token, str) or not token:
                raise _unavailable()
            host = self._host_store.resolve_launch_token(host_id, token)
            if (
                host is None
                or host.host_id != host_id
                or host.user_id != self._owner
                or host.sandbox_provider != binding.provider
                or host.sandbox_id != sandbox_id
            ):
                raise _unavailable()

            self._persist(self._checkpoint, binding)
            self._persist_intent(ManagedCreationIntent(uuid4().hex, hash_host_launch_token(token)))
            if self._stopping.is_set():
                raise _unavailable()
            create = self._delegate._create_workload
            cleanup = self._delegate._best_effort_delete
            core = self._delegate._load_core
            custom = self._delegate._load_custom if binding.provider == "agent_sandbox" else None

            def observe_resources(namespace, manifest):
                if namespace != binding.namespace:
                    raise _unavailable()
                with self._start_lock:
                    intent = self._intent
                    if (
                        self._submitted
                        or intent is None
                        or intent.secret_uid is None
                        or self._stopping.is_set()
                    ):
                        raise _unavailable()
                    self._submitted = True
                    if (
                        manifest["kind"] != "Job"
                        or manifest["apiVersion"] != "batch/v1"
                        or manifest["metadata"]["name"] != sandbox_id
                        or manifest["metadata"]["namespace"] != binding.namespace
                    ):
                        raise _unavailable()
                    template = _template(manifest, replace(binding, provider="kubernetes"))
                    self._stamp(manifest, intent.nonce)
                    self._stamp(template, intent.nonce)
                    for document in (
                        (manifest, template) if binding.provider == "kubernetes" else (manifest,)
                    ):
                        finalizers = document["metadata"].setdefault("finalizers", [])
                        if TERMINATION_FINALIZER in finalizers:
                            raise _unavailable()
                        finalizers.append(TERMINATION_FINALIZER)
                    digest = _template_sha256(template)
                    template["metadata"]["annotations"][INPUT_TEMPLATE_ANNOTATION] = digest
                    self._persist_intent(
                        replace(intent, workload_submitted=True, input_template_sha256=digest)
                    )

                def retain_observed():
                    if _binding(self._delegate, sandbox_id, host_id) != binding:
                        raise _unavailable()
                    actual = read_managed_resources(
                        self._delegate,
                        binding,
                        host_token_sha256=hash_host_launch_token(token),
                        creation=self._intent,
                    )
                    self._persist(self._checkpoint_resources, actual)

                try:
                    create(namespace, manifest)
                except Exception as error:  # noqa: BLE001 - a failed ACK can follow a committed create.
                    if getattr(error, "status", None) != 409:
                        retain_observed()
                    raise _unavailable() from None
                retain_observed()

            self._delegate._create_workload = observe_resources
            self._delegate._load_core = lambda: _CreationCore(core(), self, binding)
            # Retain unknown effects for UID-bound recovery; a name is not cleanup authority.
            self._delegate._best_effort_delete = lambda *_: None
            if custom is not None:
                self._delegate._load_custom = lambda: _CreateOnlyCustom(custom())
            try:
                return self._delegate.start_host(sandbox_id, host_id=host_id, **kwargs)
            finally:
                self._delegate._create_workload = create
                self._delegate._best_effort_delete = cleanup
                self._delegate._load_core = core
                if custom is not None:
                    self._delegate._load_custom = custom
        finally:
            self._delegate._close_clients()

    def _persist_intent(self, intent):
        self._persist(self._checkpoint_creation, intent)
        self._intent = intent

    @staticmethod
    def _stamp(document, nonce):
        annotations = document["metadata"].setdefault("annotations", {})
        if CREATION_ANNOTATION in annotations or INPUT_TEMPLATE_ANNOTATION in annotations:
            raise _unavailable()
        annotations[CREATION_ANNOTATION] = nonce


class _CreationCore:
    def __init__(self, delegate, owner, binding):
        self._delegate, self._owner, self._binding = delegate, owner, binding

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def create_namespaced_secret(self, namespace, body, **kwargs):
        owner, binding = self._owner, self._binding
        with owner._start_lock:
            intent = owner._intent
            try:
                if (
                    intent is None
                    or intent.secret_submitted
                    or owner._stopping.is_set()
                    or kwargs.get("async_req") is True
                    or namespace != binding.namespace
                    or body["metadata"]["namespace"] != namespace
                    or body["metadata"]["name"] != _token_secret_name(binding.resource_name)
                    or body["metadata"]["labels"].get("app.kubernetes.io/managed-by") != "omnigent"
                    or body["metadata"]["labels"].get("omnigent.ai/role") != "sandbox-host"
                    or body["kind"] != "Secret"
                    or body["apiVersion"] != "v1"
                    or body["type"] != "Opaque"
                    or body.get("data")
                    or set(body["stringData"]) != {HOST_TOKEN_ENV_VAR}
                    or hash_host_launch_token(body["stringData"][HOST_TOKEN_ENV_VAR])
                    != intent.host_token_sha256
                ):
                    raise _unavailable()
                owner._stamp(body, intent.nonce)
                owner._persist_intent(replace(intent, secret_submitted=True))
                result = self._delegate.create_namespaced_secret(namespace, body, **kwargs)
                raw = self._delegate.read_namespaced_secret(
                    _token_secret_name(binding.resource_name), namespace, _request_timeout=10
                )
                secret = owner._delegate._api_client.sanitize_for_serialization(raw)
                _creation_metadata(secret, intent)
                uid = _secret_uid(secret, binding, intent.host_token_sha256)
                owner._persist_intent(replace(intent, secret_submitted=True, secret_uid=uid))
                return result
            except Exception:  # noqa: BLE001 - SDK response bodies may contain credentials.
                raise _unavailable() from None


class _CreateOnlyCustom:
    def __init__(self, delegate):
        self._delegate = delegate

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def patch_namespaced_custom_object(self, *_args, **_kwargs):
        from kubernetes.client.rest import ApiException

        raise ApiException(status=409, reason="Managed workload already exists")


def bind_managed_preparation(
    deployment: ManagedSandboxDeployment,
    *,
    provider: str,
    host_store: Any,
    owner: str,
    checkpoint: Callable[[ManagedPreparationBinding], Awaitable[None]],
    checkpoint_resources: Callable[[ManagedResourceBinding], Awaitable[None]],
    checkpoint_creation: Callable[[ManagedCreationIntent], Awaitable[None]],
    stopping: Event,
    loop: asyncio.AbstractEventLoop,
) -> ManagedSandboxDeployment:
    selected = deployment.for_provider(provider)
    if selected is None or not selected.managed_launch_supported:
        raise _unavailable()

    def factory():
        delegate = _direct_launcher(selected, provider)
        return cast(
            SandboxHostLauncher,
            _CheckpointedLauncher(
                delegate,
                host_store=host_store,
                owner=owner,
                checkpoint=checkpoint,
                checkpoint_resources=checkpoint_resources,
                checkpoint_creation=checkpoint_creation,
                stopping=stopping,
                loop=loop,
            ),
        )

    return replace(
        deployment,
        configs=(replace(selected, launcher_factory=factory),),
    )


def inspect_managed_resources(
    deployment: ManagedSandboxDeployment, record: InteractiveRecoveryRecord
) -> ManagedResourceBinding:
    preparation, expected = record.managed_preparation, record.managed_resources
    if preparation is None or expected is None:
        raise _unavailable()
    selected = deployment.for_provider(preparation.provider)
    delegate = _direct_launcher(selected, preparation.provider)
    try:
        if _binding(delegate, preparation.resource_name, preparation.host_id) != preparation:
            raise _unavailable()
        observed = read_managed_resources(
            delegate,
            preparation,
            host_token_sha256=expected.host_token_sha256,
            creation=record.managed_creation,
        )
        if observed != expected:
            raise _unavailable()
        return observed
    except Exception:  # noqa: BLE001 - inspection never exposes cluster or credential details.
        raise _unavailable() from None
    finally:
        delegate._close_clients()
