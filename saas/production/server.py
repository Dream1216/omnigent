"""Production-only downstream composition for the Omnigent SaaS server.

The official OSS entrypoint remains untouched.  This module is an alternative
deployment command (``python -m saas.production.server``) that composes the
official stores with SaaS authentication and the stable public Run API.  It
never runs migrations: schema/role convergence belongs to the separate
pre-deployment PostgreSQL job.
"""

from __future__ import annotations

import fcntl
import importlib
import inspect
import logging
import os
import re
import secrets
import shutil
import stat
from collections.abc import Callable, Mapping, MutableMapping
from concurrent.futures import Future, ThreadPoolExecutor, wait
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Protocol, cast

import sqlalchemy as sa
import yaml
from fastapi import APIRouter, FastAPI, Response
from fastapi.responses import JSONResponse
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from saas.application import create_omnigent_saas_app
from saas.compatibility import OmnigentStoreAdapter
from saas.control_plane.api_credentials import ApiCredentialService
from saas.control_plane.context_snapshot import (
    ContextSnapshotPolicy,
    ContextSnapshotService,
    ControlPlaneAvailabilityGate,
)
from saas.control_plane.http_auth import (
    SaasCookieConfig,
    SaasHttpIntegration,
    create_saas_http_integration,
)
from saas.control_plane.identity import IdentityManagementService, PasswordCredentialService
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.public_api import PublicApiExecutionService
from saas.control_plane.resolver import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver
from saas.production.onboarding import (
    ProductionOnboardingHttpServices,
    build_production_onboarding_http_services,
)
from saas.production.server_config import (
    ProductionServerConfig,
    load_production_server_config,
)
from saas.public_api_contract import FilterBoundCursorCodec

logger = logging.getLogger("omnigent-saas-server")

_PRODUCTION_OFFICIAL_CONFIG_KEYS = frozenset({"execution_timeout", "llm", "policies"})
_PRODUCTION_LLM_KEYS = frozenset(
    {
        "fallback_models",
        "max_completion_tokens",
        "max_tokens",
        "model",
        "reasoning_effort",
        "request_timeout",
        "retry",
        "seed",
        "temperature",
        "top_p",
    }
)
_SECRET_CONFIG_KEYS = frozenset(
    {
        "authorization",
        "access_key",
        "api_key",
        "apikey",
        "connection",
        "credential",
        "credential_process",
        "env",
        "headers",
        "kubeconfig",
        "profile",
        "password",
        "private_key",
        "secret",
        "secret_mounts",
        "secret_name",
        "token",
    }
)
_SECRET_CONFIG_KEY_SUFFIXES = (
    "_access_key",
    "_api_key",
    "_authorization",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)
_AMBIENT_CLOUD_FILE_PROVIDER_LOCKS = MappingProxyType(
    {
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "BOTO_CONFIG": os.devnull,
        "DATABRICKS_CONFIG_FILE": os.devnull,
        "GOOGLE_APPLICATION_CREDENTIALS": os.devnull,
    }
)
_AMBIENT_ONLY_LLM_PROVIDERS = frozenset({"bedrock", "databricks", "vertex"})


class ProductionServerCompositionError(RuntimeError):
    """Stable fail-closed composition error raised before socket bind."""


class ProductionExternalAdapter(Protocol):
    """Deployment-owned Runner or Preview adapter readiness contract."""

    def assert_production_ready(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionAdapterConfig:
    """Secret-free release facts exposed to trusted adapter factories."""

    product_revision: str
    upstream_revision: str
    image_digest: str
    runtime_version: str
    adapter_contract_version: str
    public_origin: str
    capabilities: frozenset[str]
    preview_root_domain: str | None
    preview_lease_seconds: int

    @classmethod
    def from_server_config(cls, config: ProductionServerConfig) -> ProductionAdapterConfig:
        return cls(
            product_revision=config.product_revision,
            upstream_revision=config.upstream_revision,
            image_digest=config.image_digest,
            runtime_version=config.runtime_version,
            adapter_contract_version=config.adapter_contract_version,
            public_origin=config.public_origin,
            capabilities=config.capabilities,
            preview_root_domain=config.preview_root_domain,
            preview_lease_seconds=config.preview_lease_seconds,
        )


class SplitAuthorityApiCredentialService:
    """Route bearer validation and credential governance to distinct logins."""

    def __init__(
        self,
        *,
        authenticator: ApiCredentialService,
        governance: ApiCredentialService,
    ) -> None:
        self._authenticator = authenticator
        self._governance = governance

    @staticmethod
    def is_api_credential(token: str) -> bool:
        return ApiCredentialService.is_api_credential(token)

    def authenticate(self, token: str, *, source_ip: str | None) -> Any:
        return self._authenticator.authenticate(token, source_ip=source_ip)

    def require_permission(self, principal: Any, **scope: Any) -> None:
        self._authenticator.require_permission(principal, **scope)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        # All public methods not explicitly recognized above are lifecycle or
        # management mutations and therefore belong to saas_governance.
        return getattr(self._governance, name)


DatabaseStateVerifier = Callable[[Mapping[str, Engine], ProductionServerConfig], None]
ReadinessCheck = Callable[[], None]


@dataclass(frozen=True, slots=True)
class ProductionExternalAdapters:
    """Optional deployment adapters, mandatory when their capability is advertised."""

    runner: ProductionExternalAdapter | None = None
    preview: ProductionExternalAdapter | None = None


@dataclass(slots=True)
class RoleSessionFactories:
    """Runtime and control-plane connections bound to five distinct service logins."""

    runtime_engine: Engine
    authenticator: sessionmaker[Session]
    app: sessionmaker[Session]
    governance: sessionmaker[Session]
    public_api: sessionmaker[Session]
    _engines: tuple[Engine, ...] = field(repr=False)
    _readiness_engines: Mapping[str, Engine] = field(
        default_factory=dict,
        repr=False,
    )

    def __post_init__(self) -> None:
        factories = (self.authenticator, self.app, self.governance, self.public_api)
        if any(not callable(factory) for factory in factories):
            raise TypeError("role Session factories must be callable")
        binds = tuple(factory.kw.get("bind") for factory in factories)
        if any(bind is None for bind in binds) or len({id(bind) for bind in binds}) != len(binds):
            raise ProductionServerCompositionError(
                "authenticator, app, governance, and public API require distinct engines"
            )
        if self.runtime_engine in binds:
            raise ProductionServerCompositionError(
                "official runtime and SaaS control-plane roles require distinct engines"
            )
        if self._readiness_engines:
            expected_roles = set(self.engines)
            if set(self._readiness_engines) != expected_roles:
                raise ProductionServerCompositionError(
                    "readiness engines must cover the exact five service roles"
                )
            readiness_ids = {id(engine) for engine in self._readiness_engines.values()}
            business_ids = {id(engine) for engine in self.engines.values()}
            if len(readiness_ids) != len(expected_roles) or readiness_ids & business_ids:
                raise ProductionServerCompositionError(
                    "readiness engines must be distinct from every business engine"
                )

    @property
    def engines(self) -> Mapping[str, Engine]:
        """Expose engines by reviewed role for verify-only startup checks."""

        return MappingProxyType(
            {
                "runtime": self.runtime_engine,
                "authenticator": cast(Engine, self.authenticator.kw["bind"]),
                "app": cast(Engine, self.app.kw["bind"]),
                "governance": cast(Engine, self.governance.kw["bind"]),
                "public_api": cast(Engine, self.public_api.kw["bind"]),
            }
        )

    def close(self) -> None:
        """Dispose only engines created for this process."""

        engines = (*self._engines, *self._readiness_engines.values())
        for engine in {id(value): value for value in engines}.values():
            engine.dispose()

    @property
    def readiness_engines(self) -> Mapping[str, Engine]:
        """Return isolated, low-budget probe engines when production built them."""

        return self._readiness_engines or self.engines


class ProductionReadiness:
    """Content-blind, bounded, single-flight readiness checks."""

    def __init__(
        self,
        checks: Mapping[str, ReadinessCheck],
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        if not checks or any(not name or not callable(check) for name, check in checks.items()):
            raise ValueError("production readiness checks are invalid")
        if not 0.01 <= timeout_seconds < 2.5:
            raise ValueError("production readiness timeout is invalid")
        self._checks = MappingProxyType(dict(checks))
        self._timeout_seconds = timeout_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=len(checks),
            thread_name_prefix="omnigent-readiness",
        )
        self._inflight: dict[str, Future[bool]] = {}
        self._lock = Lock()
        self._closed = False

    @staticmethod
    def _evaluate(check: ReadinessCheck) -> bool:
        try:
            check()
        except Exception:  # noqa: BLE001 - readiness must redact provider errors.
            return False
        return True

    def failures(self) -> tuple[str, ...]:
        """Return failed names within one shared deadline and never queue duplicates."""

        with self._lock:
            if self._closed:
                return tuple(sorted(self._checks))
            futures: dict[str, Future[bool]] = {}
            for name, check in self._checks.items():
                future = self._inflight.get(name)
                if future is None:
                    future = self._executor.submit(self._evaluate, check)
                    self._inflight[name] = future
                futures[name] = future
        done, _pending = wait(futures.values(), timeout=self._timeout_seconds)
        failed = [
            name for name, future in futures.items() if future not in done or not future.result()
        ]
        with self._lock:
            for name, future in futures.items():
                if future.done() and self._inflight.get(name) is future:
                    self._inflight.pop(name, None)
        return tuple(sorted(failed))

    def assert_ready(self) -> None:
        """Fail composition when any mandatory dependency is unavailable."""

        failed = self.failures()
        if failed:
            raise ProductionServerCompositionError(
                "required production dependencies are not ready: " + ", ".join(failed)
            )

    def close(self) -> None:
        """Cancel queued checks and prevent any new readiness work."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._executor.shutdown(wait=False, cancel_futures=True)


@dataclass(slots=True)
class ProductionSaasServices:
    """SaaS integration plus owned readiness and onboarding authorities."""

    integration: SaasHttpIntegration
    readiness: ProductionReadiness
    onboarding: ProductionOnboardingHttpServices | None = field(
        default=None,
        repr=False,
    )
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        """Idempotently release every process-owned dependency."""

        if self._closed:
            return
        self._closed = True
        try:
            self.readiness.close()
        finally:
            if self.onboarding is not None:
                self.onboarding.close()


@dataclass(slots=True)
class PrivateArtifactCacheDirectory:
    """Locked per-process cache directory and its inode-pinning descriptors."""

    path: Path
    root_fd: int = field(repr=False)
    child_fd: int = field(repr=False)
    child_name: str

    def close(self) -> None:
        """Remove only this exact private child, then release both descriptors."""

        if self.child_fd < 0:
            return
        try:
            with suppress(FileNotFoundError):
                shutil.rmtree(self.child_name, dir_fd=self.root_fd)
        finally:
            os.close(self.child_fd)
            os.close(self.root_fd)
            self.child_fd = -1
            self.root_fd = -1


@dataclass(frozen=True, slots=True)
class OfficialRuntimeDependencies:
    """Official ``create_app`` dependencies constructed without migrations."""

    agent_store: Any
    file_store: Any
    conversation_store: Any
    artifact_store: Any
    agent_cache: Any
    comment_store: Any
    permission_store: Any
    policy_store: Any
    host_store: Any
    scheduled_task_store: Any | None
    project_store: Any
    artifact_readiness_check: ReadinessCheck = field(repr=False)
    sandbox_config: Any = None
    server_config: Mapping[str, Any] = field(default_factory=dict, repr=False)
    _artifact_cache: PrivateArtifactCacheDirectory | None = field(default=None, repr=False)

    def as_app_dependencies(self) -> dict[str, Any]:
        """Return the exact official factory keyword contract."""

        return {
            "agent_store": self.agent_store,
            "file_store": self.file_store,
            "conversation_store": self.conversation_store,
            "artifact_store": self.artifact_store,
            "agent_cache": self.agent_cache,
            "comment_store": self.comment_store,
            "permission_store": self.permission_store,
            "policy_store": self.policy_store,
            "host_store": self.host_store,
            "scheduled_task_store": self.scheduled_task_store,
            "project_store": self.project_store,
            "sandbox_config": self.sandbox_config,
            "server_config": dict(self.server_config),
        }

    def close(self) -> None:
        """Release the fd that pins the private per-process cache directory."""

        if self._artifact_cache is not None:
            self._artifact_cache.close()
            object.__setattr__(self, "_artifact_cache", None)


@dataclass(slots=True)
class BuiltProductionServer:
    """Fully composed app plus bind settings and owned connection lifecycle."""

    app: FastAPI
    host: str
    port: int
    sessions: RoleSessionFactories
    official: OfficialRuntimeDependencies
    services: ProductionSaasServices

    def close(self) -> None:
        try:
            self.services.close()
            self.official.close()
        finally:
            self.sessions.close()


def verify_installed_build_lineage(config: ProductionServerConfig) -> None:
    """Bind the runtime process to the wheel/image commit before any DB connect."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise ProductionServerCompositionError(
            "installed build revision is unavailable"
        ) from error
    if installed_revision != config.product_revision:
        raise ProductionServerCompositionError(
            "installed build revision does not match the configured product revision"
        )


def _call_factory(factory: Callable[..., Any], config: ProductionAdapterConfig) -> Any:
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):
        raise ProductionServerCompositionError(
            "external adapter factory is not inspectable"
        ) from None
    parameters = signature.parameters
    if "config" in parameters or any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    ):
        return factory(config=config)
    required = [
        parameter
        for parameter in parameters.values()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if required:
        raise ProductionServerCompositionError(
            "external adapter factory must be zero-argument or accept config"
        )
    return factory()


def load_external_adapter(
    reference: str,
    config: ProductionServerConfig,
) -> ProductionExternalAdapter:
    """Load one deployment-trusted ``module:attribute`` adapter factory."""

    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise ProductionServerCompositionError("external adapter factory reference is invalid")
    adapter_config = ProductionAdapterConfig.from_server_config(config)
    try:
        candidate = getattr(importlib.import_module(module_name), attribute_name)
        if isinstance(candidate, type):
            candidate = _call_factory(candidate, adapter_config)
        if callable(getattr(candidate, "assert_production_ready", None)):
            adapter = candidate
        elif callable(getattr(candidate, "build", None)):
            adapter = _call_factory(candidate.build, adapter_config)
        elif callable(candidate):
            adapter = _call_factory(candidate, adapter_config)
        else:
            adapter = candidate
    except ProductionServerCompositionError:
        raise
    except Exception:  # noqa: BLE001 - redact deployment-owned adapter diagnostics.
        # Deployment adapter diagnostics can include endpoint or provider
        # material.  The public startup error is intentionally content-blind.
        raise ProductionServerCompositionError("external adapter factory failed") from None
    if not callable(getattr(adapter, "assert_production_ready", None)):
        raise ProductionServerCompositionError(
            "external adapter factory returned an incomplete adapter"
        )
    return cast(ProductionExternalAdapter, adapter)


def load_external_adapters(config: ProductionServerConfig) -> ProductionExternalAdapters:
    """Load only adapters enabled by the immutable capability profile."""

    return ProductionExternalAdapters(
        runner=(
            load_external_adapter(config.runner_adapter_factory, config)
            if config.runner_adapter_factory is not None
            else None
        ),
        preview=(
            load_external_adapter(config.preview_adapter_factory, config)
            if config.preview_adapter_factory is not None
            else None
        ),
    )


def _load_official_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or not 0 < metadata.st_size <= 16 * 1024
            ):
                raise ProductionServerCompositionError(
                    "official server config integrity is invalid"
                )
            raw = os.read(descriptor, metadata.st_size + 1)
        finally:
            os.close(descriptor)
        document = yaml.safe_load(raw.decode("utf-8"))
    except ProductionServerCompositionError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError):
        # YAML parser diagnostics may echo the malformed line.  The config is
        # required to be non-secret, but suppress chaining to keep that
        # invariant true even for an operator mistake.
        raise ProductionServerCompositionError("official server config cannot be loaded") from None
    if document is None:
        return {}
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise ProductionServerCompositionError("official server config must contain a mapping")
    if not set(document).issubset(_PRODUCTION_OFFICIAL_CONFIG_KEYS):
        raise ProductionServerCompositionError(
            "official server config contains an unsupported production field"
        )
    llm = document.get("llm")
    if llm is not None and (
        not isinstance(llm, dict)
        or not all(isinstance(key, str) for key in llm)
        or not set(llm).issubset(_PRODUCTION_LLM_KEYS)
    ):
        raise ProductionServerCompositionError(
            "official server LLM config contains an unsupported production field"
        )
    _reject_secret_official_config(document)
    _reject_ambient_official_models(document)
    return cast(dict[str, Any], document)


def _reject_secret_official_config(value: object) -> None:
    """Reject secret/provider selection and environment expansion recursively."""

    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ProductionServerCompositionError(
                    "official server config must use string keys"
                )
            normalized = key.lower().replace("-", "_")
            if (
                normalized in _SECRET_CONFIG_KEYS
                or normalized.endswith(_SECRET_CONFIG_KEY_SUFFIXES)
                or normalized.endswith("_env")
            ):
                raise ProductionServerCompositionError(
                    "official server config must not contain secret or provider authority"
                )
            _reject_secret_official_config(nested)
        return
    if isinstance(value, list):
        for nested in value:
            _reject_secret_official_config(nested)
        return
    if isinstance(value, str) and "${" in value:
        raise ProductionServerCompositionError(
            "official server config must not expand process environment"
        )


def _reject_ambient_official_models(value: object) -> None:
    """Reject every official policy/LLM model that requires ambient cloud auth."""

    if isinstance(value, dict):
        for key, nested in value.items():
            models: list[object] = []
            if key == "model":
                models.append(nested)
            elif key == "fallback_models" and isinstance(nested, list):
                models.extend(nested)
            if any(
                isinstance(model, str) and model.partition("/")[0] in _AMBIENT_ONLY_LLM_PROVIDERS
                for model in models
            ):
                raise ProductionServerCompositionError(
                    "official server LLM config requires an unsupported ambient provider"
                )
            _reject_ambient_official_models(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_ambient_official_models(nested)


def lock_down_ambient_cloud_file_providers(
    environment: MutableMapping[str, str],
) -> None:
    """Pin boto, Google ADC, and Databricks file providers to an empty device.

    The production config loader rejects caller-supplied values for these
    variables.  Setting fixed values only after validation also closes the
    implicit ``~/.aws`` and legacy boto config paths for any later dependency
    that constructs a boto client without explicit credentials.
    """

    if environment.get("AWS_EC2_METADATA_DISABLED") != "true" or any(
        name in environment for name in _AMBIENT_CLOUD_FILE_PROVIDER_LOCKS
    ):
        raise ProductionServerCompositionError(
            "ambient AWS credential providers were not validated"
        )
    environment.update(_AMBIENT_CLOUD_FILE_PROVIDER_LOCKS)


def _new_engine(database_url: str) -> Engine:
    return sa.create_engine(database_url, pool_pre_ping=True)


def _new_readiness_engine(database_url: str) -> Engine:
    return sa.create_engine(
        database_url,
        poolclass=NullPool,
        connect_args={
            "connect_timeout": 1,
            "options": "-c statement_timeout=1000 -c lock_timeout=1000",
            "tcp_user_timeout": 1000,
        },
    )


def create_role_session_factories(
    config: ProductionServerConfig,
    *,
    verify_state: DatabaseStateVerifier,
    engine_factory: Callable[[str], Engine] = _new_engine,
    readiness_engine_factory: Callable[[str], Engine] | None = None,
) -> RoleSessionFactories:
    """Open service-login engines, verify current state, and never migrate it."""

    urls = config.secrets.database_urls.as_mapping()
    created: list[Engine] = []
    readiness_created: list[Engine] = []
    try:
        engines: dict[str, Engine] = {}
        readiness_engines: dict[str, Engine] = {}
        probe_factory = readiness_engine_factory or (
            _new_readiness_engine if engine_factory is _new_engine else engine_factory
        )
        for role, database_url in urls.items():
            engine = engine_factory(database_url)
            if engine.dialect.name != "postgresql":
                raise ProductionServerCompositionError(f"{role} service login must use PostgreSQL")
            created.append(engine)
            engines[role] = engine
            readiness_engine = probe_factory(database_url)
            if readiness_engine.dialect.name != "postgresql":
                raise ProductionServerCompositionError(
                    f"{role} readiness login must use PostgreSQL"
                )
            readiness_created.append(readiness_engine)
            readiness_engines[role] = readiness_engine
        verify_state(MappingProxyType(engines), config)
        return RoleSessionFactories(
            runtime_engine=engines["runtime"],
            authenticator=sessionmaker(engines["authenticator"], expire_on_commit=False),
            app=sessionmaker(engines["app"], expire_on_commit=False),
            governance=sessionmaker(engines["governance"], expire_on_commit=False),
            public_api=sessionmaker(engines["public_api"], expire_on_commit=False),
            _engines=tuple(created),
            _readiness_engines=MappingProxyType(readiness_engines),
        )
    except Exception:
        for engine in (*created, *readiness_created):
            engine.dispose()
        raise


def open_private_artifact_cache_directory(
    root: Path,
    *,
    product_revision: str,
) -> PrivateArtifactCacheDirectory:
    """Create and fd-pin a new empty cache directory for one server process.

    The official cache trusts an already published ``agent_id`` directory.
    Reusing a path across processes would therefore turn derived cache bytes
    into an authority.  The configured root must be owned by this uid with
    exact mode 0700, and every process receives an unguessable empty child.
    On Linux the returned ``/proc/self/fd`` path remains bound to the opened
    inode even if a path component is renamed after validation.  Platforms
    whose descriptor filesystem cannot traverse directory descriptors receive
    an absolute fallback path only after reopening it and matching its inode to
    the pinned descriptor; the owner-only locked root remains held for life.
    """

    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise ProductionServerCompositionError("artifact cache root cannot be created") from error

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root_fd = os.open(root, flags)
    except OSError as error:
        raise ProductionServerCompositionError("artifact cache root is unsafe") from error
    child_fd: int | None = None
    child_name: str | None = None
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ProductionServerCompositionError(
                "artifact cache root is already owned by another process"
            ) from None
        root_state = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_state.st_mode)
            or root_state.st_uid != os.geteuid()
            or stat.S_IMODE(root_state.st_mode) != 0o700
        ):
            raise ProductionServerCompositionError(
                "artifact cache root must be an owner-only directory"
            )
        for stale_name in os.listdir(root_fd):
            if re.fullmatch(r"[0-9a-f]{12}-[0-9a-f]{32}", stale_name) is None:
                raise ProductionServerCompositionError(
                    "artifact cache root contains an unrecognized entry"
                )
            stale_state = os.stat(stale_name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(stale_state.st_mode)
                or stale_state.st_uid != os.geteuid()
                or stat.S_IMODE(stale_state.st_mode) != 0o700
            ):
                raise ProductionServerCompositionError(
                    "artifact cache root contains an unsafe stale entry"
                )
            shutil.rmtree(stale_name, dir_fd=root_fd)
        for _attempt in range(64):
            child_name = f"{product_revision[:12]}-{secrets.token_hex(16)}"
            try:
                os.mkdir(child_name, mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            child_fd = os.open(child_name, flags, dir_fd=root_fd)
            break
        if child_fd is None:
            raise ProductionServerCompositionError(
                "private artifact cache directory could not be allocated"
            )
        child_state = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(child_state.st_mode)
            or child_state.st_uid != os.geteuid()
            or stat.S_IMODE(child_state.st_mode) != 0o700
        ):
            raise ProductionServerCompositionError("private artifact cache directory is unsafe")
        assert child_name is not None
        descriptor_path: Path | None = None
        probe_name = f".fd-path-probe-{secrets.token_hex(8)}"
        probe_fd = os.open(
            probe_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=child_fd,
        )
        os.close(probe_fd)
        try:
            for descriptor_root in (Path("/proc/self/fd"), Path("/dev/fd")):
                candidate = descriptor_root / str(child_fd)
                try:
                    with (candidate / probe_name).open("rb"):
                        pass
                except OSError:
                    continue
                descriptor_path = candidate
                break
        finally:
            os.unlink(probe_name, dir_fd=child_fd)
        if descriptor_path is None:
            fallback_path = root / child_name
            fallback_fd = os.open(fallback_path, flags)
            try:
                fallback_state = os.fstat(fallback_fd)
                if (fallback_state.st_dev, fallback_state.st_ino) != (
                    child_state.st_dev,
                    child_state.st_ino,
                ):
                    raise ProductionServerCompositionError(
                        "private artifact cache fallback changed after validation"
                    )
            finally:
                os.close(fallback_fd)
            descriptor_path = fallback_path
        return PrivateArtifactCacheDirectory(
            path=descriptor_path,
            root_fd=root_fd,
            child_fd=child_fd,
            child_name=child_name,
        )
    except Exception:
        if child_fd is not None:
            os.close(child_fd)
        if child_name is not None:
            with suppress(FileNotFoundError):
                shutil.rmtree(child_name, dir_fd=root_fd)
        os.close(root_fd)
        raise


def build_official_runtime_dependencies(
    config: ProductionServerConfig,
) -> OfficialRuntimeDependencies:
    """Construct official stores/caps with a narrow runtime login and no migration call."""

    from omnigent.runtime import init as init_runtime
    from omnigent.runtime.agent_cache import AgentCache
    from omnigent.runtime.caps import RuntimeCaps
    from omnigent.server.managed_hosts import parse_sandbox_config
    from omnigent.spec import parse_default_policies, parse_server_llm
    from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
    from omnigent.stores.comment_store.sqlalchemy_store import SqlAlchemyCommentStore
    from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
    from omnigent.stores.file_store.sqlalchemy_store import SqlAlchemyFileStore
    from omnigent.stores.host_store import HostStore
    from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore
    from omnigent.stores.policy_store.sqlalchemy_store import SqlAlchemyPolicyStore
    from omnigent.stores.project_store.sqlalchemy_store import SqlAlchemyProjectStore
    from saas.production.artifact_store import build_production_s3_artifact_store

    database_url = config.secrets.database_urls.runtime
    official_config = _load_official_config(config.official_config_path)
    cache = open_private_artifact_cache_directory(
        config.artifact_cache_dir,
        product_revision=config.product_revision,
    )
    try:
        built_artifact_store = build_production_s3_artifact_store(config)
        artifact_store = built_artifact_store.store
        agent_store = SqlAlchemyAgentStore(database_url)
        file_store = SqlAlchemyFileStore(database_url)
        conversation_store = SqlAlchemyConversationStore(database_url)
        comment_store = SqlAlchemyCommentStore(database_url)
        permission_store = SqlAlchemyPermissionStore(database_url)
        policy_store = SqlAlchemyPolicyStore(database_url)
        host_store = HostStore(database_url)
        project_store = SqlAlchemyProjectStore(database_url)
        agent_cache = AgentCache(
            artifact_store=artifact_store,
            cache_dir=cache.path,
        )
        caps = RuntimeCaps(
            execution_timeout=int(official_config.get("execution_timeout") or 7200),
            default_policies=parse_default_policies(
                official_config.get("policies"), expand_env=False
            ),
            llm=parse_server_llm(official_config.get("llm"), expand_env=False),
        )
        init_runtime(
            agent_cache=agent_cache,
            caps=caps,
            agent_store=agent_store,
            file_store=file_store,
            conversation_store=conversation_store,
            artifact_store=artifact_store,
            comment_store=comment_store,
            policy_store=policy_store,
        )
        return OfficialRuntimeDependencies(
            agent_store=agent_store,
            file_store=file_store,
            conversation_store=conversation_store,
            artifact_store=artifact_store,
            agent_cache=agent_cache,
            comment_store=comment_store,
            permission_store=permission_store,
            policy_store=policy_store,
            host_store=host_store,
            # The official scheduler performs a context-free all-workspace scan.
            # Production recurring execution remains disabled until a SaaS-owned
            # scheduler can enumerate and bind one reviewed RuntimeContext at a time.
            scheduled_task_store=None,
            project_store=project_store,
            artifact_readiness_check=built_artifact_store.assert_ready,
            sandbox_config=parse_sandbox_config(official_config.get("sandbox")),
            server_config=official_config,
            _artifact_cache=cache,
        )
    except Exception:
        cache.close()
        raise


def _database_check(factory: sessionmaker[Session]) -> ReadinessCheck:
    def check() -> None:
        with factory() as database:
            database.execute(sa.text("SELECT 1"))

    return check


def _runtime_database_check(engine: Engine) -> ReadinessCheck:
    def check() -> None:
        with engine.connect() as connection:
            connection.execute(sa.text("SELECT 1"))

    return check


def _external_check(adapter: ProductionExternalAdapter) -> ReadinessCheck:
    return adapter.assert_production_ready


def _production_router(
    config: ProductionServerConfig,
    readiness: ProductionReadiness,
) -> APIRouter:
    router = APIRouter()

    @router.get("/readyz", include_in_schema=False, response_model=None)
    def readyz(response: Response) -> dict[str, object] | JSONResponse:
        failed = readiness.failures()
        if failed:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "failed_dependencies": list(failed)},
                headers={"Cache-Control": "no-store"},
            )
        response.headers["Cache-Control"] = "no-store"
        return {"status": "ready"}

    @router.get("/version", include_in_schema=False)
    def version(response: Response) -> dict[str, object]:
        response.headers["Cache-Control"] = "no-store"
        return dict(config.version_document)

    return router


def build_production_saas_services(
    config: ProductionServerConfig,
    sessions: RoleSessionFactories,
    *,
    external: ProductionExternalAdapters | None = None,
    onboarding: ProductionOnboardingHttpServices | None = None,
    extra_readiness_checks: Mapping[str, ReadinessCheck] | None = None,
) -> ProductionSaasServices:
    """Build Tenant authentication, onboarding, and stable public Run API services."""

    adapters = external or ProductionExternalAdapters()
    checks: dict[str, ReadinessCheck] = {
        f"database.{role}": _runtime_database_check(engine)
        for role, engine in sessions.readiness_engines.items()
    }
    for capability, adapter in (("runner", adapters.runner), ("preview", adapters.preview)):
        if capability in config.capabilities:
            if adapter is None:
                raise ProductionServerCompositionError(
                    f"required {capability} production adapter is not configured"
                )
            checks[f"external.{capability}"] = _external_check(adapter)
    if extra_readiness_checks:
        overlap = set(checks).intersection(extra_readiness_checks)
        if overlap:
            raise ProductionServerCompositionError(
                "duplicate readiness check names: " + ", ".join(sorted(overlap))
            )
        checks.update(extra_readiness_checks)

    lifecycle = MembershipLifecycleService(sessions.authenticator)
    identities = IdentityManagementService(sessions.authenticator)
    passwords = PasswordCredentialService(sessions.authenticator)
    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({config.runtime_version}),
        allowed_source_revisions=frozenset({config.upstream_revision}),
        allowed_schema_revisions=frozenset({config.official_schema_revision}),
        adapter_contract_version=config.adapter_contract_version,
    )
    context_resolver = SqlAlchemyContextResolver(sessions.app, policy)
    context_snapshots = ContextSnapshotService(
        ContextSnapshotPolicy(
            active_key_id=config.active_key_id,
            keys={config.active_key_id: config.secrets.context_snapshot_key},
            issuer=f"{config.public_origin}/saas",
            audience=config.public_origin,
            ttl=timedelta(seconds=config.snapshot_ttl_seconds),
        )
    )
    # Credential lifecycle is a governance mutation; public Run transactions
    # use the separate saas_public_api login below.  The existing integration
    # deliberately shares one ApiCredentialService between management and
    # bearer validation, so governance is the least authority that supports
    # the whole mounted contract without a hidden privilege escalation.
    api_credentials = SplitAuthorityApiCredentialService(
        authenticator=ApiCredentialService(
            sessions.authenticator,
            credential_pepper=config.secrets.api_credential_pepper,
        ),
        governance=ApiCredentialService(
            sessions.governance,
            credential_pepper=config.secrets.api_credential_pepper,
        ),
    )
    public_execution = PublicApiExecutionService(
        sessions.public_api,
        cursor_codec=FilterBoundCursorCodec(
            keys={config.active_key_id: config.secrets.cursor_hmac_key},
            active_key_id=config.active_key_id,
        ),
        idempotency_keys={config.active_key_id: config.secrets.idempotency_hmac_key},
        active_idempotency_key_id=config.active_key_id,
        product_revision=config.product_revision,
        upstream_revision=config.upstream_revision,
        schema_revision=config.official_schema_revision,
        adapter_contract_version=config.adapter_contract_version,
    )
    availability = ControlPlaneAvailabilityGate()
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        context_resolver=context_resolver,
        cookie_config=SaasCookieConfig(
            name=config.cookie_name,
            secure=True,
            same_site="lax",
            ttl=timedelta(seconds=config.session_ttl_seconds),
            trusted_origins=frozenset({config.public_origin}),
        ),
        context_snapshots=context_snapshots,
        availability_gate=availability,
        runtime_store_adapter=OmnigentStoreAdapter(config.adapter_contract_version),
        api_credentials=cast(ApiCredentialService, api_credentials),
        public_api_execution=public_execution,
        onboarding=None if onboarding is None else onboarding.onboarding,
        onboarding_status=None if onboarding is None else onboarding.onboarding_status,
        onboarding_client_network=(
            None if onboarding is None else onboarding.onboarding_client_network
        ),
    )
    if "preview" in config.capabilities:
        from saas.production.preview_control import (
            ProductionPreviewControlPolicy,
            build_production_preview_control_router,
        )

        if config.preview_root_domain is None:
            raise ProductionServerCompositionError(
                "Preview capability requires a cookie-isolated root domain"
            )
        if config.secrets.preview_exchange_hmac_key is None:
            raise ProductionServerCompositionError(
                "Preview capability requires a dedicated exchange authority"
            )
        integration.router.include_router(
            build_production_preview_control_router(
                auth_provider=integration.auth_provider,
                resolver=context_resolver,
                sessions=sessions.app,
                policy=ProductionPreviewControlPolicy.from_origins(
                    primary_origin=config.public_origin,
                    preview_root_domain=config.preview_root_domain,
                    lease_seconds=config.preview_lease_seconds,
                    exchange_hmac_key=config.secrets.preview_exchange_hmac_key,
                ),
            )
        )
    readiness = ProductionReadiness(checks)
    # The readiness/version endpoints are SaaS-owned and therefore live below
    # the existing /saas router; no competing official router is introduced.
    integration.router.include_router(_production_router(config, readiness))
    try:
        readiness.assert_ready()
    except Exception:
        readiness.close()
        raise
    return ProductionSaasServices(
        integration=integration,
        readiness=readiness,
        onboarding=onboarding,
    )


def build_production_server(
    config: ProductionServerConfig,
    sessions: RoleSessionFactories,
    *,
    official: OfficialRuntimeDependencies | None = None,
    external: ProductionExternalAdapters | None = None,
    onboarding: ProductionOnboardingHttpServices | None = None,
    extra_readiness_checks: Mapping[str, ReadinessCheck] | None = None,
) -> BuiltProductionServer:
    """Build the app only after every mandatory dependency passes readiness."""

    official_dependencies = official or build_official_runtime_dependencies(config)
    readiness_checks = dict(extra_readiness_checks or {})
    if "artifact_store" in readiness_checks:
        raise ProductionServerCompositionError(
            "artifact-store readiness authority cannot be overridden"
        )
    readiness_checks["artifact_store"] = official_dependencies.artifact_readiness_check
    try:
        services = build_production_saas_services(
            config,
            sessions,
            external=external,
            onboarding=onboarding,
            extra_readiness_checks=readiness_checks,
        )
    except Exception:
        official_dependencies.close()
        if onboarding is not None:
            onboarding.close()
        raise
    app_dependencies = official_dependencies.as_app_dependencies()
    # These official lifespan jobs run before request middleware can bind a
    # RuntimeContext. Keep both disabled in production even when a caller
    # injects an otherwise valid official dependency bundle.
    if (
        config.official_builtin_agent_seed_enabled
        or config.official_cross_workspace_scheduler_enabled
    ):
        services.close()
        official_dependencies.close()
        raise ProductionServerCompositionError(
            "context-free official lifespan jobs cannot be enabled in production"
        )
    app_dependencies["scheduled_task_store"] = None
    try:
        app = create_omnigent_saas_app(
            integration=services.integration,
            suppress_context_free_builtin_seed=True,
            **app_dependencies,
        )
    except Exception:
        services.close()
        official_dependencies.close()
        raise
    app.state.production_saas_readiness = services.readiness
    app.state.production_saas_version = dict(config.version_document)
    app.state.production_saas_services = services
    return BuiltProductionServer(
        app=app,
        host=config.host,
        port=config.port,
        sessions=sessions,
        official=official_dependencies,
        services=services,
    )


def _verify_postgresql_state(
    engines: Mapping[str, Engine],
    config: ProductionServerConfig,
) -> None:
    """Call the migration module's verify-only contract; never its mutation entrypoint."""

    from saas.production.postgresql_migration import verify_production_postgresql_state

    verify_production_postgresql_state(engines=engines, config=config)


def main() -> None:
    """Load, verify, compose, and serve; no import or migration side effects."""

    config = load_production_server_config()
    # This check is intentionally first: a stale/wrong image must not open a
    # database connection merely to discover it cannot serve this release.
    verify_installed_build_lineage(config)
    lock_down_ambient_cloud_file_providers(os.environ)
    external = load_external_adapters(config)
    sessions = create_role_session_factories(config, verify_state=_verify_postgresql_state)
    built: BuiltProductionServer | None = None
    try:
        onboarding = build_production_onboarding_http_services()
        built = build_production_server(
            config,
            sessions,
            external=external,
            onboarding=onboarding,
        )
        import uvicorn

        from omnigent.runner.transports.ws_tunnel.limits import (
            RUNNER_TUNNEL_MAX_MESSAGE_BYTES,
        )

        logger.info(
            "starting production SaaS server revision=%s bind=%s:%d",
            config.product_revision,
            built.host,
            built.port,
        )
        uvicorn.run(
            built.app,
            host=built.host,
            port=built.port,
            ws_max_size=RUNNER_TUNNEL_MAX_MESSAGE_BYTES,
        )
    finally:
        if built is not None:
            built.close()
        else:
            sessions.close()


if __name__ == "__main__":
    main()


__all__ = [
    "BuiltProductionServer",
    "DatabaseStateVerifier",
    "OfficialRuntimeDependencies",
    "ProductionAdapterConfig",
    "ProductionExternalAdapter",
    "ProductionExternalAdapters",
    "ProductionReadiness",
    "ProductionSaasServices",
    "ProductionServerCompositionError",
    "RoleSessionFactories",
    "SplitAuthorityApiCredentialService",
    "build_official_runtime_dependencies",
    "build_production_saas_services",
    "build_production_server",
    "create_role_session_factories",
    "load_external_adapter",
    "load_external_adapters",
    "lock_down_ambient_cloud_file_providers",
    "main",
    "verify_installed_build_lineage",
]
