"""P4 server-owned Sandbox, Secret Broker, Egress, and Preview authority."""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import NoReturn, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import ControlPlaneOutboxEvent, ProjectRecord
from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.isolation_models import (
    CREDENTIAL_SCHEMES,
    EgressPolicyRecord,
    ExecutionProfileRecord,
    PreviewLeaseRecord,
    RunIsolationGrantRecord,
    SecretAccessLeaseRecord,
    SecretBindingRecord,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling import SchedulingControlPlane, SchedulingError
from saas.control_plane.scheduling_models import RunDispatchRecord, RunnerRegistrationRecord
from saas.control_plane.worktree_models import WorktreeInstanceRecord
from saas.control_plane.worktrees import WorktreeMaterializationGrant

_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EGRESS_RULE = re.compile(
    r"^(?P<methods>\*|(?:GET|HEAD|POST|PUT|PATCH|DELETE)(?:,(?:GET|HEAD|POST|PUT|PATCH|DELETE))*) "
    r"(?P<host>[A-Za-z0-9*.-]{1,253})(?P<path>/[^?#\\ ]*)$"
)
_ACTIVE_RUN_STATUSES = frozenset(
    {"leased", "starting", "running", "waiting_input", "waiting_approval", "cancelling"}
)
_ACTIVE_WORKTREE_STATUSES = frozenset({"materializing", "ready", "checkpointing"})
_REQUIRED_RUNNER_CAPABILITY_PREFIXES = (
    "sandbox.readonly_root",
    "sandbox.nonroot",
    "sandbox.no_new_privileges",
    "sandbox.no_host_socket",
    "sandbox.resource_limits",
    "egress.proxy",
    "secret.broker",
)
_PREVIEW_RESPONSE_HEADERS = {
    "Content-Security-Policy": (
        "sandbox allow-scripts allow-forms allow-modals allow-popups; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_FORBIDDEN_PREVIEW_REQUEST_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-forwarded-access-token"}
)
_RUNNER_AGENT_LOGIN = re.compile(r"^runner_[0-9a-f]{32}_g[1-9][0-9]*$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _validate_time(value: datetime) -> None:
    if value.tzinfo is None:
        raise IsolationControlPlaneError("time_timezone_required", "time must include a timezone")


def _text(value: str, *, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} is invalid")
    return cleaned


def _opaque_ref(value: str, *, field: str, maximum: int = 256) -> str:
    cleaned = _text(value, field=field, maximum=maximum)
    if not _OPAQUE_REF.fullmatch(cleaned) or ".." in cleaned or cleaned.startswith("/"):
        raise IsolationControlPlaneError(
            f"{field}_invalid", f"{field} must be an opaque provider reference"
        )
    return cleaned


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _token_hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _normalized_tools(values: tuple[str, ...] | list[str], *, field: str) -> tuple[str, ...]:
    normalized = tuple(sorted(set(values)))
    if any(not _TOOL_NAME.fullmatch(value) for value in normalized):
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} contains an invalid tool")
    return normalized


def _normalize_hostname(value: str, *, field: str) -> str:
    cleaned = _text(value, field=field, maximum=253).rstrip(".").lower()
    try:
        encoded = cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} is invalid") from exc
    if (
        not encoded
        or ":" in encoded
        or "@" in encoded
        or encoded == "localhost"
        or encoded.endswith((".localhost", ".local"))
        or encoded in {"metadata.google.internal", "instance-data.ec2.internal"}
    ):
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} is not a public host")
    try:
        ipaddress.ip_address(encoded)
    except ValueError:
        pass
    else:
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} must not be an IP literal")
    labels = encoded.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        raise IsolationControlPlaneError(f"{field}_invalid", f"{field} is invalid")
    return encoded


def _normalize_egress_rules(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for raw in values:
        match = _EGRESS_RULE.fullmatch(raw.strip())
        if match is None:
            raise IsolationControlPlaneError(
                "egress_rule_invalid", "egress rules must use 'METHODS host/path' syntax"
            )
        raw_host = match.group("host").lower().rstrip(".")
        wildcard = raw_host.startswith("*.")
        if "*" in raw_host[2:] or ("*" in raw_host and not wildcard):
            raise IsolationControlPlaneError(
                "egress_rule_invalid", "egress host wildcards are limited to the leftmost label"
            )
        host = _normalize_hostname(raw_host[2:] if wildcard else raw_host, field="egress_host")
        path = match.group("path")
        if ".." in path or len(path) > 1024:
            raise IsolationControlPlaneError("egress_rule_invalid", "egress path is invalid")
        methods = match.group("methods")
        if methods != "*":
            methods = ",".join(sorted(set(methods.split(","))))
        normalized.add(f"{methods} {'*.' if wildcard else ''}{host}{path}")
    return tuple(sorted(normalized))


def _rule_allows_host(rule: str, host: str) -> bool:
    match = _EGRESS_RULE.fullmatch(rule)
    if match is None:
        return False
    rule_host = match.group("host")
    return host == rule_host or (rule_host.startswith("*.") and host.endswith(rule_host[1:]))


def _set_token_rls(db: Session, setting: str, digest: str) -> None:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(sa.select(sa.func.set_config(setting, digest, True)))


class IsolationControlPlaneError(RuntimeError):
    """Stable fail-closed error surface for isolation and Preview operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SecretValueProvider(Protocol):
    """Resolve a secret inside the trusted broker process only."""

    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str: ...


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    allowed: tuple[str, ...]
    approval_required: tuple[str, ...]
    denied: tuple[str, ...]

    def evaluate(self, tool_name: str) -> str:
        """Return allow, approval, or deny; unknown tools default to deny."""

        if tool_name in self.denied or tool_name not in self.allowed:
            return "deny"
        if tool_name in self.approval_required:
            return "approval"
        return "allow"


@dataclass(frozen=True, slots=True)
class SandboxLaunchContract:
    backend: str
    network_mode: str
    root_read_only: bool
    run_as_uid: int
    run_as_gid: int
    no_new_privileges: bool
    host_socket_access: bool
    syscall_profile_ref: str
    cpu_millis: int
    memory_bytes: int
    pids_limit: int
    tool_policy: ToolPolicy
    egress_rules: tuple[str, ...]
    allow_private_destinations: bool
    required_runner_capabilities: tuple[str, ...]
    config_hash: str


@dataclass(frozen=True, slots=True)
class IssuedIsolationGrant:
    grant_id: UUID
    token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SecretLeaseReference:
    binding_id: UUID
    name: str
    host: str
    credential_scheme: str
    username: str | None
    inject_env: tuple[str, ...]
    token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TrustedRunnerLaunchGrant:
    grant_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    run_id: UUID
    runner_id: UUID
    worktree_id: UUID
    worktree_access_mode: str
    worktree_lease_generation: int
    run_fence_token: int
    runner_connection_generation: int
    contract: SandboxLaunchContract
    secret_leases: tuple[SecretLeaseReference, ...]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SecretMaterial:
    binding_id: UUID
    name: str
    host: str
    credential_scheme: str
    username: str | None
    inject_env: tuple[str, ...]
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PreviewOriginConfig:
    primary_origin: str
    primary_cookie_domain: str
    preview_root_domain: str
    maximum_lease: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        try:
            primary = urlsplit(self.primary_origin)
            primary_port = primary.port
        except ValueError as exc:
            raise IsolationControlPlaneError(
                "primary_origin_invalid", "primary origin must be an HTTPS origin"
            ) from exc
        if (
            primary.scheme != "https"
            or not primary.hostname
            or primary.path not in {"", "/"}
            or primary.username
            or primary.password
            or primary.query
            or primary.fragment
            or primary_port not in {None, 443}
        ):
            raise IsolationControlPlaneError(
                "primary_origin_invalid", "primary origin must be an HTTPS origin"
            )
        primary_host = _normalize_hostname(primary.hostname, field="primary_origin_host")
        cookie_domain = _normalize_hostname(
            self.primary_cookie_domain.lstrip("."), field="primary_cookie_domain"
        )
        preview_root = _normalize_hostname(self.preview_root_domain, field="preview_root_domain")
        if not (primary_host == cookie_domain or primary_host.endswith(f".{cookie_domain}")):
            raise IsolationControlPlaneError(
                "primary_cookie_domain_invalid", "primary cookie domain does not own the origin"
            )
        if (
            preview_root == cookie_domain
            or preview_root.endswith(f".{cookie_domain}")
            or cookie_domain.endswith(f".{preview_root}")
        ):
            raise IsolationControlPlaneError(
                "preview_origin_not_isolated",
                "Preview root must be outside the primary cookie domain",
            )
        if self.maximum_lease <= timedelta(0) or self.maximum_lease > timedelta(hours=1):
            raise IsolationControlPlaneError(
                "preview_lease_limit_invalid", "Preview maximum lease is invalid"
            )


@dataclass(frozen=True, slots=True)
class IssuedPreviewLease:
    preview_id: UUID
    url: str
    host: str
    token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PreviewRouteGrant:
    preview_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    runner_id: UUID
    runner_connection_generation: int
    run_id: UUID
    run_fence_token: int
    worktree_id: UUID
    worktree_lease_generation: int
    opaque_preview_key: str
    preview_token_hash: str = field(repr=False)
    upstream_request_headers: dict[str, str]
    response_headers: dict[str, str]
    expires_at: datetime
    preview_host: str = ""


class IsolationControlPlane:
    """Own server-chosen isolation facts while official code owns sandbox primitives."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        authorizer: ProjectAuthorizer | None = None,
        scheduler: SchedulingControlPlane | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer or ProjectAuthorizer(session_factory)
        self._scheduler = scheduler or SchedulingControlPlane(session_factory)
        bind = session_factory.kw.get("bind")
        self._runner_rpc = bool(
            bind is not None
            and bind.dialect.name == "postgresql"
            and _RUNNER_AGENT_LOGIN.fullmatch(bind.url.username or "")
        )

    def create_egress_policy(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        name: str,
        rules: tuple[str, ...] | list[str],
        version: int = 1,
    ) -> UUID:
        """Create a default-deny policy; private and metadata destinations stay blocked."""

        self._authorizer.require(request, action="egress.policy.manage", project_id=project_id)
        normalized = _normalize_egress_rules(rules)
        if version <= 0:
            raise IsolationControlPlaneError("egress_policy_version_invalid", "version is invalid")
        policy_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            db.add(
                EgressPolicyRecord(
                    id=policy_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    created_by=request.actor_id,
                    name=_text(name, field="egress_policy_name", maximum=128),
                    rules=list(normalized),
                    rules_hash=_canonical_hash(normalized),
                    allow_private_destinations=False,
                    status="active",
                    version=version,
                )
            )
        return policy_id

    def create_execution_profile(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        egress_policy_id: UUID,
        name: str,
        sandbox_backend: str,
        syscall_profile_ref: str,
        cpu_millis: int,
        memory_bytes: int,
        pids_limit: int,
        allowed_tools: tuple[str, ...] | list[str],
        approval_required_tools: tuple[str, ...] | list[str] = (),
        denied_tools: tuple[str, ...] | list[str] = (),
        version: int = 1,
    ) -> UUID:
        """Create a hardened profile; callers cannot request a soft or unsandboxed mode."""

        self._authorizer.require(request, action="environment.manage", project_id=project_id)
        if sandbox_backend not in {"linux_bwrap", "darwin_seatbelt"}:
            raise IsolationControlPlaneError(
                "sandbox_backend_denied", "managed Runs require a hard-enforcing backend"
            )
        if cpu_millis <= 0 or memory_bytes <= 0 or pids_limit <= 0 or version <= 0:
            raise IsolationControlPlaneError(
                "sandbox_resource_limit_invalid", "sandbox resource limits are invalid"
            )
        allowed = _normalized_tools(allowed_tools, field="allowed_tools")
        approvals = _normalized_tools(approval_required_tools, field="approval_required_tools")
        denied = _normalized_tools(denied_tools, field="denied_tools")
        if not allowed or set(approvals) - set(allowed) or set(denied) & set(allowed):
            raise IsolationControlPlaneError(
                "tool_policy_invalid", "tool policy sets must be non-empty and non-conflicting"
            )
        config = {
            "sandbox_backend": sandbox_backend,
            "network_mode": "proxy_only",
            "root_read_only": True,
            "run_as_uid": 65532,
            "run_as_gid": 65532,
            "no_new_privileges": True,
            "host_socket_access": False,
            "syscall_profile_ref": _opaque_ref(
                syscall_profile_ref, field="syscall_profile_ref", maximum=128
            ),
            "cpu_millis": cpu_millis,
            "memory_bytes": memory_bytes,
            "pids_limit": pids_limit,
            "allowed_tools": allowed,
            "approval_required_tools": approvals,
            "denied_tools": denied,
        }
        profile_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            # The Project row is the stable writer mutex for the partial
            # one-active-profile invariant.  It serializes concurrent profile
            # replacements before either writer can observe/retire the current
            # generation and insert its successor.
            project = db.scalar(
                sa.select(ProjectRecord)
                .where(
                    ProjectRecord.id == project_id,
                    ProjectRecord.tenant_id == request.tenant_id,
                    ProjectRecord.space_id == request.space_id,
                    ProjectRecord.status == "active",
                )
                .with_for_update()
            )
            if project is None:
                raise IsolationControlPlaneError("project_unavailable", "project is unavailable")
            policy = db.scalar(
                sa.select(EgressPolicyRecord)
                .where(EgressPolicyRecord.id == egress_policy_id)
                .with_for_update(read=True)
            )
            if (
                policy is None
                or policy.status != "active"
                or policy.tenant_id != request.tenant_id
                or policy.space_id != request.space_id
                or policy.project_id != project_id
                or policy.allow_private_destinations
            ):
                raise IsolationControlPlaneError(
                    "egress_policy_unavailable", "egress policy is unavailable"
                )
            active_profiles = tuple(
                db.scalars(
                    sa.select(ExecutionProfileRecord)
                    .where(
                        ExecutionProfileRecord.tenant_id == request.tenant_id,
                        ExecutionProfileRecord.space_id == request.space_id,
                        ExecutionProfileRecord.project_id == project_id,
                        ExecutionProfileRecord.status == "active",
                    )
                    .order_by(ExecutionProfileRecord.id)
                    .with_for_update()
                )
            )
            for active_profile in active_profiles:
                active_profile.status = "retired"
            db.add(
                ExecutionProfileRecord(
                    id=profile_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    egress_policy_id=policy.id,
                    created_by=request.actor_id,
                    name=_text(name, field="execution_profile_name", maximum=128),
                    sandbox_backend=sandbox_backend,
                    network_mode="proxy_only",
                    root_read_only=True,
                    run_as_uid=65532,
                    run_as_gid=65532,
                    no_new_privileges=True,
                    host_socket_access=False,
                    syscall_profile_ref=str(config["syscall_profile_ref"]),
                    cpu_millis=cpu_millis,
                    memory_bytes=memory_bytes,
                    pids_limit=pids_limit,
                    allowed_tools=list(allowed),
                    approval_required_tools=list(approvals),
                    denied_tools=list(denied),
                    config_hash=_canonical_hash(config),
                    status="active",
                    version=version,
                )
            )
        return profile_id

    def bind_secret(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        execution_profile_id: UUID,
        name: str,
        vault_provider: str,
        vault_ref: str,
        version_ref: str,
        credential_scheme: str,
        host: str,
        username: str | None = None,
        inject_env: tuple[str, ...] | list[str] = (),
        version: int = 1,
    ) -> UUID:
        """Bind vault metadata to an exact allowed host without reading plaintext."""

        self._authorizer.require(request, action="secret.manage", project_id=project_id)
        if credential_scheme not in CREDENTIAL_SCHEMES or version <= 0:
            raise IsolationControlPlaneError(
                "secret_binding_invalid", "secret credential scheme or version is invalid"
            )
        normalized_host = _normalize_hostname(host, field="secret_host")
        environment_names = tuple(sorted(set(inject_env)))
        if any(not _ENV_NAME.fullmatch(value) for value in environment_names):
            raise IsolationControlPlaneError(
                "secret_inject_env_invalid", "secret environment placeholder name is invalid"
            )
        metadata = {
            "name": _text(name, field="secret_name", maximum=128),
            "vault_provider": _opaque_ref(vault_provider, field="vault_provider", maximum=64),
            "vault_ref": _opaque_ref(vault_ref, field="vault_ref"),
            "version_ref": _opaque_ref(version_ref, field="secret_version_ref", maximum=128),
            "credential_scheme": credential_scheme,
            "host": normalized_host,
            "username": (
                _text(username, field="secret_username", maximum=128) if username else None
            ),
            "inject_env": environment_names,
        }
        binding_id = uuid4()
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            profile = db.get(ExecutionProfileRecord, execution_profile_id)
            policy = (
                db.get(EgressPolicyRecord, profile.egress_policy_id)
                if profile is not None
                else None
            )
            if (
                profile is None
                or policy is None
                or profile.status != "active"
                or policy.status != "active"
                or profile.tenant_id != request.tenant_id
                or profile.space_id != request.space_id
                or profile.project_id != project_id
                or not any(_rule_allows_host(rule, normalized_host) for rule in policy.rules)
            ):
                raise IsolationControlPlaneError(
                    "secret_egress_binding_denied",
                    "secret host is not allowed by the active egress policy",
                )
            db.add(
                SecretBindingRecord(
                    id=binding_id,
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    execution_profile_id=execution_profile_id,
                    created_by=request.actor_id,
                    name=str(metadata["name"]),
                    vault_provider=str(metadata["vault_provider"]),
                    vault_ref=str(metadata["vault_ref"]),
                    version_ref=str(metadata["version_ref"]),
                    credential_scheme=credential_scheme,
                    host=normalized_host,
                    username=metadata["username"]
                    if isinstance(metadata["username"], str)
                    else None,
                    inject_env=list(environment_names),
                    metadata_hash=_canonical_hash(metadata),
                    status="active",
                    version=version,
                )
            )
        return binding_id

    def issue_launch_grant(
        self,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        worktree_grant: WorktreeMaterializationGrant,
        lifetime: timedelta = timedelta(seconds=60),
        now: datetime | None = None,
    ) -> IssuedIsolationGrant:
        """Issue one-time launch authority bound to the active Run and Worktree fences."""

        issued_at = now or _utcnow()
        _validate_time(issued_at)
        if lifetime <= timedelta(0) or lifetime > timedelta(minutes=2):
            raise IsolationControlPlaneError(
                "isolation_grant_lifetime_invalid", "isolation grant lifetime is invalid"
            )
        if worktree_grant.runner_id != runner_id or worktree_grant.run_id != run_id:
            raise IsolationControlPlaneError(
                "isolation_worktree_binding_invalid", "Worktree grant binding is invalid"
            )
        if self._runner_rpc:
            return self._issue_postgresql_runner_grant(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                worktree_grant=worktree_grant,
                lifetime=lifetime,
            )
        try:
            capability = self._scheduler.verify_capability(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                action="sandbox.launch",
                required_resource_scope={"change_set_id": str(worktree_grant.change_set_id)},
                now=issued_at,
            )
        except SchedulingError as exc:
            raise IsolationControlPlaneError(exc.code, str(exc)) from exc
        if (
            capability.tenant_id is None
            or capability.space_id is None
            or capability.project_id is None
            or capability.fence_token != worktree_grant.run_fence_token
        ):
            raise IsolationControlPlaneError(
                "isolation_capability_scope_invalid", "capability scope is invalid"
            )
        raw_token = f"iso_{secrets.token_urlsafe(40)}"
        expires_at = min(issued_at + lifetime, capability.expires_at)
        grant_id = uuid4()
        with self._session_factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=capability.tenant_id,
                    space_id=capability.space_id,
                    project_id=capability.project_id,
                    actor_id=None,
                ),
            )
            dispatch = db.scalar(
                sa.select(RunDispatchRecord)
                .where(RunDispatchRecord.run_id == run_id)
                .with_for_update()
            )
            if (
                dispatch is None
                or dispatch.status != "leased"
                or dispatch.selected_runner_id != runner_id
            ):
                raise IsolationControlPlaneError(
                    "isolation_dispatch_profile_unbound",
                    "leased dispatch has no authoritative execution profile binding",
                )
            run = db.scalar(sa.select(RunRecord).where(RunRecord.id == run_id).with_for_update())
            binding = db.execute(
                SchedulingControlPlane._dispatch_profile_query(
                    dispatch.execution_profile_id,
                    dispatch.egress_policy_id,
                ).with_for_update(read=True)
            ).one_or_none()
            profile, policy = binding if binding is not None else (None, None)
            runner = db.get(RunnerRegistrationRecord, runner_id)
            worktree = db.get(WorktreeInstanceRecord, worktree_grant.worktree_id)
            required_capabilities = self._required_runner_capabilities(profile)
            expected_requirements_hash = dispatch_requirements_hash(
                tenant_id=dispatch.tenant_id,
                space_id=dispatch.space_id,
                project_id=dispatch.project_id,
                pool_id=dispatch.pool_id,
                execution_profile_id=dispatch.execution_profile_id,
                execution_profile_hash=dispatch.execution_profile_hash,
                egress_policy_id=dispatch.egress_policy_id,
                egress_policy_hash=dispatch.egress_policy_hash,
                queue_class=dispatch.queue_class,
                required_capabilities=dispatch.required_capabilities,
                cost_units=dispatch.cost_units,
                eligible_at=dispatch.eligible_at,
                max_wait_at=dispatch.max_wait_at,
            )
            if (
                run is None
                or run.status not in _ACTIVE_RUN_STATUSES
                or run.fence_token != capability.fence_token
                or run.tenant_id != capability.tenant_id
                or run.space_id != capability.space_id
                or run.project_id != capability.project_id
                or profile is None
                or policy is None
                or profile.config_hash != dispatch.execution_profile_hash
                or policy.rules_hash != dispatch.egress_policy_hash
                or profile.egress_policy_id != policy.id
                or dispatch.requirements_hash != expected_requirements_hash
                or profile.status not in {"active", "retired"}
                or policy.status not in {"active", "retired"}
                or policy.allow_private_destinations
                or profile.tenant_id != capability.tenant_id
                or profile.space_id != capability.space_id
                or profile.project_id != capability.project_id
                or policy.tenant_id != capability.tenant_id
                or policy.space_id != capability.space_id
                or policy.project_id != capability.project_id
                or runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != worktree_grant.runner_connection_generation
                or worktree is None
                or worktree.status not in _ACTIVE_WORKTREE_STATUSES
                or worktree.tenant_id != capability.tenant_id
                or worktree.space_id != capability.space_id
                or worktree.project_id != capability.project_id
                or worktree.run_id != run_id
                or worktree.runner_id != runner_id
                or worktree.change_set_id != worktree_grant.change_set_id
                or worktree.lease_generation != worktree_grant.lease_generation
                or worktree.run_fence_token != worktree_grant.run_fence_token
                or worktree.runner_connection_generation
                != worktree_grant.runner_connection_generation
                or not set(required_capabilities).issubset(set(dispatch.required_capabilities))
                or not set(required_capabilities).issubset(set(runner.capabilities))
            ):
                raise IsolationControlPlaneError(
                    "isolation_profile_or_runner_unavailable",
                    "profile, Runner attestation, or Worktree fence is unavailable",
                )
            grant_payload = {
                "grant_id": str(grant_id),
                "tenant_id": str(capability.tenant_id),
                "space_id": str(capability.space_id),
                "project_id": str(capability.project_id),
                "run_id": str(run_id),
                "runner_id": str(runner_id),
                "worktree_id": str(worktree.id),
                "profile_id": str(profile.id),
                "profile_hash": profile.config_hash,
                "egress_policy_id": str(policy.id),
                "egress_policy_hash": policy.rules_hash,
                "run_fence_token": capability.fence_token,
                "runner_connection_generation": runner.connection_generation,
                "worktree_lease_generation": worktree.lease_generation,
                "expires_at": expires_at.isoformat(),
            }
            db.add(
                RunIsolationGrantRecord(
                    id=grant_id,
                    token_hash=_token_hash(raw_token),
                    tenant_id=capability.tenant_id,
                    space_id=capability.space_id,
                    project_id=capability.project_id,
                    run_id=run_id,
                    runner_id=runner_id,
                    worktree_id=worktree.id,
                    execution_profile_id=profile.id,
                    capability_id=capability.capability_id,
                    run_fence_token=capability.fence_token,
                    runner_connection_generation=runner.connection_generation,
                    worktree_lease_generation=worktree.lease_generation,
                    grant_hash=_canonical_hash(grant_payload),
                    status="active",
                    expires_at=expires_at,
                )
            )
            self._append_outbox(
                db,
                tenant_id=capability.tenant_id,
                aggregate_type="RunIsolationGrant",
                aggregate_key=str(grant_id),
                event_type="run.isolation_grant.issued",
                payload={
                    "grant_id": str(grant_id),
                    "run_id": str(run_id),
                    "runner_id": str(runner_id),
                    "worktree_id": str(worktree.id),
                    "execution_profile_id": str(profile.id),
                    "expires_at": expires_at.isoformat(),
                },
                idempotency_key=f"run-isolation:{grant_id}:issued",
            )
        return IssuedIsolationGrant(grant_id, raw_token, expires_at)

    def redeem_launch_grant(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        now: datetime | None = None,
    ) -> TrustedRunnerLaunchGrant:
        """Redeem once and mint per-binding, one-time Secret Broker leases."""

        redeemed_at = now or _utcnow()
        _validate_time(redeemed_at)
        if self._runner_rpc:
            return self._redeem_postgresql_runner_grant(
                token=token,
                runner_id=runner_id,
                run_id=run_id,
            )
        digest = _token_hash(_text(token, field="isolation_grant_token", maximum=512))
        with self._session_factory.begin() as db:
            _set_token_rls(db, "app.isolation_token_hash", digest)
            record = db.scalar(
                sa.select(RunIsolationGrantRecord)
                .where(RunIsolationGrantRecord.token_hash == digest)
                .with_for_update()
            )
            if record is None or not hmac.compare_digest(record.token_hash, digest):
                raise IsolationControlPlaneError(
                    "isolation_grant_invalid", "isolation grant is invalid"
                )
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=record.tenant_id,
                    space_id=record.space_id,
                    project_id=record.project_id,
                    actor_id=None,
                ),
            )
            if (
                record.status != "active"
                or _aware(record.expires_at) <= redeemed_at
                or record.runner_id != runner_id
                or record.run_id != run_id
            ):
                raise IsolationControlPlaneError(
                    "isolation_grant_stale", "isolation grant is expired, used, or misbound"
                )
            run = db.scalar(sa.select(RunRecord).where(RunRecord.id == run_id).with_for_update())
            dispatch = db.scalar(
                sa.select(RunDispatchRecord)
                .where(RunDispatchRecord.run_id == run_id)
                .with_for_update(read=True)
            )
            runner = db.get(RunnerRegistrationRecord, runner_id)
            worktree = db.get(WorktreeInstanceRecord, record.worktree_id)
            binding = (
                db.execute(
                    SchedulingControlPlane._dispatch_profile_query(
                        record.execution_profile_id,
                        dispatch.egress_policy_id,
                    ).with_for_update(read=True)
                ).one_or_none()
                if dispatch is not None
                else None
            )
            profile, policy = binding if binding is not None else (None, None)
            required_capabilities = self._required_runner_capabilities(profile)
            expected_requirements_hash = (
                dispatch_requirements_hash(
                    tenant_id=dispatch.tenant_id,
                    space_id=dispatch.space_id,
                    project_id=dispatch.project_id,
                    pool_id=dispatch.pool_id,
                    execution_profile_id=dispatch.execution_profile_id,
                    execution_profile_hash=dispatch.execution_profile_hash,
                    egress_policy_id=dispatch.egress_policy_id,
                    egress_policy_hash=dispatch.egress_policy_hash,
                    queue_class=dispatch.queue_class,
                    required_capabilities=dispatch.required_capabilities,
                    cost_units=dispatch.cost_units,
                    eligible_at=dispatch.eligible_at,
                    max_wait_at=dispatch.max_wait_at,
                )
                if dispatch is not None
                else None
            )
            if (
                run is None
                or run.status not in _ACTIVE_RUN_STATUSES
                or run.fence_token != record.run_fence_token
                or run.lease_expires_at is None
                or _aware(run.lease_expires_at) <= redeemed_at
                or run.tenant_id != record.tenant_id
                or run.space_id != record.space_id
                or run.project_id != record.project_id
                or dispatch is None
                or dispatch.status != "leased"
                or dispatch.selected_runner_id != runner_id
                or dispatch.execution_profile_id != record.execution_profile_id
                or dispatch.requirements_hash != expected_requirements_hash
                or runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != record.runner_connection_generation
                or not set(required_capabilities).issubset(set(runner.capabilities))
                or worktree is None
                or worktree.status not in _ACTIVE_WORKTREE_STATUSES
                or worktree.lease_generation != record.worktree_lease_generation
                or worktree.run_fence_token != record.run_fence_token
                or worktree.runner_connection_generation != record.runner_connection_generation
                or profile is None
                or profile.status not in {"active", "retired"}
                or profile.config_hash != dispatch.execution_profile_hash
                or policy is None
                or policy.status not in {"active", "retired"}
                or policy.allow_private_destinations
                or policy.rules_hash != dispatch.egress_policy_hash
                or profile.egress_policy_id != policy.id
                or profile.tenant_id != record.tenant_id
                or profile.space_id != record.space_id
                or profile.project_id != record.project_id
                or policy.tenant_id != record.tenant_id
                or policy.space_id != record.space_id
                or policy.project_id != record.project_id
            ):
                raise IsolationControlPlaneError(
                    "isolation_fence_stale", "Run, Runner, Worktree, or profile fence is stale"
                )
            contract = self._contract(profile, policy, required_capabilities)
            secret_records = tuple(
                db.scalars(
                    sa.select(SecretBindingRecord)
                    .where(
                        SecretBindingRecord.execution_profile_id == profile.id,
                        SecretBindingRecord.status == "active",
                    )
                    .order_by(SecretBindingRecord.name, SecretBindingRecord.id)
                )
            )
            secret_leases: list[SecretLeaseReference] = []
            for binding in secret_records:
                raw_secret_token = f"sec_{secrets.token_urlsafe(40)}"
                lease = SecretAccessLeaseRecord(
                    token_hash=_token_hash(raw_secret_token),
                    tenant_id=record.tenant_id,
                    space_id=record.space_id,
                    project_id=record.project_id,
                    isolation_grant_id=record.id,
                    secret_binding_id=binding.id,
                    run_id=record.run_id,
                    runner_id=record.runner_id,
                    run_fence_token=record.run_fence_token,
                    runner_connection_generation=record.runner_connection_generation,
                    status="active",
                    expires_at=record.expires_at,
                )
                db.add(lease)
                db.flush()
                secret_leases.append(
                    SecretLeaseReference(
                        binding_id=binding.id,
                        name=binding.name,
                        host=binding.host,
                        credential_scheme=binding.credential_scheme,
                        username=binding.username,
                        inject_env=tuple(binding.inject_env),
                        token=raw_secret_token,
                        expires_at=_aware(lease.expires_at),
                    )
                )
            record.status = "redeemed"
            record.redeemed_at = redeemed_at
            self._append_outbox(
                db,
                tenant_id=record.tenant_id,
                aggregate_type="RunIsolationGrant",
                aggregate_key=str(record.id),
                event_type="run.isolation_grant.redeemed",
                payload={
                    "grant_id": str(record.id),
                    "run_id": str(record.run_id),
                    "runner_id": str(record.runner_id),
                    "worktree_id": str(record.worktree_id),
                    "secret_binding_count": len(secret_leases),
                },
                idempotency_key=f"run-isolation:{record.id}:redeemed",
            )
            return TrustedRunnerLaunchGrant(
                record.id,
                record.tenant_id,
                record.space_id,
                record.project_id,
                record.run_id,
                record.runner_id,
                record.worktree_id,
                worktree.access_mode,
                record.worktree_lease_generation,
                record.run_fence_token,
                record.runner_connection_generation,
                contract,
                tuple(secret_leases),
                _aware(record.expires_at),
            )

    def redeem_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
        now: datetime | None = None,
    ) -> SecretMaterial:
        """Resolve one secret once in the trusted broker; plaintext never reaches the database."""

        redeemed_at = now or _utcnow()
        _validate_time(redeemed_at)
        if self._runner_rpc:
            return self._redeem_postgresql_runner_secret(
                token=token,
                runner_id=runner_id,
                run_id=run_id,
                provider=provider,
            )
        digest = _token_hash(_text(token, field="secret_lease_token", maximum=512))
        material: SecretMaterial
        with self._session_factory.begin() as db:
            _set_token_rls(db, "app.secret_token_hash", digest)
            lease = db.scalar(
                sa.select(SecretAccessLeaseRecord)
                .where(SecretAccessLeaseRecord.token_hash == digest)
                .with_for_update()
            )
            if lease is None or not hmac.compare_digest(lease.token_hash, digest):
                raise IsolationControlPlaneError("secret_lease_invalid", "secret lease is invalid")
            apply_rls_context(
                db,
                RlsContext(tenant_id=lease.tenant_id, space_id=lease.space_id, actor_id=None),
            )
            run = db.get(RunRecord, lease.run_id)
            runner = db.get(RunnerRegistrationRecord, lease.runner_id)
            binding = db.get(SecretBindingRecord, lease.secret_binding_id)
            if (
                lease.status != "active"
                or _aware(lease.expires_at) <= redeemed_at
                or lease.runner_id != runner_id
                or lease.run_id != run_id
                or run is None
                or run.status not in _ACTIVE_RUN_STATUSES
                or run.fence_token != lease.run_fence_token
                or runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != lease.runner_connection_generation
                or binding is None
                or binding.status != "active"
            ):
                raise IsolationControlPlaneError(
                    "secret_lease_stale", "secret lease or distributed fence is stale"
                )
            value = provider.resolve(
                provider=binding.vault_provider,
                vault_ref=binding.vault_ref,
                version_ref=binding.version_ref,
            ).strip()
            if not value or len(value) > 65536:
                raise IsolationControlPlaneError(
                    "secret_material_invalid", "secret provider returned invalid material"
                )
            lease.status = "redeemed"
            lease.redeemed_at = redeemed_at
            self._append_outbox(
                db,
                tenant_id=lease.tenant_id,
                aggregate_type="SecretAccessLease",
                aggregate_key=str(lease.id),
                event_type="secret.access.redeemed",
                payload={
                    "lease_id": str(lease.id),
                    "binding_id": str(binding.id),
                    "run_id": str(lease.run_id),
                    "runner_id": str(lease.runner_id),
                    "host": binding.host,
                },
                idempotency_key=f"secret-access:{lease.id}:redeemed",
            )
            material = SecretMaterial(
                binding.id,
                binding.name,
                binding.host,
                binding.credential_scheme,
                binding.username,
                tuple(binding.inject_env),
                value,
            )
        return material

    def issue_preview_lease(
        self,
        request: RequestContext,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        worktree_grant: WorktreeMaterializationGrant,
        origin: PreviewOriginConfig,
        lifetime: timedelta,
        now: datetime | None = None,
    ) -> IssuedPreviewLease:
        """Issue a short-lived public route on a root outside the SaaS cookie domain."""

        issued_at = now or _utcnow()
        _validate_time(issued_at)
        project_id = request.project_id
        if project_id is None:
            raise IsolationControlPlaneError("preview_project_required", "Preview needs a Project")
        self._authorizer.require(request, action="preview.open", project_id=project_id)
        if lifetime <= timedelta(0) or lifetime > origin.maximum_lease:
            raise IsolationControlPlaneError(
                "preview_lifetime_invalid", "Preview lifetime is invalid"
            )
        try:
            capability = self._scheduler.verify_capability(
                capability_token=capability_token,
                runner_id=runner_id,
                run_id=run_id,
                action="preview.serve",
                # The scheduling capability already binds the exact
                # Tenant/Space/Project/Run/Runner/fence. The trusted Worktree
                # grant below independently binds its ChangeSet to the same
                # Run/Runner/fence, so a caller-selected ChangeSet scope is
                # neither necessary nor available at fair-claim time.
                required_resource_scope={"run_id": str(run_id)},
                now=issued_at,
            )
        except SchedulingError as exc:
            raise IsolationControlPlaneError(exc.code, str(exc)) from exc
        if (
            capability.tenant_id != request.tenant_id
            or capability.space_id != request.space_id
            or capability.project_id != project_id
            or worktree_grant.runner_id != runner_id
            or worktree_grant.run_id != run_id
            or worktree_grant.run_fence_token != capability.fence_token
        ):
            raise IsolationControlPlaneError(
                "preview_scope_invalid", "Preview scope or distributed fence is invalid"
            )
        opaque_key = f"pvr_{secrets.token_hex(24)}"
        preview_root = _normalize_hostname(origin.preview_root_domain, field="preview_root_domain")
        preview_host = f"pv-{opaque_key[4:28]}.{preview_root}"
        raw_token = f"pv_{secrets.token_urlsafe(40)}"
        expires_at = min(issued_at + lifetime, capability.expires_at)
        preview_id = uuid4()
        response_hash = _canonical_hash(_PREVIEW_RESPONSE_HEADERS)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            worktree = db.get(WorktreeInstanceRecord, worktree_grant.worktree_id)
            runner = db.get(RunnerRegistrationRecord, runner_id)
            if (
                worktree is None
                or worktree.status != "ready"
                or worktree.tenant_id != request.tenant_id
                or worktree.space_id != request.space_id
                or worktree.project_id != project_id
                or worktree.run_id != run_id
                or worktree.runner_id != runner_id
                or worktree.change_set_id != worktree_grant.change_set_id
                or worktree.lease_generation != worktree_grant.lease_generation
                or worktree.run_fence_token != capability.fence_token
                or runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != worktree_grant.runner_connection_generation
            ):
                raise IsolationControlPlaneError(
                    "preview_target_unavailable", "Preview Worktree or Runner is unavailable"
                )
            db.add(
                PreviewLeaseRecord(
                    id=preview_id,
                    token_hash=_token_hash(raw_token),
                    tenant_id=request.tenant_id,
                    space_id=request.space_id,
                    project_id=project_id,
                    run_id=run_id,
                    runner_id=runner_id,
                    worktree_id=worktree.id,
                    created_by=request.actor_id,
                    opaque_preview_key=opaque_key,
                    preview_host=preview_host,
                    run_fence_token=capability.fence_token,
                    runner_connection_generation=runner.connection_generation,
                    worktree_lease_generation=worktree.lease_generation,
                    response_policy_hash=response_hash,
                    status="active",
                    expires_at=expires_at,
                )
            )
            self._append_outbox(
                db,
                tenant_id=request.tenant_id,
                aggregate_type="PreviewLease",
                aggregate_key=str(preview_id),
                event_type="preview.lease.issued",
                payload={
                    "preview_id": str(preview_id),
                    "run_id": str(run_id),
                    "worktree_id": str(worktree.id),
                    "preview_host": preview_host,
                    "expires_at": expires_at.isoformat(),
                },
                idempotency_key=f"preview:{preview_id}:issued",
            )
        return IssuedPreviewLease(
            preview_id,
            f"https://{preview_host}/",
            preview_host,
            raw_token,
            expires_at,
        )

    def authorize_preview_request(
        self,
        *,
        host: str,
        token: str,
        incoming_headers: dict[str, str],
        now: datetime | None = None,
    ) -> PreviewRouteGrant:
        """Authorize an exact host/token route and strip all ambient SaaS credentials."""

        accessed_at = now or _utcnow()
        _validate_time(accessed_at)
        normalized_host = _normalize_hostname(host, field="preview_host")
        normalized_headers = {key.lower(): value for key, value in incoming_headers.items()}
        if any(
            normalized_headers.get(name, "").strip() for name in _FORBIDDEN_PREVIEW_REQUEST_HEADERS
        ):
            raise IsolationControlPlaneError(
                "preview_ambient_credential_denied",
                "Preview requests must not carry SaaS cookies or authorization headers",
            )
        digest = _token_hash(_text(token, field="preview_access_token", maximum=512))
        with self._session_factory.begin() as db:
            _set_token_rls(db, "app.preview_token_hash", digest)
            record = db.scalar(
                sa.select(PreviewLeaseRecord)
                .where(PreviewLeaseRecord.token_hash == digest)
                .with_for_update()
            )
            if record is None or not hmac.compare_digest(record.token_hash, digest):
                raise IsolationControlPlaneError(
                    "preview_token_invalid", "Preview token is invalid"
                )
            apply_rls_context(
                db,
                RlsContext(tenant_id=record.tenant_id, space_id=record.space_id, actor_id=None),
            )
            run = db.get(RunRecord, record.run_id)
            runner = db.get(RunnerRegistrationRecord, record.runner_id)
            worktree = db.get(WorktreeInstanceRecord, record.worktree_id)
            if (
                record.status != "active"
                or _aware(record.expires_at) <= accessed_at
                or record.preview_host != normalized_host
                or record.response_policy_hash != _canonical_hash(_PREVIEW_RESPONSE_HEADERS)
                or run is None
                or run.status not in _ACTIVE_RUN_STATUSES
                or run.fence_token != record.run_fence_token
                or runner is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != record.runner_connection_generation
                or worktree is None
                or worktree.status != "ready"
                or worktree.lease_generation != record.worktree_lease_generation
                or worktree.run_fence_token != record.run_fence_token
            ):
                raise IsolationControlPlaneError(
                    "preview_lease_stale", "Preview lease or distributed fence is stale"
                )
            record.last_accessed_at = accessed_at
            safe_headers = {
                key: value
                for key, value in normalized_headers.items()
                if key
                in {
                    "accept",
                    "accept-encoding",
                    "accept-language",
                    "content-type",
                    "user-agent",
                }
            }
            return PreviewRouteGrant(
                preview_id=record.id,
                tenant_id=record.tenant_id,
                space_id=record.space_id,
                project_id=record.project_id,
                runner_id=record.runner_id,
                runner_connection_generation=record.runner_connection_generation,
                run_id=record.run_id,
                run_fence_token=record.run_fence_token,
                worktree_id=record.worktree_id,
                worktree_lease_generation=record.worktree_lease_generation,
                opaque_preview_key=record.opaque_preview_key,
                preview_token_hash=record.token_hash,
                upstream_request_headers=safe_headers,
                response_headers=dict(_PREVIEW_RESPONSE_HEADERS),
                expires_at=_aware(record.expires_at),
            )

    def revoke_preview_lease(
        self,
        request: RequestContext,
        *,
        preview_id: UUID,
        now: datetime | None = None,
    ) -> bool:
        """Revoke a Preview lease idempotently."""

        revoked_at = now or _utcnow()
        _validate_time(revoked_at)
        project_id = request.project_id
        if project_id is None:
            raise IsolationControlPlaneError("preview_project_required", "Preview needs a Project")
        self._authorizer.require(request, action="preview.open", project_id=project_id)
        with self._session_factory.begin() as db:
            self._apply_request_context(db, request)
            record = db.scalar(
                sa.select(PreviewLeaseRecord)
                .where(PreviewLeaseRecord.id == preview_id)
                .with_for_update()
            )
            if record is None:
                raise IsolationControlPlaneError(
                    "preview_not_found", "Preview lease was not found"
                )
            if record.status == "revoked":
                return False
            record.status = "revoked"
            record.revoked_at = revoked_at
            self._append_outbox(
                db,
                tenant_id=record.tenant_id,
                aggregate_type="PreviewLease",
                aggregate_key=str(record.id),
                event_type="preview.lease.revoked",
                payload={"preview_id": str(record.id), "run_id": str(record.run_id)},
                idempotency_key=f"preview:{record.id}:revoked",
            )
            return True

    def _issue_postgresql_runner_grant(
        self,
        *,
        capability_token: str,
        runner_id: UUID,
        run_id: UUID,
        worktree_grant: WorktreeMaterializationGrant,
        lifetime: timedelta,
    ) -> IssuedIsolationGrant:
        lifetime_seconds = max(1, int(lifetime.total_seconds()))
        request_identity = json.dumps(
            {
                "lifetime_seconds": lifetime_seconds,
                "run_fence_token": worktree_grant.run_fence_token,
                "run_id": str(run_id),
                "runner_id": str(runner_id),
                "worktree_id": str(worktree_grant.worktree_id),
                "worktree_lease_generation": worktree_grant.lease_generation,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        identity_key = capability_token.encode()
        grant_id = UUID(
            bytes=hmac.new(
                identity_key,
                b"omnigent-isolation-grant-id-v1\x00" + request_identity,
                sha256,
            ).digest()[:16],
            version=4,
        )
        raw_token = (
            f"iso_{grant_id.hex}_"
            + hmac.new(
                identity_key,
                b"omnigent-isolation-grant-token-v1\x00" + request_identity,
                sha256,
            ).hexdigest()
        )
        try:
            with self._session_factory.begin() as db:
                row = (
                    db.execute(
                        sa.text(
                            "SELECT * FROM public.saas_runner_issue_isolation_grant_v1("
                            ":capability_hash, :runner_id, :run_id, :worktree_id, "
                            ":worktree_generation, :run_fence, :grant_id, :grant_hash, "
                            ":lifetime_seconds)"
                        ),
                        {
                            "capability_hash": _token_hash(capability_token),
                            "runner_id": runner_id,
                            "run_id": run_id,
                            "worktree_id": worktree_grant.worktree_id,
                            "worktree_generation": worktree_grant.lease_generation,
                            "run_fence": worktree_grant.run_fence_token,
                            "grant_id": grant_id,
                            "grant_hash": _token_hash(raw_token),
                            "lifetime_seconds": lifetime_seconds,
                        },
                    )
                    .mappings()
                    .one()
                )
        except sa.exc.DBAPIError as exc:
            self._raise_runner_rpc_error(exc)
        return IssuedIsolationGrant(
            UUID(str(row["grant_id"])),
            raw_token,
            _aware(row["expires_at"]),
        )

    def _redeem_postgresql_runner_grant(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
    ) -> TrustedRunnerLaunchGrant:
        raw_token = _text(token, field="isolation_grant_token", maximum=512)
        digest = _token_hash(raw_token)
        try:
            with self._session_factory.begin() as db:
                metadata = db.scalar(
                    sa.text(
                        "SELECT public.saas_runner_isolation_metadata_v1("
                        ":token_hash, :runner_id, :run_id)"
                    ),
                    {"token_hash": digest, "runner_id": runner_id, "run_id": run_id},
                )
            snapshot = cast(dict[str, object], metadata)
            bindings = cast(list[dict[str, object]], snapshot["secret_bindings"])
            commitments: list[dict[str, str]] = []
            secret_tokens: dict[UUID, str] = {}
            for binding in bindings:
                binding_id = UUID(str(binding["binding_id"]))
                binding_identity = (
                    f"{snapshot['grant_id']}|{binding_id}|{run_id}|{runner_id}"
                ).encode()
                lease_id = UUID(
                    bytes=hmac.new(
                        raw_token.encode(),
                        b"omnigent-secret-lease-id-v1\x00" + binding_identity,
                        sha256,
                    ).digest()[:16],
                    version=4,
                )
                secret_token = (
                    "sec_"
                    + hmac.new(
                        raw_token.encode(),
                        b"omnigent-secret-lease-token-v1\x00" + binding_identity,
                        sha256,
                    ).hexdigest()
                )
                commitments.append(
                    {
                        "binding_id": str(binding_id),
                        "lease_id": str(lease_id),
                        "token_hash": _token_hash(secret_token),
                    }
                )
                secret_tokens[binding_id] = secret_token
            with self._session_factory.begin() as db:
                redeemed = db.scalar(
                    sa.text(
                        "SELECT public.saas_runner_redeem_isolation_grant_v1("
                        ":token_hash, :runner_id, :run_id, CAST(:commitments AS jsonb))"
                    ),
                    {
                        "token_hash": digest,
                        "runner_id": runner_id,
                        "run_id": run_id,
                        "commitments": json.dumps(
                            commitments, sort_keys=True, separators=(",", ":")
                        ),
                    },
                )
        except sa.exc.DBAPIError as exc:
            self._raise_runner_rpc_error(exc)
        return self._trusted_launch_from_snapshot(cast(dict[str, object], redeemed), secret_tokens)

    def _redeem_postgresql_runner_secret(
        self,
        *,
        token: str,
        runner_id: UUID,
        run_id: UUID,
        provider: SecretValueProvider,
    ) -> SecretMaterial:
        raw_token = _text(token, field="secret_lease_token", maximum=512)
        try:
            with self._session_factory.begin() as db:
                row = (
                    db.execute(
                        sa.text(
                            "SELECT * FROM public.saas_runner_claim_secret_lease_v1("
                            ":token_hash, :runner_id, :run_id)"
                        ),
                        {
                            "token_hash": _token_hash(raw_token),
                            "runner_id": runner_id,
                            "run_id": run_id,
                        },
                    )
                    .mappings()
                    .one()
                )
        except sa.exc.DBAPIError as exc:
            self._raise_runner_rpc_error(exc)
        if bool(row["replayed"]):
            raise IsolationControlPlaneError(
                "secret_lease_stale", "secret lease or distributed fence is stale"
            )
        value = provider.resolve(
            provider=str(row["vault_provider"]),
            vault_ref=str(row["vault_ref"]),
            version_ref=str(row["version_ref"]),
        ).strip()
        if not value or len(value) > 65536:
            raise IsolationControlPlaneError(
                "secret_material_invalid", "secret provider returned invalid material"
            )
        inject_env = cast(list[object], row["inject_env"])
        return SecretMaterial(
            UUID(str(row["binding_id"])),
            str(row["binding_name"]),
            str(row["host"]),
            str(row["credential_scheme"]),
            None if row["username"] is None else str(row["username"]),
            tuple(str(value) for value in inject_env),
            value,
        )

    @staticmethod
    def _trusted_launch_from_snapshot(
        snapshot: dict[str, object], secret_tokens: dict[UUID, str]
    ) -> TrustedRunnerLaunchGrant:
        profile = cast(dict[str, object], snapshot["profile"])
        bindings = cast(list[dict[str, object]], snapshot["secret_bindings"])
        required_capabilities = tuple(
            str(value) for value in cast(list[object], snapshot["required_runner_capabilities"])
        )
        contract_payload = {
            "profile_hash": str(profile["config_hash"]),
            "egress_hash": str(snapshot["egress_hash"]),
            "required_runner_capabilities": required_capabilities,
        }
        contract = SandboxLaunchContract(
            str(profile["sandbox_backend"]),
            str(profile["network_mode"]),
            bool(profile["root_read_only"]),
            int(cast(int, profile["run_as_uid"])),
            int(cast(int, profile["run_as_gid"])),
            bool(profile["no_new_privileges"]),
            bool(profile["host_socket_access"]),
            str(profile["syscall_profile_ref"]),
            int(cast(int, profile["cpu_millis"])),
            int(cast(int, profile["memory_bytes"])),
            int(cast(int, profile["pids_limit"])),
            ToolPolicy(
                tuple(str(value) for value in cast(list[object], profile["allowed_tools"])),
                tuple(
                    str(value) for value in cast(list[object], profile["approval_required_tools"])
                ),
                tuple(str(value) for value in cast(list[object], profile["denied_tools"])),
            ),
            tuple(str(value) for value in cast(list[object], snapshot["egress_rules"])),
            bool(snapshot["allow_private_destinations"]),
            required_capabilities,
            _canonical_hash(contract_payload),
        )
        expires_at = datetime.fromisoformat(str(snapshot["expires_at"]))
        secret_leases = tuple(
            SecretLeaseReference(
                UUID(str(binding["binding_id"])),
                str(binding["name"]),
                str(binding["host"]),
                str(binding["credential_scheme"]),
                None if binding["username"] is None else str(binding["username"]),
                tuple(str(value) for value in cast(list[object], binding["inject_env"])),
                secret_tokens[UUID(str(binding["binding_id"]))],
                expires_at,
            )
            for binding in bindings
        )
        return TrustedRunnerLaunchGrant(
            UUID(str(snapshot["grant_id"])),
            UUID(str(snapshot["tenant_id"])),
            UUID(str(snapshot["space_id"])),
            UUID(str(snapshot["project_id"])),
            UUID(str(snapshot["run_id"])),
            UUID(str(snapshot["runner_id"])),
            UUID(str(snapshot["worktree_id"])),
            str(snapshot["worktree_access_mode"]),
            int(cast(int, snapshot["worktree_lease_generation"])),
            int(cast(int, snapshot["run_fence_token"])),
            int(cast(int, snapshot["runner_connection_generation"])),
            contract,
            secret_leases,
            expires_at,
        )

    @staticmethod
    def _raise_runner_rpc_error(error: sa.exc.DBAPIError) -> NoReturn:
        detail = str(error.orig).splitlines()[0]
        match = re.search(r"runner_[a-z0-9_]+", detail)
        code = match.group(0) if match is not None else "runner_database_authority_rejected"
        code = {
            "runner_isolation_grant_invalid": "isolation_grant_invalid",
            "runner_secret_lease_invalid": "secret_lease_invalid",
            "runner_secret_lease_stale": "secret_lease_stale",
        }.get(code, code)
        raise IsolationControlPlaneError(code, "Runner database authority rejected") from None

    @staticmethod
    def _required_runner_capabilities(
        profile: ExecutionProfileRecord | None,
    ) -> tuple[str, ...]:
        if profile is None:
            return ()
        return tuple(
            sorted(
                {
                    *_REQUIRED_RUNNER_CAPABILITY_PREFIXES,
                    f"sandbox.{profile.sandbox_backend}",
                    f"syscall.{profile.syscall_profile_ref}",
                }
            )
        )

    @staticmethod
    def _contract(
        profile: ExecutionProfileRecord,
        policy: EgressPolicyRecord,
        required_capabilities: tuple[str, ...],
    ) -> SandboxLaunchContract:
        tool_policy = ToolPolicy(
            tuple(profile.allowed_tools),
            tuple(profile.approval_required_tools),
            tuple(profile.denied_tools),
        )
        contract_payload = {
            "profile_hash": profile.config_hash,
            "egress_hash": policy.rules_hash,
            "required_runner_capabilities": required_capabilities,
        }
        return SandboxLaunchContract(
            profile.sandbox_backend,
            profile.network_mode,
            profile.root_read_only,
            profile.run_as_uid,
            profile.run_as_gid,
            profile.no_new_privileges,
            profile.host_socket_access,
            profile.syscall_profile_ref,
            profile.cpu_millis,
            profile.memory_bytes,
            profile.pids_limit,
            tool_policy,
            tuple(policy.rules),
            policy.allow_private_destinations,
            required_capabilities,
            _canonical_hash(contract_payload),
        )

    @staticmethod
    def _apply_request_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                actor_id=request.actor_id,
            ),
        )

    @staticmethod
    def _append_outbox(
        db: Session,
        *,
        tenant_id: UUID,
        aggregate_type: str,
        aggregate_key: str,
        event_type: str,
        payload: dict[str, object],
        idempotency_key: str,
    ) -> None:
        # Runner RLS binds each event to the already-persisted exact grant or
        # lease.  Flush the authoritative row/state transition before the
        # FK-free Outbox INSERT so SQLAlchemy cannot reorder the two writes.
        db.flush()
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=idempotency_key,
                request_hash=_canonical_hash(payload),
                attempt_count=0,
                available_at=_utcnow(),
            )
        )
