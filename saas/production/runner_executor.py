"""Concrete managed-Runner executor over fenced Worktree and isolation adapters."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import shlex
import stat
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import Future
from configparser import Error as ConfigParserError
from configparser import RawConfigParser
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from queue import Full, Queue
from threading import Lock, Thread
from typing import Any, Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.isolation import IsolationControlPlane, SecretValueProvider
from saas.control_plane.preview_execution import (
    PreviewExecutionControlPlaneError,
    PreviewRunnerExecutionAuthority,
    PreviewRunnerStartClaim,
    PreviewRunnerStopClaim,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.runner_execution_spec import (
    ManagedRunExecutionSpecError,
    ProductionRunExecutionSpec,
    production_run_execution_spec,
)
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import RunDispatchRecord
from saas.control_plane.worktree_models import WorktreeInstanceRecord
from saas.control_plane.worktrees import (
    WorktreeControlPlane,
    WorktreeControlPlaneError,
    WorktreeLease,
)
from saas.production.preview_execution import static_web_preview_execution
from saas.production.repository_mirror import (
    RepositoryMirrorError,
    load_and_verify_repository_bindings,
)
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.runner_adapter import (
    LinuxCgroupV2ContainmentVerifier,
    PhysicalWorktree,
    PreparedRunnerIsolation,
    RunnerIsolationAdapter,
    RunnerWorktreeAdapter,
    StaticRepositoryMirrorResolver,
)
from saas.runner_adapter.preview_supervisor import RunnerPreviewProcessSupervisor
from saas.runner_adapter.worktrees import ObjectRecoveryArtifactStore

_PREVIEW_EXECUTION_KIND = "omnigent.preview.v1"
_RUNNER_AGENT_DATABASE_ROLE = "saas_runner_agent"
_RUNNER_AGENT_DATABASE_FILE_ENV = "OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE"
_RUNNER_AGENT_DATABASE_CONNECTION_LIMIT = 8
_RUNNER_AGENT_DATABASE_POOL_SIZE = 4
_RUNNER_AGENT_DATABASE_MAX_OVERFLOW = (
    _RUNNER_AGENT_DATABASE_CONNECTION_LIMIT - _RUNNER_AGENT_DATABASE_POOL_SIZE
)
_RUNNER_FORBIDDEN_LIBPQ_ENV = frozenset(
    {
        "PGAPPNAME",
        "PGCHANNELBINDING",
        "PGCLIENTENCODING",
        "PGCONNECT_TIMEOUT",
        "PGDATABASE",
        "PGGSSENCMODE",
        "PGHOST",
        "PGHOSTADDR",
        "PGOPTIONS",
        "PGPASSFILE",
        "PGPASSWORD",
        "PGPORT",
        "PGREQUIRESSL",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLCERT",
        "PGSSLCRL",
        "PGSSLCRLDIR",
        "PGSSLKEY",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PGTARGETSESSIONATTRS",
        "PGUSER",
    }
)
_RUNNER_AGENT_POLICY_SHA256S_BY_MAJOR = {
    16: frozenset(
        {
            "d312cd026e9669e0fb5e723c390c8f0e93c5566ff691ad6d4a41870147d17f0a",
            "3ef7ef89c9dc74b75a3a22d8c6e31ac48d48d38f15aae1c17a9a654db9b5d325",
        }
    ),
    18: frozenset(
        {
            "d312cd026e9669e0fb5e723c390c8f0e93c5566ff691ad6d4a41870147d17f0a",
            "3ef7ef89c9dc74b75a3a22d8c6e31ac48d48d38f15aae1c17a9a654db9b5d325",
        }
    ),
}
_RUNNER_AGENT_SUPPORT_POLICY_SHA256_BY_MAJOR = {
    16: "dc0b05ef2b6602113a0158cab27b3e787f39edd8b285ab40bc10aa5fd78bd65e",
    18: "dc0b05ef2b6602113a0158cab27b3e787f39edd8b285ab40bc10aa5fd78bd65e",
}
_RUNNER_AGENT_FUNCTION_SHA256_BY_MAJOR = {
    16: "43423586ac39ca5a08a415b36f37e93d7409deb5f03050238b0b876c4d33ca02",
    18: "43423586ac39ca5a08a415b36f37e93d7409deb5f03050238b0b876c4d33ca02",
}
_RUNNER_AGENT_POLICY_COUNT = 36
_RUNNER_AGENT_POLICY_RELATION_COUNT = 18
_RUNNER_AGENT_SUPPORT_POLICY_COUNT = 19
_RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS = (
    ("lo_creat", "integer"),
    ("lo_create", "oid"),
    ("lo_from_bytea", "oid, bytea"),
    ("lo_put", "oid, bigint, bytea"),
    ("lowrite", "integer, bytea"),
    ("lo_truncate", "integer, integer"),
    ("lo_truncate64", "integer, bigint"),
    ("lo_unlink", "oid"),
    ("lo_import", "text"),
    ("lo_import", "text, oid"),
    ("lo_export", "oid, text"),
    ("pg_advisory_lock", "bigint"),
    ("pg_advisory_lock", "integer, integer"),
    ("pg_advisory_lock_shared", "bigint"),
    ("pg_advisory_lock_shared", "integer, integer"),
    ("pg_advisory_xact_lock", "bigint"),
    ("pg_advisory_xact_lock", "integer, integer"),
    ("pg_advisory_xact_lock_shared", "bigint"),
    ("pg_advisory_xact_lock_shared", "integer, integer"),
    ("pg_try_advisory_lock", "bigint"),
    ("pg_try_advisory_lock", "integer, integer"),
    ("pg_try_advisory_lock_shared", "bigint"),
    ("pg_try_advisory_lock_shared", "integer, integer"),
    ("pg_try_advisory_xact_lock", "bigint"),
    ("pg_try_advisory_xact_lock", "integer, integer"),
    ("pg_try_advisory_xact_lock_shared", "bigint"),
    ("pg_try_advisory_xact_lock_shared", "integer, integer"),
    ("pg_logical_emit_message", "boolean, text, text, boolean"),
    ("pg_logical_emit_message", "boolean, text, bytea, boolean"),
    ("pg_notify", "text, text"),
    ("pg_current_xact_id", ""),
    ("txid_current", ""),
)
_RUNNER_AGENT_PG_TRGM_FUNCTIONS = frozenset(
    {
        (
            "gin_extract_query_trgm",
            "text, internal, smallint, internal, internal, internal, internal",
        ),
        ("gin_extract_value_trgm", "text, internal"),
        (
            "gin_trgm_consistent",
            "internal, smallint, text, integer, internal, internal, internal, internal",
        ),
        (
            "gin_trgm_triconsistent",
            "internal, smallint, text, integer, internal, internal, internal",
        ),
        ("gtrgm_compress", "internal"),
        ("gtrgm_consistent", "internal, text, smallint, oid, internal"),
        ("gtrgm_decompress", "internal"),
        ("gtrgm_distance", "internal, text, smallint, oid, internal"),
        ("gtrgm_in", "cstring"),
        ("gtrgm_options", "internal"),
        ("gtrgm_out", "gtrgm"),
        ("gtrgm_penalty", "internal, internal, internal"),
        ("gtrgm_picksplit", "internal, internal"),
        ("gtrgm_same", "gtrgm, gtrgm, internal"),
        ("gtrgm_union", "internal, internal"),
        ("set_limit", "real"),
        ("show_limit", ""),
        ("show_trgm", "text"),
        ("similarity", "text, text"),
        ("similarity_dist", "text, text"),
        ("similarity_op", "text, text"),
        ("strict_word_similarity", "text, text"),
        ("strict_word_similarity_commutator_op", "text, text"),
        ("strict_word_similarity_dist_commutator_op", "text, text"),
        ("strict_word_similarity_dist_op", "text, text"),
        ("strict_word_similarity_op", "text, text"),
        ("word_similarity", "text, text"),
        ("word_similarity_commutator_op", "text, text"),
        ("word_similarity_dist_commutator_op", "text, text"),
        ("word_similarity_dist_op", "text, text"),
        ("word_similarity_op", "text, text"),
    }
)
_RUNNER_AGENT_SELECT_TABLES = frozenset(
    {
        "saas_alembic_version",
        "saas_run_dispatches",
        "saas_runs",
        "saas_repositories",
        "saas_changeset_groups",
        "saas_changesets",
        "saas_worktree_quotas",
        "saas_worktree_events",
        "saas_egress_policies",
        "saas_execution_profiles",
        "saas_secret_bindings",
    }
)
_RUNNER_AGENT_SELECT_COLUMNS = frozenset(
    (table, column)
    for table, columns in {
        "saas_runner_registrations": (
            "id pool_id placement_id instance_key failure_domain status "
            "connection_generation protocol_version source_revision schema_revision "
            "adapter_contract_version capabilities capabilities_hash max_concurrency "
            "active_leases last_heartbeat_at registered_at updated_at"
        ),
        "saas_capability_tokens": (
            "id tenant_id space_id project_id run_id runner_id "
            "runner_connection_generation dispatch_generation fence_token "
            "allowed_actions resource_scope issued_at expires_at revoked_at "
            "revocation_reason"
        ),
        "saas_worktree_instances": (
            "id tenant_id space_id project_id change_set_id run_id runner_id "
            "created_by created_by_service_account_id opaque_runtime_key access_mode "
            "status lease_generation run_fence_token runner_connection_generation "
            "lease_expires_at heartbeat_at maximum_lifetime_at reserved_bytes "
            "actual_bytes dirty recovery_artifact_ref environment_snapshot_ref "
            "event_sequence released_at quarantine_reason deleted_at created_at updated_at"
        ),
        "saas_run_isolation_grants": (
            "id tenant_id space_id project_id run_id runner_id worktree_id "
            "execution_profile_id capability_id run_fence_token "
            "runner_connection_generation worktree_lease_generation grant_hash status "
            "expires_at redeemed_at revoked_at created_at"
        ),
        "saas_secret_access_leases": (
            "id tenant_id space_id project_id isolation_grant_id secret_binding_id "
            "run_id runner_id run_fence_token runner_connection_generation status "
            "expires_at redeemed_at revoked_at created_at"
        ),
        "saas_preview_executions": (
            "id tenant_id space_id project_id source_run_id child_run_id change_set_id "
            "created_by profile idempotency_key_hash request_hash opaque_preview_key "
            "preview_host status command_generation runner_id placement_id worktree_id "
            "run_fence_token runner_connection_generation worktree_lease_generation "
            "exchange_issued_at exchange_consumed_at expires_at ready_at terminal_at "
            "failure_code version created_at updated_at"
        ),
        "saas_preview_commands": (
            "id tenant_id space_id project_id preview_execution_id command_type generation "
            "request_hash status runner_id placement_id runner_connection_generation "
            "run_fence_token claimed_by_gateway attempt_count available_at claimed_at "
            "completed_at failure_code created_at updated_at"
        ),
        "saas_preview_sessions": (
            "id tenant_id space_id project_id preview_execution_id generation status "
            "expires_at last_authenticated_at rotated_at revoked_at created_at updated_at"
        ),
    }.items()
    for column in columns.split()
)
_RUNNER_AGENT_UPDATE_COLUMNS: frozenset[tuple[str, str]] = frozenset()
_RUNNER_AGENT_API_FUNCTION_SIGNATURES = (
    ("saas_runner_agent_identity_v1", "uuid, bigint"),
    ("saas_runner_agent_registered_v1", "uuid, bigint"),
    (
        "saas_runner_allocate_worktree_v1",
        "text, uuid, uuid, uuid, uuid, text, bigint, integer, text, text, uuid",
    ),
    ("saas_runner_materialization_grant_v1", "uuid, uuid, bigint, bigint, text"),
    (
        "saas_runner_transition_worktree_v1",
        "text, uuid, uuid, bigint, bigint, text, bigint, boolean, integer, text, text, "
        "text, text, text",
    ),
    (
        "saas_runner_issue_isolation_grant_v1",
        "text, uuid, uuid, uuid, bigint, bigint, uuid, text, integer",
    ),
    ("saas_runner_isolation_metadata_v1", "text, uuid, uuid"),
    (
        "saas_runner_redeem_isolation_grant_v1",
        "text, uuid, uuid, jsonb",
    ),
    ("saas_runner_claim_secret_lease_v1", "text, uuid, uuid"),
    (
        "saas_runner_claim_preview_start_v1",
        "text, uuid, uuid, uuid, bigint, bigint, text",
    ),
    (
        "saas_runner_claim_preview_stop_v1",
        "text, uuid, uuid, uuid, bigint, bigint, text",
    ),
    (
        "saas_runner_transition_preview_v1",
        "text, text, uuid, uuid, uuid, bigint, bigint, uuid, text, uuid, bigint, "
        "boolean, boolean, text",
    ),
)
_RUNNER_AGENT_OWNER_ONLY_FUNCTION_SIGNATURES = (
    ("saas_canonical_json_v1", "jsonb"),
    ("saas_canonical_json_sha256_v1", "jsonb"),
    (
        "saas_runner_worktree_authority_live_v1",
        "text, uuid, uuid, uuid, text, bigint, boolean",
    ),
    ("saas_runner_append_worktree_event_v1", "uuid, text, jsonb, text"),
    ("saas_runner_isolation_snapshot_v1", "text, uuid, uuid"),
    (
        "saas_runner_preview_authority_v1",
        "text, uuid, uuid, uuid, bigint, bigint",
    ),
)
_RUNNER_AGENT_CONTRACT_FUNCTION_NAMES = tuple(
    function_name
    for function_name, _ in (
        *_RUNNER_AGENT_API_FUNCTION_SIGNATURES,
        *_RUNNER_AGENT_OWNER_ONLY_FUNCTION_SIGNATURES,
    )
)


class RunnerExecutorConfig(Protocol):
    @property
    def product_revision(self) -> str: ...

    @property
    def image_digest(self) -> str: ...

    @property
    def runner_id(self) -> UUID: ...

    @property
    def connection_generation(self) -> int: ...


@dataclass(slots=True)
class _ActiveExecution:
    worktree_lease: WorktreeLease
    execution_kind: str = "omnigent.agent.v1"
    preview_claim: PreviewRunnerStartClaim | None = None
    preview_started: bool = False
    physical_worktree: PhysicalWorktree | None = None
    prepared: PreparedRunnerIsolation | None = None
    environment: object | None = None
    environment_closed: bool = False
    checkpointed: bool = False
    finalization_failed: bool = False
    lease_lost: bool = False
    finalizing: bool = False
    heartbeat_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    heartbeat_stop: asyncio.Event | None = field(default=None, repr=False)
    heartbeat_task: asyncio.Task[None] | None = field(default=None, repr=False)


class _HeartbeatCallWorker:
    """One daemon worker isolating heartbeat I/O from asyncio's default pool."""

    def __init__(self) -> None:
        self._calls: Queue[tuple[Future[object], Callable[[], object]] | None] = Queue(maxsize=1)
        self._closed = False
        self._state_lock = Lock()
        self._thread = Thread(
            target=self._run,
            name="omnigent-worktree-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def submit(self, call: Callable[[], object]) -> Future[object]:
        future: Future[object] = Future()
        with self._state_lock:
            if self._closed:
                raise RuntimeError("heartbeat worker is closed")
            self._calls.put_nowait((future, call))
        return future

    def close(self, *, timeout_seconds: float = 2.0) -> bool:
        """Bound teardown without waiting forever for a poisoned provider call."""

        with self._state_lock:
            if not self._closed:
                self._closed = True
                try:
                    self._calls.put_nowait(None)
                except Full:
                    return False
        self._thread.join(timeout=max(0.0, timeout_seconds))
        return not self._thread.is_alive()

    def _run(self) -> None:
        while True:
            item = self._calls.get()
            if item is None:
                return
            future, call = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                result = call()
            except BaseException as error:  # noqa: BLE001 - transferred to event loop.
                if not future.cancelled():
                    with contextlib.suppress(BaseException):
                        future.set_exception(error)
            else:
                if not future.cancelled():
                    with contextlib.suppress(BaseException):
                        future.set_result(result)


@dataclass(frozen=True, slots=True)
class _RecoveryS3Credentials:
    access_key_id: str
    secret_access_key: str = field(repr=False)


class _FilesystemSecretProvider(SecretValueProvider):
    """Resolve versioned secret files below one owner-only deployment root."""

    def __init__(self, root: Path) -> None:
        self._root = _private_directory(root, field="secret_provider_root", create=False)

    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        if provider != "filesystem" or not _opaque(vault_ref) or not _opaque(version_ref):
            raise RunnerControlError(
                "runner_secret_provider_denied", "Secret provider reference is denied"
            )
        path = self._root / vault_ref / version_ref
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
            resolved.relative_to(self._root)
        except (OSError, ValueError) as error:
            raise RunnerControlError(
                "runner_secret_provider_denied", "Secret provider reference is unavailable"
            ) from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or not 1 <= metadata.st_size <= 65_536
        ):
            raise RunnerControlError(
                "runner_secret_provider_denied", "Secret provider file is unsafe"
            )
        return path.read_text(encoding="utf-8")


def _opaque(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 128
        and all(character.isalnum() or character in "._-" for character in value)
        and value not in {".", ".."}
    )


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise RunnerControlError("runner_executor_config_invalid", f"{name} is invalid")
    return value


def _runner_agent_database_login(runner_id: UUID, connection_generation: int) -> str:
    if (
        not isinstance(runner_id, UUID)
        or runner_id.int == 0
        or isinstance(connection_generation, bool)
        or not isinstance(connection_generation, int)
        or not 1 <= connection_generation <= 2**63 - 1
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner database identity is invalid"
        )
    login = f"runner_{runner_id.hex}_g{connection_generation}"
    if len(login.encode("ascii")) > 63:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner database identity is invalid"
        )
    return login


def _reject_ambient_runner_database_authority(source: Mapping[str, str]) -> None:
    for name, value in source.items():
        if not value.strip():
            continue
        database_authority = (
            name in {"DATABASE_URL", "OMNIGENT_SAAS_DB_URL"}
            or name in _RUNNER_FORBIDDEN_LIBPQ_ENV
            or name.endswith(("_DATABASE_URL", "_DATABASE_URL_FILE"))
        )
        if database_authority and name != _RUNNER_AGENT_DATABASE_FILE_ENV:
            raise RunnerControlError(
                "runner_executor_config_invalid",
                "Runner process received forbidden database authority",
            )


def _verify_runner_agent_database_authority(
    engine: Engine | Connection,
    *,
    runner_id: UUID,
    connection_generation: int,
    fleet_members: tuple[tuple[UUID, int], tuple[UUID, int]] | None = None,
    required_registration_status: str = "online",
) -> str:
    """Admit only one direct, non-escalatable Runner-incarnation login."""

    expected_login = _runner_agent_database_login(runner_id, connection_generation)
    if engine.dialect.name != "postgresql":
        raise RunnerControlError(
            "runner_executor_not_ready", "Runner database authority is unavailable"
        )
    try:
        connection_manager = (
            engine.connect() if isinstance(engine, Engine) else contextlib.nullcontext(engine)
        )
        with connection_manager as connection:
            identity = connection.execute(
                sa.text(
                    "SELECT current_user::text, session_user::text, "
                    "current_setting('server_version_num')::integer, role.rolcanlogin, "
                    "role.rolsuper, role.rolcreatedb, role.rolcreaterole, "
                    "role.rolreplication, role.rolbypassrls, role.rolinherit, "
                    "role.rolconfig IS NULL, role.rolconnlimit "
                    "FROM pg_roles AS role WHERE role.rolname = current_user"
                )
            ).one()
            if (
                identity[0] != expected_login
                or identity[1] != expected_login
                or identity[2] // 10_000 != 18
                or tuple(identity[3:])
                != (
                    True,
                    False,
                    False,
                    False,
                    False,
                    False,
                    True,
                    True,
                    _RUNNER_AGENT_DATABASE_CONNECTION_LIMIT,
                )
            ):
                raise ValueError("runner login flags")
            if fleet_members is not None:
                expected_members = tuple(sorted(fleet_members, key=lambda item: str(item[0])))
                if (
                    fleet_members != expected_members
                    or len({member[0] for member in fleet_members}) != 2
                    or (runner_id, connection_generation) not in fleet_members
                ):
                    raise ValueError("runner fleet identity")
                expected_logins = tuple(
                    _runner_agent_database_login(member_id, member_generation)
                    for member_id, member_generation in fleet_members
                )
                observed_logins = tuple(
                    str(value)
                    for value in connection.scalars(
                        sa.text(
                            "SELECT rolname FROM pg_roles "
                            "WHERE rolname ~ '^runner_[0-9a-f]{32}_g[1-9][0-9]*$' "
                            "ORDER BY rolname"
                        )
                    )
                )
                if observed_logins != tuple(sorted(expected_logins)):
                    raise ValueError("runner fleet login namespace")
            if connection.scalar(sa.text("SELECT pg_my_temp_schema()")) != 0:
                raise ValueError("runner temporary schema")

            cluster_settings = {
                str(row[0]): (str(row[1]), str(row[2]), bool(row[3]), str(row[4]))
                for row in connection.execute(
                    sa.text(
                        "SELECT name, setting, context, pending_restart, source "
                        "FROM pg_settings "
                        "WHERE name IN ('max_notify_queue_pages', "
                        "'max_prepared_transactions') ORDER BY name"
                    )
                ).all()
            }
            if cluster_settings != {
                "max_notify_queue_pages": (
                    "64",
                    "postmaster",
                    False,
                    "configuration file",
                ),
                "max_prepared_transactions": (
                    "0",
                    "postmaster",
                    False,
                    "configuration file",
                ),
            }:
                raise ValueError("runner cluster settings")
            if connection.scalar(sa.text("SELECT count(*) FROM pg_prepared_xacts")) != 0:
                raise ValueError("runner prepared transactions")

            revision = connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
            identity_matches = connection.execute(
                sa.text(
                    "SELECT public.saas_runner_agent_identity_v1(:runner_id, :generation), "
                    "public.saas_runner_agent_identity_v1(:runner_id, :generation + 1), "
                    "public.saas_runner_agent_registered_v1(:runner_id, :generation), "
                    "public.saas_runner_agent_registered_v1(:runner_id, :generation + 1)"
                ),
                {"runner_id": runner_id, "generation": connection_generation},
            ).one()
            server_major = identity[2] // 10_000
            registration_state = connection.execute(
                sa.text(
                    "SELECT status, connection_generation, active_leases "
                    "FROM public.saas_runner_registrations WHERE id = :runner_id"
                ),
                {"runner_id": runner_id},
            ).one()
            if (
                required_registration_status not in {"draining", "online"}
                or revision != "p0s000000012"
                or tuple(identity_matches)
                != (
                    True,
                    False,
                    True,
                    False,
                )
                or tuple(registration_state)
                != (required_registration_status, connection_generation, 0)
            ):
                raise ValueError("runner schema identity")

            policy_contract = connection.execute(
                sa.text(
                    "SELECT count(*), count(DISTINCT policy.polrelid), "
                    "count(*) FILTER (WHERE NOT relation.relrowsecurity "
                    "OR NOT relation.relforcerowsecurity OR relation.relowner <> "
                    "(SELECT registration.relowner FROM pg_class registration WHERE "
                    "registration.oid = 'public.saas_runner_registrations'::regclass)), "
                    "encode(sha256(convert_to(string_agg("
                    "relation.relname || '|' || policy.polname || '|' || "
                    "policy.polcmd::text || '|' || policy.polpermissive::text || '|' || "
                    "array_to_string(ARRAY(SELECT role.rolname "
                    "FROM unnest(policy.polroles) role_oid "
                    "JOIN pg_roles role ON role.oid = role_oid ORDER BY role.rolname), ',') || "
                    "'|' || COALESCE(pg_get_expr(policy.polqual, policy.polrelid, false), '') || "
                    "'|' || COALESCE(pg_get_expr("
                    "policy.polwithcheck, policy.polrelid, false), '') || '|' || "
                    "relation.relrowsecurity::text || '|' || "
                    "relation.relforcerowsecurity::text || '|' || "
                    "(relation.relowner = (SELECT registration.relowner FROM pg_class "
                    "registration WHERE registration.oid = "
                    "'public.saas_runner_registrations'::regclass))::text, "
                    "E'\\n' ORDER BY relation.relname, policy.polname), 'UTF8')), 'hex') "
                    "FROM pg_policy policy "
                    "JOIN pg_class relation ON relation.oid = policy.polrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND (SELECT oid FROM pg_roles WHERE rolname = :role) = ANY(policy.polroles)"
                ),
                {"role": _RUNNER_AGENT_DATABASE_ROLE},
            ).one()
            if (
                tuple(policy_contract[:3])
                != (
                    _RUNNER_AGENT_POLICY_COUNT,
                    _RUNNER_AGENT_POLICY_RELATION_COUNT,
                    0,
                )
                or policy_contract[3] not in _RUNNER_AGENT_POLICY_SHA256S_BY_MAJOR[server_major]
            ):
                raise ValueError("runner policy contract")

            support_policy_contract = connection.execute(
                sa.text(
                    "SELECT count(*), count(DISTINCT policy.polrelid), "
                    "count(*) FILTER (WHERE NOT relation.relrowsecurity "
                    "OR NOT relation.relforcerowsecurity OR relation.relowner <> "
                    "(SELECT registration.relowner FROM pg_class registration WHERE "
                    "registration.oid = 'public.saas_runner_registrations'::regclass)), "
                    "encode(sha256(convert_to(string_agg("
                    "relation.relname || '|' || policy.polname || '|' || "
                    "policy.polcmd::text || '|' || policy.polpermissive::text || '|' || "
                    "array_to_string(ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' "
                    "ELSE role.rolname END FROM unnest(policy.polroles) role_oid "
                    "LEFT JOIN pg_roles role ON role.oid = role_oid ORDER BY 1), ',') || "
                    "'|' || COALESCE(pg_get_expr(policy.polqual, policy.polrelid, false), '') || "
                    "'|' || COALESCE(pg_get_expr("
                    "policy.polwithcheck, policy.polrelid, false), '') || '|' || "
                    "relation.relrowsecurity::text || '|' || "
                    "relation.relforcerowsecurity::text || '|' || "
                    "(relation.relowner = (SELECT registration.relowner FROM pg_class "
                    "registration WHERE registration.oid = "
                    "'public.saas_runner_registrations'::regclass))::text, "
                    "E'\\n' ORDER BY relation.relname, policy.polname), 'UTF8')), 'hex') "
                    "FROM pg_policy policy "
                    "JOIN pg_class relation ON relation.oid = policy.polrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' "
                    "AND policy.polname ~ '^rls_.*_runner_api_definer$'"
                )
            ).one()
            if (
                tuple(support_policy_contract[:3])
                != (_RUNNER_AGENT_SUPPORT_POLICY_COUNT, _RUNNER_AGENT_SUPPORT_POLICY_COUNT, 0)
                or support_policy_contract[3]
                != _RUNNER_AGENT_SUPPORT_POLICY_SHA256_BY_MAJOR[server_major]
            ):
                raise ValueError("runner API support policy contract")

            function_hash = connection.scalar(
                sa.text(
                    "SELECT encode(sha256(convert_to(string_agg("
                    "procedure.proname || '|' || oidvectortypes(procedure.proargtypes) || "
                    "'|' || language.lanname || '|' || procedure.prokind::text || '|' || "
                    "procedure.prosecdef::text || '|' || procedure.proleakproof::text || "
                    "'|' || procedure.provolatile::text || '|' || "
                    "procedure.proparallel::text || '|' || "
                    "COALESCE(array_to_string(procedure.proconfig, E'\\x1f'), '') || '|' || "
                    "pg_get_function_result(procedure.oid) || '|' || procedure.prosrc || "
                    "'|' || (procedure.proowner = (SELECT relation.relowner FROM pg_class "
                    "relation WHERE relation.oid = "
                    "'public.saas_runner_registrations'::regclass))::text, "
                    "E'\\n' ORDER BY procedure.proname), 'UTF8')), 'hex') "
                    "FROM pg_proc AS procedure "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid = procedure.pronamespace "
                    "JOIN pg_language AS language ON language.oid = procedure.prolang "
                    "WHERE namespace.nspname = 'public' "
                    "AND procedure.proname = ANY(CAST(:function_names AS text[]))"
                ),
                {"function_names": list(_RUNNER_AGENT_CONTRACT_FUNCTION_NAMES)},
            )
            if function_hash != _RUNNER_AGENT_FUNCTION_SHA256_BY_MAJOR[server_major]:
                raise ValueError("runner function contract")

            memberships = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT granted.rolname, membership.admin_option, "
                        "membership.inherit_option, membership.set_option "
                        "FROM pg_auth_members AS membership "
                        "JOIN pg_roles AS member ON member.oid = membership.member "
                        "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                        "WHERE member.rolname = current_user ORDER BY granted.rolname"
                    )
                ).all()
            ]
            if memberships != [(_RUNNER_AGENT_DATABASE_ROLE, False, True, False)]:
                raise ValueError("runner membership")

            base_role = connection.execute(
                sa.text(
                    "SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, "
                    "role.rolcreaterole, role.rolreplication, role.rolbypassrls, "
                    "role.rolinherit, role.rolconfig IS NULL, role.rolconnlimit "
                    "FROM pg_roles AS role WHERE role.rolname = :role"
                ),
                {"role": _RUNNER_AGENT_DATABASE_ROLE},
            ).one()
            if tuple(base_role) != (
                False,
                False,
                False,
                False,
                False,
                False,
                True,
                True,
                -1,
            ):
                raise ValueError("runner base role flags")
            outgoing = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "WHERE member.rolname = :role"
                ),
                {"role": _RUNNER_AGENT_DATABASE_ROLE},
            )
            if outgoing != 0:
                raise ValueError("runner base role membership")

            unsafe_catalog_authority = connection.scalar(
                sa.text(
                    "WITH principals AS (SELECT oid FROM pg_roles WHERE rolname IN "
                    "(current_user, :role)), owned AS ("
                    "SELECT 1 FROM pg_database object, principals "
                    "WHERE object.datdba = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object, principals "
                    "WHERE object.nspowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_class object, principals "
                    "WHERE object.relowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_proc object, principals "
                    "WHERE object.proowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_type object, principals "
                    "WHERE object.typowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_language object, principals "
                    "WHERE object.lanowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object, principals "
                    "WHERE object.lomowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_tablespace object, principals "
                    "WHERE object.spcowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object, principals "
                    "WHERE object.fdwowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_server object, principals "
                    "WHERE object.srvowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_extension object, principals "
                    "WHERE object.extowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_event_trigger object, principals "
                    "WHERE object.evtowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_publication object, principals "
                    "WHERE object.pubowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_subscription object, principals "
                    "WHERE object.subowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_collation object, principals "
                    "WHERE object.collowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_conversion object, principals "
                    "WHERE object.conowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_operator object, principals "
                    "WHERE object.oprowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_opclass object, principals "
                    "WHERE object.opcowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_opfamily object, principals "
                    "WHERE object.opfowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_ts_dict object, principals "
                    "WHERE object.dictowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_ts_config object, principals "
                    "WHERE object.cfgowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_statistic_ext object, principals "
                    "WHERE object.stxowner = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object, principals "
                    "WHERE object.defaclrole = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_user_mappings "
                    "UNION ALL SELECT 1 FROM pg_db_role_setting object, principals "
                    "WHERE object.setrole = principals.oid "
                    "UNION ALL SELECT 1 FROM pg_db_role_setting object "
                    "WHERE object.setrole = 0 AND object.setdatabase IN "
                    "(0, (SELECT oid FROM pg_database WHERE datname = current_database()))) "
                    "SELECT count(*) FROM owned"
                ),
                {"role": _RUNNER_AGENT_DATABASE_ROLE},
            )
            if unsafe_catalog_authority != 0:
                raise ValueError("runner catalog authority")

            direct_login_acls = connection.scalar(
                sa.text(
                    "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                    "observed AS ("
                    "SELECT 1 FROM pg_database object CROSS JOIN LATERAL "
                    "aclexplode(object.datacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_namespace object CROSS JOIN LATERAL "
                    "aclexplode(object.nspacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_class object CROSS JOIN LATERAL "
                    "aclexplode(object.relacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_attribute object CROSS JOIN LATERAL "
                    "aclexplode(object.attacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_proc object CROSS JOIN LATERAL "
                    "aclexplode(object.proacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_type object CROSS JOIN LATERAL "
                    "aclexplode(object.typacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_language object CROSS JOIN LATERAL "
                    "aclexplode(object.lanacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object "
                    "CROSS JOIN LATERAL aclexplode(object.lomacl) acl, login "
                    "WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object "
                    "CROSS JOIN LATERAL aclexplode(object.fdwacl) acl, login "
                    "WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_server object CROSS JOIN LATERAL "
                    "aclexplode(object.srvacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_tablespace object CROSS JOIN LATERAL "
                    "aclexplode(object.spcacl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_parameter_acl object CROSS JOIN LATERAL "
                    "aclexplode(object.paracl) acl, login WHERE acl.grantee = login.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object CROSS JOIN LATERAL "
                    "aclexplode(object.defaclacl) acl, login WHERE acl.grantee = login.oid) "
                    "SELECT count(*) FROM observed"
                )
            )
            if direct_login_acls != 0:
                raise ValueError("runner direct ACL")

            database_acls = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT object.datname, acl.privilege_type, acl.is_grantable, "
                        "acl.grantor = object.datdba FROM pg_database object "
                        "CROSS JOIN LATERAL aclexplode(object.datacl) acl "
                        "WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role) "
                        "ORDER BY object.datname, acl.privilege_type"
                    ),
                    {"role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            ]
            current_database = str(connection.scalar(sa.text("SELECT current_database()")))
            if database_acls != [(current_database, "CONNECT", False, True)]:
                raise ValueError("runner database direct ACL")

            schema_acls = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT object.nspname, acl.privilege_type, acl.is_grantable, "
                        "acl.grantor = object.nspowner FROM pg_namespace object "
                        "CROSS JOIN LATERAL aclexplode(object.nspacl) acl "
                        "WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role) "
                        "ORDER BY object.nspname, acl.privilege_type"
                    ),
                    {"role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            ]
            if schema_acls != [("public", "USAGE", False, True)]:
                raise ValueError("runner schema direct ACL")

            unexpected_base_acls = connection.scalar(
                sa.text(
                    "WITH base AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
                    "observed AS ("
                    "SELECT 1 FROM pg_type object CROSS JOIN LATERAL "
                    "aclexplode(object.typacl) acl, base WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_language object CROSS JOIN LATERAL "
                    "aclexplode(object.lanacl) acl, base WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object "
                    "CROSS JOIN LATERAL aclexplode(object.lomacl) acl, base "
                    "WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object "
                    "CROSS JOIN LATERAL aclexplode(object.fdwacl) acl, base "
                    "WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_foreign_server object CROSS JOIN LATERAL "
                    "aclexplode(object.srvacl) acl, base WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_tablespace object CROSS JOIN LATERAL "
                    "aclexplode(object.spcacl) acl, base WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_parameter_acl object CROSS JOIN LATERAL "
                    "aclexplode(object.paracl) acl, base WHERE acl.grantee = base.oid "
                    "UNION ALL SELECT 1 FROM pg_default_acl object CROSS JOIN LATERAL "
                    "aclexplode(object.defaclacl) acl, base WHERE acl.grantee = base.oid) "
                    "SELECT count(*) FROM observed"
                ),
                {"role": _RUNNER_AGENT_DATABASE_ROLE},
            )
            if unexpected_base_acls != 0:
                raise ValueError("runner base catalog ACL")

            table_acls = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT namespace.nspname, relation.relname, acl.privilege_type, "
                        "acl.is_grantable, acl.grantor = relation.relowner "
                        "FROM pg_class AS relation "
                        "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                        "CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl "
                        "WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role)"
                    ),
                    {"role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            expected_table_acls = frozenset(
                {("public", table, "SELECT", False, True) for table in _RUNNER_AGENT_SELECT_TABLES}
            )
            if table_acls != expected_table_acls:
                raise ValueError("runner table ACL")

            column_acls = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT namespace.nspname, relation.relname, attribute.attname, "
                        "acl.privilege_type, acl.is_grantable, "
                        "acl.grantor = relation.relowner "
                        "FROM pg_attribute AS attribute "
                        "JOIN pg_class AS relation ON relation.oid = attribute.attrelid "
                        "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                        "CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl "
                        "WHERE attribute.attnum > 0 "
                        "AND NOT attribute.attisdropped "
                        "AND acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role)"
                    ),
                    {"role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            expected_column_acls = frozenset(
                {
                    ("public", table, column, "SELECT", False, True)
                    for table, column in _RUNNER_AGENT_SELECT_COLUMNS
                }
                | {
                    ("public", table, column, "UPDATE", False, True)
                    for table, column in _RUNNER_AGENT_UPDATE_COLUMNS
                }
            )
            if column_acls != expected_column_acls:
                raise ValueError("runner column ACL")

            function_acls = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT procedure.proname, "
                        "oidvectortypes(procedure.proargtypes), "
                        "pg_get_userbyid(acl.grantee), pg_get_userbyid(acl.grantor), "
                        "acl.privilege_type, acl.is_grantable, "
                        "pg_get_userbyid(procedure.proowner) "
                        "FROM pg_proc AS procedure "
                        "JOIN pg_namespace AS namespace "
                        "ON namespace.oid = procedure.pronamespace "
                        "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
                        "acldefault('f', procedure.proowner))) AS acl "
                        "WHERE namespace.nspname = 'public' "
                        "AND procedure.proname = ANY(CAST(:function_names AS text[])) "
                        "ORDER BY procedure.proname"
                    ),
                    {"function_names": list(_RUNNER_AGENT_CONTRACT_FUNCTION_NAMES)},
                ).all()
            ]
            expected_function_acls = []
            for function_name, arguments in (
                *_RUNNER_AGENT_API_FUNCTION_SIGNATURES,
                *_RUNNER_AGENT_OWNER_ONLY_FUNCTION_SIGNATURES,
            ):
                owner = next(row[6] for row in function_acls if row[0] == function_name)
                expected_function_acls.append(
                    (
                        function_name,
                        arguments,
                        owner,
                        owner,
                        "EXECUTE",
                        False,
                        owner,
                    )
                )
                if (function_name, arguments) in _RUNNER_AGENT_API_FUNCTION_SIGNATURES:
                    expected_function_acls.append(
                        (
                            function_name,
                            arguments,
                            _RUNNER_AGENT_DATABASE_ROLE,
                            owner,
                            "EXECUTE",
                            False,
                            owner,
                        )
                    )
            if sorted(function_acls) != sorted(expected_function_acls):
                raise ValueError("runner function ACL")

            base_function_acls = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT namespace.nspname, procedure.proname, "
                        "oidvectortypes(procedure.proargtypes), acl.privilege_type, "
                        "acl.is_grantable, acl.grantor = procedure.proowner "
                        "FROM pg_proc procedure JOIN pg_namespace namespace "
                        "ON namespace.oid = procedure.pronamespace "
                        "CROSS JOIN LATERAL aclexplode(procedure.proacl) acl "
                        "WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = :role)"
                    ),
                    {"role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            if base_function_acls != frozenset(
                {
                    (
                        "public",
                        function_name,
                        arguments,
                        "EXECUTE",
                        False,
                        True,
                    )
                    for function_name, arguments in _RUNNER_AGENT_API_FUNCTION_SIGNATURES
                }
            ):
                raise ValueError("runner base function ACL")

            principal_names = (expected_login, _RUNNER_AGENT_DATABASE_ROLE)
            database_authority = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, database.datname, database.datallowconn, "
                        "database.datallowconn AND has_database_privilege("
                        "principal.name, database.oid, 'CONNECT'), "
                        "database.datallowconn AND has_database_privilege("
                        "principal.name, database.oid, 'CREATE'), "
                        "database.datallowconn AND has_database_privilege("
                        "principal.name, database.oid, 'TEMPORARY') "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_database database "
                        "ORDER BY principal.name, database.datname"
                    ),
                    {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            ]
            for (
                principal,
                database_name,
                allow_connections,
                connect,
                create,
                temporary,
            ) in database_authority:
                expected_current = database_name == current_database
                if (
                    (expected_current and not allow_connections)
                    or bool(connect) != expected_current
                    or create
                    or temporary
                    or principal not in principal_names
                ):
                    raise ValueError("runner effective database ACL")

            schema_authority = [
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, namespace.nspname, "
                        "has_schema_privilege(principal.name, namespace.oid, 'USAGE'), "
                        "has_schema_privilege(principal.name, namespace.oid, 'CREATE') "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_namespace namespace "
                        "WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                        "AND namespace.nspname NOT LIKE 'pg_toast%' "
                        "AND namespace.nspname NOT LIKE 'pg_temp%' "
                        "ORDER BY principal.name, namespace.nspname"
                    ),
                    {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            ]
            for principal, schema_name, usage, create in schema_authority:
                if (
                    bool(usage) != (schema_name == "public")
                    or create
                    or principal not in principal_names
                ):
                    raise ValueError("runner effective schema ACL")

            restricted_schema_authority = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM (VALUES (CAST(:login AS name)), "
                    "(CAST(:role AS name))) AS principal(name) "
                    "CROSS JOIN pg_namespace namespace "
                    "WHERE (namespace.nspname LIKE 'pg_toast%' "
                    "OR namespace.nspname LIKE 'pg_temp%') AND ("
                    "has_schema_privilege(principal.name, namespace.oid, 'USAGE') OR "
                    "has_schema_privilege(principal.name, namespace.oid, 'CREATE'))"
                ),
                {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
            )
            if restricted_schema_authority != 0:
                raise ValueError("runner restricted schema ACL")

            language_authority = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, language.lanname "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_language AS language "
                        "WHERE has_language_privilege(principal.name, language.oid, 'USAGE')"
                    ),
                    {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            expected_language_authority = frozenset(
                (principal, language)
                for principal in principal_names
                for language in ("c", "internal", "plpgsql", "sql")
            )
            if language_authority != expected_language_authority:
                raise ValueError("runner effective language ACL")

            type_authority = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, namespace.nspname, type.typname, "
                        "COALESCE(extension.extname, ''), "
                        "COALESCE(extension.extversion, '') "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_type AS type "
                        "JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace "
                        "LEFT JOIN pg_depend AS dependency ON dependency.classid = "
                        "'pg_type'::regclass AND dependency.objid = type.oid "
                        "AND dependency.refclassid = 'pg_extension'::regclass "
                        "AND dependency.deptype = 'e' "
                        "LEFT JOIN pg_extension AS extension "
                        "ON extension.oid = dependency.refobjid "
                        "WHERE namespace.nspname NOT IN "
                        "('pg_catalog', 'information_schema') "
                        "AND namespace.nspname NOT LIKE 'pg_toast%' "
                        "AND namespace.nspname NOT LIKE 'pg_temp%' "
                        "AND type.typelem = 0 "
                        "AND has_type_privilege(principal.name, type.oid, 'USAGE')"
                    ),
                    {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            if type_authority != frozenset(
                (
                    principal,
                    "public",
                    "gtrgm",
                    "pg_trgm",
                    "1.6",
                )
                for principal in principal_names
            ):
                raise ValueError("runner effective type ACL")

            public_relation_authority = connection.scalar(
                sa.text(
                    "WITH observed AS ("
                    "SELECT 1 FROM pg_class relation JOIN pg_namespace namespace "
                    "ON namespace.oid = relation.relnamespace CROSS JOIN LATERAL "
                    "aclexplode(relation.relacl) acl WHERE acl.grantee = 0 "
                    "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND namespace.nspname NOT LIKE 'pg_toast%' "
                    "AND namespace.nspname NOT LIKE 'pg_temp%' "
                    "UNION ALL SELECT 1 FROM pg_attribute attribute "
                    "JOIN pg_class relation ON relation.oid = attribute.attrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                    "WHERE acl.grantee = 0 AND attribute.attnum > 0 "
                    "AND NOT attribute.attisdropped "
                    "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND namespace.nspname NOT LIKE 'pg_toast%' "
                    "AND namespace.nspname NOT LIKE 'pg_temp%' "
                    "UNION ALL SELECT 1 FROM pg_largeobject_metadata object "
                    "CROSS JOIN LATERAL aclexplode(object.lomacl) acl "
                    "WHERE acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_foreign_data_wrapper object "
                    "CROSS JOIN LATERAL aclexplode(object.fdwacl) acl "
                    "WHERE acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_foreign_server object "
                    "CROSS JOIN LATERAL aclexplode(object.srvacl) acl "
                    "WHERE acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_tablespace object "
                    "CROSS JOIN LATERAL aclexplode(object.spcacl) acl "
                    "WHERE acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_parameter_acl object "
                    "CROSS JOIN LATERAL aclexplode(object.paracl) acl "
                    "WHERE acl.grantee = 0) SELECT count(*) FROM observed"
                )
            )
            if public_relation_authority != 0:
                raise ValueError("runner PUBLIC object ACL")

            denied_catalog_signatures = tuple(
                f"{function_name}({arguments})"
                for function_name, arguments in _RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS
            )
            denied_catalog_authority = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, procedure.proname, "
                        "oidvectortypes(procedure.proargtypes), "
                        "has_function_privilege(principal.name, procedure.oid, 'EXECUTE') "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_proc AS procedure "
                        "JOIN pg_namespace AS namespace "
                        "ON namespace.oid = procedure.pronamespace "
                        "WHERE namespace.nspname = 'pg_catalog' "
                        "AND (procedure.proname || '(' || "
                        "oidvectortypes(procedure.proargtypes) || ')') = "
                        "ANY(CAST(:signatures AS text[]))"
                    ),
                    {
                        "login": expected_login,
                        "role": _RUNNER_AGENT_DATABASE_ROLE,
                        "signatures": list(denied_catalog_signatures),
                    },
                ).all()
            )
            if denied_catalog_authority != frozenset(
                (principal, function_name, arguments, False)
                for principal in principal_names
                for function_name, arguments in _RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS
            ):
                raise ValueError("runner dangerous catalog function ACL")

            # The base role and per-incarnation LOGIN have no direct authority
            # over core catalog objects.  Effective PUBLIC authority is checked
            # separately below against initdb's recorded baseline.
            direct_catalog_authority = connection.scalar(
                sa.text(
                    "WITH principals AS (SELECT oid FROM pg_roles "
                    "WHERE rolname IN (:login, :role)), observed AS ("
                    "SELECT 1 FROM pg_namespace object CROSS JOIN LATERAL "
                    "aclexplode(object.nspacl) acl WHERE acl.grantee IN "
                    "(SELECT oid FROM principals) AND object.nspname IN "
                    "('pg_catalog', 'information_schema') "
                    "UNION ALL SELECT 1 FROM pg_class object "
                    "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(object.relacl) acl "
                    "WHERE acl.grantee IN (SELECT oid FROM principals) "
                    "AND namespace.nspname IN ('pg_catalog', 'information_schema') "
                    "UNION ALL SELECT 1 FROM pg_attribute attribute "
                    "JOIN pg_class relation ON relation.oid = attribute.attrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                    "WHERE acl.grantee IN (SELECT oid FROM principals) "
                    "AND namespace.nspname IN ('pg_catalog', 'information_schema') "
                    "AND attribute.attnum > 0 "
                    "AND NOT attribute.attisdropped "
                    "UNION ALL SELECT 1 FROM pg_proc object "
                    "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                    "CROSS JOIN LATERAL aclexplode(object.proacl) acl "
                    "WHERE acl.grantee IN (SELECT oid FROM principals) "
                    "AND namespace.nspname IN ('pg_catalog', 'information_schema') "
                    "UNION ALL SELECT 1 FROM pg_type object "
                    "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                    "CROSS JOIN LATERAL aclexplode(object.typacl) acl "
                    "WHERE acl.grantee IN (SELECT oid FROM principals) "
                    "AND namespace.nspname IN ('pg_catalog', 'information_schema') "
                    "UNION ALL SELECT 1 FROM pg_language object CROSS JOIN LATERAL "
                    "aclexplode(object.lanacl) acl WHERE acl.grantee IN "
                    "(SELECT oid FROM principals)) SELECT count(*) FROM observed"
                ),
                {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
            )
            if direct_catalog_authority != 0:
                raise ValueError("runner direct catalog ACL")

            # A compromised administrator must not be able to expand PUBLIC
            # pg_catalog authority without poisoning the next claim.  Initial
            # privileges are authoritative when PostgreSQL records them. Core
            # objects without a receipt use acldefault; normal-OID objects get
            # an empty baseline, so a post-bootstrap pg_catalog function's
            # implicit PUBLIC EXECUTE is itself authority drift.
            public_catalog_acl_expansions = connection.scalar(
                sa.text(
                    "WITH objects(classoid, objoid, objsubid, owner_oid, "
                    "object_acl, acl_kind) AS ("
                    "SELECT 'pg_namespace'::regclass::oid, namespace.oid, 0, "
                    "namespace.nspowner, namespace.nspacl, 'n'::\"char\" "
                    "FROM pg_namespace namespace WHERE namespace.nspname = 'pg_catalog' "
                    "UNION ALL SELECT 'pg_class'::regclass::oid, relation.oid, 0, "
                    "relation.relowner, relation.relacl, CASE WHEN relation.relkind = 'S' "
                    "THEN 'S' ELSE 'r' END::\"char\" FROM pg_class relation "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'pg_catalog' "
                    "UNION ALL SELECT 'pg_class'::regclass::oid, relation.oid, "
                    "attribute.attnum, relation.relowner, attribute.attacl, 'c'::\"char\" "
                    "FROM pg_attribute attribute JOIN pg_class relation "
                    "ON relation.oid = attribute.attrelid JOIN pg_namespace namespace "
                    "ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'pg_catalog' AND attribute.attnum > 0 "
                    "AND NOT attribute.attisdropped "
                    "UNION ALL SELECT 'pg_proc'::regclass::oid, procedure.oid, 0, "
                    "procedure.proowner, procedure.proacl, 'f'::\"char\" "
                    "FROM pg_proc procedure JOIN pg_namespace namespace "
                    "ON namespace.oid = procedure.pronamespace "
                    "WHERE namespace.nspname = 'pg_catalog' "
                    "UNION ALL SELECT 'pg_type'::regclass::oid, type.oid, 0, "
                    "type.typowner, type.typacl, 'T'::\"char\" FROM pg_type type "
                    "JOIN pg_namespace namespace ON namespace.oid = type.typnamespace "
                    "WHERE namespace.nspname = 'pg_catalog' "
                    "UNION ALL SELECT 'pg_language'::regclass::oid, language.oid, 0, "
                    "language.lanowner, language.lanacl, 'l'::\"char\" "
                    "FROM pg_language language), normalized AS ("
                    "SELECT object.*, initial.initprivs FROM objects object "
                    "LEFT JOIN LATERAL (SELECT candidate.initprivs "
                    "FROM pg_init_privs candidate WHERE candidate.classoid = object.classoid "
                    "AND candidate.objoid = object.objoid "
                    "AND candidate.objsubid = object.objsubid "
                    "ORDER BY candidate.privtype LIMIT 1) initial ON true), "
                    "current_public AS (SELECT object.classoid, object.objoid, "
                    "object.objsubid, privilege.privilege_type, privilege.is_grantable "
                    "FROM normalized object CROSS JOIN LATERAL aclexplode(COALESCE("
                    "object.object_acl, acldefault(object.acl_kind, object.owner_oid))) "
                    "privilege WHERE privilege.grantee = 0), baseline_public AS ("
                    "SELECT object.classoid, object.objoid, object.objsubid, "
                    "privilege.privilege_type, privilege.is_grantable "
                    "FROM normalized object CROSS JOIN LATERAL aclexplode(CASE "
                    "WHEN object.initprivs IS NOT NULL THEN object.initprivs "
                    "WHEN object.objoid < 16384 THEN "
                    "acldefault(object.acl_kind, object.owner_oid) "
                    "ELSE ARRAY[]::aclitem[] END) "
                    "privilege WHERE privilege.grantee = 0) SELECT count(*) "
                    "FROM current_public current LEFT JOIN baseline_public baseline "
                    "ON baseline.classoid = current.classoid "
                    "AND baseline.objoid = current.objoid "
                    "AND baseline.objsubid = current.objsubid "
                    "AND baseline.privilege_type = current.privilege_type "
                    "AND baseline.is_grantable = current.is_grantable "
                    "WHERE baseline.objoid IS NULL"
                )
            )
            if public_catalog_acl_expansions != 0:
                raise ValueError("runner PUBLIC catalog ACL expansion")

            # PostgreSQL's information_schema views have a documented core
            # PUBLIC projection that is not fully represented in
            # pg_init_privs. Preserve only those initdb OIDs; any normal-OID
            # object created later starts from an empty PUBLIC baseline.
            public_information_schema_expansions = connection.scalar(
                sa.text(
                    "WITH observed AS ("
                    "SELECT 1 FROM pg_class relation JOIN pg_namespace namespace "
                    "ON namespace.oid = relation.relnamespace CROSS JOIN LATERAL "
                    "aclexplode(COALESCE(relation.relacl, acldefault(CASE WHEN "
                    "relation.relkind = 'S' THEN 'S' ELSE 'r' END::\"char\", "
                    "relation.relowner))) acl WHERE namespace.nspname = "
                    "'information_schema' AND relation.oid >= 16384 "
                    "AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_attribute attribute "
                    "JOIN pg_class relation ON relation.oid = attribute.attrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                    "WHERE namespace.nspname = 'information_schema' "
                    "AND relation.oid >= 16384 AND attribute.attnum > 0 "
                    "AND NOT attribute.attisdropped AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_proc procedure "
                    "JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace "
                    "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
                    "acldefault('f', procedure.proowner))) acl "
                    "WHERE namespace.nspname = 'information_schema' "
                    "AND procedure.oid >= 16384 AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_type type JOIN pg_namespace namespace "
                    "ON namespace.oid = type.typnamespace CROSS JOIN LATERAL "
                    "aclexplode(COALESCE(type.typacl, acldefault('T', type.typowner))) acl "
                    "WHERE namespace.nspname = 'information_schema' "
                    "AND type.oid >= 16384 AND acl.grantee = 0) "
                    "SELECT count(*) FROM observed"
                )
            )
            if public_information_schema_expansions != 0:
                raise ValueError("runner PUBLIC information_schema ACL expansion")

            # pg_toast and pg_temp prefixes are not a blanket trust boundary.
            # A privileged actor can place normal-OID routines in pg_toast and
            # grant schema reachability.  No post-initdb object under either
            # prefix may carry PUBLIC relation, column, routine, or type access.
            restricted_namespace_public_authority = connection.scalar(
                sa.text(
                    "WITH observed AS ("
                    "SELECT 1 FROM pg_class relation JOIN pg_namespace namespace "
                    "ON namespace.oid = relation.relnamespace CROSS JOIN LATERAL "
                    "aclexplode(COALESCE(relation.relacl, acldefault(CASE WHEN "
                    "relation.relkind = 'S' THEN 'S' ELSE 'r' END::\"char\", "
                    "relation.relowner))) acl WHERE relation.oid >= 16384 "
                    "AND (namespace.nspname LIKE 'pg_toast%' "
                    "OR namespace.nspname LIKE 'pg_temp%') AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_attribute attribute "
                    "JOIN pg_class relation ON relation.oid = attribute.attrelid "
                    "JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(attribute.attacl) acl "
                    "WHERE relation.oid >= 16384 AND attribute.attnum > 0 "
                    "AND NOT attribute.attisdropped AND ("
                    "namespace.nspname LIKE 'pg_toast%' OR "
                    "namespace.nspname LIKE 'pg_temp%') AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_proc procedure "
                    "JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace "
                    "CROSS JOIN LATERAL aclexplode(COALESCE(procedure.proacl, "
                    "acldefault('f', procedure.proowner))) acl "
                    "WHERE procedure.oid >= 16384 AND ("
                    "namespace.nspname LIKE 'pg_toast%' OR "
                    "namespace.nspname LIKE 'pg_temp%') AND acl.grantee = 0 "
                    "UNION ALL SELECT 1 FROM pg_type type JOIN pg_namespace namespace "
                    "ON namespace.oid = type.typnamespace CROSS JOIN LATERAL "
                    "aclexplode(COALESCE(type.typacl, acldefault('T', type.typowner))) acl "
                    "WHERE type.oid >= 16384 AND (namespace.nspname LIKE 'pg_toast%' "
                    "OR namespace.nspname LIKE 'pg_temp%') AND acl.grantee = 0) "
                    "SELECT count(*) FROM observed"
                )
            )
            if restricted_namespace_public_authority != 0:
                raise ValueError("runner PUBLIC restricted namespace ACL expansion")

            executable_functions = frozenset(
                tuple(row)
                for row in connection.execute(
                    sa.text(
                        "SELECT principal.name, namespace.nspname, procedure.proname, "
                        "oidvectortypes(procedure.proargtypes), "
                        "COALESCE(extension.extname, ''), "
                        "COALESCE(extension.extversion, '') "
                        "FROM (VALUES (CAST(:login AS name)), (CAST(:role AS name))) "
                        "AS principal(name) CROSS JOIN pg_proc procedure "
                        "JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace "
                        "LEFT JOIN pg_depend dependency ON dependency.classid = "
                        "'pg_proc'::regclass "
                        "AND dependency.objid = procedure.oid "
                        "AND dependency.refclassid = 'pg_extension'::regclass "
                        "AND dependency.deptype = 'e' "
                        "LEFT JOIN pg_extension extension ON extension.oid = dependency.refobjid "
                        "WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema') "
                        "AND namespace.nspname NOT LIKE 'pg_toast%' "
                        "AND namespace.nspname NOT LIKE 'pg_temp%' "
                        "AND has_function_privilege(principal.name, procedure.oid, 'EXECUTE')"
                    ),
                    {"login": expected_login, "role": _RUNNER_AGENT_DATABASE_ROLE},
                ).all()
            )
            pg_trgm_version = connection.scalar(
                sa.text("SELECT extversion FROM pg_extension WHERE extname = 'pg_trgm'")
            )
            if pg_trgm_version != "1.6":
                raise ValueError("runner extension contract")
            extension_functions = _RUNNER_AGENT_PG_TRGM_FUNCTIONS
            expected_executable_functions = frozenset(
                (
                    principal,
                    "public",
                    function_name,
                    arguments,
                    extension_name,
                    extension_version,
                )
                for principal in principal_names
                for function_name, arguments, extension_name, extension_version in (
                    *(
                        (function_name, arguments, "", "")
                        for function_name, arguments in _RUNNER_AGENT_API_FUNCTION_SIGNATURES
                    ),
                    *(
                        (function_name, arguments, "pg_trgm", "1.6")
                        for function_name, arguments in extension_functions
                    ),
                )
            )
            if executable_functions != expected_executable_functions:
                raise ValueError("runner effective function ACL")

            unsafe_default_acls = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_default_acl defaults "
                    "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl "
                    "WHERE defaults.defaclrole = (SELECT registration.relowner "
                    "FROM pg_class registration WHERE registration.oid = "
                    "'public.saas_runner_registrations'::regclass) "
                    "AND acl.grantee <> defaults.defaclrole"
                )
            )
            if unsafe_default_acls != 0:
                raise ValueError("runner default ACL")
            return runner_agent_database_authority_contract_sha256(server_major=server_major)
    except RunnerControlError:
        raise
    except Exception:  # noqa: BLE001 - database details and DSN stay private.
        raise RunnerControlError(
            "runner_executor_not_ready",
            "Runner database authority is unavailable",
        ) from None


def runner_agent_database_authority_contract_sha256(*, server_major: int = 18) -> str:
    """Hash every accepted runtime catalog constant; live values are exact-checked above."""

    if server_major != 18:
        raise RunnerControlError(
            "runner_executor_not_ready", "Runner database authority is unavailable"
        )
    document = {
        "api_function_signatures": sorted(_RUNNER_AGENT_API_FUNCTION_SIGNATURES),
        "connection_limit": _RUNNER_AGENT_DATABASE_CONNECTION_LIMIT,
        "denied_pg_catalog_functions": sorted(_RUNNER_AGENT_DENIED_PG_CATALOG_FUNCTIONS),
        "function_sha256": _RUNNER_AGENT_FUNCTION_SHA256_BY_MAJOR[server_major],
        "owner_only_function_signatures": sorted(_RUNNER_AGENT_OWNER_ONLY_FUNCTION_SIGNATURES),
        "pg_trgm_functions": sorted(_RUNNER_AGENT_PG_TRGM_FUNCTIONS),
        "policy_count": _RUNNER_AGENT_POLICY_COUNT,
        "policy_relation_count": _RUNNER_AGENT_POLICY_RELATION_COUNT,
        "policy_sha256s": sorted(_RUNNER_AGENT_POLICY_SHA256S_BY_MAJOR[server_major]),
        "role": _RUNNER_AGENT_DATABASE_ROLE,
        "schema_revision": "p0s000000012",
        "select_columns": sorted(_RUNNER_AGENT_SELECT_COLUMNS),
        "select_tables": sorted(_RUNNER_AGENT_SELECT_TABLES),
        "server_major": server_major,
        "support_policy_count": _RUNNER_AGENT_SUPPORT_POLICY_COUNT,
        "support_policy_sha256": _RUNNER_AGENT_SUPPORT_POLICY_SHA256_BY_MAJOR[server_major],
        "update_columns": sorted(_RUNNER_AGENT_UPDATE_COLUMNS),
    }
    return sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _positive_integer(source: Mapping[str, str], name: str, *, default: int, maximum: int) -> int:
    try:
        value = int(source.get(name, str(default)))
    except ValueError as error:
        raise RunnerControlError("runner_executor_config_invalid", f"{name} is invalid") from error
    if not 1 <= value <= maximum:
        raise RunnerControlError("runner_executor_config_invalid", f"{name} is invalid")
    return value


def _private_directory(path: Path, *, field: str, create: bool) -> Path:
    if not path.is_absolute():
        raise RunnerControlError("runner_executor_config_invalid", f"{field} is invalid")
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RunnerControlError(
            "runner_executor_config_invalid", f"{field} is invalid"
        ) from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RunnerControlError("runner_executor_config_invalid", f"{field} is invalid")
    return resolved


def _verified_repository_mirror_bindings(
    source: Mapping[str, str],
    *,
    runner_id: UUID,
    connection_generation: int,
) -> tuple[Mapping[str, Path], Path]:
    try:
        verified = load_and_verify_repository_bindings(
            _required(source, "OMNIGENT_SAAS_RUNNER_REPOSITORY_BINDINGS_FILE"),
            _required(source, "OMNIGENT_SAAS_RUNNER_REPOSITORY_RECEIPT_FILE"),
            expected_runner_id=runner_id,
            expected_runner_generation=connection_generation,
            expected_runner_slot=_required(
                source,
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT",
            ),
            expected_binding_keys=("primary",),
            expected_spec_sha256=_required(
                source,
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256",
            ),
            expected_bindings_sha256=_required(
                source,
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256",
            ),
            expected_receipt_sha256=_required(
                source,
                "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256",
            ),
        )
    except (RepositoryMirrorError, RunnerControlError):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Repository bindings are invalid"
        ) from None
    mirror_root = _private_directory(
        Path(_required(source, "OMNIGENT_SAAS_RUNNER_REPOSITORY_MIRROR_ROOT")),
        field="repository_mirror_root",
        create=False,
    )
    if any(
        not binding.resolve(strict=True).is_relative_to(mirror_root)
        for binding in verified.bindings.values()
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid",
            "Repository binding escaped the release-pinned mirror root",
        )
    return verified.bindings, mirror_root


def _recovery_s3_credentials(source: Mapping[str, str]) -> _RecoveryS3Credentials:
    if any(name.startswith(("AWS_", "BOTO_")) for name in source):
        raise RunnerControlError(
            "runner_executor_config_invalid",
            "Runner executor must not receive ambient AWS credential providers",
        )
    try:
        runner_id = UUID(_required(source, "OMNIGENT_SAAS_RUNNER_ID"))
        generation = _positive_integer(
            source,
            "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION",
            default=0,
            maximum=2**63 - 1,
        )
    except (ValueError, AttributeError, RunnerControlError):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery identity is invalid"
        ) from None
    if (
        runner_id.int == 0
        or source["OMNIGENT_SAAS_RUNNER_ID"] != str(runner_id)
        or source["OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION"] != str(generation)
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery identity is invalid"
        )
    profile = _required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE")
    if profile != f"runner-{runner_id}-g{generation}":
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credential profile is invalid"
        )
    path = Path(_required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_FILE"))
    if not path.is_absolute():
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        with os.fdopen(descriptor, "rb") as credential_file:
            metadata = os.fstat(credential_file.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not 1 <= metadata.st_size <= 65_536
            ):
                raise ValueError("unsafe credential file")
            payload = credential_file.read(65_537)
            if len(payload) != metadata.st_size:
                raise ValueError("unstable credential file")
        revision = _required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION")
        expected_revision = f"sha256:{sha256(payload).hexdigest()}"
        parser = RawConfigParser(interpolation=None, strict=True)
        parser.read_string(payload.decode("utf-8"))
    except (OSError, UnicodeError, ConfigParserError, ValueError):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        ) from None
    if not hmac.compare_digest(revision, expected_revision):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        )
    if parser.defaults() or parser.sections() != [profile]:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        )
    values = dict(parser.items(profile, raw=True))
    if set(values) != {"aws_access_key_id", "aws_secret_access_key"} or any(
        not value or value != value.strip() or "\x00" in value or "\n" in value or "\r" in value
        for value in values.values()
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        )
    access_key_id = values["aws_access_key_id"]
    secret_access_key = values["aws_secret_access_key"]
    if not 16 <= len(access_key_id) <= 256 or not 16 <= len(secret_access_key) <= 512:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery credentials file is invalid"
        )
    return _RecoveryS3Credentials(access_key_id, secret_access_key)


def _recovery_artifact_store(
    source: Mapping[str, str],
    *,
    runner_id: UUID | None = None,
    connection_generation: int | None = None,
) -> ObjectRecoveryArtifactStore:
    if (runner_id is None) != (connection_generation is None) or (
        runner_id is not None
        and connection_generation is not None
        and (
            source.get("OMNIGENT_SAAS_RUNNER_ID") != str(runner_id)
            or source.get("OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION")
            != str(connection_generation)
        )
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery identity is invalid"
        )
    uri = _required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI")
    parsed = urlsplit(uri)
    environment_runner_id = _required(source, "OMNIGENT_SAAS_RUNNER_ID")
    environment_generation = _required(source, "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION")
    required_suffix = f"/runner/{environment_runner_id}/generation/{environment_generation}"
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or ".." in Path(parsed.path).parts
        or not parsed.path.endswith(required_suffix)
        or parsed.path.endswith("/")
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery artifact URI is invalid"
        )
    endpoint = _required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL")
    parsed_endpoint = urlsplit(endpoint)
    if (
        parsed_endpoint.scheme != "https"
        or not parsed_endpoint.hostname
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or parsed_endpoint.path
        or parsed_endpoint.query
        or parsed_endpoint.fragment
        or endpoint != f"https://{parsed_endpoint.netloc}"
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery artifact endpoint is invalid"
        )
    region = _required(source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_REGION")
    credential_revision = _required(
        source, "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION"
    )
    if (
        not _opaque(region)
        or len(credential_revision) != 71
        or not credential_revision.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in credential_revision[7:])
    ):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery artifact region is invalid"
        )
    credentials = _recovery_s3_credentials(source)
    try:
        import boto3
        from botocore.config import Config

        from omnigent.stores.artifact_store.s3 import S3ArtifactStore

        client = boto3.client(
            "s3",
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            endpoint_url=endpoint,
            region_name=region,
            config=Config(
                signature_version="s3v4",
                connect_timeout=5,
                read_timeout=30,
                retries={"mode": "standard", "max_attempts": 3},
            ),
        )
        return ObjectRecoveryArtifactStore(S3ArtifactStore(uri, client=client))
    except Exception:  # noqa: BLE001 - provider errors may contain credentials.
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner recovery artifact store is unavailable"
        ) from None


def _expected_cgroup_path(source: Mapping[str, str]) -> str:
    configured = _required(source, "OMNIGENT_SAAS_RUNNER_EXPECTED_CGROUP_PATH")
    if configured != "self":
        return configured
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner cgroup membership is unavailable"
        ) from error
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner requires one unified cgroup"
        )
    return lines[0][3:]


class ProductionHostIsolationExecutor:
    """Execute immutable Runs through existing Worktree and sandbox authorities."""

    def __init__(
        self,
        *,
        config: RunnerExecutorConfig,
        engine: Engine,
        sessions: sessionmaker[Session],
        worktrees: WorktreeControlPlane,
        isolation: IsolationControlPlane,
        worktree_adapter: RunnerWorktreeAdapter,
        isolation_adapter: RunnerIsolationAdapter,
        reserved_bytes: int,
        worktree_lease_seconds: int,
        command_timeout_seconds: int,
        database_fleet_verifier: Callable[[], None] | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._sessions = sessions
        self._worktrees = worktrees
        self._isolation = isolation
        self._worktree_adapter = worktree_adapter
        self._isolation_adapter = isolation_adapter
        self._preview_commands = PreviewRunnerExecutionAuthority(sessions)
        self._preview_supervisor: RunnerPreviewProcessSupervisor | None = None
        self._reserved_bytes = reserved_bytes
        self._worktree_lease_seconds = worktree_lease_seconds
        self._command_timeout_seconds = command_timeout_seconds
        self._database_fleet_verifier = database_fleet_verifier
        self._worktree_heartbeat_interval_seconds = max(0.1, worktree_lease_seconds / 3)
        self._worktree_heartbeat_timeout_seconds = max(0.1, worktree_lease_seconds / 6)
        self._worktree_heartbeat_safety_seconds = max(0.2, worktree_lease_seconds / 3)
        self._heartbeat_worker = _HeartbeatCallWorker()
        self._heartbeat_worker_poisoned = False
        self._database_authority_poisoned = False
        self._active: dict[UUID, _ActiveExecution] = {}
        self._preparing: set[UUID] = set()
        self._lock = Lock()

    def bind_preview_runtime(self, supervisor: RunnerPreviewProcessSupervisor) -> None:
        """Bind the process supervisor owned by this Runner incarnation's tunnel."""

        if not isinstance(supervisor, RunnerPreviewProcessSupervisor):
            raise RunnerControlError(
                "runner_preview_runtime_invalid", "Preview runtime is unavailable"
            )
        with self._lock:
            if self._active or self._preparing or self._preview_supervisor is not None:
                raise RunnerControlError(
                    "runner_preview_runtime_invalid", "Preview runtime is already bound"
                )
            self._preview_supervisor = supervisor

    def assert_production_ready(self) -> None:
        if self._engine.dialect.name != "postgresql":
            raise RunnerControlError(
                "runner_executor_not_ready", "Runner executor requires PostgreSQL"
            )
        with self._engine.connect() as connection:
            connection.execute(sa.text("SELECT 1"))
        if self._preview_supervisor is None:
            raise RunnerControlError("runner_executor_not_ready", "Preview runtime is not bound")
        self.assert_claimable()

    def assert_claimable(self) -> None:
        """Revalidate live DB authority and reject every poisoned incarnation."""

        with self._lock:
            heartbeat_poisoned = self._heartbeat_worker_poisoned
            authority_poisoned = self._database_authority_poisoned
        if heartbeat_poisoned:
            raise RunnerControlError(
                "runner_worktree_heartbeat_worker_poisoned",
                "Worktree heartbeat worker requires Runner restart",
            )
        if authority_poisoned:
            raise RunnerControlError(
                "runner_database_authority_poisoned",
                "Runner database authority requires Runner restart",
            )
        try:
            if self._database_fleet_verifier is not None:
                self._database_fleet_verifier()
            else:
                _verify_runner_agent_database_authority(
                    self._engine,
                    runner_id=self._config.runner_id,
                    connection_generation=self._config.connection_generation,
                )
        except RunnerControlError:
            with self._lock:
                self._database_authority_poisoned = True
            raise RunnerControlError(
                "runner_database_authority_drifted",
                "Runner database authority changed after startup",
            ) from None

    def _load_run(
        self, lease: RunnerControlClientLease
    ) -> tuple[RunRecord, ProductionRunExecutionSpec]:
        envelope = lease.execution_envelope
        if (
            envelope is None
            or envelope.runner_id != self._config.runner_id
            or envelope.run_id != lease.run_id
            or envelope.fence_token != lease.fence_token
            or envelope.product_revision != self._config.product_revision
            or envelope.image_digest != self._config.image_digest
        ):
            raise RunnerControlError(
                "runner_execution_envelope_invalid", "Execution envelope is misbound"
            )
        with self._sessions() as database:
            # The executor login is subject to FORCE RLS in production.  Bind
            # only the already authenticated, immutable claim scope before any
            # Run/dispatch lookup; never derive a broader context from rows that
            # would otherwise be invisible.
            apply_rls_context(
                database,
                RlsContext(
                    tenant_id=envelope.tenant_id,
                    space_id=envelope.space_id,
                    project_id=envelope.project_id,
                ),
            )
            run = database.get(RunRecord, lease.run_id)
            dispatch = database.get(RunDispatchRecord, lease.run_id)
            expires_at = None if run is None else run.lease_expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if (
                run is None
                or dispatch is None
                or run.tenant_id != envelope.tenant_id
                or run.space_id != envelope.space_id
                or run.project_id != envelope.project_id
                or run.product_revision != envelope.product_revision
                or run.status != "running"
                or run.lease_owner != str(envelope.runner_id)
                or run.lease_token != lease.lease_token
                or run.fence_token != envelope.fence_token
                or expires_at is None
                or expires_at <= datetime.now(timezone.utc)
                or run.input.get("change_set_id") != str(envelope.change_set_id)
                or dispatch.status != "leased"
                or dispatch.selected_runner_id != envelope.runner_id
                or dispatch.selected_failure_domain != lease.failure_domain
                or dispatch.dispatch_generation != lease.dispatch_generation
                or dispatch.execution_profile_id != envelope.execution_profile_id
                or dispatch.execution_profile_hash != envelope.execution_profile_hash
                or dispatch.egress_policy_id != envelope.egress_policy_id
                or dispatch.egress_policy_hash != envelope.egress_policy_hash
                or dispatch.requirements_hash
                != dispatch_requirements_hash(
                    tenant_id=dispatch.tenant_id,
                    space_id=dispatch.space_id,
                    project_id=dispatch.project_id,
                    pool_id=dispatch.pool_id,
                    execution_profile_id=dispatch.execution_profile_id,
                    execution_profile_hash=dispatch.execution_profile_hash,
                    egress_policy_id=dispatch.egress_policy_id,
                    egress_policy_hash=dispatch.egress_policy_hash,
                    queue_class=dispatch.queue_class,
                    required_capabilities=list(dispatch.required_capabilities),
                    cost_units=dispatch.cost_units,
                    eligible_at=dispatch.eligible_at,
                    max_wait_at=dispatch.max_wait_at,
                )
            ):
                raise RunnerControlError(
                    "runner_execution_envelope_invalid", "Run changed after claim"
                )
            try:
                execution_spec = production_run_execution_spec(run.input)
            except ManagedRunExecutionSpecError as exc:
                raise RunnerControlError(
                    "runner_execution_envelope_invalid",
                    "Run execution specification changed after claim",
                ) from exc
            if (
                execution_spec.spec_hash != envelope.execution_spec_hash
                or execution_spec.launch_argv != envelope.launch_argv
                or execution_spec.kind != envelope.execution_kind
                or execution_spec.preview_execution_id != envelope.preview_execution_id
                or execution_spec.checkpoint_revision != envelope.checkpoint_revision
            ):
                raise RunnerControlError(
                    "runner_execution_envelope_invalid",
                    "Run execution specification changed after claim",
                )
            return run, execution_spec

    def _allocate_execution(
        self, lease: RunnerControlClientLease
    ) -> tuple[_ActiveExecution, tuple[str, ...]]:
        _run, execution_spec = self._load_run(lease)
        envelope = lease.execution_envelope
        assert envelope is not None
        preview_claim: PreviewRunnerStartClaim | None = None
        if execution_spec.kind == _PREVIEW_EXECUTION_KIND:
            if self._preview_supervisor is None:
                raise RunnerControlError(
                    "runner_preview_runtime_invalid", "Preview runtime is unavailable"
                )
            preview_claim = self._preview_commands.claim_start(
                tenant_id=envelope.tenant_id,
                space_id=envelope.space_id,
                project_id=envelope.project_id,
                child_run_id=envelope.run_id,
                runner_id=envelope.runner_id,
                connection_generation=self._config.connection_generation,
                run_fence_token=envelope.fence_token,
                capability_token=lease.capability_token,
                preview_execution_id=execution_spec.preview_execution_id,
            )
        try:
            worktree_lease = self._worktrees.allocate_worktree(
                capability_token=lease.capability_token,
                runner_id=envelope.runner_id,
                run_id=envelope.run_id,
                change_set_id=envelope.change_set_id,
                access_mode=(
                    "readonly" if execution_spec.kind == _PREVIEW_EXECUTION_KIND else "writer"
                ),
                reserved_bytes=self._reserved_bytes,
                lease_duration=timedelta(seconds=self._worktree_lease_seconds),
                trace_id=f"runner:{envelope.runner_id}",
            )
        except Exception:
            if preview_claim is not None:
                with contextlib.suppress(Exception):
                    self._preview_commands.abort_runtime(
                        preview_claim,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        cancelled=False,
                    )
            raise
        # Register the lease as soon as it exists.  If Git materialization or
        # grant preparation fails, the agent can still terminalize the Run and
        # release/quarantine this exact fenced Worktree instead of losing it in
        # an untracked preparation exception.
        active = _ActiveExecution(
            worktree_lease,
            execution_kind=execution_spec.kind,
            preview_claim=preview_claim,
        )
        with self._lock:
            self._active[lease.run_id] = active
        return active, execution_spec.launch_argv

    def _finish_preparation(
        self, active: _ActiveExecution, lease: RunnerControlClientLease
    ) -> None:
        envelope = lease.execution_envelope
        assert envelope is not None
        physical_worktree = self._worktree_adapter.materialize(
            active.worktree_lease,
            trace_id=f"runner:{envelope.runner_id}:materialize",
        )
        with self._lock:
            active.physical_worktree = physical_worktree
        if active.execution_kind == _PREVIEW_EXECUTION_KIND:
            claim = active.preview_claim
            if claim is None or not physical_worktree.readonly:
                raise RunnerControlError(
                    "runner_preview_runtime_invalid", "Preview readonly Worktree is unavailable"
                )
            self._preview_commands.mark_starting(
                claim,
                runner_id=envelope.runner_id,
                connection_generation=self._config.connection_generation,
                run_fence_token=envelope.fence_token,
            )
            return
        grant = self._worktrees.materialization_grant(
            worktree_id=active.worktree_lease.worktree_id,
            runner_id=envelope.runner_id,
            lease_generation=active.worktree_lease.lease_generation,
            run_fence_token=envelope.fence_token,
            lease_token=active.worktree_lease.lease_token,
        )
        issued = self._isolation.issue_launch_grant(
            capability_token=lease.capability_token,
            runner_id=envelope.runner_id,
            run_id=envelope.run_id,
            worktree_grant=grant,
        )
        prepared = self._isolation_adapter.prepare(
            grant_token=issued.token,
            runner_id=envelope.runner_id,
            run_id=envelope.run_id,
            physical_worktree=physical_worktree,
        )
        with self._lock:
            accepted = not active.environment_closed and not active.lease_lost
            if accepted:
                active.prepared = prepared
        if not accepted:
            prepared.close()

    def _prepare(
        self, lease: RunnerControlClientLease
    ) -> tuple[_ActiveExecution, tuple[str, ...]]:
        active, command = self._allocate_execution(lease)
        self._finish_preparation(active, lease)
        return active, command

    def _close_environment(self, active: _ActiveExecution) -> None:
        with self._lock:
            if active.environment_closed:
                return
            active.environment_closed = True
            environment = active.environment
        close = getattr(environment, "close", None)
        if callable(close):
            close()

    @staticmethod
    def _close_prepared(active: _ActiveExecution) -> None:
        if active.prepared is not None:
            active.prepared.close()

    def _publish_environment(self, active: _ActiveExecution, environment: object) -> bool:
        with self._lock:
            if active.environment_closed:
                accepted = False
            else:
                active.environment = environment
                accepted = True
        if not accepted:
            close = getattr(environment, "close", None)
            if callable(close):
                close()
        return accepted

    async def _lose_worktree_lease(self, active: _ActiveExecution) -> None:
        with self._lock:
            active.lease_lost = True
        await asyncio.to_thread(self._close_environment, active)
        await asyncio.to_thread(self._close_prepared, active)

    async def _renew_worktree(self, active: _ActiveExecution, *, safety_seconds: float) -> None:
        """Perform one isolated authoritative renewal without using the default pool."""

        async with active.heartbeat_lock:
            with self._lock:
                current = active.worktree_lease
                physical_worktree = active.physical_worktree
                poisoned = self._heartbeat_worker_poisoned
                finalizing = active.finalizing
                lease_lost = active.lease_lost
            if lease_lost:
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unknown",
                    "Worktree lease was already lost",
                )
            if poisoned:
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_worker_poisoned",
                    "Worktree heartbeat worker requires Runner restart",
                )
            lease_duration = timedelta(seconds=self._worktree_lease_seconds)

            def call() -> object:
                if finalizing:
                    return self._worktree_adapter.renew_fence(
                        current,
                        lease_duration=lease_duration,
                        physical_worktree=physical_worktree,
                    )
                return self._worktree_adapter.heartbeat(
                    current,
                    lease_duration=lease_duration,
                    physical_worktree=physical_worktree,
                )

            future = self._heartbeat_worker.submit(call)
            wrapped = asyncio.wrap_future(future)
            timeout = min(
                self._worktree_heartbeat_timeout_seconds,
                max(0.1, safety_seconds / 2),
            )
            try:
                done, _pending = await asyncio.wait({wrapped}, timeout=timeout)
            except asyncio.CancelledError:
                with self._lock:
                    self._heartbeat_worker_poisoned = True
                await self._lose_worktree_lease(active)
                raise
            if not done:
                # The isolated daemon may eventually return, but it can never
                # consume the default pool or receive another call.  Poisoning
                # the executor requires process replacement before another Run.
                with self._lock:
                    self._heartbeat_worker_poisoned = True
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unknown",
                    "Worktree heartbeat exceeded its bounded response window",
                )
            try:
                mutation = cast(Any, wrapped.result())
            except Exception as error:
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unknown",
                    "Worktree heartbeat failed or returned an unknown result",
                ) from error
            renewed_until = mutation.lease_expires_at
            if renewed_until is None:
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unknown",
                    "Worktree heartbeat returned no authoritative expiry",
                )
            if renewed_until.tzinfo is None:
                renewed_until = renewed_until.replace(tzinfo=timezone.utc)
            if renewed_until <= datetime.now(timezone.utc) + timedelta(seconds=safety_seconds):
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unsafe",
                    "Worktree heartbeat did not preserve the safety margin",
                )
            with self._lock:
                if active.lease_lost:
                    return
                active.worktree_lease = replace(current, expires_at=renewed_until)

    async def _stop_worktree_heartbeat(
        self,
        active: _ActiveExecution,
        *,
        require_healthy: bool,
    ) -> None:
        with self._lock:
            stop = active.heartbeat_stop
            task = active.heartbeat_task
        if stop is None or task is None:
            return
        stop.set()
        failure: BaseException | None = None
        try:
            await task
        except (Exception, asyncio.CancelledError) as error:  # noqa: BLE001
            failure = error
        finally:
            with self._lock:
                if active.heartbeat_task is task:
                    active.heartbeat_task = None
                    active.heartbeat_stop = None
        if failure is not None and require_healthy:
            raise RunnerControlError(
                "runner_worktree_heartbeat_unknown",
                "Worktree heartbeat failed before terminal transition",
            ) from failure

    async def _heartbeat_worktree(self, active: _ActiveExecution, stop: asyncio.Event) -> None:
        """Renew from allocation through checkpoint and the final terminal seal."""

        while True:
            with self._lock:
                current = active.worktree_lease
            expires_at = current.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            remaining = (expires_at - datetime.now(timezone.utc)).total_seconds()
            if remaining <= 0:
                await self._lose_worktree_lease(active)
                raise RunnerControlError(
                    "runner_worktree_heartbeat_unsafe",
                    "Worktree lease expired before heartbeat",
                )
            # Allocation may be capped by a much shorter Run lease (45s in the
            # production policy) even when the requested Worktree TTL is 300s.
            # Base cadence and safety on that effective window, never the
            # configured upper bound alone.
            safety_seconds = min(
                self._worktree_heartbeat_safety_seconds,
                max(0.2, remaining / 3),
            )
            delay = min(
                self._worktree_heartbeat_interval_seconds,
                max(0.0, remaining - safety_seconds),
            )
            if delay:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                except TimeoutError:
                    pass
                else:
                    return
            if stop.is_set():
                return
            await self._renew_worktree(active, safety_seconds=safety_seconds)

    async def _stop_preview_process(self, active: _ActiveExecution) -> bool:
        claim = active.preview_claim
        supervisor = self._preview_supervisor
        if claim is None or supervisor is None:
            return not active.preview_started
        if not active.preview_started:
            return True
        exit_state = await supervisor.stop(claim.preview_execution_id)
        if exit_state is None:
            exit_state = await supervisor.last_exit(claim.preview_execution_id)
        active.preview_started = False
        return exit_state is not None and exit_state.cleanup_error_code is None

    async def _execute_preview(
        self,
        active: _ActiveExecution,
        lease: RunnerControlClientLease,
        *,
        cancellation: asyncio.Event,
        heartbeat: asyncio.Task[None],
    ) -> str:
        envelope = lease.execution_envelope
        claim = active.preview_claim
        physical = active.physical_worktree
        supervisor = self._preview_supervisor
        if (
            envelope is None
            or claim is None
            or physical is None
            or not physical.readonly
            or supervisor is None
        ):
            raise RunnerControlError(
                "runner_preview_runtime_invalid", "Preview runtime is unavailable"
            )
        try:
            current_expiry = active.worktree_lease.expires_at
            if current_expiry.tzinfo is None:
                current_expiry = current_expiry.replace(tzinfo=timezone.utc)
            remaining = (current_expiry - datetime.now(timezone.utc)).total_seconds()
            safety_seconds = min(
                self._worktree_heartbeat_safety_seconds,
                max(0.2, remaining / 3),
            )
            await self._renew_worktree(active, safety_seconds=safety_seconds)
            route = await asyncio.to_thread(
                self._preview_commands.prepare_route,
                claim,
                runner_id=envelope.runner_id,
                connection_generation=self._config.connection_generation,
                run_fence_token=envelope.fence_token,
                worktree_id=active.worktree_lease.worktree_id,
                worktree_lease_generation=active.worktree_lease.lease_generation,
            )
            execution = static_web_preview_execution(
                {
                    "change_set_id": str(claim.change_set_id),
                    "execution": {
                        "checkpoint_revision": claim.checkpoint_revision,
                        "kind": _PREVIEW_EXECUTION_KIND,
                        "preview_execution_id": str(claim.preview_execution_id),
                        "profile": "static_web_v1",
                    },
                }
            )
            process_spec = await asyncio.to_thread(execution.process_spec, physical.worktree_path)
            await supervisor.start(route, process_spec)
            active.preview_started = True
            await asyncio.to_thread(
                self._preview_commands.mark_ready,
                claim,
                runner_id=envelope.runner_id,
                connection_generation=self._config.connection_generation,
                run_fence_token=envelope.fence_token,
                worktree_id=active.worktree_lease.worktree_id,
                worktree_lease_generation=active.worktree_lease.lease_generation,
            )

            async def wait_for_stop() -> PreviewRunnerStopClaim:
                while True:
                    requested = await asyncio.to_thread(
                        self._preview_commands.claim_stop,
                        tenant_id=claim.tenant_id,
                        space_id=claim.space_id,
                        project_id=claim.project_id,
                        preview_execution_id=claim.preview_execution_id,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        child_run_id=claim.child_run_id,
                        capability_token=lease.capability_token,
                    )
                    if requested is not None:
                        return requested
                    if await supervisor.snapshot(claim.preview_execution_id) is None:
                        raise RunnerControlError(
                            "runner_preview_process_lost",
                            "Preview process exited before a durable stop",
                        )
                    await asyncio.sleep(0.25)

            stop_command = asyncio.create_task(
                wait_for_stop(), name=f"preview-stop-command-{claim.preview_execution_id}"
            )
            cancelled = asyncio.create_task(
                cancellation.wait(), name=f"preview-run-cancel-{claim.preview_execution_id}"
            )
            try:
                done, _pending = await asyncio.wait(
                    {stop_command, cancelled, heartbeat},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if heartbeat in done:
                    with contextlib.suppress(Exception):
                        await heartbeat
                    await self._stop_preview_process(active)
                    return "orphaned"
                if cancelled in done:
                    clean = await self._stop_preview_process(active)
                    await asyncio.to_thread(
                        self._preview_commands.abort_runtime,
                        claim,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        cancelled=True,
                    )
                    return "cancelled" if clean else "orphaned"
                try:
                    stop_claim = await stop_command
                except Exception:  # noqa: BLE001 - process detail stays private.
                    await self._stop_preview_process(active)
                    await asyncio.to_thread(
                        self._preview_commands.abort_runtime,
                        claim,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        cancelled=False,
                    )
                    return "failed"
                clean = await self._stop_preview_process(active)
                await asyncio.to_thread(
                    self._preview_commands.complete_stop,
                    stop_claim,
                    runner_id=envelope.runner_id,
                    connection_generation=self._config.connection_generation,
                    run_fence_token=envelope.fence_token,
                    success=clean,
                )
                return "succeeded" if clean else "failed"
            finally:
                cancelled.cancel()
                stop_command.cancel()
                await asyncio.gather(cancelled, stop_command, return_exceptions=True)
        except Exception:
            await self._stop_preview_process(active)
            if not active.lease_lost:
                with contextlib.suppress(PreviewExecutionControlPlaneError):
                    await asyncio.to_thread(
                        self._preview_commands.abort_runtime,
                        claim,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        cancelled=False,
                    )
            raise

    async def execute(
        self,
        lease: RunnerControlClientLease,
        *,
        cancellation: asyncio.Event,
    ) -> str:
        with self._lock:
            if self._heartbeat_worker_poisoned:
                raise RunnerControlError(
                    "runner_worktree_heartbeat_worker_poisoned",
                    "Worktree heartbeat worker requires Runner restart",
                )
            if lease.run_id in self._active or lease.run_id in self._preparing:
                raise RunnerControlError(
                    "runner_execution_duplicate", "Run already has an active launch"
                )
            self._preparing.add(lease.run_id)
        try:
            active, command = await asyncio.to_thread(self._allocate_execution, lease)
        finally:
            with self._lock:
                self._preparing.discard(lease.run_id)
        heartbeat_stop = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._heartbeat_worktree(active, heartbeat_stop),
            name=f"worktree-heartbeat-{lease.run_id}",
        )
        with self._lock:
            active.heartbeat_stop = heartbeat_stop
            active.heartbeat_task = heartbeat
        try:
            # The durable lease is already heartbeating while Git and sandbox
            # preparation run; materialization never owns liveness implicitly.
            await asyncio.to_thread(self._finish_preparation, active, lease)
            if heartbeat.done():
                try:
                    await heartbeat
                except Exception:  # noqa: BLE001 - heartbeat details are sensitive.
                    return "orphaned"
                await self._lose_worktree_lease(active)
                return "orphaned"
            if active.execution_kind == _PREVIEW_EXECUTION_KIND:
                if cancellation.is_set():
                    return "cancelled"
                return await self._execute_preview(
                    active,
                    lease,
                    cancellation=cancellation,
                    heartbeat=heartbeat,
                )
            if active.prepared is None:
                if active.lease_lost:
                    return "orphaned"
                raise RunnerControlError(
                    "runner_execution_kernel_invalid",
                    "Official isolation kernel is unavailable",
                )
            if cancellation.is_set():
                await asyncio.to_thread(self._close_prepared, active)
                return "cancelled"
            # Keep the official async helper on this event loop for its complete
            # lifecycle; only synchronous database/Git preparation runs in the
            # worker thread above.
            environment = await active.prepared.start()
            if not await asyncio.to_thread(self._publish_environment, active, environment):
                return "orphaned" if active.lease_lost else "cancelled"
            if heartbeat.done():
                try:
                    await heartbeat
                except Exception:  # noqa: BLE001 - heartbeat details are sensitive.
                    return "orphaned"
                await self._lose_worktree_lease(active)
                return "orphaned"
            # A fresh authoritative CAS after helper startup prevents shell
            # launch on a lease that expired or was fenced during preparation.
            current_expiry = active.worktree_lease.expires_at
            if current_expiry.tzinfo is None:
                current_expiry = current_expiry.replace(tzinfo=timezone.utc)
            remaining = (current_expiry - datetime.now(timezone.utc)).total_seconds()
            safety_seconds = min(
                self._worktree_heartbeat_safety_seconds,
                max(0.2, remaining / 3),
            )
            try:
                await self._renew_worktree(active, safety_seconds=safety_seconds)
            except Exception:  # noqa: BLE001 - authoritative CAS failed closed.
                return "orphaned"
            shell = getattr(active.environment, "shell", None)
            if not callable(shell):
                raise RunnerControlError(
                    "runner_execution_kernel_invalid", "Official isolation kernel is unavailable"
                )
            execution = asyncio.create_task(
                cast(
                    Coroutine[Any, Any, dict[str, object]],
                    shell(
                        shlex.join(command),
                        timeout=self._command_timeout_seconds,
                        max_output=4 * 1024 * 1024,
                    ),
                )
            )
            cancelled = asyncio.create_task(cancellation.wait())
            try:
                done, _pending = await asyncio.wait(
                    {execution, cancelled, heartbeat}, return_when=asyncio.FIRST_COMPLETED
                )
                if heartbeat in done:
                    try:
                        await heartbeat
                    except Exception:  # noqa: BLE001 - heartbeat details are sensitive.
                        await self.cancel(lease)
                        return "orphaned"
                    await self._lose_worktree_lease(active)
                    return "orphaned"
                if cancelled in done and execution not in done:
                    await self.cancel(lease)
                    return "cancelled"
                result = await execution
                clean = result.get("exit_code") in {None, 0} and "error" not in result
                return "succeeded" if clean else "failed"
            finally:
                cancelled.cancel()
                if not execution.done():
                    execution.cancel()
                await asyncio.gather(cancelled, execution, return_exceptions=True)
        finally:
            # The exact Worktree fence remains live through checkpoint and the
            # final pre-terminal CAS. ``prepare_terminal_transition`` owns the
            # normal stop; failed paths are recovered by the same durable fence.
            await asyncio.to_thread(self._close_environment, active)

    async def cancel(self, lease: RunnerControlClientLease) -> None:
        with self._lock:
            active = self._active.get(lease.run_id)
        if active is None:
            return
        if active.execution_kind == _PREVIEW_EXECUTION_KIND:
            await self._stop_preview_process(active)
        await asyncio.to_thread(self._close_environment, active)
        await asyncio.to_thread(self._close_prepared, active)

    def _reconcile_physical_gc(self, *, limit: int) -> int:
        deleted = 0
        # Discovery is bounded to this Runner's durable logical rows.  Physical
        # deletion still derives and inspects only the adapter's private state
        # path, and requires a fresh exact deletion_grant before any I/O.
        with self._sessions() as database:
            candidates = tuple(
                database.execute(
                    sa.select(
                        WorktreeInstanceRecord.id,
                        WorktreeInstanceRecord.lease_generation,
                        WorktreeInstanceRecord.opaque_runtime_key,
                    )
                    .where(
                        WorktreeInstanceRecord.runner_id == self._config.runner_id,
                        WorktreeInstanceRecord.status == "gc_eligible",
                    )
                    .order_by(WorktreeInstanceRecord.id)
                    .limit(limit)
                )
            )
        for worktree_id, lease_generation, opaque_runtime_key in candidates:
            try:
                self._worktree_adapter.delete(
                    worktree_id=worktree_id,
                    expected_lease_generation=lease_generation,
                    opaque_runtime_key=opaque_runtime_key,
                    trace_id=f"runner:{self._config.runner_id}:physical-gc",
                )
            except WorktreeControlPlaneError as error:
                # Most local states are still live.  Only the exact, current
                # gc_eligible fence grants physical deletion; stale probes are
                # expected and never weaken or mutate that authority.
                if error.code == "worktree_delete_fence_stale":
                    continue
                raise
            deleted += 1
        return deleted

    async def reconcile_physical_gc(self, *, limit: int) -> int:
        if not 1 <= limit <= 1000:
            raise RunnerControlError("runner_gc_limit_invalid", "Runner GC limit is invalid")
        return await asyncio.to_thread(self._reconcile_physical_gc, limit=limit)

    async def prepare_finalization(
        self,
        lease: RunnerControlClientLease,
        *,
        result: str,
    ) -> str:
        """Checkpoint the fenced writer before any durable terminal transition.

        A failed checkpoint is never converted into success.  The exact
        Worktree remains fenced for the existing lease-expiry/quarantine
        recovery loop and the caller terminalizes the Run as ``orphaned``.
        """

        with self._lock:
            active = self._active.get(lease.run_id)
        if active is None:
            return result
        with self._lock:
            active.finalizing = True
        current_expiry = active.worktree_lease.expires_at
        if current_expiry.tzinfo is None:
            current_expiry = current_expiry.replace(tzinfo=timezone.utc)
        remaining = (current_expiry - datetime.now(timezone.utc)).total_seconds()
        safety_seconds = min(
            self._worktree_heartbeat_safety_seconds,
            max(0.2, remaining / 3),
        )
        try:
            # Serialize behind any in-flight command heartbeat.  An unknown
            # result must become visible before checkpoint can publish data.
            await self._renew_worktree(active, safety_seconds=safety_seconds)
        except Exception:  # noqa: BLE001 - authority details stay private.
            active.finalization_failed = True
            return "orphaned"
        envelope = lease.execution_envelope
        if active.execution_kind == _PREVIEW_EXECUTION_KIND:
            clean = await self._stop_preview_process(active)
            if active.lease_lost or envelope is None:
                active.finalization_failed = True
                return "orphaned"
            claim = active.preview_claim
            if claim is not None:
                try:
                    await asyncio.to_thread(
                        self._preview_commands.abort_runtime,
                        claim,
                        runner_id=envelope.runner_id,
                        connection_generation=self._config.connection_generation,
                        run_fence_token=envelope.fence_token,
                        cancelled=result == "cancelled",
                    )
                except PreviewExecutionControlPlaneError:
                    if result != "succeeded":
                        active.finalization_failed = True
                        return "orphaned"
            if not clean:
                active.finalization_failed = True
                return "orphaned"
            return result
        await asyncio.to_thread(self._close_environment, active)
        await asyncio.to_thread(self._close_prepared, active)
        if active.physical_worktree is None:
            return result
        if active.checkpointed:
            return result
        if active.lease_lost:
            active.finalization_failed = True
            return "orphaned"
        if envelope is None:
            active.finalization_failed = True
            return "orphaned"
        try:
            await asyncio.to_thread(
                self._worktree_adapter.checkpoint,
                active.worktree_lease,
                environment_snapshot_ref=(
                    f"run:{envelope.run_id}:fence:{envelope.fence_token}:final"
                ),
                trace_id=f"runner:{envelope.runner_id}:checkpoint:{result}",
            )
        except Exception:  # noqa: BLE001 - adapter details may contain sensitive paths.
            active.finalization_failed = True
            return "orphaned"
        active.checkpointed = True
        return result

    async def prepare_terminal_transition(self, lease: RunnerControlClientLease) -> None:
        """Seal one fresh fence, then stop renewals immediately before Run terminality."""

        with self._lock:
            active = self._active.get(lease.run_id)
        if active is None:
            return
        await self._stop_worktree_heartbeat(active, require_healthy=True)
        if active.lease_lost:
            raise RunnerControlError(
                "runner_worktree_heartbeat_unknown",
                "Worktree lease was lost before terminal transition",
            )
        current_expiry = active.worktree_lease.expires_at
        if current_expiry.tzinfo is None:
            current_expiry = current_expiry.replace(tzinfo=timezone.utc)
        remaining = (current_expiry - datetime.now(timezone.utc)).total_seconds()
        safety_seconds = min(
            self._worktree_heartbeat_safety_seconds,
            max(0.2, remaining / 3),
        )
        await self._renew_worktree(active, safety_seconds=safety_seconds)
        if active.lease_lost:
            raise RunnerControlError(
                "runner_worktree_heartbeat_unknown",
                "Worktree lease was lost before terminal transition",
            )

    async def finalize(self, lease: RunnerControlClientLease, *, result: str) -> None:
        with self._lock:
            active = self._active.get(lease.run_id)
        if active is None:
            return
        # Defensive for direct callers: normal agent flow already seals and
        # stops this task before the Run becomes terminal.
        await self._stop_worktree_heartbeat(active, require_healthy=False)
        envelope = lease.execution_envelope
        if envelope is None:
            raise RunnerControlError(
                "runner_execution_envelope_invalid", "Execution envelope is missing"
            )
        await asyncio.to_thread(self._close_environment, active)
        await asyncio.to_thread(self._close_prepared, active)
        final_change_set_status = None
        if active.execution_kind != _PREVIEW_EXECUTION_KIND:
            final_change_set_status = (
                "committed"
                if result == "succeeded" and active.checkpointed
                else "checkpointed"
                if active.checkpointed
                else None
            )
        await asyncio.to_thread(
            self._worktrees.release,
            worktree_id=active.worktree_lease.worktree_id,
            runner_id=envelope.runner_id,
            lease_generation=active.worktree_lease.lease_generation,
            run_fence_token=active.worktree_lease.run_fence_token,
            lease_token=active.worktree_lease.lease_token,
            final_change_set_status=final_change_set_status,
            trace_id=f"runner:{envelope.runner_id}:release:{result}",
        )
        # Retain the exact local fence until durable release succeeds.  A
        # transient/unknown failure can then be retried in-process instead of
        # silently discarding the only recoverable finalization state.
        with self._lock:
            if self._active.get(lease.run_id) is active:
                self._active.pop(lease.run_id, None)


def build_production_host_isolation_executor(
    *, config: RunnerExecutorConfig
) -> ProductionHostIsolationExecutor:
    """Build the deployable executor; every external input is a secured file or fixed limit."""

    source = os.environ
    _reject_ambient_runner_database_authority(source)
    expected_login = _runner_agent_database_login(config.runner_id, config.connection_generation)
    try:
        database_url, parsed, _path = load_production_database_url_file(source, "runner_agent")
    except ProductionServerConfigError:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner database authority is invalid"
        ) from None
    if parsed.username != expected_login:
        raise RunnerControlError(
            "runner_executor_config_invalid", "Runner database identity does not match"
        ) from None
    engine = sa.create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=_RUNNER_AGENT_DATABASE_POOL_SIZE,
        max_overflow=_RUNNER_AGENT_DATABASE_MAX_OVERFLOW,
    )
    try:

        def verify_database_fleet() -> None:
            try:
                from saas.production.runner_database_fleet import (
                    verify_runner_database_fleet_runtime_admission,
                    verify_runner_database_fleet_runtime_catalog_binding,
                )

                admission, members = verify_runner_database_fleet_runtime_admission(
                    source,
                    runner_id=config.runner_id,
                    connection_generation=config.connection_generation,
                )
                contract_sha256 = _verify_runner_agent_database_authority(
                    engine,
                    runner_id=config.runner_id,
                    connection_generation=config.connection_generation,
                    fleet_members=members,
                )
                verify_runner_database_fleet_runtime_catalog_binding(
                    admission,
                    runtime_authority_contract_sha256=contract_sha256,
                )
            except Exception:  # noqa: BLE001 - redact every admission/import failure.
                raise RunnerControlError(
                    "runner_executor_not_ready",
                    "Runner database fleet admission is unavailable",
                ) from None

        verify_database_fleet()
        sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        scheduling = SchedulingControlPlane(sessions)
        worktrees = WorktreeControlPlane(sessions, scheduler=scheduling)
        isolation = IsolationControlPlane(sessions, scheduler=scheduling)
        work_root = _private_directory(
            Path(_required(source, "OMNIGENT_SAAS_RUNNER_WORK_ROOT")),
            field="work_root",
            create=True,
        )
        mirror_bindings, repository_mirror_root = _verified_repository_mirror_bindings(
            source,
            runner_id=config.runner_id,
            connection_generation=config.connection_generation,
        )
        if work_root.is_relative_to(
            repository_mirror_root
        ) or repository_mirror_root.is_relative_to(work_root):
            raise RunnerControlError(
                "runner_executor_config_invalid",
                "Runner work and repository roots must not overlap",
            )
        worktree_adapter = RunnerWorktreeAdapter(
            managed_root=work_root / "worktrees",
            mirror_root=repository_mirror_root,
            state_root=work_root / "state",
            authority=worktrees,
            mirrors=StaticRepositoryMirrorResolver(mirror_bindings),
            recovery_artifacts=_recovery_artifact_store(
                source,
                runner_id=config.runner_id,
                connection_generation=config.connection_generation,
            ),
            runner_id=config.runner_id,
        )
        isolation_adapter = RunnerIsolationAdapter(
            staging_root=work_root / "secrets",
            authority=isolation,
            secret_provider=_FilesystemSecretProvider(
                Path(_required(source, "OMNIGENT_SAAS_RUNNER_SECRET_PROVIDER_ROOT"))
            ),
            containment=LinuxCgroupV2ContainmentVerifier(
                runner_id=config.runner_id,
                expected_cgroup_path=_expected_cgroup_path(source),
            ),
        )
        return ProductionHostIsolationExecutor(
            config=config,
            engine=engine,
            sessions=sessions,
            worktrees=worktrees,
            isolation=isolation,
            worktree_adapter=worktree_adapter,
            isolation_adapter=isolation_adapter,
            reserved_bytes=_positive_integer(
                source,
                "OMNIGENT_SAAS_RUNNER_WORKTREE_RESERVED_BYTES",
                default=5 * 1024 * 1024 * 1024,
                maximum=1024 * 1024 * 1024 * 1024,
            ),
            worktree_lease_seconds=_positive_integer(
                source,
                "OMNIGENT_SAAS_RUNNER_WORKTREE_LEASE_SECONDS",
                default=300,
                maximum=3600,
            ),
            command_timeout_seconds=_positive_integer(
                source,
                "OMNIGENT_SAAS_RUNNER_COMMAND_TIMEOUT_SECONDS",
                default=1800,
                maximum=86_400,
            ),
            database_fleet_verifier=verify_database_fleet,
        )
    except Exception:
        engine.dispose()
        raise


__all__ = [
    "ProductionHostIsolationExecutor",
    "build_production_host_isolation_executor",
]
