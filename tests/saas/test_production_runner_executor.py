from __future__ import annotations

import asyncio
import hashlib
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

import saas.production.runner_executor as runner_executor_module
from saas.control_plane import (
    ChangeSetRecord,
    ChangeSetSpec,
    ExecutionProfileRecord,
    ExecutionRevisionSet,
    IsolationControlPlane,
    PreviewRouteGrant,
    RunDispatchRecord,
    RunnerRegistrationRecord,
    TenantQueueShareRecord,
    WorktreeInstanceRecord,
    WorktreeQuotaRecord,
)
from saas.control_plane.outbox import DispatchResult
from saas.control_plane.preview_execution import (
    PreviewRunnerStartClaim,
    PreviewRunnerStopClaim,
)
from saas.control_plane.worktrees import WorktreeControlPlaneError, WorktreeLease
from saas.production.repository_mirror import RepositoryMirrorError
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from saas.production.runner_executor import (
    _RUNNER_FORBIDDEN_LIBPQ_ENV,
    ProductionHostIsolationExecutor,
    _ActiveExecution,
    _recovery_artifact_store,
    _recovery_s3_credentials,
    _reject_ambient_runner_database_authority,
    _runner_agent_database_login,
    _verified_repository_mirror_bindings,
)
from saas.production.worker import ProductionSchedulerWorker, ProductionWorkerAdapters
from saas.runner_adapter import (
    FilesystemRecoveryArtifactStore,
    PhysicalWorktree,
    PreparedRunnerIsolation,
    RunnerIsolationAdapter,
    RunnerWorktreeAdapter,
    StaticRepositoryMirrorResolver,
)
from saas.runner_adapter.preview_supervisor import PreviewProcessExit
from tests.saas.test_worktree_control_plane import (
    WorktreeFixture,
    _configure_worktree_quota,
    _create_bare_mirror,
    _create_git_fixture,
    worktree_fixture,  # noqa: F401
)

_PRODUCT_REVISION = "a" * 40
_IMAGE_DIGEST = "sha256:" + "b" * 64
_RUNNER_CAPABILITIES = (
    "egress.proxy",
    "git",
    "sandbox.linux_bwrap",
    "sandbox.no_host_socket",
    "sandbox.no_new_privileges",
    "sandbox.nonroot",
    "sandbox.readonly_root",
    "sandbox.resource_limits",
    "secret.broker",
    "shell",
    "syscall.oci-default-v1",
)


@pytest.fixture(autouse=True)
def _close_heartbeat_workers(monkeypatch: pytest.MonkeyPatch):
    """Give every test exact ownership of the executor's dedicated daemon."""

    workers: list[object] = []
    worker_type = runner_executor_module._HeartbeatCallWorker
    original_init = worker_type.__init__

    def tracked_init(worker: object) -> None:
        original_init(worker)
        workers.append(worker)

    monkeypatch.setattr(worker_type, "__init__", tracked_init)
    yield
    for worker in workers:
        assert worker.close(timeout_seconds=2.0)
    assert not any(
        thread.name == "omnigent-worktree-heartbeat" and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_runner_database_login_is_exact_and_ambient_authority_is_rejected() -> None:
    runner_id = UUID("ffffffff-ffff-4fff-bfff-ffffffffffff")
    generation = 2**63 - 1
    assert _runner_agent_database_login(runner_id, generation) == (
        "runner_ffffffffffff4fffbfffffffffffffff_g9223372036854775807"
    )
    assert len(_runner_agent_database_login(runner_id, generation).encode("ascii")) <= 63

    allowed = {"OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE": "/run/secrets/runner-agent-db"}
    _reject_ambient_runner_database_authority(allowed)
    for name in (
        "DATABASE_URL",
        "OMNIGENT_SAAS_DB_URL",
        "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE",
        "UNRELATED_DATABASE_URL",
        *_RUNNER_FORBIDDEN_LIBPQ_ENV,
    ):
        secret = f"postgresql://fleet-secret@database/{name.lower()}"
        with pytest.raises(RunnerControlError) as rejected:
            _reject_ambient_runner_database_authority({**allowed, name: secret})
        assert rejected.value.code == "runner_executor_config_invalid"
        assert secret not in str(rejected.value)
        assert rejected.value.__cause__ is None

    for invalid_generation in (0, 2**63):
        with pytest.raises(RunnerControlError, match="database identity"):
            _runner_agent_database_login(runner_id, invalid_generation)


def test_repository_bindings_use_the_full_release_pinned_mirror_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner_id = UUID("ffffffff-ffff-4fff-bfff-ffffffffffff")
    mirror_root = tmp_path / "repository" / "mirrors" / "a"
    mirror = mirror_root / "active" / "repository.git"
    mirror.mkdir(parents=True, mode=0o700)
    mirror_root.chmod(0o700)
    observed: dict[str, object] = {}

    def verify(bindings_file: str, receipt_file: str, **kwargs: object) -> object:
        observed.update(
            {
                "bindings_file": bindings_file,
                "receipt_file": receipt_file,
                **kwargs,
            }
        )
        return SimpleNamespace(bindings={"primary": mirror})

    monkeypatch.setattr(runner_executor_module, "load_and_verify_repository_bindings", verify)
    source = {
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_BINDINGS_FILE": (
            "/repository/state/repository-bindings.json"
        ),
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_RECEIPT_FILE": (
            "/repository/state/repository-mirror-receipt.json"
        ),
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_MIRROR_ROOT": str(mirror_root),
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT": "a",
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256": "1" * 64,
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256": "2" * 64,
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256": "3" * 64,
    }

    assert _verified_repository_mirror_bindings(
        source,
        runner_id=runner_id,
        connection_generation=7,
    ) == ({"primary": mirror}, mirror_root)
    assert observed == {
        "bindings_file": "/repository/state/repository-bindings.json",
        "receipt_file": "/repository/state/repository-mirror-receipt.json",
        "expected_runner_id": runner_id,
        "expected_runner_generation": 7,
        "expected_runner_slot": "a",
        "expected_binding_keys": ("primary",),
        "expected_spec_sha256": "1" * 64,
        "expected_bindings_sha256": "2" * 64,
        "expected_receipt_sha256": "3" * 64,
    }

    monkeypatch.setattr(
        runner_executor_module,
        "load_and_verify_repository_bindings",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RepositoryMirrorError("secret credential path")
        ),
    )
    with pytest.raises(RunnerControlError) as rejected:
        _verified_repository_mirror_bindings(
            source,
            runner_id=runner_id,
            connection_generation=7,
        )
    assert rejected.value.code == "runner_executor_config_invalid"
    assert "secret credential path" not in str(rejected.value)


def test_runner_recovery_credentials_are_explicit_static_and_non_ambient(
    tmp_path: Path,
) -> None:
    runner_id = uuid4()
    profile = f"runner-{runner_id}-g7"
    path = tmp_path / "recovery-credentials"
    path.write_text(
        f"[{profile}]\naws_access_key_id={'a' * 20}\naws_secret_access_key={'b' * 40}\n",
        encoding="utf-8",
    )
    path.chmod(0o400)
    source = {
        "OMNIGENT_SAAS_RUNNER_ID": str(runner_id),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": "7",
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": profile,
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_FILE": str(path),
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": (
            f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        ),
    }

    credentials = _recovery_s3_credentials(source)
    assert credentials.access_key_id == "a" * 20
    assert "b" * 40 not in repr(credentials)

    for forbidden in (
        "AWS_EC2_METADATA_DISABLED",
        "AWS_REGION",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BOTO_CONFIG",
        "BOTO_FUTURE_AMBIENT_PROVIDER",
    ):
        with pytest.raises(RunnerControlError, match="ambient AWS"):
            _recovery_s3_credentials({**source, forbidden: ""})

    for changed in (
        {"OMNIGENT_SAAS_RUNNER_ID": "runner-secret-not-a-uuid"},
        {"OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": "07"},
        {"OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": "runner-wrong-g7"},
        {"OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": ("sha256:" + "0" * 64)},
    ):
        with pytest.raises(RunnerControlError) as rejected:
            _recovery_s3_credentials({**source, **changed})
        assert "a" * 20 not in str(rejected.value)
        assert "b" * 40 not in str(rejected.value)
        assert str(path) not in str(rejected.value)
        assert rejected.value.__cause__ is None

    path.chmod(0o600)
    path.write_text(
        f"[{profile}]\n"
        f"aws_access_key_id={'a' * 20}\n"
        f"aws_secret_access_key={'b' * 40}\n"
        f"aws_session_token={'c' * 32}\n",
        encoding="utf-8",
    )
    path.chmod(0o400)
    source["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION"] = (
        f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    )
    with pytest.raises(RunnerControlError, match="credentials file"):
        _recovery_s3_credentials(source)


def test_runner_recovery_uri_requires_exact_runner_generation_suffix() -> None:
    runner_id = uuid4()
    source = {
        "OMNIGENT_SAAS_RUNNER_ID": str(runner_id),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": "3",
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI": (
            f"s3://private-bucket/runtime/runner/{runner_id}/generation/2"
        ),
    }
    with pytest.raises(RunnerControlError) as rejected:
        _recovery_artifact_store(source)
    assert rejected.value.code == "runner_executor_config_invalid"
    assert str(runner_id) not in str(rejected.value)
    assert source["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI"] not in str(rejected.value)

    with pytest.raises(RunnerControlError, match="recovery identity"):
        _recovery_artifact_store(
            source,
            runner_id=uuid4(),
            connection_generation=3,
        )


def test_runner_recovery_provider_errors_are_fully_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import boto3

    runner_id = uuid4()
    profile = f"runner-{runner_id}-g11"
    path = tmp_path / "recovery-provider-credentials"
    path.write_text(
        f"[{profile}]\naws_access_key_id={'a' * 20}\naws_secret_access_key={'b' * 40}\n",
        encoding="utf-8",
    )
    path.chmod(0o400)
    source = {
        "OMNIGENT_SAAS_RUNNER_ID": str(runner_id),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": "11",
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI": (
            f"s3://private-bucket/runtime/runner/{runner_id}/generation/11"
        ),
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL": ("https://objects.example.test"),
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_REGION": "cn-east-1",
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE": profile,
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_FILE": str(path),
        "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION": (
            f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        ),
    }
    leaked = f"provider leaked {'a' * 20} {'b' * 40} {path}"

    def unavailable(*_args, **_kwargs):
        raise RuntimeError(leaked)

    monkeypatch.setattr(boto3, "client", unavailable)
    with pytest.raises(RunnerControlError) as rejected:
        _recovery_artifact_store(source)
    assert rejected.value.code == "runner_executor_config_invalid"
    assert leaked not in str(rejected.value)
    assert "a" * 20 not in str(rejected.value)
    assert "b" * 40 not in str(rejected.value)
    assert str(path) not in str(rejected.value)
    assert rejected.value.__cause__ is None


@dataclass(frozen=True, slots=True)
class _Config:
    product_revision: str
    image_digest: str
    runner_id: UUID
    connection_generation: int = 1


class _NoSecrets:
    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        raise AssertionError(f"unexpected secret reference {provider}/{vault_ref}/{version_ref}")


class _Containment:
    def require_enforced(self, *, runner_id: UUID, contract) -> None:
        assert runner_id.int
        assert contract.backend == "linux_bwrap"
        assert contract.network_mode == "proxy_only"
        assert contract.root_read_only
        assert contract.no_new_privileges
        assert not contract.host_socket_access


@dataclass(slots=True)
class _PreparedExecutor:
    fixture: WorktreeFixture
    executor: ProductionHostIsolationExecutor
    lease: RunnerControlClientLease
    change_set_id: UUID


class _CloseTrackingEnvironment:
    def __init__(self) -> None:
        self.closed = 0
        self.shell_calls = 0

    async def shell(self, *_args, **_kwargs) -> dict[str, object]:
        self.shell_calls += 1
        return {"exit_code": 0}

    def close(self) -> None:
        self.closed += 1


class _DelayedPrepared:
    def __init__(
        self,
        started: asyncio.Event,
        proceed: asyncio.Event,
        environment: _CloseTrackingEnvironment,
    ) -> None:
        self._started = started
        self._proceed = proceed
        self._environment = environment
        self.closed = 0

    async def start(self) -> _CloseTrackingEnvironment:
        self._started.set()
        await self._proceed.wait()
        return self._environment

    def close(self) -> None:
        self.closed += 1


class _ImmediatePrepared:
    def __init__(self, environment: _CloseTrackingEnvironment) -> None:
        self._environment = environment
        self.closed = 0

    async def start(self) -> _CloseTrackingEnvironment:
        return self._environment

    def close(self) -> None:
        self.closed += 1


class _HeartbeatBoundEnvironment(_CloseTrackingEnvironment):
    def __init__(self, completed: asyncio.Event) -> None:
        super().__init__()
        self._completed = completed

    async def shell(self, *_args, **_kwargs) -> dict[str, object]:
        self.shell_calls += 1
        await self._completed.wait()
        return {"exit_code": 0}


class _HeartbeatRaceEnvironment(_CloseTrackingEnvironment):
    def __init__(self, committed: asyncio.Event, release_response: threading.Event) -> None:
        super().__init__()
        self._committed = committed
        self._release_response = release_response

    async def shell(self, *_args, **_kwargs) -> dict[str, object]:
        self.shell_calls += 1
        await self._committed.wait()
        self._release_response.set()
        return {"exit_code": 0}


class _PreviewCommands:
    def __init__(self, route: PreviewRouteGrant, stop: PreviewRunnerStopClaim) -> None:
        self.route = route
        self.stop = stop
        self.calls: list[str] = []

    def prepare_route(self, *_args, **_kwargs) -> PreviewRouteGrant:
        self.calls.append("prepare-route")
        return self.route

    def mark_ready(self, *_args, **_kwargs) -> PreviewRouteGrant:
        self.calls.append("mark-ready")
        return self.route

    def claim_stop(self, **_kwargs) -> PreviewRunnerStopClaim:
        self.calls.append("claim-stop")
        return self.stop

    def complete_stop(self, *_args, **_kwargs) -> None:
        self.calls.append("complete-stop")

    def abort_runtime(self, *_args, **_kwargs) -> None:
        self.calls.append("abort")


class _PreviewSupervisor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def start(self, route: PreviewRouteGrant, spec) -> object:
        assert route.preview_host == "preview.example.test"
        assert spec.argv[-1] == "saas.runner_adapter.static_web_preview"
        self.calls.append("start")
        return object()

    async def stop(self, preview_id: UUID) -> PreviewProcessExit:
        self.calls.append("stop")
        return PreviewProcessExit(
            preview_id=preview_id,
            pid=123,
            reason="stopped",
            returncode=0,
            stopped_at=datetime.now(timezone.utc),
        )

    async def last_exit(self, _preview_id: UUID) -> None:
        return None

    async def snapshot(self, _preview_id: UUID) -> object:
        return object()


def _build_prepared_executor(
    fixture: WorktreeFixture,
    tmp_path: Path,
    *,
    suffix: str,
) -> _PreparedExecutor:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    git_root = tmp_path / f"git-{suffix}"
    git_root.mkdir(mode=0o700)
    source, source_head = _create_git_fixture(git_root)
    mirror_root = tmp_path / f"mirrors-{suffix}"
    mirror_root.mkdir(mode=0o700)
    mirror = _create_bare_mirror(source, mirror_root, "repository.git")
    binding_key = f"runner_{suffix}_{uuid4().hex}"
    repository_id = fixture.worktrees.register_repository(
        fixture.request,
        project_id=fixture.project_id,
        provider="github-app",
        source_binding_key=binding_key,
        display_name=f"Runner executor {suffix}",
        default_branch="main",
    )
    group = fixture.worktrees.create_change_set_group(
        fixture.request,
        project_id=fixture.project_id,
        title=f"Runner executor {suffix}",
        specs=(
            ChangeSetSpec(
                repository_id=repository_id,
                base_revision=source_head,
                branch_ref=f"refs/heads/codex/{suffix}",
            ),
        ),
    )
    change_set_id = group.change_set_ids[0]
    _configure_worktree_quota(fixture)

    isolation = IsolationControlPlane(fixture.factory, scheduler=fixture.scheduling)
    policy_id = isolation.create_egress_policy(
        fixture.request,
        project_id=fixture.project_id,
        name=f"runner-egress-{suffix}",
        rules=["GET api.github.com/**"],
    )
    profile_id = isolation.create_execution_profile(
        fixture.request,
        project_id=fixture.project_id,
        egress_policy_id=policy_id,
        name=f"runner-profile-{suffix}",
        sandbox_backend="linux_bwrap",
        syscall_profile_ref="oci-default-v1",
        cpu_millis=1000,
        memory_bytes=512 * 1024 * 1024,
        pids_limit=128,
        allowed_tools=["git", "shell"],
    )
    with fixture.factory() as database:
        profile = database.get(ExecutionProfileRecord, profile_id)
        assert profile is not None
        profile_hash = profile.config_hash

    fixture.execution.configure_quota(
        fixture.request,
        project_id=fixture.project_id,
        resource="run_units",
        limit_units=4,
    )
    task_id = fixture.execution.create_task(
        fixture.request,
        project_id=fixture.project_id,
        title=f"Runner executor {suffix}",
    )
    admission = fixture.execution.admit_run(
        fixture.request,
        project_id=fixture.project_id,
        task_id=task_id,
        session_id=None,
        input_payload={
            "change_set_id": str(change_set_id),
            "execution": {
                "kind": "omnigent.agent.v1",
                "agent_path": "agents/review.yaml",
                "prompt": "Review the managed change set",
            },
        },
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=f"runner-executor-{suffix}",
        revisions=ExecutionRevisionSet(
            product_revision=_PRODUCT_REVISION,
            upstream_revision="upstream",
            schema_revision="p4b000000001",
            adapter_contract_version="0.2.0",
        ),
    )
    pool_id = fixture.scheduling.create_pool(
        placement_id=fixture.placement_id,
        name=f"runner-executor-{suffix}",
        queue_class="interactive",
        capacity_slots=1,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    fixture.scheduling.configure_tenant_share(
        tenant_id=fixture.request.tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=1,
        burst_limit=1,
    )
    fixture.scheduling.prepare_dispatch(
        run_id=admission.run_id,
        pool_id=pool_id,
        required_capabilities=list(_RUNNER_CAPABILITIES),
        execution_profile_id=profile_id,
        execution_profile_hash=profile_hash,
        eligible_at=now,
        maximum_wait=timedelta(minutes=10),
    )
    connection = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"runner-executor-{suffix}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=list(_RUNNER_CAPABILITIES),
        max_concurrency=1,
        now=now,
    )
    claimed = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(minutes=5),
        heartbeat_timeout=timedelta(seconds=30),
        capability_actions=["run.execute", "sandbox.launch", "worktree.write"],
        capability_resource_scope={"control_plane": "runner_control"},
        expected_product_revision=_PRODUCT_REVISION,
        product_image_digest=_IMAGE_DIGEST,
        now=now + timedelta(seconds=1),
    )
    assert claimed is not None and claimed.execution_envelope is not None
    for offset, status in enumerate(("starting", "running"), start=2):
        fixture.execution.transition_run(
            run_id=claimed.run_id,
            lease_token=claimed.lease_token,
            fence_token=claimed.fence_token,
            target_status=status,
            trace_id=f"runner:{suffix}:{status}",
            now=now + timedelta(seconds=offset),
        )

    managed_root = tmp_path / f"managed-{suffix}"
    state_root = tmp_path / f"state-{suffix}"
    recovery_root = tmp_path / f"recovery-{suffix}"
    staging_root = tmp_path / f"staging-{suffix}"
    worktree_adapter = RunnerWorktreeAdapter(
        managed_root=managed_root,
        mirror_root=mirror_root,
        state_root=state_root,
        authority=fixture.worktrees,
        mirrors=StaticRepositoryMirrorResolver({binding_key: mirror}),
        recovery_artifacts=FilesystemRecoveryArtifactStore(recovery_root),
    )
    isolation_adapter = RunnerIsolationAdapter(
        staging_root=staging_root,
        authority=isolation,
        secret_provider=_NoSecrets(),
        containment=_Containment(),
    )
    engine = cast(Engine, fixture.factory.kw["bind"])
    executor = ProductionHostIsolationExecutor(
        config=_Config(_PRODUCT_REVISION, _IMAGE_DIGEST, connection.runner_id),
        engine=engine,
        sessions=fixture.factory,
        worktrees=fixture.worktrees,
        isolation=isolation,
        worktree_adapter=worktree_adapter,
        isolation_adapter=isolation_adapter,
        reserved_bytes=1_000_000,
        worktree_lease_seconds=300,
        command_timeout_seconds=60,
    )
    lease = RunnerControlClientLease(
        run_id=claimed.run_id,
        lease_token=claimed.lease_token,
        fence_token=claimed.fence_token,
        dispatch_generation=claimed.dispatch_generation,
        failure_domain=claimed.failure_domain,
        expires_at=claimed.expires_at,
        capability_id=claimed.capability_id,
        capability_token=claimed.capability_token,
        execution_envelope=claimed.execution_envelope,
    )
    return _PreparedExecutor(fixture, executor, lease, change_set_id)


def _terminalize(context: _PreparedExecutor, status: str) -> None:
    context.fixture.execution.transition_run(
        run_id=context.lease.run_id,
        lease_token=context.lease.lease_token,
        fence_token=context.lease.fence_token,
        target_status=status,
        trace_id=f"runner:terminal:{status}",
    )


@pytest.mark.asyncio
async def test_preview_execution_uses_readonly_static_supervisor_and_durable_stop(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="preview-closed")
    original_envelope = context.lease.execution_envelope
    assert original_envelope is not None
    preview_id = uuid4()
    operation_at = datetime.now(timezone.utc)
    preview_root = tmp_path / "preview-readonly"
    publish_root = preview_root / "dist"
    publish_root.mkdir(parents=True, mode=0o700)
    claim = PreviewRunnerStartClaim(
        command_id=uuid4(),
        claim_token="claim-token-not-browser-visible",
        tenant_id=original_envelope.tenant_id,
        space_id=original_envelope.space_id,
        project_id=original_envelope.project_id,
        preview_execution_id=preview_id,
        child_run_id=original_envelope.run_id,
        change_set_id=original_envelope.change_set_id,
        checkpoint_revision="c" * 40,
        expires_at=operation_at + timedelta(minutes=5),
    )
    route = PreviewRouteGrant(
        preview_id=preview_id,
        tenant_id=original_envelope.tenant_id,
        space_id=original_envelope.space_id,
        project_id=original_envelope.project_id,
        runner_id=original_envelope.runner_id,
        runner_connection_generation=1,
        run_id=original_envelope.run_id,
        run_fence_token=original_envelope.fence_token,
        worktree_id=uuid4(),
        worktree_lease_generation=3,
        opaque_preview_key="pvr_" + "a" * 48,
        preview_token_hash="0" * 64,
        upstream_request_headers={},
        response_headers={"Content-Security-Policy": "sandbox"},
        expires_at=claim.expires_at,
        preview_host="preview.example.test",
    )
    worktree_lease = WorktreeLease(
        worktree_id=route.worktree_id,
        change_set_id=claim.change_set_id,
        run_id=claim.child_run_id,
        runner_id=route.runner_id,
        opaque_runtime_key="wti_" + "b" * 48,
        access_mode="readonly",
        lease_generation=route.worktree_lease_generation,
        run_fence_token=route.run_fence_token,
        lease_token="readonly-lease-token",
        expires_at=claim.expires_at,
    )
    active = _ActiveExecution(
        worktree_lease,
        execution_kind="omnigent.preview.v1",
        preview_claim=claim,
        physical_worktree=PhysicalWorktree(
            worktree_id=route.worktree_id,
            worktree_path=preview_root,
            head_revision=claim.checkpoint_revision,
            actual_bytes=0,
            readonly=True,
        ),
    )
    commands = _PreviewCommands(
        route,
        PreviewRunnerStopClaim(
            uuid4(),
            "stop-token-not-browser-visible",
            claim.tenant_id,
            claim.space_id,
            claim.project_id,
            preview_id,
        ),
    )
    supervisor = _PreviewSupervisor()
    cast(Any, context.executor)._preview_commands = commands
    cast(Any, context.executor)._preview_supervisor = supervisor

    async def renewed(_active: _ActiveExecution, *, safety_seconds: float) -> None:
        assert safety_seconds > 0

    monkeypatch.setattr(context.executor, "_renew_worktree", renewed)
    lease = replace(
        context.lease,
        execution_envelope=replace(
            original_envelope,
            execution_kind="omnigent.preview.v1",
            preview_execution_id=preview_id,
            checkpoint_revision=claim.checkpoint_revision,
        ),
    )

    async def pending_heartbeat() -> None:
        await asyncio.Event().wait()

    heartbeat = asyncio.create_task(pending_heartbeat())
    try:
        result = await context.executor._execute_preview(
            active,
            lease,
            cancellation=asyncio.Event(),
            heartbeat=heartbeat,
        )
    finally:
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)

    assert result == "succeeded"
    assert supervisor.calls == ["start", "stop"]
    assert commands.calls == [
        "prepare-route",
        "mark-ready",
        "claim-stop",
        "complete-stop",
    ]
    assert active.worktree_lease.access_mode == "readonly"
    assert not active.checkpointed


@pytest.mark.asyncio
async def test_concrete_executor_checkpoints_dirty_writer_before_success_and_release(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="dirty-success")
    active, command = context.executor._prepare(context.lease)
    assert active.physical_worktree is not None
    assert active.prepared is not None
    assert context.lease.execution_envelope is not None
    assert active.prepared.launch_grant.run_id == context.lease.run_id
    assert command == context.lease.execution_envelope.launch_argv
    (active.physical_worktree.worktree_path / "runner-output.txt").write_text(
        "durable output\n", encoding="utf-8"
    )

    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    assert result == "succeeded"
    with context.fixture.factory() as database:
        change_set = database.get(ChangeSetRecord, context.change_set_id)
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        assert change_set is not None and change_set.status == "checkpointed"
        assert change_set.recovery_artifact_ref is not None
        assert worktree is not None and worktree.status == "ready"
        assert worktree.recovery_artifact_ref == change_set.recovery_artifact_ref

    _terminalize(context, "succeeded")
    await context.executor.finalize(context.lease, result=result)
    with context.fixture.factory() as database:
        change_set = database.get(ChangeSetRecord, context.change_set_id)
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert change_set is not None and change_set.status == "committed"
        assert worktree is not None and worktree.status == "released"
        assert quota is not None and quota.active_instances == quota.active_writers == 0


@pytest.mark.asyncio
async def test_checkpoint_failure_downgrades_success_and_leaves_durable_recovery_fence(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="checkpoint-fail")
    active, _command = context.executor._prepare(context.lease)
    assert active.physical_worktree is not None
    (active.physical_worktree.worktree_path / "uncheckpointed.txt").write_text(
        "must not be called success\n", encoding="utf-8"
    )

    def fail_after_dirty_fence(*_args, **_kwargs):
        context.fixture.worktrees.heartbeat(
            worktree_id=active.worktree_lease.worktree_id,
            runner_id=active.worktree_lease.runner_id,
            lease_generation=active.worktree_lease.lease_generation,
            run_fence_token=active.worktree_lease.run_fence_token,
            lease_token=active.worktree_lease.lease_token,
            actual_bytes=active.physical_worktree.actual_bytes + 128,
            dirty=True,
        )
        raise RuntimeError("artifact store unavailable")

    monkeypatch.setattr(context.executor._worktree_adapter, "checkpoint", fail_after_dirty_fence)
    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    assert result == "orphaned"
    _terminalize(context, result)
    with pytest.raises(WorktreeControlPlaneError) as blocked_release:
        await context.executor.finalize(context.lease, result=result)
    assert blocked_release.value.code == "worktree_checkpoint_required"
    with context.fixture.factory() as database:
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert worktree is not None and worktree.status == "ready" and worktree.dirty
        assert worktree.recovery_artifact_ref is None
        assert quota is not None and quota.active_instances == quota.active_writers == 1

    recovered = context.fixture.worktrees.expire_stale_leases(
        now=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    assert len(recovered) == 1 and recovered[0].status == "quarantined"


@pytest.mark.asyncio
async def test_isolation_prepare_failure_is_tracked_checkpointed_and_released(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="prepare-fail")

    def fail_prepare(**_values):
        raise RuntimeError("sandbox preparation unavailable")

    monkeypatch.setattr(context.executor._isolation_adapter, "prepare", fail_prepare)
    with pytest.raises(RuntimeError, match="sandbox preparation unavailable"):
        context.executor._prepare(context.lease)
    active = context.executor._active[context.lease.run_id]
    assert active.physical_worktree is not None and active.prepared is None

    result = await context.executor.prepare_finalization(context.lease, result="failed")
    assert result == "failed" and active.checkpointed
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)
    with context.fixture.factory() as database:
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        change_set = database.get(ChangeSetRecord, context.change_set_id)
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert worktree is not None and worktree.status == "released"
        assert change_set is not None and change_set.status == "checkpointed"
        assert quota is not None and quota.active_instances == quota.active_writers == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_stage",
    ("materialize", "materialization_grant", "issue_launch_grant"),
)
async def test_each_preparation_stage_failure_retains_exact_lease_for_finalization(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    context = _build_prepared_executor(
        worktree_fixture,
        tmp_path,
        suffix=f"prepare-{failure_stage}",
    )

    def fail_stage(*_args, **_values):
        raise RuntimeError(f"{failure_stage} unavailable")

    if failure_stage == "materialize":
        monkeypatch.setattr(context.executor._worktree_adapter, "materialize", fail_stage)
    elif failure_stage == "materialization_grant":
        monkeypatch.setattr(context.executor._worktrees, "materialization_grant", fail_stage)
    else:
        monkeypatch.setattr(context.executor._isolation, "issue_launch_grant", fail_stage)

    with pytest.raises(RuntimeError, match=failure_stage):
        context.executor._prepare(context.lease)
    active = context.executor._active[context.lease.run_id]
    assert active.worktree_lease.run_id == context.lease.run_id

    result = await context.executor.prepare_finalization(context.lease, result="failed")
    assert result == "failed"
    assert active.checkpointed == (failure_stage == "issue_launch_grant")
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)
    with context.fixture.factory() as database:
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert worktree is not None and worktree.status == "released"
        assert quota is not None and quota.active_instances == quota.active_writers == 0


@pytest.mark.asyncio
async def test_allocation_failure_creates_no_untracked_active_worktree(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="allocate-fail")

    def fail_allocate(*_args, **_values):
        raise RuntimeError("allocation unavailable")

    monkeypatch.setattr(context.executor._worktrees, "allocate_worktree", fail_allocate)
    with pytest.raises(RuntimeError, match="allocation unavailable"):
        context.executor._prepare(context.lease)
    assert context.lease.run_id not in context.executor._active
    assert await context.executor.prepare_finalization(context.lease, result="failed") == "failed"
    await context.executor.finalize(context.lease, result="failed")
    with context.fixture.factory() as database:
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert quota is not None and quota.active_instances == quota.active_writers == 0


@pytest.mark.asyncio
async def test_cancel_during_helper_start_closes_the_late_environment(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="cancel-start")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active

    started = asyncio.Event()
    proceed = asyncio.Event()
    environment = _CloseTrackingEnvironment()
    delayed = _DelayedPrepared(started, proceed, environment)
    active.prepared = cast(PreparedRunnerIsolation, delayed)

    def delayed_prepare(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", delayed_prepare)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    cancellation = asyncio.Event()
    execution = asyncio.create_task(
        context.executor.execute(context.lease, cancellation=cancellation)
    )
    await started.wait()
    cancellation.set()
    await context.executor.cancel(context.lease)
    proceed.set()

    assert await execution == "cancelled"
    assert delayed.closed >= 1
    assert environment.closed == 1
    assert environment.shell_calls == 0

    assert (
        await context.executor.prepare_finalization(context.lease, result="cancelled")
        == "cancelled"
    )
    context.fixture.execution.transition_run(
        run_id=context.lease.run_id,
        lease_token=context.lease.lease_token,
        fence_token=context.lease.fence_token,
        target_status="cancelling",
        trace_id="runner:cancel-during-start",
    )
    _terminalize(context, "cancelled")
    await context.executor.finalize(context.lease, result="cancelled")


@pytest.mark.asyncio
async def test_worktree_heartbeat_covers_materialization_before_shell(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-prepare")
    active, command = context.executor._allocate_execution(context.lease)
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active
    original_finish = context.executor._finish_preparation
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    two_heartbeats = threading.Event()
    heartbeat_count = 0
    environment = _CloseTrackingEnvironment()

    def counted_heartbeat(*args, **kwargs):
        nonlocal heartbeat_count
        mutation = original_heartbeat(*args, **kwargs)
        heartbeat_count += 1
        if heartbeat_count == 2:
            two_heartbeats.set()
        return mutation

    def allocated(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    def delayed_finish(_active: object, _lease: RunnerControlClientLease) -> None:
        assert two_heartbeats.wait(timeout=2)
        original_finish(active, context.lease)
        assert active.prepared is not None
        active.prepared.close()
        active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))

    monkeypatch.setattr(context.executor, "_allocate_execution", allocated)
    monkeypatch.setattr(context.executor, "_finish_preparation", delayed_finish)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", counted_heartbeat)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 1

    assert (
        await context.executor.execute(context.lease, cancellation=asyncio.Event()) == "succeeded"
    )
    assert heartbeat_count >= 3  # two during preparation plus pre-shell CAS
    assert environment.shell_calls == 1

    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)


@pytest.mark.asyncio
async def test_pre_shell_authoritative_cas_rejects_stale_runner_fence(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="pre-shell-cas")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active
    environment = _CloseTrackingEnvironment()

    class _StaleOnStart:
        async def start(self) -> _CloseTrackingEnvironment:
            assert context.lease.execution_envelope is not None
            with context.fixture.factory.begin() as database:
                runner = database.get(
                    RunnerRegistrationRecord,
                    context.lease.execution_envelope.runner_id,
                )
                assert runner is not None
                runner.connection_generation += 1
            return environment

        def close(self) -> None:
            return None

    active.prepared = cast(PreparedRunnerIsolation, _StaleOnStart())

    def allocated(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", allocated)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)

    result = await context.executor.execute(context.lease, cancellation=asyncio.Event())
    assert result == "orphaned"
    assert active.lease_lost
    assert environment.shell_calls == 0
    assert (
        await context.executor.prepare_finalization(context.lease, result="succeeded")
        == "orphaned"
    )
    assert not active.checkpointed


@pytest.mark.asyncio
async def test_active_command_keeps_heartbeat_through_terminal_preparation(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-live")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active

    completed = asyncio.Event()
    environment = _HeartbeatBoundEnvironment(completed)
    active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    heartbeat_count = 0
    loop = asyncio.get_running_loop()

    def counted_heartbeat(*args, **kwargs):
        nonlocal heartbeat_count
        mutation = original_heartbeat(*args, **kwargs)
        heartbeat_count += 1
        if heartbeat_count == 2:
            loop.call_soon_threadsafe(completed.set)
        return mutation

    def prepared(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", prepared)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", counted_heartbeat)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 1

    original_expiry = active.worktree_lease.expires_at
    assert (
        await context.executor.execute(context.lease, cancellation=asyncio.Event()) == "succeeded"
    )
    assert heartbeat_count >= 2
    assert active.worktree_lease.expires_at >= original_expiry
    assert not active.lease_lost
    post_execute_count = heartbeat_count
    await asyncio.sleep(0.04)
    assert heartbeat_count > post_execute_count

    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    await context.executor.prepare_terminal_transition(context.lease)
    stopped_count = heartbeat_count
    await asyncio.sleep(0.04)
    assert heartbeat_count == stopped_count
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)


@pytest.mark.asyncio
async def test_checkpoint_longer_than_original_ttl_keeps_exact_fence_live(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-final")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active
    active.prepared = cast(
        PreparedRunnerIsolation, _ImmediatePrepared(_CloseTrackingEnvironment())
    )

    def allocated(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", allocated)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 1
    assert (
        await context.executor.execute(context.lease, cancellation=asyncio.Event()) == "succeeded"
    )

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=0.12)
    async with active.heartbeat_lock:
        with context.fixture.factory.begin() as database:
            record = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
            assert record is not None
            record.lease_expires_at = expires_at
        with context.executor._lock:
            active.worktree_lease = replace(active.worktree_lease, expires_at=expires_at)

    artifact_store = cast(Any, context.executor._worktree_adapter)._recovery_artifacts
    original_put = artifact_store.put
    upload_started = threading.Event()
    release_upload = threading.Event()

    def delayed_put(artifact):
        upload_started.set()
        assert release_upload.wait(timeout=2)
        return original_put(artifact)

    monkeypatch.setattr(artifact_store, "put", delayed_put)
    preparation = asyncio.create_task(
        context.executor.prepare_finalization(context.lease, result="succeeded")
    )
    assert await asyncio.to_thread(upload_started.wait, 1)
    await asyncio.sleep(0.2)
    assert datetime.now(timezone.utc) > expires_at
    release_upload.set()
    assert await asyncio.wait_for(preparation, timeout=2) == "succeeded"
    assert active.worktree_lease.expires_at > expires_at
    assert not active.lease_lost

    await context.executor.prepare_terminal_transition(context.lease)
    _terminalize(context, "succeeded")
    await context.executor.finalize(context.lease, result="succeeded")


@pytest.mark.asyncio
async def test_cancel_keeps_worktree_heartbeat_until_terminal_preparation(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-cancel")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active

    never_completed = asyncio.Event()
    heartbeat_seen = asyncio.Event()
    environment = _HeartbeatBoundEnvironment(never_completed)
    active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    heartbeat_count = 0
    heartbeat_condition = threading.Condition()
    loop = asyncio.get_running_loop()

    def counted_heartbeat(*args, **kwargs):
        nonlocal heartbeat_count
        mutation = original_heartbeat(*args, **kwargs)
        with heartbeat_condition:
            heartbeat_count += 1
            heartbeat_condition.notify_all()
        loop.call_soon_threadsafe(heartbeat_seen.set)
        return mutation

    def wait_for_heartbeat_after(previous_count: int) -> bool:
        with heartbeat_condition:
            return heartbeat_condition.wait_for(
                lambda: heartbeat_count > previous_count,
                timeout=1,
            )

    def prepared(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", prepared)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", counted_heartbeat)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 1

    cancellation = asyncio.Event()
    execution = asyncio.create_task(
        context.executor.execute(context.lease, cancellation=cancellation)
    )
    await heartbeat_seen.wait()
    cancellation.set()
    assert await execution == "cancelled"
    with heartbeat_condition:
        post_execute_count = heartbeat_count
    assert await asyncio.to_thread(wait_for_heartbeat_after, post_execute_count)

    result = await context.executor.prepare_finalization(context.lease, result="cancelled")
    await context.executor.prepare_terminal_transition(context.lease)
    with heartbeat_condition:
        stopped_count = heartbeat_count
    await asyncio.sleep(0.04)
    with heartbeat_condition:
        assert heartbeat_count == stopped_count
    context.fixture.execution.transition_run(
        run_id=context.lease.run_id,
        lease_token=context.lease.lease_token,
        fence_token=context.lease.fence_token,
        target_status="cancelling",
        trace_id="runner:heartbeat-cancel",
    )
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)


@pytest.mark.asyncio
async def test_unknown_worktree_heartbeat_fails_closed_without_checkpoint(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-unknown")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active

    heartbeat_committed = asyncio.Event()
    release_response = threading.Event()
    environment = _HeartbeatRaceEnvironment(heartbeat_committed, release_response)
    active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    loop = asyncio.get_running_loop()
    heartbeat_count = 0

    def unknown_after_commit(*args, **kwargs):
        nonlocal heartbeat_count
        heartbeat_count += 1
        mutation = original_heartbeat(*args, **kwargs)
        if heartbeat_count == 1:
            return mutation
        loop.call_soon_threadsafe(heartbeat_committed.set)
        assert release_response.wait(timeout=1)
        raise TimeoutError("heartbeat response lost after commit")

    def prepared(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", prepared)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", unknown_after_commit)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 1

    result = await context.executor.execute(context.lease, cancellation=asyncio.Event())
    # Shell completion and the heartbeat response race deliberately.  The
    # executor may return the shell result first, but finalization must join the
    # in-flight authority call before checkpointing.
    assert result == "succeeded"
    assert environment.closed == 1

    def checkpoint_must_not_run(*_args, **_kwargs):
        raise AssertionError("checkpoint must not run after an unknown heartbeat")

    monkeypatch.setattr(context.executor._worktree_adapter, "checkpoint", checkpoint_must_not_run)
    assert (
        await context.executor.prepare_finalization(context.lease, result="succeeded")
        == "orphaned"
    )
    assert active.lease_lost
    assert not active.checkpointed


@pytest.mark.asyncio
async def test_never_returning_heartbeat_isolated_from_default_pool_and_poisoned(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-never")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active
    environment = _HeartbeatBoundEnvironment(asyncio.Event())
    active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    blocked_forever = threading.Event()
    heartbeat_count = 0

    def never_returns(*args, **kwargs):
        nonlocal heartbeat_count
        heartbeat_count += 1
        if heartbeat_count == 1:
            return original_heartbeat(*args, **kwargs)
        blocked_forever.wait()
        raise AssertionError("unreachable")

    def allocated(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", allocated)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", never_returns)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 0.05

    result = await asyncio.wait_for(
        context.executor.execute(context.lease, cancellation=asyncio.Event()),
        timeout=1,
    )
    assert result == "orphaned"
    assert active.lease_lost and context.executor._heartbeat_worker_poisoned
    assert await asyncio.wait_for(asyncio.to_thread(lambda: "default-pool-free"), timeout=1) == (
        "default-pool-free"
    )
    with pytest.raises(RunnerControlError) as poisoned:
        await context.executor.execute(context.lease, cancellation=asyncio.Event())
    assert poisoned.value.code == "runner_worktree_heartbeat_worker_poisoned"
    assert (
        await context.executor.prepare_finalization(context.lease, result="succeeded")
        == "orphaned"
    )
    blocked_forever.set()


@pytest.mark.asyncio
async def test_late_heartbeat_response_after_timeout_cannot_restore_execution(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="heartbeat-late")
    active, command = context.executor._prepare(context.lease)
    assert active.prepared is not None
    active.prepared.close()
    with context.executor._lock:
        assert context.executor._active.pop(context.lease.run_id) is active
    environment = _HeartbeatBoundEnvironment(asyncio.Event())
    active.prepared = cast(PreparedRunnerIsolation, _ImmediatePrepared(environment))
    original_heartbeat = context.executor._worktree_adapter.heartbeat
    heartbeat_started = asyncio.Event()
    release_response = threading.Event()
    heartbeat_count = 0
    loop = asyncio.get_running_loop()

    def returns_too_late(*args, **kwargs):
        nonlocal heartbeat_count
        heartbeat_count += 1
        mutation = original_heartbeat(*args, **kwargs)
        if heartbeat_count == 1:
            return mutation
        loop.call_soon_threadsafe(heartbeat_started.set)
        assert release_response.wait(timeout=2)
        return mutation

    def allocated(_lease: RunnerControlClientLease):
        with context.executor._lock:
            context.executor._active[context.lease.run_id] = active
        return active, command

    monkeypatch.setattr(context.executor, "_allocate_execution", allocated)
    monkeypatch.setattr(context.executor, "_finish_preparation", lambda *_args: None)
    monkeypatch.setattr(context.executor._worktree_adapter, "heartbeat", returns_too_late)
    context.executor._worktree_heartbeat_interval_seconds = 0.01
    context.executor._worktree_heartbeat_timeout_seconds = 0.05

    execution = asyncio.create_task(
        context.executor.execute(context.lease, cancellation=asyncio.Event())
    )
    await heartbeat_started.wait()
    expiry_before_late_response = active.worktree_lease.expires_at
    assert await asyncio.wait_for(execution, timeout=1) == "orphaned"
    release_response.set()
    await asyncio.sleep(0.05)
    assert active.lease_lost and context.executor._heartbeat_worker_poisoned
    assert active.worktree_lease.expires_at == expiry_before_late_response
    assert environment.closed == 1
    assert (
        await context.executor.prepare_finalization(context.lease, result="succeeded")
        == "orphaned"
    )


@pytest.mark.asyncio
async def test_terminal_finalize_failure_retains_exact_state_for_retry(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="finalize-fail")
    active, _command = context.executor._prepare(context.lease)
    assert context.lease.execution_envelope is not None
    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    assert result == "succeeded" and active.checkpointed
    _terminalize(context, result)

    original_release = context.executor._worktrees.release

    def fail_release(**_values):
        raise RuntimeError("worktree release unavailable")

    monkeypatch.setattr(context.executor._worktrees, "release", fail_release)
    with pytest.raises(RuntimeError, match="worktree release unavailable"):
        await context.executor.finalize(context.lease, result=result)
    assert context.lease.run_id in context.executor._active

    monkeypatch.setattr(context.executor._worktrees, "release", original_release)
    await context.executor.finalize(context.lease, result=result)
    assert context.lease.run_id not in context.executor._active

    assert context.fixture.scheduling.recover_expired_dispatches() == (context.lease.run_id,)
    with context.fixture.factory() as database:
        dispatch = database.get(RunDispatchRecord, context.lease.run_id)
        runner = database.get(
            RunnerRegistrationRecord,
            context.lease.execution_envelope.runner_id,
        )
        share = database.scalar(
            sa.select(TenantQueueShareRecord).where(
                TenantQueueShareRecord.tenant_id == context.lease.execution_envelope.tenant_id
            )
        )
        worktree = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        assert dispatch is not None and dispatch.status == "released"
        assert runner is not None and runner.active_leases == 0
        assert share is not None and share.active_leases == 0
        assert worktree is not None and worktree.status == "released"


@pytest.mark.asyncio
async def test_runner_reconciles_only_its_exact_gc_eligible_physical_state(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="physical-gc")
    active, _command = context.executor._prepare(context.lease)
    assert active.physical_worktree is not None
    physical_path = active.physical_worktree.worktree_path
    result = await context.executor.prepare_finalization(context.lease, result="succeeded")
    _terminalize(context, result)
    await context.executor.finalize(context.lease, result=result)
    eligible = context.fixture.worktrees.mark_gc_eligible(
        now=datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    assert [item.worktree_id for item in eligible] == [active.worktree_lease.worktree_id]

    assert await context.executor.reconcile_physical_gc(limit=1) == 1
    assert await context.executor.reconcile_physical_gc(limit=1) == 0
    assert not physical_path.exists()
    with context.fixture.factory() as database:
        record = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        assert record is not None and record.status == "deleted"


def test_worker_loop_releases_worktree_quota_after_runner_process_loss(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
) -> None:
    context = _build_prepared_executor(worktree_fixture, tmp_path, suffix="worker-recovery")
    active, _command = context.executor._prepare(context.lease)
    _terminalize(context, "failed")
    with context.fixture.factory.begin() as database:
        record = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        assert record is not None
        record.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        assert quota is not None and quota.active_instances == 1

    stop = threading.Event()

    class _Dispatcher:
        def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult:
            assert batch_size == 1
            stop.set()
            return DispatchResult(claimed=0, published=0, failed=0, quarantined=0)

    class _Ready:
        def assert_production_ready(self) -> None:
            return None

    worker = ProductionSchedulerWorker(
        _Dispatcher(),
        context.fixture.scheduling,
        ProductionWorkerAdapters(runner=_Ready(), preview=_Ready()),
        batch_size=1,
        idle_interval_seconds=0.01,
        error_backoff_seconds=0.01,
        max_error_backoff_seconds=0.1,
        recovery_interval_seconds=1,
        recovery_limit=10,
        worktree_recovery=context.fixture.worktrees,
        worktree_recovery_interval_seconds=1,
        worktree_gc_interval_seconds=30,
        worktree_recovery_limit=10,
        clock=lambda: 0.0,
    )

    stats = worker.run(stop)

    assert stats.worktree_recovery_cycles == 1
    assert stats.worktrees_recovered == 1
    with context.fixture.factory() as database:
        quota = database.scalar(sa.select(WorktreeQuotaRecord))
        record = database.get(WorktreeInstanceRecord, active.worktree_lease.worktree_id)
        assert quota is not None and quota.active_instances == quota.reserved_bytes == 0
        assert record is not None and record.status == "released"
