from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from omnigent.inner.credential_proxy import prepare_credential_proxy_runtime
from saas.control_plane import (
    ControlPlaneOutboxEvent,
    EgressPolicyRecord,
    ExecutionProfileRecord,
    IsolationControlPlane,
    IsolationControlPlaneError,
    PreviewOriginConfig,
    RunIsolationGrantRecord,
    SecretAccessLeaseRecord,
    SecretBindingRecord,
)
from saas.control_plane.execution import ExecutionRevisionSet
from saas.runner_adapter import (
    PhysicalWorktree,
    RunnerIsolationAdapter,
    RunnerIsolationAdapterError,
)
from tests.saas.test_worktree_control_plane import (
    LeasedRun,
    WorktreeFixture,
    _allocate,
    _configure_worktree_quota,
    _repository_and_change_set,
    worktree_fixture,  # noqa: F401
)

_RUNNER_ISOLATION_CAPABILITIES = (
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


class _SecretProvider:
    def __init__(self, value: str) -> None:
        self.value = value
        self.calls: list[tuple[str, str, str]] = []

    def resolve(self, *, provider: str, vault_ref: str, version_ref: str) -> str:
        self.calls.append((provider, vault_ref, version_ref))
        return self.value


class _Containment:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, str]] = []

    def require_enforced(self, *, runner_id: UUID, contract) -> None:
        assert contract.root_read_only is True
        assert contract.run_as_uid > 0
        assert contract.run_as_gid > 0
        assert contract.no_new_privileges is True
        assert contract.host_socket_access is False
        assert contract.cpu_millis > 0
        assert contract.memory_bytes > 0
        assert contract.pids_limit > 0
        self.calls.append((runner_id, contract.config_hash))


def _revisions() -> ExecutionRevisionSet:
    return ExecutionRevisionSet(
        product_revision="product",
        upstream_revision="upstream",
        schema_revision="p4c000000001",
        adapter_contract_version="0.2.0",
    )


def _lease_isolated_run(
    fixture: WorktreeFixture,
    *,
    change_set_id: UUID,
    now: datetime,
    key: str,
) -> LeasedRun:
    request = fixture.request
    fixture.execution.configure_quota(
        request,
        project_id=fixture.project_id,
        resource="run_units",
        limit_units=20,
    )
    task_id = fixture.execution.create_task(
        request,
        project_id=fixture.project_id,
        title=f"Isolation task {key}",
    )
    admitted = fixture.execution.admit_run(
        request,
        project_id=fixture.project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"change_set_id": str(change_set_id)},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=f"isolation-{key}",
        revisions=_revisions(),
    )
    pool_id = fixture.scheduling.create_pool(
        placement_id=fixture.placement_id,
        name=f"isolation-{key}",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    fixture.scheduling.configure_tenant_share(
        tenant_id=request.tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=2,
        burst_limit=2,
    )
    fixture.scheduling.prepare_dispatch(
        run_id=admitted.run_id,
        pool_id=pool_id,
        required_capabilities=list(_RUNNER_ISOLATION_CAPABILITIES),
        eligible_at=now,
        maximum_wait=timedelta(hours=1),
    )
    connection = fixture.scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"runner-isolation-{key}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=list(_RUNNER_ISOLATION_CAPABILITIES),
        max_concurrency=1,
        now=now,
    )
    lease = fixture.scheduling.claim_fair_run(
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        lease_duration=timedelta(minutes=5),
        capability_actions=[
            "preview.serve",
            "sandbox.launch",
            "worktree.read",
            "worktree.write",
        ],
        capability_resource_scope={"change_set_id": str(change_set_id)},
        now=now + timedelta(seconds=1),
    )
    assert lease is not None
    return LeasedRun(
        lease.run_id,
        pool_id,
        connection.runner_id,
        connection.connection_generation,
        connection.connection_token,
        lease.lease_token,
        lease.fence_token,
        lease.capability_token,
    )


def _ready_worktree(
    fixture: WorktreeFixture,
    leased: LeasedRun,
    change_set_id: UUID,
    *,
    now: datetime,
):
    lease = _allocate(fixture, leased, change_set_id, now=now + timedelta(seconds=2))
    fixture.worktrees.begin_materialization(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        trace_id="isolation-materialize",
        now=now + timedelta(seconds=3),
    )
    grant = fixture.worktrees.materialization_grant(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        now=now + timedelta(seconds=4),
    )
    fixture.worktrees.acknowledge_ready(
        worktree_id=lease.worktree_id,
        runner_id=lease.runner_id,
        lease_generation=lease.lease_generation,
        run_fence_token=lease.run_fence_token,
        lease_token=lease.lease_token,
        actual_bytes=1024,
        trace_id="isolation-ready",
        now=now + timedelta(seconds=5),
    )
    return lease, grant


def _profile(
    fixture: WorktreeFixture,
    isolation: IsolationControlPlane,
    *,
    bind_secret: bool = True,
) -> tuple[UUID, UUID, UUID | None]:
    policy_id = isolation.create_egress_policy(
        fixture.request,
        project_id=fixture.project_id,
        name=f"public-api-{uuid4().hex}",
        rules=["GET api.github.com/**", "POST api.github.com/graphql"],
    )
    profile_id = isolation.create_execution_profile(
        fixture.request,
        project_id=fixture.project_id,
        egress_policy_id=policy_id,
        name=f"managed-{uuid4().hex}",
        sandbox_backend="linux_bwrap",
        syscall_profile_ref="oci-default-v1",
        cpu_millis=1000,
        memory_bytes=1_073_741_824,
        pids_limit=256,
        allowed_tools=["sys_os_read", "sys_os_write", "sys_os_shell"],
        approval_required_tools=["sys_os_shell"],
        denied_tools=["host.docker_socket"],
    )
    binding_id = None
    if bind_secret:
        binding_id = isolation.bind_secret(
            fixture.request,
            project_id=fixture.project_id,
            execution_profile_id=profile_id,
            name="github-api",
            vault_provider="vault-prod",
            vault_ref="projects/demo/secrets/github",
            version_ref="v7",
            credential_scheme="bearer",
            host="api.github.com",
            inject_env=["GH_TOKEN"],
        )
    return policy_id, profile_id, binding_id


def test_server_chosen_profile_rejects_soft_sandbox_private_egress_and_secret_mismatch(
    worktree_fixture: WorktreeFixture,  # noqa: F811
) -> None:
    isolation = IsolationControlPlane(
        worktree_fixture.factory, scheduler=worktree_fixture.scheduling
    )

    with pytest.raises(IsolationControlPlaneError) as private_ip:
        isolation.create_egress_policy(
            worktree_fixture.request,
            project_id=worktree_fixture.project_id,
            name="metadata",
            rules=["GET 169.254.169.254/**"],
        )
    assert private_ip.value.code == "egress_host_invalid"

    policy_id = isolation.create_egress_policy(
        worktree_fixture.request,
        project_id=worktree_fixture.project_id,
        name="default-deny",
        rules=["GET api.github.com/**"],
    )
    with pytest.raises(IsolationControlPlaneError) as soft_backend:
        isolation.create_execution_profile(
            worktree_fixture.request,
            project_id=worktree_fixture.project_id,
            egress_policy_id=policy_id,
            name="unsafe",
            sandbox_backend="none",
            syscall_profile_ref="oci-default-v1",
            cpu_millis=1000,
            memory_bytes=1024,
            pids_limit=16,
            allowed_tools=["sys_os_read"],
        )
    assert soft_backend.value.code == "sandbox_backend_denied"

    _, profile_id, _ = _profile(worktree_fixture, isolation, bind_secret=False)
    with pytest.raises(IsolationControlPlaneError) as wrong_host:
        isolation.bind_secret(
            worktree_fixture.request,
            project_id=worktree_fixture.project_id,
            execution_profile_id=profile_id,
            name="exfil",
            vault_provider="vault-prod",
            vault_ref="projects/demo/secrets/exfil",
            version_ref="v1",
            credential_scheme="bearer",
            host="attacker.example",
        )
    assert wrong_host.value.code == "secret_egress_binding_denied"

    with worktree_fixture.factory() as db:
        policy = db.get(EgressPolicyRecord, policy_id)
        profile = db.get(ExecutionProfileRecord, profile_id)
        assert policy is not None and policy.allow_private_destinations is False
        assert profile is not None
        assert profile.network_mode == "proxy_only"
        assert profile.root_read_only is True
        assert profile.run_as_uid == 65532
        assert profile.no_new_privileges is True
        assert profile.host_socket_access is False


def test_one_time_launch_secret_broker_and_official_credential_proxy_are_fenced_and_secretless(
    worktree_fixture: WorktreeFixture,  # noqa: F811
    tmp_path: Path,
) -> None:
    now = datetime.now(timezone.utc) + timedelta(minutes=1)
    _, change_set_id = _repository_and_change_set(worktree_fixture, suffix="isolation")
    _configure_worktree_quota(worktree_fixture)
    leased = _lease_isolated_run(
        worktree_fixture,
        change_set_id=change_set_id,
        now=now,
        key="secretless",
    )
    worktree_lease, materialization = _ready_worktree(
        worktree_fixture, leased, change_set_id, now=now
    )
    isolation = IsolationControlPlane(
        worktree_fixture.factory, scheduler=worktree_fixture.scheduling
    )
    _, profile_id, binding_id = _profile(worktree_fixture, isolation)
    assert binding_id is not None
    issued = isolation.issue_launch_grant(
        capability_token=leased.capability_token,
        runner_id=leased.runner_id,
        run_id=leased.run_id,
        worktree_grant=materialization,
        execution_profile_id=profile_id,
        now=now + timedelta(seconds=6),
    )
    assert issued.token not in repr(issued)

    physical_root = tmp_path / "physical-worktree"
    physical_root.mkdir(mode=0o700)
    (physical_root / "source.py").write_text("print('safe')\n", encoding="utf-8")
    (physical_root / ".git").write_text("gitdir: /not/exposed\n", encoding="utf-8")
    staging_root = tmp_path / "trusted-secret-stage"
    staging_root.mkdir(mode=0o700)
    secret_value = "real-secret-must-never-enter-the-sandbox"
    provider = _SecretProvider(secret_value)
    containment = _Containment()
    linked_target = tmp_path / "linked-secret-target"
    linked_target.mkdir(mode=0o700)
    linked_staging = tmp_path / "linked-secret-stage"
    linked_staging.symlink_to(linked_target, target_is_directory=True)
    with pytest.raises(RunnerIsolationAdapterError) as unsafe_staging:
        RunnerIsolationAdapter(
            staging_root=linked_staging,
            authority=isolation,
            secret_provider=provider,
            containment=containment,
        )
    assert unsafe_staging.value.code == "secret_staging_root_unsafe"
    adapter = RunnerIsolationAdapter(
        staging_root=staging_root,
        authority=isolation,
        secret_provider=provider,
        containment=containment,
    )
    prepared = adapter.prepare(
        grant_token=issued.token,
        runner_id=leased.runner_id,
        run_id=leased.run_id,
        physical_worktree=PhysicalWorktree(
            worktree_lease.worktree_id,
            physical_root,
            "a" * 40,
            1024,
            False,
        ),
    )
    assert containment.calls and containment.calls[0][0] == leased.runner_id
    assert prepared.launch_grant.contract.tool_policy.evaluate("sys_os_read") == "allow"
    assert prepared.launch_grant.contract.tool_policy.evaluate("sys_os_shell") == "approval"
    assert prepared.launch_grant.contract.tool_policy.evaluate("unknown_tool") == "deny"
    sandbox = prepared.os_env_spec.sandbox
    assert sandbox is not None
    assert sandbox.type == "linux_bwrap"
    assert sandbox.allow_network is False
    assert sandbox.egress_allow_private_destinations is False
    assert sandbox.cwd_hidden_scan_overflow == "error"
    assert sandbox.cwd_hidden_scan_recursive is True
    assert sandbox.mask_paths == [str(physical_root / ".git")]
    assert sandbox.credential_proxy is not None
    source_path = Path(sandbox.credential_proxy.entries[0].source.path or "")
    assert source_path.is_file()
    assert source_path.stat().st_mode & 0o777 == 0o600
    assert not source_path.is_relative_to(physical_root)
    serialized_spec = json.dumps(asdict(prepared.os_env_spec), default=str)
    assert secret_value not in serialized_spec
    assert secret_value not in repr(prepared)

    runtime = prepare_credential_proxy_runtime(sandbox.credential_proxy, parent_env={})
    assert runtime.rewrites[0].resolve_secret() == secret_value
    assert runtime.rewrites[0].host == "api.github.com"
    assert runtime.helper_env_updates["GH_TOKEN"].startswith("oa_cred_")
    assert secret_value not in runtime.helper_env_updates.values()
    prepared.close()
    assert not source_path.exists()
    assert not prepared.secret_directory.exists()
    assert provider.calls == [("vault-prod", "projects/demo/secrets/github", "v7")]

    with pytest.raises(RunnerIsolationAdapterError) as replay:
        adapter.prepare(
            grant_token=issued.token,
            runner_id=leased.runner_id,
            run_id=leased.run_id,
            physical_worktree=PhysicalWorktree(
                worktree_lease.worktree_id,
                physical_root,
                "a" * 40,
                1024,
                False,
            ),
        )
    assert replay.value.code == "isolation_grant_stale"

    with worktree_fixture.factory() as db:
        grant = db.get(RunIsolationGrantRecord, issued.grant_id)
        binding = db.get(SecretBindingRecord, binding_id)
        leases = tuple(db.scalars(sa.select(SecretAccessLeaseRecord)))
        outbox = tuple(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert grant is not None and grant.status == "redeemed"
        assert binding is not None and binding.vault_ref == "projects/demo/secrets/github"
        assert len(leases) == 1 and leases[0].status == "redeemed"
        persisted = json.dumps(
            {
                "grant": grant.grant_hash,
                "binding": binding.metadata_hash,
                "outbox": [event.payload for event in outbox],
            },
            default=str,
        )
        assert secret_value not in persisted


def test_runner_reconnect_fences_unredeemed_isolation_grant(
    worktree_fixture: WorktreeFixture,  # noqa: F811
) -> None:
    now = datetime.now(timezone.utc) + timedelta(minutes=1)
    _, change_set_id = _repository_and_change_set(worktree_fixture, suffix="reconnect")
    _configure_worktree_quota(worktree_fixture)
    leased = _lease_isolated_run(
        worktree_fixture,
        change_set_id=change_set_id,
        now=now,
        key="reconnect",
    )
    _, materialization = _ready_worktree(worktree_fixture, leased, change_set_id, now=now)
    isolation = IsolationControlPlane(
        worktree_fixture.factory, scheduler=worktree_fixture.scheduling
    )
    _, profile_id, _ = _profile(worktree_fixture, isolation, bind_secret=False)
    issued = isolation.issue_launch_grant(
        capability_token=leased.capability_token,
        runner_id=leased.runner_id,
        run_id=leased.run_id,
        worktree_grant=materialization,
        execution_profile_id=profile_id,
        now=now + timedelta(seconds=6),
    )
    worktree_fixture.scheduling.register_runner(
        pool_id=leased.pool_id,
        instance_key="runner-isolation-reconnect",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=list(_RUNNER_ISOLATION_CAPABILITIES),
        max_concurrency=1,
        now=now + timedelta(seconds=7),
    )

    with pytest.raises(IsolationControlPlaneError) as stale:
        isolation.redeem_launch_grant(
            token=issued.token,
            runner_id=leased.runner_id,
            run_id=leased.run_id,
            now=now + timedelta(seconds=8),
        )
    assert stale.value.code == "isolation_fence_stale"


def test_preview_origin_is_cookie_isolated_exact_host_fenced_and_revocable(
    worktree_fixture: WorktreeFixture,  # noqa: F811
) -> None:
    now = datetime.now(timezone.utc) + timedelta(minutes=1)
    _, change_set_id = _repository_and_change_set(worktree_fixture, suffix="preview")
    _configure_worktree_quota(worktree_fixture)
    leased = _lease_isolated_run(
        worktree_fixture,
        change_set_id=change_set_id,
        now=now,
        key="preview",
    )
    _, materialization = _ready_worktree(worktree_fixture, leased, change_set_id, now=now)
    isolation = IsolationControlPlane(
        worktree_fixture.factory, scheduler=worktree_fixture.scheduling
    )
    origin = PreviewOriginConfig(
        primary_origin="https://app.example.com",
        primary_cookie_domain="example.com",
        preview_root_domain="example-preview.net",
    )
    with pytest.raises(IsolationControlPlaneError) as shared_cookie_domain:
        PreviewOriginConfig(
            primary_origin="https://app.example.com",
            primary_cookie_domain="example.com",
            preview_root_domain="preview.example.com",
        )
    assert shared_cookie_domain.value.code == "preview_origin_not_isolated"
    with pytest.raises(IsolationControlPlaneError) as credentialed_origin:
        PreviewOriginConfig(
            primary_origin="https://user@app.example.com",
            primary_cookie_domain="example.com",
            preview_root_domain="example-preview.net",
        )
    assert credentialed_origin.value.code == "primary_origin_invalid"

    preview = isolation.issue_preview_lease(
        worktree_fixture.request,
        capability_token=leased.capability_token,
        runner_id=leased.runner_id,
        run_id=leased.run_id,
        worktree_grant=materialization,
        origin=origin,
        lifetime=timedelta(minutes=10),
        now=now + timedelta(seconds=6),
    )
    assert preview.token not in preview.url
    assert preview.token not in repr(preview)
    assert preview.url == f"https://{preview.host}/"

    route = isolation.authorize_preview_request(
        host=preview.host,
        token=preview.token,
        incoming_headers={
            "Accept": "text/html",
            "User-Agent": "preview-test",
            "X-Forwarded-For": "192.0.2.1",
        },
        now=now + timedelta(seconds=7),
    )
    assert route.runner_id == leased.runner_id
    assert route.runner_connection_generation == materialization.runner_connection_generation
    assert route.run_fence_token == materialization.run_fence_token
    assert route.worktree_id == materialization.worktree_id
    assert route.worktree_lease_generation == materialization.lease_generation
    assert route.upstream_request_headers == {
        "accept": "text/html",
        "user-agent": "preview-test",
    }
    assert route.response_headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in route.response_headers["Content-Security-Policy"]

    with pytest.raises(IsolationControlPlaneError) as cookie:
        isolation.authorize_preview_request(
            host=preview.host,
            token=preview.token,
            incoming_headers={"Cookie": "omnigent_session=must-not-cross-origin"},
            now=now + timedelta(seconds=8),
        )
    assert cookie.value.code == "preview_ambient_credential_denied"

    with pytest.raises(IsolationControlPlaneError) as wrong_host:
        isolation.authorize_preview_request(
            host=f"other.{origin.preview_root_domain}",
            token=preview.token,
            incoming_headers={},
            now=now + timedelta(seconds=8),
        )
    assert wrong_host.value.code == "preview_lease_stale"

    assert isolation.revoke_preview_lease(
        worktree_fixture.request,
        preview_id=preview.preview_id,
        now=now + timedelta(seconds=9),
    )
    assert not isolation.revoke_preview_lease(
        worktree_fixture.request,
        preview_id=preview.preview_id,
        now=now + timedelta(seconds=10),
    )
    with pytest.raises(IsolationControlPlaneError) as revoked:
        isolation.authorize_preview_request(
            host=preview.host,
            token=preview.token,
            incoming_headers={},
            now=now + timedelta(seconds=11),
        )
    assert revoked.value.code == "preview_lease_stale"
