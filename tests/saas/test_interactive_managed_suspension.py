"""Scripted retained-parent contracts; not live kubelet/PVC or dormant resume proof."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace
from threading import Event
from types import SimpleNamespace
from uuid import UUID

import pytest

from saas.production.interactive_managed_recovery import suspend_managed_resources
from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    ManagedPodTermination,
    ManagedSuspensionReceipt,
    ManagedTerminationReceipt,
    ManagedVolumeBinding,
    _decode,
    _encode,
    managed_retirement_proof_sha256,
    managed_suspension_proof_sha256,
    physical_recovery_proof_sha256,
)
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _reference
from tests.saas.test_interactive_managed_recovery import _fixture
from tests.saas.test_interactive_managed_resources import _resources
from tests.saas.test_interactive_managed_termination_records import _intent


async def _retained(tmp_path, monkeypatch, *, persistent=True):
    c = await _fixture(tmp_path, monkeypatch, "agent_sandbox")
    c.p = c.c.p
    c.state.record.managed_creation = replace(
        c.state.record.managed_creation, pod_uid=str(UUID(int=3)), pod_name="owned-pod"
    )
    c.pod["metadata"].setdefault("finalizers", []).append("saas.omnigent.ai/observe-termination")
    claims = {}
    if persistent:
        c.state.parent["spec"]["volumeClaimTemplates"] = [
            {"metadata": {"name": "home"}, "spec": {"accessModes": ["ReadWriteOnce"]}}
        ]
        c.pod["spec"]["volumes"] = [
            {"name": "home", "persistentVolumeClaim": {"claimName": "owned-home"}}
        ]
        claims["owned-home"] = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": "owned-home",
                "namespace": c.state.record.managed_preparation.namespace,
                "uid": str(UUID(int=7)),
                "ownerReferences": copy.deepcopy(c.pod["metadata"]["ownerReferences"]),
            },
            "spec": {"accessModes": ["ReadWriteOnce"]},
            "status": {"phase": "Bound"},
        }
    api = c.p.delegate._api_client.call_api

    def with_claims(path, method, **kwargs):
        if "/persistentvolumeclaims/" in path:
            assert method == "GET"
            return copy.deepcopy(claims.get(path.rsplit("/", 1)[1]))
        return api(path, method, **kwargs)

    c.p.delegate._api_client.call_api = with_claims

    async def step():
        return await suspend_managed_resources(c.p.deployment, c.state.record, c.checkpoint)

    c.suspend = step
    c.claims = claims
    return c


@pytest.mark.asyncio
@pytest.mark.parametrize("persistent", [False, True])
async def test_suspend_keeps_parent_and_claims_but_waits_for_kubelet_and_secret_ack(
    tmp_path, monkeypatch, persistent
):
    c = await _retained(tmp_path, monkeypatch, persistent=persistent)
    uid = c.state.parent["metadata"]["uid"]
    claims = copy.deepcopy(c.claims)
    await c.suspend()
    await c.suspend()
    assert not c.state.record.managed_suspension.complete
    assert c.state.record.managed_suspension.termination.quiescence_sha256
    assert c.state.secret is not None and c.state.pods
    c.terminal()
    for _ in range(5):
        await c.suspend()
        if c.state.record.managed_suspension.complete:
            break
    receipt = c.state.record.managed_suspension
    assert receipt.complete and not receipt.termination.complete
    assert receipt.termination.secret_gone and receipt.termination.pods[0].containers_sha256
    assert c.state.record.managed_termination is None
    assert c.state.parent["metadata"]["uid"] == uid
    assert c.state.parent["spec"]["operatingMode"] == "Suspended"
    assert c.state.secret is None and not c.state.pods and c.claims == claims
    assert len(receipt.volumes) == int(persistent)
    assert not any(
        method == "DELETE" and "/pods/" not in path and "/secrets/" not in path
        for method, path, _ in c.state.effects
    )
    # Explicit full retirement may subsequently use the same kubelet facts.
    for _ in range(6):
        await c.step()
        if c.state.record.managed_termination.complete:
            break
    assert c.state.record.managed_termination.complete and c.state.parent is None
    assert c.state.record.managed_suspension == receipt


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", ["uid", "owner", "deleted", "unbound", "template"])
async def test_retained_claim_drift_cannot_complete_or_delete_the_parent(
    tmp_path, monkeypatch, drift
):
    c = await _retained(tmp_path, monkeypatch)
    await c.suspend()
    await c.suspend()
    c.terminal()
    claim = c.claims["owned-home"]
    if drift == "uid":
        claim["metadata"]["uid"] = str(UUID(int=8))
    elif drift == "owner":
        claim["metadata"]["ownerReferences"][0]["uid"] = str(UUID(int=8))
    elif drift == "deleted":
        claim["metadata"]["deletionTimestamp"] = "2026-10-20T00:00:00Z"
    elif drift == "unbound":
        claim["status"]["phase"] = "Pending"
    else:
        c.state.parent["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"] = [
            "ReadWriteMany"
        ]
    before = copy.deepcopy(c.state.effects)
    with pytest.raises(RunnerControlError):
        await c.suspend()
    assert c.state.effects == before and c.state.parent is not None
    assert not c.state.record.managed_suspension.complete


async def _root(c, *, preparation=None, creation=None, resources=None):
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(
        active, managed_preparation=preparation or _reference(provider="agent_sandbox")
    )
    seed = creation or _intent(
        secret_submitted=True,
        secret_uid=str(UUID(int=2)),
        workload_submitted=True,
        input_template_sha256="a" * 64,
        pod_uid=str(UUID(int=3)),
        pod_name="owned-pod",
    )
    initial = replace(
        seed,
        secret_submitted=False,
        secret_uid=None,
        workload_submitted=False,
        input_template_sha256=None,
        pod_uid=None,
        pod_name=None,
    )
    for intent in (
        initial,
        replace(initial, secret_submitted=True),
        replace(initial, secret_submitted=True, secret_uid=seed.secret_uid),
        replace(seed, pod_uid=None, pod_name=None),
    ):
        c.executor._put(active, managed_creation=intent)
    c.executor._put(active, managed_resources=resources or _resources())
    c.executor._put(active, managed_creation=seed)
    c.executor._put(active, phase="draining", outcome="orphaned")
    return active


@pytest.mark.asyncio
async def test_suspension_journal_is_monotonic_and_has_a_distinct_non_retirement_proof(
    controller_case,
):
    c = controller_case
    active = await _root(c)
    term = ManagedTerminationReceipt(secret_uid=str(UUID(int=2)))
    initial = ManagedSuspensionReceipt(term)
    c.executor._put(active, managed_suspension=initial)
    captured = replace(
        initial,
        volume_templates_sha256="f" * 64,
        volumes=(ManagedVolumeBinding("owned-home", str(UUID(int=7))),),
    )
    c.executor._put(active, managed_suspension=captured)
    stopped = replace(
        captured,
        termination=replace(
            term,
            secret_gone=True,
            quiescence_sha256="d" * 64,
            pods=(ManagedPodTermination(str(UUID(int=3)), "owned-pod", "c" * 64),),
        ),
    )
    c.executor._put(active, managed_suspension=stopped)
    complete = replace(stopped, complete=True)
    c.executor._put(
        active,
        managed_suspension=complete,
        phase="terminal",
        process_stopped=True,
        stop_kind="managed_suspend",
    )
    record = c.journal.read(active.record.run_id)
    raw = _encode(record)
    assert json.loads(raw)["schema_version"] == 11 and _decode(raw) == record
    assert physical_recovery_proof_sha256(record) == managed_suspension_proof_sha256(record)
    with pytest.raises(InteractiveRecoveryError):
        managed_retirement_proof_sha256(record)
    for receipt in (
        None,
        captured,
        stopped,
        replace(complete, volumes=()),
        replace(complete, volume_templates_sha256="e" * 64),
    ):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(record, managed_suspension=receipt))
    for version in range(1, 11):
        document = json.loads(raw)
        document["schema_version"] = version
        with pytest.raises(InteractiveRecoveryError):
            _decode(json.dumps(document).encode())


async def _controller_suspended(c, db_uri, tmp_path, monkeypatch):
    from omnigent.stores.host_store import HostStore
    from saas.production.interactive_driver import OfficialInteractiveDriver
    from tests.saas.test_interactive_orphaned_retirement import (
        _release,
        _terminal,
        _trusted_recovery,
    )

    scripted = await _retained(tmp_path, monkeypatch)
    record = scripted.state.record
    active = await _root(
        c,
        preparation=record.managed_preparation,
        creation=record.managed_creation,
        resources=record.managed_resources,
    )
    active.finished.set()
    _terminal(c)
    _release(c)
    _trusted_recovery(c)
    store = HostStore(db_uri)
    app = SimpleNamespace(state=SimpleNamespace(sandbox_config=scripted.p.deployment))
    driver = OfficialInteractiveDriver(
        app=app, dependencies=SimpleNamespace(host_store=store), contract_version="0.2.0"
    )
    with driver._adapter.bind(c.context):
        host = store.register_managed_host(
            host_id=record.managed_preparation.host_id,
            name="owned-suspend",
            user_id=c.context.runtime_user_key,
            token=scripted.c.token,
            provider="agent_sandbox",
            sandbox_id=record.managed_preparation.resource_name,
            token_expires_at=2_000_000_000,
        )
    for name in (
        "inspect_managed_retirement",
        "detach_managed_retirement",
        "finish_managed_retirement",
    ):
        setattr(c.physical, name, getattr(driver, name))

    async def suspend(record, checkpoint):
        scripted.state.record = record

        async def observe(**changes):
            result = await checkpoint(**changes)
            scripted.state.record = result
            return result

        return await driver.suspend_managed(record, observe)

    c.physical.suspend_managed = suspend
    for _ in range(2):
        assert not await c.executor.retire_managed_origin(
            active.record.run_id, cutoff=0, now=1_792_500_000, retaining=True
        )
    scripted.terminal()
    for _ in range(5):
        if await c.executor.retire_managed_origin(
            active.record.run_id, cutoff=0, now=1_792_500_000, retaining=True
        ):
            break
    source = c.journal.read(active.record.run_id)
    assert source.process_stopped and source.managed_suspension.complete
    assert source.managed_termination is None and c.confirmed == [source.run_id]
    with driver._adapter.bind(c.context):
        retired_host = store.get_host(host.host_id)
        assert retired_host.sandbox_id is retired_host.terminating_sandbox_id is None
        assert store.resolve_launch_token(host.host_id, scripted.c.token) is None
    conversation = SimpleNamespace(host_id=host.host_id, runner_id=None)
    driver._official.conversation_store = SimpleNamespace(get_conversation=lambda _: conversation)
    authorized = replace(
        c.authorized,
        launch={
            **c.authorized.launch,
            "host_type": "managed",
            "sandbox_provider": "agent_sandbox",
        },
    )
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
async def test_controller_revokes_the_old_host_and_admits_only_the_retained_parent(
    controller_case, db_uri, tmp_path, monkeypatch
):
    c = controller_case
    case = await _controller_suspended(c, db_uri, tmp_path, monkeypatch)
    before = copy.deepcopy(case.scripted.state.effects)
    admission = await case.driver.revalidate_managed(
        case.authorized, (case.source,), previous=None
    )
    assert (
        admission.resuming
        and admission.origin == case.source
        and admission.host == case.retired_host
    )
    assert case.scripted.state.effects == before
    assert (
        case.scripted.state.parent["metadata"]["uid"] == case.source.managed_resources.workload_uid
    )
    assert len(case.scripted.claims) == 1 and not c.inputs and not c.gateway_calls
    # A replaced retained claim is not a reason to create a fresh empty workspace.
    case.scripted.claims["owned-home"]["metadata"]["uid"] = str(UUID(int=99))
    with pytest.raises(RunnerControlError):
        await case.driver.revalidate_managed(case.authorized, (case.source,), previous=None)
    assert case.scripted.state.effects == before


@pytest.mark.asyncio
async def test_seven_day_reaper_can_finish_a_previously_suspended_generation(
    controller_case, db_uri, tmp_path, monkeypatch
):
    from omnigent.db.utils import now_epoch
    from saas.production.interactive_managed_retirement import ControllerManagedSandboxReaper

    c = controller_case
    case = await _controller_suspended(c, db_uri, tmp_path, monkeypatch)
    scripted = case.scripted
    proof = physical_recovery_proof_sha256(case.source)
    scripted.p.deployment.reaper = replace(
        scripted.p.deployment.reaper, enabled=True, terminate_after_offline_days=7
    )
    reaper = ControllerManagedSandboxReaper(
        executor=c.executor,
        driver=case.driver,
        host_store=case.store,
        sandbox_config=scripted.p.deployment,
    )

    async def retire(record, checkpoint):
        scripted.state.record = record

        async def observe(**changes):
            updated = await checkpoint(**changes)
            scripted.state.record = updated
            return updated

        return await case.driver.retire_managed(record, observe)

    c.physical.retire_managed = retire
    current = now_epoch()
    assert await reaper.sweep_once(now=current) == 0 and scripted.state.parent is not None
    for _ in range(5):
        if await reaper.sweep_once(now=current + 8 * 86400):
            break
    stopped = c.journal.read(case.source.run_id)
    assert stopped.managed_termination.complete and scripted.state.parent is None
    assert stopped.managed_suspension == case.source.managed_suspension
    assert physical_recovery_proof_sha256(stopped) == proof


@pytest.mark.asyncio
async def test_resume_patch_uses_uid_rv_and_never_replaces_pvc_templates(
    controller_case, db_uri, tmp_path, monkeypatch
):
    import base64

    from omnigent.host.identity import HOST_TOKEN_ENV_VAR
    from saas.production.interactive_preparation import _ResumeCustom
    from saas.production.interactive_resources import CREATION_ANNOTATION

    case = await _controller_suspended(controller_case, db_uri, tmp_path, monkeypatch)
    scripted, source = case.scripted, case.source
    parent = scripted.state.parent
    original = copy.deepcopy(parent)
    token = "new-owned-host-token"
    from hashlib import sha256

    intent = replace(
        source.managed_creation,
        nonce="e" * 32,
        host_token_sha256=sha256(token.encode()).hexdigest(),
        secret_uid=str(UUID(int=12)),
        pod_uid=None,
        pod_name=None,
    )
    secret = copy.deepcopy(scripted.secret)
    secret["metadata"].pop("deletionTimestamp", None)
    secret["metadata"]["uid"] = intent.secret_uid
    secret["metadata"]["annotations"][CREATION_ANNOTATION] = intent.nonce
    secret["data"][HOST_TOKEN_ENV_VAR] = base64.b64encode(token.encode()).decode()
    scripted.state.secret = secret
    owner = SimpleNamespace(
        _delegate=scripted.p.delegate, _resume=source, _intent=intent, _stopping=Event()
    )
    body = copy.deepcopy(parent)
    body["metadata"]["annotations"][CREATION_ANNOTATION] = intent.nonce
    body["spec"]["operatingMode"] = "Running"
    body["spec"]["shutdownTime"] = "2030-01-01T00:00:00Z"
    api = scripted.p.delegate._api_client.call_api
    writes = []

    def patch(path, method, **kwargs):
        if method != "PATCH":
            return api(path, method, **kwargs)
        operations = kwargs["body"]
        assert operations[:2] == [
            {"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": original["metadata"]["resourceVersion"],
            },
        ]
        assert not any(
            op["path"].startswith("/spec/volumeClaimTemplates")
            or op["path"].startswith("/metadata/finalizers")
            for op in operations
        )
        writes.append(kwargs)
        return copy.deepcopy(body)

    scripted.p.delegate._api_client.call_api = patch
    preparation = source.managed_preparation
    from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION, SANDBOX_PLURAL

    wrapped = _ResumeCustom(SimpleNamespace(), owner, preparation)
    await asyncio.to_thread(
        wrapped.create_namespaced_custom_object,
        API_GROUP,
        API_VERSION,
        preparation.namespace,
        SANDBOX_PLURAL,
        body,
        _request_timeout=10,
    )
    assert len(writes) == 1 and parent == original
    body["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"] = ["ReadWriteMany"]
    with pytest.raises(RunnerControlError):
        await asyncio.to_thread(
            wrapped.create_namespaced_custom_object,
            API_GROUP,
            API_VERSION,
            preparation.namespace,
            SANDBOX_PLURAL,
            body,
            _request_timeout=10,
        )
    assert len(writes) == 1 and parent == original


@pytest.mark.asyncio
async def test_two_resumes_keep_parent_and_claims_but_have_independent_run_authority(
    controller_case, db_uri, tmp_path, monkeypatch
):
    import base64
    from dataclasses import fields
    from hashlib import sha256

    from omnigent.host.identity import HOST_TOKEN_ENV_VAR
    from saas.control_plane.execution import ExecutionControlPlane
    from saas.control_plane.scheduling import SchedulingControlPlane
    from saas.production.interactive_managed_generation import RetiredGenerationHostStore
    from saas.production.interactive_resources import (
        CREATION_ANNOTATION,
        INPUT_TEMPLATE_ANNOTATION,
        _template_sha256,
    )
    from saas.production.runner_control import (
        ProductionRunnerMachineAuthority,
        RunnerControlClientLease,
    )
    from tests.saas.test_interactive_orphaned_retirement import _machine
    from tests.saas.test_interactive_runner_lease import _admit

    c = controller_case
    case = await _controller_suspended(c, db_uri, tmp_path, monkeypatch)
    scripted = case.scripted
    roots = [case.source]
    authorize, prepare = c.executor._authorize, c.physical.prepare
    control = ProductionRunnerMachineAuthority(
        SchedulingControlPlane(c.f.factory),
        ExecutionControlPlane(c.f.factory),
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    machine = {
        key: getattr(c.connection, key)
        for key in ("runner_id", "connection_generation", "connection_token")
    }

    async def managed(lease):
        authorized, issued = await authorize(lease)
        return replace(
            authorized,
            launch={
                **authorized.launch,
                "host_type": "managed",
                "sandbox_provider": "agent_sandbox",
            },
        ), issued

    def args(record):
        return {
            **_machine(c),
            "run_id": record.run_id,
            "fence_token": record.fence_token,
            "capability_token": record.grant.capability_token,
        }

    async def released(record):
        SchedulingControlPlane(c.f.factory).inspect_interactive_recovery(**args(record))

    async def confirm(record):
        SchedulingControlPlane(c.f.factory).confirm_interactive_recovery(
            **args(record),
            proof_sha256=physical_recovery_proof_sha256(record),
            certificate_fingerprint_sha256="a" * 64,
            cleanup_kind="physical_stop",
        )
        c.confirmed.append(record.run_id)

    c.executor._authorize = managed
    c.executor._verify_released, c.executor._confirm_recovery = released, confirm
    c.physical.revalidate_managed = case.driver.revalidate_managed

    async def wake(
        actual, *, previous, on_launch, on_preparation, on_resources, on_creation, generation
    ):
        assert previous is None and generation.resuming and generation.origin == roots[-1]
        index = len(roots)
        row = c.journal.read(actual.run_id)
        assert row.managed_resume and row.managed_predecessor_run_id == roots[-1].run_id
        token = "distinct-owned-resume-token-" + str(index)
        digest = sha256(token.encode()).hexdigest()
        preparation = generation.origin.managed_preparation
        with case.driver._adapter.bind(c.context):
            host = RetiredGenerationHostStore(
                case.store, generation.host
            ).replace_managed_host_sandbox(
                host_id=generation.host.host_id,
                user_id=generation.host.user_id,
                token=token,
                provider="agent_sandbox",
                sandbox_id=preparation.resource_name,
                token_expires_at=2_000_000_000,
            )
            assert host is not None
        await on_preparation(preparation)
        from saas.production.interactive_recovery import (
            ManagedCreationIntent,
            ManagedResourceBinding,
        )

        intent = ManagedCreationIntent(str(index) * 32, digest)
        await on_creation(intent)
        intent = replace(intent, secret_submitted=True)
        await on_creation(intent)
        secret = copy.deepcopy(scripted.secret)
        secret["metadata"].pop("deletionTimestamp", None)
        secret["metadata"]["uid"] = str(UUID(int=10 * index + 2))
        secret["metadata"]["annotations"][CREATION_ANNOTATION] = intent.nonce
        secret["data"][HOST_TOKEN_ENV_VAR] = base64.b64encode(token.encode()).decode()
        scripted.state.secret = secret
        intent = replace(intent, secret_uid=secret["metadata"]["uid"])
        await on_creation(intent)
        parent = scripted.state.parent
        template = copy.deepcopy(parent["spec"]["podTemplate"])
        annotations = template["metadata"]["annotations"]
        annotations[CREATION_ANNOTATION] = intent.nonce
        annotations.pop(INPUT_TEMPLATE_ANNOTATION)
        template_digest = _template_sha256(template)
        intent = replace(intent, workload_submitted=True, input_template_sha256=template_digest)
        await on_creation(intent)
        annotations[INPUT_TEMPLATE_ANNOTATION] = template_digest
        parent["metadata"]["annotations"][CREATION_ANNOTATION] = intent.nonce
        parent["metadata"]["generation"] += 1
        parent["metadata"]["resourceVersion"] = "woken-rv-" + str(index)
        parent["spec"].update(
            podTemplate=template, operatingMode="Running", shutdownTime="2030-01-01T00:00:00Z"
        )
        pod = copy.deepcopy(scripted.pod)
        pod["metadata"].pop("deletionTimestamp", None)
        pod["metadata"].update(
            uid=str(UUID(int=10 * index + 3)),
            resourceVersion="woken-pod-rv",
            finalizers=["saas.omnigent.ai/observe-termination"],
            annotations=copy.deepcopy(annotations),
        )
        pod["spec"] = copy.deepcopy(template["spec"])
        pod["spec"]["volumes"] = [
            {"name": "home", "persistentVolumeClaim": {"claimName": "owned-home"}}
        ]
        pod["status"] = {"phase": "Running"}
        scripted.pod.clear()
        scripted.pod.update(pod)
        scripted.state.pods = {pod["metadata"]["uid"]: scripted.pod}
        await on_resources(
            ManagedResourceBinding(
                parent["metadata"]["uid"],
                secret["metadata"]["uid"],
                _template_sha256(template),
                digest,
            )
        )
        await on_creation(
            replace(intent, pod_uid=pod["metadata"]["uid"], pod_name=pod["metadata"]["name"])
        )

        async def launch(frame, peer):
            return await on_launch(replace(frame, binding_token=str(index) * 43), peer)

        return await prepare(actual, previous=None, on_launch=launch)

    c.physical.prepare = wake
    claims = copy.deepcopy(scripted.claims)
    parent_uid = scripted.state.parent["metadata"]["uid"]
    for index in (1, 2):
        run_id = _admit(c.f, str(index + 6) * 32, text="Distinct resumed input " + str(index))
        claimed = control.claim_run(**machine)
        assert claimed.run_id == run_id
        lease = RunnerControlClientLease(
            **{
                field.name: getattr(claimed, field.name)
                for field in fields(RunnerControlClientLease)
            }
        )
        for status in ("starting", "running"):
            control.transition_run(
                **machine,
                run_id=run_id,
                lease_token=lease.lease_token,
                fence_token=lease.fence_token,
                capability_token=lease.capability_token,
                target_status=status,
            )
        assert await c.executor.execute(lease, cancellation=asyncio.Event()) == "succeeded"
        assert await c.executor.prepare_finalization(lease, result="succeeded") == "succeeded"
        control.transition_run(
            **machine,
            run_id=run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            capability_token=lease.capability_token,
            target_status="succeeded",
        )
        await c.executor.finalize(lease, result="succeeded")
        control.release_run(**machine, run_id=run_id, fence_token=lease.fence_token)
        current = c.journal.read(run_id)
        assert current.grant.run_id == run_id and current.grant != roots[-1].grant
        assert (
            current.managed_resume
            and current.managed_predecessor_stop_sha256
            == managed_suspension_proof_sha256(roots[-1])
        )
        assert current.managed_resources.workload_uid == parent_uid
        assert current.channel_value != roots[-1].channel_value
        assert current.official_runner_id != roots[-1].official_runner_id
        assert current.managed_creation.pod_uid != roots[-1].managed_creation.pod_uid
        scripted.state.parent["spec"]["shutdownTime"] = "2026-10-19T00:00:00Z"
        assert not await c.executor.retire_managed_origin(
            run_id, cutoff=0, now=1_792_500_000, retaining=True
        )
        scripted.terminal()
        for _ in range(5):
            if await c.executor.retire_managed_origin(
                run_id, cutoff=0, now=1_792_500_000, retaining=True
            ):
                break
        stopped = c.journal.read(run_id)
        assert stopped.process_stopped and stopped.managed_suspension.complete
        roots.append(stopped)
        assert scripted.claims == claims and scripted.state.parent["metadata"]["uid"] == parent_uid
    assert len(c.inputs) == len(c.gateway_calls) == 2
