"""Scripted UID/RV effects and receipts; not a kubelet or production stop attestation."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace
from inspect import signature
from types import SimpleNamespace
from uuid import UUID

import pytest

from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION
from saas.production.interactive_managed_recovery import recover_managed_resources
from saas.production.interactive_resources import TERMINATION_FINALIZER
from saas.production.runner_control import RunnerControlError
from tests.saas.test_interactive_managed_resources import _case


async def _fixture(tmp_path, monkeypatch, provider="kubernetes"):
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    c = _case(tmp_path, monkeypatch, provider)
    await asyncio.to_thread(c.wrap().start_host, "owned-job", host_id="c" * 32, token=c.token)
    serializer = client.ApiClient()
    c.p.delegate._api_client.sanitize_for_serialization = serializer.sanitize_for_serialization
    parent, secret = copy.deepcopy(c.workload), copy.deepcopy(c.secret)
    for document in (parent, secret):
        document["metadata"]["resourceVersion"] = "opaque-rv-0"
        document["metadata"]["generation"] = 1
    template = parent["spec"]["template" if provider == "kubernetes" else "podTemplate"]
    pod = copy.deepcopy(template)
    pod["metadata"].update(
        name="owned-pod",
        namespace="owned-runners",
        uid=str(UUID(int=3)),
        resourceVersion="opaque-pod-rv",
        ownerReferences=[
            {
                "apiVersion": "batch/v1"
                if provider == "kubernetes"
                else API_GROUP + "/" + API_VERSION,
                "kind": "Job" if provider == "kubernetes" else "Sandbox",
                "name": "owned-job",
                "uid": parent["metadata"]["uid"],
                "controller": True,
                "blockOwnerDeletion": True,
            }
        ],
    )
    pod["status"] = {"phase": "Running"}
    state = SimpleNamespace(
        parent=parent,
        secret=secret,
        pods={pod["metadata"]["uid"]: pod},
        effects=[],
        receipts=[],
        sequence=0,
        fail_checkpoint=False,
        pod_list_type={"apiVersion": "v1", "kind": "PodList"},
    )
    state.record = SimpleNamespace(
        managed_preparation=c.p.recorded[0],
        managed_creation=c.intents[-1],
        managed_resources=c.resources[0],
        managed_termination=None,
        managed_suspension=None,
        managed_origin_run_id=None,
        official_runner_id=None,
        phase="terminal",
    )

    async def checkpoint(**changes):
        if state.fail_checkpoint:
            raise OSError("isolated-no-durable-ack")
        state.record = SimpleNamespace(**{**vars(state.record), **changes})
        if changes:
            state.receipts.append(state.record.managed_termination)
        return state.record

    def api(path, method, **values):
        signature(client.ApiClient.call_api).bind(None, path, method, **values)
        if path.endswith("/pods"):
            assert method == "GET"
            return {
                **state.pod_list_type,
                "items": copy.deepcopy(list(state.pods.values())),
                "metadata": {},
            }
        is_pod = "/pods/" in path
        document = (
            next(
                (
                    pod
                    for pod in state.pods.values()
                    if pod["metadata"]["name"] == path.rsplit("/", 1)[1]
                ),
                None,
            )
            if is_pod
            else state.secret
            if "/secrets/" in path
            else state.parent
        )
        if document is None:
            raise ApiException(status=404, reason="isolated-not-found")
        if method == "GET":
            if values["response_types_map"][200] == "V1Job":
                return serializer._ApiClient__deserialize(copy.deepcopy(document), "V1Job")
            return copy.deepcopy(document)
        receipt = state.record.managed_termination
        if receipt is None and state.record.managed_suspension is not None:
            receipt = state.record.managed_suspension.termination
        assert receipt is not None
        assert values["_request_timeout"] == 10
        body = values["body"]
        metadata = document["metadata"]
        if method == "DELETE":
            assert body["preconditions"] == {
                key: metadata[key] for key in ("uid", "resourceVersion")
            }
            assert body["propagationPolicy"] == "Foreground" and "gracePeriodSeconds" not in body
            if not is_pod and "/secrets/" not in path and not metadata.get("deletionTimestamp"):
                metadata["generation"] += 1
            metadata["deletionTimestamp"] = "2026-10-20T00:00:00Z"
            if "/secrets/" in path:
                state.secret = None
        else:
            assert (
                method == "PATCH"
                and values["header_params"]["Content-Type"] == "application/json-patch+json"
            )
            assert body[:2] == [
                {"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": metadata["resourceVersion"],
                },
            ]
            operation = body[2]
            if operation["path"].startswith("/spec/"):
                document["spec"][operation["path"].rsplit("/", 1)[1]] = operation["value"]
                metadata["generation"] += 1
                document["status"] = {
                    "conditions": [
                        {
                            "type": "Suspended",
                            "status": "True" if provider == "kubernetes" else "False",
                            "reason": "JobSuspended"
                            if provider == "kubernetes"
                            else "PodTerminating",
                            "observedGeneration": metadata["generation"],
                        }
                    ]
                }
                for child in state.pods.values():
                    child["metadata"]["deletionTimestamp"] = "2026-10-20T00:00:00Z"
            else:
                assert operation["path"] == "/metadata/finalizers"
                if is_pod and TERMINATION_FINALIZER not in operation["value"]:
                    receipts = receipt.pods
                    assert len(receipts) == 1 and receipts[0].containers_sha256
                if TERMINATION_FINALIZER in operation["value"]:
                    assert provider == "agent_sandbox" and not metadata.get("deletionTimestamp")
                    assert receipt.pods[0].uid == metadata["uid"]
                metadata["finalizers"] = operation["value"]
                if not metadata["finalizers"]:
                    if is_pod:
                        state.pods.pop(metadata["uid"])
                    else:
                        state.parent = None
        state.sequence += 1
        metadata["resourceVersion"] = "opaque-rv-" + str(state.sequence)
        state.effects.append((method, path, copy.deepcopy(body)))
        return copy.deepcopy(document)

    c.p.delegate._api_client.call_api = api

    async def step():
        return await recover_managed_resources(c.p.deployment, state.record, checkpoint)

    def terminal():
        pod["status"]["phase"] = "Failed"
        for declared, key in (
            ("containers", "containerStatuses"),
            ("initContainers", "initContainerStatuses"),
        ):
            pod["status"][key] = [
                {
                    "name": item["name"],
                    "containerID": "containerd://" + item["name"],
                    "state": {
                        "terminated": {
                            "containerID": "containerd://" + item["name"],
                            "exitCode": 137,
                            "reason": "Error",
                            "startedAt": "2026-10-19T23:00:00Z",
                            "finishedAt": "2026-10-20T00:00:01Z",
                        }
                    },
                }
                for item in pod["spec"].get(declared, [])
            ]

    return SimpleNamespace(**locals())


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_suspension_and_durable_container_receipts_precede_finalizer_release(
    tmp_path, monkeypatch, provider
):
    c = await _fixture(tmp_path, monkeypatch, provider)
    await c.step()
    if provider == "agent_sandbox":
        assert c.state.parent["spec"]["operatingMode"] == "Running"
        assert TERMINATION_FINALIZER in c.pod["metadata"]["finalizers"]
        await c.step()
    assert c.state.record.managed_termination.pods[0].containers_sha256 is None
    assert c.state.record.managed_termination.quiescence_sha256 is None
    await c.step()
    assert c.state.record.managed_termination.quiescence_sha256
    assert not c.state.record.managed_termination.complete
    assert len(c.state.effects) == (2 if provider == "agent_sandbox" else 1)
    c.terminal()
    for _ in range(6):
        await c.step()
        if c.state.record.managed_termination.complete:
            break
    receipt = c.state.record.managed_termination
    assert receipt.complete and receipt.secret_gone and receipt.pods[0].containers_sha256
    assert c.state.parent is None and c.state.secret is None and not c.state.pods


@pytest.mark.asyncio
async def test_missing_pod_after_observation_is_not_termination(tmp_path, monkeypatch):
    c = await _fixture(tmp_path, monkeypatch)
    await c.step()
    c.state.pods.clear()
    await c.step()
    assert c.state.record.managed_termination.quiescence_sha256
    assert not c.state.record.managed_termination.complete
    assert c.state.parent is not None and c.state.secret is not None
    assert not any(method == "DELETE" for method, _, _ in c.state.effects)


@pytest.mark.asyncio
async def test_agent_pod_is_uid_protected_before_suspension(tmp_path, monkeypatch):
    c = await _fixture(tmp_path, monkeypatch, "agent_sandbox")
    c.pod["metadata"].pop("finalizers", None)
    await c.step()
    assert c.state.effects[0][0] == "PATCH" and "/pods/" in c.state.effects[0][1]
    assert c.state.effects[0][2][-1]["value"] == [TERMINATION_FINALIZER]
    assert c.state.parent["spec"]["operatingMode"] == "Running"
    await c.step()
    assert c.state.parent["spec"]["operatingMode"] == "Suspended"


@pytest.mark.asyncio
async def test_raw_job_template_null_metadata_is_not_an_identity_change(tmp_path, monkeypatch):
    c = await _fixture(tmp_path, monkeypatch)
    c.state.parent["spec"]["template"]["metadata"]["creationTimestamp"] = None
    await c.step()
    assert c.state.parent["spec"]["suspend"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
async def test_pinned_real_api_client_executes_the_complete_controlled_transport(
    tmp_path, monkeypatch, provider
):
    from urllib.parse import urlsplit

    from kubernetes import client
    from kubernetes.client.rest import ApiException, RESTResponse
    from urllib3 import HTTPResponse

    c = await _fixture(tmp_path, monkeypatch, provider)
    configuration = client.Configuration()
    for name in ("host", "ssl_ca_cert", "verify_ssl", "assert_hostname", "tls_server_name"):
        setattr(configuration, name, getattr(c.c.p.configuration, name))
    actual = client.ApiClient(configuration)

    def transport(method, url, **values):
        try:
            document = c.api(
                urlsplit(url).path,
                method,
                body=values.get("body"),
                header_params=values.get("headers"),
                query_params=values.get("query_params"),
                response_types_map={200: "object"},
                _request_timeout=values["_request_timeout"],
            )
        except ApiException as error:
            error.body = b'{"reason":"NotFound"}'
            raise
        return RESTResponse(
            HTTPResponse(
                body=json.dumps(document).encode(),
                status=200,
                headers={"Content-Type": "application/json"},
                preload_content=True,
            )
        )

    monkeypatch.setattr(actual, "request", transport)
    c.c.p.delegate._api_client = actual
    try:
        await c.step()
        if provider == "agent_sandbox":
            await c.step()
        await c.step()
        c.terminal()
        for _ in range(6):
            await c.step()
            if c.state.record.managed_termination.complete:
                break
        assert c.state.record.managed_termination.complete
        assert c.state.parent is None and c.state.secret is None and not c.state.pods
    finally:
        actual.close()


@pytest.mark.asyncio
async def test_checkpoint_failure_never_mutates_resources(tmp_path, monkeypatch):
    c = await _fixture(tmp_path, monkeypatch)
    c.state.fail_checkpoint = True
    with pytest.raises(RunnerControlError):
        await c.step()
    assert not c.state.effects


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "key", "value"),
    [
        ("list", "kind", "List"),
        ("list", "apiVersion", "batch/v1"),
        ("pod", "kind", "Job"),
        ("pod", "apiVersion", "batch/v1"),
    ],
)
async def test_pod_list_envelope_and_explicit_item_types_remain_required(
    tmp_path, monkeypatch, target, key, value
):
    c = await _fixture(tmp_path, monkeypatch)
    document = c.state.pod_list_type if target == "list" else c.pod
    document[key] = value
    with pytest.raises(RunnerControlError):
        await c.step()
    assert not c.state.effects
    assert c.state.record.managed_termination.pods == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox"])
@pytest.mark.parametrize("drift", ["extra_generation", "resumed", "missing_quiescence"])
async def test_deleting_parent_requires_the_exact_predelete_quiescence(
    tmp_path, monkeypatch, provider, drift
):
    c = await _fixture(tmp_path, monkeypatch, provider)
    await c.step()
    if provider == "agent_sandbox":
        await c.step()
    await c.step()
    c.terminal()
    await c.step()
    parent = c.state.parent
    assert parent["metadata"]["generation"] == 3 and parent["metadata"]["deletionTimestamp"]
    assert not c.state.pods and c.state.record.managed_termination.quiescence_sha256
    if drift == "extra_generation":
        parent["metadata"]["generation"] += 1
    elif drift == "resumed":
        parent["spec"]["suspend" if provider == "kubernetes" else "operatingMode"] = (
            False if provider == "kubernetes" else "Running"
        )
        parent["metadata"]["generation"] += 1
    else:
        c.state.record.managed_termination = replace(
            c.state.record.managed_termination, quiescence_sha256=None
        )
    before = c.state.effects.copy()
    if drift == "extra_generation":
        with pytest.raises(RunnerControlError):
            await c.step()
    else:
        await c.step()
    assert c.state.effects == before
    assert TERMINATION_FINALIZER in parent["metadata"]["finalizers"]
    assert c.state.secret is not None and not c.state.record.managed_termination.complete


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift", ["workload_uid", "pod_owner", "missing_finalizer", "unknown_state", "last_state"]
)
async def test_foreign_or_unproven_runtime_cannot_release_protection(tmp_path, monkeypatch, drift):
    c = await _fixture(tmp_path, monkeypatch)
    if drift == "workload_uid":
        c.state.parent["metadata"]["uid"] = str(UUID(int=4))
    elif drift == "pod_owner":
        c.pod["metadata"]["ownerReferences"][0]["controller"] = False
    elif drift == "missing_finalizer":
        c.pod["metadata"]["finalizers"] = []
    else:
        await c.step()
        await c.step()
        c.terminal()
        status = c.pod["status"]["containerStatuses"][0]
        if drift == "unknown_state":
            status["state"]["terminated"]["reason"] = "ContainerStatusUnknown"
        else:
            status["lastState"] = status["state"]
            status["state"] = {"running": {}}
        await c.step()
        assert not c.state.record.managed_termination.complete
        assert TERMINATION_FINALIZER in c.pod["metadata"]["finalizers"]
        return
    with pytest.raises(RunnerControlError):
        await c.step()
    assert not c.state.effects
