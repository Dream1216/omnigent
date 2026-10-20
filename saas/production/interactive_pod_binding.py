"""Retain one owned Agent Sandbox Pod before it may expire or be replaced."""

from __future__ import annotations

from dataclasses import replace

from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import ManagedPodTermination
from saas.production.interactive_resources import (
    TERMINATION_FINALIZER,
    _creation_metadata,
    _template,
    read_managed_resources,
)


def owned_pod(pod, preparation, creation, resources):
    metadata = pod["metadata"]
    expected = {
        "apiVersion": "batch/v1"
        if preparation.provider == "kubernetes"
        else API_GROUP + "/" + API_VERSION,
        "kind": "Job" if preparation.provider == "kubernetes" else "Sandbox",
        "name": preparation.resource_name,
        "uid": resources.workload_uid,
        "controller": True,
        "blockOwnerDeletion": True,
    }
    if (
        metadata.get("ownerReferences") != [expected]
        or metadata["namespace"] != preparation.namespace
        or pod.get("kind", "Pod") != "Pod"
        or pod.get("apiVersion", "v1") != "v1"
    ):
        raise _unavailable()
    _creation_metadata(pod, creation, template=True)
    _template({"spec": {"template": pod}}, replace(preparation, provider="kubernetes"))
    identity = ManagedPodTermination(metadata["uid"], metadata["name"])
    if creation.pod_uid is not None and (identity.uid, identity.name) != (
        creation.pod_uid,
        creation.pod_name,
    ):
        raise _unavailable()
    return identity


def read_running_pod(launcher, preparation, creation, resources):
    try:
        return _read_running_pod(launcher, preparation, creation, resources)
    except Exception:  # noqa: BLE001 - SDK response bodies and credentials stay private.
        raise _unavailable() from None


def _read_running_pod(launcher, preparation, creation, resources):
    if preparation.provider != "agent_sandbox":
        raise _unavailable()
    raw = launcher._load_core().read_namespaced_pod(
        preparation.resource_name, preparation.namespace, _request_timeout=10
    )
    pod = launcher._api_client.sanitize_for_serialization(raw)
    identity = owned_pod(pod, preparation, creation, resources)
    if (
        identity.name != preparation.resource_name
        or pod["metadata"].get("deletionTimestamp")
        or pod.get("status", {}).get("phase") != "Running"
        or (
            creation.pod_uid is not None
            and TERMINATION_FINALIZER not in pod["metadata"].get("finalizers", [])
        )
    ):
        raise _unavailable()
    return pod


def protect_created_pod(owner, preparation):
    try:
        _protect_created_pod(owner, preparation)
    except Exception:  # noqa: BLE001 - failed SDK or checkpoint ACK is not a safe launch.
        raise _unavailable() from None


def _protect_created_pod(owner, preparation):
    from saas.production.interactive_managed_recovery import _tests
    from saas.production.interactive_preparation import _binding

    delegate, intent, resources = owner._delegate, owner._intent, owner._resources
    if intent is None or resources is None or owner._stopping.is_set():
        raise _unavailable()
    if _binding(delegate, preparation.resource_name, preparation.host_id) != preparation:
        raise _unavailable()
    if (
        read_managed_resources(
            delegate, preparation, host_token_sha256=intent.host_token_sha256, creation=intent
        )
        != resources
    ):
        raise _unavailable()
    pod = read_running_pod(delegate, preparation, intent, resources)
    identity = owned_pod(pod, preparation, intent, resources)
    if intent.pod_uid is None:
        owner._persist_intent(replace(intent, pod_uid=identity.uid, pod_name=identity.name))
    if owner._stopping.is_set():
        raise _unavailable()
    if _binding(delegate, preparation.resource_name, preparation.host_id) != preparation:
        raise _unavailable()
    markers = pod["metadata"].get("finalizers", [])
    if TERMINATION_FINALIZER not in markers:
        delegate._api_client.call_api(
            f"/api/v1/namespaces/{preparation.namespace}/pods/{identity.name}",
            "PATCH",
            header_params={
                "Accept": "application/json",
                "Content-Type": "application/json-patch+json",
            },
            body=[
                *_tests(pod),
                {
                    "op": "add",
                    "path": "/metadata/finalizers",
                    "value": [*markers, TERMINATION_FINALIZER],
                },
            ],
            response_types_map={200: "object", 201: "object", 202: "object"},
            auth_settings=["BearerToken"],
            _return_http_data_only=True,
            _request_timeout=10,
        )
    current = read_running_pod(delegate, preparation, owner._intent, resources)
    if TERMINATION_FINALIZER not in current["metadata"].get("finalizers", []):
        raise _unavailable()
