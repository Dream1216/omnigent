"""UID-fenced cleanup with kubelet container facts retained until durable ACK."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import replace
from datetime import datetime
from hashlib import sha256

from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION, SANDBOX_PLURAL
from omnigent.onboarding.sandboxes.kubernetes import _token_secret_name
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import (
    ManagedPodTermination,
    ManagedResourceBinding,
    ManagedTerminationReceipt,
)
from saas.production.interactive_resources import (
    TERMINATION_FINALIZER,
    _creation_metadata,
    _metadata,
    _secret_uid,
    _template,
    _template_sha256,
)

_LOGGER = logging.getLogger(__name__)


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _tests(document):
    metadata = document["metadata"]
    if not isinstance(metadata["resourceVersion"], str) or not metadata["resourceVersion"]:
        raise _unavailable()
    return [
        {"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
    ]


def _terminal_digest(pod):
    """A missing container ID, lastState, lost node or a terminal phase alone is insufficient."""
    status, spec = pod.get("status", {}), pod["spec"]
    if not pod["metadata"].get("deletionTimestamp"):
        return None
    if status.get("reason") in {"NodeLost", "ContainerStatusUnknown"}:
        return None
    if status.get("phase") not in {"Succeeded", "Failed"}:
        return None
    observed = []
    for declared_key, status_key in (
        ("initContainers", "initContainerStatuses"),
        ("containers", "containerStatuses"),
        ("ephemeralContainers", "ephemeralContainerStatuses"),
    ):
        declared, actual = spec.get(declared_key, []), status.get(status_key, [])
        names = [container["name"] for container in declared]
        indexed = {container["name"]: container for container in actual}
        if (
            len(names) != len(set(names))
            or len(indexed) != len(actual)
            or set(indexed) != set(names)
        ):
            return None
        for name in names:
            value = indexed[name]
            state = value.get("state", {})
            if set(state) != {"terminated"}:
                return None
            ended = state["terminated"]
            if (
                not value.get("containerID")
                or not ended.get("containerID")
                or value["containerID"] != ended["containerID"]
                or type(ended.get("exitCode")) is not int
                or ended.get("reason") in {"ContainerStatusUnknown", "NodeLost"}
            ):
                return None
            try:
                finish = datetime.fromisoformat(ended["finishedAt"].replace("Z", "+00:00"))
                start = datetime.fromisoformat(ended["startedAt"].replace("Z", "+00:00"))
                if (
                    finish.utcoffset() is None
                    or start.utcoffset() is None
                    or start.year < 2000
                    or finish < start
                ):
                    return None
            except (KeyError, TypeError, ValueError, AttributeError):
                return None
            observed.append(
                {
                    "family": declared_key,
                    "name": name,
                    **{
                        key: ended.get(key)
                        for key in (
                            "containerID",
                            "exitCode",
                            "signal",
                            "reason",
                            "startedAt",
                            "finishedAt",
                        )
                    },
                }
            )
    if not observed:
        return None
    return _digest(observed)


class _Recovery:
    def __init__(self, launcher, record, checkpoint, loop):
        self.launcher, self.record = launcher, record
        self.checkpoint, self.loop = checkpoint, loop
        self.stage = "binding"
        self.http_status: int | None = None
        self.preparation, self.creation = record.managed_preparation, record.managed_creation
        self.namespace = self.preparation.namespace
        self.parent_path = (
            f"/apis/batch/v1/namespaces/{self.namespace}/jobs/"
            if self.preparation.provider == "kubernetes"
            else f"/apis/{API_GROUP}/{API_VERSION}/namespaces/{self.namespace}/{SANDBOX_PLURAL}/"
        ) + self.preparation.resource_name
        self.secret_path = f"/api/v1/namespaces/{self.namespace}/secrets/" + _token_secret_name(
            self.preparation.resource_name
        )

    def persist(self, **changes):
        future = asyncio.run_coroutine_threadsafe(self.checkpoint(**changes), self.loop)
        try:
            self.record = future.result(timeout=10)
        except TimeoutError:
            future.cancel()
            raise _unavailable() from None
        return self.record

    def api(self, path, method="GET", *, body=None, query=None):
        from kubernetes.client.rest import ApiException

        from saas.production.interactive_preparation import _binding

        kind = (
            "parent"
            if path == self.parent_path
            else "secret"
            if path == self.secret_path
            else "pods"
        )
        self.stage, self.http_status = method + ":" + kind, None

        if method != "GET":
            self.persist()
        if (
            _binding(self.launcher, self.preparation.resource_name, self.preparation.host_id)
            != self.preparation
        ):
            raise _unavailable()
        try:
            response_type = (
                "V1Job"
                if path == self.parent_path
                and method == "GET"
                and self.preparation.provider == "kubernetes"
                else "object"
            )
            result = self.launcher._api_client.call_api(
                path,
                method,
                query_params=query or [],
                header_params={
                    "Accept": "application/json",
                    "Content-Type": (
                        "application/json-patch+json" if method == "PATCH" else "application/json"
                    ),
                },
                body=body,
                response_types_map={200: response_type, 201: response_type, 202: response_type},
                auth_settings=["BearerToken"],
                _return_http_data_only=True,
                _request_timeout=10,
            )
            return (
                self.launcher._api_client.sanitize_for_serialization(result)
                if response_type == "V1Job"
                else result
            )
        except ApiException as error:
            self.http_status = error.status if type(error.status) is int else None
            if method == "GET" and error.status == 404:
                return None
            raise _unavailable() from None

    def delete(self, path, document):
        _tests(document)
        return self.api(
            path,
            "DELETE",
            body={
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "propagationPolicy": "Foreground",
                "preconditions": {
                    key: document["metadata"][key] for key in ("uid", "resourceVersion")
                },
            },
        )

    def release_finalizer(self, path, document):
        finalizers = document["metadata"].get("finalizers", [])
        if TERMINATION_FINALIZER in finalizers:
            self.api(
                path,
                "PATCH",
                body=[
                    *_tests(document),
                    {
                        "op": "replace",
                        "path": "/metadata/finalizers",
                        "value": [value for value in finalizers if value != TERMINATION_FINALIZER],
                    },
                ],
            )

    def parent(self):
        document = self.api(self.parent_path)
        if document is None:
            return None
        kind = "Job" if self.preparation.provider == "kubernetes" else "Sandbox"
        uid = _metadata(
            document,
            namespace=self.namespace,
            name=self.preparation.resource_name,
            kind=kind,
            allow_deleting=True,
        )
        template = _template(document, self.preparation)
        _creation_metadata(document, self.creation)
        _creation_metadata(template, self.creation, template=True)
        if self.preparation.provider == "kubernetes" and TERMINATION_FINALIZER not in template[
            "metadata"
        ].get("finalizers", []):
            raise _unavailable()
        if (
            TERMINATION_FINALIZER not in document["metadata"].get("finalizers", [])
            and self.record.managed_termination.quiescence_sha256 is None
        ):
            raise _unavailable()
        resources = ManagedResourceBinding(
            uid,
            self.creation.secret_uid,
            _template_sha256(template),
            self.creation.host_token_sha256,
        )
        if self.record.managed_resources is None:
            self.persist(managed_resources=resources)
        elif resources != self.record.managed_resources:
            raise _unavailable()
        return document

    def pods(self):
        indexed, cursor = {}, None
        parent = self.record.managed_resources
        if parent is None:
            raise _unavailable()
        for _ in range(64):
            page = self.api(
                f"/api/v1/namespaces/{self.namespace}/pods",
                query=[("limit", 100)] + ([("continue", cursor)] if cursor else []),
            )
            if page is None or page.get("apiVersion") != "v1" or page.get("kind") != "PodList":
                raise _unavailable()
            for pod in page["items"]:
                refs = pod["metadata"].get("ownerReferences", [])
                if not any(ref.get("uid") == parent.workload_uid for ref in refs):
                    continue
                expected = {
                    "apiVersion": "batch/v1"
                    if self.preparation.provider == "kubernetes"
                    else API_GROUP + "/" + API_VERSION,
                    "kind": "Job" if self.preparation.provider == "kubernetes" else "Sandbox",
                    "name": self.preparation.resource_name,
                    "uid": parent.workload_uid,
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
                if (
                    len(refs) != 1
                    or refs[0] != expected
                    or pod["metadata"]["namespace"] != self.namespace
                    or pod.get("kind", "Pod") != "Pod"
                    or pod.get("apiVersion", "v1") != "v1"
                ):
                    raise _unavailable()
                _creation_metadata(pod, self.creation, template=True)
                _template(
                    {"spec": {"template": pod}}, replace(self.preparation, provider="kubernetes")
                )
                identity = ManagedPodTermination(pod["metadata"]["uid"], pod["metadata"]["name"])
                if identity.uid in indexed or len(indexed) >= 64:
                    raise _unavailable()
                indexed[identity.uid] = pod
            cursor = page.get("metadata", {}).get("continue")
            if not cursor:
                return indexed
        raise _unavailable()

    def suspend(self, parent):
        kubernetes = self.preparation.provider == "kubernetes"
        desired = (
            parent["spec"].get("suspend") is True
            if kubernetes
            else parent["spec"].get("operatingMode") == "Suspended"
        )
        if not desired:
            if parent["metadata"].get("deletionTimestamp"):
                return False
            self.api(
                self.parent_path,
                "PATCH",
                body=[
                    *_tests(parent),
                    {
                        "op": "add",
                        "path": "/spec/suspend" if kubernetes else "/spec/operatingMode",
                        "value": True if kubernetes else "Suspended",
                    },
                ],
            )
            return False
        metadata = parent["metadata"]
        generation = metadata["generation"]
        if type(generation) is not int or generation < 1:
            raise _unavailable()
        deleting = metadata.get("deletionTimestamp") is not None
        receipt = self.record.managed_termination
        digest = _digest(
            {
                "uid": metadata["uid"],
                # The API server increments generation once when marking deletion.
                "generation": generation - int(deleting),
                "provider": self.preparation.provider,
                "suspended": True,
            }
        )
        if deleting:
            if receipt.quiescence_sha256 is None:
                return False
            if receipt.quiescence_sha256 != digest:
                raise _unavailable()
            return True
        conditions = parent.get("status", {}).get("conditions", [])
        if kubernetes:
            ready = any(
                row.get("type") == "Suspended"
                and row.get("status") == "True"
                and row.get("reason") == "JobSuspended"
                for row in conditions
            )
        else:
            ready = any(
                row.get("type") == "Suspended"
                and row.get("observedGeneration") == parent["metadata"]["generation"]
                and (
                    (row.get("status"), row.get("reason"))
                    in {("False", "PodTerminating"), ("True", "PodTerminated")}
                )
                for row in conditions
            )
        if not ready:
            return False
        if receipt.quiescence_sha256 is None:
            self.persist(managed_termination=replace(receipt, quiescence_sha256=digest))
        elif receipt.quiescence_sha256 != digest:
            raise _unavailable()
        return True

    def step(self):
        receipt = self.record.managed_termination
        if receipt is None:
            self.persist(
                managed_termination=ManagedTerminationReceipt(secret_uid=self.creation.secret_uid)
            )
        if self.record.managed_termination.complete:
            return self.record
        if self.creation.workload_submitted:
            parent = self.parent()
            if parent is None and self.record.managed_termination.quiescence_sha256 is None:
                return self.record
            pods = self.pods()
            known = {row.uid: row for row in self.record.managed_termination.pods}
            for uid, pod in pods.items():
                if uid not in known:
                    if (
                        self.preparation.provider == "kubernetes"
                        and TERMINATION_FINALIZER not in pod["metadata"].get("finalizers", [])
                    ):
                        raise _unavailable()
                    known[uid] = ManagedPodTermination(uid, pod["metadata"]["name"])
            self.persist(
                managed_termination=replace(
                    self.record.managed_termination,
                    pods=tuple(known[key] for key in sorted(known)),
                )
            )
            for uid, pod in pods.items():
                finalizers = pod["metadata"].get("finalizers", [])
                if (
                    TERMINATION_FINALIZER not in finalizers
                    and known[uid].containers_sha256 is None
                ):
                    if self.preparation.provider != "agent_sandbox" or pod["metadata"].get(
                        "deletionTimestamp"
                    ):
                        raise _unavailable()
                    self.api(
                        f"/api/v1/namespaces/{self.namespace}/pods/" + known[uid].name,
                        "PATCH",
                        body=[
                            *_tests(pod),
                            {
                                "op": "add",
                                "path": "/metadata/finalizers",
                                "value": [*finalizers, TERMINATION_FINALIZER],
                            },
                        ],
                    )
                    return self.record
            if self.preparation.provider == "agent_sandbox" and not known:
                return self.record
            if parent is not None and not self.suspend(parent):
                return self.record
            for uid, pod in pods.items():
                if known[uid].name != pod["metadata"]["name"]:
                    raise _unavailable()
                path = f"/api/v1/namespaces/{self.namespace}/pods/" + known[uid].name
                digest = _terminal_digest(pod)
                if known[uid].containers_sha256 is None:
                    if not pod["metadata"].get("deletionTimestamp"):
                        self.delete(path, pod)
                        continue
                    if digest is None:
                        continue
                    known[uid] = replace(known[uid], containers_sha256=digest)
                    self.persist(
                        managed_termination=replace(
                            self.record.managed_termination,
                            pods=tuple(known[key] for key in sorted(known)),
                        )
                    )
                elif digest != known[uid].containers_sha256:
                    raise _unavailable()
                self.release_finalizer(path, pod)
            if any(row.containers_sha256 is None for row in known.values()) or self.pods():
                return self.record
            if self.preparation.provider == "agent_sandbox" and not known:
                return self.record
            if parent is not None:
                if not parent["metadata"].get("deletionTimestamp"):
                    self.delete(self.parent_path, parent)
                    return self.record
                self.release_finalizer(self.parent_path, parent)
                return self.record
        if self.creation.secret_submitted and not self.record.managed_termination.secret_gone:
            secret = self.api(self.secret_path)
            receipt = self.record.managed_termination
            if secret is None:
                if receipt.secret_uid is None:
                    return self.record
                self.persist(managed_termination=replace(receipt, secret_gone=True))
            else:
                uid = _secret_uid(
                    secret, self.preparation, self.creation.host_token_sha256, allow_deleting=True
                )
                _creation_metadata(secret, self.creation)
                if receipt.secret_uid is None:
                    self.persist(managed_termination=replace(receipt, secret_uid=uid))
                elif uid != receipt.secret_uid:
                    raise _unavailable()
                self.delete(self.secret_path, secret)
                return self.record
        self.persist(managed_termination=replace(self.record.managed_termination, complete=True))
        return self.record


async def recover_managed_resources(deployment, record, checkpoint):
    from saas.production.interactive_preparation import _binding, _direct_launcher

    preparation = record.managed_preparation
    if (
        preparation is None
        or record.managed_creation is None
        or record.official_runner_id is not None
    ):
        raise _unavailable()
    delegate = _direct_launcher(
        deployment.for_provider(preparation.provider), preparation.provider
    )
    loop = asyncio.get_running_loop()

    def run():
        recovery = _Recovery(delegate, record, checkpoint, loop)
        try:
            if _binding(delegate, preparation.resource_name, preparation.host_id) != preparation:
                raise _unavailable()
            return recovery.step()
        except Exception as error:  # noqa: BLE001 - SDK responses and private credentials stay private.
            _LOGGER.warning(
                "Managed recovery pending at %s (%s; HTTP %s)",
                recovery.stage,
                type(error).__name__,
                recovery.http_status,
            )
            raise _unavailable() from None
        finally:
            delegate._close_clients()

    return await asyncio.to_thread(run)
