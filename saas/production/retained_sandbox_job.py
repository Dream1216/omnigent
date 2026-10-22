"""Plan a bounded Job controller replacement without deleting its retained Pods."""

from __future__ import annotations

import math
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

_CONTROLLER_LABEL = "batch.kubernetes.io/controller-uid"
_IMAGE = re.compile(r"ghcr\.io/dream1216/omnigent-saas-host@sha256:[0-9a-f]{64}\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def plan_retained_job_image_repair(
    job: dict[str, Any],
    pods: list[dict[str, Any]],
    *,
    namespace: str,
    expected_job_uid: str,
    old_image: str,
    image: str,
    now: datetime,
) -> dict[str, Any]:
    """Keep the original selector, Pod identities, storage and absolute expiry."""
    _require(now.tzinfo is not None, "an aware operator clock is required")
    _require(
        bool(_IMAGE.fullmatch(old_image) and _IMAGE.fullmatch(image)),
        "pinned Host images required",
    )
    _require(old_image != image, "distinct old and admitted images required")
    UUID(expected_job_uid)
    original = deepcopy(job)
    metadata, spec = original["metadata"], original["spec"]
    name = metadata["name"]
    _require(
        original.get("apiVersion") == "batch/v1"
        and original.get("kind") == "Job"
        and metadata.get("namespace") == namespace
        and metadata.get("uid") == expected_job_uid
        and bool(metadata.get("resourceVersion"))
        and name.startswith("omnigent-managed-")
        and not metadata.get("deletionTimestamp")
        and not metadata.get("ownerReferences")
        and metadata.get("labels", {}).get("app.kubernetes.io/managed-by") == "omnigent"
        and metadata.get("labels", {}).get("omnigent.ai/role") == "sandbox-host",
        "managed Job identity or ownership changed",
    )
    _require(
        spec.get("parallelism", 1) == spec.get("completions", 1) == 1
        and not spec.get("suspend", False)
        and not spec.get("managedBy")
        and not spec.get("manualSelector", False)
        and spec.get("selector") == {"matchLabels": {_CONTROLLER_LABEL: expected_job_uid}},
        "only an original single-Pod Job with its unique generated selector is repairable",
    )
    status = original.get("status", {})
    _require(
        status.get("active") == 1
        and not status.get("terminating", 0)
        and not any(
            c.get("status") == "True"
            for c in status.get("conditions", [])
            if c.get("type") in ("Complete", "Failed", "FailureTarget", "SuccessCriteriaMet")
        ),
        "Job is not stably active",
    )
    _require(bool(pods), "retained Pods are required")
    active = []
    for pod in pods:
        pm = pod["metadata"]
        owners = [o for o in pm.get("ownerReferences", []) if o.get("controller")]
        _require(
            pm.get("namespace") == namespace
            and pm.get("labels", {}).get(_CONTROLLER_LABEL) == expected_job_uid
            and not pm.get("deletionTimestamp")
            and len(owners) == 1
            and owners[0].get("kind") == "Job"
            and owners[0].get("name") == name
            and owners[0].get("uid") == expected_job_uid,
            "selector overlaps a foreign, deleting or unowned Pod",
        )
        phase = pod.get("status", {}).get("phase")
        _require(phase in ("Running", "Failed"), "unexpected pending or completed child Pod")
        if phase == "Running":
            active.append(pod)
    _require(len(active) == 1, "exactly one retained Running Pod is required")
    running = active[0]
    _require(
        any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in running["status"].get("conditions", [])
        ),
        "retained Pod is not ready",
    )
    pod_spec = running["spec"]
    hosts = [c for c in pod_spec["containers"] if c["name"] == "host"]
    home = [v for v in pod_spec["volumes"] if v["name"] == "home"]
    _require(
        len(hosts) == len(home) == 1
        and hosts[0]["image"] in (old_image, image)
        and ("emptyDir" in home[0] or "persistentVolumeClaim" in home[0])
        and any(
            m["name"] == "home" and m["mountPath"] == "/home/omnigent"
            for m in hosts[0].get("volumeMounts", [])
        ),
        "retained Host or HOME identity changed",
    )
    template = spec["template"]["spec"]
    _require(
        template.get("volumes") == pod_spec.get("volumes"), "HOME or projected volumes differ"
    )
    changes = 0
    for field in ("containers", "initContainers"):
        for container in template.get(field, []):
            _require(container["image"] in (old_image, image), "unexpected template image")
            if container["image"] != image:
                container["image"] = image
                changes += 1
    _require(changes > 0, "Job template already uses the admitted image")
    spec["manualSelector"] = True
    expires_at = None
    if "activeDeadlineSeconds" in spec:
        seconds = spec["activeDeadlineSeconds"]
        _require(
            type(seconds) is int and seconds > 0 and bool(status.get("startTime")),
            "finite Job lifetime is invalid",
        )
        started = datetime.fromisoformat(status["startTime"].replace("Z", "+00:00"))
        expiry = started + timedelta(seconds=seconds)
        remaining = math.floor((expiry - now).total_seconds())
        _require(remaining >= 600, "Job expiry is too close for a safe controller handoff")
        spec["activeDeadlineSeconds"] = remaining
        expires_at = expiry.astimezone(timezone.utc).isoformat()
    annotations = deepcopy(metadata.get("annotations", {}))
    annotations.update(
        {
            "omnigent.io/retained-job-source-uid": expected_job_uid,
            "omnigent.io/retained-job-image": image,
            "omnigent.io/retained-job-planned-at": now.astimezone(timezone.utc).isoformat(),
        }
    )
    if expires_at is not None:
        annotations["omnigent.io/retained-job-original-expiry"] = expires_at
    replacement = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": deepcopy(metadata["labels"]),
            "annotations": annotations,
        },
        "spec": spec,
    }
    return {
        "schema_version": 1,
        "job": name,
        "namespace": namespace,
        "old_job_uid": expected_job_uid,
        "retained_pod_uids": sorted(p["metadata"]["uid"] for p in pods),
        "running_pod_uid": running["metadata"]["uid"],
        "image": image,
        "expires_at": expires_at,
        "delete_options": {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "propagationPolicy": "Orphan",
            "preconditions": {
                "uid": expected_job_uid,
                "resourceVersion": metadata["resourceVersion"],
            },
        },
        "replacement": replacement,
        "pod_deletion_allowed": False,
        "pvc_deletion_allowed": False,
    }
