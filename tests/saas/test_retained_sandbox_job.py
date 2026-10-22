from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from saas.production.retained_sandbox_job import plan_retained_job_image_repair

OLD = "ghcr.io/dream1216/omnigent-saas-host@sha256:" + "1" * 64
NEW = "ghcr.io/dream1216/omnigent-saas-host@sha256:" + "2" * 64
NOW = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)


def fixture():
    uid = str(uuid4())
    labels = {"batch.kubernetes.io/controller-uid": uid}
    spec = {
        "containers": [
            {
                "name": "host",
                "image": OLD,
                "volumeMounts": [{"name": "home", "mountPath": "/home/omnigent"}],
            }
        ],
        "initContainers": [{"name": "workspace-prep", "image": OLD}],
        "volumes": [{"name": "home", "emptyDir": {}}],
        "restartPolicy": "OnFailure",
    }
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "omnigent-managed-own-test",
            "namespace": "test",
            "uid": uid,
            "resourceVersion": "17",
            "labels": {
                "app.kubernetes.io/managed-by": "omnigent",
                "omnigent.ai/role": "sandbox-host",
            },
        },
        "spec": {
            "selector": {"matchLabels": labels},
            "parallelism": 1,
            "completions": 1,
            "activeDeadlineSeconds": 604800,
            "template": {"metadata": {"labels": labels}, "spec": deepcopy(spec)},
        },
        "status": {"active": 1, "startTime": "2026-10-15T12:00:00Z"},
    }
    pod = {
        "metadata": {
            "name": "own-test-child",
            "namespace": "test",
            "uid": str(uuid4()),
            "labels": labels,
            "ownerReferences": [
                {"kind": "Job", "name": job["metadata"]["name"], "uid": uid, "controller": True}
            ],
        },
        "spec": spec,
        "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]},
    }
    return job, [pod]


def plan(job, pods, **kwargs):
    return plan_retained_job_image_repair(
        job,
        pods,
        namespace="test",
        expected_job_uid=job["metadata"]["uid"],
        old_image=OLD,
        image=NEW,
        now=kwargs.get("now", NOW),
    )


def test_plan_keeps_storage_identity_and_absolute_expiry_without_mutating_inputs():
    job, pods = fixture()
    original = deepcopy((job, pods))
    value = plan(job, pods)
    assert (job, pods) == original
    replacement = value["replacement"]
    assert replacement["spec"]["selector"] == job["spec"]["selector"]
    assert replacement["spec"]["manualSelector"] is True
    assert replacement["spec"]["activeDeadlineSeconds"] == 10800
    assert value["expires_at"] == "2026-10-22T12:00:00+00:00"
    assert value["delete_options"]["propagationPolicy"] == "Orphan"
    assert value["delete_options"]["preconditions"] == {
        "uid": job["metadata"]["uid"],
        "resourceVersion": "17",
    }
    assert value["running_pod_uid"] == pods[0]["metadata"]["uid"]
    actual = deepcopy(replacement["spec"])
    actual.pop("manualSelector")
    actual["activeDeadlineSeconds"] = job["spec"]["activeDeadlineSeconds"]
    for field in ("containers", "initContainers"):
        for c in actual["template"]["spec"][field]:
            assert c["image"] == NEW
            c["image"] = OLD
    assert actual == job["spec"]
    assert value["pod_deletion_allowed"] is value["pvc_deletion_allowed"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "uid",
        "namespace",
        "selector",
        "parallelism",
        "suspended",
        "completed",
        "pod_owner",
        "foreign_pod",
        "pod_deleting",
        "pod_pending",
        "pod_succeeded",
        "not_ready",
        "extra_running",
        "home",
        "image",
        "template_volume",
    ],
)
def test_rejects_unsafe_or_raced_job_and_pod_state(mutation):
    job, pods = fixture()
    if mutation == "uid":
        job["spec"]["selector"]["matchLabels"]["batch.kubernetes.io/controller-uid"] = str(uuid4())
    elif mutation == "namespace":
        job["metadata"]["namespace"] = "foreign"
    elif mutation == "selector":
        job["spec"]["selector"] = {"matchLabels": {"app": "shared"}}
    elif mutation == "parallelism":
        job["spec"]["parallelism"] = 2
    elif mutation == "suspended":
        job["spec"]["suspend"] = True
    elif mutation == "completed":
        job["status"]["conditions"] = [{"type": "Complete", "status": "True"}]
    elif mutation == "pod_owner":
        pods[0]["metadata"]["ownerReferences"][0]["uid"] = str(uuid4())
    elif mutation == "foreign_pod":
        pods[0]["metadata"]["labels"] = {"app": "shared"}
    elif mutation == "pod_deleting":
        pods[0]["metadata"]["deletionTimestamp"] = "now"
    elif mutation == "pod_pending":
        pods[0]["status"]["phase"] = "Pending"
    elif mutation == "pod_succeeded":
        pods[0]["status"]["phase"] = "Succeeded"
    elif mutation == "not_ready":
        pods[0]["status"]["conditions"] = []
    elif mutation == "extra_running":
        pods.append(deepcopy(pods[0]))
    elif mutation == "home":
        pods[0]["spec"]["volumes"] = []
    elif mutation == "image":
        job["spec"]["template"]["spec"]["containers"][0]["image"] = "unqualified:latest"
    elif mutation == "template_volume":
        job["spec"]["template"]["spec"]["volumes"] = [
            {"name": "home", "emptyDir": {"sizeLimit": "1Gi"}}
        ]
    with pytest.raises(ValueError):
        plan(job, pods)


def test_preserves_pvc_and_accepts_already_updated_running_container():
    job, pods = fixture()
    volume = [{"name": "home", "persistentVolumeClaim": {"claimName": "owned-home"}}]
    job["spec"]["template"]["spec"]["volumes"] = deepcopy(volume)
    pods[0]["spec"]["volumes"] = volume
    pods[0]["spec"]["containers"][0]["image"] = NEW
    assert plan(job, pods)["replacement"]["spec"]["template"]["spec"]["volumes"] == volume


def test_refuses_expiry_inside_handoff_safety_window():
    job, pods = fixture()
    with pytest.raises(ValueError, match="expiry"):
        plan(job, pods, now=datetime(2026, 10, 22, 11, 55, tzinfo=timezone.utc))
