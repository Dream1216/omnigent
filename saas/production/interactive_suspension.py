"""Retained workspace identities observed through the existing UID-fenced engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import ManagedVolumeBinding


def _claims(recovery, names):
    preparation = recovery.preparation
    parent = recovery.record.managed_resources
    bindings = []
    if parent is None or len(names) > 8 or len(set(names)) != len(names):
        raise _unavailable()
    for name in sorted(names):
        # Validate the path component before issuing any request.
        ManagedVolumeBinding(name, parent.workload_uid)
        document = recovery.api(
            f"/api/v1/namespaces/{preparation.namespace}/persistentvolumeclaims/{name}"
        )
        if document is None:
            raise _unavailable()
        metadata = document["metadata"]
        expected = {
            "apiVersion": API_GROUP + "/" + API_VERSION,
            "kind": "Sandbox",
            "name": preparation.resource_name,
            "uid": parent.workload_uid,
        }
        if (
            document.get("apiVersion") != "v1"
            or document.get("kind") != "PersistentVolumeClaim"
            or metadata.get("name") != name
            or metadata.get("namespace") != preparation.namespace
            or metadata.get("deletionTimestamp")
            or not any(
                all(ref.get(key) == value for key, value in expected.items())
                for ref in metadata.get("ownerReferences", [])
            )
            or document.get("status", {}).get("phase") != "Bound"
            or document.get("spec", {}).get("accessModes") != ["ReadWriteOnce"]
        ):
            raise _unavailable()
        bindings.append(ManagedVolumeBinding(name, metadata["uid"]))
    return tuple(bindings)


def observe_retained_workspace(recovery, parent, pods):
    from saas.production.interactive_managed_recovery import _digest

    if (
        parent is None
        or parent["metadata"].get("deletionTimestamp")
        or parent["spec"].get("shutdownPolicy") != "Retain"
    ):
        raise _unavailable()
    receipt = recovery.record.managed_suspension
    templates = parent["spec"].get("volumeClaimTemplates", [])
    digest = _digest(templates)
    if receipt.volume_templates_sha256 is None:
        if len(pods) != 1:
            raise _unavailable()
        (pod,) = pods.values()
        expected = {item["metadata"]["name"] for item in templates}
        volumes = [
            volume
            for volume in pod["spec"].get("volumes", [])
            if "persistentVolumeClaim" in volume
        ]
        if (
            len(expected) != len(templates)
            or {volume["name"] for volume in volumes} != expected
            or len(volumes) != len(expected)
        ):
            raise _unavailable()
        claims = _claims(
            recovery, [volume["persistentVolumeClaim"]["claimName"] for volume in volumes]
        )
        recovery.persist(
            managed_suspension=replace(receipt, volume_templates_sha256=digest, volumes=claims)
        )
    elif (
        digest != receipt.volume_templates_sha256
        or _claims(recovery, [volume.name for volume in receipt.volumes]) != receipt.volumes
    ):
        raise _unavailable()


def read_suspended_resources(launcher, record, *, new_creation=None):
    """Read-only revalidation immediately before a scoped same-parent wake."""
    from saas.production.interactive_managed_recovery import _digest, _Recovery
    from saas.production.interactive_preparation import _binding
    from saas.production.interactive_recovery import managed_suspension_proof_sha256
    from saas.production.interactive_resources import _creation_metadata, _secret_uid

    managed_suspension_proof_sha256(record)
    preparation = record.managed_preparation
    if _binding(launcher, preparation.resource_name, preparation.host_id) != preparation:
        raise _unavailable()
    recovery = _Recovery(launcher, record, None, None, retaining=True)
    parent = recovery.parent()
    if (
        parent is None
        or parent["spec"].get("operatingMode") != "Suspended"
        or parent["metadata"].get("deletionTimestamp")
    ):
        raise _unavailable()
    generation = parent["metadata"]["generation"]
    if (
        type(generation) is not int
        or generation < 1
        or _digest(
            {
                "uid": parent["metadata"]["uid"],
                "generation": generation,
                "provider": preparation.provider,
                "suspended": True,
            }
        )
        != record.managed_suspension.termination.quiescence_sha256
    ):
        raise _unavailable()
    pods = recovery.pods()
    if pods:
        raise _unavailable()
    observe_retained_workspace(recovery, parent, pods)
    secret = recovery.api(recovery.secret_path)
    if new_creation is None:
        if secret is not None:
            raise _unavailable()
    else:
        if (
            secret is None
            or _secret_uid(secret, preparation, new_creation.host_token_sha256)
            != new_creation.secret_uid
        ):
            raise _unavailable()
        _creation_metadata(secret, new_creation)
    return parent


def suspension_due(deployment, record, *, now):
    from saas.production.interactive_managed_recovery import _Recovery
    from saas.production.interactive_preparation import _binding, _direct_launcher
    from saas.production.interactive_recovery import (
        ManagedSuspensionReceipt,
        ManagedTerminationReceipt,
    )

    preparation = record.managed_preparation
    if (
        preparation is None
        or preparation.provider != "agent_sandbox"
        or record.managed_creation is None
        or record.managed_creation.pod_uid is None
        or record.managed_termination is not None
    ):
        return False
    launcher = _direct_launcher(
        deployment.for_provider(preparation.provider), preparation.provider
    )
    try:
        if _binding(launcher, preparation.resource_name, preparation.host_id) != preparation:
            raise _unavailable()
        observed = (
            record
            if record.managed_suspension is not None
            else replace(
                record,
                managed_suspension=ManagedSuspensionReceipt(
                    ManagedTerminationReceipt(secret_uid=record.managed_creation.secret_uid)
                ),
            )
        )
        recovery = _Recovery(launcher, observed, None, None, retaining=True)
        parent = recovery.parent()
        if (
            parent is None
            or parent["metadata"].get("deletionTimestamp")
            or parent["spec"].get("shutdownPolicy") != "Retain"
        ):
            raise _unavailable()
        if (
            record.managed_suspension is not None
            or parent["spec"].get("operatingMode") == "Suspended"
        ):
            return True
        deadline = datetime.fromisoformat(parent["spec"]["shutdownTime"].replace("Z", "+00:00"))
        if deadline.utcoffset() is None:
            raise _unavailable()
        return deadline <= datetime.fromtimestamp(now, timezone.utc)
    finally:
        launcher._close_clients()
