"""Fail-closed provenance for the isolated native ARM component observation."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from saas.scripts.observe_arm64_startup import (
    REPOSITORY,
    WORKFLOW,
    validate_imported_image,
    validate_native,
    validate_origin,
)

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT / "saas/supply_chain/arm64-startup-diagnostic"
BINDINGS = json.loads((SUPPORT / "bindings.json").read_text())


def test_fixed_installed_bindings_match_product_source():
    for installed, expected in BINDINGS["installed_files"].items():
        relative = installed.split("/site-packages/", 1)[1]
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "path",
        "repository",
        "attempt",
        "status",
        "conclusion",
        "artifact_run",
        "artifact_source",
        "name",
        "expired",
        "digest",
    ],
)
def test_original_artifact_origin_rejects_changed_identity(fault):
    source = BINDINGS["source_revision"]
    run = {
        "id": BINDINGS["source_run"],
        "head_sha": source,
        "path": WORKFLOW,
        "repository": {"full_name": REPOSITORY},
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "failure",
    }
    artifact = {
        "workflow_run": {"id": run["id"], "head_sha": source},
        "name": f"failed-server-preflight-oci-{source}-{run['id']}-1",
        "expired": False,
        "digest": "sha256:" + BINDINGS["original_artifact_sha256"],
    }
    if fault == "source":
        run["head_sha"] = "a" * 40
    elif fault == "path":
        run["path"] = "other.yml"
    elif fault == "repository":
        run["repository"] = {"full_name": "other/repository"}
    elif fault == "attempt":
        run["run_attempt"] = True
    elif fault == "status":
        run["status"] = "in_progress"
    elif fault == "conclusion":
        run["conclusion"] = "success"
    elif fault == "artifact_run":
        artifact["workflow_run"]["id"] += 1
    elif fault == "artifact_source":
        artifact["workflow_run"]["head_sha"] = "a" * 40
    elif fault == "name":
        artifact["name"] = "other"
    elif fault == "expired":
        artifact["expired"] = True
    elif fault == "digest":
        artifact["digest"] = ""
    if fault is None:
        assert validate_origin(run, artifact, source) == BINDINGS["original_artifact_sha256"]
    else:
        with pytest.raises(ValueError, match="provenance"):
            validate_origin(run, artifact, source)


@pytest.mark.parametrize("fault", [None, "descriptor", "id", "layers"])
def test_docker_identity_checks_descriptor_id_and_layers_independently(fault):
    selected = {"manifest_digest": "sha256:" + "a" * 64, "rootfs_diff_ids": ["sha256:" + "b" * 64]}
    actual = {
        "Descriptor": {"digest": selected["manifest_digest"]},
        "Id": selected["manifest_digest"],
        "RootFS": {"Layers": selected["rootfs_diff_ids"]},
    }
    if fault == "descriptor":
        actual["Descriptor"]["digest"] = "sha256:" + "c" * 64
    elif fault == "id":
        actual["Id"] = "sha256:" + "c" * 64
    elif fault == "layers":
        actual["RootFS"]["Layers"] = []
    if fault is None:
        validate_imported_image(actual, selected)
    else:
        with pytest.raises(ValueError, match=r"differs|differ"):
            validate_imported_image(actual, selected)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "platform",
        "libc",
        "installed_files",
        "uid",
        "roles",
        "duplicate_role",
        "locale",
        "encoding",
        "controls",
        "mocked",
        "lifecycle",
        "High",
        "expiry",
    ],
)
def test_native_observation_is_component_only_and_exactly_bound(fault):
    native = {
        "kind": "installed-production-startup-locale/v1",
        "source_revision": BINDINGS["source_revision"],
        "platform": "linux/arm64",
        "actual_loaded_libc": {"sha256": BINDINGS["libc_sha256"]},
        "installed_files": copy.deepcopy(BINDINGS["installed_files"]),
        "uid": 1000,
        "gid": 1000,
        "mocked_exec": False,
        "production_source_modified": False,
        "whole_service_lifecycle_qualified": False,
        "High_disposition": False,
        "expires_at": "2026-11-11T10:40:00Z",
        "actual_controls": {
            "no_new_privileges": True,
            "all_capabilities_empty": True,
            "rootfs_readonly": True,
            "interfaces": ["lo"],
            "non_loopback_routes": 0,
        },
        "entries": [
            {
                "role": role,
                "effective_LC_MESSAGES": "C.UTF-8",
                "effective_encoding": "UTF-8",
                "five_locale_inputs": {
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "LC_MESSAGES": "C.UTF-8",
                    "LANGUAGE": None,
                    "LOCPATH": None,
                },
            }
            for role in (
                "server",
                "worker",
                "runner_control",
                "runner_agent",
                "preview_edge",
                "preview_owner",
            )
        ],
    }
    if fault in {"source", "platform", "uid", "expiry"}:
        native[
            {
                "source": "source_revision",
                "platform": "platform",
                "uid": "uid",
                "expiry": "expires_at",
            }[fault]
        ] = "wrong"
    elif fault == "libc":
        native["actual_loaded_libc"]["sha256"] = "a" * 64
    elif fault == "installed_files":
        native["installed_files"].pop(next(iter(native["installed_files"])))
    elif fault == "roles":
        native["entries"].pop()
    elif fault == "duplicate_role":
        native["entries"][-1] = copy.deepcopy(native["entries"][0])
    elif fault == "locale":
        native["entries"][0]["five_locale_inputs"]["LOCPATH"] = "/workspace/catalog"
    elif fault == "encoding":
        native["entries"][0]["effective_encoding"] = "ASCII"
    elif fault == "controls":
        native["actual_controls"]["interfaces"].append("eth0")
    elif fault in {"mocked", "lifecycle", "High"}:
        native[
            {
                "mocked": "mocked_exec",
                "lifecycle": "whole_service_lifecycle_qualified",
                "High": "High_disposition",
            }[fault]
        ] = True
    if fault is None:
        validate_native(native, BINDINGS)
    else:
        with pytest.raises(ValueError, match="protected bindings"):
            validate_native(native, BINDINGS)


def test_local_interpreter_cannot_manufacture_native_image_proof():
    process = subprocess.run(
        [sys.executable, "-I", "-B", str(SUPPORT / "probe.py")],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert process.returncode != 0
    assert "requires actual Linux ARM64 userspace" in process.stderr or (
        "requires installed image virtualenv" in process.stderr
    )


def test_workflow_keeps_arm_probe_out_of_build_and_sign_chain():
    workflow = yaml.safe_load((ROOT / WORKFLOW).read_text())
    job = workflow["jobs"]["diagnostic-arm64-startup"]
    assert job["runs-on"] == "ubuntu-24.04-arm"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert "workflow_dispatch" in job["if"]
    assert "!inputs.diagnostic_arm64_startup" in workflow["jobs"]["diagnostic-host-only"]["if"]
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert '"$PUBLISH_SIGNED" == "false"' in commands
    assert '"$HOST_DIAGNOSTIC" == "true"' in commands
    assert '"$GITHUB_RUN_ATTEMPT" == "1"' in commands
    assert "setup-qemu" not in json.dumps(job)
