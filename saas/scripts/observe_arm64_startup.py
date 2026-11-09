"""Run one original OCI startup diagnostic on an isolated native ARM CI machine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive

REPOSITORY = "Dream1216/omnigent"
WORKFLOW = ".github/workflows/saas-image-candidate.yml"


def validate_origin(run: dict[str, Any], artifact: dict[str, Any], source: str) -> str:
    digest = artifact.get("digest", "")
    if (
        re.fullmatch(r"[0-9a-f]{40}", source) is None
        or run.get("head_sha") != source
        or run.get("path") != WORKFLOW
        or run.get("repository", {}).get("full_name") != REPOSITORY
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] != 1
        or run.get("status") != "completed"
        or run.get("conclusion") != "failure"
        or artifact.get("workflow_run", {}).get("id") != run.get("id")
        or artifact.get("workflow_run", {}).get("head_sha") != source
        or artifact.get("name") != f"failed-server-preflight-oci-{source}-{run['id']}-1"
        or artifact.get("expired") is not False
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("original failed Server artifact provenance differs")
    return digest.removeprefix("sha256:")


def _api(path: str) -> dict[str, Any]:
    return json.loads(
        subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/{path}"], timeout=30)
    )


def validate_imported_image(actual: dict[str, Any], selected: dict[str, Any]) -> None:
    if not (actual["Descriptor"]["digest"] == actual["Id"] == selected["manifest_digest"]):
        raise ValueError("actual imported ARM image manifest differs from original OCI")
    if actual["RootFS"]["Layers"] != selected["rootfs_diff_ids"]:
        raise ValueError("actual imported ARM image layers differ from original OCI")


def validate_native(native: dict[str, Any], bindings: dict[str, Any]) -> None:
    clean = {
        key: None if key in {"LANGUAGE", "LOCPATH"} else "C.UTF-8"
        for key in ("LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LOCPATH")
    }
    roles = {"server", "worker", "runner_control", "runner_agent", "preview_edge", "preview_owner"}
    entries = native.get("entries", [])
    if (
        native.get("kind") != "installed-production-startup-locale/v1"
        or native.get("source_revision") != bindings["source_revision"]
        or native.get("platform") != "linux/arm64"
        or native.get("actual_loaded_libc", {}).get("sha256") != bindings["libc_sha256"]
        or native.get("installed_files") != bindings["installed_files"]
        or native.get("uid") != 1000
        or native.get("gid") != 1000
        or native.get("mocked_exec") is not False
        or native.get("production_source_modified") is not False
        or native.get("whole_service_lifecycle_qualified") is not False
        or native.get("High_disposition") is not False
        or native.get("expires_at") != "2026-11-11T10:40:00Z"
        or len(entries) != 6
        or {entry.get("role") for entry in entries} != roles
        or any(
            entry.get("five_locale_inputs") != clean
            or entry.get("effective_LC_MESSAGES") not in {"C.UTF-8", "C.utf8"}
            or entry.get("effective_encoding", "").lower().replace("-", "") != "utf8"
            for entry in entries
        )
        or native.get("actual_controls")
        != {
            "no_new_privileges": True,
            "all_capabilities_empty": True,
            "rootfs_readonly": True,
            "interfaces": ["lo"],
            "non_loopback_routes": 0,
        }
    ):
        raise ValueError("actual installed startup evidence differs from protected bindings")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-run", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--scan-run", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        parser.error("requires the isolated native ARM64 CI machine, without QEMU borrowing")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        parser.error("diagnostic repository differs")
    repo = Path(__file__).resolve().parents[2]
    from saas.scripts.compat018_native_input import prepare_startup_input

    bindings, run, artifact, expected_zip, image, raw, support = prepare_startup_input(
        repo,
        source_revision=args.source_revision,
        raw_run_id=args.source_run,
        first_artifact_id=args.artifact_id,
        scan_run_id=args.scan_run,
        output=args.output,
    )
    facts = inspect_oci_archive(image, label_profile="executable")
    selected = facts["platforms"]["linux/arm64"]
    if selected["labels"]["org.opencontainers.image.revision"] != args.source_revision:
        raise ValueError("actual selected OCI source differs")
    with tarfile.open(image) as stream:
        index = stream.extractfile("index.json")
        if index is None:
            raise ValueError("original OCI index is absent")
        descriptors = json.load(index)["manifests"]
    if len(descriptors) != 1:
        raise ValueError("original OCI root is ambiguous")
    root = descriptors[0]["digest"]
    subprocess.run(["docker", "load", "-i", str(image)], check=True, timeout=180)
    actual = json.loads(
        subprocess.check_output(["docker", "image", "inspect", "--platform", "linux/arm64", root])
    )[0]
    validate_imported_image(actual, selected)
    evidence = args.output.resolve() / "evidence"
    evidence.mkdir()
    subprocess.run(["sudo", "chown", "1000:1000", str(evidence)], check=True)
    owner = secrets.token_hex(12)
    name = f"omnigent-arm-startup-{owner}"
    record: dict[str, Any] = {
        "schema_version": 1,
        "source_revision": args.source_revision,
        "operation": name,
        "source_run": run["id"],
        "artifact_id": artifact["id"],
        "original_artifact_sha256": expected_zip,
        "subject": {
            "source_revision": args.source_revision,
            "platform": "linux/arm64",
            "manifest_digest": selected["manifest_digest"],
            "config_digest": selected["config_digest"],
            "libc_sha256": bindings["libc_sha256"],
        },
        "original_report_sha256": hashlib.sha256(raw).hexdigest(),
        "control_revision": os.environ["GITHUB_SHA"],
        "control_run": os.environ["GITHUB_RUN_ID"],
        "control_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "host_platform": platform.platform(),
        "host_architecture": platform.machine(),
        "QEMU_used": False,
        "DB_credentials_shared_PVC_external_network": False,
        "High_disposition": False,
        "full_image_or_lifecycle_qualified": False,
        "owned_container_absent": False,
        "support_files": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(support.iterdir())
            if path.is_file()
        },
    }
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--pull",
                "never",
                "--platform",
                "linux/arm64",
                "--name",
                name,
                "--label",
                f"io.omnigent.arm-locale={owner}",
                "--no-healthcheck",
                "--network",
                "none",
                "--user",
                "1000:1000",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--mount",
                f"type=bind,src={support},dst=/qualification,readonly",
                "--mount",
                f"type=bind,src={evidence},dst=/evidence",
                "--entrypoint",
                "/opt/venv/bin/python",
                root,
                "-I",
                "-B",
                "/qualification/probe.py",
            ],
            check=False,
            timeout=120,
        )
        record["qualification_exit"] = result.returncode
        inspected = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
        if inspected["Config"]["Labels"].get("io.omnigent.arm-locale") != owner:
            raise ValueError("actual diagnostic container ownership differs")
        record["actual_container_id"] = inspected["Id"]
        host = inspected["HostConfig"]
        if (
            host["NetworkMode"] != "none"
            or host["Privileged"] is not False
            or host["ReadonlyRootfs"] is not True
            or host["CapDrop"] != ["ALL"]
            or host["CapAdd"]
            or host["PidMode"] == "host"
            or "no-new-privileges:true" not in host["SecurityOpt"]
            or inspected["Config"]["User"] != "1000:1000"
        ):
            raise ValueError("actual container runtime contract differs")
        mounts = {mount["Destination"]: mount for mount in inspected["Mounts"]}
        if (
            mounts["/qualification"]["RW"] is not False
            or mounts["/qualification"]["Source"] != str(support)
            or mounts["/evidence"]["RW"] is not True
            or mounts["/evidence"]["Source"] != str(evidence)
        ):
            raise ValueError("actual support/evidence mount identity differs")
        record["actual_runtime_contract"] = {
            key: host[key]
            for key in (
                "NetworkMode",
                "Privileged",
                "ReadonlyRootfs",
                "CapDrop",
                "CapAdd",
                "PidMode",
                "SecurityOpt",
                "Memory",
                "PidsLimit",
                "NanoCpus",
                "Tmpfs",
            )
        }
        if result.returncode:
            raise ValueError("actual installed startup component rejected")
        native = json.loads((evidence / "native-startup.PUBLIC.json").read_text())
        validate_native(native, bindings)
        if native["pid_namespace"] == os.readlink("/proc/self/ns/pid"):
            raise ValueError("actual diagnostic PID namespace was not private")
        record["native_facts"] = native
    finally:
        candidates = subprocess.check_output(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--filter",
                f"label=io.omnigent.arm-locale={owner}",
                "--format",
                "{{.ID}}",
            ],
            text=True,
            timeout=30,
        ).splitlines()
        for candidate in candidates:
            if re.fullmatch(r"[0-9a-f]{64}", candidate) is None:
                raise ValueError("owned diagnostic container identity is invalid")
            subprocess.run(
                ["docker", "container", "rm", "--force", candidate], check=True, timeout=30
            )
        remaining = subprocess.check_output(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                f"name=^/{name}$",
                "--filter",
                f"label=io.omnigent.arm-locale={owner}",
            ],
            text=True,
            timeout=30,
        ).strip()
        record["owned_container_absent"] = not remaining
        (args.output / "arm-startup-operator.PUBLIC.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n"
        )
        if remaining:
            raise ValueError("owned diagnostic container remains after cleanup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
