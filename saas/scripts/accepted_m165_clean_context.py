"""Revalidate the retained M165 bytes with one independent Server build."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from saas.scripts import accepted_oci_recovery as recovery
from saas.scripts.compare_oci_rebuilds import compare_archives, inspect_oci_archive
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import extract_artifact, read_json, require
from saas.scripts.scan_oci_candidates import file_sha256

KIND = "accepted_M165_clean_context_independent_Server"
TREE = "b3fdf6616fd13755e10da06a45f6deb7d7c5ef9f"
PARENT = {
    "run_id": 42459609969,
    "attempt": 1,
    "controller_revision": "e86f4e92210468103e0b5c4e37406958498deebe",
    "job_id": 128666051041,
    "job_conclusion": "failure",
    "artifact_id": 13610607355,
    "artifact_bytes": 5200935577,
    "artifact_sha256": "47613d97aa0077cd9d2100cee592e5a39ce5020f802862ea49e16096b929438e",
}
COMPARE_STEP = "Match actual four-platform bytes to original independent comparisons"


def verify_parent(run: dict[str, Any], job: dict[str, Any], artifact: dict[str, Any]) -> None:
    steps = {step["name"]: step for step in job.get("steps", [])}
    require(
        run.get("id") == PARENT["run_id"]
        and run.get("head_sha") == PARENT["controller_revision"]
        and run.get("path") == recovery.WORKFLOW
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == "main"
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and run.get("repository", {}).get("full_name") == recovery.REPOSITORY
        and job.get("id") == PARENT["job_id"]
        and job.get("run_id") == PARENT["run_id"]
        and job.get("run_attempt") == 1
        and job.get("name") == "build-accepted-product"
        and job.get("status") == "completed"
        and job.get("conclusion") == "failure"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and [name for name, step in steps.items() if step.get("conclusion") == "failure"]
        == [COMPARE_STEP]
        and all(
            steps.get(name, {}).get("conclusion") == "success"
            for name in (
                "Recover Server using its existing first-attempt build cache",
                "Recover Host using its existing first-attempt build cache",
                "Stage actual OCI before any cleanup or inspection can fail",
                "Preserve actual OCI before any fresh vulnerability scan",
            )
        )
        and artifact.get("id") == PARENT["artifact_id"]
        and artifact.get("name") == f"accepted-raw-{recovery.PRODUCT}-{PARENT['run_id']}"
        and artifact.get("size_in_bytes") == PARENT["artifact_bytes"]
        and artifact.get("digest") == f"sha256:{PARENT['artifact_sha256']}"
        and artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == PARENT["run_id"]
        and artifact.get("workflow_run", {}).get("head_sha") == PARENT["controller_revision"],
        "the one retained failed parent and successful preservation steps differ",
    )


def source_inputs(repo: Path) -> dict[str, tuple[str, bytes]]:
    tree = subprocess.check_output(
        ["git", "rev-parse", f"{recovery.PRODUCT}^{{tree}}"], cwd=repo, text=True
    ).strip()
    require(tree == TREE, "frozen product tree differs")
    entries = subprocess.check_output(["git", "ls-tree", "-r", "-z", recovery.PRODUCT], cwd=repo)
    selected = []
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        detail, name = entry.split(b"\t", 1)
        mode, kind, blob = detail.decode().split()
        path = name.decode()
        if path in {
            "LICENSE",
            "NOTICE",
            "pyproject.toml",
            "setup.py",
            "uv.lock",
        } or path.startswith(("omnigent/", "saas/", "sdks/", "examples/", "integrations/slack/")):
            require(kind == "blob", "unexpected product source entry")
            selected.append((path, mode, blob))
    bodies = subprocess.check_output(
        ["git", "cat-file", "--batch"],
        input="".join(f"{blob}\n" for _, _, blob in selected).encode(),
        cwd=repo,
    )
    offset, result = 0, {}
    for path, mode, blob in selected:
        end = bodies.index(b"\n", offset)
        actual_blob, kind, size = bodies[offset:end].decode().split()
        require(actual_blob == blob and kind == "blob", "Git batch source identity differs")
        offset = end + 1
        body = bodies[offset : offset + int(size)]
        offset += int(size) + 1
        if path == "pyproject.toml":
            body, count = re.subn(rb"(?ms)^\[tool\.uv\.workspace\]\n.*?^\n", b"", body)
            require(count == 1, "the original Dockerfile workspace transformation differs")
        result[path] = mode, body
    require(offset == len(bodies) and bool(result), "incomplete frozen source input")
    return result


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo | str) -> bytes:
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("required regular archive file is missing")
    with stream:
        return stream.read()


def verify_context_layer(stream: Any, expected: dict[str, tuple[str, bytes]]) -> dict[str, Any]:
    """Check actual copied source and generated UI without ignoring the old layer drift."""
    with tarfile.open(fileobj=stream, mode="r:*") as layer:
        members = layer.getmembers()
        require(len({member.name for member in members}) == len(members), "duplicate layer path")
        by_name = {member.name: member for member in members}
        for name, (mode, body) in expected.items():
            member = by_name.get("build/" + name)
            if member is None:
                raise ValueError("frozen tracked source file is missing")
            if mode == "120000":
                require(
                    member.issym() and member.linkname.encode() == body,
                    "frozen tracked source symlink differs",
                )
            else:
                require(
                    member.isfile()
                    and member.mode == (0o755 if mode == "100755" else 0o644)
                    and _member_bytes(layer, member) == body,
                    "frozen tracked source bytes or mode differ",
                )
        ui_proofs = {}
        for prefix in ("omnigent/server/static/web-ui/", "saas/login_ui/static/"):
            copies = []
            for base in ("build/", "build/build/lib/"):
                files = {}
                for member in members:
                    if member.name.startswith(base + prefix) and not member.isdir():
                        require(member.isfile(), "generated UI contains a nonregular file")
                        files[member.name.removeprefix(base + prefix)] = hashlib.sha256(
                            _member_bytes(layer, member)
                        ).hexdigest()
                copies.append(files)
            require(bool(copies[0]) and copies[0] == copies[1], "generated UI copies differ")
            required = (
                {"index.html"}
                if prefix.startswith("omnigent/")
                else {"login.html", "signup.html", "signup-verify.html", "signup-status.html"}
            )
            require(required <= copies[0].keys(), "generated UI entry point is missing")
            ui_proofs[prefix] = {
                "files": len(copies[0]),
                "sha256": hashlib.sha256(
                    json.dumps(copies[0], sort_keys=True).encode()
                ).hexdigest(),
            }
    return {"tracked_inputs": len(expected), "generated_UI": ui_proofs}


def verify_first(root: Path, repo: Path) -> dict[str, Any]:
    original = recovery.original_report(root / "original-report.zip")
    facts = {
        role: inspect_oci_archive(root / f"{role}-1.tar", label_profile="executable")
        for role in ("server", "host")
    }
    host = original["images"]["omnigent-saas-host"]
    require(
        host["first"] == facts["host"]
        and host["second"]["platforms"] == facts["host"]["platforms"]
        and host["second"]["attestations"] == facts["host"]["attestations"]
        and host["matching_platform_manifest_and_config"] is True
        and host["history_created_by_equal"] is True,
        "retained Host differs from its original independent build pair",
    )
    expected = source_inputs(repo)
    source_proofs = {}
    with tarfile.open(root / "server-1.tar") as archive:
        for platform, actual in facts["server"]["platforms"].items():
            old = original["images"]["omnigent-saas-server"]["first"]["platforms"][platform]
            projected = copy.deepcopy(old)
            for key in ("manifest_digest", "config_digest"):
                projected[key] = actual[key]
            projected["layers"][3] = actual["layers"][3]
            projected["rootfs_diff_ids"][3] = actual["rootfs_diff_ids"][3]
            require(projected == actual, "Server differs beyond the known copied build layer")
            digest = actual["layers"][3]["digest"]
            body = _member_bytes(archive, "blobs/sha256/" + digest.removeprefix("sha256:"))
            source_proofs[platform] = verify_context_layer(io.BytesIO(body), expected)
    return {
        "kind": KIND,
        "product_revision": recovery.PRODUCT,
        "product_tree": TREE,
        "source_date_epoch": recovery.EPOCH,
        "parent_raw_checkpoint": PARENT,
        "old_Server_byte_identity_claimed": False,
        "facts": facts,
        "source_proofs": source_proofs,
        "archive_sha256": {
            role: file_sha256(root / f"{role}-1.tar") for role in ("server", "host")
        },
    }


def prepare(root: Path, repo: Path) -> None:
    recovery.prepare(root.with_name(root.name + "-historical-comparison"))
    prefix = f"repos/{recovery.REPOSITORY}/actions"
    verify_parent(
        recovery.api(f"{prefix}/runs/{PARENT['run_id']}"),
        recovery.api(f"{prefix}/jobs/{PARENT['job_id']}"),
        recovery.api(f"{prefix}/artifacts/{PARENT['artifact_id']}"),
    )
    archive = root.with_suffix(".zip")
    download_artifact_bytes(
        PARENT["artifact_id"],
        archive,
        expected_size=PARENT["artifact_bytes"],
        expected_sha256=PARENT["artifact_sha256"],
    )
    extract_artifact(archive, root, zip_sha256=PARENT["artifact_sha256"])
    archive.unlink()
    result = verify_first(root, repo)
    (root / "clean-context-first.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n"
    )


def comparison(root: Path, repo: Path) -> dict[str, Any]:
    first = verify_first(root, repo)
    require(first == read_json(root / "clean-context-first.json"), "retained first proof changed")
    repeated = compare_archives(
        root / "server-1.tar", root / "server-2.tar", label_profile="executable"
    )
    require(
        repeated["matching_platform_manifest_and_config"] is True
        and repeated["history_created_by_equal"] is True
        and repeated["first"] == first["facts"]["server"],
        "independent clean Server build is not reproducible",
    )
    report = recovery.original_report(root / "original-report.zip")
    report["images"]["omnigent-saas-server"] = repeated
    report["clean_context_reproducibility"] = {
        **{key: value for key, value in first.items() if key != "facts"},
        "first_proof_sha256": file_sha256(root / "clean-context-first.json"),
        "independent_Server_archive_sha256": file_sha256(root / "server-2.tar"),
        "Host_rebuilt_in_this_confirmation": False,
    }
    return report


def confirm(root: Path, repo: Path) -> dict[str, Any]:
    report = comparison(root, repo)
    (root / "saas-image-candidate.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    return report


def verify_complete(root: Path, repo: Path) -> None:
    require(
        comparison(root, repo) == read_json(root / "saas-image-candidate.json"),
        "confirmed comparison report changed",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "confirm", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root, args.repo)
    elif args.command == "confirm":
        confirm(args.root, args.repo)
    else:
        verify_complete(args.root, args.repo)


if __name__ == "__main__":
    main()
