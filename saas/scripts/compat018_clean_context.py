"""Draft finite 4e C2 context audit and independent clean Server comparison.

The historical Server registration is retained; a new clean pair is never
claimed to have the old Server bytes. No download, dispatch or signing occurs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from saas.scripts import compat018_oci_recovery as recovery
from saas.scripts.compare_oci_rebuilds import compare_archives, inspect_oci_archive

KIND = "compat018_4e_clean_context_independent_Server/v1"
TREE = recovery.TREE
require = recovery.require


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
        require(
            len({member.name for member in members}) == len(members),
            "duplicate layer path",
        )
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
                else {
                    "login.html",
                    "signup.html",
                    "signup-verify.html",
                    "signup-status.html",
                }
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
    original, _, _ = recovery.original_evidence(root / "original-report.zip")
    facts = {
        role: inspect_oci_archive(root / f"{role}-1.tar", label_profile="executable")
        for role in ("server", "host")
    }
    historical_host = original["images"]["omnigent-saas-host"]
    require(
        historical_host["first"] == facts["host"]
        and historical_host["second"]["platforms"] == facts["host"]["platforms"]
        and historical_host["second"]["attestations"] == facts["host"]["attestations"]
        and historical_host["matching_platform_manifest_and_config"] is True
        and historical_host["history_created_by_equal"] is True,
        "new C2 Host does not equal its actual historical independent pair",
    )
    expected = source_inputs(repo)
    source_proofs = {}
    with tarfile.open(root / "server-1.tar") as archive:
        require(
            set(facts["server"]["platforms"]) == {"linux/amd64", "linux/arm64"},
            "C2 Server requires both original architectures",
        )
        for platform, actual in facts["server"]["platforms"].items():
            historical = original["images"]["omnigent-saas-server"]["first"]["platforms"][platform]
            require(
                actual["labels"] == recovery.LABELS and len(actual["layers"]) > 3,
                "C2 Server product labels or context layer differ",
            )
            projected = copy.deepcopy(historical)
            for key in ("manifest_digest", "config_digest"):
                projected[key] = actual[key]
            projected["layers"][3] = actual["layers"][3]
            projected["rootfs_diff_ids"][3] = actual["rootfs_diff_ids"][3]
            require(
                projected == actual,
                "C2 Server differs beyond the frozen Dockerfile copied /build layer",
            )
            layer_digest = actual["layers"][3]["digest"]
            body = _member_bytes(archive, "blobs/sha256/" + layer_digest.removeprefix("sha256:"))
            source_proofs[platform] = verify_context_layer(io.BytesIO(body), expected)
    return {
        "kind": KIND,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "source_date_epoch": recovery.EPOCH,
        "historical_comparison": {
            "artifact_id": recovery.REPORT_ID,
            "zip_sha256": recovery.REPORT_SHA,
            "seal_sha256": recovery.OLD_SEAL_SHA,
        },
        "historical_Server_facts_equal": facts["server"]
        == original["images"]["omnigent-saas-server"]["first"],
        "new_Host_matches_historical_independent_pair": True,
        "facts": facts,
        "source_proofs": source_proofs,
        "archive_sha256": {
            role: recovery.sha256(root / f"{role}-1.tar") for role in ("server", "host")
        },
    }


def audit(root: Path, repo: Path) -> dict[str, Any]:
    first = verify_first(root, repo)
    native = {
        "workflow_path": recovery.WORKFLOW,
        "controller_revision": os.environ.get("GITHUB_WORKFLOW_SHA"),
        "run_id": int(os.environ.get("GITHUB_RUN_ID", "0")),
        "attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
        "job_name": os.environ.get("GITHUB_JOB"),
        "actor": os.environ.get("GITHUB_ACTOR"),
    }
    require(
        isinstance(native["controller_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", native["controller_revision"])
        and native["run_id"] > 0
        and native["attempt"] == 1
        and native["job_name"] == "build-compat018-product"
        and isinstance(native["actor"], str)
        and bool(native["actor"]),
        "first C2 proof requires the actual native builder identity",
    )
    first["native_builder"] = native
    (root / "clean-context-first.json").write_text(
        json.dumps(first, sort_keys=True, indent=2) + "\n"
    )
    return first


def comparison(root: Path, repo: Path, profile: str) -> dict[str, Any]:
    require(
        profile in {"historical", "clean-C2-server"},
        "unknown finite C2 comparison profile",
    )
    first = verify_first(root, repo)
    retained = json.loads((root / "clean-context-first.json").read_text())
    native_builder = retained.pop("native_builder", None)
    require(
        first == retained and isinstance(native_builder, dict),
        "C2 first source and UI proof changed",
    )
    original, _, _ = recovery.original_evidence(root / "original-report.zip")
    report = copy.deepcopy(original)
    independent_sha = None
    if profile == "historical":
        require(
            first["historical_Server_facts_equal"] is True,
            "historical C2 mode cannot admit different Server bytes",
        )
    else:
        repeated = compare_archives(
            root / "server-1.tar", root / "server-2.tar", label_profile="executable"
        )
        require(
            repeated["matching_platform_manifest_and_config"] is True
            and repeated["history_created_by_equal"] is True
            and repeated["first"] == first["facts"]["server"],
            "independent clean C2 Server pair differs",
        )
        report["images"]["omnigent-saas-server"] = repeated
        independent_sha = recovery.sha256(root / "server-2.tar")
    report["clean_context_reproducibility"] = {
        "kind": KIND,
        "comparison_profile": profile,
        "native_builder": native_builder,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "source_date_epoch": recovery.EPOCH,
        "historical_comparison": first["historical_comparison"],
        "first_proof_sha256": recovery.sha256(root / "clean-context-first.json"),
        "independent_Server_archive_sha256": independent_sha,
        "old_Server_byte_identity_claimed": profile == "historical",
        "new_Host_matches_historical_independent_pair": True,
    }
    return report


def confirm(root: Path, repo: Path, profile: str) -> dict[str, Any]:
    report = comparison(root, repo, profile)
    (root / "saas-image-candidate.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    return report


def verify_complete(root: Path, repo: Path, profile: str) -> None:
    require(
        comparison(root, repo, profile)
        == json.loads((root / "saas-image-candidate.json").read_text()),
        "C2 comparison report changed",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("audit", "confirm", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument(
        "--comparison-profile",
        choices=("historical", "clean-C2-server"),
        default="clean-C2-server",
    )
    args = parser.parse_args()
    if args.command == "audit":
        audit(args.root, args.repo)
    elif args.command == "confirm":
        confirm(args.root, args.repo, args.comparison_profile)
    else:
        verify_complete(args.root, args.repo, args.comparison_profile)


if __name__ == "__main__":
    main()
