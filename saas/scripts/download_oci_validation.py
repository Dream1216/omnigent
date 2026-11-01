"""Inspect or transfer a manual unsigned validation bundle without promotion authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from saas.scripts.oci_promotion import MANIFEST_NAME, extract_artifact, require

_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/(?!(?:\.|\.\.)$)[A-Za-z0-9_.-]{1,100}")


def verify_validation_coordinates(
    metadata: dict, run: dict, *, repository: str, revision: str, run_id: int, artifact_id: int
) -> None:
    require(
        _REPOSITORY.fullmatch(repository) is not None,
        "invalid repository",
    )
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid source revision")
    require(
        type(run_id) is int and run_id > 0 and type(artifact_id) is int and artifact_id > 0,
        "invalid native coordinates",
    )
    require(
        run.get("id") == run_id
        and run.get("head_sha") == revision
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("event") == "workflow_dispatch"
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == 1
        and run.get("path") == ".github/workflows/saas-image-candidate.yml"
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository,
        "validation requires a successful first-attempt manual candidate for this exact source",
    )
    digest = metadata.get("digest")
    require(
        metadata.get("id") == artifact_id
        and metadata.get("name") == f"saas-oci-validation-{revision}"
        and metadata.get("expired") is False
        and isinstance(digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
        and digest != "sha256:" + "0" * 64
        and type(metadata.get("size_in_bytes")) is int
        and metadata["size_in_bytes"] > 0
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == revision,
        "validation artifact does not bind this exact workflow run and source",
    )


def transfer_plan(
    metadata: dict, parent: Path, *, max_download: int, max_expanded: int, reserve: int
) -> dict:
    require(
        all(type(value) is int and value > 0 for value in (max_download, max_expanded, reserve)),
        "explicit positive transfer budgets are required",
    )
    size = metadata["size_in_bytes"]
    free = shutil.disk_usage(parent).free
    required = size + max_expanded + reserve
    return {
        "status": "transfer_capacity_available"
        if size <= max_download and free >= required
        else "held_for_capacity",
        "artifact_bytes": size,
        "max_download_bytes": max_download,
        "max_expanded_bytes": max_expanded,
        "reserve_bytes": reserve,
        "required_free_bytes": required,
        "observed_free_bytes": free,
        "covers_oci_inspection_or_container_storage": False,
        "production_qualification": False,
    }


def stream_archive(
    command: list[str], output: Path, *, size: int, digest: str, timeout: int
) -> None:
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert process.stdout is not None
        checksum, count = hashlib.sha256(), 0
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "validation transfer timed out")
                ready, _, _ = select.select([process.stdout], [], [], remaining)
                require(bool(ready), "validation transfer timed out")
                chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= size, "validation transfer exceeds native artifact size")
                checksum.update(chunk)
                stream.write(chunk)
        require(
            process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
            "native validation download failed",
        )
        require(
            count == size and checksum.hexdigest() == digest,
            "validation ZIP size or digest mismatch",
        )
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


def extract_validation(
    archive: Path,
    output: Path,
    *,
    zip_digest: str,
    manifest_digest: str,
    max_expanded: int,
    reserve: int,
) -> int:
    require(
        re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is not None and manifest_digest != "0" * 64,
        "an independently captured candidate seal digest is required",
    )
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        require(len(members) <= 10000, "validation ZIP has too many entries")
        require(
            all(item.filename != "unsigned-validation-transfer.json" for item in members),
            "validation ZIP contains a reserved transfer receipt",
        )
        expanded = sum(item.file_size for item in members)
        require(expanded <= max_expanded, "validation ZIP exceeds expanded-byte budget")
        require(
            shutil.disk_usage(output.parent).free >= expanded + reserve,
            "validation extraction would consume reserved capacity",
        )
        manifest = bundle.getinfo(MANIFEST_NAME)
        require(manifest.file_size <= 1024 * 1024, "candidate seal exceeds budget")
        require(
            hashlib.sha256(bundle.read(manifest)).hexdigest() == manifest_digest,
            "candidate seal digest mismatch",
        )
    previous = os.umask(0o077)
    try:
        extract_artifact(archive, output, zip_sha256=zip_digest)
    finally:
        os.umask(previous)
    output.chmod(0o700)
    return expanded


def _native_json(endpoint: str) -> dict:
    completed = subprocess.run(
        ["gh", "api", endpoint],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    require(len(completed.stdout) <= 2 * 1024 * 1024, "native metadata exceeds budget")
    value = json.loads(completed.stdout)
    require(isinstance(value, dict), "native metadata must be an object")
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "download"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-download-bytes", type=int, required=True)
    parser.add_argument("--max-expanded-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    try:
        require(
            _REPOSITORY.fullmatch(args.repository) is not None,
            "invalid repository",
        )
        output = args.output_dir
        require(
            output.is_absolute()
            and output.parent.resolve(strict=True) == output.parent
            and not output.exists()
            and not output.is_symlink(),
            "validation output must be new with an existing resolved parent",
        )
        require(1 <= args.timeout_seconds <= 3600, "invalid transfer timeout")
        endpoint = f"repos/{args.repository}/actions/artifacts/{args.artifact_id}"
        metadata = _native_json(endpoint)
        run = _native_json(f"repos/{args.repository}/actions/runs/{args.run_id}")
        verify_validation_coordinates(
            metadata,
            run,
            repository=args.repository,
            revision=args.revision,
            run_id=args.run_id,
            artifact_id=args.artifact_id,
        )
        plan = transfer_plan(
            metadata,
            output.parent,
            max_download=args.max_download_bytes,
            max_expanded=args.max_expanded_bytes,
            reserve=args.reserve_bytes,
        )
        if args.command == "inspect" or plan["status"] == "held_for_capacity":
            print(
                json.dumps(
                    plan | {"artifact_id": args.artifact_id, "zip_sha256": metadata["digest"][7:]},
                    sort_keys=True,
                )
            )
            return int(plan["status"] == "held_for_capacity")
        require(
            args.manifest_sha256 is not None
            and re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is not None
            and args.manifest_sha256 != "0" * 64,
            "candidate seal digest is required",
        )
        with tempfile.TemporaryDirectory(
            prefix=".oci-validation-", dir=output.parent
        ) as temporary:
            archive = Path(temporary) / "candidate.zip"
            stream_archive(
                ["gh", "api", endpoint + "/zip"],
                archive,
                size=metadata["size_in_bytes"],
                digest=metadata["digest"][7:],
                timeout=args.timeout_seconds,
            )
            expanded = extract_validation(
                archive,
                output,
                zip_digest=metadata["digest"][7:],
                manifest_digest=args.manifest_sha256,
                max_expanded=args.max_expanded_bytes,
                reserve=args.reserve_bytes,
            )
        receipt = {
            "schema_version": 1,
            "status": "transferred",
            "production_qualification": False,
            "candidate_seal_verified": False,
            "runtime_qualified": False,
            "repository": args.repository,
            "product_revision": args.revision,
            "run_id": args.run_id,
            "run_attempt": 1,
            "artifact_id": args.artifact_id,
            "zip_sha256": metadata["digest"][7:],
            "expanded_bytes": expanded,
            "candidate_manifest_sha256": args.manifest_sha256,
            "capacity_plan": plan,
        }
        descriptor = os.open(
            output / "unsigned-validation-transfer.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(receipt, sort_keys=True) + "\n")
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except Exception:  # noqa: BLE001 - native responses and command diagnostics stay private.
        print(json.dumps({"status": "rejected", "error": "unsigned_validation_transfer_rejected"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
