"""Authenticate the current C2 bytes for the existing native startup operator."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path
from typing import Any

from saas.scripts import compat018_oci_recovery as recovery
from saas.scripts import compat018_recovered_input as recovered
from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import require


def first_payload(archive: Path, output: Path, profile: dict[str, Any], bindings) -> Path:
    expected = {
        "server-1.tar",
        "registered-source-profile.json",
        "reviewed-subject-image-facts.json",
    }
    with zipfile.ZipFile(archive) as bundle:
        files = [entry for entry in bundle.infolist() if not entry.is_dir()]
        require(
            len(files) == len(expected)
            and {entry.filename for entry in files} == expected
            and sum(entry.file_size for entry in files) <= 2 * 1024**3
            and all(not stat.S_ISLNK(entry.external_attr >> 16) for entry in files)
            and bundle.testzip() is None,
            "native startup input is not the exact bounded first Server transport",
        )
        for name in expected - {"server-1.tar"}:
            require(bundle.getinfo(name).file_size <= 4 * 1024**2, "first proof exceeds its bound")
        profile_bytes = bundle.read("registered-source-profile.json")
        first = json.loads(bundle.read("reviewed-subject-image-facts.json"))
        require(
            json.loads(profile_bytes) == profile
            and first.get("kind") == "registered_compat018_first_pair_actual_source_facts/v1"
            and all(
                first.get(key) == profile[key]
                for key in ("product_revision", "product_tree", "source_date_epoch")
            )
            and first.get("profile_sha256")
            == hashlib.sha256(
                json.dumps(
                    profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            and first.get("historical_4e_byte_identity_claimed") is False
            and first.get("independent_rebuild_or_runtime_or_High_or_signature_qualified") is False
            and bindings.get("source_revision") == profile["product_revision"],
            "native startup first proof belongs to another C2 subject",
        )
        image = output / "server-1.tar"
        with bundle.open("server-1.tar") as source, image.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    require(
        recovery.sha256(image) == first["images"]["server"]["archive_sha256"],
        "first Server archive hash differs",
    )
    facts = inspect_oci_archive(image, label_profile="executable")
    selected = facts["platforms"]["linux/arm64"]
    target = first["images"]["server"]["targets"]["linux/arm64"]
    inventory = target["installed_component_inventory"]
    require(
        facts == first["images"]["server"]["facts"]
        and selected["manifest_digest"] == target["manifest_digest"]
        and selected["config_digest"] == target["config_digest"]
        and selected["labels"]["org.opencontainers.image.revision"] == profile["product_revision"]
        and len(bindings["installed_files"]) == 24,
        "actual native startup OCI identity differs from the audited C2 first image",
    )
    for path, digest in {
        **bindings["installed_files"],
        "usr/lib/libc.so.6": bindings["libc_sha256"],
    }.items():
        matches = [entry for entry in inventory if entry.get("path") == path]
        require(
            len(matches) == 1
            and matches[0].get("type") == "0"
            and matches[0].get("sha256") == digest,
            "actual C2 installed caller or libc differs from its own native bindings",
        )
    return image


def scan_report(archive: Path, selected: dict[str, Any]) -> bytes:
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        files = [entry for entry in entries if not entry.is_dir()]
        require(
            len(files) == len({entry.filename for entry in files})
            and len(files) <= 12
            and sum(entry.file_size for entry in files) <= 64 * 1024**2
            and all(not stat.S_ISLNK(entry.external_attr >> 16) for entry in files)
            and bundle.testzip() is None,
            "native ARM scan report transport is ambiguous or oversized",
        )
        reports = [entry for entry in files if entry.filename == "grype/server-arm64-grype.json"]
        require(len(reports) == 1, "native ARM raw report is absent or ambiguous")
        raw = bundle.read(reports[0])
    report = json.loads(raw)
    require(
        report.get("source", {}).get("target", {}).get("manifestDigest")
        == selected["manifest_digest"]
        and report.get("source", {}).get("target", {}).get("imageID") == selected["config_digest"]
        and isinstance(report.get("matches"), list),
        "actual native ARM report names another OCI manifest or config",
    )
    return raw


def prepare_startup_input(
    control: Path,
    *,
    source_revision: str,
    raw_run_id: int,
    first_artifact_id: int,
    scan_run_id: int,
    output: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, Path, bytes, Path]:
    profile = recovery.registered_profile()
    recovered.exact_product(profile)
    require(
        source_revision == profile["product_revision"], "native startup source is not current C2"
    )
    row, run, _ = recovered._derive_row(control, raw_run_id, sealed=False, profile=profile)
    upload = "Retain the audited first Server for the existing native startup operator"
    builder = recovered._job(
        row,
        "builder_job_id",
        "build-compat018-product",
        (
            "Audit actual fixed C2 source, UI, and historical Host",
            upload,
        ),
    )
    artifact = recovered.api(f"repos/{recovery.REPOSITORY}/actions/artifacts/{first_artifact_id}")
    digest = artifact.get("digest", "")
    require(
        type(artifact.get("size_in_bytes")) is int
        and 0 < artifact["size_in_bytes"] <= 2 * 1024**3
        and isinstance(digest, str)
        and len(digest) == 71
        and digest.startswith("sha256:"),
        "native first Server has no bounded original artifact transport",
    )
    transport = {
        **row,
        "artifact_id": first_artifact_id,
        "zip_size": artifact["size_in_bytes"],
        "zip_sha256": digest[7:],
    }
    recovered._artifact(
        transport, f"compat018-native-startup-{source_revision}-{raw_run_id}", builder, upload
    )
    output.mkdir(parents=True, exist_ok=False)
    archive = output / "original.PRIVATE.zip"
    download_artifact_bytes(
        first_artifact_id,
        archive,
        expected_size=transport["zip_size"],
        expected_sha256=transport["zip_sha256"],
    )
    support = control / "saas/supply_chain/compat018-startup-diagnostic"
    bindings = json.loads((support / "bindings.json").read_text())
    image = first_payload(archive, output, profile, bindings)
    selected = inspect_oci_archive(image, label_profile="executable")["platforms"]["linux/arm64"]
    scan = recovered.api(f"repos/{recovery.REPOSITORY}/actions/runs/{scan_run_id}")
    scan_revision = scan.get("head_sha")
    scan_row = {"run_id": scan_run_id, "controller_revision": scan_revision}
    recovered._run(scan_row, sealed=False)
    recovered._code(control, scan_revision)
    job = recovered._unique(
        f"repos/{recovery.REPOSITORY}/actions/runs/{scan_run_id}/attempts/1/jobs",
        "jobs",
        "scan-and-seal-same-oci",
    )
    steps = job.get("steps", [])
    names = (
        "Download and independently recheck the same real raw checkpoint",
        "Fresh scan and seal without rebuilding or relaxing any gate",
        "Preserve raw rejection and original checkpoint on every outcome",
    )
    selected_steps = [[step for step in steps if step.get("name") == name] for name in names]
    require(
        job.get("run_id") == scan_run_id
        and job.get("run_attempt") == 1
        and job.get("head_sha") == scan_revision
        and job.get("status") == "completed"
        and job.get("conclusion") in {"success", "failure"}
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and "self-hosted" not in job.get("labels", [])
        and all(
            len(matches) == 1 and matches[0].get("status") == "completed"
            for matches in selected_steps
        )
        and selected_steps[0][0].get("conclusion") == "success"
        and selected_steps[1][0].get("conclusion") in {"success", "failure"}
        and selected_steps[2][0].get("conclusion") == "success"
        and [matches[0]["number"] for matches in selected_steps]
        == sorted({matches[0]["number"] for matches in selected_steps}),
        "native startup has no actual original scan and retained raw report",
    )
    scan_artifact = recovered._unique(
        f"repos/{recovery.REPOSITORY}/actions/runs/{scan_run_id}/artifacts",
        "artifacts",
        f"compat018-same-oci-scan-{scan_run_id}",
    )
    scan_digest = scan_artifact.get("digest", "")
    require(
        isinstance(scan_digest, str)
        and len(scan_digest) == 71
        and scan_digest.startswith("sha256:")
        and type(scan_artifact.get("size_in_bytes")) is int
        and 0 < scan_artifact["size_in_bytes"] <= 64 * 1024**2,
        "original scan transport exceeds its finite bounds",
    )
    scan_row.update(
        artifact_id=scan_artifact["id"],
        zip_size=scan_artifact["size_in_bytes"],
        zip_sha256=scan_digest[7:],
    )
    recovered._artifact(scan_row, f"compat018-same-oci-scan-{scan_run_id}", job, names[-1])
    scan_zip = output / "original-scan.PRIVATE.zip"
    download_artifact_bytes(
        scan_artifact["id"],
        scan_zip,
        expected_size=scan_row["zip_size"],
        expected_sha256=scan_row["zip_sha256"],
    )
    raw = scan_report(scan_zip, selected)
    (output / "original-arm64-grype.PUBLIC.json").write_bytes(raw)
    (output / "native-input-origin.PUBLIC.json").write_text(
        json.dumps(
            {
                "raw_run": row,
                "first_Server_transport": transport,
                "original_scan_transport": scan_row,
                "startup_only": True,
                "High_disposition": False,
                "full_image_or_lifecycle_qualified": False,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    return bindings, run, artifact, transport["zip_sha256"], image, raw, support
