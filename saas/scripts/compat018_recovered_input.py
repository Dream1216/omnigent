"""Draft finite C2 recovery origin; never relabel a new producer as the old PR."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.scripts import compat018_oci_recovery as recovery
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pytest_results import verify_job_artifact_identity

COMPONENT = "Compatibility018"
ORIGIN = "compat018_clean_recovered_oci/v1"
VARIANT = "protected_legacy_initial_publication/compat018-recovered/v1"
SOURCES = (
    recovery.WORKFLOW,
    "saas/scripts/compat018_oci_recovery.py",
    "saas/scripts/compat018_clean_context.py",
)
HISTORICAL = {
    "run_id": 41849013923,
    "attempt": 2,
    "artifact_id": 13353731321,
    "zip_size": 5101978587,
    "zip_sha256": "475a5d49d717f9914d3086345cf5399c09994342c6c7ebcf751a1f3afcd77f9e",
    "seal_sha256": recovery.OLD_SEAL_SHA,
}
require = recovery.require
SEALED_FILES = {
    "server-1.tar",
    "host-1.tar",
    "saas-image-candidate.json",
    "oci-promotion-manifest.json",
    "grype/candidate-scan-summary.json",
    "clean-context-first.json",
    "original-report.zip",
    *(
        f"grype/{role}-{arch}-grype.json"
        for role in ("server", "host")
        for arch in ("amd64", "arm64")
    ),
}


def verify_sealed_zip(archive: Path, size: int, *, crc: bool) -> None:
    with zipfile.ZipFile(archive) as bundle:
        all_entries = bundle.infolist()
        files = [item for item in all_entries if not item.is_dir()]
        require(
            len(all_entries) <= 16
            and len({item.filename for item in all_entries}) == len(all_entries)
            and len(files) == len(SEALED_FILES)
            and {item.filename for item in files} == SEALED_FILES
            and all(item.filename == "grype/" for item in all_entries if item.is_dir())
            and sum(item.file_size for item in files) <= size
            and all(
                stat.S_IFMT(item.external_attr >> 16) in {0, stat.S_IFREG}
                and not item.flag_bits & 1
                for item in files
            ),
            "recovered C2 ZIP is not the exact bounded original nine plus two proofs",
        )
        if crc:
            require(bundle.testzip() is None, "complete recovered C2 ZIP CRC failed")


def exact_product(profile: dict[str, Any]) -> None:
    require(
        profile.get("component") == COMPONENT
        and profile.get("product_revision") == recovery.PRODUCT
        and profile.get("product_tree") == recovery.TREE
        and profile.get("source_date_epoch") == recovery.EPOCH,
        "recovered origin is limited to the one fixed C2 product",
    )


def validate_coordinates(value: Any) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "product_revision",
            "product_tree",
            "comparison_profile",
            "raw_checkpoint",
            "sealed_oci",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["product_revision"] == recovery.PRODUCT
        and value["product_tree"] == recovery.TREE
        and value["comparison_profile"] in {"historical", "clean-C2-server"},
        "unknown or unfrozen C2 recovery registration",
    )
    for role, job_key in (
        ("raw_checkpoint", "builder_job_id"),
        ("sealed_oci", "scan_job_id"),
    ):
        row = value[role]
        keys = {
            "controller_revision",
            "run_id",
            "attempt",
            job_key,
            "artifact_id",
            "zip_size",
            "zip_sha256",
        }
        if role == "sealed_oci":
            keys.add("seal_sha256")
        require(
            isinstance(row, dict) and set(row) == keys,
            "C2 producer coordinate has missing or unknown fields",
        )
        require(
            all(
                type(row[k]) is int and row[k] > 0
                for k in ("run_id", "attempt", job_key, "artifact_id", "zip_size")
            )
            and row["attempt"] == 1
            and row["zip_size"] <= 16 * 1024**3
            and isinstance(row["controller_revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", row["controller_revision"]) is not None
            and all(
                isinstance(row[k], str) and re.fullmatch(r"[0-9a-f]{64}", row[k])
                for k in ("zip_sha256", "seal_sha256")
                if k in row
            ),
            "C2 producer requires actual attempt-one coordinates and full hashes",
        )
        require(
            row["run_id"] != HISTORICAL["run_id"]
            and row["artifact_id"] != HISTORICAL["artifact_id"],
            "new recovery cannot masquerade as the historical PR artifact",
        )
    require(
        value["raw_checkpoint"]["artifact_id"] != value["sealed_oci"]["artifact_id"],
        "raw and sealed artifacts cannot be conflated",
    )
    return copy.deepcopy(value)


def dispatch_selection(
    profile: dict[str, Any], environ: dict[str, str] | None = None
) -> tuple[int, int] | None:
    """Only the two actual native run IDs are operator inputs; all other facts are derived."""
    env = os.environ if environ is None else environ
    raw = env.get("COMPAT018_RAW_RUN_ID", "")
    sealed = env.get("COMPAT018_SEALED_RUN_ID", "")
    if not raw and not sealed:
        return None
    exact_product(profile)
    require(
        isinstance(raw, str) and re.fullmatch(r"[1-9][0-9]{0,19}", raw) is not None,
        "C2 recovery requires one actual raw run ID",
    )
    sealed = sealed or raw
    require(
        isinstance(sealed, str) and re.fullmatch(r"[1-9][0-9]{0,19}", sealed) is not None,
        "C2 recovery sealed run ID is invalid",
    )
    require(
        int(raw) != HISTORICAL["run_id"] and int(sealed) != HISTORICAL["run_id"],
        "new C2 dispatch cannot relabel the historical PR run",
    )
    return int(raw), int(sealed)


def _unique(endpoint: str, collection: str, name: str) -> dict[str, Any]:
    response = api(endpoint + "?per_page=100")
    values = response.get(collection, [])
    require(
        type(response.get("total_count")) is int and response["total_count"] == len(values) <= 100,
        "C2 native producer listing is incomplete or exceeds its finite bound",
    )
    matches = [item for item in values if item.get("name") == name]
    require(len(matches) == 1, "C2 native producer name is not unique")
    return matches[0]


def _derive_row(
    control: Path, run_id: int, *, sealed: bool
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    run = api(f"repos/{recovery.REPOSITORY}/actions/runs/{run_id}")
    row = {"run_id": run_id, "attempt": 1, "controller_revision": run.get("head_sha")}
    require(
        isinstance(row["controller_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", row["controller_revision"]) is not None,
        "actual C2 native run has no full controller revision",
    )
    require(
        _run(row, sealed=sealed) == run,
        "C2 native run changed while deriving its identity",
    )
    code = _code(control, row["controller_revision"])
    key = "scan_job_id" if sealed else "builder_job_id"
    name = "scan-and-seal-same-oci" if sealed else "build-compat018-product"
    listed = _unique(
        f"repos/{recovery.REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs",
        "jobs",
        name,
    )
    require(
        type(listed.get("id")) is int and listed["id"] > 0,
        "actual C2 native job has no positive ID",
    )
    row[key] = listed["id"]
    artifact_name = (
        f"saas-oci-promotion-{recovery.PRODUCT}"
        if sealed
        else f"compat018-raw-{recovery.PRODUCT}-{run_id}"
    )
    artifact = _unique(
        f"repos/{recovery.REPOSITORY}/actions/runs/{run_id}/artifacts",
        "artifacts",
        artifact_name,
    )
    digest = artifact.get("digest", "")
    require(
        isinstance(digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
        and type(artifact.get("id")) is int
        and artifact["id"] > 0
        and type(artifact.get("size_in_bytes")) is int
        and 0 < artifact["size_in_bytes"] <= 16 * 1024**3,
        "actual C2 artifact has no bounded native ID, size and full SHA",
    )
    row.update(
        artifact_id=artifact["id"],
        zip_size=artifact["size_in_bytes"],
        zip_sha256=digest[7:],
    )
    return row, run, code


def _code(control: Path, revision: str) -> dict[str, str]:
    result = {}
    prefix = f"repos/{recovery.REPOSITORY}/contents/"
    for name in SOURCES:
        body = api(f"{prefix}{name}?ref={revision}")
        require(
            body.get("path") == name
            and body.get("encoding") == "base64"
            and type(body.get("size")) is int
            and 0 < body["size"] <= 262144,
            "native C2 controller source metadata differs",
        )
        raw = base64.b64decode("".join(body["content"].split()), validate=True)
        require(
            len(raw) == body["size"] and raw == (control / name).read_bytes(),
            "native C2 workflow/helper bytes differ from reviewed control",
        )
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def _run(row: dict[str, Any], *, sealed: bool) -> dict[str, Any]:
    run = api(f"repos/{recovery.REPOSITORY}/actions/runs/{row['run_id']}")
    require(
        run.get("id") == row["run_id"]
        and run.get("run_attempt") == 1
        and run.get("head_sha") == row["controller_revision"]
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == "main"
        and run.get("path") == recovery.WORKFLOW
        and run.get("repository", {}).get("full_name") == recovery.REPOSITORY
        and run.get("status") == "completed"
        and (
            run.get("conclusion") == "success"
            if sealed
            else run.get("conclusion") in {"success", "failure"}
        ),
        "C2 producer is not the actual reviewed native main run",
    )
    return run


def _job(
    row: dict[str, Any], key: str, name: str, required_steps: tuple[str, ...]
) -> dict[str, Any]:
    job = api(f"repos/{recovery.REPOSITORY}/actions/jobs/{row[key]}")
    require(
        job.get("id") == row[key]
        and job.get("run_id") == row["run_id"]
        and job.get("run_attempt") == 1
        and job.get("head_sha") == row["controller_revision"]
        and job.get("name") == name
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and "self-hosted" not in job.get("labels", []),
        "C2 has no successful exact hosted producer job",
    )
    numbers = []
    for step_name in required_steps:
        matches = [s for s in job.get("steps", []) if s.get("name") == step_name]
        require(
            len(matches) == 1
            and matches[0].get("status") == "completed"
            and matches[0].get("conclusion") == "success"
            and type(matches[0].get("number")) is int,
            "required C2 native producer step did not succeed exactly once",
        )
        numbers.append(matches[0]["number"])
    require(numbers == sorted(set(numbers)), "C2 producer steps are out of order")
    return job


def _artifact(row: dict[str, Any], name: str, job: dict[str, Any], upload: str) -> dict[str, Any]:
    metadata = api(f"repos/{recovery.REPOSITORY}/actions/artifacts/{row['artifact_id']}")
    require(
        metadata.get("id") == row["artifact_id"]
        and metadata.get("name") == name
        and metadata.get("size_in_bytes") == row["zip_size"]
        and metadata.get("digest") == "sha256:" + row["zip_sha256"]
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == row["run_id"]
        and metadata.get("workflow_run", {}).get("head_sha") == row["controller_revision"],
        "C2 artifact is not the registered actual producer bytes",
    )
    step = next(s for s in job["steps"] if s["name"] == upload)
    created = datetime.fromisoformat(metadata["created_at"])
    start = datetime.fromisoformat(step["started_at"])
    end = datetime.fromisoformat(step["completed_at"])
    require(start <= created <= end, "C2 artifact is outside its real upload interval")
    return metadata


def collect(
    control: Path,
    profile: dict[str, Any],
    run_ids: tuple[int, int],
    historical: dict[str, Any],
    destination: Path,
) -> dict[str, Any]:
    exact_product(profile)
    require(historical == HISTORICAL, "frozen six-key historical C2 registration changed")
    require(
        isinstance(run_ids, tuple)
        and len(run_ids) == 2
        and all(type(v) is int and v > 0 and v != HISTORICAL["run_id"] for v in run_ids),
        "C2 requires only two actual native attempt-one run IDs",
    )
    raw, raw_run, raw_code = _derive_row(control, run_ids[0], sealed=False)
    sealed, sealed_run, sealed_code = _derive_row(control, run_ids[1], sealed=True)
    code = {"raw": raw_code, "sealed": sealed_code}
    steps = [
        "Recover Server using its existing first-attempt build cache",
        "Recover Host using its existing first-attempt build cache",
        "Audit actual fixed C2 source, UI, and historical Host",
    ]
    steps += [
        "Confirm exact C2 comparison profile",
        "Preserve actual OCI before any fresh vulnerability scan",
    ]
    builder = _job(raw, "builder_job_id", "build-compat018-product", tuple(steps))
    scan_steps = (
        "Download and independently recheck the same real raw checkpoint",
        "Fresh scan and seal without rebuilding or relaxing any gate",
        "Retain actually admitted immutable OCI",
    )
    scanner = _job(sealed, "scan_job_id", "scan-and-seal-same-oci", scan_steps)
    raw_name = f"compat018-raw-{recovery.PRODUCT}-{raw['run_id']}"
    raw_metadata = _artifact(raw, raw_name, builder, steps[-1])
    artifact_name = f"saas-oci-promotion-{recovery.PRODUCT}"
    metadata = _artifact(sealed, artifact_name, scanner, scan_steps[-1])
    # Download the unique actual sealed ZIP before deriving comparison or seal facts.
    # No pre-registered or placeholder artifact ID/hash is accepted.
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "original-oci.zip"
    download_artifact_bytes(
        sealed["artifact_id"],
        archive,
        expected_size=sealed["zip_size"],
        expected_sha256=sealed["zip_sha256"],
    )
    verify_sealed_zip(archive, sealed["zip_size"], crc=True)
    with zipfile.ZipFile(archive) as bundle:
        for name in ("saas-image-candidate.json", "oci-promotion-manifest.json"):
            require(
                0 < bundle.getinfo(name).file_size <= 4 * 1024**2,
                "C2 JSON proof exceeds its finite bound",
            )
        candidate = json.loads(bundle.read("saas-image-candidate.json"))
        sealed["seal_sha256"] = hashlib.sha256(
            bundle.read("oci-promotion-manifest.json")
        ).hexdigest()
    comparison = candidate.get("clean_context_reproducibility", {}).get("comparison_profile")
    value = validate_coordinates(
        {
            "schema_version": 1,
            "product_revision": recovery.PRODUCT,
            "product_tree": recovery.TREE,
            "comparison_profile": comparison,
            "raw_checkpoint": raw,
            "sealed_oci": sealed,
        }
    )
    if value["comparison_profile"] == "clean-C2-server":
        complete_steps = (
            *steps[:3],
            "Independently build only C2 Server without cache",
            *steps[3:],
        )
        require(
            _job(raw, "builder_job_id", "build-compat018-product", complete_steps) == builder,
            "C2 raw builder changed during clean comparison validation",
        )
    upload = next(s for s in scanner["steps"] if s["name"] == scan_steps[-1])
    verify_job_artifact_identity(
        metadata,
        sealed_run,
        scanner,
        revision=sealed["controller_revision"],
        artifact_name=artifact_name,
        upload_step=upload,
        archive=archive,
    )
    for path, before in (
        (f"runs/{raw['run_id']}", raw_run),
        (f"runs/{sealed['run_id']}", sealed_run),
        (f"jobs/{builder['id']}", builder),
        (f"jobs/{scanner['id']}", scanner),
        (f"artifacts/{raw['artifact_id']}", raw_metadata),
        (f"artifacts/{sealed['artifact_id']}", metadata),
    ):
        require(
            api(f"repos/{recovery.REPOSITORY}/actions/{path}") == before,
            "C2 native producer changed during transfer",
        )
    result = {
        "kind": ORIGIN,
        "component": COMPONENT,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "run_id": sealed["run_id"],
        "attempt": 1,
        "job_id": scanner["id"],
        "artifact_id": sealed["artifact_id"],
        "artifact_name": artifact_name,
        "zip_size": sealed["zip_size"],
        "zip_sha256": sealed["zip_sha256"],
        "seal_sha256": sealed["seal_sha256"],
        "producer": value,
        "controller_sources": code,
        "native_actors": {
            "raw": raw_run.get("actor", {}).get("login"),
            "sealed": sealed_run.get("actor", {}).get("login"),
        },
        "historical_comparison": {
            "artifact_id": recovery.REPORT_ID,
            "zip_size": recovery.REPORT_SIZE,
            "zip_sha256": recovery.REPORT_SHA,
        },
        "sealed_zip_full_CRC_verified": True,
        "raw_bytes_verification_basis": "exact successful code-bound scan download and comparison",
    }
    validate_descriptor(result, profile)
    return result


def validate_descriptor(value: dict[str, Any], profile: dict[str, Any]) -> None:
    exact_product(profile)
    require(
        set(value)
        == {
            "kind",
            "component",
            "product_revision",
            "product_tree",
            "run_id",
            "attempt",
            "job_id",
            "artifact_id",
            "artifact_name",
            "zip_size",
            "zip_sha256",
            "seal_sha256",
            "producer",
            "controller_sources",
            "native_actors",
            "historical_comparison",
            "sealed_zip_full_CRC_verified",
            "raw_bytes_verification_basis",
        }
        and value.get("kind") == ORIGIN
        and value.get("component") == COMPONENT
        and value.get("product_revision") == recovery.PRODUCT
        and value.get("product_tree") == recovery.TREE
        and value.get("sealed_zip_full_CRC_verified") is True,
        "unverified or foreign recovered C2 descriptor",
    )
    registration = validate_coordinates(value["producer"])
    sealed = registration["sealed_oci"]
    require(
        all(
            value.get(k) == sealed[k]
            for k in (
                "run_id",
                "attempt",
                "artifact_id",
                "zip_size",
                "zip_sha256",
                "seal_sha256",
            )
        )
        and value.get("job_id") == sealed["scan_job_id"]
        and value.get("artifact_name") == f"saas-oci-promotion-{recovery.PRODUCT}",
        "C2 admission uses another actual producer coordinate",
    )
    require(
        value["historical_comparison"]
        == {
            "artifact_id": recovery.REPORT_ID,
            "zip_size": recovery.REPORT_SIZE,
            "zip_sha256": recovery.REPORT_SHA,
        }
        and value["raw_bytes_verification_basis"]
        == "exact successful code-bound scan download and comparison",
        "C2 historical evidence and actual raw verification roles differ",
    )
    require(
        set(value["controller_sources"]) == {"raw", "sealed"}
        and set(value["native_actors"]) == {"raw", "sealed"},
        "C2 controller or actor roles differ",
    )
    for role in ("raw", "sealed"):
        sources = value["controller_sources"].get(role, {})
        require(
            set(sources) == set(SOURCES)
            and all(
                isinstance(s, str) and re.fullmatch(r"[0-9a-f]{64}", s) for s in sources.values()
            )
            and isinstance(value["native_actors"].get(role), str)
            and bool(value["native_actors"][role]),
            "C2 controller source or native actor is incomplete",
        )


def verify_payload(root: Path, descriptor: dict[str, Any], product: Path) -> None:
    """Recheck the actual first bytes; Server2 belongs to the bound hosted builder."""
    from saas.scripts import compat018_clean_context as clean

    profile = {
        "component": COMPONENT,
        "product_revision": recovery.PRODUCT,
        "product_tree": recovery.TREE,
        "source_date_epoch": recovery.EPOCH,
    }
    validate_descriptor(descriptor, profile)
    first = clean.verify_first(root, product)
    stored = json.loads((root / "clean-context-first.json").read_text())
    native = stored.pop("native_builder", None)
    raw = descriptor["producer"]["raw_checkpoint"]
    require(
        first == stored
        and native
        == {
            "workflow_path": recovery.WORKFLOW,
            "controller_revision": raw["controller_revision"],
            "run_id": raw["run_id"],
            "attempt": 1,
            "job_name": "build-compat018-product",
            "actor": descriptor["native_actors"]["raw"],
        },
        "actual C2 first proof is not the registered native raw builder",
    )
    candidate = json.loads((root / "saas-image-candidate.json").read_text())
    original, _, _ = recovery.original_evidence(root / "original-report.zip")
    proof = candidate.get("clean_context_reproducibility", {})
    comparison_profile = descriptor["producer"]["comparison_profile"]
    require(
        set(proof)
        == {
            "kind",
            "comparison_profile",
            "native_builder",
            "product_revision",
            "product_tree",
            "source_date_epoch",
            "historical_comparison",
            "first_proof_sha256",
            "independent_Server_archive_sha256",
            "old_Server_byte_identity_claimed",
            "new_Host_matches_historical_independent_pair",
        }
        and proof.get("kind") == clean.KIND
        and proof.get("comparison_profile") == comparison_profile
        and proof.get("product_revision") == recovery.PRODUCT
        and proof.get("product_tree") == recovery.TREE
        and proof.get("source_date_epoch") == recovery.EPOCH
        and proof.get("native_builder") == native
        and proof.get("historical_comparison") == first["historical_comparison"]
        and proof.get("first_proof_sha256") == recovery.sha256(root / "clean-context-first.json")
        and proof.get("old_Server_byte_identity_claimed") is (comparison_profile == "historical")
        and proof.get("new_Host_matches_historical_independent_pair") is True
        and candidate.get("product_revision") == recovery.PRODUCT
        and candidate.get("source_date_epoch") == recovery.EPOCH
        and candidate.get("upstream_revision") == recovery.UPSTREAM
        and candidate.get("status") == "pass"
        and candidate.get("violations") == []
        and set(candidate.get("images", {})) == {"omnigent-saas-server", "omnigent-saas-host"}
        and candidate["images"]["omnigent-saas-host"] == original["images"]["omnigent-saas-host"],
        "C2 admitted comparison/proof/original Host roles differ",
    )
    server = candidate["images"]["omnigent-saas-server"]
    require(
        server.get("first") == first["facts"]["server"]
        and server.get("second", {}).get("platforms") == first["facts"]["server"]["platforms"]
        and server.get("second", {}).get("attestations")
        == first["facts"]["server"]["attestations"]
        and server.get("matching_platform_manifest_and_config") is True
        and server.get("history_created_by_equal") is True,
        "C2 sealed bytes differ from the actual independent comparison",
    )
    if comparison_profile == "historical":
        require(
            first["historical_Server_facts_equal"] is True
            and server == original["images"]["omnigent-saas-server"]
            and proof.get("independent_Server_archive_sha256") is None,
            "historical comparison is not the original independent Server pair",
        )
    else:
        independent = proof.get("independent_Server_archive_sha256")
        require(
            isinstance(independent, str)
            and re.fullmatch(r"[0-9a-f]{64}", independent) is not None,
            "clean comparison has no actual independent Server archive hash",
        )
    require(
        recovery.sha256(root / "oci-promotion-manifest.json") == descriptor["seal_sha256"],
        "C2 source descriptor seal does not match actual manifest bytes",
    )
