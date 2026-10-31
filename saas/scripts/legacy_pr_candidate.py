"""Bind unsigned PR OCI inputs and a fresh protected-control wheel separately.

These checks do not qualify the other source workflows, native PostgreSQL or
production admission. The publisher must also inspect and scan the exact OCI
bytes with the existing promotion helpers before signing them.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any, cast

from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_source_ci import (
    _job_pages,
    checkout_commit,
    download_job_log,
    verify_run_pull_request,
)
from saas.scripts.oci_promotion import (
    expected_labels,
    extract_artifact,
    require,
    verify_candidate,
)
from saas.scripts.protected_legacy_initial_build import (
    REPOSITORY,
    load_profile,
    provenance,
    validate_profile,
    verify_native_statement,
    verify_pr_tree,
    verify_source_delta,
)

CANDIDATE_WORKFLOW = ".github/workflows/saas-image-candidate.yml"
UPLOAD_STEP = "Retain sealed OCI for frozen legacy validation"
VALIDATION_REFS = {
    "Core": "codex/legacy-validation-core-dc1e9a97",
    "Gateway": "codex/legacy-validation-gateway-3319b59a",
    "Model": "codex/legacy-validation-model-7cea0940",
}
_REQUIRED_STEPS = (
    "Checkout immutable candidate",
    "Verify exact candidate revision",
    "Verify migrations and downstream compatibility",
    "Run current-revision OSS and SaaS regressions",
    "Build server candidate attempt 1",
    "Preflight scan exact server candidate on both architectures",
    "Build server candidate attempt 2",
    "Build host candidate attempt 1",
    "Build host candidate attempt 2",
    "Compare repeated executable image facts",
    "Scan exact OCI candidates on both architectures",
    "Seal exact admitted OCI archives and raw scan evidence",
    UPLOAD_STEP,
)
_HEX256 = re.compile(r"[0-9a-f]{64}")


def load_transfer_profile(control: Path, component: str) -> dict[str, Any]:
    """Only trusted control code may register a validation PR and workflow bytes."""
    path = control / "saas/supply_chain/legacy-security-transfer-profiles.json"
    require(path.is_file() and not path.is_symlink(), "missing reviewed transfer profiles")
    store = json.loads(path.read_text())
    require(
        set(store) == {"schema_version", "profiles"}
        and type(store["schema_version"]) is int
        and store["schema_version"] == 1
        and isinstance(store["profiles"], dict)
        and component in store["profiles"],
        "no reviewed legacy PR transfer profile",
    )
    result = store["profiles"][component]
    validate_transfer_profile(result, component)
    return result


def validate_transfer_profile(value: dict[str, Any], component: str) -> None:
    require(
        isinstance(value, dict)
        and set(value) == {"component", "pull_number", "base_ref", "workflow_sha256", "actor"}
        and component in VALIDATION_REFS
        and value["component"] == component
        and value["base_ref"] == VALIDATION_REFS[component]
        and type(value["pull_number"]) is int
        and value["pull_number"] > 0
        and isinstance(value["workflow_sha256"], str)
        and _HEX256.fullmatch(value["workflow_sha256"]) is not None,
        "unreviewed validation PR or workflow coordinate",
    )
    require(
        isinstance(value["actor"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\[bot\])?", value["actor"]) is not None,
        "missing reviewed native PR actor",
    )


def verify_pr_oci_artifact(
    metadata: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    profile: dict[str, Any],
    transfer: dict[str, Any],
    pull: dict[str, Any],
    merge_commit: dict[str, Any],
    workflow_bytes: bytes,
    checkout_log: str,
    artifact_id: int,
    zip_size: int,
    zip_sha256: str,
    seal_sha256: str,
) -> dict[str, Any]:
    """Use authenticated API records and logs, never API JSON from the artifact."""
    component = profile["component"]
    validate_profile(profile, component)
    validate_transfer_profile(transfer, component)
    merge = verify_pr_tree(
        pull,
        merge_commit,
        profile,
        number=transfer["pull_number"],
        base_ref=transfer["base_ref"],
    )
    require(
        hashlib.sha256(workflow_bytes).hexdigest() == transfer["workflow_sha256"],
        "source candidate workflow bytes differ",
    )
    require(
        run.get("path") == CANDIDATE_WORKFLOW
        and run.get("event") == "pull_request"
        and run.get("head_sha") == profile["product_revision"]
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and all(type(run.get(key)) is int and run[key] > 0 for key in ("id", "run_attempt")),
        "original PR OCI run is not a successful exact-source run",
    )
    verify_run_pull_request(run, profile, transfer["pull_number"])
    require(
        isinstance(pull.get("head", {}).get("ref"), str)
        and bool(pull["head"]["ref"])
        and run.get("head_branch") == pull["head"]["ref"]
        and run.get("actor", {}).get("login") == transfer["actor"]
        and run.get("triggering_actor", {}).get("login") == transfer["actor"],
        "PR OCI run used another branch or native actor",
    )
    require(
        type(job.get("id")) is int
        and job["id"] > 0
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("head_sha") == profile["product_revision"]
        and job.get("name") == "build-candidate"
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-latest" in job.get("labels", [])
        and "self-hosted" not in job.get("labels", []),
        "PR OCI build job differs from the original hosted execution",
    )
    steps = job.get("steps")
    require(
        isinstance(steps, list) and all(isinstance(step, dict) for step in steps),
        "native candidate steps are missing",
    )
    steps = cast(list[dict[str, Any]], steps)
    selected = []
    for name in _REQUIRED_STEPS:
        matching = [step for step in steps if step.get("name") == name]
        require(len(matching) == 1, "required native OCI step is missing or ambiguous")
        step = matching[0]
        require(
            step.get("status") == "completed"
            and step.get("conclusion") == "success"
            and type(step.get("number")) is int,
            "required native OCI step did not succeed",
        )
        selected.append(step)
    numbers = [step["number"] for step in selected]
    require(
        numbers == sorted(set(numbers)),
        "native OCI upload preceded its required admission",
    )
    require(
        checkout_commit(checkout_log, selected[0]) == profile["product_revision"],
        "OCI build did not actually checkout the exact product SHA",
    )
    require(
        all(
            isinstance(value, str) and _HEX256.fullmatch(value) is not None
            for value in (zip_sha256, seal_sha256)
        ),
        "invalid PR OCI input digest",
    )
    name = (
        f"legacy-validation-oci-{component}-{profile['product_revision']}-"
        f"{run['id']}-{run['run_attempt']}"
    )
    require(
        type(artifact_id) is int
        and artifact_id > 0
        and type(zip_size) is int
        and zip_size > 0
        and metadata.get("id") == artifact_id
        and metadata.get("name") == name
        and metadata.get("expired") is False
        and metadata.get("size_in_bytes") == zip_size
        and metadata.get("digest") == "sha256:" + zip_sha256
        and metadata.get("workflow_run", {}).get("id") == run["id"]
        and metadata.get("workflow_run", {}).get("head_sha") == profile["product_revision"],
        "PR OCI artifact does not bind its original run, attempt and bytes",
    )
    return {
        "kind": "legacy_pr_sealed_oci/v1",
        "component": component,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "baseline_revision": profile["baseline_revision"],
        "pull_number": transfer["pull_number"],
        "base_ref": transfer["base_ref"],
        "merge_revision": merge,
        "workflow_path": CANDIDATE_WORKFLOW,
        "workflow_sha256": transfer["workflow_sha256"],
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "artifact_id": artifact_id,
        "zip_size": zip_size,
        "zip_sha256": zip_sha256,
        "seal_sha256": seal_sha256,
        "actor": transfer["actor"],
    }


def transfer_provenance(
    profile: dict[str, Any],
    *,
    original_oci: dict[str, Any],
    transfer: dict[str, Any],
    control_revision: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_sha256: str,
    seal_sha256: str,
    wheel_sha256: str,
) -> dict[str, Any]:
    """Keep the new PR input variant separate from the original control-run input."""
    validate_transfer_profile(transfer, profile["component"])
    required = {
        "kind",
        "component",
        "product_revision",
        "product_tree",
        "baseline_revision",
        "pull_number",
        "base_ref",
        "merge_revision",
        "workflow_path",
        "workflow_sha256",
        "run_id",
        "attempt",
        "job_id",
        "artifact_id",
        "zip_size",
        "zip_sha256",
        "seal_sha256",
        "actor",
    }
    require(
        set(original_oci) == required and original_oci["kind"] == "legacy_pr_sealed_oci/v1",
        "unknown original OCI transfer variant",
    )
    for key in ("component", "product_revision", "product_tree", "baseline_revision"):
        require(original_oci[key] == profile[key], "original OCI product or role differs")
    for key in ("pull_number", "base_ref", "workflow_sha256", "actor"):
        require(
            original_oci[key] == transfer[key],
            "original OCI validation profile differs",
        )
    require(
        original_oci["workflow_path"] == CANDIDATE_WORKFLOW
        and original_oci["run_id"] != run_id
        and original_oci["artifact_id"] != artifact_id
        and all(
            type(original_oci[key]) is int and original_oci[key] > 0
            for key in ("run_id", "attempt", "job_id", "artifact_id", "zip_size")
        )
        and all(
            isinstance(original_oci[key], str) and _HEX256.fullmatch(original_oci[key]) is not None
            for key in ("zip_sha256", "seal_sha256")
        )
        and isinstance(original_oci["merge_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", original_oci["merge_revision"]) is not None
        and original_oci["seal_sha256"] == seal_sha256,
        "original OCI and fresh control wheel input identities are conflated",
    )
    result = provenance(
        profile,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        seal_sha256=seal_sha256,
        wheel_sha256=wheel_sha256,
    )
    parameters = result["buildDefinition"]["externalParameters"]
    parameters["input_variant"] = "original_pr_oci_and_fresh_control_wheel/v1"
    parameters["original_pr_oci"] = copy.deepcopy(original_oci)
    parameters["fresh_control_wheel"] = {
        "run_id": run_id,
        "attempt": attempt,
        "job": "build-initial",
        "artifact_id": artifact_id,
        "zip_sha256": zip_sha256,
        "wheel_sha256": wheel_sha256,
        "control_revision": control_revision,
        "product_revision": profile["product_revision"],
    }
    result["buildDefinition"]["resolvedDependencies"].append(
        {
            "uri": f"https://github.com/{REPOSITORY}/actions/artifacts/{original_oci['artifact_id']}",
            "digest": {"sha256": original_oci["zip_sha256"]},
        }
    )
    return result


def collect_native_pr_oci(
    control: Path,
    component: str,
    *,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_size: int,
    zip_sha256: str,
    seal_sha256: str,
    destination: Path,
) -> dict[str, Any]:
    """Read original inputs directly from GitHub and reject subsequent PR drift."""
    require(
        all(
            type(value) is int and value > 0 for value in (run_id, attempt, artifact_id, zip_size)
        ),
        "invalid native PR input coordinates",
    )
    profile = load_profile(control, component)
    transfer = load_transfer_profile(control, component)
    endpoint = f"repos/{REPOSITORY}/pulls/{transfer['pull_number']}"
    pull = api(endpoint)
    merge = pull.get("merge_commit_sha")
    require(
        isinstance(merge, str) and re.fullmatch(r"[0-9a-f]{40}", merge) is not None,
        "native PR merge coordinate missing",
    )
    commit = api(f"repos/{REPOSITORY}/git/commits/{merge}")
    verify_pr_tree(
        pull,
        commit,
        profile,
        number=transfer["pull_number"],
        base_ref=transfer["base_ref"],
    )
    source = api(f"repos/{REPOSITORY}/contents/{CANDIDATE_WORKFLOW}?ref={merge}")
    require(
        source.get("path") == CANDIDATE_WORKFLOW
        and source.get("encoding") == "base64"
        and type(source.get("size")) is int
        and 0 < source["size"] <= 262144,
        "native candidate workflow record differs",
    )
    body = base64.b64decode("".join(source["content"].split()), validate=True)
    require(len(body) == source["size"], "native candidate workflow size differs")
    run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    require(
        run.get("id") == run_id and run.get("run_attempt") == attempt,
        "native PR run response differs from requested attempt",
    )
    jobs = _job_pages(run_id, attempt)
    build = [job for job in jobs if job.get("name") == "build-candidate"]
    require(len(build) == 1, "native PR OCI build job is missing or ambiguous")
    metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    log_path = destination / f"job-{build[0]['id']}.log"
    download_job_log(build[0]["id"], log_path)
    observation = verify_pr_oci_artifact(
        metadata,
        run,
        build[0],
        profile=profile,
        transfer=transfer,
        pull=pull,
        merge_commit=commit,
        workflow_bytes=body,
        checkout_log=log_path.read_text(),
        artifact_id=artifact_id,
        zip_size=zip_size,
        zip_sha256=zip_sha256,
        seal_sha256=seal_sha256,
    )
    latest = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(
        all(
            latest.get(key) == run.get(key)
            for key in (
                "id",
                "run_attempt",
                "head_sha",
                "event",
                "path",
                "status",
                "conclusion",
            )
        ),
        "newer PR run attempt invalidates the original input",
    )
    refreshed = api(endpoint)
    verify_pr_tree(
        refreshed,
        commit,
        profile,
        number=transfer["pull_number"],
        base_ref=transfer["base_ref"],
    )
    result = {
        "original_oci": observation,
        "native_run": run,
        "native_jobs": jobs,
        "native_artifact": metadata,
        "native_PR": refreshed,
        "native_merge_commit": commit,
        "workflow_sha256": hashlib.sha256(body).hexdigest(),
        "checkout_log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
        "complete_source_CI_PG_image_production_admission": False,
    }
    (destination / "native-PR-OCI-input.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def verify_transferred_oci(
    archive: Path,
    root: Path,
    *,
    product_checkout: Path,
    profile: dict[str, Any],
    original_oci: dict[str, Any],
    current_scan_root: Path | None = None,
) -> dict[str, Any]:
    """Reinspect original bytes and fresh scans without running product code."""
    verify_source_delta(product_checkout, profile)
    for key in ("component", "product_revision", "product_tree", "baseline_revision"):
        require(original_oci.get(key) == profile[key], "transferred OCI product differs")
    require(
        original_oci.get("kind") == "legacy_pr_sealed_oci/v1"
        and archive.is_file()
        and not archive.is_symlink()
        and archive.stat().st_size == original_oci.get("zip_size"),
        "transferred original OCI archive size or kind differs",
    )
    files = {
        "server-1.tar",
        "host-1.tar",
        "oci-promotion-manifest.json",
        "saas-image-candidate.json",
        "grype/candidate-scan-summary.json",
    }
    files.update(
        f"grype/{image}-{arch}-grype.json"
        for image in ("server", "host")
        for arch in ("amd64", "arm64")
    )
    with zipfile.ZipFile(archive) as bundle:
        entries = [item for item in bundle.infolist() if not item.is_dir()]
        require(
            len(entries) == len(files) and {item.filename for item in entries} == files,
            "original OCI artifact has missing or extra payloads",
        )
        require(
            all(
                item.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                for item in entries
            )
            and sum(item.file_size for item in entries) <= archive.stat().st_size,
            "original OCI artifact is not the reviewed uncompressed upload",
        )
    extract_artifact(archive, root, zip_sha256=original_oci["zip_sha256"])
    return verify_candidate(
        root,
        manifest_sha256=original_oci["seal_sha256"],
        labels=expected_labels(product_checkout, profile["product_revision"]),
        source_date_epoch=profile["source_date_epoch"],
        current_scan_root=current_scan_root,
    )


def verify_transfer_attestation(
    subject: str,
    *,
    digest: str,
    profile: dict[str, Any],
    original_oci: dict[str, Any],
    transfer: dict[str, Any],
    control_revision: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_sha256: str,
    seal_sha256: str,
    wheel_sha256: str,
) -> None:
    """Do not reinterpret the old single-control-run predicate as this variant."""
    predicate = transfer_provenance(
        profile,
        original_oci=original_oci,
        transfer=transfer,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        seal_sha256=seal_sha256,
        wheel_sha256=wheel_sha256,
    )
    verify_native_statement(
        subject,
        digest=digest,
        predicate=predicate,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
    )
