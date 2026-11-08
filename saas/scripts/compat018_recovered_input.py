"""Draft finite C2 recovery origin; never relabel a new producer as the old PR."""

from __future__ import annotations

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
# Finite conservative import closure and the existing scan gate policies.
SOURCES = (
    "saas/actions/runtime-evidence-context/action.yml",
    ".github/workflows/saas-compat018-oci-recovery.yml",
    "saas/__init__.py",
    "saas/compatibility/__init__.py",
    "saas/compatibility/runtime_partition.py",
    "saas/compatibility/store_adapter.py",
    "saas/control_plane/__init__.py",
    "saas/control_plane/api_credential_models.py",
    "saas/control_plane/api_credentials.py",
    "saas/control_plane/api_http.py",
    "saas/control_plane/approval_operations.py",
    "saas/control_plane/approval_scheduler.py",
    "saas/control_plane/approval_source_adapters.py",
    "saas/control_plane/approval_source_projection.py",
    "saas/control_plane/authorization.py",
    "saas/control_plane/billing.py",
    "saas/control_plane/billing_http.py",
    "saas/control_plane/billing_metering.py",
    "saas/control_plane/billing_models.py",
    "saas/control_plane/binding_saga.py",
    "saas/control_plane/bindings.py",
    "saas/control_plane/certificate_models.py",
    "saas/control_plane/certificates.py",
    "saas/control_plane/client_network.py",
    "saas/control_plane/context_snapshot.py",
    "saas/control_plane/db_models.py",
    "saas/control_plane/dispatch_binding.py",
    "saas/control_plane/email_provider.py",
    "saas/control_plane/enterprise_access.py",
    "saas/control_plane/enterprise_http.py",
    "saas/control_plane/enterprise_identity.py",
    "saas/control_plane/enterprise_identity_models.py",
    "saas/control_plane/enterprise_models.py",
    "saas/control_plane/enterprise_scim_http.py",
    "saas/control_plane/execution.py",
    "saas/control_plane/execution_models.py",
    "saas/control_plane/gateway_models.py",
    "saas/control_plane/gateways.py",
    "saas/control_plane/governance.py",
    "saas/control_plane/http_auth.py",
    "saas/control_plane/idempotency.py",
    "saas/control_plane/identity.py",
    "saas/control_plane/isolation.py",
    "saas/control_plane/isolation_models.py",
    "saas/control_plane/lifecycle.py",
    "saas/control_plane/member_admin.py",
    "saas/control_plane/member_http.py",
    "saas/control_plane/model_budget.py",
    "saas/control_plane/model_provider.py",
    "saas/control_plane/notification_delivery.py",
    "saas/control_plane/notification_events.py",
    "saas/control_plane/notification_http.py",
    "saas/control_plane/notification_models.py",
    "saas/control_plane/oidc.py",
    "saas/control_plane/onboarding.py",
    "saas/control_plane/onboarding_http.py",
    "saas/control_plane/onboarding_models.py",
    "saas/control_plane/onboarding_status.py",
    "saas/control_plane/onboarding_workflow.py",
    "saas/control_plane/outbox.py",
    "saas/control_plane/outbox_delivery.py",
    "saas/control_plane/outbox_delivery_models.py",
    "saas/control_plane/permissions.py",
    "saas/control_plane/placement_models.py",
    "saas/control_plane/placements.py",
    "saas/control_plane/platform_governed_access.py",
    "saas/control_plane/platform_governed_models.py",
    "saas/control_plane/platform_http.py",
    "saas/control_plane/platform_lifecycle.py",
    "saas/control_plane/platform_models.py",
    "saas/control_plane/platform_notification_http.py",
    "saas/control_plane/platform_password_auth.py",
    "saas/control_plane/platform_security.py",
    "saas/control_plane/platform_support_http.py",
    "saas/control_plane/postgresql_role_authority.py",
    "saas/control_plane/preview_hosts.py",
    "saas/control_plane/preview_sessions.py",
    "saas/control_plane/privacy_attestation.py",
    "saas/control_plane/privacy_execution.py",
    "saas/control_plane/privacy_lifecycle.py",
    "saas/control_plane/privacy_models.py",
    "saas/control_plane/privacy_operations.py",
    "saas/control_plane/project_http.py",
    "saas/control_plane/projects.py",
    "saas/control_plane/public_api.py",
    "saas/control_plane/public_api_models.py",
    "saas/control_plane/removal_impact.py",
    "saas/control_plane/resolver.py",
    "saas/control_plane/rls.py",
    "saas/control_plane/rls_inventory.py",
    "saas/control_plane/runner_execution_spec.py",
    "saas/control_plane/runtime_provider.py",
    "saas/control_plane/runtime_provider_journal.py",
    "saas/control_plane/scheduling.py",
    "saas/control_plane/scheduling_models.py",
    "saas/control_plane/scim_syntax.py",
    "saas/control_plane/webhook_models.py",
    "saas/control_plane/webhooks.py",
    "saas/control_plane/worktree_models.py",
    "saas/control_plane/worktrees.py",
    "saas/login_ui/__init__.py",
    "saas/login_ui/http.py",
    "saas/observability.py",
    "saas/onboarding_composition.py",
    "saas/onboarding_email.py",
    "saas/preview_gateway.py",
    "saas/preview_relay_transport.py",
    "saas/preview_tunnel.py",
    "saas/production/__init__.py",
    "saas/production/admission.py",
    "saas/production/business.py",
    "saas/production/deletion.py",
    "saas/production/deployment.py",
    "saas/production/evidence-admission-policy.json",
    "saas/production/legacy_publication.py",
    "saas/production/legacy_stack.py",
    "saas/production/observability.py",
    "saas/production/readiness.py",
    "saas/production/recovery.py",
    "saas/production/review_exception.py",
    "saas/production/slo_capacity.py",
    "saas/production/slo_witness.py",
    "saas/public_api_contract.py",
    "saas/runtime_rls/__init__.py",
    "saas/runtime_rls/installer.py",
    "saas/scim_schema_catalog.py",
    "saas/scripts/__init__.py",
    "saas/scripts/approved_disposition.py",
    "saas/scripts/check_acceptance_manifest.py",
    "saas/scripts/check_adr_approvals.py",
    "saas/scripts/check_image_supply_chain.py",
    "saas/scripts/check_production_baseline.py",
    "saas/scripts/combined_runtime_disposition.py",
    "saas/scripts/compare_oci_rebuilds.py",
    "saas/scripts/compat018_clean_context.py",
    "saas/scripts/compat018_oci_recovery.py",
    "saas/scripts/compat018_recovered_input.py",
    "saas/scripts/legacy_artifact_download.py",
    "saas/scripts/legacy_build_controller.py",
    "saas/scripts/legacy_check_history.py",
    "saas/scripts/legacy_control_results.py",
    "saas/scripts/legacy_domain_discovery.py",
    "saas/scripts/legacy_domain_eligibility.py",
    "saas/scripts/legacy_domain_native.py",
    "saas/scripts/legacy_domain_non_execution.py",
    "saas/scripts/legacy_initial_publisher.py",
    "saas/scripts/legacy_job_log_archive.py",
    "saas/scripts/legacy_native_evidence.py",
    "saas/scripts/legacy_pg_contract.py",
    "saas/scripts/legacy_pr_candidate.py",
    "saas/scripts/legacy_publication_reader.py",
    "saas/scripts/legacy_publication_renewal.py",
    "saas/scripts/legacy_pytest_results.py",
    "saas/scripts/legacy_security_policy.py",
    "saas/scripts/legacy_source_ci.py",
    "saas/scripts/legacy_source_qualification.py",
    "saas/scripts/oci_promotion.py",
    "saas/scripts/prepare_evidence_receipt.py",
    "saas/scripts/protected_legacy_initial_build.py",
    "saas/scripts/resume_oci_promotion.py",
    "saas/scripts/runtime_evidence_intake.py",
    "saas/scripts/scan_oci_candidates.py",
    "saas/scripts/sqlite_component_disposition.py",
    "saas/supply_chain/release-policy.json",
    "saas/supply_chain/runtime-condition-inputs.json",
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
        and value["comparison_profile"] in {"historical", "clean-C2-server", "clean-C2-pair"},
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
    revision = run.get("head_sha")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("actual C2 native run has no full controller revision")
    row = {"run_id": run_id, "attempt": 1, "controller_revision": revision}
    require(
        _run(row, sealed=sealed) == run,
        "C2 native run changed while deriving its identity",
    )
    code = _code(control, revision)
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
    prefix = f"repos/{recovery.REPOSITORY}/git/"
    commit = api(f"{prefix}commits/{revision}")
    tree_sha = commit.get("tree", {}).get("sha")
    require(
        commit.get("sha") == revision
        and isinstance(tree_sha, str)
        and re.fullmatch(r"[0-9a-f]{40}", tree_sha) is not None,
        "native C2 commit has no immutable source tree",
    )
    tree = api(f"{prefix}trees/{tree_sha}?recursive=1")
    entries = tree.get("tree", [])
    require(
        tree.get("sha") == tree_sha
        and tree.get("truncated") is False
        and isinstance(entries, list)
        and 0 < len(entries) <= 20000,
        "native C2 execution tree metadata is incomplete",
    )
    result = {}
    for name in SOURCES:
        matches = [entry for entry in entries if entry.get("path") == name]
        require(len(matches) == 1, "native C2 execution source is missing or duplicated")
        entry = matches[0]
        path = control / name
        require(
            path.is_file() and not path.is_symlink(), "reviewed C2 execution source is missing"
        )
        raw = path.read_bytes()
        mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        blob_sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(
            len(raw) <= 262144
            and entry.get("type") == "blob"
            and entry.get("mode") == mode
            and entry.get("size") == len(raw)
            and entry.get("sha") == blob_sha,
            f"native C2 execution source differs from reviewed control: {name}",
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
        "Audit actual fixed C2 source, UI, and historical Host",
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
    paired = value["comparison_profile"] == "clean-C2-pair"
    first_steps = (
        ("Authenticate and load the exact retained first pair without rebuilding it",)
        if paired
        else (
            "Recover Server using its existing first-attempt build cache",
            "Recover Host using its existing first-attempt build cache",
        )
    )
    second_steps = (
        ()
        if value["comparison_profile"] == "historical"
        else (
            "Independently build only C2 Server without cache",
            *(("Independently build C2 Host without cache",) if paired else ()),
        )
    )
    complete_steps = (*first_steps, steps[0], *second_steps, *steps[1:])
    require(
        _job(raw, "builder_job_id", "build-compat018-product", complete_steps) == builder,
        "C2 raw builder changed during clean comparison validation",
    )
    if paired:
        for name in (
            "Recover Server using its existing first-attempt build cache",
            "Recover Host using its existing first-attempt build cache",
        ):
            matches = [s for s in builder["steps"] if s.get("name") == name]
            require(
                len(matches) == 1 and matches[0].get("conclusion") == "skipped",
                "retained C2 first pair was rebuilt",
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
    comparison_profile = descriptor["producer"]["comparison_profile"]
    paired = comparison_profile == clean.PAIR_PROFILE
    first = clean.first_for_profile(root, product, comparison_profile)
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
    keys = {
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
    if paired:
        keys.update(
            {
                "independent_Host_archive_sha256",
                "old_Host_byte_identity_claimed",
                "historical_Host_facts",
                "retained_first_input",
            }
        )
    require(
        set(proof) == keys
        and proof.get("kind") == (clean.PAIR_KIND if paired else clean.KIND)
        and proof.get("comparison_profile") == comparison_profile
        and proof.get("product_revision") == recovery.PRODUCT
        and proof.get("product_tree") == recovery.TREE
        and proof.get("source_date_epoch") == recovery.EPOCH
        and proof.get("native_builder") == native
        and proof.get("historical_comparison") == first["historical_comparison"]
        and proof.get("first_proof_sha256") == recovery.sha256(root / "clean-context-first.json")
        and proof.get("old_Server_byte_identity_claimed") is (comparison_profile == "historical")
        and proof.get("new_Host_matches_historical_independent_pair")
        is first["new_Host_matches_historical_independent_pair"]
        and candidate.get("product_revision") == recovery.PRODUCT
        and candidate.get("source_date_epoch") == recovery.EPOCH
        and candidate.get("upstream_revision") == recovery.UPSTREAM
        and candidate.get("status") == "pass"
        and candidate.get("violations") == []
        and set(candidate.get("images", {})) == {"omnigent-saas-server", "omnigent-saas-host"},
        "C2 admitted comparison/proof/original Host roles differ",
    )
    host = candidate["images"]["omnigent-saas-host"]
    if paired:
        independent_host = proof.get("independent_Host_archive_sha256")
        require(
            isinstance(independent_host, str)
            and re.fullmatch(r"[0-9a-f]{64}", independent_host) is not None
            and proof.get("old_Host_byte_identity_claimed") is False
            and proof.get("historical_Host_facts") == original["images"]["omnigent-saas-host"]
            and proof.get("retained_first_input") == recovery.RETAINED_FIRST
            and host.get("first") == first["facts"]["host"]
            and host.get("second", {}).get("platforms") == first["facts"]["host"]["platforms"]
            and host.get("second", {}).get("attestations")
            == first["facts"]["host"]["attestations"]
            and host.get("matching_platform_manifest_and_config") is True
            and host.get("history_created_by_equal") is True,
            "C2 Host has no actual independent pair or retained native origin",
        )
    else:
        require(
            first["new_Host_matches_historical_independent_pair"] is True
            and host == original["images"]["omnigent-saas-host"],
            "C2 historical Host pair differs",
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
