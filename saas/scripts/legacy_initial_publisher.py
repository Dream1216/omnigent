"""Publish exact reviewed legacy inputs through separated native control jobs.

Every cross-job input is downloaded using authenticated native metadata and
rechecked against the exact main workflow, job, upload interval and original ZIP.
Only the runtime command executes product code; its job has read permissions.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_build_controller import (
    control_context,
    download_fresh_wheel,
    download_original_oci,
    load_original_inputs,
    verify_wheel_bundle,
)
from saas.scripts.legacy_check_history import _pages
from saas.scripts.legacy_control_results import collect_pg_receipts, verify_control_run
from saas.scripts.legacy_native_evidence import api, preserve_native_evidence
from saas.scripts.legacy_pr_candidate import (
    UPLOAD_STEP,
    load_transfer_profile,
    transfer_provenance,
)
from saas.scripts.legacy_pytest_results import verify_job_artifact_identity
from saas.scripts.legacy_source_ci import _job_pages, checkout_commit, download_job_log
from saas.scripts.legacy_source_qualification import qualify_source_ci
from saas.scripts.oci_promotion import (
    IMAGES,
    PLATFORMS,
    expected_labels,
    extract_layout,
    read_json,
    require,
    validate_scans,
    verify_candidate,
    verify_readback,
)
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    REPOSITORY,
    WORKFLOW,
    load_profile,
    verify_native_statement,
    verify_source_delta,
)
from saas.scripts.resume_oci_promotion import (
    BUILD_TYPE,
    SPDX_PREDICATE_TYPE,
    verify_sbom,
)
from saas.scripts.scan_oci_candidates import file_sha256

PREFIX = f"repos/{REPOSITORY}"
VARIANT = "protected_legacy_initial_publication/v2"
SYFT_VERSION = "1.54.1"
SYFT_SHA256 = "c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47"
CHECKOUT = "Checkout exact main publication control"
PRODUCT_CHECKOUT = "Checkout exact publication product"
RUN_STEPS = {
    "prepare-publication": (
        CHECKOUT,
        "Select registered publication product",
        PRODUCT_CHECKOUT,
        "Prepare original native inputs and fresh raw scans",
        "Retain publication preparation",
    ),
    "publish-exact-oci": (
        CHECKOUT,
        "Select registered publication product",
        PRODUCT_CHECKOUT,
        "Publish exact OCI and verify registry readback",
        "Retain exact publication receipt",
    ),
    "verify-published-runtime": (
        CHECKOUT,
        "Select registered publication product",
        PRODUCT_CHECKOUT,
        "Verify all published platforms and generate current SBOMs",
        "Retain independent runtime and SBOM evidence",
    ),
    "attest-exact-inputs": (
        CHECKOUT,
        "Select registered publication product",
        PRODUCT_CHECKOUT,
        "Revalidate native inputs and construct typed statement",
        "Attest exact fresh wheel",
        "Attest exact server index",
        "Attest exact host index",
        "Attest server amd64 SBOM",
        "Attest server arm64 SBOM",
        "Attest host amd64 SBOM",
        "Attest host arm64 SBOM",
        "Verify actual native signatures",
        "Retain native signature readback receipt",
    ),
}
UPLOAD_NAMES = {
    "prepare-publication": "Retain publication preparation",
    "publish-exact-oci": "Retain exact publication receipt",
    "verify-published-runtime": "Retain independent runtime and SBOM evidence",
    "attest-exact-inputs": "Retain native signature readback receipt",
}
FRESH_STEPS = (
    "Checkout exact main control",
    "Select registered immutable product",
    "Checkout registered product",
    "Verify complete source before executing product build",
    "Derive hashed build backend constraints from the product lock",
    "Build fresh SaaS login export",
    "Build fresh product wheel and SPA",
    "Inspect and stage fresh product bytes with trusted control",
    "Retain unsigned fresh wheel for protected promotion",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def native_context(control: Path, revision: str) -> dict[str, Any]:
    control_context(control, revision)
    require(
        os.environ.get("GITHUB_WORKFLOW_SHA") == revision
        and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
        "publication requires the exact native main workflow identity",
    )
    context = {
        "control_revision": revision,
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "actor": os.environ["GITHUB_ACTOR"],
    }
    verify_native_control(control, context)
    return context


def verify_native_control(control: Path, context: dict[str, Any]) -> dict[str, Any]:
    run = api(f"{PREFIX}/actions/runs/{context['run_id']}")
    verify_control_run(
        run,
        revision=context["control_revision"],
        run_id=context["run_id"],
        attempt=context["attempt"],
        actor=context["actor"],
    )
    source = api(f"{PREFIX}/contents/{WORKFLOW}?ref={context['control_revision']}")
    require(
        source.get("path") == WORKFLOW
        and source.get("encoding") == "base64"
        and type(source.get("size")) is int
        and 0 < source["size"] <= 262144,
        "native publication workflow source differs",
    )
    body = base64.b64decode("".join(source["content"].split()), validate=True)
    require(
        len(body) == source["size"] and body == (control / WORKFLOW).read_bytes(),
        "native publication workflow bytes differ from clean main control",
    )
    return run


def successful_steps(
    job: dict[str, Any], names: tuple[str, ...], context: dict[str, Any], *, name: str
) -> dict[str, dict[str, Any]]:
    require(
        type(job.get("id")) is int
        and job["id"] > 0
        and job.get("name") == name
        and job.get("run_id") == context["run_id"]
        and job.get("run_attempt") == context["attempt"]
        and job.get("head_sha") == context["control_revision"]
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-latest" in job.get("labels", [])
        and "self-hosted" not in job.get("labels", []),
        "publication input job is not the exact successful hosted control job",
    )
    found = {}
    numbers = []
    for step_name in names:
        matches = [step for step in job.get("steps", []) if step.get("name") == step_name]
        require(
            len(matches) == 1
            and matches[0].get("status") == "completed"
            and matches[0].get("conclusion") == "success"
            and type(matches[0].get("number")) is int
            and matches[0]["number"] > 0,
            "native publication execution step is missing, duplicate or unsuccessful",
        )
        found[step_name] = matches[0]
        numbers.append(matches[0]["number"])
    require(numbers == sorted(set(numbers)), "native publication steps are out of order")
    return found


def artifact_name(role: str, profile: dict[str, Any], context: dict[str, Any]) -> str:
    return (
        f"legacy-{role}-{profile['component']}-{profile['product_revision']}-"
        f"{context['control_revision']}-{context['run_id']}-{context['attempt']}"
    )


def artifact_coordinate(metadata: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["id"],
        "artifact_id": metadata["id"],
        "artifact_name": metadata["name"],
        "zip_size": metadata["size_in_bytes"],
        "zip_sha256": metadata["digest"][7:],
    }


def one_native_artifact(name: str, context: dict[str, Any]) -> dict[str, Any]:
    artifacts = _pages(f"{PREFIX}/actions/runs/{context['run_id']}/artifacts", "artifacts")
    matches = [row for row in artifacts if row.get("name") == name]
    require(len(matches) == 1, "native publication artifact is missing or duplicated")
    metadata = api(f"{PREFIX}/actions/artifacts/{matches[0]['id']}")
    require(metadata == matches[0], "native artifact changed between listing and detail")
    require(
        type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= 1024 * 1024 * 1024
        and isinstance(metadata.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["digest"]) is not None,
        "native publication artifact size or digest differs",
    )
    return metadata


def safe_extract(archive: Path, destination: Path, *, max_bytes: int) -> None:
    """Reject links, special files, duplicate paths and expansion before writing."""
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        require(0 < len(entries) <= 8192, "publication ZIP member count exceeds bound")
        names = set()
        total = 0
        for item in entries:
            path = PurePosixPath(item.filename)
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(
                bool(item.filename)
                and "\\" not in item.filename
                and not path.is_absolute()
                and ".." not in path.parts
                and path.as_posix() == item.filename.rstrip("/")
                and path.as_posix() not in {".", ""}
                and path.as_posix() not in names
                and kind in {0, stat.S_IFREG, stat.S_IFDIR}
                and not item.flag_bits & 1
                and item.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                "unsafe publication ZIP member",
            )
            names.add(path.as_posix())
            total += item.file_size
            require(total <= max_bytes, "publication ZIP expansion exceeds bound")
        destination.mkdir(parents=True, exist_ok=False)
        bundle.extractall(destination)


def validate_export_inventory(root: Path, role: str) -> None:
    scan_files = {
        "scans/grype/candidate-scan-summary.json",
        *(
            f"scans/grype/{name}-{arch}-grype.json"
            for name in IMAGES
            for arch in ("amd64", "arm64")
        ),
    }
    sbom_files = {
        f"sbom/{name}-{arch}.{kind}.json"
        for name in IMAGES
        for arch in ("amd64", "arm64")
        for kind in ("spdx", "cyclonedx")
    }
    inventories = {
        "preparation": {"admission.json", *scan_files},
        "publication": {"admission.json", "publication.json"},
        "runtime": {"admission.json", "runtime.json", *scan_files, *sbom_files},
        "signatures": {"native-signatures.json"},
    }
    require(role in inventories, "unknown publication export role")
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    require(actual == inventories[role], "publication export has missing or extra payloads")
    for relative in actual:
        path = root / relative
        require(path.stat().st_size <= 256 * 1024 * 1024, "publication JSON exceeds parser bound")
        read_json(path)


def collect_job_export(
    control: Path,
    product: Path,
    profile: dict[str, Any],
    context: dict[str, Any],
    *,
    job_name: str,
    role: str,
    destination: Path,
) -> tuple[Path, dict[str, Any]]:
    destination.mkdir(parents=True, exist_ok=False)
    with preserve_native_evidence(destination / "native-api", evidence_root=destination):
        run = verify_native_control(control, context)
        jobs = _job_pages(context["run_id"], context["attempt"])
        matches = [job for job in jobs if job.get("name") == job_name]
        require(len(matches) == 1, "native publication job is missing or duplicated")
        job = api(f"{PREFIX}/actions/jobs/{matches[0]['id']}")
        require(job == matches[0], "native publication job changed since listing")
        steps = successful_steps(job, RUN_STEPS[job_name], context, name=job_name)
        log_path = destination / "job.log"
        download_job_log(job["id"], log_path)
        log = log_path.read_text()
        require(
            checkout_commit(log, steps[CHECKOUT]) == context["control_revision"]
            and checkout_commit(log, steps[PRODUCT_CHECKOUT]) == profile["product_revision"],
            "native publication job actually checked out another control or product",
        )
        name = artifact_name(role, profile, context)
        metadata = one_native_artifact(name, context)
        archive = destination / "original-export.zip"
        download_artifact_bytes(
            metadata["id"],
            archive,
            expected_size=metadata["size_in_bytes"],
            expected_sha256=metadata["digest"][7:],
        )
        verify_job_artifact_identity(
            metadata,
            run,
            job,
            revision=context["control_revision"],
            artifact_name=name,
            upload_step=steps[UPLOAD_NAMES[job_name]],
            archive=archive,
        )
        require(
            api(f"{PREFIX}/actions/artifacts/{metadata['id']}") == metadata
            and api(f"{PREFIX}/actions/jobs/{job['id']}") == job,
            "native publication input changed after transfer",
        )
        verify_native_control(control, context)
        verify_source_delta(product, profile)
        root = destination / "export"
        safe_extract(archive, root, max_bytes=1024 * 1024 * 1024)
        validate_export_inventory(root, role)
        return root, artifact_coordinate(metadata, job)


def collect_fresh_wheel(
    control: Path,
    product: Path,
    profile: dict[str, Any],
    context: dict[str, Any],
    destination: Path,
) -> tuple[dict[str, Any], Path]:
    destination.mkdir(parents=True, exist_ok=False)
    with preserve_native_evidence(destination / "native-api", evidence_root=destination):
        verify_native_control(control, context)
        jobs = _job_pages(context["run_id"], context["attempt"])
        matches = [job for job in jobs if job.get("name") == "build-initial"]
        require(len(matches) == 1, "fresh wheel build job is missing or duplicated")
        job = api(f"{PREFIX}/actions/jobs/{matches[0]['id']}")
        require(job == matches[0], "fresh wheel native job changed since listing")
        steps = successful_steps(job, FRESH_STEPS, context, name="build-initial")
        log_path = destination / "job.log"
        download_job_log(job["id"], log_path)
        log = log_path.read_text()
        require(
            checkout_commit(log, steps[FRESH_STEPS[0]]) == context["control_revision"]
            and checkout_commit(log, steps[FRESH_STEPS[2]]) == profile["product_revision"],
            "fresh wheel native execution used another control or product checkout",
        )
        name = (
            f"legacy-initial-{profile['component']}-{profile['product_revision']}-"
            f"{context['control_revision']}-{context['run_id']}-{context['attempt']}"
        )
        metadata = one_native_artifact(name, context)
        observation = download_fresh_wheel(
            profile,
            **context,
            job_id=job["id"],
            artifact_id=metadata["id"],
            zip_size=metadata["size_in_bytes"],
            zip_sha256=metadata["digest"][7:],
            destination=destination / "download",
        )
        require(observation["native_artifact"] == metadata, "fresh wheel artifact changed")
        archive = destination / "download/fresh-wheel.zip"
        verify_job_artifact_identity(
            metadata,
            observation["native_run"],
            job,
            revision=context["control_revision"],
            artifact_name=name,
            upload_step=steps[FRESH_STEPS[-1]],
            archive=archive,
        )
        facts = verify_wheel_bundle(
            archive,
            destination / "wheel",
            product=product,
            profile=profile,
            control_revision=context["control_revision"],
            zip_sha256=metadata["digest"][7:],
        )
        require(
            api(f"{PREFIX}/actions/jobs/{job['id']}") == job
            and api(f"{PREFIX}/actions/artifacts/{metadata['id']}") == metadata,
            "fresh wheel changed after static source verification",
        )
        coordinate = {
            **context,
            **artifact_coordinate(metadata, job),
            "product_revision": profile["product_revision"],
            "product_tree": profile["product_tree"],
            "wheel_filename": facts["wheel_filename"],
            "wheel_sha256": facts["wheel_sha256"],
            "source_facts_sha256": digest(facts),
        }
        return coordinate, destination / "wheel" / facts["wheel_filename"]


def strict_qualification(result: dict[str, Any], profile: dict[str, Any], revision: str) -> None:
    require(
        result.get("kind") == "legacy_source_qualification/v1"
        and result.get("status") == "pass"
        and result.get("source_ci_pass") is True
        and result.get("technical_source_ci") == "pass"
        and result.get("control_revision") == revision
        and all(
            result.get(key) == profile[key]
            for key in ("component", "product_revision", "product_tree")
        ),
        "complete exact source qualification is not a strict pass",
    )


def collect_original_input(
    control: Path, profile: dict[str, Any], destination: Path
) -> dict[str, Any]:
    with preserve_native_evidence(destination / "native-api", evidence_root=destination):
        result = download_original_oci(
            control,
            profile["component"],
            **load_original_inputs(control, profile),
            destination=destination / "download",
        )
        original = result["original_oci"]
        jobs = [job for job in result["native_jobs"] if job.get("id") == original["job_id"]]
        require(len(jobs) == 1, "original OCI upload has no unique native producer job")
        job = jobs[0]
        uploads = [step for step in job.get("steps", []) if step.get("name") == UPLOAD_STEP]
        require(len(uploads) == 1, "original OCI producer upload step is ambiguous")
        metadata = result["native_artifact"]
        verify_job_artifact_identity(
            metadata,
            result["native_run"],
            job,
            revision=profile["product_revision"],
            artifact_name=metadata["name"],
            upload_step=uploads[0],
            archive=destination / "download/original-oci.zip",
        )
        require(
            api(f"{PREFIX}/actions/jobs/{job['id']}") == job
            and api(f"{PREFIX}/actions/artifacts/{metadata['id']}") == metadata,
            "original OCI native producer job or upload changed after transfer",
        )
        return original


def collect_inputs(
    control: Path, product: Path, component: str, context: dict[str, Any], destination: Path
) -> tuple[dict[str, Any], Path, Path]:
    destination.mkdir(parents=True, exist_ok=False)
    profile = load_profile(control, component)
    verify_source_delta(product, profile)
    source = qualify_source_ci(
        control, product, component, context["control_revision"], destination / "source"
    )
    strict_qualification(source, profile, context["control_revision"])
    pg = collect_pg_receipts(
        control,
        product,
        component,
        context["control_revision"],
        run_id=context["run_id"],
        attempt=context["attempt"],
        actor=context["actor"],
        destination=destination / "pg",
    )
    require(pg.get("native_PG_receipts_pass") is True, "native PG16 and PG18 did not pass")
    original = collect_original_input(control, profile, destination / "original")
    fresh, wheel = collect_fresh_wheel(control, product, profile, context, destination / "fresh")
    require(
        original["run_id"] != fresh["run_id"]
        and original["artifact_id"] != fresh["artifact_id"]
        and original["job_id"] != fresh["job_id"],
        "original PR OCI and fresh control wheel execution identities are conflated",
    )
    result = {
        "kind": VARIANT,
        "control": {
            **context,
            "workflow_path": WORKFLOW,
            "workflow_sha256": file_sha256(control / WORKFLOW),
        },
        "profile": profile,
        "transfer_profile": load_transfer_profile(control, component),
        "original_pr_oci": original,
        "fresh_control_wheel": fresh,
        "source_qualification": {"sha256": digest(source), "result": source},
        "native_product_pg": {"sha256": digest(pg), "result": pg},
        "rebuild_in_publisher": False,
    }
    with preserve_native_evidence(destination / "final-native-api", evidence_root=destination):
        verify_native_control(control, context)
        verify_source_delta(product, profile)
    write_json(destination / "admission.json", result)
    return result, destination / "original/download/original-oci.zip", wheel


def unpack_original(archive: Path, original: dict[str, Any], destination: Path) -> None:
    require(
        archive.stat().st_size == original["zip_size"]
        and file_sha256(archive) == original["zip_sha256"],
        "original OCI ZIP bytes differ",
    )
    expected = {
        "server-1.tar",
        "host-1.tar",
        "oci-promotion-manifest.json",
        "saas-image-candidate.json",
        "grype/candidate-scan-summary.json",
        *(f"grype/{role}-{arch}-grype.json" for role in IMAGES for arch in ("amd64", "arm64")),
    }
    with zipfile.ZipFile(archive) as bundle:
        files = [item for item in bundle.infolist() if not item.is_dir()]
        require(
            len(files) == len(expected)
            and {item.filename for item in files} == expected
            and sum(item.file_size for item in files) <= original["zip_size"],
            "original OCI ZIP is not the exact sealed uncompressed payload inventory",
        )
    safe_extract(archive, destination, max_bytes=original["zip_size"])


def scan(control: Path, root: Path, destination: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "saas.scripts.scan_oci_candidates",
            "--image",
            f"server={root / 'server-1.tar'}",
            "--image",
            f"host={root / 'host-1.tar'}",
            "--output",
            str(destination / "grype"),
        ],
        cwd=control,
        check=True,
    )


def validate_input_identities(admission: dict[str, Any]) -> None:
    profile = admission["profile"]
    fresh = admission["fresh_control_wheel"]
    context = admission["control"]
    transfer_provenance(
        profile,
        original_oci=admission["original_pr_oci"],
        transfer=admission["transfer_profile"],
        control_revision=context["control_revision"],
        run_id=context["run_id"],
        attempt=context["attempt"],
        artifact_id=fresh["artifact_id"],
        zip_sha256=fresh["zip_sha256"],
        seal_sha256=admission["original_pr_oci"]["seal_sha256"],
        wheel_sha256=fresh["wheel_sha256"],
    )
    require(
        all(
            fresh.get(key) == context[key]
            for key in ("control_revision", "run_id", "attempt", "actor")
        )
        and all(fresh.get(key) == profile[key] for key in ("product_revision", "product_tree"))
        and type(fresh.get("job_id")) is int
        and fresh["job_id"] > 0
        and fresh["job_id"] != admission["original_pr_oci"]["job_id"]
        and type(fresh.get("zip_size")) is int
        and fresh["zip_size"] > 0,
        "fresh wheel native run/job/actor/ZIP/product binding differs",
    )


def admitted_manifest(
    root: Path, admission: dict[str, Any], product: Path, scans: Path
) -> dict[str, Any]:
    validate_input_identities(admission)
    profile = admission["profile"]
    return verify_candidate(
        root,
        manifest_sha256=admission["original_pr_oci"]["seal_sha256"],
        labels=expected_labels(product, profile["product_revision"]),
        source_date_epoch=profile["source_date_epoch"],
        current_scan_root=scans,
    )


def prepare_current_manifest(
    control: Path, root: Path, admission: dict[str, Any], product: Path, output: Path
) -> dict[str, Any]:
    """Keep the original sealed bytes and scan the same OCI with the current DB."""
    scan(control, root, output / "scans")
    return admitted_manifest(root, admission, product, output / "scans")


def compare_admission(root: Path, expected: dict[str, Any]) -> None:
    require(
        read_json(root / "admission.json") == expected,
        "transferred admission differs from fresh native source revalidation",
    )


def image_references(admission: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    require(
        manifest.get("product_revision") == admission["profile"]["product_revision"]
        and set(manifest.get("images", {})) == set(IMAGES),
        "published image references differ from the exact admitted product",
    )
    return {
        role: f"ghcr.io/dream1216/omnigent-saas-{role}@{manifest['images'][role]['index_digest']}"
        for role in IMAGES
    }


def read_registry(root: Path, manifest: dict[str, Any], images: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for role in IMAGES:
        layout = root / f"{role}-layout"
        subprocess.run(
            ["crane", "pull", "--format=oci", "--platform=all", images[role], str(layout)],
            check=True,
        )
        archive = root / f"{role}-1.tar"
        with tarfile.open(archive, "w") as bundle:
            for name in ("oci-layout", "index.json", "blobs"):
                bundle.add(layout / name, arcname=name)
        shutil.rmtree(layout)
        verify_readback(archive, manifest["images"][role])
        archive.unlink()


def publish_exact(
    root: Path, admission: dict[str, Any], manifest: dict[str, Any], destination: Path
) -> dict[str, str]:
    images = image_references(admission, manifest)
    for role in IMAGES:
        layout = destination / f"publish-{role}"
        extract_layout(root / f"{role}-1.tar", layout)
        tag = (
            images[role].split("@", 1)[0]
            + ":legacy-"
            + admission["profile"]["component"].lower()
            + "-sha-"
            + admission["profile"]["product_revision"]
        )
        current = subprocess.run(
            ["crane", "digest", tag], text=True, capture_output=True, check=False
        )
        if current.returncode == 0:
            require(
                current.stdout.strip() == manifest["images"][role]["index_digest"],
                "immutable legacy tag already refers to different OCI",
            )
        else:
            require(
                "MANIFEST_UNKNOWN" in current.stderr or "NAME_UNKNOWN" in current.stderr,
                "registry lookup failed without proving an absent legacy tag",
            )
            subprocess.run(["crane", "push", str(layout), tag], check=True)
        actual = subprocess.check_output(["crane", "digest", tag], text=True).strip()
        require(actual == manifest["images"][role]["index_digest"], "published OCI index changed")
        shutil.rmtree(layout)
        (root / f"{role}-1.tar").unlink()
    read_registry(destination / "readback", manifest, images)
    return images


def install_syft(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=False)
    archive = root / "syft.tar.gz"
    url = f"https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}/syft_{SYFT_VERSION}_linux_amd64.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response, archive.open("xb") as output:
        shutil.copyfileobj(response, output, length=1024 * 1024)
    require(
        file_sha256(archive) == SYFT_SHA256, "Syft archive differs from the hash-pinned release"
    )
    with tarfile.open(archive) as bundle:
        member = bundle.getmember("syft")
        require(
            member.isfile() and 0 < member.size <= 256 * 1024 * 1024,
            "invalid Syft executable member",
        )
        stream = bundle.extractfile(member)
        require(stream is not None, "missing Syft executable")
        with (root / "syft").open("xb") as output:
            shutil.copyfileobj(cast(BinaryIO, stream), output)
    (root / "syft").chmod(0o700)
    return root / "syft"


def child_reference(
    images: dict[str, str], manifest: dict[str, Any], role: str, platform: str
) -> str:
    return (
        images[role].split("@", 1)[0]
        + "@"
        + manifest["images"][role]["facts"]["platforms"][platform]["manifest_digest"]
    )


def validate_sbom_files(
    root: Path, images: dict[str, str], manifest: dict[str, Any]
) -> dict[str, Any]:
    result = {}
    for role in IMAGES:
        for platform in PLATFORMS:
            arch = platform.split("/")[1]
            prefix = f"{role}-{arch}"
            spdx = read_json(root / f"{prefix}.spdx.json")
            cyclonedx = read_json(root / f"{prefix}.cyclonedx.json")
            child = child_reference(images, manifest, role, platform)
            require(
                spdx.get("spdxVersion") == "SPDX-2.3"
                and spdx.get("SPDXID") == "SPDXRef-DOCUMENT"
                and isinstance(spdx.get("packages"), list)
                and bool(spdx["packages"])
                and f"Tool: syft-{SYFT_VERSION}"
                in spdx.get("creationInfo", {}).get("creators", []),
                "per-platform SPDX inventory or scanner identity differs",
            )
            require(
                cyclonedx.get("bomFormat") == "CycloneDX"
                and isinstance(cyclonedx.get("components"), list)
                and bool(cyclonedx["components"]),
                "per-platform CycloneDX inventory is empty or invalid",
            )
            result[prefix] = {
                "image": child,
                "platform": platform,
                "spdx_sha256": file_sha256(root / f"{prefix}.spdx.json"),
                "cyclonedx_sha256": file_sha256(root / f"{prefix}.cyclonedx.json"),
            }
    return result


def execute_runtime(
    control: Path,
    admission: dict[str, Any],
    manifest: dict[str, Any],
    images: dict[str, str],
    oci_root: Path,
    destination: Path,
    work: Path,
) -> dict[str, Any]:
    """Called only by the unprivileged runtime job; containers receive no token."""
    require(
        os.environ.get("GITHUB_JOB") == "verify-published-runtime",
        "product runtime execution requires its isolated unprivileged job",
    )
    read_registry(work / "readback", manifest, images)
    # Readback verifies all admitted manifests/configs/layers before scanning
    # their original tar framing, which retains the original archive SHA.
    scan(control, oci_root, destination / "scans")
    scans = validate_scans(destination / "scans", manifest["images"], now=datetime.now(UTC))
    syft = install_syft(work / "tools")
    sboms = destination / "sbom"
    sboms.mkdir()
    runtime = []
    for role in IMAGES:
        for platform in PLATFORMS:
            child = child_reference(images, manifest, role, platform)
            command = [
                "docker",
                "run",
                "--rm",
                "--pull",
                "always",
                "--platform",
                platform,
                "--network",
                "none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
            ]
            python = (
                "import sys; from omnigent import _build_info; "
                "assert _build_info.COMMIT_SHA == sys.argv[1]; "
                "assert _build_info.BUILD_TIME_EPOCH == int(sys.argv[2]); "
                "import pyexpat,zlib; assert pyexpat.EXPAT_VERSION == 'expat_2.9.0'; "
                "assert zlib.ZLIB_RUNTIME_VERSION == '1.3.2.1-motley'; "
                "import saas.production.platform_model_sandbox_host"
            )
            if role == "server":
                python += "; import kubernetes"
            else:
                python += (
                    "; from omnigent.onboarding.harness_install import harness_cli_installed; "
                    "keys=('anthropic','openai','pi','kiro','kimi','qwen','opencode','gemini',"
                    "'devin','jcode'); assert all(harness_cli_installed(key) for key in keys)"
                )
            subprocess.run(
                [
                    *command,
                    "--entrypoint",
                    "/opt/venv/bin/python",
                    child,
                    "-B",
                    "-I",
                    "-c",
                    python,
                    admission["profile"]["product_revision"],
                    str(admission["profile"]["source_date_epoch"]),
                ],
                check=True,
            )
            subprocess.run(
                [
                    *command,
                    "--entrypoint",
                    "/bin/sh",
                    child,
                    "-ec",
                    "test ! -e /usr/bin/perl && test ! -e /usr/local/bin/perl",
                ],
                check=True,
            )
            prefix = sboms / f"{role}-{platform.split('/')[1]}"
            subprocess.run(
                [
                    str(syft),
                    child,
                    "--platform",
                    platform,
                    "-o",
                    f"spdx-json={prefix}.spdx.json",
                    "-o",
                    f"cyclonedx-json={prefix}.cyclonedx.json",
                ],
                check=True,
            )
            subprocess.run(["docker", "image", "rm", child], check=True)
            runtime.append({"role": role, "platform": platform, "image": child, "status": "pass"})
    return {
        "runtime": runtime,
        "scans": scans,
        "sboms": validate_sbom_files(sboms, images, manifest),
    }


def typed_provenance(
    admission: dict[str, Any],
    publication: dict[str, Any],
    runtime: dict[str, Any],
    *,
    preparation_artifact: dict[str, Any],
    publication_artifact: dict[str, Any],
    runtime_artifact: dict[str, Any],
) -> dict[str, Any]:
    """A separate variant; the original v1 statement and verifier stay exact."""
    require(
        admission.get("kind") == VARIANT and admission.get("rebuild_in_publisher") is False,
        "unknown initial publication variant",
    )
    validate_input_identities(admission)
    profile = admission["profile"]
    fresh = admission["fresh_control_wheel"]
    strict_qualification(
        admission["source_qualification"]["result"],
        profile,
        admission["control"]["control_revision"],
    )
    require(
        digest(admission["source_qualification"]["result"])
        == admission["source_qualification"]["sha256"]
        and digest(admission["native_product_pg"]["result"])
        == admission["native_product_pg"]["sha256"]
        and admission["native_product_pg"]["result"].get("native_PG_receipts_pass") is True,
        "source or PG evidence digest differs",
    )
    require(
        publication["admission_sha256"] == runtime["admission_sha256"] == digest(admission),
        "published/runtime source admission differs",
    )
    require(
        runtime["publication_sha256"] == digest(publication), "runtime checked another publication"
    )
    repository = "https://github.com/" + REPOSITORY
    context = admission["control"]
    artifacts = {
        "preparation": preparation_artifact,
        "publication": publication_artifact,
        "runtime": runtime_artifact,
    }
    for role, coordinate in artifacts.items():
        require(
            set(coordinate) == {"job_id", "artifact_id", "artifact_name", "zip_size", "zip_sha256"}
            and all(
                type(coordinate[key]) is int and coordinate[key] > 0
                for key in ("job_id", "artifact_id", "zip_size")
            )
            and isinstance(coordinate["zip_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", coordinate["zip_sha256"]) is not None
            and coordinate["artifact_name"] == artifact_name(role, profile, context),
            "typed native stage artifact coordinates differ",
        )
    artifact_ids = [
        coordinate["artifact_id"]
        for coordinate in [admission["original_pr_oci"], fresh, *artifacts.values()]
    ]
    require(
        len(artifact_ids) == len(set(artifact_ids)),
        "typed publication artifact roles are conflated",
    )
    dependencies = [
        {
            "uri": f"git+{repository}@refs/heads/main",
            "digest": {"gitCommit": context["control_revision"]},
        },
        {
            "uri": f"git+{repository}@{profile['product_revision']}",
            "digest": {
                "gitCommit": profile["product_revision"],
                "gitTree": profile["product_tree"],
            },
        },
    ]
    for coordinate in [
        admission["original_pr_oci"],
        admission["fresh_control_wheel"],
        *artifacts.values(),
    ]:
        dependencies.append(
            {
                "uri": f"{repository}/actions/artifacts/{coordinate['artifact_id']}",
                "digest": {"sha256": coordinate["zip_sha256"]},
            }
        )
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "workflow": {"path": WORKFLOW, "ref": "refs/heads/main", "repository": repository},
                "input_variant": VARIANT,
                "legacy_security_profile": copy.deepcopy(profile),
                "control_identity": copy.deepcopy(context),
                "original_pr_oci": copy.deepcopy(admission["original_pr_oci"]),
                "fresh_control_wheel": copy.deepcopy(admission["fresh_control_wheel"]),
                "source_qualification": copy.deepcopy(admission["source_qualification"]),
                "native_product_pg": copy.deepcopy(admission["native_product_pg"]),
                "native_stage_artifacts": copy.deepcopy(artifacts),
                "published_oci": copy.deepcopy(publication),
                "independent_runtime": copy.deepcopy(runtime),
                "rebuild_in_publisher": False,
            },
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {"id": f"{repository}/{WORKFLOW}@refs/heads/main"},
            "metadata": {
                "invocationId": (
                    f"{repository}/actions/runs/{context['run_id']}/attempts/{context['attempt']}"
                )
            },
        },
    }


def verify_runtime_report(
    root: Path, admission: dict[str, Any], publication: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    runtime = read_json(root / "runtime.json")
    require(
        runtime.get("kind") == "legacy_independent_published_runtime/v1"
        and runtime.get("admission_sha256") == digest(admission)
        and runtime.get("publication_sha256") == digest(publication)
        and runtime.get("status") == "pass",
        "independent runtime report does not bind current native inputs",
    )
    expected = [
        {
            "role": role,
            "platform": platform,
            "image": child_reference(publication["images"], manifest, role, platform),
            "status": "pass",
        }
        for role in IMAGES
        for platform in PLATFORMS
    ]
    require(
        runtime.get("runtime") == expected,
        "every image platform must pass independent runtime checks",
    )
    require(
        runtime.get("scans")
        == validate_scans(root / "scans", manifest["images"], now=datetime.now(UTC)),
        "current raw runtime scans differ",
    )
    require(
        runtime.get("sboms")
        == validate_sbom_files(root / "sbom", publication["images"], manifest),
        "current per-platform SBOM bytes differ",
    )
    return runtime


def native_sbom_verify(subject: str, predicate: dict[str, Any], context: dict[str, Any]) -> None:
    require(
        re.fullmatch(
            r"oci://ghcr.io/dream1216/omnigent-saas-(server|host)@sha256:[0-9a-f]{64}", subject
        )
        is not None,
        "invalid native SBOM subject",
    )
    command = [
        "gh",
        "attestation",
        "verify",
        subject,
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        f"{REPOSITORY}/{WORKFLOW}",
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        context["control_revision"],
        "--deny-self-hosted-runners",
        "--predicate-type",
        SPDX_PREDICATE_TYPE,
        "--format",
        "json",
    ]
    entries = json.loads(subprocess.check_output(command, text=True))
    require(isinstance(entries, list), "native SBOM verification output is not a list")
    repository = f"https://github.com/{REPOSITORY}"
    claims = {
        "issuer": "https://token.actions.githubusercontent.com",
        "sourceRepositoryURI": repository,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryDigest": context["control_revision"],
        "buildSignerDigest": context["control_revision"],
        "buildConfigDigest": context["control_revision"],
        "runnerEnvironment": "github-hosted",
        "subjectAlternativeName": f"{repository}/{WORKFLOW}@refs/heads/main",
        "runInvocationURI": (
            f"{repository}/actions/runs/{context['run_id']}/attempts/{context['attempt']}"
        ),
    }
    verify_sbom(entries, subject=subject.split("@", 1)[1], predicate=predicate, claims=claims)


def verify_signatures(root: Path, admission: dict[str, Any], wheel: Path) -> dict[str, Any]:
    predicate = read_json(root / "provenance.json")
    publication = read_json(root / "publication.json")
    runtime = read_json(root / "runtime.json")
    context = admission["control"]
    coordinates = {key: context[key] for key in ("control_revision", "run_id", "attempt")}
    verify_native_statement(
        str(wheel),
        digest="sha256:" + admission["fresh_control_wheel"]["wheel_sha256"],
        predicate=predicate,
        **coordinates,
    )
    for role in IMAGES:
        image = publication["images"][role]
        verify_native_statement(
            "oci://" + image, digest=image.split("@", 1)[1], predicate=predicate, **coordinates
        )
    for name, facts in runtime["sboms"].items():
        native_sbom_verify(
            "oci://" + facts["image"], read_json(root / "sbom" / f"{name}.spdx.json"), context
        )
    result = {
        "kind": "legacy_native_signature_readback/v2",
        "status": "pass",
        "admission_sha256": digest(admission),
        "predicate_sha256": digest(predicate),
        "publication_sha256": digest(publication),
        "runtime_sha256": digest(runtime),
        "native_gh_attestation_verify": True,
        "production_admission": False,
    }
    write_json(root / "native-signatures.json", result)
    return result


def stage(
    command: str,
    control: Path,
    product: Path,
    component: str,
    context: dict[str, Any],
    destination: Path,
) -> dict[str, str]:
    admission, archive, wheel = collect_inputs(
        control, product, component, context, destination / "inputs"
    )
    root = destination / "oci"
    unpack_original(archive, admission["original_pr_oci"], root)
    output = destination / "export"
    output.mkdir()
    profile = admission["profile"]
    coordinates = {}
    if command == "prepare":
        manifest = prepare_current_manifest(control, root, admission, product, output)
        write_json(output / "admission.json", admission)
    else:
        preparation, coordinate = collect_job_export(
            control,
            product,
            profile,
            context,
            job_name="prepare-publication",
            role="preparation",
            destination=destination / "preparation",
        )
        coordinates["preparation_artifact"] = coordinate
        compare_admission(preparation, admission)
        manifest = admitted_manifest(root, admission, product, preparation / "scans")
        if command == "publish":
            images = publish_exact(root, admission, manifest, destination)
            publication = {
                "kind": "legacy_exact_oci_publication/v1",
                "admission_sha256": digest(admission),
                "images": images,
                "candidate_seal_sha256": admission["original_pr_oci"]["seal_sha256"],
                "registry_readback_pass": True,
                "rebuilt": False,
            }
            write_json(output / "publication.json", publication)
        else:
            published, coordinate = collect_job_export(
                control,
                product,
                profile,
                context,
                job_name="publish-exact-oci",
                role="publication",
                destination=destination / "publication",
            )
            coordinates["publication_artifact"] = coordinate
            publication = read_json(published / "publication.json")
            expected = {
                "kind": "legacy_exact_oci_publication/v1",
                "admission_sha256": digest(admission),
                "images": image_references(admission, manifest),
                "candidate_seal_sha256": admission["original_pr_oci"]["seal_sha256"],
                "registry_readback_pass": True,
                "rebuilt": False,
            }
            require(
                publication == expected, "native publisher receipt differs from admitted exact OCI"
            )
            if command == "runtime":
                result = execute_runtime(
                    control,
                    admission,
                    manifest,
                    publication["images"],
                    root,
                    output,
                    destination / "runtime-work",
                )
                write_json(
                    output / "runtime.json",
                    {
                        "kind": "legacy_independent_published_runtime/v1",
                        "status": "pass",
                        "admission_sha256": digest(admission),
                        "publication_sha256": digest(publication),
                        **result,
                    },
                )
            else:
                runtime_root, coordinate = collect_job_export(
                    control,
                    product,
                    profile,
                    context,
                    job_name="verify-published-runtime",
                    role="runtime",
                    destination=destination / "runtime",
                )
                coordinates["runtime_artifact"] = coordinate
                runtime = verify_runtime_report(runtime_root, admission, publication, manifest)
                read_registry(destination / "readback", manifest, publication["images"])
                predicate = typed_provenance(admission, publication, runtime, **coordinates)
                write_json(output / "provenance.json", predicate)
                write_json(output / "publication.json", publication)
                write_json(output / "runtime.json", runtime)
                shutil.copytree(runtime_root / "sbom", output / "sbom")
                shutil.copyfile(wheel, output / wheel.name)
                if command == "consume":
                    signed, _ = collect_job_export(
                        control,
                        product,
                        profile,
                        context,
                        job_name="attest-exact-inputs",
                        role="signatures",
                        destination=destination / "signatures",
                    )
                    result = verify_signatures(output, admission, wheel)
                    require(
                        read_json(signed / "native-signatures.json") == result,
                        "signing receipt differs from independent cryptographic readback",
                    )
    if command != "prepare":
        write_json(output / "admission.json", admission)
    with preserve_native_evidence(destination / "final-native-api", evidence_root=destination):
        verify_native_control(control, context)
        verify_source_delta(product, profile)
    shutil.rmtree(root)
    values = {
        "component": component,
        "product_revision": profile["product_revision"],
        "wheel_path": str(
            wheel if command in {"prepare", "publish", "runtime"} else output / wheel.name
        ),
        "wheel_sha256": admission["fresh_control_wheel"]["wheel_sha256"],
        "admission_sha256": digest(admission),
    }
    images = image_references(admission, manifest)
    for role in IMAGES:
        values[f"{role}_name"] = images[role].split("@", 1)[0]
        values[f"{role}_digest"] = images[role].split("@", 1)[1]
        for platform in PLATFORMS:
            values[f"{role}_{platform.split('/')[1]}_digest"] = child_reference(
                images, manifest, role, platform
            ).split("@", 1)[1]
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "publish", "runtime", "attest-inputs", "verify-signatures", "consume"),
    )
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    jobs = {
        "prepare": "prepare-publication",
        "publish": "publish-exact-oci",
        "runtime": "verify-published-runtime",
        "attest-inputs": "attest-exact-inputs",
        "verify-signatures": "attest-exact-inputs",
        "consume": "independent-readback",
    }
    require(
        os.environ.get("GITHUB_JOB") == jobs[args.command],
        "publication command is outside its designated permission-separated job",
    )
    if args.command != "verify-signatures":
        args.destination.mkdir(parents=True, exist_ok=False)
    context_name = (
        "signature-context-api" if args.command == "verify-signatures" else "context-api"
    )
    with preserve_native_evidence(args.destination / context_name, evidence_root=args.destination):
        context = native_context(args.control, args.control_revision)
    if args.command == "verify-signatures":
        output = args.destination / "export"
        admission = read_json(output / "admission.json")
        require(
            admission["control"]
            == {
                **context,
                "workflow_path": WORKFLOW,
                "workflow_sha256": file_sha256(args.control / WORKFLOW),
            },
            "signing readback control differs",
        )
        wheel = output / admission["fresh_control_wheel"]["wheel_filename"]
        require(
            file_sha256(wheel) == admission["fresh_control_wheel"]["wheel_sha256"],
            "signed wheel changed",
        )
        final_admission, _, _ = collect_inputs(
            args.control,
            args.product,
            args.component,
            context,
            args.destination / "signature-final-inputs",
        )
        require(final_admission == admission, "native source inputs changed during signing")
        verify_signatures(output, admission, wheel)
        return 0
    values = stage(
        args.command,
        args.control.resolve(),
        args.product.resolve(),
        args.component,
        context,
        args.destination.resolve(),
    )
    if args.github_output is not None:
        require(
            all(
                re.fullmatch(r"[a-z][a-z0-9_]*", key) and "\n" not in value and "\r" not in value
                for key, value in values.items()
            ),
            "unsafe publication workflow output",
        )
        with args.github_output.open("a") as output:
            output.write("".join(f"{key}={value}\n" for key, value in values.items()))
    print(json.dumps(values, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
