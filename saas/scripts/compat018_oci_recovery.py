"""Draft: recover only fixed C2 4e OCI; a raw checkpoint is never qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PRODUCT = "4e11681dd3809febeb42cb5d752d423b5f751f82"
TREE = "cd9cbd2f918df17a44dc63423ac29a5ddd887820"
UPSTREAM = "825f8500d7cc8e997e5562fa55694cd146165f3c"
EPOCH = 1793801374
REPOSITORY = "Dream1216/omnigent"
WORKFLOW = ".github/workflows/saas-compat018-oci-recovery.yml"
ORIGINAL_RUN = 41849013923
ORIGINAL_JOB = 126696305642
REPORT_ID = 13354100637
REPORT_SIZE = 692811
REPORT_SHA = "a8e83dac2d6947b404f2bc4259c0b23306d231d4f35dece8c4dd11f2a10cc272"
OLD_SEAL_SHA = "fcb031afbb2cc0f9341bd27df19bbc500b04280630fe1e8442d2f39cda727406"
RETAINED_FIRST: dict[str, Any] = {
    "controller_revision": "2f051d9c91540383943841f69ea671427a4709ee",
    "run_id": 42499062491,
    "attempt": 1,
    "builder_job_id": 128787789677,
    "artifact_id": 13626562662,
    "zip_size": 5090605679,
    "zip_sha256": "43aa73c367f489c32c0f133714d8e67216bafa28e0a3ec07a81d69c26abb86c3",
    "original_log_sha256": "a91b2294db2dddb5ca6a7d0a7fe1605c98a801b54b70cee2720b1fe8ff4a5f15",
}
LABELS = {
    "org.opencontainers.image.revision": PRODUCT,
    "ai.omnigent.upstream.revision": UPSTREAM,
    "ai.omnigent.saas.schema-revision": "p0s000000018",
    "ai.omnigent.saas.adapter-contract-version": "0.2.0",
}


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def original_evidence(archive: Path) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    require(
        archive.is_file()
        and not archive.is_symlink()
        and archive.stat().st_size == REPORT_SIZE
        and sha256(archive) == REPORT_SHA,
        "original small comparison artifact bytes differ",
    )
    with zipfile.ZipFile(archive) as bundle:
        require(bundle.testzip() is None, "original comparison ZIP CRC failed")
        comparison_bytes = bundle.read("saas-image-candidate.json")
        comparison = json.loads(comparison_bytes)
        seal_bytes = bundle.read("oci-promotion-manifest.json")
        seal = json.loads(seal_bytes)
        require(
            hashlib.sha256(seal_bytes).hexdigest() == OLD_SEAL_SHA
            and seal.get("product_revision") == PRODUCT
            and seal.get("source_date_epoch") == EPOCH
            and seal.get("labels") == LABELS
            and seal.get("comparison_sha256") == hashlib.sha256(comparison_bytes).hexdigest(),
            "original seal/comparison source binding differs",
        )
        require(
            comparison.get("candidate_evidence_version") == 3
            and comparison.get("status") == "pass"
            and comparison.get("violations") == []
            and comparison.get("product_revision") == PRODUCT
            and comparison.get("upstream_revision") == UPSTREAM
            and comparison.get("source_date_epoch") == EPOCH
            and comparison.get("adapter_contract_version") == "0.2.0"
            and comparison.get("label_profile") == "executable"
            and set(comparison.get("images", {}))
            == {"omnigent-saas-server", "omnigent-saas-host"},
            "original comparison does not bind fixed C2 product",
        )
        scans = seal["scans"]
        summary_bytes = bundle.read("grype/candidate-scan-summary.json")
        require(
            hashlib.sha256(summary_bytes).hexdigest() == scans["summary_sha256"],
            "historical summary hash differs",
        )
        for role in ("server", "host"):
            repeated = comparison["images"][f"omnigent-saas-{role}"]
            facts = repeated["first"]
            require(
                repeated.get("matching_platform_manifest_and_config") is True
                and repeated.get("history_created_by_equal") is True
                and repeated.get("second", {}).get("platforms") == facts["platforms"]
                and repeated.get("second", {}).get("attestations") == facts["attestations"]
                and seal["images"][role]["facts"] == facts
                and set(facts["platforms"]) == {"linux/amd64", "linux/arm64"},
                "original repeated facts differ",
            )
            for platform, fact in facts["platforms"].items():
                name = f"grype/{role}-{platform.split('/')[-1]}-grype.json"
                body = bundle.read(name)
                raw = json.loads(body)
                high = [m for m in raw["matches"] if m["vulnerability"]["severity"] == "High"]
                require(
                    fact["labels"] == LABELS
                    and hashlib.sha256(body).hexdigest() == scans["reports"][name]
                    and raw["descriptor"]["name"] == "grype"
                    and raw["descriptor"]["version"] == "0.120.1"
                    and raw["source"]["target"]["manifestDigest"] == fact["manifest_digest"]
                    and raw["source"]["target"]["imageID"] == fact["config_digest"]
                    and not raw.get("ignoredMatches", [])
                    and not any(
                        m["vulnerability"]["severity"] == "Critical" for m in raw["matches"]
                    )
                    and len(high) == 1
                    and high[0]["vulnerability"]["id"] == "CVE-2026-119586",
                    "historical four-target raw facts differ; they are not fresh admission",
                )
    return comparison, seal, comparison_bytes


def prepare(directory: Path) -> None:
    from saas.scripts.legacy_artifact_download import download_artifact_bytes

    prefix = f"repos/{REPOSITORY}"
    run = api(f"{prefix}/actions/runs/{ORIGINAL_RUN}")
    require(
        run.get("id") == ORIGINAL_RUN
        and run.get("head_sha") == PRODUCT
        and run.get("event") == "pull_request"
        and run.get("run_attempt") == 2
        and run.get("path") == ".github/workflows/saas-image-candidate.yml"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "original native PR producer differs",
    )
    pr = api(f"{prefix}/pulls/223")
    require(
        pr.get("number") == 223
        and pr.get("head", {}).get("sha") == PRODUCT
        and pr.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY,
        "original PR product differs",
    )
    job = api(f"{prefix}/actions/jobs/{ORIGINAL_JOB}")
    steps = {step["name"]: step for step in job.get("steps", [])}
    require(
        job.get("run_id") == ORIGINAL_RUN
        and job.get("run_attempt") == 2
        and job.get("name") == "build-candidate"
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and all(
            steps.get(name, {}).get("conclusion") == "success"
            for name in (
                "Build server candidate attempt 1",
                "Build server candidate attempt 2",
                "Build host candidate attempt 1",
                "Build host candidate attempt 2",
                "Compare repeated executable image facts",
                "Scan exact OCI candidates on both architectures",
                "Seal exact admitted OCI archives and raw scan evidence",
            )
        ),
        "original build/comparison/seal steps are not successful",
    )
    metadata = api(f"{prefix}/actions/artifacts/{REPORT_ID}")
    require(
        metadata.get("id") == REPORT_ID
        and metadata.get("name") == f"saas-image-candidate-{PRODUCT}"
        and metadata.get("digest") == f"sha256:{REPORT_SHA}"
        and metadata.get("size_in_bytes") == REPORT_SIZE
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == ORIGINAL_RUN
        and metadata.get("workflow_run", {}).get("head_sha") == PRODUCT,
        "original retained small evidence metadata differs",
    )
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / "original-report.zip"
    download_artifact_bytes(
        REPORT_ID, archive, expected_size=REPORT_SIZE, expected_sha256=REPORT_SHA
    )
    original_evidence(archive)


def verify_raw(directory: Path, *, comparison_profile: str = "historical") -> dict[str, Any]:
    from saas.scripts.compare_oci_rebuilds import inspect_oci_archive

    require(
        comparison_profile in {"historical", "clean-C2-server", "clean-C2-pair"},
        "unknown C2 comparison profile",
    )
    if (
        comparison_profile in {"clean-C2-server", "clean-C2-pair"}
        or (directory / "clean-context-first.json").exists()
    ):
        from saas.scripts import compat018_clean_context as clean

        require(
            not (directory / "grype").exists()
            and not (directory / "oci-promotion-manifest.json").exists(),
            "raw checkpoint must not carry admission reports",
        )
        clean.verify_complete(directory, Path.cwd(), comparison_profile)
        report = json.loads((directory / "saas-image-candidate.json").read_text())
        result = {
            "schema_version": 2,
            "product_revision": PRODUCT,
            "product_tree": TREE,
            "upstream_revision": UPSTREAM,
            "source_date_epoch": EPOCH,
            "rebuilt": True,
            "comparison_profile": comparison_profile,
            "original_comparison_artifact_id": REPORT_ID,
            "original_comparison_artifact_sha256": REPORT_SHA,
            "images": {
                role: {
                    "archive_sha256": sha256(directory / f"{role}-1.tar"),
                    "facts": report["images"][f"omnigent-saas-{role}"]["first"],
                }
                for role in ("server", "host")
            },
            "raw_checkpoint_only": True,
            "fresh_scans_passed": False,
            "source_and_pg_same_final_run_qualified": False,
            "signed_or_production_admitted": False,
        }
        (directory / "unadmitted-build.json").write_text(json.dumps(result, indent=2) + "\n")
        return result

    report, _, body = original_evidence(directory / "original-report.zip")
    require(
        not (directory / "grype").exists()
        and not (directory / "oci-promotion-manifest.json").exists(),
        "raw checkpoint must not carry historical or stale admission reports",
    )
    images = {}
    for role in ("server", "host"):
        archive = directory / f"{role}-1.tar"
        require(
            archive.is_file() and not archive.is_symlink(),
            "missing regular recovered OCI",
        )
        facts = inspect_oci_archive(archive, label_profile="executable")
        require(
            facts == report["images"][f"omnigent-saas-{role}"]["first"],
            "recovered OCI differs from exact original C2 independent comparison",
        )
        images[role] = {"archive_sha256": sha256(archive), "facts": facts}
    # Preserve the comparison bytes named by the historical seal, including formatting.
    (directory / "saas-image-candidate.json").write_bytes(body)
    result = {
        "schema_version": 1,
        "product_revision": PRODUCT,
        "product_tree": TREE,
        "upstream_revision": UPSTREAM,
        "source_date_epoch": EPOCH,
        "rebuilt": True,
        "original_comparison_artifact_id": REPORT_ID,
        "original_comparison_artifact_sha256": REPORT_SHA,
        "images": images,
        "raw_checkpoint_only": True,
        "fresh_scans_passed": False,
        "source_and_pg_same_final_run_qualified": False,
        "signed_or_production_admitted": False,
    }
    (directory / "unadmitted-build.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def verify_raw_producer(
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
    metadata: dict[str, Any],
    run_id: int,
    artifact_id: int,
    sha: str,
    controller: str,
    *,
    product_revision: str = PRODUCT,
) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40}", controller) and re.fullmatch(r"[0-9a-f]{64}", sha),
        "exact controller and archive SHA required",
    )
    require(
        run.get("id") == run_id
        and run.get("run_attempt") == 1
        and run.get("head_sha") == controller
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "raw native producer differs; controller is not product",
    )
    builders = [j for j in jobs if j.get("name") == "build-compat018-product"]
    require(
        len(builders) == 1
        and builders[0].get("run_id") == run_id
        and builders[0].get("run_attempt") == 1
        and builders[0].get("status") == "completed"
        and builders[0].get("conclusion") == "success"
        and builders[0].get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in builders[0].get("labels", []),
        "raw checkpoint has no successful hosted builder",
    )
    require(
        metadata.get("id") == artifact_id
        and metadata.get("name") == f"compat018-raw-{product_revision}-{run_id}"
        and metadata.get("digest") == f"sha256:{sha}"
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == controller
        and type(metadata.get("size_in_bytes")) is int
        and 0 < metadata["size_in_bytes"] <= 16 * 1024**3,
        "actual rebuilt checkpoint artifact differs",
    )


def download_raw(
    run_id: int,
    artifact_id: int,
    sha: str,
    controller: str,
    root: Path,
    *,
    comparison_profile: str = "historical",
    registered_subject: bool = False,
) -> None:
    from saas.scripts.legacy_artifact_download import download_artifact_bytes
    from saas.scripts.oci_promotion import extract_artifact

    prefix = f"repos/{REPOSITORY}"
    run = api(f"{prefix}/actions/runs/{run_id}")
    jobs = api(f"{prefix}/actions/runs/{run_id}/attempts/1/jobs?per_page=100")["jobs"]
    metadata = api(f"{prefix}/actions/artifacts/{artifact_id}")
    profile = registered_profile() if registered_subject else None
    verify_raw_producer(
        run,
        jobs,
        metadata,
        run_id,
        artifact_id,
        sha,
        controller,
        product_revision=profile["product_revision"] if profile is not None else PRODUCT,
    )
    archive = root.with_suffix(".zip")
    download_artifact_bytes(
        artifact_id,
        archive,
        expected_size=metadata["size_in_bytes"],
        expected_sha256=sha,
    )
    extract_artifact(archive, root, zip_sha256=sha)
    if registered_subject:
        registered_raw(root)
    elif comparison_profile == "historical" and not (root / "clean-context-first.json").exists():
        verify_raw(root)
    else:
        verify_raw(root, comparison_profile=comparison_profile)


def verify_retained_first_native(
    run: dict[str, Any], job: dict[str, Any], metadata: dict[str, Any], log: bytes
) -> None:
    """Authenticate one rejected input; this never grants builder success."""
    value = RETAINED_FIRST
    require(
        run.get("id") == value["run_id"]
        and run.get("head_sha") == value["controller_revision"]
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("run_attempt") == 1
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "retained first input is not the exact rejected controller run",
    )
    steps = job.get("steps", [])
    required = (
        "Verify product checkout and install its existing locked helpers",
        "Build the original locked React18 login export before the original OCI action",
        "Recover Server using its existing first-attempt build cache",
        "Recover Host using its existing first-attempt build cache",
        "Stage actual OCI before cleanup or inspection can fail",
        "Preserve actual OCI before any fresh vulnerability scan",
    )
    for name in (*required, "Audit actual fixed C2 source, UI, and historical Host"):
        require(
            len([step for step in steps if step.get("name") == name]) == 1,
            "retained first native step is missing or duplicated",
        )
    by_name = {step["name"]: step for step in steps}
    require(
        job.get("id") == value["builder_job_id"]
        and job.get("run_id") == value["run_id"]
        and job.get("run_attempt") == 1
        and job.get("head_sha") == value["controller_revision"]
        and job.get("name") == "build-compat018-product"
        and job.get("status") == "completed"
        and job.get("conclusion") == "failure"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-24.04" in job.get("labels", [])
        and all(by_name[name].get("conclusion") == "success" for name in required)
        and [step.get("name") for step in steps if step.get("conclusion") == "failure"]
        == ["Audit actual fixed C2 source, UI, and historical Host"],
        "retained first archive has another failure or unproved build/upload",
    )
    require(
        metadata.get("id") == value["artifact_id"]
        and metadata.get("name") == f"compat018-raw-{PRODUCT}-{value['run_id']}"
        and metadata.get("size_in_bytes") == value["zip_size"]
        and metadata.get("digest") == "sha256:" + str(value["zip_sha256"])
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == value["run_id"]
        and metadata.get("workflow_run", {}).get("head_sha") == value["controller_revision"]
        and hashlib.sha256(log).hexdigest() == value["original_log_sha256"]
        and b"ValueError: new C2 Host does not equal its actual historical independent pair"
        in log,
        "retained first artifact or original refusal log differs",
    )
    upload = by_name[required[-1]]
    require(
        datetime.fromisoformat(upload["started_at"])
        <= datetime.fromisoformat(metadata["created_at"])
        <= datetime.fromisoformat(upload["completed_at"]),
        "retained first artifact was not created by the successful original upload",
    )


def download_retained_first(root: Path) -> dict[str, Any]:
    """Reuse the exact first archives; source audit and both fresh pairs remain required."""
    from saas.scripts.legacy_artifact_download import download_artifact_bytes
    from saas.scripts.legacy_source_ci import download_job_log
    from saas.scripts.oci_promotion import extract_artifact

    value = RETAINED_FIRST
    prefix = f"repos/{REPOSITORY}/actions"
    run = api(f"{prefix}/runs/{value['run_id']}")
    job = api(f"{prefix}/jobs/{value['builder_job_id']}")
    metadata = api(f"{prefix}/artifacts/{value['artifact_id']}")
    log = root.with_suffix(".original-rejection.log")
    download_job_log(int(value["builder_job_id"]), log)
    verify_retained_first_native(run, job, metadata, log.read_bytes())
    archive = root.with_suffix(".zip")
    download_artifact_bytes(
        int(value["artifact_id"]),
        archive,
        expected_size=int(value["zip_size"]),
        expected_sha256=str(value["zip_sha256"]),
    )
    extract_artifact(archive, root, zip_sha256=str(value["zip_sha256"]))
    require(
        {p.name for p in root.iterdir()} == {"server-1.tar", "host-1.tar", "original-report.zip"},
        "retained first archive inventory differs",
    )
    original_evidence(root / "original-report.zip")
    # GitHub retains the immutable original ZIP; remove only this verified local copy.
    archive.unlink()
    (root / "retained-first-native.json").write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n"
    )
    return dict(value)


def seal(root: Path) -> dict[str, Any]:
    from saas.scripts.oci_promotion import seal_candidate

    # C2 labels come from the exact original seal, never the current M controller checkout.
    _, old_seal, _ = original_evidence(root / "original-report.zip")
    result = seal_candidate(
        root, labels=old_seal["labels"], source_date_epoch=EPOCH, now=datetime.now(UTC)
    )
    path = root / "oci-promotion-manifest.json"
    path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(f"manifest-sha256={sha256(path)}")
    return result


def registered_profile() -> dict[str, Any]:
    from saas.scripts.protected_legacy_initial_build import load_profile

    profile = load_profile(Path(__file__).resolve().parents[2], "Compatibility018")
    require(profile["product_revision"] != PRODUCT, "replacement cannot relabel historical 4e")
    return profile


def registered_raw(root: Path, *, write: bool = False) -> dict[str, Any]:
    """Bind a raw checkpoint to its own registered profile and two actual pairs."""
    from saas.scripts.compare_oci_rebuilds import compare_archives

    profile = registered_profile()
    require(
        json.loads((root / "registered-source-profile.json").read_text()) == profile,
        "raw C2 source profile changed",
    )
    first = json.loads((root / "reviewed-subject-image-facts.json").read_text())
    require(
        all(
            first.get(key) == profile[key]
            for key in ("product_revision", "product_tree", "source_date_epoch")
        )
        and first.get("historical_4e_byte_identity_claimed") is False,
        "raw C2 source facts belong to another subject",
    )
    labels = {**LABELS, "org.opencontainers.image.revision": profile["product_revision"]}
    images = {}
    for role in ("server", "host"):
        comparison = compare_archives(
            root / f"{role}-1.tar", root / f"{role}-2.tar", label_profile="executable"
        )
        require(
            comparison["matching_platform_manifest_and_config"] is True
            and comparison["history_created_by_equal"] is True
            and comparison["first"] == first["images"][role]["facts"]
            and sha256(root / f"{role}-1.tar") == first["images"][role]["archive_sha256"],
            "registered C2 actual independent pair or audited first archive differs",
        )
        for side in ("first", "second"):
            actual = comparison[side]
            require(
                actual.get("attestation_descriptor_count", 0) >= 2
                and set(actual["platforms"]) == {"linux/amd64", "linux/arm64"}
                and all(row["labels"] == labels for row in actual["platforms"].values()),
                "registered C2 complete platform labels or provenance/SBOM descriptors differ",
            )
        images["omnigent-saas-" + role] = comparison
    report = {
        "candidate_evidence_version": 3,
        "status": "pass",
        "violations": [],
        "product_revision": profile["product_revision"],
        "source_date_epoch": profile["source_date_epoch"],
        "upstream_revision": labels["ai.omnigent.upstream.revision"],
        "adapter_contract_version": labels["ai.omnigent.saas.adapter-contract-version"],
        "label_profile": "executable",
        "images": images,
        "production_ready": False,
        "registered_source_profile_sha256": sha256(root / "registered-source-profile.json"),
        "registered_first_facts_sha256": sha256(root / "reviewed-subject-image-facts.json"),
        "historical_4e_byte_identity_claimed": False,
    }
    path = root / "saas-image-candidate.json"
    if write:
        require(not path.exists(), "registered comparison already exists")
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    else:
        require(json.loads(path.read_text()) == report, "registered comparison changed")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "inspect-original",
            "prepare",
            "verify",
            "download",
            "seal",
            "retained-first",
            "registered-prepare",
            "registered-confirm",
        ),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--sha256")
    parser.add_argument("--controller")
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--registered-subject", action="store_true")
    parser.add_argument(
        "--comparison-profile",
        choices=("historical", "clean-C2-server", "clean-C2-pair"),
        default="historical",
    )
    args = parser.parse_args()
    if args.registered_subject and args.command not in {"verify", "download", "seal"}:
        parser.error("registered subject flag is limited to raw verification/scan/seal")
    if args.command == "registered-prepare":
        profile = registered_profile()
        args.root.mkdir(parents=True, exist_ok=False)
        (args.root / "registered-source-profile.json").write_text(
            json.dumps(profile, sort_keys=True, indent=2) + "\n"
        )
        if args.github_env:
            with args.github_env.open("a") as stream:
                for key, value in {
                    "PRODUCT_REVISION": profile["product_revision"],
                    "SOURCE_REVISION": profile["product_revision"],
                    "PRODUCT_TREE": profile["product_tree"],
                    "SOURCE_DATE_EPOCH": str(profile["source_date_epoch"]),
                }.items():
                    stream.write(f"{key}={value}\n")
    elif args.command == "registered-confirm":
        registered_raw(args.root, write=True)
    elif args.command == "inspect-original":
        original_evidence(args.root)
        print(
            json.dumps(
                {
                    "original_artifact_verified": True,
                    "product_revision": PRODUCT,
                    "historical_each_target_critical": 0,
                    "historical_each_target_high": 1,
                    "fresh_scans_passed": False,
                    "signed_or_production_admitted": False,
                }
            )
        )
    elif args.command == "retained-first":
        download_retained_first(args.root)
    elif args.command == "prepare":
        prepare(args.root)
    elif args.command == "verify":
        if args.registered_subject:
            registered_raw(args.root)
        else:
            verify_raw(args.root, comparison_profile=args.comparison_profile)
    elif args.command == "seal":
        if args.registered_subject:
            from saas.scripts.oci_promotion import seal_candidate

            registered_raw(args.root)
            profile = registered_profile()
            result = seal_candidate(
                args.root,
                labels={
                    **LABELS,
                    "org.opencontainers.image.revision": profile["product_revision"],
                },
                source_date_epoch=profile["source_date_epoch"],
                now=datetime.now(UTC),
            )
            path = args.root / "oci-promotion-manifest.json"
            path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
            print(f"manifest-sha256={sha256(path)}")
        else:
            seal(args.root)
    else:
        require(
            bool(args.run_id and args.artifact_id and args.sha256 and args.controller),
            "actual raw producer coordinates required",
        )
        download_raw(
            args.run_id,
            args.artifact_id,
            args.sha256,
            args.controller,
            args.root,
            comparison_profile=args.comparison_profile,
            registered_subject=args.registered_subject,
        )


if __name__ == "__main__":
    main()
