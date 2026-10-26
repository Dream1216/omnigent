"""Bind an original signed publication to a fresh complete native publication.

Historical scan bytes are integrity evidence only. Current scan admission is
performed exclusively by read_registered_publication on the fresh publication.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts.legacy_publication_reader import HistoricalProducer, object_view, trusted_entries
from saas.scripts.oci_promotion import read_json, require


def candidate_identity(registration: dict[str, Any]) -> dict[str, Any]:
    admission = registration["admission"]
    return {
        "profile": registration["profile"],
        "original_pr_oci": admission["original_pr_oci"],
        "wheel_sha256": admission["fresh_control_wheel"]["wheel_sha256"],
    }


def verify_renewal_identity(original: dict[str, Any], current: dict[str, Any]) -> None:
    require(
        candidate_identity(original) == candidate_identity(current),
        "renewed publication changed the candidate source/tree/OCI/wheel identity",
    )
    require(
        original["producer"]["run_id"] != current["producer"]["run_id"],
        "renewed publication must have a separate complete native producer run",
    )
    require(
        original["predicate_sha256"] != current["predicate_sha256"],
        "renewed publication must preserve the old predicate and bind a new predicate",
    )

    def artifacts(row):
        return {
            row["admission"]["fresh_control_wheel"]["artifact_id"],
            *(coordinate["artifact_id"] for coordinate in row["stage_artifacts"].values()),
        }

    require(
        not (artifacts(original) & artifacts(current)),
        "renewed publication reuses original fresh/stage artifact coordinates",
    )


def _scan_integrity(root: Path) -> dict[str, Any]:
    """Hash the complete retained raw inventory; grant no scan freshness or pass."""
    reports = {
        f"grype/{role}-{platform.split('/')[-1]}-grype.json": publisher.file_sha256(
            root / "grype" / f"{role}-{platform.split('/')[-1]}-grype.json"
        )
        for role in publisher.IMAGES
        for platform in publisher.PLATFORMS
    }
    return {
        "summary_sha256": publisher.file_sha256(root / "grype/candidate-scan-summary.json"),
        "reports": reports,
    }


def read_original_publication_anchor(
    repository: Path,
    original: dict[str, Any],
    current: dict[str, Any],
    current_facts: dict[str, Any],
    destination: Path,
) -> dict[str, Any]:
    """Reverify original native bytes/signatures without treating old scans as current."""
    verify_renewal_identity(original, current)
    producer = HistoricalProducer(**original["producer"])
    profile = original["profile"]
    with (
        object_view(repository, producer.control_revision, destination / "control") as control,
        object_view(repository, profile["product_revision"], destination / "product") as product,
    ):
        producer.verify(control, producer.control_revision)
        require(
            trusted_entries(repository, profile["component"])
            == trusted_entries(control, profile["component"]),
            "original publication profiles are no longer exactly registered",
        )
        require(
            publisher.load_profile(control, profile["component"]) == profile,
            "original publication source profile differs",
        )
        publisher.verify_source_delta(product, profile)
        fresh, wheel = publisher.collect_fresh_wheel(
            control, product, profile, producer.context, destination / "fresh"
        )
        require(
            fresh == original["admission"]["fresh_control_wheel"],
            "original native wheel ZIP/job identity differs or expired",
        )
        require(
            fresh["wheel_sha256"] == current_facts["wheel_sha256"],
            "original and freshly admitted wheel bytes differ",
        )
        # Current admission has independently re-downloaded this same original
        # PR OCI. Retained control ZIPs cannot replace its native expiry check.
        coordinate = original["admission"]["original_pr_oci"]
        metadata = publisher.api(
            f"{publisher.PREFIX}/actions/artifacts/{coordinate['artifact_id']}"
        )
        require(
            metadata.get("expired") is False
            and metadata.get("id") == coordinate["artifact_id"]
            and metadata.get("digest") == "sha256:" + coordinate["zip_sha256"]
            and metadata.get("size_in_bytes") == coordinate["zip_size"]
            and metadata.get("workflow_run", {}).get("id") == coordinate["run_id"],
            "original PR OCI native metadata changed or expired",
        )
        exports, coordinates = {}, {}
        for role, job in (
            ("preparation", "prepare-publication"),
            ("publication", "publish-exact-oci"),
            ("runtime", "verify-published-runtime"),
            ("signatures", "attest-exact-inputs"),
        ):
            root, observed = publisher.collect_job_export(
                control,
                product,
                profile,
                producer.context,
                job_name=job,
                role=role,
                destination=destination / role,
            )
            require(
                observed == original["stage_artifacts"][role],
                "original native stage ZIP coordinate differs or expired",
            )
            exports[role], coordinates[role] = root, observed
            if role != "signatures":
                publisher.compare_admission(root, original["admission"])
        old_admission = original["admission"]
        publication = read_json(exports["publication"] / "publication.json")
        require(
            publication
            == {
                "kind": "legacy_exact_oci_publication/v1",
                "admission_sha256": publisher.digest(old_admission),
                "images": current_facts["images"],
                "candidate_seal_sha256": coordinate["seal_sha256"],
                "registry_readback_pass": True,
                "rebuilt": False,
            },
            "original signed publication does not bind the same immutable OCI",
        )
        runtime = read_json(exports["runtime"] / "runtime.json")
        manifest = current_facts["manifest"]
        expected_runtime = [
            {
                "role": role,
                "platform": platform,
                "image": publisher.child_reference(
                    publication["images"], manifest, role, platform
                ),
                "status": "pass",
            }
            for role in publisher.IMAGES
            for platform in publisher.PLATFORMS
        ]
        require(
            runtime.get("kind") == "legacy_independent_published_runtime/v1"
            and runtime.get("status") == "pass"
            and runtime.get("admission_sha256") == publisher.digest(old_admission)
            and runtime.get("publication_sha256") == publisher.digest(publication)
            and runtime.get("runtime") == expected_runtime
            and runtime.get("scans") == _scan_integrity(exports["runtime"] / "scans")
            and runtime.get("sboms")
            == publisher.validate_sbom_files(
                exports["runtime"] / "sbom", publication["images"], manifest
            ),
            "original signed runtime/scan/SBOM bytes differ",
        )
        predicate = publisher.typed_provenance(
            old_admission,
            publication,
            runtime,
            preparation_artifact=coordinates["preparation"],
            publication_artifact=coordinates["publication"],
            runtime_artifact=coordinates["runtime"],
        )
        require(
            publisher.digest(predicate) == original["predicate_sha256"],
            "original signed predicate was relabelled as a fresh publication",
        )
        output = destination / "verification"
        output.mkdir()
        for name, value in (
            ("provenance", predicate),
            ("publication", publication),
            ("runtime", runtime),
        ):
            publisher.write_json(output / (name + ".json"), value)
        publisher.shutil.copytree(exports["runtime"] / "sbom", output / "sbom")
        signature = publisher.verify_signatures(output, old_admission, wheel)
        require(
            signature == read_json(exports["signatures"] / "native-signatures.json"),
            "original receipt differs from actual original signature readback",
        )
        producer.verify(control, producer.control_revision)
        publisher.verify_source_delta(product, profile)
        return {
            "predicate_sha256": original["predicate_sha256"],
            "runtime_sha256": publisher.digest(runtime),
            "historical_runtime_scans": _scan_integrity(exports["runtime"] / "scans"),
            "historical_preparation_scans": _scan_integrity(exports["preparation"] / "scans"),
            "current_scan_admission": False,
            "production_admission": False,
        }
