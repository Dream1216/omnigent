"""Admit the separate LiteLLM runtime without substituting application image evidence."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.compare_oci_rebuilds import inspect_oci_archive
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    PLATFORMS,
    archive_index_digest,
    expected_labels,
    extract_artifact,
    extract_layout,
    read_json,
    require,
    validate_scans,
    verify_artifact_metadata,
    verify_readback,
)
from saas.scripts.scan_oci_candidates import file_sha256

COMPARISON_NAME = "litellm-image-candidate.json"
ARTIFACT_PREFIX = "litellm-oci-promotion-"


def validate_runtime_release_contract(repo: Path, workflow: str, action: str) -> list[str]:
    """Require a separate complete runtime chain; application scans remain unchanged."""

    def step(name: str) -> str:
        marker = f"      - name: {name}\n"
        return (
            workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
            if workflow.count(marker) == 1
            else ""
        )

    violations = []
    path = repo / "deploy/litellm/Dockerfile"
    dockerfile = ""
    if path.is_file() and not any(
        part.is_symlink() for part in (path, path.parent, path.parent.parent)
    ):
        dockerfile = path.read_text(encoding="utf-8")
    required_labels = {
        'org.opencontainers.image.revision="${SOURCE_REVISION}"',
        'ai.omnigent.upstream.revision="${UPSTREAM_REVISION}"',
        'ai.omnigent.saas.schema-revision="${CONTROL_PLANE_SCHEMA_REVISION}"',
        'ai.omnigent.saas.adapter-contract-version="${ADAPTER_CONTRACT_VERSION}"',
        'io.omnigent.litellm.profile="oss-core"',
    }
    if any(label not in dockerfile for label in required_labels):
        violations.append("LiteLLM runtime must carry exact source and OSS profile labels")
    if (
        "'deploy/litellm/Dockerfile'" not in action
        or "LITELLM_BASE_IMAGE=${{ env.LITELLM_BASE_IMAGE }}" not in action
        or '[[ "${LITELLM_BASE_IMAGE:-}" == "$expected" ]]' not in action
    ):
        violations.append("LiteLLM composite build must use the admitted runtime and base")
    contracts = {
        "Prepare locked LiteLLM build materials": (
            "jq -er .image saas/production/litellm_release.json",
            "prepare_litellm_runtime",
            "--destination .litellm-runtime",
        ),
        "Compare repeated LiteLLM image facts": (
            "--label-profile litellm",
            "litellm-1.tar,${{ runner.temp }}/litellm-2.tar",
        ),
        "Scan exact LiteLLM candidates on both architectures": (
            "--scope litellm-runtime",
            "--image litellm=",
        ),
        "Seal exact admitted LiteLLM OCI and scan evidence": (
            "litellm_oci_promotion seal",
            '--revision "$CANDIDATE_REVISION"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH"',
        ),
        "Upload immutable admitted LiteLLM OCI bytes": (
            "inputs.publish_signed",
            "github.ref == 'refs/heads/main'",
            "litellm-oci-promotion-${{ env.CANDIDATE_REVISION }}",
            "artifacts/litellm-promotion/",
        ),
        "Download and validate admitted LiteLLM OCI": (
            "needs.build-candidate.outputs.litellm-oci-artifact-id",
            "needs.build-candidate.outputs.litellm-oci-artifact-sha256",
            "litellm_oci_promotion download",
            "litellm_oci_promotion prepare",
            '--manifest-sha256 "$LITELLM_MANIFEST_SHA256"',
            "--current-scans artifacts/litellm-current-scans",
        ),
        "Promote admitted LiteLLM OCI without rebuilding": (
            "crane push",
            ".images.litellm.index_digest",
            '[[ "$(crane digest "$IMAGE_TAG")" == "$expected" ]]',
        ),
        "Read back promoted LiteLLM before signing": (
            "crane pull --format=oci --platform=all",
            "litellm_oci_promotion readback",
            '--manifest-sha256 "$LITELLM_MANIFEST_SHA256"',
        ),
        "Verify published LiteLLM runtime on both architectures": (
            "for arch in amd64 arm64",
            '"linux/$arch" --network none',
            'find_spec("litellm_enterprise") is None',
            'm.version("litellm")',
            "library.OpenSSL_version(0)",
        ),
        "Generate LiteLLM per-architecture SBOMs and check raw findings": (
            "for arch in amd64 arm64",
            "spdx-json",
            "cyclonedx-json",
            'severity == "Critical"',
            'severity == "High"',
            ".ignoredMatches // []) == []",
            "artifacts/litellm-current-scans/grype/litellm-${arch}-grype.json",
        ),
        "Sign LiteLLM image provenance with GitHub OIDC": (
            "subject-name: ${{ steps.release.outputs.prefix }}/omnigent-litellm",
            "subject-digest: ${{ steps.build-litellm.outputs.digest }}",
            "push-to-registry: true",
        ),
        "Verify signed LiteLLM digest and source": (
            'gh attestation verify "oci://${LITELLM_IMAGE}"',
            '--source-digest "$PRODUCT_REVISION"',
            "--source-ref refs/heads/main",
            '--signer-workflow "$SIGNER_WORKFLOW"',
            "--format json",
        ),
        "Read back signed LiteLLM OCI": (
            "--scope litellm-runtime",
            "litellm_oci_promotion readback",
            "--current-scans artifacts/litellm/signed-scans",
        ),
        "Record signed candidate facts": (
            "runtime_components: {litellm:",
            "candidate_manifest_sha256: $litellm_manifest_sha256",
            "LITELLM_ATTESTATION: ${{ steps.attest-litellm.outputs.attestation-url }}",
            "original_artifact_id: $litellm_artifact_id",
            "original_artifact_sha256: $litellm_artifact_sha256",
        ),
        "Upload signed release candidate facts": ("artifacts/litellm/",),
        "Independently verify LiteLLM runtime digest and source": (
            ".runtime_components.litellm.image",
            '--source-digest "$PRODUCT_REVISION"',
            "--source-ref refs/heads/main",
            '--manifest-sha256 "$LITELLM_MANIFEST_SHA256"',
            '--archive "${RUNNER_TEMP}/litellm-readback.tar"',
        ),
    }
    for name, fragments in contracts.items():
        source = step(name)
        if not source or any(fragment not in source for fragment in fragments):
            violations.append(f"LiteLLM release step is missing or weakens its contract: {name}")
    ordered = [
        "Build LiteLLM candidate attempt 1",
        "Build LiteLLM candidate attempt 2",
        "Compare repeated LiteLLM image facts",
        "Scan exact LiteLLM candidates on both architectures",
        "Seal exact admitted LiteLLM OCI and scan evidence",
        "Upload immutable admitted LiteLLM OCI bytes",
        "Download and validate admitted LiteLLM OCI",
        "Promote admitted LiteLLM OCI without rebuilding",
        "Read back promoted LiteLLM before signing",
        "Verify published LiteLLM runtime on both architectures",
        "Generate LiteLLM per-architecture SBOMs and check raw findings",
        "Sign LiteLLM image provenance with GitHub OIDC",
        "Verify signed LiteLLM digest and source",
        "Read back signed LiteLLM OCI",
        "Record signed candidate facts",
        "Independently verify LiteLLM runtime digest and source",
    ]
    positions = [workflow.find(f"      - name: {name}\n") for name in ordered]
    if -1 in positions or positions != sorted(positions):
        violations.append(
            "LiteLLM runtime must be scanned, promoted and read back before release admission"
        )
    return violations


def runtime_labels(repo: Path, revision: str) -> dict[str, str]:
    lock = read_json(repo / "saas/production/litellm_release.json")
    image = lock.get("image", "")
    require(
        isinstance(image, str)
        and re.fullmatch(r"ghcr\.io/berriai/litellm@sha256:[0-9a-f]{64}", image) is not None
        and lock.get("license", {}).get("runtime_profile") == "oss-core",
        "LiteLLM runtime source must be pinned MIT core",
    )
    return {
        **expected_labels(repo, revision),
        "io.omnigent.integration.revision": revision,
        "io.omnigent.litellm.upstream.digest": image.split("@", 1)[1],
        "io.omnigent.litellm.openssl.version": lock["runtime_patch"]["openssl_version"],
        "io.omnigent.litellm.profile": "oss-core",
    }


def seal_runtime(
    root: Path, *, labels: dict[str, str], source_date_epoch: int, now: datetime
) -> dict[str, Any]:
    comparison = read_json(root / COMPARISON_NAME)
    revision = labels["org.opencontainers.image.revision"]
    require(
        comparison.get("candidate_evidence_version") == 3
        and comparison.get("status") == "pass"
        and comparison.get("violations") == []
        and comparison.get("label_profile") == "litellm"
        and comparison.get("product_revision") == revision
        and comparison.get("source_date_epoch") == source_date_epoch
        and comparison.get("upstream_revision") == labels["ai.omnigent.upstream.revision"]
        and comparison.get("adapter_contract_version")
        == labels["ai.omnigent.saas.adapter-contract-version"]
        and set(comparison.get("images", {})) == {"omnigent-litellm"},
        "LiteLLM reproducibility evidence does not bind the exact runtime",
    )
    archive = root / "litellm-1.tar"
    require(archive.is_file() and not archive.is_symlink(), "missing regular LiteLLM OCI")
    facts = inspect_oci_archive(archive, label_profile="litellm")
    for platform in PLATFORMS:
        require(facts["platforms"][platform]["labels"] == labels, "LiteLLM source labels differ")
    repeated = comparison["images"]["omnigent-litellm"]
    require(
        repeated.get("matching_platform_manifest_and_config") is True
        and repeated.get("history_created_by_equal") is True
        and repeated.get("first") == facts
        and repeated.get("second", {}).get("platforms") == facts["platforms"]
        and repeated.get("second", {}).get("attestations") == facts["attestations"],
        "LiteLLM archive differs from accepted repeated builds",
    )
    images = {
        "litellm": {
            "archive": "litellm-1.tar",
            "archive_sha256": file_sha256(archive),
            "index_digest": archive_index_digest(archive),
            "facts": facts,
        }
    }
    return {
        "schema_version": 1,
        "evidence_kind": "immutable_litellm_oci_promotion_candidate",
        "product_revision": revision,
        "source_date_epoch": source_date_epoch,
        "sealed_at": now.isoformat(),
        "labels": labels,
        "comparison_sha256": file_sha256(root / COMPARISON_NAME),
        "scans": validate_scans(root, images, now=now, expected_images=("litellm",)),
        "images": images,
    }


def verify_runtime(
    root: Path,
    *,
    manifest_sha256: str,
    labels: dict[str, str],
    source_date_epoch: int,
    current_scan_root: Path | None = None,
) -> dict[str, Any]:
    path = root / MANIFEST_NAME
    require(file_sha256(path) == manifest_sha256, "LiteLLM seal digest mismatch")
    manifest = read_json(path)
    sealed_at = datetime.fromisoformat(manifest["sealed_at"])
    now = datetime.now(UTC)
    require(sealed_at.tzinfo is not None and sealed_at <= now, "LiteLLM seal time is invalid")
    actual = seal_runtime(root, labels=labels, source_date_epoch=source_date_epoch, now=sealed_at)
    require(actual == manifest, "LiteLLM seal does not bind transferred OCI bytes")
    validate_scans(
        current_scan_root or root, manifest["images"], now=now, expected_images=("litellm",)
    )
    return manifest


def verify_runtime_readback(
    root: Path,
    archive: Path,
    *,
    manifest_sha256: str,
    labels: dict[str, str],
    source_date_epoch: int,
    current_scan_root: Path | None = None,
) -> dict[str, Any]:
    path = root / MANIFEST_NAME
    require(file_sha256(path) == manifest_sha256, "LiteLLM readback seal differs")
    manifest = read_json(path)
    require(
        manifest.get("evidence_kind") == "immutable_litellm_oci_promotion_candidate"
        and manifest.get("product_revision") == labels["org.opencontainers.image.revision"]
        and manifest.get("source_date_epoch") == source_date_epoch
        and manifest.get("labels") == labels
        and set(manifest.get("images", {})) == {"litellm"},
        "LiteLLM readback source differs",
    )
    verify_readback(archive, manifest["images"]["litellm"], label_profile="litellm")
    scans = None
    if current_scan_root is not None:
        image = {**manifest["images"]["litellm"], "archive_sha256": file_sha256(archive)}
        scans = validate_scans(
            current_scan_root,
            {"litellm": image},
            now=datetime.now(UTC),
            expected_images=("litellm",),
        )
    return {
        "status": "pass",
        "product_revision": manifest["product_revision"],
        "candidate_manifest_sha256": manifest_sha256,
        "image_index_digest": manifest["images"]["litellm"]["index_digest"],
        "current_scans": scans,
        "production_deployment_receipt": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seal", "download", "prepare", "readback"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--repository")
    parser.add_argument("--layout-root", type=Path)
    parser.add_argument("--current-scans", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    labels = runtime_labels(Path.cwd(), args.revision)
    if args.command == "download":
        require(
            args.artifact_id is not None
            and args.artifact_id > 0
            and args.run_id is not None
            and args.run_id > 0
            and args.repository is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is not None
            and args.artifact_sha256 is not None
            and re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256) is not None,
            "immutable LiteLLM artifact coordinates are required",
        )
        endpoint = f"repos/{args.repository}/actions/artifacts/{args.artifact_id}"
        metadata = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))
        verify_artifact_metadata(
            metadata,
            artifact_id=args.artifact_id,
            zip_sha256=args.artifact_sha256,
            revision=args.revision,
            run_id=args.run_id,
            artifact_prefix=ARTIFACT_PREFIX,
        )
        with tempfile.TemporaryDirectory(prefix="omnigent-litellm-promotion-") as temporary:
            archive = Path(temporary) / "candidate.zip"
            with archive.open("wb") as stream:
                subprocess.run(["gh", "api", endpoint + "/zip"], stdout=stream, check=True)
            extract_artifact(archive, args.root, zip_sha256=args.artifact_sha256)
        return 0
    if args.command == "seal":
        manifest = seal_runtime(
            args.root,
            labels=labels,
            source_date_epoch=args.source_date_epoch,
            now=datetime.now(UTC),
        )
        path = args.root / MANIFEST_NAME
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"manifest-sha256={file_sha256(path)}")
        return 0
    require(args.manifest_sha256 is not None, "expected LiteLLM seal is required")
    if args.command == "prepare":
        manifest = verify_runtime(
            args.root,
            manifest_sha256=args.manifest_sha256,
            labels=labels,
            source_date_epoch=args.source_date_epoch,
            current_scan_root=args.current_scans,
        )
        require(args.layout_root is not None, "runtime layout destination is required")
        extract_layout(
            args.root / manifest["images"]["litellm"]["archive"], args.layout_root / "litellm"
        )
    else:
        require(args.archive is not None, "exact registry runtime archive is required")
        print(
            json.dumps(
                verify_runtime_readback(
                    args.root,
                    args.archive,
                    manifest_sha256=args.manifest_sha256,
                    labels=labels,
                    source_date_epoch=args.source_date_epoch,
                    current_scan_root=args.current_scans,
                ),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
