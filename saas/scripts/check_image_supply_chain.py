"""Validate the production image policy and immutable release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ids(items: object, field: str = "name") -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        value
        for item in items
        if isinstance(item, dict) and isinstance((value := item.get(field)), str)
    }


def _validate_policy(repo: Path, policy: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if policy.get("schema_version") != 1:
        violations.append("release policy schema_version must be 1")
    for field in ("candidate_workflow", "release_runbook", "dockerfile", "upstream_manifest"):
        value = policy.get(field)
        if not isinstance(value, str) or not (repo / value).is_file():
            violations.append(f"release policy {field} must reference a repository file")

    images = policy.get("images")
    if _ids(images) != {"omnigent-saas-server", "omnigent-saas-host"}:
        violations.append("release policy must define server and host images")
    if isinstance(images, list):
        for image in images:
            if not isinstance(image, dict):
                violations.append("image policy entries must be objects")
                continue
            name = image.get("name", "unknown")
            if image.get("target") not in {"runtime", "host"}:
                violations.append(f"{name} has an invalid Docker target")
            if set(image.get("platforms", [])) != {"linux/amd64", "linux/arm64"}:
                violations.append(f"{name} must require amd64 and arm64")
            smoke = image.get("required_smoke")
            if not isinstance(smoke, list) or len(set(smoke)) < 5:
                violations.append(f"{name} must define at least five smoke probes")

    reproducibility = policy.get("reproducibility")
    required_args: set[str] = set()
    if not isinstance(reproducibility, dict):
        violations.append("release policy reproducibility must be an object")
    else:
        if reproducibility.get("source_date_epoch") != "product-commit-timestamp":
            violations.append("SOURCE_DATE_EPOCH must come from the product commit")
        for field in (
            "base_images_must_be_digest_pinned",
            "clean_tree_required",
            "matching_platform_manifest_and_config_required",
        ):
            if reproducibility.get(field) is not True:
                violations.append(f"reproducibility.{field} must be true")
        if reproducibility.get("repeat_builds") != 2:
            violations.append("production images require two repeated builds")
        locks = reproducibility.get("dependency_locks")
        if not isinstance(locks, list) or any(not (repo / str(path)).is_file() for path in locks):
            violations.append("every dependency lock must exist")
        args = reproducibility.get("required_build_args")
        if isinstance(args, list):
            required_args = set(args)
        expected_args = {
            "PYTHON_IMAGE",
            "NODE_IMAGE",
            "SOURCE_DATE_EPOCH",
            "SOURCE_REVISION",
            "UPSTREAM_REVISION",
            "CONTROL_PLANE_SCHEMA_REVISION",
            "ADAPTER_CONTRACT_VERSION",
        }
        if required_args != expected_args:
            violations.append("required_build_args does not match the reproducible build contract")

    dockerfile_path = policy.get("dockerfile")
    if isinstance(dockerfile_path, str) and (repo / dockerfile_path).is_file():
        dockerfile = (repo / dockerfile_path).read_text(encoding="utf-8")
        for build_arg in required_args:
            if f"ARG {build_arg}" not in dockerfile:
                violations.append(f"Dockerfile does not declare {build_arg}")
        for label in policy.get("required_labels", []):
            if not isinstance(label, str) or label not in dockerfile:
                violations.append(f"Dockerfile does not emit label {label}")
        if "COPY saas/ ./saas/" not in dockerfile:
            violations.append("production Dockerfile does not package the SaaS boundary")
    setup = (repo / "setup.py").read_text(encoding="utf-8")
    if 'os.environ.get("SOURCE_DATE_EPOCH")' not in setup:
        violations.append("build metadata does not honor SOURCE_DATE_EPOCH")

    attestations = policy.get("attestations")
    if not isinstance(attestations, dict):
        violations.append("attestations policy must be an object")
    else:
        if attestations.get("provenance_predicate") != "https://slsa.dev/provenance/v1":
            violations.append("SLSA provenance v1 is required")
        if attestations.get("provenance_mode") != "max":
            violations.append("maximum provenance mode is required")
        if set(attestations.get("sbom_formats", [])) != {"spdx-json", "cyclonedx-json"}:
            violations.append("SPDX and CycloneDX SBOMs are required")
        for field in ("keyless_signature_required", "protected_workflow_identity_required"):
            if attestations.get(field) is not True:
                violations.append(f"attestations.{field} must be true")

    regression = policy.get("regression")
    if not isinstance(regression, dict):
        violations.append("regression policy must be an object")
    else:
        suites = regression.get("official_suites")
        if not isinstance(suites, list) or len(suites) < 5:
            violations.append("at least five official OSS regression suites are required")
        elif any(not (repo / str(path)).is_file() for path in suites):
            violations.append("an official OSS regression suite path is missing")
        if regression.get("saas_suite") != "tests/saas" or not (repo / "tests/saas").is_dir():
            violations.append("the complete SaaS test suite is required")
        for field in (
            "real_postgresql_required",
            "chromium_required",
            "migration_upgrade_check_downgrade_required",
            "patch_replay_required",
            "source_intrusion_budget_required",
        ):
            if regression.get(field) is not True:
                violations.append(f"regression.{field} must be true")

    vulnerabilities = policy.get("vulnerability_policy")
    if not isinstance(vulnerabilities, dict):
        violations.append("vulnerability_policy must be an object")
    elif vulnerabilities.get("critical_allowed") != 0 or vulnerabilities.get("high_allowed") != 0:
        violations.append("critical and high vulnerability thresholds must both be zero")

    promotion = policy.get("promotion")
    if not isinstance(promotion, dict):
        violations.append("promotion policy must be an object")
    else:
        for field in ("digest_only_deployment", "n_minus_one_digest_required", "canary_required"):
            if promotion.get(field) is not True:
                violations.append(f"promotion.{field} must be true")
        if promotion.get("floating_tag_may_authorize_deployment") is not False:
            violations.append("floating tags must not authorize deployment")
    return violations


def _validate_evidence(repo: Path, policy: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if evidence.get("evidence_version") != 1:
        violations.append("image evidence version must be 1")
    product_revision = evidence.get("product_revision")
    if not isinstance(product_revision, str) or not _GIT_SHA.fullmatch(product_revision):
        violations.append("image evidence product_revision must be a full Git SHA")
    upstream = json.loads((repo / str(policy["upstream_manifest"])).read_text(encoding="utf-8"))
    for field in ("upstream_revision", "adapter_contract_version"):
        if evidence.get(field) != upstream.get(field):
            violations.append(f"image evidence {field} does not match the upstream manifest")

    workflow = evidence.get("workflow")
    if not isinstance(workflow, dict):
        violations.append("image evidence workflow must be an object")
    else:
        for field in ("repository", "workflow_ref", "run_id", "run_attempt", "builder_id"):
            if workflow.get(field) in {None, ""}:
                violations.append(f"image evidence workflow.{field} is required")
        if workflow.get("conclusion") != "success":
            violations.append("image evidence workflow did not succeed")

    materials = evidence.get("materials")
    if not isinstance(materials, dict):
        violations.append("image evidence materials must be an object")
    else:
        bases = materials.get("base_images")
        if not isinstance(bases, dict) or set(bases) != {"python", "node"}:
            violations.append("image evidence must record Python and Node base images")
        elif any(
            not isinstance(ref, str) or not _PINNED_IMAGE.fullmatch(ref) for ref in bases.values()
        ):
            violations.append("every base image material must be digest-pinned")
        locks = materials.get("lockfiles")
        expected_locks = set(policy["reproducibility"]["dependency_locks"])
        if not isinstance(locks, dict) or set(locks) != expected_locks:
            violations.append("image evidence lockfile set is incomplete")
        elif any(
            not isinstance(digest, str) or not _HEX_SHA256.fullmatch(digest)
            for digest in locks.values()
        ):
            violations.append("image evidence lockfile hashes must be SHA-256")
        else:
            for path, digest in locks.items():
                if _sha256(repo / path) != digest:
                    violations.append(f"image evidence lock hash drifted for {path}")
        dockerfile_sha = materials.get("dockerfile_sha256")
        if dockerfile_sha != _sha256(repo / str(policy["dockerfile"])):
            violations.append("image evidence Dockerfile hash drifted")

    images = evidence.get("images")
    if _ids(images) != _ids(policy.get("images")):
        violations.append("image evidence does not cover every policy image")
    policy_images = {
        image["name"]: image for image in policy.get("images", []) if isinstance(image, dict)
    }
    if isinstance(images, list):
        for image in images:
            if not isinstance(image, dict):
                violations.append("image evidence entries must be objects")
                continue
            name = str(image.get("name", "unknown"))
            expected = policy_images.get(name, {})
            if image.get("target") != expected.get("target"):
                violations.append(f"{name} target does not match policy")
            if not isinstance(image.get("manifest_digest"), str) or not _SHA256.fullmatch(
                image["manifest_digest"]
            ):
                violations.append(f"{name} manifest digest is invalid")
            for field in ("platform_digests", "config_digests"):
                values = image.get(field)
                if not isinstance(values, dict) or set(values) != set(
                    expected.get("platforms", [])
                ):
                    violations.append(f"{name} {field} does not cover every platform")
                elif any(
                    not isinstance(value, str) or not _SHA256.fullmatch(value)
                    for value in values.values()
                ):
                    violations.append(f"{name} {field} contains an invalid digest")
            labels = image.get("labels")
            if not isinstance(labels, dict) or set(labels) != set(
                policy.get("required_labels", [])
            ):
                violations.append(f"{name} labels do not match policy")
            else:
                expected_labels = {
                    "org.opencontainers.image.revision": product_revision,
                    "ai.omnigent.upstream.revision": evidence.get("upstream_revision"),
                    "ai.omnigent.saas.schema-revision": evidence.get(
                        "control_plane_schema_revision"
                    ),
                    "ai.omnigent.saas.adapter-contract-version": evidence.get(
                        "adapter_contract_version"
                    ),
                }
                if labels != expected_labels:
                    violations.append(f"{name} labels do not bind the evidence revisions")
            sbom = image.get("sbom")
            if not isinstance(sbom, dict) or set(sbom) != {"spdx_sha256", "cyclonedx_sha256"}:
                violations.append(f"{name} SBOM evidence is incomplete")
            elif any(not _HEX_SHA256.fullmatch(str(value)) for value in sbom.values()):
                violations.append(f"{name} SBOM hashes are invalid")
            provenance = image.get("provenance")
            if not isinstance(provenance, dict):
                violations.append(f"{name} provenance evidence is missing")
            else:
                if provenance.get("verified") is not True:
                    violations.append(f"{name} provenance is not verified")
                if (
                    provenance.get("predicate_type")
                    != policy["attestations"]["provenance_predicate"]
                ):
                    violations.append(f"{name} provenance predicate is invalid")
                if provenance.get("subject_digest") != image.get("manifest_digest"):
                    violations.append(f"{name} provenance subject does not match the image")
                if provenance.get("materials_digest_pinned") is not True:
                    violations.append(f"{name} provenance materials are not digest-pinned")
            signature = image.get("signature")
            if not isinstance(signature, dict) or signature.get("verified") is not True:
                violations.append(f"{name} signature is not verified")
            elif signature.get("issuer") != policy["attestations"]["signature_issuer"]:
                violations.append(f"{name} signature issuer is invalid")
            vulnerabilities = image.get("vulnerabilities")
            if not isinstance(vulnerabilities, dict):
                violations.append(f"{name} vulnerability evidence is missing")
            elif vulnerabilities.get("critical") != 0 or vulnerabilities.get("high") != 0:
                violations.append(f"{name} exceeds the vulnerability threshold")
            smoke = set(image.get("smoke_passed", []))
            if smoke != set(expected.get("required_smoke", [])):
                violations.append(f"{name} smoke evidence does not match policy")

    rebuild = evidence.get("rebuild")
    if not isinstance(rebuild, dict):
        violations.append("image evidence rebuild must be an object")
    else:
        if rebuild.get("attempts") != policy["reproducibility"]["repeat_builds"]:
            violations.append("image evidence repeat-build count is invalid")
        if rebuild.get("matching_platform_manifest_and_config") is not True:
            violations.append("repeat builds did not reproduce platform manifests and configs")

    regression = evidence.get("regression")
    required_regression = {
        "official_suites",
        "saas_suite",
        "real_postgresql",
        "chromium",
        "migration_cycle",
        "patch_replay",
        "source_intrusion_budget",
    }
    if not isinstance(regression, dict) or set(regression) != required_regression:
        violations.append("image evidence regression matrix is incomplete")
    elif any(value is not True for value in regression.values()):
        violations.append("an image regression gate did not pass")
    return violations


def validate_release(
    repo: Path,
    policy: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return policy validity separately from production promotion readiness."""

    violations = _validate_policy(repo, policy)
    blockers: list[str] = []
    evidence_violations: list[str] = []
    if evidence is None:
        blockers.append("no immutable signed production image evidence is recorded")
    else:
        evidence_violations = _validate_evidence(repo, policy, evidence)
        blockers.extend(evidence_violations)
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            "ready"
            if not violations and evidence is not None and not evidence_violations
            else "blocked"
        ),
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "policy_image_count": len(_ids(policy.get("images"))),
            "evidenced_image_count": len(_ids(evidence.get("images") if evidence else [])),
            "readiness_blocker_count": len(set(blockers)),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="saas/supply_chain/release-policy.json")
    parser.add_argument("--evidence")
    parser.add_argument("--output")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    policy = json.loads((repo / args.policy).read_text(encoding="utf-8"))
    evidence_path = args.evidence or policy.get("production_evidence")
    evidence = None
    if isinstance(evidence_path, str) and (repo / evidence_path).is_file():
        evidence = json.loads((repo / evidence_path).read_text(encoding="utf-8"))
    report = validate_release(repo, policy, evidence)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["status"] != "pass":
        return 1
    return 1 if args.require_ready and report["production_readiness"] != "ready" else 0


if __name__ == "__main__":
    raise SystemExit(main())
