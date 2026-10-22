"""Resume one admitted OCI release with separate product and signer identities."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    expected_labels,
    extract_artifact,
    read_json,
    require,
    validate_scans,
    verify_artifact_metadata,
)
from saas.scripts.scan_oci_candidates import file_sha256

LOCK_PATH = Path("saas/supply_chain/oci-promotion-resume-f440.json")
WORKFLOW = ".github/workflows/saas-oci-promotion-resume.yml"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document/v2.3"
_RELEASE_PROFILES = {
    "f440": (
        LOCK_PATH,
        WORKFLOW,
        "f4404d47f705c7a3c0745c38ccd1a9be125c31ad",
    ),
    "token-renewal-c90a079c": (
        Path("saas/supply_chain/oci-promotion-token-renewal-c90a079c.json"),
        ".github/workflows/saas-oci-promotion-token-renewal.yml",
        "c90a079cb6e3c6cadda35ee1ea3121083e86d8fa",
    ),
    "model-renewal-7cea0940": (
        Path("saas/supply_chain/oci-promotion-model-renewal-7cea0940.json"),
        ".github/workflows/saas-oci-promotion-model-renewal.yml",
        "7cea09404d49fc965ce053e51803688a5be5fe53",
    ),
}
_SELECTED_PRODUCT_REVISION = _RELEASE_PROFILES["f440"][2]


def configure_release_profile(name: str) -> None:
    """Select only an explicit reviewed product/lock/signer tuple."""
    global LOCK_PATH, WORKFLOW, _SELECTED_PRODUCT_REVISION
    require(name in _RELEASE_PROFILES, "unapproved release profile")
    LOCK_PATH, WORKFLOW, _SELECTED_PRODUCT_REVISION = _RELEASE_PROFILES[name]


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def lock() -> dict[str, Any]:
    binding = read_json(LOCK_PATH)
    require(
        binding.get("schema_version") == 1
        and binding.get("repository") == "Dream1216/omnigent"
        and binding.get("product_revision") == _SELECTED_PRODUCT_REVISION
        and binding.get("rebuilt") is False
        and binding.get("production_authority") is False,
        "release profile and immutable material scope differ",
    )
    return binding


def check_artifact(metadata: dict[str, Any], coordinate: str, name: str) -> None:
    binding = lock()
    require(
        metadata.get("id") == binding[f"{coordinate}_artifact_id"]
        and metadata.get("name") == f"{name}-{binding['product_revision']}"
        and metadata.get("digest") == f"sha256:{binding[f'{coordinate}_artifact_sha256']}"
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == binding["candidate_run_id"]
        and metadata.get("workflow_run", {}).get("head_sha") == binding["product_revision"],
        "original artifact identity differs",
    )


def download(coordinate: str, name: str, destination: Path) -> None:
    binding = lock()
    endpoint = (
        f"repos/{binding['repository']}/actions/artifacts/{binding[f'{coordinate}_artifact_id']}"
    )
    check_artifact(api(endpoint), coordinate, name)
    with tempfile.TemporaryDirectory(prefix="omnigent-resume-original-") as directory:
        archive = Path(directory) / "original.zip"
        with archive.open("wb") as stream:
            subprocess.run(["gh", "api", endpoint + "/zip"], stdout=stream, check=True)
        extract_artifact(archive, destination, zip_sha256=binding[f"{coordinate}_artifact_sha256"])


def check_original_run(run: dict[str, Any], job: dict[str, Any]) -> None:
    binding = lock()
    conclusion = binding.get("candidate_run_conclusion", "failure")
    require(
        isinstance(conclusion, str) and conclusion in {"success", "failure"},
        "unapproved original run conclusion",
    )
    require(
        run.get("id") == binding["candidate_run_id"]
        and run.get("run_attempt") == binding["candidate_run_attempt"]
        and run.get("head_sha") == binding["product_revision"]
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == ".github/workflows/saas-image-candidate.yml"
        and run.get("status") == "completed"
        and run.get("conclusion") == conclusion
        and run.get("repository", {}).get("full_name") == binding["repository"]
        and job.get("id") == binding["candidate_build_job_id"]
        and job.get("run_id") == binding["candidate_run_id"]
        and job.get("run_attempt") == binding["candidate_run_attempt"]
        and job.get("name") == "build-candidate"
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("completed_at") == binding["candidate_build_completed_at"]
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-latest" in job.get("labels", []),
        "original successful hosted candidate job is not trusted",
    )


def check_report(root: Path) -> dict[str, Any]:
    binding = lock()
    manifest = read_json(root / MANIFEST_NAME)
    comparison = read_json(root / "saas-image-candidate.json")
    require(
        file_sha256(root / MANIFEST_NAME) == binding["candidate_manifest_sha256"]
        and manifest.get("product_revision") == binding["product_revision"]
        and manifest.get("source_date_epoch") == binding["source_date_epoch"]
        and manifest.get("labels") == expected_labels(Path.cwd(), binding["product_revision"])
        and file_sha256(root / "saas-image-candidate.json") == manifest["comparison_sha256"]
        and comparison.get("status") == "pass"
        and comparison.get("violations") == []
        and comparison.get("product_revision") == binding["product_revision"]
        and comparison.get("source_date_epoch") == binding["source_date_epoch"],
        "original candidate report or source differs",
    )
    for role, digest in binding["images"].items():
        image = manifest["images"][role]
        repeated = comparison["images"][f"omnigent-saas-{role}"]
        require(
            image["index_digest"] == digest
            and repeated.get("matching_platform_manifest_and_config") is True
            and repeated.get("history_created_by_equal") is True
            and repeated.get("first") == image["facts"]
            and repeated.get("second", {}).get("platforms") == image["facts"]["platforms"]
            and repeated.get("second", {}).get("attestations") == image["facts"]["attestations"],
            "original repeat facts differ",
        )
    completed_at = datetime.fromisoformat(
        binding["candidate_build_completed_at"].replace("Z", "+00:00")
    )
    sealed_at = datetime.fromisoformat(manifest["sealed_at"])
    require(
        completed_at.tzinfo is not None
        and sealed_at.tzinfo is not None
        and sealed_at <= completed_at <= datetime.now(UTC),
        "trusted original candidate completion time differs",
    )
    require(
        validate_scans(root, manifest["images"], now=completed_at) == manifest["scans"],
        "original raw scans differ",
    )
    return manifest


def child_reference(root: Path, role: str, architecture: str) -> str:
    binding = lock()
    manifest = read_json(root / MANIFEST_NAME)
    require(
        file_sha256(root / MANIFEST_NAME) == binding["candidate_manifest_sha256"]
        and role in binding["images"]
        and architecture in ("amd64", "arm64")
        and manifest["images"][role]["index_digest"] == binding["images"][role],
        "child manifest is not in the admitted index",
    )
    digest = manifest["images"][role]["facts"]["platforms"][f"linux/{architecture}"][
        "manifest_digest"
    ]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None, "invalid child digest")
    return f"ghcr.io/dream1216/omnigent-saas-{role}@{digest}"


def promotion_predicate(policy_revision: str, run_id: str, attempt: str) -> dict[str, Any]:
    binding = lock()
    require(re.fullmatch(r"[0-9a-f]{40}", policy_revision) is not None, "invalid policy SHA")
    require(policy_revision != binding["product_revision"], "signer policy must be explicit")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "invalid signing run")
    require(re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "invalid signing attempt")
    repository = f"https://github.com/{binding['repository']}"
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "path": WORKFLOW,
                    "ref": "refs/heads/main",
                    "repository": repository,
                },
                "product_source_revision": binding["product_revision"],
                "signing_policy_revision": policy_revision,
                "original_candidate": binding,
                "rebuild_performed": False,
            },
            "internalParameters": {
                "github": {
                    "event_name": "workflow_dispatch",
                    "repository_id": "1319241251",
                    "repository_owner_id": "39821512",
                    "runner_environment": "github-hosted",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{repository}@refs/heads/main",
                    "digest": {"gitCommit": policy_revision},
                },
                {
                    "uri": f"git+{repository}@{binding['product_revision']}",
                    "digest": {"gitCommit": binding["product_revision"]},
                },
                {
                    "uri": f"{repository}/actions/artifacts/{binding['oci_artifact_id']}",
                    "digest": {"sha256": binding["oci_artifact_sha256"]},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": f"{repository}/{WORKFLOW}@refs/heads/main"},
            "metadata": {"invocationId": f"{repository}/actions/runs/{run_id}/attempts/{attempt}"},
        },
    }


def certificate_claims(revision: str, workflow: str, run_id: str, attempt: str) -> dict[str, str]:
    binding = lock()
    repository = f"https://github.com/{binding['repository']}"
    return {
        "issuer": "https://token.actions.githubusercontent.com",
        "sourceRepositoryURI": repository,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryDigest": revision,
        "buildSignerDigest": revision,
        "buildConfigDigest": revision,
        "runnerEnvironment": "github-hosted",
        "subjectAlternativeName": f"{repository}/{workflow}@refs/heads/main",
        "runInvocationURI": f"{repository}/actions/runs/{run_id}/attempts/{attempt}",
    }


def verify_predicate(
    entries: list[dict[str, Any]],
    *,
    subject: str,
    predicate: dict[str, Any],
    predicate_type: str,
    claims: dict[str, str],
) -> None:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", subject) is not None, "invalid subject")
    found = False
    for entry in entries:
        result = entry["verificationResult"]
        certificate = result["signature"]["certificate"]
        statement = result["statement"]
        if not all(certificate.get(key) == value for key, value in claims.items()):
            continue
        if statement.get("predicateType") != predicate_type:
            continue
        if json.dumps(statement.get("predicate"), sort_keys=True) != json.dumps(
            predicate, sort_keys=True
        ):
            continue
        require(
            any(s.get("digest", {}).get("sha256") == subject[7:] for s in statement["subject"]),
            "signed promotion subject differs",
        )
        found = True
    require(found, "verified certificate and explicit original-product promotion binding required")


def verify_signature(
    entries: list[dict[str, Any]], *, subject: str, policy_revision: str, run_id: str, attempt: str
) -> None:
    require(subject in lock()["images"].values(), "subject is not an admitted image index")
    verify_predicate(
        entries,
        subject=subject,
        predicate=promotion_predicate(policy_revision, run_id, attempt),
        predicate_type=PREDICATE_TYPE,
        claims=certificate_claims(policy_revision, WORKFLOW, run_id, attempt),
    )


def verify_sbom(
    entries: list[dict[str, Any]],
    *,
    subject: str,
    predicate: dict[str, Any],
    claims: dict[str, str],
) -> None:
    require(
        predicate.get("spdxVersion") == "SPDX-2.3"
        and isinstance(predicate.get("packages"), list)
        and bool(predicate["packages"]),
        "complete SPDX 2.3 package inventory required",
    )
    verify_predicate(
        entries,
        subject=subject,
        predicate=predicate,
        predicate_type=SPDX_PREDICATE_TYPE,
        claims=claims,
    )


def verify_original_wheel(entries: list[dict[str, Any]]) -> None:
    binding = lock()
    claims = certificate_claims(
        binding["product_revision"],
        ".github/workflows/saas-image-candidate.yml",
        str(binding["candidate_run_id"]),
        str(binding["candidate_run_attempt"]),
    )
    for entry in entries:
        result = entry["verificationResult"]
        certificate = result["signature"]["certificate"]
        statement = result["statement"]
        if not all(certificate.get(key) == value for key, value in claims.items()):
            continue
        if statement.get("predicateType") != PREDICATE_TYPE:
            continue
        predicate = statement["predicate"]
        require(
            any(
                s.get("digest", {}).get("sha256") == binding["wheel_sha256"]
                for s in statement["subject"]
            )
            and predicate["runDetails"]["builder"]["id"] == claims["subjectAlternativeName"]
            and predicate["runDetails"]["metadata"]["invocationId"] == claims["runInvocationURI"]
            and any(
                dependency.get("uri")
                == "git+https://github.com/Dream1216/omnigent@refs/heads/main"
                and dependency.get("digest", {}).get("gitCommit") == binding["product_revision"]
                for dependency in predicate["buildDefinition"]["resolvedDependencies"]
            ),
            "original wheel provenance differs",
        )
        return
    raise ValueError("original wheel certificate and candidate run binding required")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", choices=tuple(_RELEASE_PROFILES), default="f440")
    parser.add_argument(
        "command",
        choices=(
            "preflight",
            "wheel",
            "child",
            "predicate",
            "verify",
            "verify-sbom",
            "verify-wheel",
        ),
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--role", choices=("server", "host"))
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    parser.add_argument("--policy-revision")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--verification", type=Path)
    parser.add_argument("--subject")
    parser.add_argument("--sbom", type=Path)
    args = parser.parse_args()
    configure_release_profile(args.release)
    binding = lock()
    if args.command == "preflight":
        prefix = f"repos/{binding['repository']}/actions"
        check_original_run(
            api(f"{prefix}/runs/{binding['candidate_run_id']}"),
            api(f"{prefix}/jobs/{binding['candidate_build_job_id']}"),
        )
        metadata = api(f"{prefix}/artifacts/{binding['oci_artifact_id']}")
        verify_artifact_metadata(
            metadata,
            artifact_id=binding["oci_artifact_id"],
            zip_sha256=binding["oci_artifact_sha256"],
            revision=binding["product_revision"],
            run_id=binding["candidate_run_id"],
        )
        download("report", "saas-image-candidate", args.root)
        check_report(args.root)
        print(json.dumps({"status": "pass", "original_candidate": binding}, sort_keys=True))
    elif args.command == "wheel":
        download("wheel", "omnigent-saas-wheel", args.root)
        wheels = list(args.root.rglob("*.whl"))
        require(
            len(wheels) == 1 and file_sha256(wheels[0]) == binding["wheel_sha256"],
            "original wheel bytes differ",
        )
        print(wheels[0])
    elif args.command == "child":
        print(child_reference(args.root, args.role, args.architecture))
    elif args.command == "predicate":
        print(json.dumps(promotion_predicate(args.policy_revision, args.run_id, args.attempt)))
    elif args.command == "verify":
        verify_signature(
            json.loads(args.verification.read_text()),
            subject=args.subject,
            policy_revision=args.policy_revision,
            run_id=args.run_id,
            attempt=args.attempt,
        )
        print(
            json.dumps({"status": "pass", "verification_sha256": file_sha256(args.verification)})
        )
    elif args.command == "verify-sbom":
        verify_sbom(
            json.loads(args.verification.read_text()),
            subject=args.subject,
            predicate=read_json(args.sbom),
            claims=certificate_claims(args.policy_revision, WORKFLOW, args.run_id, args.attempt),
        )
        print(json.dumps({"status": "pass", "subject": args.subject}))
    else:
        verify_original_wheel(json.loads(args.verification.read_text()))
        print(json.dumps({"status": "pass", "wheel_sha256": binding["wheel_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
