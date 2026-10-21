"""Verify the single Server compatibility image and its exact build materials."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts import compare_oci_rebuilds as compare
from saas.scripts import oci_promotion as oci
from saas.scripts import prepare_core_f440_compat as recipe
from saas.scripts import resume_oci_promotion as signatures
from saas.scripts import scan_oci_candidates as scans

WORKFLOW = ".github/workflows/saas-core-f440-compat.yml"
REPOSITORY = "Dream1216/omnigent"
IMAGE = "ghcr.io/dream1216/omnigent-saas-core-f440-compat"


def require(value: object, message: str) -> None:
    if not value:
        raise ValueError(message)


def read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def candidate(
    repository: Path, first: Path, second: Path, revision: str, epoch: int
) -> dict[str, Any]:
    materials = recipe.load_manifest(repository)
    baseline = json.loads(
        subprocess.check_output(
            ["git", "show", recipe.BASE + ":saas/upstream-baseline.json"], cwd=repository
        )
    )
    labels = {
        "org.opencontainers.image.revision": revision,
        "ai.omnigent.upstream.revision": baseline["upstream_revision"],
        "ai.omnigent.saas.schema-revision": "p0s000000015",
        "ai.omnigent.saas.adapter-contract-version": baseline["adapter_contract_version"],
    }
    facts = compare.compare_archives(first, second, label_profile="executable")
    require(
        facts["matching_platform_manifest_and_config"] is True,
        "repeated compatibility builds differ",
    )
    for attempt in ("first", "second"):
        require(
            set(facts[attempt]["platforms"]) == set(scans.PLATFORMS),
            "both compatibility platforms required",
        )
        require(
            facts[attempt]["attestation_descriptor_count"] >= 2,
            "embedded build provenance and SBOM required",
        )
        require(
            all(row["labels"] == labels for row in facts[attempt]["platforms"].values()),
            "compatibility image labels differ",
        )
    return {
        "schema_version": 1,
        "product_revision": revision,
        "source_date_epoch": epoch,
        "image_repository": IMAGE,
        "index_digest": oci.archive_index_digest(first),
        "archive_sha256": scans.file_sha256(first),
        "facts": facts["first"],
        "repeated_build_platforms_match": True,
        "materials": materials,
        "labels": labels,
        "database_changed": False,
        "runner_permissions_changed": False,
        "production_authority": False,
    }


def validate_scans(root: Path, manifest: dict[str, Any], archive_sha: str) -> dict[str, Any]:
    summary_path = root / "server-preflight-scan-summary.json"
    summary = read(summary_path)
    require(
        summary.get("scanner") == "grype " + scans.GRYPE_VERSION
        and summary.get("exceptions") == [],
        "unfiltered current scanner required",
    )
    rows = summary.get("images", [])
    require(
        len(rows) == 2
        and {(row.get("image"), row.get("platform")) for row in rows}
        == {("server", p) for p in scans.PLATFORMS},
        "two exact compatibility platform scans required",
    )
    reports = {}
    for row in rows:
        platform = row["platform"]
        path = root / ("server-" + platform.split("/")[1] + "-grype.json")
        raw = read(path)
        descriptor = raw.get("descriptor", {})
        require(
            descriptor.get("name") == "grype" and descriptor.get("version") == scans.GRYPE_VERSION,
            "raw scanner differs",
        )
        built = scans.parse_database_status(descriptor["db"]["status"], now=datetime.now(UTC))
        require(built == summary["database_built_at"], "database freshness differs")
        config = descriptor.get("configuration", {})
        require(
            config.get("only-fixed") is False
            and config.get("only-notfixed") is False
            and config.get("exclude", []) == []
            and config.get("vex-documents", []) == [],
            "raw findings must not be filtered",
        )
        parsed = scans.scan_report(raw)
        require(
            not any(parsed["counts"].values()), "Critical or High finding blocks this component"
        )
        target = raw.get("source", {}).get("target", {})
        expected = manifest["facts"]["platforms"][platform]
        require(
            target.get("manifestDigest") == expected["manifest_digest"]
            and target.get("imageID") == expected["config_digest"]
            and target.get("labels") == manifest["labels"]
            and target.get("os") == "linux"
            and target.get("architecture") == platform.split("/")[1],
            "raw scan does not bind this exact platform",
        )
        digest = scans.file_sha256(path)
        require(
            row.get("archive_sha256") == archive_sha
            and row.get("report_sha256") == digest
            and row.get("critical") == row.get("high") == 0
            and row.get("findings") == [],
            "scan receipt differs from raw findings",
        )
        reports[path.name] = digest
    return {"summary_sha256": scans.file_sha256(summary_path), "reports": reports}


def predicate(
    manifest: dict[str, Any], revision: str, run_id: str, attempt: str
) -> dict[str, Any]:
    return {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "repository": "https://github.com/" + REPOSITORY,
                    "path": WORKFLOW,
                    "ref": "refs/heads/main",
                },
                "compatibility_contract": recipe.CONTRACT,
                "source_revision": revision,
                "database_changed": False,
                "runner_permissions_changed": False,
            },
            "internalParameters": {},
            "resolvedDependencies": [
                {"uri": "git+https://github.com/" + REPOSITORY, "digest": {"gitCommit": revision}},
                {
                    "uri": "git+https://github.com/" + REPOSITORY,
                    "digest": {"gitCommit": recipe.BASE},
                },
                {"uri": "pkg:pypi/omnigent@f440", "digest": {"sha256": recipe.WHEEL}},
                {"uri": recipe.RUNTIME, "digest": {"sha256": recipe.RUNTIME.split("@sha256:")[1]}},
                {"uri": recipe.UI, "digest": {"sha256": recipe.UI.split("@sha256:")[1]}},
                {
                    "uri": "saas/core_f440_compat/postgresql_migration.patch",
                    "digest": {"sha256": manifest["materials"]["patch_sha256"]},
                },
                {
                    "uri": "installed:" + recipe.MODULE,
                    "digest": {"sha256": manifest["materials"]["patched_module_sha256"]},
                },
            ],
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/" + REPOSITORY + "/" + WORKFLOW + "@refs/heads/main"
            },
            "metadata": {
                "invocationId": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
            },
        },
    }


def verify_signatures(
    root: Path, manifest: dict[str, Any], revision: str, run_id: str, attempt: str
) -> None:
    claims = signatures.certificate_claims(revision, WORKFLOW, run_id, attempt)
    for architecture in (None, "amd64", "arm64"):
        digest = (
            manifest["index_digest"]
            if architecture is None
            else manifest["facts"]["platforms"]["linux/" + architecture]["manifest_digest"]
        )
        expected = (
            predicate(manifest, revision, run_id, attempt)
            if architecture is None
            else read(root / "supply-chain" / (architecture + ".spdx.json"))
        )
        kind = (
            "https://slsa.dev/provenance/v1"
            if architecture is None
            else "https://spdx.dev/Document"
        )
        raw = subprocess.check_output(
            [
                "gh",
                "attestation",
                "verify",
                "oci://" + IMAGE + "@" + digest,
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                REPOSITORY + "/" + WORKFLOW,
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                revision,
                "--signer-digest",
                revision,
                "--deny-self-hosted-runners",
                "--predicate-type",
                kind,
                "--format",
                "json",
            ]
        )
        entries = json.loads(raw)
        signatures.verify_predicate(
            entries,
            subject=digest,
            predicate=expected,
            predicate_type="https://slsa.dev/provenance/v1"
            if architecture is None
            else signatures.SPDX_PREDICATE_TYPE,
            claims=claims,
        )
        (root / ((architecture or "index") + "-signature.json")).write_bytes(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("candidate", "scans", "predicate", "readback", "signatures")
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--epoch", type=int)
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--scan-root", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt", default="1")
    args = parser.parse_args()
    path = args.root / "core-compat-manifest.json"
    if args.command == "candidate":
        args.root.mkdir(parents=True, exist_ok=True)
        value = candidate(Path.cwd(), args.first, args.second, args.revision, args.epoch)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        print(
            json.dumps(
                {"index_digest": value["index_digest"], "archive_sha256": value["archive_sha256"]}
            )
        )
        return
    manifest = read(path)
    require(
        manifest["product_revision"] == args.revision
        and manifest["materials"] == recipe.load_manifest(Path.cwd()),
        "recipe source and runtime differ",
    )
    if args.command == "scans":
        print(
            json.dumps(validate_scans(args.scan_root, manifest, scans.file_sha256(args.archive)))
        )
    elif args.command == "predicate":
        print(
            json.dumps(
                predicate(manifest, args.revision, args.run_id, args.attempt), sort_keys=True
            )
        )
    elif args.command == "readback":
        require(
            oci.archive_index_digest(args.archive) == manifest["index_digest"],
            "registry index differs",
        )
        require(
            compare.inspect_oci_archive(args.archive, label_profile="executable")
            == manifest["facts"],
            "registry executable or embedded facts differ",
        )
        print(
            json.dumps(
                {
                    "status": "pass",
                    "product_revision": args.revision,
                    "index_digest": manifest["index_digest"],
                }
            )
        )
    else:
        verify_signatures(args.root, manifest, args.revision, args.run_id, args.attempt)
        print(
            json.dumps(
                {
                    "status": "pass",
                    "product_revision": args.revision,
                    "exact_index_and_two_spdx_signatures": True,
                }
            )
        )


if __name__ == "__main__":
    main()
