"""Produce the final, revision-bound production admission artifact bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.production.admission import validate_evidence_admission
from saas.production.readiness import validate_production_readiness

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_OUTPUT_FILES = {
    "admission": "evidence-admission-report.json",
    "readiness": "production-readiness-report.json",
    "bundle": "production-admission-bundle.json",
}


def _render(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git_head(repo: Path) -> str | None:
    result = subprocess.run(
        ("git", "-C", str(repo), "rev-parse", "--verify", "HEAD"),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def build_production_admission_bundle(
    repo: Path,
    *,
    product_revision: str,
    evidence_revision: str,
    now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Run both authoritative verifiers and bind their bytes to one bundle."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    violations: list[str] = []
    if _GIT_SHA.fullmatch(product_revision) is None:
        violations.append("product_revision must be a full lowercase Git SHA")
    if _GIT_SHA.fullmatch(evidence_revision) is None:
        violations.append("evidence_revision must be a full lowercase Git SHA")
    head = _git_head(repo)
    if head is None:
        violations.append("evidence repository HEAD cannot be resolved")
    elif head != evidence_revision:
        violations.append("checked-out HEAD does not match evidence_revision")

    policy = json.loads(
        (repo / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
    )
    admission = validate_evidence_admission(
        repo,
        policy,
        expected_product_revision=product_revision,
        now=current,
    )
    readiness = validate_production_readiness(
        repo,
        expected_product_revision=product_revision,
        now=current,
    )
    for name, report in (("admission", admission), ("readiness", readiness)):
        report_violations = report.get("violations", [])
        if isinstance(report_violations, list):
            violations.extend(
                f"{name}: {item}" for item in report_violations if isinstance(item, str)
            )
    admission_bytes = _render(admission)
    readiness_bytes = _render(readiness)
    structural_pass = (
        not violations and admission.get("status") == "pass" and readiness.get("status") == "pass"
    )
    ready = (
        structural_pass
        and admission.get("production_readiness") == "ready"
        and readiness.get("production_readiness") == "ready"
        and readiness.get("release_decision") == "GO"
    )
    blockers: list[str] = []
    if admission.get("production_readiness") != "ready":
        blockers.append("production evidence admission is not ready")
    if readiness.get("production_readiness") != "ready":
        blockers.append("aggregate production readiness is not ready")
    bundle = {
        "schema_version": 1,
        "contract": "omnigent-saas-final-production-admission-v1",
        "generated_at": current.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "product_revision": product_revision,
        "evidence_revision": evidence_revision,
        "status": "pass" if structural_pass else "fail",
        "production_readiness": "ready" if ready else "blocked",
        "release_decision": "GO" if ready else "NO-GO",
        "violations": sorted(set(violations)),
        "blockers": blockers,
        "reports": {
            "evidence_admission": {
                "path": _OUTPUT_FILES["admission"],
                "sha256": _sha256(admission_bytes),
            },
            "production_readiness": {
                "path": _OUTPUT_FILES["readiness"],
                "sha256": _sha256(readiness_bytes),
            },
        },
        "metrics": {
            "ready_evidence_kind_count": admission.get("metrics", {}).get("ready_kind_count"),
            "required_evidence_kind_count": admission.get("metrics", {}).get(
                "required_kind_count"
            ),
            "derived_ready_gate_count": readiness.get("metrics", {}).get(
                "derived_ready_gate_count"
            ),
            "aggregate_gate_count": readiness.get("metrics", {}).get("aggregate_gate_count"),
            "ledger_passed_gate_count": readiness.get("metrics", {}).get(
                "ledger_passed_gate_count"
            ),
        },
    }
    return {"admission": admission, "readiness": readiness, "bundle": bundle}


def _output_directory(repo: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
        raise ValueError("output directory must be a safe repository-relative path")
    output = repo / relative
    current = repo
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("output directory cannot traverse a symbolic link")
    try:
        output.resolve().relative_to(repo.resolve())
    except ValueError as error:
        raise ValueError("output directory escapes the repository") from error
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--evidence-revision", required=True)
    parser.add_argument("--output-directory", default="artifacts/production-admission")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        reports = build_production_admission_bundle(
            repo,
            product_revision=args.product_revision,
            evidence_revision=args.evidence_revision,
        )
        output = _output_directory(repo, args.output_directory)
        output.mkdir(parents=True, exist_ok=True)
        for key, filename in _OUTPUT_FILES.items():
            (output / filename).write_bytes(_render(reports[key]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(_render(reports["bundle"]).decode("utf-8"), end="")
    bundle = reports["bundle"]
    if bundle["status"] != "pass":
        return 1
    return 1 if args.require_ready and bundle["production_readiness"] != "ready" else 0


if __name__ == "__main__":
    raise SystemExit(main())
