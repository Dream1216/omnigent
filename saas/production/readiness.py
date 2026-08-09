"""Derive the ten aggregate production gates from authoritative evidence verifiers."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.production.admission import validate_evidence_admission
from saas.production.business import load_business_evidence, validate_business_readiness
from saas.production.deletion import load_deletion_evidence, validate_deletion_readiness
from saas.production.deployment import (
    load_deployment_evidence,
    validate_deployment_readiness,
)
from saas.production.recovery import load_recovery_evidence, validate_recovery_readiness
from saas.production.slo_capacity import (
    load_slo_capacity_evidence,
    validate_slo_capacity_readiness,
)
from saas.scripts.check_acceptance_manifest import validate_manifest
from saas.scripts.check_image_supply_chain import load_release_evidence, validate_release
from saas.scripts.check_production_baseline import validate_baseline

_AGGREGATE_GATES = (
    "p0-reproducible-official-image-and-oss-regression",
    "p0-slo-rpo-rto-threat-model-and-service-catalog",
    "p4-production-containment-egress-preview-tunnel",
    "p4-two-failure-domain-and-n-minus-one-rollback",
    "p5-multi-az-pitr-isolated-backup-and-recovery",
    "p5-slo-capacity-supply-chain-api-webhook-deletion",
    "p5-production-foundation-gate",
    "p6-billing-ledger-entitlement-quota-subscription",
    "p6-enterprise-identity-audit-api-platform-console-privacy",
    "p6-two-consecutive-upstream-syncs-and-commercial-gate",
)
_PRODUCT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_ONLY_EXACT_PATHS = {
    "saas/acceptance/p0-p6-evidence.json",
    "saas/acceptance/p0-production-image-evidence.json",
}
_EVIDENCE_ONLY_PREFIXES = (
    "saas/production/commercial-evidence/",
    "saas/production/deletion-evidence/",
    "saas/production/deployment-evidence/",
    "saas/production/enterprise-evidence/",
    "saas/production/evidence-admission-receipts/",
    "saas/production/recovery-evidence/",
    "saas/production/slo-capacity-evidence/",
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _ready(report: Mapping[str, Any]) -> bool:
    return report.get("status") == "pass" and report.get("production_readiness") == "ready"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", "-C", str(repo), *args),
        check=False,
        capture_output=True,
        text=True,
    )


def _evidence_only_path(value: str) -> bool:
    return value in _EVIDENCE_ONLY_EXACT_PATHS or (
        value.endswith(".json")
        and any(value.startswith(prefix) for prefix in _EVIDENCE_ONLY_PREFIXES)
    )


def validate_candidate_revision(value: str | None, repo: Path | None = None) -> dict[str, Any]:
    """Require callers to bind production admission to one exact release SHA."""

    if value is None:
        return {
            "status": "pass",
            "production_readiness": "blocked",
            "violations": [],
            "blockers": ["an exact product revision was not supplied for release admission"],
        }
    if _PRODUCT_REVISION.fullmatch(value) is None:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["release admission product revision must be a full Git SHA"],
            "blockers": [],
        }
    if repo is None:
        return {
            "status": "pass",
            "production_readiness": "ready",
            "violations": [],
            "blockers": [],
        }
    commit = _git(repo, "rev-parse", "--verify", f"{value}^{{commit}}")
    head = _git(repo, "rev-parse", "--verify", "HEAD")
    if commit.returncode != 0 or head.returncode != 0:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["release candidate revision cannot be resolved in this repository"],
            "blockers": [],
        }
    ancestor = _git(repo, "merge-base", "--is-ancestor", value, "HEAD")
    if ancestor.returncode not in {0, 1}:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["release candidate ancestry could not be verified"],
            "blockers": [],
        }
    blockers: list[str] = []
    if ancestor.returncode == 1:
        blockers.append("release candidate is not an ancestor of the evidence revision")
    changed = _git(repo, "diff", "--name-only", f"{value}..HEAD", "--")
    if changed.returncode != 0:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["release candidate evidence-only delta could not be verified"],
            "blockers": [],
        }
    non_evidence_paths = sorted(
        path for path in changed.stdout.splitlines() if path and not _evidence_only_path(path)
    )
    if non_evidence_paths:
        blockers.append(
            "commits after the release candidate modify non-evidence paths: "
            + ", ".join(non_evidence_paths)
        )
    dirty = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty.returncode != 0:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["release admission working-tree state could not be verified"],
            "blockers": [],
        }
    if dirty.stdout.strip():
        blockers.append("release admission requires a clean repository working tree")
    return {
        "status": "pass",
        "production_readiness": "blocked" if blockers else "ready",
        "violations": [],
        "blockers": blockers,
        "candidate_revision": value,
        "evidence_revision": head.stdout.strip(),
    }


def _report_blockers(name: str, report: Mapping[str, Any]) -> list[str]:
    values = report.get("violations", [])
    blockers = report.get("blockers", [])
    rendered: list[str] = []
    if isinstance(values, list):
        rendered.extend(f"{name}: {value}" for value in values if isinstance(value, str))
    if isinstance(blockers, list):
        rendered.extend(f"{name}: {value}" for value in blockers if isinstance(value, str))
    if not rendered and not _ready(report):
        rendered.append(f"{name}: verifier did not report production ready")
    return rendered


def _admission_kind_report(report: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    kinds = report.get("kinds")
    if not isinstance(kinds, Mapping):
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": ["evidence admission report has no kind results"],
            "blockers": [],
        }
    item = kinds.get(kind)
    if not isinstance(item, Mapping):
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": [f"evidence admission report omits {kind}"],
            "blockers": [],
        }
    global_violations = report.get("violations", [])
    item_violations = item.get("violations", [])
    violations = sorted(
        {
            value
            for values in (global_violations, item_violations)
            if isinstance(values, list)
            for value in values
            if isinstance(value, str)
        }
    )
    blockers = item.get("blockers", [])
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            item.get("production_readiness") if not violations else "blocked"
        ),
        "violations": violations,
        "blockers": blockers if isinstance(blockers, list) else [],
    }


def validate_consecutive_upstream_syncs(repo: Path) -> dict[str, Any]:
    """Validate the two explicit P6 consecutive-sync records and their chain."""

    violations: list[str] = []
    try:
        policy = _load_json(repo / "saas/production/upstream-sync-policy.json")
        raw_records = policy.get("records")
        if (
            policy.get("schema_version") != 1
            or not isinstance(raw_records, list)
            or len(raw_records) != 2
        ):
            raise ValueError("upstream sync policy must pin exactly two records")
        records: list[dict[str, Any]] = []
        record_paths: list[str] = []
        for item in raw_records:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise ValueError("upstream sync policy record fields are invalid")
            relative = item.get("path")
            expected_digest = item.get("sha256")
            if (
                not isinstance(relative, str)
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or not isinstance(expected_digest, str)
            ):
                raise ValueError("upstream sync policy path or digest is invalid")
            path = repo / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"upstream sync record is not a regular file: {relative}")
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_digest != expected_digest:
                violations.append(f"upstream sync record digest drifted: {relative}")
            records.append(_load_json(path))
            record_paths.append(relative)
        first, second = records
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {
            "status": "fail",
            "production_readiness": "blocked",
            "violations": [f"cannot load consecutive upstream evidence: {error}"],
            "blockers": [],
        }
    for label, record in (("first", first), ("second", second)):
        if record.get("conclusion") != "success":
            violations.append(f"{label} upstream sync did not succeed")
        upstream = record.get("upstream")
        intrusion = record.get("source_intrusion")
        if not isinstance(upstream, dict):
            violations.append(f"{label} upstream sync has no revision facts")
        elif (
            not isinstance(upstream.get("commits_advanced"), int)
            or upstream["commits_advanced"] <= 0
            or upstream.get("merge_conflicts") != 0
        ):
            violations.append(f"{label} upstream sync did not advance cleanly")
        if not isinstance(intrusion, dict):
            violations.append(f"{label} upstream sync has no intrusion facts")
        else:
            for actual, budget in (
                ("direct_upstream_files", "direct_upstream_file_budget"),
                ("upstream_net_added_loc", "upstream_net_added_loc_budget"),
                ("active_patches", "active_patch_budget"),
            ):
                if (
                    not isinstance(intrusion.get(actual), int)
                    or not isinstance(intrusion.get(budget), int)
                    or intrusion[actual] > intrusion[budget]
                ):
                    violations.append(f"{label} upstream sync exceeds {actual} budget")
    first_upstream = first.get("upstream")
    second_upstream = second.get("upstream")
    if isinstance(first_upstream, dict) and isinstance(second_upstream, dict):
        if second_upstream.get("previous_revision") != first_upstream.get("verified_revision"):
            violations.append("P6 upstream sync records are not a consecutive revision chain")
        if second_upstream.get("verified_revision") == first_upstream.get("verified_revision"):
            violations.append("second P6 upstream sync is not strictly later")
    contract = second.get("consecutive_sync_contract")
    required_flags = {
        "strictly_later_upstream_revision",
        "both_exact_compatibility_runs_passed",
        "both_source_intrusion_results_within_budget",
        "two_consecutive_upstream_sync_condition_satisfied",
    }
    if not isinstance(contract, dict) or any(
        contract.get(flag) is not True for flag in required_flags
    ):
        violations.append("second P6 record does not attest the consecutive-sync contract")
    elif (
        contract.get("first_current_p6_sync_evidence") != record_paths[0]
        or contract.get("second_later_p6_sync_evidence") != record_paths[1]
    ):
        violations.append("second P6 record references a different consecutive-sync chain")
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": "ready" if not violations else "blocked",
        "violations": sorted(set(violations)),
        "blockers": [],
    }


def derive_gate_results(reports: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map verifier readiness to the ten aggregate production gates."""

    requirements: dict[str, tuple[str, ...]] = {
        _AGGREGATE_GATES[0]: ("candidate_revision", "image", "image_admission"),
        _AGGREGATE_GATES[1]: (
            "candidate_revision",
            "baseline",
            "baseline_admission",
        ),
        _AGGREGATE_GATES[2]: (
            "candidate_revision",
            "deployment",
            "deployment_admission",
        ),
        _AGGREGATE_GATES[3]: (
            "candidate_revision",
            "deployment",
            "deployment_admission",
            "image",
            "image_admission",
        ),
        _AGGREGATE_GATES[4]: (
            "candidate_revision",
            "deployment",
            "deployment_admission",
            "recovery",
            "recovery_admission",
        ),
        _AGGREGATE_GATES[5]: (
            "candidate_revision",
            "slo_capacity",
            "slo_capacity_admission",
            "image",
            "image_admission",
            "deletion",
            "deletion_admission",
            "deployment",
            "deployment_admission",
        ),
        _AGGREGATE_GATES[6]: (
            "candidate_revision",
            "baseline",
            "baseline_admission",
            "image",
            "image_admission",
            "deployment",
            "deployment_admission",
            "recovery",
            "recovery_admission",
            "slo_capacity",
            "slo_capacity_admission",
            "deletion",
            "deletion_admission",
        ),
        _AGGREGATE_GATES[7]: (
            "candidate_revision",
            "commercial",
            "commercial_admission",
        ),
        _AGGREGATE_GATES[8]: (
            "candidate_revision",
            "enterprise",
            "enterprise_admission",
            "deletion",
            "deletion_admission",
        ),
        _AGGREGATE_GATES[9]: (
            "candidate_revision",
            "upstream_sync",
            "commercial",
            "commercial_admission",
        ),
    }
    results: dict[str, dict[str, Any]] = {}
    for gate, names in requirements.items():
        missing = [name for name in names if name not in reports]
        blockers: list[str] = []
        for name in names:
            report = reports.get(name)
            if report is not None and not _ready(report):
                blockers.extend(_report_blockers(name, report))
        blockers.extend(f"missing verifier report: {name}" for name in missing)
        results[gate] = {
            "ready": not blockers,
            "requirements": list(names),
            "blockers": sorted(set(blockers)),
        }
    return results


def validate_gate_ledger(
    manifest: Mapping[str, Any], gate_results: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    """Reject aggregate ledger claims that are stronger than derived evidence."""

    violations: list[str] = []
    ledger_gates = {
        gate.get("id"): gate
        for phase in manifest.get("phases", [])
        if isinstance(phase, dict)
        for gate in phase.get("gates", [])
        if isinstance(gate, dict)
    }
    if set(gate_results) != set(_AGGREGATE_GATES):
        violations.append("derived production gate set does not match the ten-gate contract")
    for gate_id, result in gate_results.items():
        ledger = ledger_gates.get(gate_id)
        if not isinstance(ledger, dict):
            violations.append(f"aggregate gate {gate_id} is missing from the acceptance ledger")
        elif ledger.get("status") == "passed" and result.get("ready") is not True:
            violations.append(f"aggregate gate {gate_id} is passed without qualifying evidence")
    return violations


def validate_production_readiness(
    repo: Path,
    *,
    expected_product_revision: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run every production verifier and reject ledger states stronger than evidence."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    manifest = _load_json(repo / "saas/acceptance/p0-p6-evidence.json")
    baseline = _load_json(repo / "saas/production/baseline.json")
    image_policy = _load_json(repo / "saas/supply_chain/release-policy.json")
    deployment_policy = _load_json(repo / "saas/production/deployment-policy.json")
    recovery_policy = _load_json(repo / "saas/production/recovery-policy.json")
    slo_policy = _load_json(repo / "saas/production/slo-capacity-policy.json")
    deletion_policy = _load_json(repo / "saas/production/deletion-policy.json")
    commercial_policy = _load_json(repo / "saas/production/commercial-policy.json")
    enterprise_policy = _load_json(repo / "saas/production/enterprise-policy.json")
    admission_policy = _load_json(repo / "saas/production/evidence-admission-policy.json")

    image_evidence = load_release_evidence(
        repo,
        image_policy.get("production_evidence"),
        allow_missing=True,
    )
    admission_report = validate_evidence_admission(
        repo,
        admission_policy,
        expected_product_revision=expected_product_revision,
        now=current,
    )
    reports: dict[str, Mapping[str, Any]] = {
        "candidate_revision": validate_candidate_revision(expected_product_revision, repo),
        "baseline": validate_baseline(repo, baseline),
        "image": validate_release(
            repo,
            image_policy,
            image_evidence,
            now=current,
            expected_product_revision=expected_product_revision,
        ),
        "deployment": validate_deployment_readiness(
            repo,
            deployment_policy,
            load_deployment_evidence(repo, deployment_policy),
            now=current,
            expected_product_revision=expected_product_revision,
            baseline=baseline,
        ),
        "recovery": validate_recovery_readiness(
            repo,
            recovery_policy,
            load_recovery_evidence(repo, recovery_policy),
            now=current,
            expected_product_revision=expected_product_revision,
        ),
        "slo_capacity": validate_slo_capacity_readiness(
            repo,
            slo_policy,
            load_slo_capacity_evidence(repo, slo_policy),
            now=current,
            expected_product_revision=expected_product_revision,
            baseline=baseline,
        ),
        "deletion": validate_deletion_readiness(
            repo,
            deletion_policy,
            load_deletion_evidence(repo, deletion_policy),
            now=current,
            expected_product_revision=expected_product_revision,
        ),
        "commercial": validate_business_readiness(
            repo,
            commercial_policy,
            load_business_evidence(repo, commercial_policy),
            now=current,
            expected_product_revision=expected_product_revision,
            baseline=baseline,
        ),
        "enterprise": validate_business_readiness(
            repo,
            enterprise_policy,
            load_business_evidence(repo, enterprise_policy),
            now=current,
            expected_product_revision=expected_product_revision,
            baseline=baseline,
        ),
        "upstream_sync": validate_consecutive_upstream_syncs(repo),
    }
    for kind in (
        "baseline",
        "image",
        "deployment",
        "recovery",
        "slo_capacity",
        "deletion",
        "commercial",
        "enterprise",
    ):
        reports[f"{kind}_admission"] = _admission_kind_report(admission_report, kind)
    gate_results = derive_gate_results(reports)
    violations = list(validate_manifest(repo, manifest))
    ledger_gates = {
        gate.get("id"): gate
        for phase in manifest.get("phases", [])
        if isinstance(phase, dict)
        for gate in phase.get("gates", [])
        if isinstance(gate, dict)
    }
    violations.extend(validate_gate_ledger(manifest, gate_results))

    every_gate_ready = all(result["ready"] for result in gate_results.values())
    every_gate_passed = all(
        isinstance(ledger_gates.get(gate_id), dict)
        and ledger_gates[gate_id].get("status") == "passed"
        for gate_id in _AGGREGATE_GATES
    )
    phases_complete = all(
        isinstance(phase, dict) and phase.get("status") == "complete"
        for phase in manifest.get("phases", [])
    )
    release_go = manifest.get("release_decision") == "GO"
    report_summaries = {
        name: {
            "status": report.get("status"),
            "production_readiness": report.get("production_readiness"),
            "violations": report.get("violations", []),
            "blockers": report.get("blockers", []),
        }
        for name, report in reports.items()
    }
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            "ready"
            if not violations
            and every_gate_ready
            and every_gate_passed
            and phases_complete
            and release_go
            else "blocked"
        ),
        "release_decision": manifest.get("release_decision"),
        "violations": sorted(set(violations)),
        "gate_results": gate_results,
        "verifiers": report_summaries,
        "metrics": {
            "aggregate_gate_count": len(gate_results),
            "derived_ready_gate_count": sum(
                int(result["ready"]) for result in gate_results.values()
            ),
            "ledger_passed_gate_count": sum(
                int(
                    isinstance(ledger_gates.get(gate_id), dict)
                    and ledger_gates[gate_id].get("status") == "passed"
                )
                for gate_id in _AGGREGATE_GATES
            ),
            "structural_violation_count": len(set(violations)),
        },
    }
