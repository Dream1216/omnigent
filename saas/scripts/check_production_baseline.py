"""Validate P0 production decisions, ownership, SLO, DR, and threat-model data."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from saas.scripts.check_adr_approvals import validate_approval_contract

_ADR_IDS = {f"ADR-{index:03d}" for index in range(1, 12)}
_SERVICE_IDS = {
    "control-plane",
    "compatibility-adapter",
    "queue-worker",
    "runner-sandbox",
    "billing-metering",
    "audit",
    "admin",
}
_SLO_IDS = {
    "SLO-AUTH",
    "SLO-RESOLVE",
    "SLO-ADMISSION",
    "SLO-REVOCATION",
    "SLO-OUTBOX",
    "SLO-RUN-EVENT",
}
_DATA_CLASSES = {"T0", "T1", "T2"}
_STRIDE = set("STRIDE")
_OWNER_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_MIGRATION_REVISION = re.compile(r'^revision:\s*str\s*=\s*"([^"]+)"', re.MULTILINE)
_MIGRATION_PARENT = re.compile(
    r'^down_revision:\s*str\s*\|\s*None\s*=\s*(?:"([^"]+)"|None)', re.MULTILINE
)


def _ids(items: object, *, field: str = "id") -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        value
        for item in items
        if isinstance(item, dict) and isinstance((value := item.get(field)), str)
    }


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _owner(value: object) -> bool:
    return isinstance(value, str) and _OWNER_PATTERN.fullmatch(value) is not None


def _migration_graph(repo: Path) -> dict[str, str | None]:
    graph: dict[str, str | None] = {}
    for path in (repo / "saas/control_plane/migrations/versions").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        revision = _MIGRATION_REVISION.search(text)
        parent = _MIGRATION_PARENT.search(text)
        if revision:
            graph[revision.group(1)] = parent.group(1) if parent else None
    return graph


def _migration_heads(repo: Path) -> set[str]:
    graph = _migration_graph(repo)
    return set(graph) - {parent for parent in graph.values() if parent is not None}


def _is_migration_ancestor(repo: Path, ancestor: object, descendant: object) -> bool:
    if not isinstance(ancestor, str) or not isinstance(descendant, str):
        return False
    graph = _migration_graph(repo)
    current: str | None = descendant
    visited: set[str] = set()
    while current is not None and current not in visited:
        if current == ancestor:
            return True
        visited.add(current)
        current = graph.get(current)
    return False


def validate_baseline(repo: Path, baseline: dict[str, Any]) -> dict[str, Any]:
    """Return structural violations and explicit production-readiness blockers."""

    violations: list[str] = []
    blockers: list[str] = []
    if baseline.get("schema_version") != 1:
        violations.append("schema_version must be 1")

    revision = baseline.get("revision_contract")
    if not isinstance(revision, dict):
        violations.append("revision_contract must be an object")
    else:
        manifest_path = revision.get("upstream_manifest")
        if not isinstance(manifest_path, str) or not (repo / manifest_path).is_file():
            violations.append("revision_contract.upstream_manifest must reference a file")
        else:
            manifest = json.loads((repo / manifest_path).read_text(encoding="utf-8"))
            for key in ("upstream_revision", "adapter_contract_version"):
                if revision.get(key) != manifest.get(key):
                    violations.append(f"revision_contract.{key} does not match upstream manifest")
        schema_revision = revision.get("control_plane_schema_revision")
        heads = _migration_heads(repo)
        if heads != {schema_revision}:
            violations.append(
                f"control_plane_schema_revision must be the only migration head: {sorted(heads)}"
            )
        approval = baseline.get("approval")
        approved_schema_revision = (
            approval.get("approved_control_plane_schema_revision")
            if isinstance(approval, dict)
            else None
        )
        if not _is_migration_ancestor(repo, approved_schema_revision, schema_revision):
            violations.append(
                "approved control-plane schema revision must be an ancestor of the current head"
            )
        if revision.get("deployment_scope") != "single-region-multi-az":
            violations.append("P0 deployment_scope must be single-region-multi-az")

    approval_report = validate_approval_contract(repo, baseline)
    violations.extend(
        f"ADR approval contract: {violation}" for violation in approval_report["violations"]
    )
    if approval_report["approval_readiness"] != "approved":
        blockers.append("production baseline approval is incomplete")

    adrs = baseline.get("adrs")
    if _ids(adrs) != _ADR_IDS:
        violations.append("ADR registry must contain ADR-001 through ADR-011 exactly once")
    if isinstance(adrs, list):
        for adr in adrs:
            if not isinstance(adr, dict):
                violations.append("ADR entries must be objects")
                continue
            adr_id = adr.get("id", "unknown")
            for field in ("title", "decision", "verification_gate"):
                if not _nonempty(adr.get(field)):
                    violations.append(f"{adr_id}.{field} must be non-empty")
            if not _owner(adr.get("owner")):
                violations.append(f"{adr_id}.owner must be a stable role identifier")
            if adr.get("status") not in {"proposed", "accepted", "superseded"}:
                violations.append(f"{adr_id}.status is invalid")
            if adr.get("status") != "accepted":
                blockers.append(f"{adr_id} is not accepted")

    services = baseline.get("service_catalog")
    service_ids = _ids(services)
    if service_ids != _SERVICE_IDS:
        violations.append("service_catalog does not contain the seven required services")

    slos = baseline.get("slos")
    slo_ids = _ids(slos)
    if slo_ids != _SLO_IDS:
        violations.append("SLO registry does not contain the required six objectives")
    if isinstance(slos, list):
        for slo in slos:
            if not isinstance(slo, dict):
                violations.append("SLO entries must be objects")
                continue
            slo_id = slo.get("id", "unknown")
            refs = (
                set(slo.get("service_ids", []))
                if isinstance(slo.get("service_ids"), list)
                else set()
            )
            if not refs or not refs <= service_ids:
                violations.append(f"{slo_id} references invalid services")
            for field in ("sli", "objective", "measurement", "error_budget_action"):
                if not _nonempty(slo.get(field)):
                    violations.append(f"{slo_id}.{field} must be non-empty")
            if not isinstance(slo.get("window_days"), int) or slo["window_days"] <= 0:
                violations.append(f"{slo_id}.window_days must be positive")
            if slo.get("dashboard_state") != "active":
                blockers.append(f"{slo_id} has no active measured dashboard")

    if isinstance(services, list):
        required = {
            "code_owner",
            "data_owner",
            "oncall",
            "capacity",
            "runbook",
            "schema_migration_owner",
            "secret_kms",
            "backup_data_class",
            "exit_plan",
        }
        for service in services:
            if not isinstance(service, dict):
                violations.append("service entries must be objects")
                continue
            service_id = service.get("id", "unknown")
            for field in required:
                if not _nonempty(service.get(field)):
                    violations.append(f"{service_id}.{field} must be non-empty")
            for field in ("code_owner", "data_owner", "oncall", "schema_migration_owner"):
                if not _owner(service.get(field)):
                    violations.append(f"{service_id}.{field} must be a stable role identifier")
            deps = service.get("dependencies")
            if not isinstance(deps, list) or not deps or any(not _nonempty(dep) for dep in deps):
                violations.append(f"{service_id}.dependencies must be a non-empty string list")
            refs = (
                set(service.get("slo_ids", []))
                if isinstance(service.get("slo_ids"), list)
                else set()
            )
            if not refs or not refs <= slo_ids:
                violations.append(f"{service_id} references invalid SLOs")
            if service.get("backup_data_class") not in _DATA_CLASSES:
                violations.append(f"{service_id} references an invalid backup data class")
            runbook = service.get("runbook")
            if isinstance(runbook, str) and not (repo / runbook).is_file():
                violations.append(f"{service_id} references missing runbook {runbook}")

    data_classes = baseline.get("data_classes")
    if _ids(data_classes) != _DATA_CLASSES:
        violations.append("data_classes must contain T0, T1, and T2")
    limits = {"T0": (5, 60), "T1": (15, 240), "T2": (None, 480)}
    if isinstance(data_classes, list):
        for item in data_classes:
            if not isinstance(item, dict):
                violations.append("data-class entries must be objects")
                continue
            class_id = item.get("id", "unknown")
            expected_rpo, max_rto = limits.get(str(class_id), (None, 0))
            rpo = item.get("rpo_minutes")
            if expected_rpo is not None and (not isinstance(rpo, int) or rpo > expected_rpo):
                violations.append(f"{class_id}.rpo_minutes exceeds the P0 proposal")
            if expected_rpo is None and (
                rpo is not None or not _nonempty(item.get("rpo_definition"))
            ):
                violations.append("T2 requires the latest durable recovery point definition")
            rto = item.get("rto_minutes")
            if not isinstance(rto, int) or rto > max_rto:
                violations.append(f"{class_id}.rto_minutes exceeds the P0 proposal")
            if item.get("drill_frequency_days") != 90:
                violations.append(f"{class_id} must require quarterly recovery drills")
            if item.get("approval_state") != "approved":
                blockers.append(f"{class_id} RPO/RTO is not business-approved")

    recovery_evidence = baseline.get("recovery_evidence")
    if not isinstance(recovery_evidence, list):
        violations.append("recovery_evidence must be a list")
    elif not recovery_evidence:
        blockers.append("no immutable tenant or regional recovery drill evidence is recorded")

    model = baseline.get("threat_model")
    if not isinstance(model, dict):
        violations.append("threat_model must be an object")
    else:
        assets = set(model.get("assets", [])) if isinstance(model.get("assets"), list) else set()
        boundaries = (
            set(model.get("trust_boundaries", []))
            if isinstance(model.get("trust_boundaries"), list)
            else set()
        )
        threats = model.get("threats")
        if len(assets) < 8 or len(boundaries) < 8:
            violations.append("threat model must enumerate at least eight assets and boundaries")
        if not isinstance(threats, list) or len(threats) < 12:
            violations.append("threat model must contain at least twelve concrete threats")
        else:
            if _ids(threats) != {f"TM-{index:03d}" for index in range(1, 13)}:
                violations.append("threat IDs must contain TM-001 through TM-012 exactly once")
            if {item.get("stride") for item in threats if isinstance(item, dict)} != _STRIDE:
                violations.append("threat model must cover every STRIDE category")
            for threat in threats:
                if not isinstance(threat, dict):
                    violations.append("threat entries must be objects")
                    continue
                threat_id = threat.get("id", "unknown")
                if threat.get("asset") not in assets or threat.get("boundary") not in boundaries:
                    violations.append(f"{threat_id} references an unknown asset or boundary")
                if not _owner(threat.get("owner")):
                    violations.append(f"{threat_id}.owner must be a stable role identifier")
                if threat.get("residual_risk") not in {"low", "medium", "high", "critical"}:
                    violations.append(f"{threat_id}.residual_risk is invalid")
                if not isinstance(threat.get("controls"), list) or len(threat["controls"]) < 3:
                    violations.append(f"{threat_id} requires at least three controls")
                for field in ("scenario", "verification"):
                    if not _nonempty(threat.get(field)):
                        violations.append(f"{threat_id}.{field} must be non-empty")

    register = baseline.get("risk_register")
    if not isinstance(register, dict):
        violations.append("risk_register must be an object")
    else:
        if not _nonempty(register.get("last_reviewed_at")):
            violations.append("risk_register.last_reviewed_at is required")
        interval = register.get("review_interval_days")
        if not isinstance(interval, int) or interval > 14:
            violations.append("risk register review interval cannot exceed 14 days")
        risks = register.get("risks")
        if not isinstance(risks, list) or len(risks) < 6:
            violations.append("risk register must contain at least six concrete risks")
        else:
            for risk in risks:
                if not isinstance(risk, dict):
                    violations.append("risk entries must be objects")
                    continue
                risk_id = risk.get("id", "unknown")
                if not _owner(risk.get("owner")):
                    violations.append(f"{risk_id}.owner must be a stable role identifier")
                for field in ("trigger", "mitigation", "due"):
                    if not _nonempty(risk.get(field)):
                        violations.append(f"{risk_id}.{field} must be non-empty")
                if risk.get("probability") not in {"low", "medium", "high"}:
                    violations.append(f"{risk_id}.probability is invalid")
                if risk.get("impact") not in {"low", "medium", "high", "critical"}:
                    violations.append(f"{risk_id}.impact is invalid")

    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": "ready" if not violations and not blockers else "blocked",
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "adr_count": len(_ids(adrs)),
            "service_count": len(service_ids),
            "slo_count": len(slo_ids),
            "data_class_count": len(_ids(data_classes)),
            "threat_count": len(_ids(model.get("threats") if isinstance(model, dict) else [])),
            "readiness_blocker_count": len(set(blockers)),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="saas/production/baseline.json")
    parser.add_argument("--output")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="fail when human approval or live operational evidence is incomplete",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    baseline = json.loads((repo / args.baseline).read_text(encoding="utf-8"))
    report = validate_baseline(repo, baseline)
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
