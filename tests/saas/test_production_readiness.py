from __future__ import annotations

import copy
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saas.production import legacy_stack
from saas.production.admission import validate_evidence_admission
from saas.production.readiness import (
    derive_gate_results,
    validate_candidate_revision,
    validate_consecutive_upstream_syncs,
    validate_gate_ledger,
    validate_production_readiness,
)
from tests.saas._approval_history import require_current_approval_history
from tests.saas.test_legacy_stack import complete_stack as complete_stack


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _manifest() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/acceptance/p0-p6-evidence.json").read_text(encoding="utf-8")
    )


def _report(ready: bool, blocker: str = "missing evidence") -> dict[str, object]:
    return {
        "status": "pass",
        "production_readiness": "ready" if ready else "blocked",
        "violations": [],
        "blockers": [] if ready else [blocker],
    }


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _admission_reports(ready: bool = True) -> dict[str, dict[str, object]]:
    return {
        f"{kind}_admission": _report(ready, f"{kind} admission missing")
        for kind in (
            "baseline",
            "image",
            "deployment",
            "recovery",
            "slo_capacity",
            "deletion",
            "commercial",
            "enterprise",
        )
    }


def test_current_consecutive_upstream_sync_contract_is_ready() -> None:
    report = validate_consecutive_upstream_syncs(_repo())

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["violations"] == []


def test_consecutive_upstream_sync_digest_drift_fails_closed(tmp_path: Path) -> None:
    for relative in (
        "saas/production/upstream-sync-policy.json",
        "saas/acceptance/p6-upstream-sync-ci-31011047850.json",
        "saas/acceptance/p6-upstream-sync-ci-31019511803.json",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_repo() / relative, destination)
    first = tmp_path / "saas/acceptance/p6-upstream-sync-ci-31011047850.json"
    first.write_text(first.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = validate_consecutive_upstream_syncs(tmp_path)

    assert report["status"] == "fail"
    assert any("digest drifted" in item for item in report["violations"])


def test_gate_derivation_requires_every_named_verifier() -> None:
    reports = {
        "candidate_revision": _report(True),
        "baseline": _report(True),
        "image": _report(True),
        "deployment": _report(True),
        "recovery": _report(True),
        "slo_capacity": _report(True),
        "deletion": _report(True),
        "commercial": _report(False, "real provider invoice missing"),
        "enterprise": _report(True),
        "upstream_sync": _report(True),
        **_admission_reports(),
    }

    gates = derive_gate_results(reports)

    assert len(gates) == 10
    assert gates["p5-production-foundation-gate"]["ready"] is True
    assert gates["p6-billing-ledger-entitlement-quota-subscription"]["ready"] is False
    assert gates["p6-two-consecutive-upstream-syncs-and-commercial-gate"]["ready"] is False
    assert any(
        "real provider invoice missing" in item
        for item in gates["p6-two-consecutive-upstream-syncs-and-commercial-gate"]["blockers"]
    )


def test_manual_pass_cannot_override_a_blocked_derived_gate() -> None:
    manifest = copy.deepcopy(_manifest())
    reports = {
        "candidate_revision": _report(True),
        "baseline": _report(False),
        "image": _report(False),
        "deployment": _report(False),
        "recovery": _report(False),
        "slo_capacity": _report(False),
        "deletion": _report(False),
        "commercial": _report(False),
        "enterprise": _report(False),
        "upstream_sync": _report(True),
        **_admission_reports(False),
    }
    phases = manifest["phases"]
    assert isinstance(phases, list)
    p0 = phases[0]
    assert isinstance(p0, dict)
    gates = p0["gates"]
    assert isinstance(gates, list)
    image_gate = next(
        gate
        for gate in gates
        if isinstance(gate, dict)
        and gate.get("id") == "p0-reproducible-official-image-and-oss-regression"
    )
    image_gate["status"] = "passed"

    violations = validate_gate_ledger(manifest, derive_gate_results(reports))

    assert (
        "aggregate gate p0-reproducible-official-image-and-oss-regression is passed "
        "without qualifying evidence"
    ) in violations


def test_current_overall_readiness_is_structurally_valid_and_no_go() -> None:
    require_current_approval_history(_repo())
    now = datetime(2026, 10, 21, 13, tzinfo=UTC)
    report = validate_production_readiness(_repo(), now=now)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert report["release_decision"] == "NO-GO"
    assert report["violations"] == []
    assert report["metrics"] == {
        "aggregate_gate_count": 10,
        "derived_ready_gate_count": 0,
        "ledger_passed_gate_count": 0,
        "structural_violation_count": 0,
    }
    assert report["verifiers"]["upstream_sync"]["production_readiness"] == "ready"
    assert report["verifiers"]["candidate_revision"]["production_readiness"] == "blocked"
    assert report["verifiers"]["deployment"]["production_readiness"] == "blocked"
    assert report["verifiers"]["baseline_admission"]["production_readiness"] == "blocked"
    assert report["verifiers"]["baseline_admission"]["blockers"] == [
        "no valid signed admission receipt for saas/production/baseline.json"
    ]
    policy = json.loads(
        (_repo() / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
    )
    admission = validate_evidence_admission(_repo(), policy, now=now)
    assert admission["metrics"]["active_trusted_key_count"] == 1
    assert admission["metrics"]["admitted_document_count"] == 0
    assert admission["metrics"]["receipt_count"] == 0


def test_release_candidate_revision_is_an_explicit_common_gate() -> None:
    assert validate_candidate_revision(None)["production_readiness"] == "blocked"
    assert validate_candidate_revision("short")["status"] == "fail"
    assert validate_candidate_revision("a" * 40)["production_readiness"] == "ready"


def test_candidate_lineage_allows_only_committed_evidence_after_candidate(
    tmp_path: Path,
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    source = tmp_path / "saas/runtime.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")

    evidence = tmp_path / "saas/production/deployment-evidence/drill.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "add evidence")

    assert validate_candidate_revision(candidate, tmp_path)["production_readiness"] == "ready"

    source.write_text("value = 2\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "code drift")

    report = validate_candidate_revision(candidate, tmp_path)
    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])


def test_candidate_lineage_rejects_uncommitted_evidence(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    tracked = tmp_path / "README.md"
    tracked.write_text("candidate\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")
    evidence = tmp_path / "saas/production/recovery-evidence/drill.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")

    report = validate_candidate_revision(candidate, tmp_path)

    assert report["production_readiness"] == "blocked"
    assert any("clean repository" in item for item in report["blockers"])


def test_candidate_lineage_rejects_trust_registry_changes(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    registry = tmp_path / "saas/production/evidence-admission-keys.json"
    registry.parent.mkdir(parents=True)
    registry.write_text('{"keys": []}\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "candidate")
    candidate = _git(tmp_path, "rev-parse", "HEAD")
    registry.write_text('{"keys": [{"key_id": "unreviewed"}]}\n', encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "replace trust root")

    report = validate_candidate_revision(candidate, tmp_path)

    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])


@pytest.fixture
def legacy_stack_lineage(complete_stack):
    data = complete_stack
    repo = data["repo"]
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    source = repo / "saas/runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    store = {"schema_version": 1, "stacks": {"historical-stack": copy.deepcopy(data["stack"])}}
    registry = repo / legacy_stack.STACK_REGISTRY
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps(store), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "candidate")
    candidate = _git(repo, "rev-parse", "HEAD")
    body = copy.deepcopy(data["body"])
    body["product_revision"] = candidate
    row = copy.deepcopy(data["stack"])
    row["rollback_sha256"] = legacy_stack.publisher.digest(body)
    store["stacks"]["fixture-stack"] = row
    evidence = copy.deepcopy(data["evidence"])
    evidence["product_revision"] = candidate
    envelope = {
        "kind": legacy_stack.VARIANT,
        "product_revision": candidate,
        "release_evidence": evidence,
        "legacy_fallback": {
            "stack_id": "fixture-stack",
            "publication_ids": row["publication_ids"],
            "original_publication_ids": row["original_publication_ids"],
            "full_stack_rollback": body,
        },
    }
    return repo, candidate, store, envelope


@pytest.mark.parametrize("replace_existing", [False, True])
def test_candidate_lineage_accepts_only_current_typed_stack_evidence(
    legacy_stack_lineage, replace_existing
):
    repo, candidate, store, envelope = legacy_stack_lineage
    if replace_existing:
        envelope["legacy_fallback"]["stack_id"] = "historical-stack"
        store["stacks"]["historical-stack"] = store["stacks"].pop("fixture-stack")
    (repo / legacy_stack.STACK_REGISTRY).write_text(json.dumps(store), encoding="utf-8")
    path = repo / "saas/acceptance/p0-production-image-evidence.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(envelope), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "record current physical rollback")

    report = validate_candidate_revision(candidate, repo)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["blockers"] == []


@pytest.mark.parametrize(
    "fault",
    [
        "envelope_revision",
        "image_revision",
        "rollback_revision",
        "rollback_digest",
        "envelope_kind",
        "fallback_fields",
        "publication_ids",
        "registry_json",
        "registry_object",
        "registry_fields",
        "registry_symlink",
        "stack_kind",
        "missing_physical_role",
        "changed_history",
        "deleted_history",
        "additional_stack",
        "unknown_registry",
        "additional_trust_path",
        "non_json_path",
        "runtime_source",
    ],
)
def test_candidate_lineage_rejects_unbound_or_unrelated_stack_changes(legacy_stack_lineage, fault):
    repo, candidate, store, envelope = legacy_stack_lineage
    fallback = envelope["legacy_fallback"]
    registry = repo / legacy_stack.STACK_REGISTRY
    if fault == "envelope_revision":
        envelope["product_revision"] = "b" * 40
    elif fault == "image_revision":
        envelope["release_evidence"]["product_revision"] = "b" * 40
    elif fault == "rollback_revision":
        fallback["full_stack_rollback"]["product_revision"] = "b" * 40
        store["stacks"]["fixture-stack"]["rollback_sha256"] = legacy_stack.publisher.digest(
            fallback["full_stack_rollback"]
        )
    elif fault == "rollback_digest":
        store["stacks"]["fixture-stack"]["rollback_sha256"] = "b" * 64
    elif fault == "envelope_kind":
        envelope["kind"] = "unreviewed/v1"
    elif fault == "fallback_fields":
        fallback["extra"] = True
    elif fault == "publication_ids":
        fallback["publication_ids"] = {}
    elif fault == "registry_object":
        store = []
    elif fault == "registry_fields":
        store["extra"] = True
    elif fault == "stack_kind":
        store["stacks"]["fixture-stack"]["kind"] = "unreviewed/v1"
    elif fault == "missing_physical_role":
        store["stacks"]["fixture-stack"]["physical_inventory"]["workloads"].pop("fixture-host")
    elif fault == "changed_history":
        store["stacks"]["historical-stack"]["rollback_sha256"] = "b" * 64
    elif fault == "deleted_history":
        store["stacks"].pop("historical-stack")
    elif fault == "additional_stack":
        store["stacks"]["unrelated-stack"] = copy.deepcopy(store["stacks"]["fixture-stack"])
    elif fault in {"unknown_registry", "additional_trust_path", "non_json_path"}:
        relative = {
            "unknown_registry": "saas/supply_chain/unreviewed-stacks.json",
            "additional_trust_path": "saas/supply_chain/legacy-production-publications.json",
            "non_json_path": "saas/supply_chain/legacy-production-stacks.txt",
        }[fault]
        (repo / relative).write_text("{}\n", encoding="utf-8")
    elif fault == "runtime_source":
        (repo / "saas/runtime.py").write_text("value = 2\n", encoding="utf-8")
    registry.write_text(
        "not JSON" if fault == "registry_json" else json.dumps(store), encoding="utf-8"
    )
    path = repo / "saas/acceptance/p0-production-image-evidence.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(envelope), encoding="utf-8")
    if fault == "registry_symlink":
        registry.unlink()
        registry.symlink_to(path)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "attempt unbound stack evidence")

    report = validate_candidate_revision(candidate, repo)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])


@pytest.mark.parametrize(
    "fault",
    [
        "current_target_duplicate",
        "current_history_duplicate",
        "nested_envelope_duplicate",
        "policy_duplicate",
        "previous_duplicate",
        "previous_selected_nan",
        "envelope_nan",
        "envelope_overflow",
        "history_boolean_alias",
    ],
)
def test_candidate_lineage_rejects_ambiguous_or_nonfinite_stack_json(legacy_stack_lineage, fault):
    repo, candidate, store, envelope = legacy_stack_lineage
    registry = repo / legacy_stack.STACK_REGISTRY
    policy_path = repo / "saas/production/deployment-policy.json"
    if fault == "previous_duplicate":
        original = registry.read_text(encoding="utf-8")
        registry.write_text('{"schema_version": 0, ' + original[1:], encoding="utf-8")
    elif fault == "previous_selected_nan":
        previous = json.loads(registry.read_text(encoding="utf-8"))
        previous["stacks"]["historical-stack"]["source_contracts"]["Core"]["fixture"] = float(
            "nan"
        )
        registry.write_text(json.dumps(previous), encoding="utf-8")
        envelope["legacy_fallback"]["stack_id"] = "historical-stack"
        store["stacks"]["historical-stack"] = store["stacks"].pop("fixture-stack")
    elif fault == "history_boolean_alias":
        previous = json.loads(registry.read_text(encoding="utf-8"))
        previous["stacks"]["historical-stack"]["source_contracts"]["Core"]["fixture_scalar"] = 1
        registry.write_text(json.dumps(previous), encoding="utf-8")
        store["stacks"]["historical-stack"] = copy.deepcopy(previous["stacks"]["historical-stack"])
        store["stacks"]["historical-stack"]["source_contracts"]["Core"]["fixture_scalar"] = True
    elif fault == "policy_duplicate":
        original = policy_path.read_text(encoding="utf-8")
        policy = json.loads(original)
        key = '"required_components": ' + json.dumps(policy["required_components"])
        policy_path.write_text("{" + key + ", " + original[1:], encoding="utf-8")
    if fault in {
        "previous_duplicate",
        "previous_selected_nan",
        "policy_duplicate",
        "history_boolean_alias",
    }:
        _git(repo, "add", ".")
        _git(repo, "commit", "--amend", "--no-edit")
        candidate = _git(repo, "rev-parse", "HEAD")
        envelope["product_revision"] = candidate
        envelope["release_evidence"]["product_revision"] = candidate
        envelope["legacy_fallback"]["full_stack_rollback"]["product_revision"] = candidate
    body = envelope["legacy_fallback"]["full_stack_rollback"]
    if fault == "envelope_nan":
        envelope["release_evidence"]["fixture_number"] = float("nan")
    elif fault == "envelope_overflow":
        envelope["release_evidence"]["fixture_number"] = float("inf")
    identifier = envelope["legacy_fallback"]["stack_id"]
    store["stacks"][identifier]["rollback_sha256"] = legacy_stack.publisher.digest(body)
    registry_json = json.dumps(store)
    envelope_json = json.dumps(envelope)
    if fault in {"current_target_duplicate", "current_history_duplicate"}:
        selected = "fixture-stack" if fault == "current_target_duplicate" else "historical-stack"
        key = json.dumps(selected) + ": " + json.dumps(store["stacks"][selected])
        registry_json = registry_json.replace(key, key + ", " + key, 1)
    elif fault == "nested_envelope_duplicate":
        image = json.dumps(envelope["release_evidence"])
        duplicate = '{"product_revision": "' + "b" * 40 + '", ' + image[1:]
        envelope_json = envelope_json.replace(image, duplicate, 1)
    elif fault == "envelope_overflow":
        envelope_json = envelope_json.replace(
            '"fixture_number": Infinity', '"fixture_number": 1e999'
        )
    registry.write_text(registry_json, encoding="utf-8")
    path = repo / "saas/acceptance/p0-production-image-evidence.json"
    path.parent.mkdir(parents=True)
    path.write_text(envelope_json, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "attempt ambiguous stack JSON")

    report = validate_candidate_revision(candidate, repo)

    assert report["status"] == "pass"
    assert report["production_readiness"] == "blocked"
    assert any("non-evidence paths" in item for item in report["blockers"])
