"""Portable unit fixtures for native absence audits; no source or CI evidence."""

from __future__ import annotations

import copy
import json

import pytest

from saas.scripts import legacy_domain_non_execution as audit
from tests.saas.test_legacy_domain_discovery import discovery
from tests.saas.test_legacy_domain_discovery import discovery_case as discovery_case
from tests.saas.test_legacy_domain_eligibility import domain
from tests.saas.test_legacy_domain_eligibility import native_domain as native_domain
from tests.saas.test_legacy_domain_non_execution import audit_case as audit_case
from tests.saas.test_legacy_source_qualification import invoke, qualifier
from tests.saas.test_legacy_source_qualification import scenario as scenario


@pytest.fixture
def unattributed_case(scenario, audit_case):
    zero = audit_case
    scenario["policy"].pop("domain_non_execution")
    policy = {
        "kind": audit.UNATTRIBUTED_POLICY_KIND,
        "workflow_sha256": domain.MAIN_WORKFLOW_SHA256,
        **{
            key: scenario["identity"][key]
            for key in ("validation_pr", "validation_base_ref", "product_revision", "product_tree")
        },
    }
    scenario["policy"]["domain_unattributed_zero_execution"] = {domain.MAIN_WORKFLOW: policy}
    zero["unattributed_policy"] = policy
    return zero


def verify(scenario, zero):
    return audit.verify_unattributed_zero_execution(
        scenario["profile"],
        scenario["identity"],
        zero["unattributed_policy"],
        zero["run"],
        zero["job"],
        zero["check"],
        zero["annotations"],
        zero["logs"],
    )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("conclusion", ["cancelled", "skipped"])
def test_new_unknown_native_coordinates_do_not_require_future_registration(
    scenario, discovery_case, unattributed_case, tmp_path, conclusion
):
    zero = unattributed_case
    if conclusion == "skipped":
        for key in ("run", "job", "check"):
            zero[key]["conclusion"] = conclusion
        zero["annotations"] = []
        zero["check"]["output"]["annotations_count"] = 0
    initial = copy.deepcopy(scenario["policy"]["domain_unattributed_zero_execution"])
    result = invoke(scenario, tmp_path)
    assert result["source_ci_pass"] is True and result["complete_domain_discovery"] is True
    assert result["all_apps"]["verified_main_domain_zero_execution"] == []
    assert result["domain_zero_execution_observations"] == []
    raw = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    row = raw["unattributed_zero_execution_observations"][0]
    assert row["kind"] == audit.UNATTRIBUTED_KIND and row["original_conclusion"] == conclusion
    assert row["source_classification"] == "UNKNOWN"
    assert row["original_event_source_revision"] is row["trusted_checkout_revision"] is None
    assert "registration_sha256" not in row
    assert (
        row["source_proof"]
        is row["guard_refusal"]
        is row["technical_gate_waiver"]
        is row["production_admission"]
        is False
    )
    assert (
        raw["unattributed_expected_attempts"]
        == raw["unattributed_verified_attempts"]
        == [[8002, 1]]
    )
    assert scenario["policy"]["domain_unattributed_zero_execution"] == initial
    # Another actual coordinate is audited under the same static context, not a new policy row.
    old = zero["run"]["id"]
    zero["run"]["id"] = new = 8123
    prefix = f"{discovery._REPO_URL}/actions/runs/{new}/attempts/1"
    zero["run"].update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
    zero["job"]["run_id"] = new
    zero["check"]["details_url"] = (
        f"https://github.com/Dream1216/omnigent/actions/runs/{new}/job/{zero['job']['id']}"
    )
    discovery_case["jobs"][new] = discovery_case["jobs"].pop(old)
    later = tmp_path / "later"
    later.mkdir()
    again = invoke(scenario, later)
    assert again["complete_domain_discovery"] is True
    assert scenario["policy"]["domain_unattributed_zero_execution"] == initial


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "no-policy",
        "wrong-policy-kind",
        "wrong-workflow",
        "wrong-product",
        "wrong-tree",
        "wrong-PR",
        "main",
        "unknown-component",
        "extra-policy",
        "associated-PR",
        "executed-step",
        "assigned-runner",
        "missing-steps",
        "missing-runner",
        "nonempty-ZIP",
        "unknown-annotation",
        "annotation-count",
        "wrong-App",
        "wrong-suite",
        "success",
        "failure",
        "zero-jobs",
        "no-refusal",
        "forged-json",
        "changed-native-proof",
        "new-missing-native-run",
    ],
)
def test_unknown_audit_rejects_unproved_absence_and_never_replaces_current_refusal(
    scenario, discovery_case, unattributed_case, tmp_path, monkeypatch, fault
):
    zero = unattributed_case
    policy = zero["unattributed_policy"]
    if fault == "no-policy":
        scenario["policy"].pop("domain_unattributed_zero_execution")
    elif fault == "wrong-policy-kind":
        policy["kind"] = audit.KIND
    elif fault == "wrong-workflow":
        policy["workflow_sha256"] = "f" * 64
    elif fault == "wrong-product":
        policy["product_revision"] = "f" * 40
    elif fault == "wrong-tree":
        policy["product_tree"] = "f" * 40
    elif fault == "wrong-PR":
        policy["validation_pr"] += 1
    elif fault == "main":
        policy["validation_base_ref"] = "main"
    elif fault == "unknown-component":
        scenario["profile"]["component"] = "unknown"
        # The full reader loads its profile from disk; exercise this in-memory scope directly.
        with pytest.raises(ValueError, match="exact frozen legacy domain"):
            verify(scenario, zero)
        assert not (tmp_path / "qualified/source-qualification.json").exists()
        return
    elif fault == "extra-policy":
        policy["allow_failure"] = True
    elif fault == "associated-PR":
        zero["run"]["pull_requests"] = [
            {
                "number": scenario["identity"]["validation_pr"],
                "url": discovery._REPO_URL + f"/pulls/{scenario['identity']['validation_pr']}",
            }
        ]
    elif fault == "executed-step":
        zero["job"]["steps"] = [{"name": "Set up job", "conclusion": "success"}]
    elif fault == "assigned-runner":
        zero["job"]["runner_id"] = 1000081442
    elif fault == "missing-steps":
        zero["job"].pop("steps")
    elif fault == "missing-runner":
        zero["job"].pop("runner_id")
    elif fault == "nonempty-ZIP":
        zero["logs"] += b"x"
    elif fault == "unknown-annotation":
        zero["annotations"][0]["message"] = "The operation was canceled."
    elif fault == "annotation-count":
        zero["check"]["output"]["annotations_count"] += 1
    elif fault == "wrong-App":
        zero["check"]["app"]["id"] = 123
    elif fault == "wrong-suite":
        zero["check"]["check_suite"]["id"] += 1
    elif fault in {"success", "failure"}:
        zero["run"]["conclusion"] = fault
    elif fault == "zero-jobs":
        discovery_case["jobs"][8002] = []
        # Empty jobs alone are not the new complete no-job attestation. Supply
        # its bounded endpoints with a deliberately missing suite identity.
        original = audit.api

        def missing_suite(endpoint):
            if endpoint.endswith("/attempts/1/jobs?per_page=100&page=1"):
                return {"total_count": 0, "jobs": []}
            if endpoint.endswith("/check-suites/9902"):
                return {}
            if endpoint.endswith("/check-suites/9902/check-runs?filter=all&per_page=100&page=1"):
                return {"total_count": 0, "check_runs": []}
            return original(endpoint)

        monkeypatch.setattr(audit, "api", missing_suite)
    elif fault == "no-refusal":
        scenario["policy"]["domain_not_applicable"] = {}
    elif fault == "forged-json":
        original = domain.discover_main_domain
        monkeypatch.setattr(domain, "discover_main_domain", lambda *a: dict(original(*a)))
    elif fault == "changed-native-proof":
        original = audit.collect_unattributed_zero_execution
        count = 0

        def changed(*args):
            nonlocal count
            proof = original(*args)
            count += 1
            if count > 1:
                proof.receipt["job_sha256"] = "f" * 64
            return proof

        monkeypatch.setattr(audit, "collect_unattributed_zero_execution", changed)
    elif fault == "new-missing-native-run":
        run = copy.deepcopy(zero["run"])
        run["id"] += 1
        discovery_case["runs"].append(run)
    with pytest.raises((ValueError, KeyError)):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_unattributed_typed_proof_cannot_be_used_as_registered_all_app_audit(
    scenario, discovery_case, unattributed_case, tmp_path
):
    proof = verify(scenario, unattributed_case)
    assert audit.typed_observation(proof) is False
    assert not isinstance(
        proof, (audit.ZeroExecutionObservation, audit.InfrastructureCancellationObservation)
    )
    assert qualifier.nonexecution.typed_observation(proof) is False
    scenario["policy"]["domain_not_applicable"] = {}
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault", ["hidden-memory-proof", "missing-verified-coordinate", "dict-in-memory"]
)
def test_complete_bidirectional_unknown_set_requires_the_exact_native_typed_proofs(
    scenario, discovery_case, unattributed_case, tmp_path, fault
):
    target = tmp_path / "direct-discovery"
    target.mkdir()
    result = discovery.discover_main_domain(
        scenario["profile"],
        scenario["identity"],
        scenario["policy"]["domain_not_applicable"][domain.MAIN_WORKFLOW],
        target,
        unattributed_policy=unattributed_case["unattributed_policy"],
    )
    assert result["complete_discovery"] is True
    assert (
        result["unattributed_expected_attempts"]
        == result["unattributed_verified_attempts"]
        == [(8002, 1)]
    )
    if fault == "hidden-memory-proof":
        result["unattributed_zero_execution_observations"] = []
        for record in result["records"]:
            record.pop("unattributed_zero_execution_observations", None)
    elif fault == "missing-verified-coordinate":
        result["unattributed_verified_attempts"] = []
    else:
        result.unattributed_observations = tuple(
            row.receipt for row in result.unattributed_observations
        )
    with pytest.raises(ValueError, match="exact complete typed unattributed"):
        domain._discovery_binding(result)
