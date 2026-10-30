"""Verify the original main-only guard's refusal on a frozen legacy PR."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from saas.scripts import legacy_domain_native as native
from saas.scripts import legacy_domain_non_execution as nonexecution
from saas.scripts.legacy_domain_discovery import discover_main_domain
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pr_candidate import VALIDATION_REFS
from saas.scripts.legacy_source_ci import (
    _job_pages,
    checkout_commit,
    completed_step_lines,
    download_job_log,
)
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

MAIN_WORKFLOW = native.MAIN_WORKFLOW
MAIN_WORKFLOW_SHA256 = native.MAIN_WORKFLOW_SHA256
_GATE = native._GATE
_ERROR = native._ERROR
native_digest = native.native_digest


def validate_domain_rules(policy: dict[str, Any], identity: dict[str, Any]) -> None:
    unattributed = policy.get("domain_unattributed_zero_execution", {})
    require(
        isinstance(unattributed, dict) and set(unattributed) <= {MAIN_WORKFLOW},
        "only the reviewed main-domain workflow has an unattributed zero-execution policy",
    )
    if unattributed:
        nonexecution.validate_unattributed_policy(unattributed[MAIN_WORKFLOW], policy, identity)
        require(
            bool(policy["domain_not_applicable"]),
            "unattributed audits cannot create domain eligibility",
        )
    bootstrap = policy.get("domain_unattributed_bootstrap_cancellation", {})
    require(
        isinstance(bootstrap, dict) and set(bootstrap) <= {MAIN_WORKFLOW},
        "only the reviewed main-domain workflow has an unattributed bootstrap policy",
    )
    if bootstrap:
        nonexecution.validate_bootstrap_policy(bootstrap[MAIN_WORKFLOW], policy, identity)
        require(
            bool(policy["domain_not_applicable"]),
            "bootstrap audits cannot create domain eligibility",
        )
    audits = policy.get("domain_non_execution", {})
    require(
        isinstance(audits, dict) and set(audits) <= {MAIN_WORKFLOW},
        "only the reviewed main-domain workflow has a zero-execution audit rule",
    )
    infrastructure = policy.get("domain_infrastructure_cancellation", {})
    require(
        isinstance(infrastructure, dict) and set(infrastructure) <= {MAIN_WORKFLOW},
        "only the reviewed main-domain workflow has an infrastructure cancellation audit",
    )
    refusal_cancellations = policy.get("domain_refusal_cancellation", {})
    require(
        isinstance(refusal_cancellations, dict) and set(refusal_cancellations) <= {MAIN_WORKFLOW},
        "refusal cancellation policy has an unknown workflow",
    )
    nonexecution.validate_refusal_cancellation_rules(
        refusal_cancellations.get(MAIN_WORKFLOW, []), policy, identity
    )
    rules = policy["domain_not_applicable"]
    require(
        not refusal_cancellations or bool(rules),
        "refusal cancellation cannot create domain eligibility",
    )
    require(
        not infrastructure or bool(rules),
        "infrastructure cancellation alone cannot create domain eligibility",
    )
    require(
        not audits or bool(rules), "zero-execution audit alone cannot create domain eligibility"
    )
    require(
        isinstance(rules, dict) and set(rules) <= {MAIN_WORKFLOW},
        "only the reviewed main-domain workflow has an eligibility rule",
    )
    declared = policy["workflow_catalog"].get(MAIN_WORKFLOW)
    require(
        not isinstance(declared, dict) or declared["disposition"] != "original-informational",
        "the main-domain guard cannot become generic informational evidence",
    )
    enabled = (
        isinstance(declared, dict) and declared["disposition"] == "original-domain-not-applicable"
    )
    if (
        isinstance(declared, dict)
        and declared["sha256"] == MAIN_WORKFLOW_SHA256
        and identity["validation_base_ref"] == VALIDATION_REFS.get(identity["component"])
    ):
        require(enabled, "frozen legacy route requires explicit native main-domain eligibility")
    require(
        enabled == bool(rules)
        and (
            not enabled
            or (
                declared["sha256"] == MAIN_WORKFLOW_SHA256
                and identity["validation_base_ref"] == VALIDATION_REFS.get(identity["component"])
                and identity["validation_base_ref"] != "main"
            )
        ),
        "main-domain eligibility is not bound to the original frozen validation route",
    )
    if not enabled:
        return
    rows = rules[MAIN_WORKFLOW]
    require(isinstance(rows, list) and 0 < len(rows) <= 64, "native domain runs are missing")
    seen = set()
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row)
            == {
                "kind",
                "workflow_sha256",
                "validation_pr",
                "validation_base_ref",
                "product_revision",
                "product_tree",
                "attachment_revision",
                "run_id",
                "attempt",
                "job_id",
                "check_id",
                "run_sha256",
                "job_sha256",
                "check_sha256",
                "job_log_sha256",
                "trusted_checkout_revision",
                "trusted_gate_sha256",
            }
            and all(
                type(row[key]) is int and row[key] > 0
                for key in ("run_id", "attempt", "job_id", "check_id")
            )
            and all(
                isinstance(row[key], str) and re.fullmatch(r"[0-9a-f]{64}", row[key]) is not None
                for key in (
                    "run_sha256",
                    "job_sha256",
                    "check_sha256",
                    "job_log_sha256",
                    "trusted_gate_sha256",
                )
            )
            and isinstance(row["trusted_checkout_revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", row["trusted_checkout_revision"]) is not None,
            "reviewed native domain identity is malformed",
        )
        require(
            row["kind"] == "legacy_original_main_domain_refusal/v2"
            and row["workflow_sha256"] == MAIN_WORKFLOW_SHA256
            and all(
                row[key] == identity[key]
                for key in (
                    "validation_pr",
                    "validation_base_ref",
                    "product_revision",
                    "product_tree",
                )
            )
            and isinstance(row["attachment_revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", row["attachment_revision"]) is not None,
            "typed native domain registration does not bind this exact product and PR",
        )
        key = row["run_id"], row["attempt"], row["job_id"], row["check_id"]
        require(key not in seen, "native domain identity is duplicated")
        seen.add(key)


def _environment(lines: list[str], name: str) -> str:
    matches = [
        match.group(1) for line in lines if (match := re.fullmatch(r"  " + name + r": (.*)", line))
    ]
    require(len(matches) == 1, "native domain trigger environment is missing or ambiguous")
    return matches[0]


def verify_main_domain_refusal(
    profile: dict[str, Any],
    identity: dict[str, Any],
    rule: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    check: dict[str, Any],
    log: str,
) -> dict[str, Any]:
    """Keep an exact failed native check as an inapplicable main-merge guard."""
    require(
        identity["validation_base_ref"] == VALIDATION_REFS.get(profile["component"])
        and identity["validation_base_ref"] != "main",
        "main-targeting or unknown validation PR cannot use the domain rule",
    )
    require(
        rule.get("kind") == "legacy_original_main_domain_refusal/v2"
        and rule.get("workflow_sha256") == MAIN_WORKFLOW_SHA256
        and all(
            rule.get(key) == identity[key]
            for key in ("validation_pr", "validation_base_ref", "product_revision", "product_tree")
        )
        and rule.get("product_revision") == profile["product_revision"]
        and rule.get("product_tree") == profile["product_tree"]
        and rule.get("attachment_revision") == run.get("head_sha"),
        "domain refusal requires exact typed legacy product/PR/attachment registration",
    )
    require(
        native_digest(run) == rule["run_sha256"]
        and native_digest(job) == rule["job_sha256"]
        and native_digest(check) == rule["check_sha256"]
        and hashlib.sha256(log.encode()).hexdigest() == rule["job_log_sha256"],
        "original native domain evidence differs from its exact reviewed bytes",
    )
    require(
        run.get("id") == rule["run_id"]
        and run.get("run_attempt") == rule["attempt"]
        and run.get("path") == MAIN_WORKFLOW
        and run.get("name") == "SaaS N-1 merge gate"
        and run.get("event") in {"pull_request_target", "workflow_run"}
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")) is not None
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and job.get("id") == rule["job_id"]
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == rule["attempt"]
        and job.get("head_sha") == run["head_sha"]
        and job.get("name") == "evaluate"
        and job.get("status") == "completed"
        and job.get("conclusion") == "failure"
        and job.get("runner_group_name") == "GitHub Actions"
        and job.get("labels") == ["ubuntu-latest"]
        and job.get("check_run_url")
        == f"https://api.github.com/repos/{REPOSITORY}/check-runs/{rule['check_id']}"
        and check.get("id") == rule["check_id"]
        and check.get("name") == "evaluate"
        and check.get("head_sha") == run["head_sha"]
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == run.get("check_suite_id")
        and check.get("status") == "completed"
        and check.get("conclusion") == "failure",
        "domain refusal has another provider, workflow, source, attempt or outcome",
    )
    steps = job.get("steps", [])

    def step(name: str, conclusion: str) -> dict[str, Any]:
        matches = [item for item in steps if item.get("name") == name]
        require(
            len(matches) == 1
            and matches[0].get("status") == "completed"
            and matches[0].get("conclusion") == conclusion,
            "main-domain refusal step order or outcome differs",
        )
        return matches[0]

    checkout = step("Check out trusted gate", "success")
    refusal = step("Resolve current PR head", "failure")
    later = [
        step(name, "skipped")
        for name in (
            "Evaluate exact PostgreSQL N-1 authority",
            "Mark non-completed N-1 run pending",
            "Post exact-head gate status",
        )
    ]
    numbers = [item.get("number") for item in (checkout, refusal, *later)]
    require(
        all(type(number) is int and number > 0 for number in numbers)
        and numbers == sorted(set(cast(list[int], numbers)))
        and [item.get("name") for item in steps if item.get("conclusion") == "failure"]
        == ["Resolve current PR head"]
        and checkout_commit(log, checkout) == rule["trusted_checkout_revision"],
        "a later policy or technical failure cannot be a domain exclusion",
    )
    lines = completed_step_lines(log, refusal)
    errors = [line for line in lines if line.startswith("##[error]")]
    require(
        errors == [_ERROR, "##[error]Process completed with exit code 1."]
        and _environment(lines, "EVENT_NAME") == run["event"],
        "native refusal did not execute the original main-domain guard",
    )
    environment = native.trigger_environment(log, refusal)
    original_pr, original_source = native.trigger_identity(environment, run["event"])
    require(
        original_pr == identity["validation_pr"]
        and original_source == profile["product_revision"],
        "native original event does not bind this exact validation PR and product",
    )
    if run.get("pull_requests"):
        require(
            native._pr_numbers(run["pull_requests"]) == [identity["validation_pr"]],
            "native PR association contradicts the original event",
        )
    return {
        "kind": "legacy_main_domain_not_applicable/v2",
        "workflow": MAIN_WORKFLOW,
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "check_id": check["id"],
        "check_revision": check["head_sha"],
        "check_suite_id": check["check_suite"]["id"],
        "app_id": check["app"]["id"],
        "source_head": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "attachment_revision": run["head_sha"],
        "original_event_source_revision": original_source,
        "trusted_checkout_revision": rule["trusted_checkout_revision"],
        "trusted_gate_sha256": rule["trusted_gate_sha256"],
        "registration_sha256": native_digest(rule),
        "validation_pr": identity["validation_pr"],
        "validation_base_ref": identity["validation_base_ref"],
        "original_conclusion": "failure",
        "evaluated_PG_authority": False,
        "technical_gate_waiver": False,
        "main_targeting_PR_permission": False,
        "production_admission": False,
    }


def _native_file(path: str, revision: str) -> bytes:
    return native._native_file(path, revision, read=api)


_latest_matches_attempt = native._latest_matches_attempt


@dataclass(frozen=True)
class DomainEligibility:
    """In-memory native proof; never loaded from an artifact or JSON input."""

    product_revision: str
    product_tree: str
    validation_pr: int
    validation_base_ref: str
    refusals: tuple[dict[str, Any], ...]
    discovery_sha256: str | None
    observations: tuple[
        nonexecution.ZeroExecutionObservation
        | nonexecution.InfrastructureCancellationObservation
        | nonexecution.RefusalCancellationObservation,
        ...,
    ] = ()


def _discovery_binding(result: dict[str, Any]) -> str:
    require(
        result.get("kind") == "legacy_main_domain_discovery/v1"
        and result.get("complete_discovery") is True
        and result.get("stable_discovery_sets") is True
        and result.get("blockers") == []
        and result.get("unregistered_related_coordinates") == []
        and result.get("orphaned_registered_coordinates") == []
        and result.get("changed_registered_proof_coordinates") == [],
        "native main-domain discovery is incomplete or its registration differs",
    )
    native_fields = (
        (
            "unattributed_zero_execution_observations",
            nonexecution.UnattributedZeroExecutionObservation,
        ),
        ("unattributed_no_job_observations", nonexecution.UnattributedNoJobExecutionObservation),
        (
            "unattributed_bootstrap_observations",
            nonexecution.UnattributedBootstrapCancellationObservation,
        ),
    )
    unattributed = result.get("unattributed_zero_execution_observations", [])
    no_job = result.get("unattributed_no_job_observations", [])
    bootstrap = result.get("unattributed_bootstrap_observations", [])
    if unattributed or no_job or bootstrap or getattr(result, "unattributed_observations", ()):
        require(
            isinstance(result, nonexecution.DomainDiscovery)
            and all(
                isinstance(
                    row,
                    (
                        nonexecution.UnattributedZeroExecutionObservation,
                        nonexecution.UnattributedNoJobExecutionObservation,
                        nonexecution.UnattributedBootstrapCancellationObservation,
                    ),
                )
                for row in result.unattributed_observations
            )
            and all(
                [row.receipt for row in result.unattributed_observations if isinstance(row, cls)]
                == result.get(field, [])
                for field, cls in native_fields
            )
            and result.get("unattributed_expected_attempts")
            == result.get("unattributed_verified_attempts")
            and len(result.unattributed_observations)
            == len(result.get("unattributed_expected_attempts", [])),
            "domain discovery has no exact complete typed unattributed audit proof",
        )
    audited = result.get("non_execution_observations", [])
    infrastructure = result.get("infrastructure_cancellation_observations", [])
    cancelled_refusals = result.get("refusal_cancellation_observations", [])
    if audited or infrastructure or cancelled_refusals:
        require(
            isinstance(result, nonexecution.DomainDiscovery)
            and all(nonexecution.typed_observation(row) for row in result.observations)
            and [
                row.receipt
                for row in result.observations
                if isinstance(row, nonexecution.ZeroExecutionObservation)
            ]
            == audited
            and [
                row.receipt
                for row in result.observations
                if isinstance(row, nonexecution.InfrastructureCancellationObservation)
            ]
            == infrastructure
            and [
                row.receipt
                for row in result.observations
                if isinstance(row, nonexecution.RefusalCancellationObservation)
            ]
            == cancelled_refusals,
            "domain discovery has no exact typed in-memory native audit proof",
        )
    for field, rows, classification in (
        ("unattributed_no_job_observations", no_job, "audited-unattributed-no-job-execution"),
        (
            "unattributed_bootstrap_observations",
            bootstrap,
            "audited-unattributed-bootstrap-cancellation",
        ),
        (
            "unattributed_zero_execution_observations",
            unattributed,
            "audited-unattributed-nonexecution",
        ),
        ("non_execution_observations", audited, "audited-nonexecution"),
        ("refusal_cancellation_observations", cancelled_refusals, "audited-refusal-cancellation"),
        (
            "infrastructure_cancellation_observations",
            infrastructure,
            "audited-infrastructure-cancellation",
        ),
    ):
        require(
            [row for record in result["records"] for row in record.get(field, [])] == rows
            and all(
                record["classification"] != classification
                or (record.get(field) and not record["attempts"])
                for record in result["records"]
            ),
            "domain record has no exact complete native audit set",
        )
    authenticated = []
    for record in result["records"]:
        require(
            record["classification"]
            in {
                "related",
                "other-pr",
                "old-source",
                "audited-nonexecution",
                "audited-infrastructure-cancellation",
                "audited-refusal-cancellation",
                "audited-unattributed-nonexecution",
                "audited-unattributed-no-job-execution",
                "audited-unattributed-bootstrap-cancellation",
            },
            "native main-domain source is unassignable",
        )
        authenticated.append(
            {
                "run_id": record["run_id"],
                "classification": record["classification"],
                "attempts": [
                    {
                        key: row[key]
                        for key in (
                            "run_id",
                            "attempt",
                            "job_id",
                            "check_id",
                            "classification",
                            "original_PR",
                            "original_event_source_revision",
                            "attachment_revision",
                            "trusted_checkout_revision",
                            "trusted_gate_sha256",
                            "job_log_sha256",
                        )
                    }
                    for row in record["attempts"]
                ],
            }
        )
    return native_digest(
        {
            "native_identity_sha256": result["native_identity_sha256"],
            "authenticated_sources": authenticated,
            **({"unattributed_zero_execution_audits": unattributed} if unattributed else {}),
            **({"unattributed_no_job_audits": no_job} if no_job else {}),
            **({"unattributed_bootstrap_audits": bootstrap} if bootstrap else {}),
            **({"zero_execution_audits": audited} if audited else {}),
            **({"refusal_cancellation_audits": cancelled_refusals} if cancelled_refusals else {}),
            **({"infrastructure_cancellation_audits": infrastructure} if infrastructure else {}),
        }
    )


def collect_domain_eligibility(
    profile: dict[str, Any],
    identity: dict[str, Any],
    policy: dict[str, Any],
    destination: Path,
) -> DomainEligibility:
    """Join complete authenticated discovery with every exact original refusal."""
    validate_domain_rules(policy, identity)
    rules = policy["domain_not_applicable"].get(MAIN_WORKFLOW, [])
    unattributed_policy = policy.get("domain_unattributed_zero_execution", {}).get(MAIN_WORKFLOW)
    bootstrap_policy = policy.get("domain_unattributed_bootstrap_cancellation", {}).get(
        MAIN_WORKFLOW
    )
    audit_rules = policy.get("domain_non_execution", {}).get(MAIN_WORKFLOW, [])
    infrastructure_rules = policy.get("domain_infrastructure_cancellation", {}).get(
        MAIN_WORKFLOW, []
    )
    require(
        not infrastructure_rules or rules,
        "infrastructure audits cannot replace current-product refusal",
    )
    nonexecution.validate_infrastructure_rules(infrastructure_rules, profile, identity)
    refusal_cancellation_rules = policy.get("domain_refusal_cancellation", {}).get(
        MAIN_WORKFLOW, []
    )
    nonexecution.validate_refusal_cancellation_rules(refusal_cancellation_rules, profile, identity)
    require(
        not audit_rules or rules, "zero-execution audits cannot replace current-product refusal"
    )
    nonexecution.validate_rules(audit_rules, profile, identity)
    coordinates = (
        profile["product_revision"],
        profile["product_tree"],
        identity["validation_pr"],
        identity["validation_base_ref"],
    )
    if not rules:
        return DomainEligibility(*coordinates, (), None)
    destination.mkdir(mode=0o700)
    first_path = destination / "discovery-before"
    first_path.mkdir(mode=0o700)
    before = (
        discover_main_domain(
            profile,
            identity,
            rules,
            first_path,
            audit_rules,
            infrastructure_rules,
            unattributed_policy,
            bootstrap_policy,
            **(
                {"refusal_cancellation_rules": refusal_cancellation_rules}
                if refusal_cancellation_rules
                else {}
            ),
        )
        if unattributed_policy is not None
        or bootstrap_policy is not None
        or refusal_cancellation_rules
        else discover_main_domain(
            profile, identity, rules, first_path, audit_rules, infrastructure_rules
        )
        if infrastructure_rules
        else discover_main_domain(profile, identity, rules, first_path, audit_rules)
        if audit_rules
        else discover_main_domain(profile, identity, rules, first_path)
    )
    binding = _discovery_binding(before)
    results = []
    for rule in rules:
        prefix = f"repos/{REPOSITORY}/actions/runs/{rule['run_id']}"
        endpoint = prefix + f"/attempts/{rule['attempt']}"
        run = api(endpoint)
        jobs = _job_pages(rule["run_id"], rule["attempt"])
        require(
            len(jobs) == 1 and jobs[0].get("id") == rule["job_id"], "domain job matrix differs"
        )
        job = jobs[0]
        check_endpoint = f"repos/{REPOSITORY}/check-runs/{rule['check_id']}"
        check = api(check_endpoint)
        log_path = destination / f"job-{rule['job_id']}.log"
        download_job_log(rule["job_id"], log_path)
        require(
            hashlib.sha256(_native_file(MAIN_WORKFLOW, run["head_sha"])).hexdigest()
            == MAIN_WORKFLOW_SHA256
            and hashlib.sha256(_native_file(_GATE, rule["trusted_checkout_revision"])).hexdigest()
            == rule["trusted_gate_sha256"],
            "executed original domain workflow or trusted gate bytes changed",
        )
        receipt = verify_main_domain_refusal(
            profile, identity, rule, run, job, check, log_path.read_bytes().decode("utf-8")
        )
        receipt["authenticated_domain_discovery_sha256"] = binding
        results.append(receipt)
        require(
            api(endpoint) == run
            and _job_pages(rule["run_id"], rule["attempt"]) == jobs
            and api(check_endpoint) == check,
            "native domain run, job or check changed during eligibility verification",
        )
    final_path = destination / "discovery-after"
    final_path.mkdir(mode=0o700)
    after = (
        discover_main_domain(
            profile,
            identity,
            rules,
            final_path,
            audit_rules,
            infrastructure_rules,
            unattributed_policy,
            bootstrap_policy,
            **(
                {"refusal_cancellation_rules": refusal_cancellation_rules}
                if refusal_cancellation_rules
                else {}
            ),
        )
        if unattributed_policy is not None
        or bootstrap_policy is not None
        or refusal_cancellation_rules
        else discover_main_domain(
            profile, identity, rules, final_path, audit_rules, infrastructure_rules
        )
        if infrastructure_rules
        else discover_main_domain(profile, identity, rules, final_path, audit_rules)
        if audit_rules
        else discover_main_domain(profile, identity, rules, final_path)
    )
    require(
        _discovery_binding(after) == binding,
        "native main-domain discovery changed during exact refusal verification",
    )
    unattributed_observations = tuple(getattr(after, "unattributed_observations", ()))
    require(
        all(
            any(nonexecution.matching_refusal(proof.receipt, refusal) for refusal in results)
            for proof in unattributed_observations
        ),
        "unattributed audit lacks an independent same-PR/base/tree/product main guard refusal",
    )
    observations = tuple(getattr(after, "observations", ()))
    require(
        all(
            any(nonexecution.matching_refusal(proof.receipt, refusal) for refusal in results)
            for proof in observations
        ),
        "native audit lacks an independent same-PR/base/tree/product main guard refusal",
    )
    result = DomainEligibility(*coordinates, tuple(results), binding, observations)
    (destination / "domain-eligibility.json").write_text(
        json.dumps(
            {
                "kind": "legacy_authenticated_domain_eligibility/v2",
                "product_revision": result.product_revision,
                "product_tree": result.product_tree,
                "validation_pr": result.validation_pr,
                "validation_base_ref": result.validation_base_ref,
                "discovery_sha256": binding,
                "refusals": results,
                **{
                    field: [
                        row.receipt
                        for row in unattributed_observations
                        if nonexecution.unattributed_field(row) == field
                    ]
                    for field in (
                        "unattributed_zero_execution_observations",
                        "unattributed_no_job_observations",
                        "unattributed_bootstrap_observations",
                    )
                },
                "zero_execution_observations": [
                    row.receipt
                    for row in result.observations
                    if isinstance(row, nonexecution.ZeroExecutionObservation)
                ],
                "infrastructure_cancellation_observations": [
                    row.receipt
                    for row in result.observations
                    if isinstance(row, nonexecution.InfrastructureCancellationObservation)
                ],
                "production_admission": False,
            },
            indent=2,
        )
        + "\n"
    )
    return result
