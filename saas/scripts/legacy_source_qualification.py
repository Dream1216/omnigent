"""Join reviewed source, native matrices, all-App results and test evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, cast

from saas.scripts import legacy_domain_non_execution as nonexecution
from saas.scripts import legacy_security_policy as security
from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_build_controller import control_context
from saas.scripts.legacy_check_history import (
    _stable_projection,
    collect_snapshot,
    latest_check_runs,
    latest_statuses,
    verify_required_job_bindings,
)
from saas.scripts.legacy_domain_eligibility import (
    BOOTSTRAP_KIND,
    MAIN_WORKFLOW,
    BootstrapPositiveOrigin,
    DomainEligibility,
    bootstrap_registration,
    collect_bootstrap_positive_origin,
    collect_domain_eligibility,
    validate_domain_rules,
)
from saas.scripts.legacy_native_evidence import NativeEvidence, api, preserve_native_evidence
from saas.scripts.legacy_pytest_results import (
    validate_compact_log_contract,
    verify_pytest_evidence,
)
from saas.scripts.legacy_source_ci import (
    _load_contract,
    collect_source_ci_bindings,
    download_job_log,
)
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    COMPATIBILITY_COMPONENT,
    REPOSITORY,
    load_profile,
    validate_profile,
    verify_pr_tree,
    verify_source_delta,
)

_MANDATORY_TECHNICAL = {
    ".github/workflows/ci.yml",
    ".github/workflows/e2e.yml",
    ".github/workflows/e2e-ui.yml",
    ".github/workflows/lint.yml",
    ".github/workflows/trivy.yml",
    ".github/workflows/security-scan.yml",
    ".github/workflows/saas-upstream-compat.yml",
    ".github/workflows/setup-harness-cli-pin-test.yml",
    ".github/workflows/setup-harness-cli-test.yml",
    ".github/workflows/integration.yml",
    ".github/workflows/web-tests.yml",
    ".github/workflows/windows.yml",
    ".github/workflows/ui-snapshot.yml",
    ".github/workflows/docker-build.yml",
    ".github/workflows/saas-image-candidate.yml",
    ".github/workflows/saas-n1-compat-image.yml",
}
_REGISTERED_COMPAT_SOURCE = (
    "27503d14973b751a2031c6febf12a581b42b06d1",
    "a02ea9f17664bd0290eb5025f864672c0025075c",
    258,
    "codex/legacy-compat018-expat210-20261103",
)
_RECOVERED_IMAGE_WORKFLOW = ".github/workflows/saas-image-candidate.yml"
_RECOVERED_IMAGE_DECLARATION = {
    "kind": "compat018_registered_native_image_completion/v1",
    "original_workflow": _RECOVERED_IMAGE_WORKFLOW,
    "original_cancelled_run_id": 42573722547,
    "original_cancelled_run_claimed_success": False,
    "publisher_full_archive_verification_required": True,
}
_REGISTERED_COMPAT_POLICY_SLOT = "Compatibility018@27503d14973b751a2031c6febf12a581b42b06d1"
_ORIGINAL_CANCELLED_IMAGE_CHECK_IDS = {
    129016661137,
    129016661249,
    129016661268,
    129017293227,
    129017293515,
    129017293730,
}
_COMPATIBILITY_PATH_FILTERS = {
    ".github/workflows/setup-harness-cli-test.yml": (
        "d0a58addba9cf515415f73253497ee1dc3818fee6bddb9ea77f9b8d2be4d8379",
        (
            ".github/actions/setup-harness-cli/**",
            ".github/ci-deps/package.json",
            ".github/workflows/setup-harness-cli-test.yml",
        ),
    ),
    ".github/workflows/web-tests.yml": (
        "5d9ba9571ecebf279e79eb24a1d578d56d1dde49df5b0788d77a5132c5218f6e",
        (
            "web/**",
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            ".npmrc",
            ".github/actions/setup-pnpm/**",
            ".github/workflows/web-tests.yml",
        ),
    ),
}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def workflow_catalog(product: Path, revision: str) -> dict[str, str]:
    rows = subprocess.check_output(
        ["git", "ls-tree", "-r", "-z", revision, "--", ".github/workflows"], cwd=product
    )
    result = {}
    for row in filter(None, rows.split(b"\0")):
        metadata, name = row.split(b"\t", 1)
        mode, kind, _ = metadata.decode().split()
        path = name.decode()
        if not path.endswith((".yml", ".yaml")):
            continue
        require(
            mode in {"100644", "100755"} and kind == "blob",
            "workflow catalog contains a non-regular file",
        )
        body = subprocess.check_output(
            ["git", "cat-file", "blob", revision + ":" + path], cwd=product
        )
        require(len(body) <= 262144, "original workflow exceeds its parser bound")
        result[path] = hashlib.sha256(body).hexdigest()
    require(bool(result), "original workflow catalog is empty")
    return result


def qualification_profile_slot(component: str, profile: dict[str, Any]) -> str:
    """Keep the frozen historical registration intact when selecting current C2."""
    if (
        component == COMPATIBILITY_COMPONENT
        and (profile.get("product_revision"), profile.get("product_tree"))
        == _REGISTERED_COMPAT_SOURCE[:2]
    ):
        return _REGISTERED_COMPAT_POLICY_SLOT
    return component


def load_qualification_policy(control: Path, profile: dict[str, Any]) -> dict[str, Any]:
    path = control / "saas/supply_chain/legacy-source-qualification-profiles.json"
    require(
        path.is_file() and not path.is_symlink(),
        "missing reviewed source qualification profiles",
    )
    store = json.loads(path.read_text())
    require(
        set(store) == {"schema_version", "profiles"}
        and type(store["schema_version"]) is int
        and store["schema_version"] == 1
        and isinstance(store["profiles"], dict),
        "source qualification store differs",
    )
    policy = store["profiles"].get(qualification_profile_slot(profile["component"], profile))
    require(
        isinstance(policy, dict)
        and set(policy)
        - {
            "bootstrap_positive_origin",
            "domain_non_execution",
            "domain_infrastructure_cancellation",
            "domain_refusal_cancellation",
            "domain_unattributed_zero_execution",
            "domain_unattributed_bootstrap_cancellation",
            "recovered_native_image_completion",
        }
        == {
            "component",
            "product_revision",
            "product_tree",
            "identity_contract_sha256",
            "workflow_catalog",
            "job_evidence",
            "other_checks",
            "statuses",
            "domain_not_applicable",
        }
        and all(
            policy[key] == profile[key]
            for key in ("component", "product_revision", "product_tree")
        )
        and isinstance(policy["identity_contract_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", policy["identity_contract_sha256"]) is not None,
        "no exact reviewed source qualification policy",
    )
    return policy


def _required_technical_workflows(policy, identity, actual_catalog, profile):
    if policy.get("component") != COMPATIBILITY_COMPONENT:
        return _MANDATORY_TECHNICAL
    require(isinstance(profile, dict), "compatibility path scope needs the exact source profile")
    validate_profile(profile, COMPATIBILITY_COMPONENT)
    require(
        all(
            policy[key] == identity[key] == profile[key]
            for key in ("component", "product_revision", "product_tree")
        )
        and (
            (
                identity["validation_pr"] == 223
                and identity["validation_base_ref"] == "codex/p18-a7-validation-base-20261102"
            )
            or (
                identity["product_revision"],
                identity["product_tree"],
                identity["validation_pr"],
                identity["validation_base_ref"],
            )
            == _REGISTERED_COMPAT_SOURCE
        ),
        "compatibility path scope differs from the exact source and PR",
    )
    for path, (source_hash, patterns) in _COMPATIBILITY_PATH_FILTERS.items():
        require(
            actual_catalog.get(path) == source_hash
            and policy["workflow_catalog"][path]["disposition"] == "original-not-triggered",
            "compatibility path-filtered workflow bytes or disposition differ",
        )
        require(
            not any(
                delta["path"] == pattern
                or (pattern.endswith("/**") and delta["path"].startswith(pattern[:-2]))
                for delta in profile["source_delta"]
                for pattern in patterns
            ),
            "compatibility source changes match an original workflow path filter",
        )
    return _MANDATORY_TECHNICAL - _COMPATIBILITY_PATH_FILTERS.keys()


def _verify_recovered_image_completion(policy, identity, profile, completion) -> bool:
    """The cancelled original image run stays failed; require a separate native proof."""
    declaration = policy.get("recovered_native_image_completion")
    if declaration is None:
        require(completion is None, "undeclared recovered image evidence")
        return False
    from saas.scripts.compat018_recovered_input import NativeRecoveredImageCompletion

    require(
        policy.get("component") == COMPATIBILITY_COMPONENT
        and isinstance(profile, dict)
        and profile.get("component") == identity.get("component") == COMPATIBILITY_COMPONENT
        and declaration == _RECOVERED_IMAGE_DECLARATION
        and declaration["original_cancelled_run_claimed_success"] is False
        and declaration["publisher_full_archive_verification_required"] is True
        and (
            identity.get("product_revision"),
            identity.get("product_tree"),
            identity.get("validation_pr"),
            identity.get("validation_base_ref"),
        )
        == _REGISTERED_COMPAT_SOURCE
        and all(
            profile.get(key) == identity.get(key)
            for key in ("component", "product_revision", "product_tree")
        )
        and isinstance(completion, NativeRecoveredImageCompletion),
        "recovered image completion is not the exact current registered native proof",
    )
    receipt = completion.receipt
    require(
        receipt.get("kind") == declaration["kind"]
        and receipt.get("product_revision") == profile["product_revision"]
        and receipt.get("product_tree") == profile["product_tree"]
        and receipt.get("whole_archive_bytes_verified_here") is False
        and receipt.get("publisher_full_archive_verification_required") is True
        and receipt.get("regression_or_PG_qualification_claimed") is False,
        "recovered image metadata cannot claim archive, regression or PG admission",
    )
    for role in ("raw_checkpoint", "sealed_oci"):
        row = receipt.get(role, {})
        require(
            type(row.get("run_id")) is int
            and row["run_id"] > 0
            and row["run_id"] != declaration["original_cancelled_run_id"]
            and type(row.get("attempt")) is int
            and row["attempt"] == 1,
            "recovered image cannot borrow the cancelled original or an unknown attempt",
        )
    return True


def validate_qualification_policy(
    policy: dict[str, Any],
    identity: dict[str, Any],
    actual_catalog: dict[str, str],
    *,
    profile: dict[str, Any] | None = None,
    recovered_image: object = None,
) -> None:
    require(
        policy["identity_contract_sha256"] == _digest(identity),
        "reviewed source identity contract changed",
    )
    catalog = policy["workflow_catalog"]
    require(
        isinstance(catalog, dict) and set(catalog) == set(actual_catalog),
        "original workflow catalog is incomplete",
    )
    required = set()
    for path, row in catalog.items():
        require(
            isinstance(row, dict)
            and set(row) == {"sha256", "disposition", "reason"}
            and row["sha256"] == actual_catalog[path]
            and row["disposition"]
            in {
                "required-technical",
                "original-governance",
                "original-informational",
                "original-not-triggered",
                "original-domain-not-applicable",
            }
            and isinstance(row["reason"], str)
            and bool(row["reason"].strip()),
            "original workflow disposition or bytes are not reviewed",
        )
        if row["disposition"] == "required-technical":
            required.add(path)
        require(
            row["disposition"] != "original-domain-not-applicable" or path == MAIN_WORKFLOW,
            "another workflow cannot use the main-domain eligibility rule",
        )
    validate_domain_rules(policy, identity)
    recovered = _verify_recovered_image_completion(policy, identity, profile, recovered_image)
    identity_required = {row["path"] for row in identity["workflows"]}
    if recovered:
        require(
            _RECOVERED_IMAGE_WORKFLOW not in identity_required,
            "recovered image cannot replace or duplicate an original successful source workflow",
        )
    require(
        required >= _required_technical_workflows(policy, identity, actual_catalog, profile)
        and required == identity_required | ({_RECOVERED_IMAGE_WORKFLOW} if recovered else set()),
        "complete mandatory technical workflow set differs",
    )
    evidence = policy["job_evidence"]
    require(
        isinstance(evidence, dict) and set(evidence) == identity_required,
        "technical job evidence plan is incomplete",
    )
    for workflow in identity["workflows"]:
        plans = evidence[workflow["path"]]
        if "trusted_security_policy" in workflow:
            security.validate_registration(
                {
                    **policy,
                    "baseline_revision": workflow["trusted_security_policy"]["baseline_revision"],
                },
                identity,
                workflow,
            )
            require(
                plans
                == {
                    "Security Scan": {
                        "kind": "control-metadata",
                        "reason": plans.get("Security Scan", {}).get("reason"),
                        "execution_steps": security.EXECUTION_STEPS,
                        "pytest": None,
                    }
                },
                "original OWNER policy must retain successful policy steps and no product tests",
            )
        require(
            isinstance(plans, dict) and set(plans) == set(workflow["jobs"]),
            "original job matrix evidence plan differs",
        )
        for name, contract in workflow["jobs"].items():
            row = plans[name]
            require(
                isinstance(row, dict)
                and set(row)
                in (
                    {"kind", "reason", "execution_steps", "pytest"},
                    {"kind", "reason", "execution_steps", "pytest", "native_log_contract"},
                )
                and row["kind"]
                in {
                    "native-command",
                    "pytest",
                    "control-metadata",
                    "original-conditional",
                }
                and isinstance(row["reason"], str)
                and bool(row["reason"].strip())
                and isinstance(row["execution_steps"], list),
                "native job evidence declaration differs",
            )
            for step in row["execution_steps"]:
                require(
                    set(step) == {"number", "name"}
                    and type(step["number"]) is int
                    and step["number"] > 0
                    and isinstance(step["name"], str)
                    and bool(step["name"]),
                    "native execution step identity is malformed",
                )
            if contract["conclusion"] == "skipped":
                require(
                    row["kind"] == "original-conditional"
                    and not row["execution_steps"]
                    and row["pytest"] is None,
                    "skipped original job cannot contribute technical evidence",
                )
            else:
                require(
                    row["kind"] != "original-conditional" and bool(row["execution_steps"]),
                    "successful job has no executed-step evidence",
                )
                product_steps = [
                    step
                    for step in contract["checkouts"]
                    if step["revision"] in {"product", "product-merge"}
                ]
                require(
                    bool(product_steps) == (row["kind"] in {"native-command", "pytest"}),
                    "product execution cannot be demoted to control metadata",
                )
            require(
                (row["pytest"] is not None) == (row["kind"] == "pytest"),
                "pytest job evidence is missing or misclassified",
            )
            if row["pytest"] is not None:
                _validate_pytest_plan(row["pytest"])
            if "native_log_contract" in row:
                require(
                    row["kind"] == "pytest", "compact contract requires original pytest evidence"
                )
                expected = cast(dict[str, Any], row["pytest"])
                validate_compact_log_contract(
                    row["native_log_contract"],
                    {
                        "source_revision": policy["product_revision"],
                        "workflow_path": workflow["path"],
                        "job_name": name,
                        "run_id": workflow["run_id"],
                        "attempt": workflow["attempt"],
                        "artifact_id": expected["artifact_id"],
                        "xml_member": expected["xml_member"],
                        "test_step": expected["test_step"],
                        "upload_step": expected["upload_step"],
                    },
                )
    require(
        isinstance(policy["other_checks"], list) and isinstance(policy["statuses"], list),
        "all-App policy inventories are missing",
    )


def _validate_pytest_plan(row: dict[str, Any]) -> None:
    require(
        isinstance(row, dict)
        and set(row)
        == {
            "artifact_id",
            "artifact_name",
            "xml_member",
            "test_step",
            "upload_step",
            "approved_skips",
            "approved_reruns",
        }
        and type(row["artifact_id"]) is int
        and row["artifact_id"] > 0
        and all(
            isinstance(row[key], str) and bool(row[key]) for key in ("artifact_name", "xml_member")
        )
        and isinstance(row["approved_skips"], list)
        and isinstance(row["approved_reruns"], list),
        "reviewed pytest artifact plan differs",
    )
    for field in ("test_step", "upload_step"):
        require(
            isinstance(row[field], dict)
            and set(row[field]) == {"number", "name"}
            and type(row[field]["number"]) is int
            and row[field]["number"] > 0
            and isinstance(row[field]["name"], str)
            and bool(row[field]["name"]),
            "reviewed pytest step identity differs",
        )
    for field, extra in (
        ("approved_skips", "reason_sha256"),
        ("approved_reruns", "count"),
    ):
        keys = []
        for item in row[field]:
            require(
                isinstance(item, dict)
                and set(item) == {"classname", "name", extra}
                and isinstance(item["name"], str)
                and bool(item["name"])
                and isinstance(item["classname"], str)
                and (
                    bool(item["classname"])
                    or (
                        field == "approved_skips"
                        and item["classname"] == ""
                        and re.fullmatch(r"tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+", item["name"])
                        is not None
                    )
                ),
                "reviewed pytest exception identity differs",
            )
            value = item[extra]
            require(
                (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
                if extra == "reason_sha256"
                else (type(value) is int and value > 0),
                "reviewed pytest exception value differs",
            )
            keys.append((item["classname"], item["name"]))
        require(len(keys) == len(set(keys)), "reviewed pytest exceptions are duplicated")


def _verify_steps(job: dict[str, Any], plan: dict[str, Any]) -> None:
    for expected in plan["execution_steps"]:
        selected = [
            row
            for row in job.get("steps", [])
            if all(row.get(key) == expected[key] for key in ("number", "name"))
        ]
        require(
            len(selected) == 1
            and selected[0].get("status") == "completed"
            and selected[0].get("conclusion") == "success",
            "required original command step did not execute successfully",
        )
    if job["conclusion"] == "success" and any(
        row.get("name") == "Upload pytest artifacts" for row in job.get("steps", [])
    ):
        require(
            plan["kind"] == "pytest",
            "original pytest artifacts cannot be downgraded to status-only evidence",
        )


def _check_key(role: str, row: dict[str, Any]) -> tuple[Any, ...]:
    return role, row["app"]["id"], row["check_suite"]["id"], row["name"]


def _recovered_cancelled_image_checks(snapshots, policy, completion):
    """Retain the exact cancelled antecedent; its replacement never supplies PG credit."""
    if completion is None:
        return {}
    identity = {
        **{key: policy[key] for key in ("component", "product_revision", "product_tree")},
        "validation_pr": _REGISTERED_COMPAT_SOURCE[2],
        "validation_base_ref": _REGISTERED_COMPAT_SOURCE[3],
    }
    _verify_recovered_image_completion(policy, identity, policy, completion)
    head = snapshots["head"]
    originals = [
        run
        for run in head["runs"]
        if run.get("id") == _RECOVERED_IMAGE_DECLARATION["original_cancelled_run_id"]
    ]
    require(len(originals) == 1, "original cancelled image native run is missing or duplicated")
    original = originals[0]
    require(
        original.get("head_sha") == policy["product_revision"]
        and original.get("path") == _RECOVERED_IMAGE_WORKFLOW
        and original.get("event") == "pull_request"
        and original.get("run_attempt") == 1
        and original.get("status") == "completed"
        and original.get("conclusion") == "cancelled",
        "recovered image cannot rewrite the exact original cancelled image outcome",
    )
    checks = [
        row
        for row in latest_check_runs(head)
        if row.get("check_suite", {}).get("id") == original.get("check_suite_id")
    ]
    require(
        len(checks) == len(_ORIGINAL_CANCELLED_IMAGE_CHECK_IDS)
        and {row.get("id") for row in checks} == _ORIGINAL_CANCELLED_IMAGE_CHECK_IDS
        and all(
            row.get("app", {}).get("id") == 15368
            and row.get("head_sha") == policy["product_revision"]
            and row.get("status") == "completed"
            and row.get("conclusion") == "cancelled"
            for row in checks
        ),
        "original cancelled image check matrix or native outcomes differ",
    )
    return {row["id"]: row for row in checks}


def assess_all_app_policy(
    snapshots: dict[str, dict[str, Any]],
    observations: list[dict[str, Any]],
    policy: dict[str, Any],
    domain_receipts: list[dict[str, Any]] | None = None,
    domain_observations: tuple[
        nonexecution.ZeroExecutionObservation
        | nonexecution.InfrastructureCancellationObservation
        | nonexecution.RefusalCancellationObservation,
        ...,
    ] = (),
    *,
    recovered_image: object = None,
) -> dict[str, Any]:
    cancelled_image = _recovered_cancelled_image_checks(snapshots, policy, recovered_image)
    if policy.get("component") == COMPATIBILITY_COMPONENT:
        require(
            not any(
                run.get("path") in _COMPATIBILITY_PATH_FILTERS
                for snapshot in snapshots.values()
                for run in snapshot["runs"]
            ),
            "native compatibility workflow run contradicts original path-filtered scope",
        )
    require(
        isinstance(domain_observations, tuple)
        and all(nonexecution.typed_observation(row) for row in domain_observations)
        and all(
            any(
                nonexecution.matching_refusal(row.receipt, refusal)
                for refusal in domain_receipts or []
            )
            for row in domain_observations
        ),
        "domain audit requires typed proof and same-PR/base/tree/product main guard refusal",
    )
    audit_checks = {row.receipt["check_id"]: row.receipt for row in domain_observations}
    require(
        len(audit_checks) == len(domain_observations), "zero-execution check audit is duplicated"
    )
    domain_checks = {row["check_id"]: row for row in domain_receipts or []}
    technical_ids = {
        int(job["check_run_url"].rsplit("/", 1)[1])
        for item in observations
        for job in item["jobs"]
    }
    actual_checks = {
        _check_key(role, row): row
        for role, snapshot in snapshots.items()
        for row in latest_check_runs(snapshot)
        if not (role == "head" and row["id"] in technical_ids)
    }
    expected = {}
    for row in policy["other_checks"]:
        require(
            set(row)
            == {
                "role",
                "app_id",
                "suite_id",
                "name",
                "scope",
                "expected_conclusion",
                "reason",
            }
            and row["role"] in {"head", "merge"}
            and type(row["app_id"]) is int
            and row["app_id"] > 0
            and type(row["suite_id"]) is int
            and row["suite_id"] > 0
            and isinstance(row["name"], str)
            and bool(row["name"])
            and row["scope"]
            in {
                "required-technical",
                "original-governance",
                "original-informational",
                "original-conditional",
                "original-domain-not-applicable",
                "original-domain-zero-execution",
                "original-domain-infrastructure-cancellation",
                "original-domain-refusal-cancellation",
                "original-recovered-image-cancellation",
            }
            and isinstance(row["reason"], str)
            and bool(row["reason"].strip()),
            "all-App check disposition is malformed",
        )
        key = row["role"], row["app_id"], row["suite_id"], row["name"]
        require(key not in expected, "all-App check policy is duplicated")
        if row["app_id"] == 15368:
            origins = [
                item
                for item in snapshots[row["role"]]["runs"]
                if item.get("check_suite_id") == row["suite_id"]
            ]
            require(len(origins) == 1, "all-App check has no unique native workflow origin")
            origin = origins[0]
            declared_workflow = policy["workflow_catalog"].get(origin["path"])
            require(
                declared_workflow is not None
                and declared_workflow["disposition"] != "original-not-triggered",
                "native workflow eligibility contradicts the reviewed catalog",
            )
            if row["scope"] == "original-recovered-image-cancellation":
                check = actual_checks.get(key, {})
                require(
                    row["role"] == "head"
                    and origin.get("id")
                    == _RECOVERED_IMAGE_DECLARATION["original_cancelled_run_id"]
                    and origin["path"] == _RECOVERED_IMAGE_WORKFLOW
                    and declared_workflow["disposition"] == "required-technical"
                    and cancelled_image.get(check.get("id")) == check
                    and row["expected_conclusion"] is None,
                    "cancelled original image requires exact current native replacement proof",
                )
            if origin["path"] == MAIN_WORKFLOW:
                require(
                    row["scope"] == declared_workflow["disposition"]
                    or (
                        row["scope"]
                        in {
                            "original-domain-zero-execution",
                            "original-domain-infrastructure-cancellation",
                            "original-domain-refusal-cancellation",
                        }
                        and declared_workflow["disposition"] == "original-domain-not-applicable"
                    ),
                    "main-domain check bypasses its original governance or domain disposition",
                )
            if row["scope"] == "original-governance":
                require(
                    declared_workflow["disposition"] == "original-governance",
                    "technical workflow cannot be demoted to a governance refusal",
                )
            if row["scope"] == "original-domain-not-applicable":
                proof = domain_checks.get(actual_checks.get(key, {}).get("id"))
                require(
                    declared_workflow["disposition"] == "original-domain-not-applicable"
                    and origin["path"] == MAIN_WORKFLOW
                    and proof is not None
                    and proof["run_id"] == origin["id"]
                    and proof["attempt"] == origin["run_attempt"]
                    and proof["app_id"] == row["app_id"]
                    and proof["check_suite_id"] == row["suite_id"]
                    and proof["check_revision"] == snapshots[row["role"]]["revision"],
                    "main-domain check has no exact native refusal evidence",
                )
            if row["scope"] in {
                "original-domain-zero-execution",
                "original-domain-infrastructure-cancellation",
                "original-domain-refusal-cancellation",
            }:
                proof = audit_checks.get(actual_checks.get(key, {}).get("id"))
                require(
                    origin["path"] == MAIN_WORKFLOW
                    and declared_workflow["disposition"] == "original-domain-not-applicable"
                    and proof is not None
                    and proof["run_id"] == origin["id"]
                    and proof["attempt"] == origin["run_attempt"]
                    and proof["app_id"] == row["app_id"]
                    and proof["check_suite_id"] == row["suite_id"]
                    and proof["check_revision"] == snapshots[row["role"]]["revision"]
                    and proof["original_conclusion"] == actual_checks[key]["conclusion"]
                    and _digest(actual_checks[key]) == proof["check_sha256"]
                    and proof["source_classification"] == "UNKNOWN"
                    and proof["source_proof"]
                    is proof["guard_refusal"]
                    is proof["technical_gate_waiver"]
                    is proof["production_admission"]
                    is False
                    and proof["kind"]
                    == (
                        nonexecution.REFUSAL_CANCELLATION_KIND
                        if row["scope"] == "original-domain-refusal-cancellation"
                        else nonexecution.KIND
                        if row["scope"] == "original-domain-zero-execution"
                        else nonexecution.INFRASTRUCTURE_KIND
                    )
                    and proof["execution"]
                    in (
                        {"native-refusal-then-cancelled"}
                        if row["scope"] == "original-domain-refusal-cancellation"
                        else {"native-proven-zero"}
                        if row["scope"] == "original-domain-zero-execution"
                        else {
                            "native-infrastructure-executed-cancelled",
                            "native-assigned-runner-cancelled-execution-UNKNOWN",
                        }
                    )
                    and any(
                        nonexecution.matching_refusal(proof, refusal)
                        for refusal in cast(list[dict[str, Any]], domain_receipts)
                    ),
                    "main-domain audit check has no exact typed native audit and refusal",
                )
                proof = cast(dict[str, Any], proof)
                if row["scope"] == "original-domain-infrastructure-cancellation":
                    require(
                        _digest(
                            {
                                key: value
                                for key, value in origin.items()
                                if key not in {"jobs_url", "logs_url"}
                            }
                        )
                        == proof["run_snapshot_sha256"],
                        "all-App infrastructure native run differs from the exact audit tuple",
                    )
            require(
                declared_workflow["disposition"] != "original-domain-not-applicable"
                or row["scope"]
                in {
                    "original-domain-not-applicable",
                    "original-domain-zero-execution",
                    "original-domain-infrastructure-cancellation",
                    "original-domain-refusal-cancellation",
                },
                "a domain refusal cannot be demoted to generic information or governance",
            )
            if declared_workflow["disposition"] == "required-technical":
                require(
                    row["scope"] == "required-technical"
                    or (
                        row["scope"] == "original-recovered-image-cancellation"
                        and actual_checks.get(key, {}).get("id") in cancelled_image
                    )
                    or (
                        row["scope"] == "original-conditional"
                        and policy["job_evidence"][origin["path"]].get(row["name"], {}).get("kind")
                        == "original-conditional"
                    )
                    or (row["scope"] == "original-informational" and origin["event"] == "push"),
                    "required original technical check was downgraded",
                )
        else:
            require(
                row["scope"]
                not in {
                    "original-governance",
                    "original-domain-not-applicable",
                    "original-domain-zero-execution",
                    "original-domain-infrastructure-cancellation",
                    "original-domain-refusal-cancellation",
                    "original-recovered-image-cancellation",
                },
                "external provider cannot supply an original governance exception",
            )
        expected[key] = row
    require(
        set(expected) == set(actual_checks),
        "unreviewed or missing all-App check contexts",
    )
    governance = []
    informational = []
    infrastructure_cancellations = []
    refusal_cancellations = []
    recovered_image_cancellations = []
    for key, rule in expected.items():
        check = actual_checks[key]
        require(check["status"] == "completed", "all-App check is not terminal")
        if rule["scope"] == "original-governance":
            require(
                rule["expected_conclusion"] is None,
                "governance refusal cannot be rewritten as an approved outcome",
            )
            if check["conclusion"] != "success":
                governance.append(
                    {
                        "role": key[0],
                        "check_id": check["id"],
                        "name": check["name"],
                        "conclusion": check["conclusion"],
                        "reason": rule["reason"],
                    }
                )
        elif rule["scope"] == "original-recovered-image-cancellation":
            require(
                rule["expected_conclusion"] is None and check["conclusion"] == "cancelled",
                "the original image cancellation remains cancelled",
            )
            recovered_image_cancellations.append(
                {
                    "check_id": check["id"],
                    "original_conclusion": "cancelled",
                    "original_technical_or_PG_credit": False,
                    "replacement_native_image_completion_required": True,
                    "final_same_product_PG_and_full_archive_admission_still_required": True,
                }
            )
        elif rule["scope"] == "original-domain-refusal-cancellation":
            require(
                rule["expected_conclusion"] is None and check["conclusion"] == "cancelled",
                "refusal cancellation must retain cancelled outcome",
            )
            refusal_cancellations.append(
                {
                    "check_id": check["id"],
                    "conclusion": "cancelled",
                    "reason": rule["reason"],
                    "scope": rule["scope"],
                    "source_proof": False,
                    "guard_refusal": False,
                    "technical_gate_waiver": False,
                    "production_admission": False,
                }
            )
        elif rule["scope"] == "original-domain-infrastructure-cancellation":
            require(
                rule["expected_conclusion"] is None and check["conclusion"] == "cancelled",
                "infrastructure cancellation must retain its original cancelled outcome",
            )
            infrastructure_cancellations.append(
                {
                    "check_id": check["id"],
                    "conclusion": check["conclusion"],
                    "reason": rule["reason"],
                    "scope": rule["scope"],
                    "source_proof": False,
                    "guard_refusal": False,
                    "technical_gate_waiver": False,
                    "production_admission": False,
                }
            )
        elif rule["scope"] in {
            "original-informational",
            "original-domain-not-applicable",
            "original-domain-zero-execution",
        }:
            require(
                rule["expected_conclusion"] is None,
                "informational result must remain explicit original data",
            )
            informational.append(
                {
                    "check_id": check["id"],
                    "conclusion": check["conclusion"],
                    "reason": rule["reason"],
                    "scope": rule["scope"],
                }
            )
        else:
            allowed = (
                {"success"} if rule["scope"] == "required-technical" else {"skipped", "neutral"}
            )
            require(
                rule["expected_conclusion"] in allowed
                and check["conclusion"] == rule["expected_conclusion"],
                "required or original conditional all-App check differs",
            )
    statuses = {
        (role, row["context"]): row
        for role, snapshot in snapshots.items()
        for row in latest_statuses(snapshot)
    }
    declared = {}
    for row in policy["statuses"]:
        require(
            set(row) == {"role", "context", "creator_id", "scope", "reason"}
            and row["role"] in {"head", "merge"}
            and isinstance(row["context"], str)
            and bool(row["context"])
            and type(row["creator_id"]) is int
            and row["creator_id"] > 0
            and row["scope"] in {"required-technical", "original-informational"}
            and isinstance(row["reason"], str)
            and bool(row["reason"].strip()),
            "native status policy differs",
        )
        key = row["role"], row["context"]
        require(key not in declared, "native status policy repeats a context")
        declared[key] = row
    require(set(statuses) == set(declared), "unreviewed or missing native status contexts")
    for key, rule in declared.items():
        status = statuses[key]
        require(
            status["creator"]["id"] == rule["creator_id"],
            "native status creator differs",
        )
        if rule["scope"] == "required-technical":
            require(
                status["state"] == "success",
                "required native commit status is not successful",
            )
    return {
        "governance_refusals": governance,
        "original_informational_checks": informational,
        "original_infrastructure_cancellations": infrastructure_cancellations,
        "all_original_governance_clear": not governance,
        **(
            {"original_recovered_image_cancellations": recovered_image_cancellations}
            if recovered_image_cancellations
            else {}
        ),
        **(
            {
                "verified_main_domain_refusal_cancellations": [
                    row.receipt
                    for row in domain_observations
                    if isinstance(row, nonexecution.RefusalCancellationObservation)
                ],
                "original_refusal_cancellations": refusal_cancellations,
            }
            if refusal_cancellations
            else {}
        ),
        "verified_main_domain_refusals": domain_receipts or [],
        "verified_main_domain_zero_execution": [
            row.receipt
            for row in domain_observations
            if isinstance(row, nonexecution.ZeroExecutionObservation)
        ],
        "verified_main_domain_infrastructure_cancellations": [
            row.receipt
            for row in domain_observations
            if isinstance(row, nonexecution.InfrastructureCancellationObservation)
        ],
    }


def _qualify_source_ci(
    control: Path,
    product: Path,
    component: str,
    control_revision: str,
    destination: Path,
    evidence: NativeEvidence,
    *,
    context_verifier,
    recovered_selection: tuple[int, int] | None = None,
) -> dict[str, Any]:
    context_verifier(control, control_revision)
    profile = load_profile(control, component)
    verify_source_delta(product, profile)
    identity = _load_contract(control, profile)
    policy = load_qualification_policy(control, profile)
    catalog = workflow_catalog(product, profile["product_revision"])
    recovered_image = None
    if "recovered_native_image_completion" in policy:
        from saas.scripts.compat018_recovered_input import (
            collect_native_recovered_image_completion,
            dispatch_selection,
        )

        selected = (
            dispatch_selection(profile) if recovered_selection is None else recovered_selection
        )
        if selected is None:
            raise ValueError("current C2 source qualification requires actual raw and scan runs")
        recovered_image = collect_native_recovered_image_completion(control, profile, selected)
    else:
        require(recovered_selection is None, "undeclared explicit recovered source selection")
    validate_qualification_policy(
        policy, identity, catalog, profile=profile, recovered_image=recovered_image
    )
    bootstrap = "bootstrap_positive_origin" in policy
    registration = bootstrap_registration(control, profile, policy) if bootstrap else None
    if bootstrap:
        evidence.enable_bootstrap_limits()
        evidence.observe_bootstrap_rate_limit()
    collector = collect_bootstrap_positive_origin if bootstrap else collect_domain_eligibility
    evidence.stage = "initial-PR-and-checks"
    endpoint = f"repos/{REPOSITORY}/pulls/{identity['validation_pr']}"
    initial_pull = api(endpoint)
    merge = initial_pull.get("merge_commit_sha")
    require(
        isinstance(merge, str) and re.fullmatch(r"[0-9a-f]{40}", merge) is not None,
        "initial native PR merge coordinate missing",
    )
    merge = cast(str, merge)
    initial_commit = api(f"repos/{REPOSITORY}/git/commits/{merge}")
    verify_pr_tree(
        initial_pull,
        initial_commit,
        profile,
        number=identity["validation_pr"],
        base_ref=identity["validation_base_ref"],
    )
    revisions = {"head": profile["product_revision"], "merge": merge}
    before = {role: collect_snapshot(revision) for role, revision in revisions.items()}
    (destination / "native-checks-before.json").write_text(json.dumps(before, indent=2) + "\n")
    evidence.stage = "main-domain-native-eligibility"
    domain_eligibility = collector(profile, identity, policy, destination / "main-domain")
    if bootstrap:
        require(
            isinstance(domain_eligibility, BootstrapPositiveOrigin)
            and isinstance(registration, dict)
            and domain_eligibility.source_bundle_sha256 == registration["source_bundle_sha256"],
            "source qualification requires authenticated typed native domain proof",
        )
    require(
        isinstance(domain_eligibility, BootstrapPositiveOrigin if bootstrap else DomainEligibility)
        and domain_eligibility.product_revision == profile["product_revision"]
        and domain_eligibility.product_tree == profile["product_tree"]
        and domain_eligibility.validation_pr == identity["validation_pr"]
        and domain_eligibility.validation_base_ref == identity["validation_base_ref"]
        and (
            bootstrap
            or not domain_eligibility.refusals
            or domain_eligibility.discovery_sha256 is not None
        )
        and (not domain_eligibility.observations or bool(domain_eligibility.refusals)),
        "source qualification requires authenticated typed native domain proof",
    )
    domain_receipts = list(domain_eligibility.refusals)
    evidence.stage = "source-identity-reader"
    observation = collect_source_ci_bindings(control, component, destination / "source-identities")
    require(
        observation["merge_commit"] == merge, "native PR merge changed during identity collection"
    )
    (destination / "native-source-identities.json").write_text(
        json.dumps(observation, indent=2) + "\n"
    )
    verify_required_job_bindings(before["head"], observation["workflows"])
    security.require_policy_observation(profile, identity, observation, before["head"])
    test_evidence = []
    for item in observation["workflows"]:
        run = item["run"]
        for job in item["jobs"]:
            evidence.stage = f"job-{job['id']}-steps"
            plan = policy["job_evidence"][run["path"]][job["name"]]
            _verify_steps(job, plan)
            if plan["kind"] != "pytest":
                continue
            evidence.stage = f"job-{job['id']}-pytest-artifact"
            expected = plan["pytest"]
            metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{expected['artifact_id']}")
            require(
                metadata.get("id") == expected["artifact_id"]
                and metadata.get("name") == expected["artifact_name"]
                and metadata.get("expired") is False
                and metadata.get("workflow_run", {}).get("id") == run["id"]
                and metadata.get("workflow_run", {}).get("head_sha")
                == profile["product_revision"],
                "native test artifact does not match its reviewed coordinate",
            )
            archive = destination / f"test-artifact-{expected['artifact_id']}.zip"
            digest = metadata.get("digest", "")
            require(
                re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
                "native test artifact hash missing",
            )
            download_artifact_bytes(
                expected["artifact_id"],
                archive,
                expected_size=metadata["size_in_bytes"],
                expected_sha256=digest[7:],
            )
            log_path = destination / "source-identities" / f"job-{job['id']}.log"
            if not log_path.exists():
                download_job_log(job["id"], log_path)
            result = verify_pytest_evidence(
                metadata,
                run,
                job,
                revision=profile["product_revision"],
                artifact_name=expected["artifact_name"],
                upload_step=expected["upload_step"],
                archive=archive,
                xml_member=expected["xml_member"],
                native_log=log_path.read_text(),
                test_step=expected["test_step"],
                approved_skips={
                    (row["classname"], row["name"]): row["reason_sha256"]
                    for row in expected["approved_skips"]
                },
                approved_reruns={
                    (row["classname"], row["name"]): row["count"]
                    for row in expected["approved_reruns"]
                },
                **(
                    {"native_log_contract": plan["native_log_contract"]}
                    if "native_log_contract" in plan
                    else {}
                ),
            )
            refreshed = api(f"repos/{REPOSITORY}/actions/artifacts/{expected['artifact_id']}")
            require(
                all(
                    refreshed.get(key) == metadata.get(key)
                    for key in (
                        "id",
                        "name",
                        "expired",
                        "size_in_bytes",
                        "digest",
                        "created_at",
                        "workflow_run",
                    )
                ),
                "native test artifact changed during qualification",
            )
            test_evidence.append(
                {
                    "workflow": run["path"],
                    "job_id": job["id"],
                    "artifact_id": metadata["id"],
                    "ZIP_sha256": digest[7:],
                    "result": result,
                }
            )
    evidence.stage = "checks-after"
    after = {role: collect_snapshot(revision) for role, revision in revisions.items()}
    (destination / "native-checks-after.json").write_text(json.dumps(after, indent=2) + "\n")
    for role in revisions:
        require(
            _stable_projection(before[role]) == _stable_projection(after[role]),
            "native checks changed during full source qualification",
        )
    verify_required_job_bindings(after["head"], observation["workflows"])
    policy_decisions = security.refresh_policy_observation(
        profile, identity, observation, after["head"], destination / "security-policy-after"
    )
    evidence.stage = "final-main-domain-native-eligibility"
    require(
        collector(
            profile,
            identity,
            policy,
            destination / "main-domain-after",
            **(
                {"previous": domain_eligibility}
                if not bootstrap
                and isinstance(domain_eligibility, DomainEligibility)
                and domain_eligibility._closing_capture is not None
                else {}
            ),
        )
        == domain_eligibility,
        "native main-domain contexts changed during source qualification",
    )
    evidence.stage = "all-app-policy"
    all_apps = assess_all_app_policy(
        after,
        observation["workflows"],
        policy,
        domain_receipts,
        domain_eligibility.observations,
        **({"recovered_image": recovered_image} if recovered_image is not None else {}),
    )
    all_apps["verified_original_security_policy_decisions"] = policy_decisions
    evidence.stage = "final-PR-and-source"
    endpoint = f"repos/{REPOSITORY}/pulls/{identity['validation_pr']}"
    pull = api(endpoint)
    commit = api(f"repos/{REPOSITORY}/git/commits/{observation['merge_commit']}")
    verify_pr_tree(
        pull,
        commit,
        profile,
        number=identity["validation_pr"],
        base_ref=identity["validation_base_ref"],
    )
    verify_source_delta(product, profile)
    complete_domain_discovery = not bootstrap and (
        not domain_receipts or domain_eligibility.discovery_sha256 is not None
    )
    if all_apps["all_original_governance_clear"]:
        status = "pass"
    else:
        status = "blocked-governance"
    result: dict[str, Any] = {
        "kind": "legacy_source_qualification/v1",
        "component": component,
        "control_revision": control_revision,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "merge_commit": observation["merge_commit"],
        "technical_source_ci": "pass",
        "trusted_security_policy_decisions": policy_decisions,
        "status": status,
        "source_ci_pass": status == "pass",
        "complete_domain_discovery": complete_domain_discovery,
        "domain_qualification_kind": BOOTSTRAP_KIND
        if bootstrap
        else "legacy_authenticated_domain_eligibility/v2",
        "domain_discovery_sha256": domain_eligibility.discovery_sha256,
        "domain_zero_execution_observations": [
            row.receipt
            for row in domain_eligibility.observations
            if isinstance(row, nonexecution.ZeroExecutionObservation)
        ],
        "domain_infrastructure_cancellation_observations": [
            row.receipt
            for row in domain_eligibility.observations
            if isinstance(row, nonexecution.InfrastructureCancellationObservation)
        ],
        "all_apps": all_apps,
        "identity_contract_sha256": _digest(identity),
        "qualification_policy_sha256": _digest(policy),
        "workflow_catalog_sha256": _digest(catalog),
        "technical_workflows": len(observation["workflows"]) + (recovered_image is not None),
        "test_artifacts": test_evidence,
        "native_snapshots_sha256": _digest(after),
        "exact_product_PG_pass": False,
        "image_admission": False,
        "production_admission": False,
    }
    if recovered_image is not None:
        result["recovered_native_image_completion"] = recovered_image.receipt
    if bootstrap:
        result.update(
            positive_origin_complete=True,
            global_history="NOT_ASSERTED_NOT_NA",
            bootstrap_positive_origin=registration,
            # Observed counters/quota change between revalidation jobs. Keep
            # them in native evidence, never in the signed stable input body.
            request_safety={
                key: value
                for key, value in evidence.bootstrap_usage().items()
                if key in {"kind", "metadata_limit", "direct_download_limit"}
            },
        )
    evidence.stage = result["status"]
    (destination / "source-qualification.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def qualify_source_ci(
    control: Path,
    product: Path,
    component: str,
    control_revision: str,
    destination: Path,
) -> dict[str, Any]:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with preserve_native_evidence(
        destination / "native-api", evidence_root=destination
    ) as evidence:
        return _qualify_source_ci(
            control,
            product,
            component,
            control_revision,
            destination,
            evidence,
            context_verifier=control_context,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    result = qualify_source_ci(
        args.control,
        args.product,
        args.component,
        args.control_revision,
        args.destination,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["source_ci_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
