"""Distinct native audit observations for one legacy governance domain.

Neither zero execution nor infrastructure cancellation authenticates product
source or a guard refusal. Only the independent refusal collector supplies it.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import threading
import zipfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from saas.scripts import legacy_domain_native as native
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pr_candidate import VALIDATION_REFS
from saas.scripts.oci_promotion import require

KIND = "legacy_original_main_domain_zero_execution/v1"
INFRASTRUCTURE_KIND = "legacy_original_main_domain_infrastructure_cancellation/v1"
UNATTRIBUTED_KIND = "legacy_original_main_domain_unattributed_zero_execution/v1"
UNATTRIBUTED_POLICY_KIND = "legacy_original_main_domain_unattributed_zero_execution_policy/v1"
_UBUNTU26_NOTICE = (
    '"The ubuntu-latest label will migrate to Ubuntu 26 beginning October 19, 2026. '
    "For more information, see https://github.com/actions/runner-images/issues/14748" + '"'
)
# Only this fully reviewed native archive is in scope for the infrastructure audit.
_INFRASTRUCTURE_LOG_SHA256 = "241c8b329b636f72a4a5e33bb980a294ef13f789b0411ddf6fea7bad83499024"
_INFRASTRUCTURE_LOG_MEMBERS = (
    ("0_evaluate.txt", 4028, "17cd77bcf832e5146453ea30df55cc75bcb83725e06703df6bc90199b85cfacc"),
    (
        "evaluate/system.txt",
        836,
        "7a81ae5eed43388008df830a961a8d32da5435ee184fcc6314c041fae22a4a2e",
    ),
)
_INFRASTRUCTURE_STEPS = (
    (1, "Set up job", "success"),
    (2, "Check out trusted gate", "cancelled"),
    (3, "Resolve current PR head", "skipped"),
    (4, "Evaluate exact PostgreSQL N-1 authority", "skipped"),
    (5, "Mark non-completed N-1 run pending", "skipped"),
    (6, "Post exact-head gate status", "skipped"),
    (12, "Post Check out trusted gate", "success"),
    (13, "Complete job", "success"),
)
_EMPTY_ZIP = b"PK\x05\x06" + b"\x00" * 18
_FIELDS = {
    "kind",
    "workflow_sha256",
    "validation_pr",
    "validation_base_ref",
    "product_revision",
    "product_tree",
    "event",
    "attachment_revision",
    "run_id",
    "attempt",
    "job_id",
    "check_id",
    "run_sha256",
    "job_sha256",
    "check_sha256",
    "annotations_sha256",
    "run_logs_sha256",
}


@dataclass(frozen=True)
class ZeroExecutionObservation:
    """Created by exact native verification, never decoded from an artifact."""

    receipt: dict[str, Any]


@dataclass(frozen=True)
class InfrastructureCancellationObservation:
    """Executed infrastructure audit; never zero execution or source proof."""

    receipt: dict[str, Any]


@dataclass(frozen=True)
class UnattributedZeroExecutionObservation:
    """Native absence audit; never a registered source or all-App observation."""

    receipt: dict[str, Any]


class DomainDiscovery(dict):
    """Serializable discovery facts with separately retained in-memory proofs."""

    def __init__(self, facts, observations=(), unattributed_observations=()):
        super().__init__(facts)
        self.observations = tuple(observations)
        self.unattributed_observations = tuple(unattributed_observations)


def validate_rules(rows, profile, identity):
    require(
        isinstance(rows, list) and len(rows) <= 128,
        "domain zero-execution registrations are malformed",
    )
    seen = set()
    for row in rows:
        require(
            isinstance(row, dict) and set(row) == _FIELDS,
            "domain zero-execution registration fields differ",
        )
        require(
            row["kind"] == KIND
            and row["workflow_sha256"] == native.MAIN_WORKFLOW_SHA256
            and row["event"] in native._EVENTS
            and all(identity[key] == profile[key] for key in ("product_revision", "product_tree"))
            and identity["validation_base_ref"] == VALIDATION_REFS.get(profile["component"])
            and identity["validation_base_ref"] != "main"
            and all(
                row[key] == identity[key]
                for key in (
                    "validation_pr",
                    "validation_base_ref",
                    "product_revision",
                    "product_tree",
                )
            ),
            "zero-execution audit is not the exact frozen legacy domain",
        )
        require(
            bool(
                all(
                    type(row[key]) is int and row[key] > 0
                    for key in ("run_id", "attempt", "job_id", "check_id")
                )
                and all(
                    isinstance(row[key], str) and re.fullmatch(r"[0-9a-f]{64}", row[key])
                    for key in (
                        "run_sha256",
                        "job_sha256",
                        "check_sha256",
                        "annotations_sha256",
                        "run_logs_sha256",
                    )
                )
                and isinstance(row["attachment_revision"], str)
                and re.fullmatch(r"[0-9a-f]{40}", row["attachment_revision"])
            ),
            "zero-execution native coordinates or hashes differ",
        )
        key = row["run_id"], row["attempt"], row["job_id"], row["check_id"]
        require(key not in seen, "zero-execution native registration is duplicated")
        seen.add(key)


def _verify_native_zero_execution(identity, rule, run, job, check, annotations, logs):
    """The unchanged intrinsic native checks shared by both distinct audit contracts."""
    require(
        run.get("id") == rule["run_id"]
        and run.get("run_attempt") == rule["attempt"]
        and run.get("event") == rule["event"]
        and run.get("path") == native.MAIN_WORKFLOW
        and run.get("name") == "SaaS N-1 merge gate"
        and run.get("repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_sha") == rule["attachment_revision"]
        and native._pr_numbers(run.get("pull_requests")) in ([], [identity["validation_pr"]])
        and run.get("status") == job.get("status") == check.get("status") == "completed"
        and run.get("conclusion") == job.get("conclusion") == check.get("conclusion")
        and run.get("conclusion") in {"cancelled", "skipped"},
        "zero-execution run identity, PR association or terminal outcome differs",
    )
    require(
        job.get("id") == rule["job_id"]
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == rule["attempt"]
        and job.get("head_sha") == check.get("head_sha") == run["head_sha"]
        and job.get("name") == check.get("name") == "evaluate"
        and job.get("labels") == ["ubuntu-latest"]
        and job.get("check_run_url") == f"{native._REPO_URL}/check-runs/{rule['check_id']}"
        and check.get("id") == rule["check_id"]
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == run.get("check_suite_id")
        and check.get("details_url")
        == (f"https://github.com/Dream1216/omnigent/actions/runs/{run['id']}/job/{job['id']}")
        and "steps" in job
        and job["steps"] == []
        and all(
            key in job
            for key in ("runner_id", "runner_name", "runner_group_id", "runner_group_name")
        )
        and all(
            job[key] is None or type(job[key]) is int for key in ("runner_id", "runner_group_id")
        )
        and (
            job.get("runner_id"),
            job.get("runner_name"),
            job.get("runner_group_id"),
            job.get("runner_group_name"),
        )
        in {(0, "", 0, ""), (None, None, None, None)},
        "zero-execution job/check/provider/runner or empty steps differ",
    )
    output = check.get("output", {})
    require(
        isinstance(annotations, list)
        and output.get("annotations_count") == len(annotations)
        and output.get("annotations_url")
        == (f"{native._REPO_URL}/check-runs/{check['id']}/annotations")
        and all(output.get(key) is None for key in ("title", "summary", "text")),
        "zero-execution complete native annotation set differs",
    )
    if run["conclusion"] == "cancelled":
        _cancelled_annotations(run, check, annotations, infrastructure=False)
    else:
        require(
            run["event"] == "workflow_run" and annotations == [],
            "skipped domain audit has another event or native annotations",
        )
    require(logs == _EMPTY_ZIP, "zero-execution original run log ZIP is not exactly empty")


def verify_zero_execution(profile, identity, rule, run, job, check, annotations, logs):
    """Authenticate execution absence without assigning an original event source."""
    validate_rules([rule], profile, identity)
    _verify_native_zero_execution(identity, rule, run, job, check, annotations, logs)
    require(
        native.native_digest(run) == rule["run_sha256"]
        and native.native_digest(job) == rule["job_sha256"]
        and native.native_digest(check) == rule["check_sha256"]
        and native.native_digest(annotations) == rule["annotations_sha256"]
        and hashlib.sha256(logs).hexdigest() == rule["run_logs_sha256"],
        "zero-execution native tuple differs from exact reviewed registration",
    )
    return ZeroExecutionObservation(
        {
            "kind": KIND,
            "workflow": native.MAIN_WORKFLOW,
            "workflow_sha256": rule["workflow_sha256"],
            **{
                key: rule[key]
                for key in (
                    "validation_pr",
                    "validation_base_ref",
                    "product_revision",
                    "product_tree",
                    "run_id",
                    "attempt",
                    "job_id",
                    "check_id",
                    "attachment_revision",
                    "run_sha256",
                    "job_sha256",
                    "check_sha256",
                    "annotations_sha256",
                    "run_logs_sha256",
                )
            },
            "check_revision": check["head_sha"],
            "check_suite_id": run["check_suite_id"],
            "app_id": 15368,
            "source_classification": "UNKNOWN",
            "original_event_source_revision": None,
            "trusted_checkout_revision": None,
            "execution": "native-proven-zero",
            "original_conclusion": run["conclusion"],
            "source_proof": False,
            "guard_refusal": False,
            "technical_gate_waiver": False,
            "production_admission": False,
            "registration_sha256": native.native_digest(rule),
        }
    )


def download_run_logs(run_id: int, attempt: int, path: Path):
    """Read only a fixed native endpoint, with the original zero-log bound."""
    _download_run_logs(run_id, attempt, path, 1024)


def _download_run_logs(run_id: int, attempt: int, path: Path, bound: int):
    require(
        type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
        "invalid zero-execution native log coordinates",
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        process = subprocess.Popen(
            ["gh", "api", f"{native._ROOT}/actions/runs/{run_id}/attempts/{attempt}/logs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        timer = threading.Timer(45, process.kill)
        timer.start()
        try:
            assert process.stdout is not None
            total = 0
            while chunk := process.stdout.read(1024):
                total += len(chunk)
                require(total <= bound, "native domain log ZIP exceeds its strict bound")
                output.write(chunk)
            require(process.wait() == 0, "original zero-execution run logs are unavailable")
        finally:
            timer.cancel()
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()


def annotations_for(check_id):
    rows = []
    for page in range(1, 3):
        payload = api(f"{native._ROOT}/check-runs/{check_id}/annotations?per_page=100&page={page}")
        require(
            isinstance(payload, list)
            and len(payload) <= 100
            and all(isinstance(row, dict) for row in payload),
            "zero-execution native annotation page differs",
        )
        rows.extend(payload)
        require(len(rows) <= 128, "zero-execution native annotation bound exceeded")
        if len(payload) < 100:
            return rows
    raise ValueError("zero-execution native annotation pagination is incomplete")


def collect_zero_execution(profile, identity, rule, run, jobs, destination):
    require(len(jobs) == 1, "zero-execution native job set differs")
    job = jobs[0]
    check = api(f"{native._ROOT}/check-runs/{rule['check_id']}")
    annotations = annotations_for(rule["check_id"])
    path = destination / f"zero-run-{run['id']}-attempt-{run['run_attempt']}.zip"
    download_run_logs(run["id"], run["run_attempt"], path)
    body = native._native_file(native.MAIN_WORKFLOW, run["head_sha"])
    require(
        hashlib.sha256(body).hexdigest() == native.MAIN_WORKFLOW_SHA256,
        "zero-execution workflow bytes differ from the reviewed original",
    )
    return verify_zero_execution(
        profile, identity, rule, run, job, check, annotations, path.read_bytes()
    )


def _annotation(run, level, message, line=1):
    return {
        "path": ".github",
        "blob_href": f"https://github.com/Dream1216/omnigent/blob/{run['head_sha']}/.github",
        "start_line": line,
        "end_line": line,
        "start_column": None,
        "end_column": None,
        "annotation_level": level,
        "title": "",
        "message": message,
        "raw_details": "",
    }


def _cancelled_annotations(run, check, annotations, *, infrastructure):
    """Keep the complete ordered failure set; permit only the exact runner notice."""
    require(
        bool(
            isinstance(annotations, list)
            and annotations
            and all(isinstance(row, dict) for row in annotations)
        ),
        "cancelled domain annotation set is empty or malformed",
    )
    message = annotations[0].get("message", "")
    require(
        re.fullmatch(
            r"Canceling since a higher priority waiting request for "
            r"saas-n1-merge-gate-[0-9a-f]{40} exists",
            message,
        )
        is not None,
        "cancelled domain audit lacks the original concurrency annotation",
    )
    expected = [_annotation(run, "failure", message)]
    if infrastructure:
        require(
            message == "Canceling since a higher priority waiting request for "
            f"saas-n1-merge-gate-{run['head_sha']} exists",
            "infrastructure cancellation concurrency key differs",
        )
        expected.append(_annotation(run, "failure", "The operation was canceled.", 29))
    notice = _annotation(run, "notice", _UBUNTU26_NOTICE)
    require(
        annotations == [*expected, notice]
        if infrastructure
        else annotations in (expected, [*expected, notice]),
        "cancelled domain annotations contain an unknown, repeated or reordered entry",
    )
    output = check.get("output", {})
    require(
        output.get("annotations_count") == len(annotations)
        and output.get("annotations_url")
        == f"{native._REPO_URL}/check-runs/{check['id']}/annotations"
        and all(output.get(key) is None for key in ("title", "summary", "text")),
        "cancelled domain complete native annotation set differs",
    )


def validate_infrastructure_rules(rows, profile, identity):
    require(
        isinstance(rows, list) and len(rows) <= 128, "infrastructure registrations are malformed"
    )
    for row in rows:
        require(
            isinstance(row, dict)
            and row.get("kind") == INFRASTRUCTURE_KIND
            and row.get("event") == "pull_request_target"
            and row.get("run_logs_sha256") == _INFRASTRUCTURE_LOG_SHA256,
            "infrastructure registration is not the reviewed cancellation archive and event",
        )
    validate_rules([{**row, "kind": KIND} for row in rows], profile, identity)


def _infrastructure_logs(logs):
    require(
        len(logs) == 2054 and hashlib.sha256(logs).hexdigest() == _INFRASTRUCTURE_LOG_SHA256,
        "infrastructure archive differs from the fully reviewed native command log",
    )
    with zipfile.ZipFile(io.BytesIO(logs)) as archive:
        entries = archive.infolist()
        require(
            tuple((entry.filename, entry.file_size) for entry in entries)
            == tuple((name, size) for name, size, _ in _INFRASTRUCTURE_LOG_MEMBERS),
            "infrastructure archive has missing, extra or duplicate members",
        )
        for entry, (_, _, digest) in zip(entries, _INFRASTRUCTURE_LOG_MEMBERS, strict=True):
            require(
                entry.compress_type == zipfile.ZIP_DEFLATED
                and entry.external_attr == 0
                and hashlib.sha256(archive.read(entry)).hexdigest() == digest,
                "infrastructure archive contains unreviewed native command evidence",
            )


def verify_infrastructure_cancellation(
    profile, identity, rule, run, job, check, annotations, logs
):
    """Verify the exact setup/partial-checkout cancellation, without source attribution."""
    validate_infrastructure_rules([rule], profile, identity)
    require(
        run.get("id") == rule["run_id"]
        and run.get("run_attempt") == rule["attempt"]
        and run.get("event") == rule["event"] == "pull_request_target"
        and run.get("path") == native.MAIN_WORKFLOW
        and run.get("name") == "SaaS N-1 merge gate"
        and run.get("repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_sha") == rule["attachment_revision"]
        and native._pr_numbers(run.get("pull_requests")) in ([], [identity["validation_pr"]])
        and run.get("status") == job.get("status") == check.get("status") == "completed"
        and run.get("conclusion")
        == job.get("conclusion")
        == check.get("conclusion")
        == "cancelled",
        "infrastructure cancellation native run, PR association or outcome differs",
    )
    require(
        job.get("id") == rule["job_id"]
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == rule["attempt"]
        and job.get("head_sha") == check.get("head_sha") == run["head_sha"]
        and job.get("name") == check.get("name") == "evaluate"
        and job.get("labels") == ["ubuntu-latest"]
        and job.get("check_run_url") == f"{native._REPO_URL}/check-runs/{rule['check_id']}"
        and check.get("id") == rule["check_id"]
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == run.get("check_suite_id")
        and check.get("details_url")
        == f"https://github.com/Dream1216/omnigent/actions/runs/{run['id']}/job/{job['id']}"
        and (
            job.get("runner_id"),
            job.get("runner_name"),
            job.get("runner_group_id"),
            job.get("runner_group_name"),
        )
        == (1000081455, "GitHub Actions 1000081455", 0, "GitHub Actions"),
        "infrastructure cancellation native job/check/provider/runner differs",
    )
    steps = job.get("steps")
    require(
        isinstance(steps, list)
        and all(isinstance(step, dict) for step in steps)
        and tuple((step.get("number"), step.get("name"), step.get("conclusion")) for step in steps)
        == _INFRASTRUCTURE_STEPS
        and all(step.get("status") == "completed" for step in steps),
        "infrastructure cancellation executed another native step or changed step order",
    )
    prior = native._instant(job.get("started_at"))
    end = native._instant(job.get("completed_at"))
    for step in steps:
        started, completed = (
            native._instant(step.get("started_at")),
            native._instant(step.get("completed_at")),
        )
        require(prior <= started <= completed <= end, "infrastructure step time/order differs")
        prior = completed
    _cancelled_annotations(run, check, annotations, infrastructure=True)
    _infrastructure_logs(logs)
    require(
        native.native_digest(run) == rule["run_sha256"]
        and native.native_digest(job) == rule["job_sha256"]
        and native.native_digest(check) == rule["check_sha256"]
        and native.native_digest(annotations) == rule["annotations_sha256"]
        and hashlib.sha256(logs).hexdigest() == rule["run_logs_sha256"],
        "infrastructure cancellation native tuple differs from reviewed registration",
    )
    return InfrastructureCancellationObservation(
        {
            **rule,
            "workflow": native.MAIN_WORKFLOW,
            "check_revision": check["head_sha"],
            "check_suite_id": run["check_suite_id"],
            "app_id": 15368,
            "source_classification": "UNKNOWN",
            "original_event_source_revision": None,
            "trusted_checkout_revision": None,
            "checkout_classification": "UNKNOWN",
            "execution": "native-infrastructure-executed-cancelled",
            "git_executed": True,
            "run_snapshot_sha256": native.native_digest(
                {key: value for key, value in run.items() if key not in {"jobs_url", "logs_url"}}
            ),
            "original_conclusion": "cancelled",
            "source_proof": False,
            "guard_refusal": False,
            "technical_gate_waiver": False,
            "production_admission": False,
            "registration_sha256": native.native_digest(rule),
        }
    )


def download_infrastructure_run_logs(run_id, attempt, path):
    _download_run_logs(run_id, attempt, path, 4096)


def collect_infrastructure_cancellation(profile, identity, rule, run, jobs, destination):
    require(len(jobs) == 1, "infrastructure cancellation native job set differs")
    check = api(f"{native._ROOT}/check-runs/{rule['check_id']}")
    annotations = annotations_for(rule["check_id"])
    path = destination / f"infrastructure-run-{run['id']}-attempt-{run['run_attempt']}.zip"
    download_infrastructure_run_logs(run["id"], run["run_attempt"], path)
    require(
        hashlib.sha256(native._native_file(native.MAIN_WORKFLOW, run["head_sha"])).hexdigest()
        == native.MAIN_WORKFLOW_SHA256,
        "infrastructure workflow bytes differ from the reviewed original",
    )
    return verify_infrastructure_cancellation(
        profile, identity, rule, run, jobs[0], check, annotations, path.read_bytes()
    )


def collect_observation(profile, identity, rule, run, jobs, destination):
    if rule["kind"] == KIND:
        return collect_zero_execution(profile, identity, rule, run, jobs, destination)
    if rule["kind"] == REFUSAL_CANCELLATION_KIND:
        return collect_refusal_cancellation(profile, identity, rule, run, jobs, destination)
    require(rule["kind"] == INFRASTRUCTURE_KIND, "unknown domain observation kind")
    return collect_infrastructure_cancellation(profile, identity, rule, run, jobs, destination)


def matching_refusal(proof, refusal):
    return (
        refusal.get("kind") == "legacy_main_domain_not_applicable/v2"
        and all(
            refusal.get(key) == proof[key]
            for key in ("validation_pr", "validation_base_ref", "product_tree")
        )
        and refusal.get("source_head")
        == refusal.get("original_event_source_revision")
        == proof["product_revision"]
        and refusal.get("original_conclusion") == "failure"
        and refusal.get("technical_gate_waiver") is refusal.get("production_admission") is False
    )


def typed_observation(proof):
    return (
        (
            isinstance(proof, RefusalCancellationObservation)
            and proof.receipt.get("kind") == REFUSAL_CANCELLATION_KIND
            and proof.receipt.get("execution") == "native-refusal-then-cancelled"
        )
        or (
            isinstance(proof, ZeroExecutionObservation)
            and proof.receipt.get("kind") == KIND
            and proof.receipt.get("execution") == "native-proven-zero"
        )
        or (
            isinstance(proof, InfrastructureCancellationObservation)
            and proof.receipt.get("kind") == INFRASTRUCTURE_KIND
            and proof.receipt.get("execution") == "native-infrastructure-executed-cancelled"
        )
    )


def validate_unattributed_policy(policy, profile, identity):
    fields = {
        "kind",
        "workflow_sha256",
        "validation_pr",
        "validation_base_ref",
        "product_revision",
        "product_tree",
    }
    require(
        isinstance(policy, dict)
        and set(policy) == fields
        and policy["kind"] == UNATTRIBUTED_POLICY_KIND
        and policy["workflow_sha256"] == native.MAIN_WORKFLOW_SHA256
        and identity["validation_base_ref"] == VALIDATION_REFS.get(profile["component"])
        and identity["validation_base_ref"] != "main"
        and all(identity[key] == profile[key] for key in ("product_revision", "product_tree"))
        and all(
            policy[key] == identity[key]
            for key in ("validation_pr", "validation_base_ref", "product_revision", "product_tree")
        ),
        "unattributed zero-execution policy is not the exact frozen legacy domain",
    )


def verify_unattributed_zero_execution(
    profile, identity, policy, run, job, check, annotations, logs
):
    """Verify complete native absence without manufacturing a reviewed registration."""
    validate_unattributed_policy(policy, profile, identity)
    require(
        native._pr_numbers(run.get("pull_requests")) == []
        and run.get("event") in native._EVENTS
        and all(
            type(value) is int and value > 0
            for value in (run.get("id"), run.get("run_attempt"), job.get("id"), check.get("id"))
        )
        and run["run_attempt"] <= 10
        and isinstance(run.get("head_sha"), str)
        and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]) is not None,
        "unattributed audit has a PR association or malformed native coordinates",
    )
    coordinates = {
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "check_id": check["id"],
        "event": run["event"],
        "attachment_revision": run["head_sha"],
    }
    _verify_native_zero_execution(identity, coordinates, run, job, check, annotations, logs)
    return UnattributedZeroExecutionObservation(
        {
            "kind": UNATTRIBUTED_KIND,
            "workflow": native.MAIN_WORKFLOW,
            "workflow_sha256": policy["workflow_sha256"],
            **{
                key: policy[key]
                for key in (
                    "validation_pr",
                    "validation_base_ref",
                    "product_revision",
                    "product_tree",
                )
            },
            **coordinates,
            "run_sha256": native.native_digest(run),
            "job_sha256": native.native_digest(job),
            "check_sha256": native.native_digest(check),
            "annotations_sha256": native.native_digest(annotations),
            "run_logs_sha256": hashlib.sha256(logs).hexdigest(),
            "check_suite_id": run["check_suite_id"],
            "app_id": 15368,
            "policy_sha256": native.native_digest(policy),
            "source_classification": "UNKNOWN",
            "original_event_source_revision": None,
            "trusted_checkout_revision": None,
            "execution": "native-proven-zero",
            "original_conclusion": run["conclusion"],
            "source_proof": False,
            "guard_refusal": False,
            "technical_gate_waiver": False,
            "production_admission": False,
        }
    )


def collect_unattributed_zero_execution(profile, identity, policy, run, jobs, destination):
    require(len(jobs) == 1, "unattributed zero-execution native job set differs")
    job = jobs[0]
    match = re.fullmatch(
        re.escape(native._REPO_URL) + r"/check-runs/([1-9][0-9]*)", job.get("check_run_url", "")
    )
    require(match is not None, "unattributed audit check URL is not native")
    if match is None:
        raise ValueError("unattributed audit check URL is not native")
    check_id = int(match[1])
    check = api(f"{native._ROOT}/check-runs/{check_id}")
    annotations = annotations_for(check_id)
    path = destination / f"unattributed-run-{run['id']}-attempt-{run['run_attempt']}.zip"
    download_run_logs(run["id"], run["run_attempt"], path)
    require(
        hashlib.sha256(native._native_file(native.MAIN_WORKFLOW, run["head_sha"])).hexdigest()
        == native.MAIN_WORKFLOW_SHA256,
        "unattributed zero-execution workflow bytes differ from the reviewed original",
    )
    return verify_unattributed_zero_execution(
        profile, identity, policy, run, job, check, annotations, path.read_bytes()
    )


NO_JOB_KIND = "legacy_original_main_domain_unattributed_no_job_execution/v1"
BOOTSTRAP_KIND = "legacy_original_main_domain_unattributed_bootstrap_cancellation/v1"
BOOTSTRAP_POLICY_KIND = "legacy_original_main_domain_unattributed_bootstrap_cancellation_policy/v1"
_BOOTSTRAP_SCHEMAS = {
    "checkout-before-format": {
        "shape": "checkout",
        "operation_annotation_line": 31,
        "member_sha256": {
            "0_evaluate.txt": "36fc88f312c62bc740acf0fad3e8e5a366abc9bb537f66284946cada6b149da0",
            "evaluate/system.txt": (
                "32abbc9088d65f448a27bf19524d83d1bfa982f0098f6b6d278928541d61e916"
            ),
        },
    },
    "setup-central": {
        "shape": "setup",
        "operation_annotation_line": 35,
        "member_sha256": {
            "0_evaluate.txt": "622b96ef522e3a84e761f71f35b813d239dac9d2e3838a193fc552e36b091426",
            "evaluate/system.txt": (
                "018e7affa936121673ff71fd483cb6ada11780e4e21a8b4eb22237c28cbd1f00"
            ),
        },
    },
    "setup-west": {
        "shape": "setup",
        "operation_annotation_line": 35,
        "member_sha256": {
            "0_evaluate.txt": "3e28e3619af553997c6108880d5bb7e74b8f2a6d52b2ba7fe948827a009625b0",
            "evaluate/system.txt": (
                "1531428742bc084bd5625a1575d1f4289003d68f899a4ddb5c25621cd5404199"
            ),
        },
    },
}


@dataclass(frozen=True)
class UnattributedNoJobExecutionObservation:
    """Native complete empty job/check sets; never a positive-job audit."""

    receipt: dict[str, Any]


@dataclass(frozen=True)
class UnattributedBootstrapCancellationObservation:
    """Assigned runner/bootstrap cancellation, never zero execution or source proof."""

    receipt: dict[str, Any]


def validate_bootstrap_policy(policy, profile, identity):
    require(
        isinstance(policy, dict) and policy.get("kind") == BOOTSTRAP_POLICY_KIND,
        "bootstrap cancellation policy has no exact reviewed kind",
    )
    validate_unattributed_policy({**policy, "kind": UNATTRIBUTED_POLICY_KIND}, profile, identity)


def _unattributed_run(run):
    require(
        type(run.get("id")) is int
        and run["id"] > 0
        and type(run.get("run_attempt")) is int
        and 0 < run["run_attempt"] <= 10
        and type(run.get("workflow_id")) is int
        and run["workflow_id"] > 0
        and type(run.get("check_suite_id")) is int
        and run["check_suite_id"] > 0
        and run.get("path") == native.MAIN_WORKFLOW
        and run.get("name") == "SaaS N-1 merge gate"
        and run.get("event") in native._EVENTS
        and run.get("repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_repository", {}).get("full_name") == "Dream1216/omnigent"
        and isinstance(run.get("head_sha"), str)
        and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]) is not None
        and native._pr_numbers(run.get("pull_requests")) == []
        and run.get("status") == "completed"
        and run.get("conclusion") == "cancelled",
        "unattributed native cancellation run identity or terminal state differs",
    )


def cancelled_job_coordinates(run, job, check):
    """Strict native assigned-job identity; it gives no source or eligibility credit."""
    _unattributed_run(run)
    require(
        type(job.get("id")) is int
        and job["id"] > 0
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("head_sha") == check.get("head_sha") == run["head_sha"]
        and job.get("name") == check.get("name") == "evaluate"
        and job.get("status") == check.get("status") == "completed"
        and job.get("conclusion") == check.get("conclusion") == "cancelled"
        and type(job.get("runner_id")) is int
        and job["runner_id"] > 0
        and job.get("runner_name") == f"GitHub Actions {job['runner_id']}"
        and job.get("runner_group_id") == 0
        and job.get("runner_group_name") == "GitHub Actions"
        and job.get("labels") == ["ubuntu-latest"]
        and type(check.get("id")) is int
        and check["id"] > 0
        and job.get("check_run_url") == f"{native._REPO_URL}/check-runs/{check['id']}"
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == run["check_suite_id"]
        and check.get("details_url")
        == f"https://github.com/Dream1216/omnigent/actions/runs/{run['id']}/job/{job['id']}",
        "unattributed cancelled job/check/provider/runner identity differs",
    )
    return {
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "check_id": check["id"],
    }


def _audit_receipt(kind, policy, run):
    return {
        "kind": kind,
        "workflow": native.MAIN_WORKFLOW,
        **{
            key: policy[key]
            for key in (
                "workflow_sha256",
                "validation_pr",
                "validation_base_ref",
                "product_revision",
                "product_tree",
            )
        },
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "event": run["event"],
        "attachment_revision": run["head_sha"],
        "run_sha256": native.native_digest(run),
        "check_suite_id": run["check_suite_id"],
        "policy_sha256": native.native_digest(policy),
        "source_classification": "UNKNOWN",
        "original_event_source_revision": None,
        "trusted_checkout_revision": None,
        "original_conclusion": run["conclusion"],
        "source_proof": False,
        "guard_refusal": False,
        "technical_gate_waiver": False,
        "production_admission": False,
    }


def verify_no_job_execution(profile, identity, policy, run, jobs, suite, checks, logs):
    validate_unattributed_policy(policy, profile, identity)
    _unattributed_run(run)
    require(
        isinstance(jobs, dict)
        and type(jobs.get("total_count")) is int
        and jobs["total_count"] == 0
        and jobs.get("jobs") == []
        and isinstance(checks, dict)
        and type(checks.get("total_count")) is int
        and checks["total_count"] == 0
        and checks.get("check_runs") == [],
        "no-job audit lacks complete native zero job/check counts and lists",
    )
    require(
        suite.get("id") == run["check_suite_id"]
        and suite.get("url") == f"{native._REPO_URL}/check-suites/{run['check_suite_id']}"
        and suite.get("check_runs_url") == suite["url"] + "/check-runs"
        and suite.get("repository", {}).get("full_name") == "Dream1216/omnigent"
        and suite.get("app", {}).get("id") == 15368
        and suite.get("head_sha") == run["head_sha"]
        and suite.get("status") == "completed"
        and suite.get("conclusion") == "cancelled"
        and native._pr_numbers(suite.get("pull_requests")) == []
        and type(suite.get("latest_check_runs_count")) is int
        and suite["latest_check_runs_count"] == 0,
        "no-job audit native suite/source/provider or complete check count differs",
    )
    require(logs == _EMPTY_ZIP, "no-job audit original run ZIP is not exactly empty")
    return UnattributedNoJobExecutionObservation(
        {
            **_audit_receipt(NO_JOB_KIND, policy, run),
            "execution": "native-no-jobs-no-checks",
            "job_id": None,
            "check_id": None,
            "jobs_response_sha256": native.native_digest(jobs),
            "suite_sha256": native.native_digest(suite),
            "checks_response_sha256": native.native_digest(checks),
            "run_logs_sha256": hashlib.sha256(logs).hexdigest(),
        }
    )


def _bootstrap_log_schema(run, job, logs, shape):
    require(0 < len(logs) <= 65536, "bootstrap archive exceeds its bounded schema")
    require(
        logs.startswith(b"PK\x03\x04") and logs[-22:-18] == b"PK\x05\x06",
        "bootstrap archive has a prefix, trailer or non-native ZIP layout",
    )
    digests = {}
    with zipfile.ZipFile(io.BytesIO(logs)) as archive:
        entries = archive.infolist()
        require(
            tuple(entry.filename for entry in entries) == ("0_evaluate.txt", "evaluate/system.txt")
            and archive.comment == b""
            and entries[0].header_offset == 0,
            "bootstrap archive has missing, extra, duplicate or commented members",
        )
        for entry in entries:
            require(
                entry.compress_type == zipfile.ZIP_DEFLATED
                and entry.external_attr == 0
                and entry.extra == entry.comment == b""
                and entry.file_size <= 16384,
                "bootstrap member compression, metadata or size differs",
            )
            text = archive.read(entry).decode("utf-8")
            require(
                "\r" not in text and text.endswith("\n") == (entry.filename == "0_evaluate.txt"),
                "bootstrap member encoding differs",
            )
            normalized = []
            for index, line in enumerate(text.removesuffix("\n").split("\n")):
                if index == 0:
                    line = line.removeprefix("\ufeff")
                match = re.fullmatch(
                    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,7}Z) (.*)",
                    line,
                )
                require(match is not None, "bootstrap member has unknown native timestamp framing")
                if match is None:
                    raise ValueError("bootstrap member has unknown native timestamp framing")
                observed, body = native._instant(match[1]), match[2]
                end = native._instant(job["completed_at"]) + timedelta(seconds=1)
                lower = (
                    native._instant(job["started_at"])
                    if entry.filename == "0_evaluate.txt"
                    else min(
                        native._instant(run["created_at"]), native._instant(run["run_started_at"])
                    )
                )
                require(
                    lower <= observed < end,
                    "bootstrap log crosses its authenticated native time window",
                )
                uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                if body.startswith("Worker ID: "):
                    require(
                        re.fullmatch(r"Worker ID: \{" + uuid + r"\}", body) is not None,
                        "bootstrap worker metadata has an unknown shape",
                    )
                    body = "Worker ID: {WORKER_UUID}"
                if body.startswith("Temporarily overriding HOME="):
                    pattern = (
                        r"Temporarily overriding HOME='/home/runner/work/_temp/"
                        + uuid
                        + r"' before making global git config changes"
                    )
                    require(
                        re.fullmatch(pattern, body) is not None,
                        "bootstrap temporary directory has an unknown shape",
                    )
                    body = (
                        "Temporarily overriding HOME='/home/runner/work/_temp/TEMP_UUID' "
                        "before making global git config changes"
                    )
                prefix = "Job is about to start running on the hosted runner: "
                if body.startswith(prefix):
                    require(
                        body == prefix + job["runner_name"],
                        "bootstrap system log names another runner",
                    )
                    body = prefix + "RUNNER_NAME"
                normalized.append(body)
            digests[entry.filename] = hashlib.sha256(
                ("\n".join(normalized) + "\n").encode()
            ).hexdigest()
    matches = [
        name
        for name, schema in _BOOTSTRAP_SCHEMAS.items()
        if schema["shape"] == shape and schema["member_sha256"] == digests
    ]
    require(
        len(matches) == 1, "bootstrap archive contains an unreviewed command, output or log schema"
    )
    return matches[0]


def verify_bootstrap_cancellation(profile, identity, policy, run, job, check, annotations, logs):
    validate_bootstrap_policy(policy, profile, identity)
    coordinates = cancelled_job_coordinates(run, job, check)
    require(
        isinstance(job.get("steps"), list)
        and all(s.get("status") == "completed" for s in job["steps"]),
        "bootstrap cancellation has incomplete native steps",
    )
    steps = tuple((s.get("number"), s.get("name"), s.get("conclusion")) for s in job["steps"])
    require(
        steps in (((1, "Set up job", "cancelled"),), _INFRASTRUCTURE_STEPS),
        "bootstrap cancellation executed an unreviewed governance or business step",
    )
    shape = "setup" if len(steps) == 1 else "checkout"
    schema_name = _bootstrap_log_schema(run, job, logs, shape)
    require(
        isinstance(annotations, list) and len(annotations) == 3,
        "bootstrap cancellation complete annotation set differs",
    )
    message = annotations[0].get("message", "")
    require(
        re.fullmatch(
            r"Canceling since a higher priority waiting request for "
            r"saas-n1-merge-gate-[0-9a-f]{40} exists",
            message,
        )
        is not None,
        "bootstrap cancellation lacks its exact native concurrency annotation",
    )
    expected = [
        _annotation(run, "failure", message),
        _annotation(
            run,
            "failure",
            "The operation was canceled.",
            _BOOTSTRAP_SCHEMAS[schema_name]["operation_annotation_line"],
        ),
        _annotation(run, "notice", _UBUNTU26_NOTICE),
    ]
    output = check.get("output", {})
    require(
        annotations == expected
        and output.get("annotations_count") == 3
        and output.get("annotations_url")
        == f"{native._REPO_URL}/check-runs/{check['id']}/annotations"
        and all(output.get(key) is None for key in ("title", "summary", "text")),
        "bootstrap cancellation has unknown, missing or reordered annotations",
    )
    return UnattributedBootstrapCancellationObservation(
        {
            **_audit_receipt(BOOTSTRAP_KIND, policy, run),
            **coordinates,
            "execution": "native-bootstrap-only-cancelled",
            "bootstrap_schema": schema_name,
            "git_executed": shape == "checkout",
            "job_sha256": native.native_digest(job),
            "check_sha256": native.native_digest(check),
            "annotations_sha256": native.native_digest(annotations),
            "run_logs_sha256": hashlib.sha256(logs).hexdigest(),
        }
    )


def collect_unattributed_audit(
    profile, identity, zero_policy, bootstrap_policy, run, jobs, destination
):
    require(
        hashlib.sha256(native._native_file(native.MAIN_WORKFLOW, run["head_sha"])).hexdigest()
        == native.MAIN_WORKFLOW_SHA256,
        "unattributed native audit workflow bytes differ",
    )
    if not jobs:
        require(zero_policy is not None, "no-job native audit policy is disabled")
        prefix = f"{native._ROOT}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        raw_jobs = api(prefix + "/jobs?per_page=100&page=1")
        suite = api(f"{native._ROOT}/check-suites/{run['check_suite_id']}")
        checks = api(
            f"{native._ROOT}/check-suites/{run['check_suite_id']}/check-runs?filter=all&per_page=100&page=1"
        )
        path = destination / f"no-job-run-{run['id']}-attempt-{run['run_attempt']}.zip"
        download_run_logs(run["id"], run["run_attempt"], path)
        return verify_no_job_execution(
            profile, identity, zero_policy, run, raw_jobs, suite, checks, path.read_bytes()
        )
    require(len(jobs) == 1, "unattributed native audit job set differs")
    if jobs[0].get("steps") == []:
        require(zero_policy is not None, "unassigned-job native audit policy is disabled")
        return collect_unattributed_zero_execution(
            profile, identity, zero_policy, run, jobs, destination
        )
    require(bootstrap_policy is not None, "assigned bootstrap native audit policy is disabled")
    job = jobs[0]
    match = re.fullmatch(
        re.escape(native._REPO_URL) + r"/check-runs/([1-9][0-9]*)", job.get("check_run_url", "")
    )
    require(match is not None, "bootstrap native check URL differs")
    if match is None:
        raise ValueError("bootstrap native check URL differs")
    check_id = int(match[1])
    check = api(f"{native._ROOT}/check-runs/{check_id}")
    annotations = annotations_for(check_id)
    path = destination / f"bootstrap-run-{run['id']}-attempt-{run['run_attempt']}.zip"
    download_infrastructure_run_logs(run["id"], run["run_attempt"], path)
    return verify_bootstrap_cancellation(
        profile, identity, bootstrap_policy, run, job, check, annotations, path.read_bytes()
    )


UnattributedObservation = (
    UnattributedZeroExecutionObservation
    | UnattributedNoJobExecutionObservation
    | UnattributedBootstrapCancellationObservation
)


def unattributed_field(proof):
    for cls, field in (
        (UnattributedZeroExecutionObservation, "unattributed_zero_execution_observations"),
        (UnattributedNoJobExecutionObservation, "unattributed_no_job_observations"),
        (UnattributedBootstrapCancellationObservation, "unattributed_bootstrap_observations"),
    ):
        if isinstance(proof, cls):
            return field
    raise ValueError("unattributed audit has no native typed observation")


REFUSAL_CANCELLATION_KIND = "legacy_original_main_domain_refusal_then_cancellation/v1"
_REFUSAL_CANCELLATION_PINS = {
    "run_sha256": "9d8f5e5904b17bb7cd3d605a8d2ad31a62e6e4654a4196d1d72cdf483e5258f6",
    "job_sha256": "1e47f092f7a1dea83eb3c9aaefa9dd29371434de5a6dd6ce686a3e0d19a8ed4a",
    "check_sha256": "cd50adc209080bff2ff724ef3456150a34378986a2b5b4a93f713f43812d550d",
    "annotations_sha256": "e567b2d9ced88d0730a90d811e074a9acf0993981164c0109d9f8dde85be2877",
    "run_logs_sha256": "00543dac8eb32b6b4eb4325b9fc84fb0f5b8192cb6f5c47b7aa7c1f6cba91274",
}
_REFUSAL_CANCELLATION_CONTROL = "95ad31ca3a45b52ec7c071beeb4351f5e39a39fe"
_REFUSAL_CANCELLATION_GATE_SHA256 = (
    "a3d115ddfaa911d74de290a6030ec74112edf5ace4270267ab1486d15a55bed5"
)
_REFUSAL_CANCELLATION_STEPS = (
    (1, "Set up job", "success"),
    (2, "Check out trusted gate", "success"),
    (3, "Resolve current PR head", "failure"),
    (4, "Evaluate exact PostgreSQL N-1 authority", "skipped"),
    (5, "Mark non-completed N-1 run pending", "skipped"),
    (6, "Post exact-head gate status", "skipped"),
    (12, "Post Check out trusted gate", "success"),
    (13, "Complete job", "success"),
)


@dataclass(frozen=True)
class RefusalCancellationObservation:
    """Exact cancelled audit; the independent failed-run refusal remains required."""

    receipt: dict[str, Any]


def validate_refusal_cancellation_rules(rows, profile, identity):
    require(isinstance(rows, list) and len(rows) <= 1, "refusal cancellation scope differs")
    for row in rows:
        require(
            isinstance(row, dict)
            and row.get("kind") == REFUSAL_CANCELLATION_KIND
            and profile["component"] == "Core"
            and profile["product_revision"] == "62b5598cdba624987921cd7c865152564b3e59f4"
            and profile["product_tree"] == "84bae20062a79a874c3755e6cf75728029c1f6fc"
            and (row.get("run_id"), row.get("attempt"), row.get("job_id"), row.get("check_id"))
            == (40673555905, 1, 122766118278, 122766118278)
            and row.get("event") == "pull_request_target"
            and row.get("attachment_revision") == profile["product_revision"]
            and all(row.get(key) == value for key, value in _REFUSAL_CANCELLATION_PINS.items()),
            "refusal cancellation is not the exact reviewed Core native tuple",
        )
    validate_rules([{**row, "kind": KIND} for row in rows], profile, identity)


def verify_refusal_cancellation(profile, identity, rule, run, job, check, annotations, logs):
    from saas.scripts.legacy_source_ci import checkout_commit, completed_step_lines

    validate_refusal_cancellation_rules([rule], profile, identity)
    require(
        all(
            native.native_digest(value) == rule[key]
            for key, value in (
                ("run_sha256", run),
                ("job_sha256", job),
                ("check_sha256", check),
                ("annotations_sha256", annotations),
            )
        )
        and len(logs) == 4894
        and hashlib.sha256(logs).hexdigest() == rule["run_logs_sha256"],
        "refusal cancellation raw native tuple differs",
    )
    require(
        run.get("id") == rule["run_id"]
        and run.get("run_attempt") == rule["attempt"]
        and run.get("event") == rule["event"]
        and run.get("path") == native.MAIN_WORKFLOW
        and run.get("repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_repository", {}).get("full_name") == "Dream1216/omnigent"
        and run.get("head_sha")
        == job.get("head_sha")
        == check.get("head_sha")
        == profile["product_revision"]
        and native._pr_numbers(run.get("pull_requests")) in ([], [identity["validation_pr"]])
        and run.get("status") == job.get("status") == check.get("status") == "completed"
        and run.get("conclusion")
        == job.get("conclusion")
        == check.get("conclusion")
        == "cancelled"
        and job.get("id") == check.get("id") == rule["job_id"]
        and job.get("run_id") == rule["run_id"]
        and job.get("run_attempt") == rule["attempt"]
        and job.get("name") == check.get("name") == "evaluate"
        and job.get("labels") == ["ubuntu-latest"]
        and job.get("check_run_url") == f"{native._REPO_URL}/check-runs/{check['id']}"
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == run.get("check_suite_id"),
        "refusal cancellation native identity/provider/outcome differs",
    )
    steps = job.get("steps", [])
    require(
        tuple((s.get("number"), s.get("name"), s.get("conclusion")) for s in steps)
        == _REFUSAL_CANCELLATION_STEPS
        and all(s.get("status") == "completed" for s in steps),
        "refusal cancellation executed a different native step",
    )
    prior, end = native._instant(job.get("started_at")), native._instant(job.get("completed_at"))
    for step in steps:
        start, finish = (
            native._instant(step.get("started_at")),
            native._instant(step.get("completed_at")),
        )
        require(prior <= start <= finish <= end, "refusal cancellation chronology differs")
        prior = finish
    with zipfile.ZipFile(io.BytesIO(logs)) as archive:
        require(
            archive.namelist() == ["0_evaluate.txt", "evaluate/system.txt"]
            and archive.testzip() is None,
            "refusal cancellation archive inventory differs",
        )
        log = archive.read("0_evaluate.txt").decode("utf-8")
    require(
        checkout_commit(log, steps[1]) == _REFUSAL_CANCELLATION_CONTROL,
        "refusal cancellation checkout differs",
    )
    lines = completed_step_lines(log, steps[2])
    require(
        [line for line in lines if line.startswith("##[error]")]
        == [native._ERROR, "##[error]Process completed with exit code 1."],
        "refusal cancellation did not execute the original main-only refusal",
    )
    number, source = native.trigger_identity(
        native.trigger_environment(log, steps[2]), run["event"]
    )
    require(
        number == identity["validation_pr"] and source == profile["product_revision"],
        "refusal cancellation original event differs",
    )
    return RefusalCancellationObservation(
        {
            **rule,
            "workflow": native.MAIN_WORKFLOW,
            "check_revision": check["head_sha"],
            "check_suite_id": run["check_suite_id"],
            "app_id": 15368,
            "source_classification": "UNKNOWN",
            "original_event_source_revision": source,
            "trusted_checkout_revision": _REFUSAL_CANCELLATION_CONTROL,
            "execution": "native-refusal-then-cancelled",
            "original_conclusion": "cancelled",
            "source_proof": False,
            "guard_refusal": False,
            "technical_gate_waiver": False,
            "production_admission": False,
            "registration_sha256": native.native_digest(rule),
        }
    )


def collect_refusal_cancellation(profile, identity, rule, run, jobs, destination):
    validate_refusal_cancellation_rules([rule], profile, identity)
    require(len(jobs) == 1, "refusal cancellation native job set differs")
    check = api(f"{native._ROOT}/check-runs/{rule['check_id']}")
    annotations = annotations_for(rule["check_id"])
    path = destination / f"refusal-cancelled-run-{run['id']}-attempt-{run['run_attempt']}.zip"
    _download_run_logs(run["id"], run["run_attempt"], path, 8192)
    require(
        hashlib.sha256(native._native_file(native.MAIN_WORKFLOW, run["head_sha"])).hexdigest()
        == native.MAIN_WORKFLOW_SHA256
        and hashlib.sha256(
            native._native_file(native._GATE, _REFUSAL_CANCELLATION_CONTROL)
        ).hexdigest()
        == _REFUSAL_CANCELLATION_GATE_SHA256,
        "refusal cancellation workflow/gate source bytes differ",
    )
    return verify_refusal_cancellation(
        profile, identity, rule, run, jobs[0], check, annotations, path.read_bytes()
    )
