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
from pathlib import Path
from typing import Any

from saas.scripts import legacy_domain_native as native
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pr_candidate import VALIDATION_REFS
from saas.scripts.oci_promotion import require

KIND = "legacy_original_main_domain_zero_execution/v1"
INFRASTRUCTURE_KIND = "legacy_original_main_domain_infrastructure_cancellation/v1"
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


class DomainDiscovery(dict):
    """Serializable discovery facts with separately retained in-memory proofs."""

    def __init__(self, facts, observations=()):
        super().__init__(facts)
        self.observations = tuple(observations)


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
            and re.fullmatch(r"[0-9a-f]{40}", row["attachment_revision"]),
            "zero-execution native coordinates or hashes differ",
        )
        key = row["run_id"], row["attempt"], row["job_id"], row["check_id"]
        require(key not in seen, "zero-execution native registration is duplicated")
        seen.add(key)


def verify_zero_execution(profile, identity, rule, run, job, check, annotations, logs):
    """Authenticate execution absence without assigning an original event source."""
    validate_rules([rule], profile, identity)
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
        isinstance(annotations, list)
        and annotations
        and all(isinstance(row, dict) for row in annotations),
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
        isinstance(proof, ZeroExecutionObservation)
        and proof.receipt.get("kind") == KIND
        and proof.receipt.get("execution") == "native-proven-zero"
    ) or (
        isinstance(proof, InfrastructureCancellationObservation)
        and proof.receipt.get("kind") == INFRASTRUCTURE_KIND
        and proof.receipt.get("execution") == "native-infrastructure-executed-cancelled"
    )
