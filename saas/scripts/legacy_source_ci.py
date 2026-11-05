"""Bind native workflow observations to the actual tested product tree.

The trusted control checkout supplies the complete reviewed job and workflow
manifest. This reader does not infer test coverage, accept artifact-owned API
records, waive failed checks or replace native PostgreSQL and image admission.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import select
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from saas.scripts import legacy_security_policy as security
from saas.scripts.legacy_native_evidence import api, reserve_native_download
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import (
    REPOSITORY,
    load_profile,
    verify_pr_tree,
)

CHECKOUT_REVISION = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
_SHA = re.compile(r"[0-9a-f]{40}")
_WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml")
_COMMAND = re.compile(
    r'^\[command\](?:"[^"\r\n]*[/\\]git(?:\.exe)?"|'
    r"[^\r\n]*[/\\]git(?:\.exe)?|git(?:\.exe)?) log -1 --format=%H$"
)
_REQUIRED_WORKFLOWS = {
    ".github/workflows/ci.yml",
    ".github/workflows/e2e.yml",
    ".github/workflows/e2e-ui.yml",
    ".github/workflows/lint.yml",
    ".github/workflows/trivy.yml",
    ".github/workflows/saas-upstream-compat.yml",
    ".github/workflows/setup-harness-cli-pin-test.yml",
}


def _instant(value: Any) -> datetime:
    require(isinstance(value, str), "native timestamp is missing")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "native timestamp lacks a timezone")
    return result


def completed_step_lines(log: str, step: dict[str, Any]) -> list[str]:
    """Select native log lines within one authenticated completed step window."""
    require(
        step.get("status") == "completed",
        "native log step did not complete",
    )
    started, completed = (
        _instant(step.get("started_at")),
        _instant(step.get("completed_at")),
    )
    require(completed >= started, "native checkout step time is reversed")
    # Job API timestamps have second precision; native log timestamps are finer.
    end = completed + timedelta(seconds=1)
    selected = []
    for line in log.splitlines():
        encoded_timestamp = line.startswith("\ufeff")
        if encoded_timestamp:
            require(not line.startswith("\ufeff\ufeff"), "repeated native timestamp BOM")
            line = line[1:]
        timestamp, separator, body = line.partition(" ")
        if not separator:
            require(not encoded_timestamp, "BOM has no native timestamp and body")
            continue
        if encoded_timestamp:
            require(
                re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,7})?Z",
                    timestamp,
                )
                is not None,
                "BOM does not prefix the exact native UTC timestamp encoding",
            )
        try:
            observed = _instant(timestamp)
        except ValueError:
            require(not encoded_timestamp, "BOM prefixes an invalid native timestamp")
            continue
        if started <= observed < end:
            selected.append(body)
    return selected


def checkout_commit(log: str, step: dict[str, Any]) -> str:
    """Read one pinned checkout's commit within its authenticated step window."""
    require(
        step.get("status") == "completed" and step.get("conclusion") == "success",
        "native checkout step did not succeed",
    )
    selected = completed_step_lines(log, step)
    invocations = [body for body in selected if body.startswith("##[group]Run actions/checkout@")]
    require(
        invocations == [f"##[group]Run actions/checkout@{CHECKOUT_REVISION}"],
        "native checkout action is missing, ambiguous or not the reviewed pin",
    )
    commands = [index for index, body in enumerate(selected) if _COMMAND.fullmatch(body)]
    require(len(commands) == 1, "native checkout final Git command is ambiguous")
    index = commands[0]
    require(index + 1 < len(selected), "native checkout final Git result is missing")
    commit = selected[index + 1]
    require(
        _SHA.fullmatch(commit) is not None,
        "native checkout did not return a complete Git SHA",
    )
    return commit


def checkout_step_log(
    log: str, step: dict[str, Any], job_steps: list[dict[str, Any]], workflow: bytes
) -> str:
    """Exclude a declared following action from the completion-second overlap."""
    following = sorted(
        (
            row
            for row in job_steps
            if row["number"] > step["number"]
            and row.get("conclusion") != "skipped"
            and row.get("started_at") is not None
        ),
        key=lambda row: row["number"],
    )
    if not following:
        return log
    next_step = following[0]
    ended = _instant(step["completed_at"])
    if _instant(next_step["started_at"]) != ended:
        return log
    source = workflow.decode("utf-8")
    offset = 0
    for line in log.splitlines(keepends=True):
        timestamp, separator, body = line.removeprefix("\ufeff").partition(" ")
        boundary = re.fullmatch(
            r"##\[group\]Run ([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40})",
            body.rstrip("\r\n"),
        )
        if separator and boundary:
            observed = _instant(timestamp)
            action = boundary[1]
            declared = re.search(
                r"(?m)^[ \t]*-[ \t]*name:[ \t]*"
                + re.escape(next_step["name"])
                + r"[ \t]*\r?\n[ \t]*uses:[ \t]*"
                + re.escape(action)
                + r"[ \t]*(?:#.*)?$",
                source,
            )
            if ended <= observed < ended + timedelta(seconds=1) and declared:
                return log[:offset]
        offset += len(line)
    return log


def verify_job_set(
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
    specification: dict[str, Any],
    product_revision: str,
) -> None:
    """Reject missing matrices, role/attempt swaps and unexpected skips."""
    require(
        run.get("id") == specification["run_id"]
        and run.get("run_attempt") == specification["attempt"]
        and run.get("path") == specification["path"]
        and run.get("name") == specification["name"]
        and run.get("head_sha") == product_revision
        and run.get("event") == "pull_request"
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "original workflow run is not a successful exact-source PR run",
    )
    expected = specification["jobs"]
    names = [job.get("name") for job in jobs]
    require(
        len(names) == len(set(names)) and set(names) == set(expected),
        "native job matrix differs",
    )
    for job in jobs:
        contract = expected[job["name"]]
        require(
            job.get("run_id") == specification["run_id"]
            and job.get("run_attempt") == specification["attempt"]
            and job.get("head_sha") == product_revision
            and job.get("status") == "completed"
            and job.get("conclusion") == contract["conclusion"],
            "native job source, attempt or conclusion differs",
        )
        if contract["conclusion"] == "skipped":
            require(
                not contract["checkouts"],
                "a product checkout cannot be credited from a skipped job",
            )
            continue
        require(
            contract["conclusion"] == "success"
            and job.get("runner_group_name") == "GitHub Actions"
            and set(job.get("labels", [])) == set(contract["labels"])
            and "self-hosted" not in job.get("labels", []),
            "native job is not the reviewed hosted execution",
        )


def verify_run_pull_request(run: dict[str, Any], profile: dict[str, Any], number: int) -> None:
    """Reject a same-head run associated with another base or pull request."""
    pulls = run.get("pull_requests")
    require(
        isinstance(pulls, list) and len(pulls) == 1,
        "native run PR association is ambiguous",
    )
    pulls = cast(list[dict[str, Any]], pulls)
    pull = pulls[0]
    repository_url = f"https://api.github.com/repos/{REPOSITORY}"
    require(
        pull.get("number") == number
        and pull.get("url") == f"{repository_url}/pulls/{number}"
        and pull.get("head", {}).get("sha") == profile["product_revision"]
        and pull.get("base", {}).get("sha") == profile["baseline_revision"]
        and pull.get("head", {}).get("repo", {}).get("url") == repository_url
        and pull.get("base", {}).get("repo", {}).get("url") == repository_url,
        "native run belongs to another PR, source or frozen base",
    )


def _write_log_diagnostic(destination: Path, diagnostic: dict[str, Any]) -> None:
    # Diagnostics are advisory and must not replace a download or cleanup failure.
    try:
        descriptor = os.open(
            destination.with_name(destination.name + ".native-download.json"),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w") as output:
            json.dump(diagnostic, output, sort_keys=True)
            output.write("\n")
    except OSError:
        pass


def _download_job_log_direct(
    job_id: int, destination: Path, *, http1: bool = False, maximum_bytes: int = 32 * 1024 * 1024
) -> None:
    """Fetch a bounded native log directly; never follow an artifact-provided URL."""
    require(type(job_id) is int and job_id > 0, "invalid native job ID")
    require(
        type(maximum_bytes) is int and maximum_bytes in {32 * 1024 * 1024, 40 * 1024 * 1024},
        "native job log bound is invalid",
    )
    reserve_native_download(f"repos/{REPOSITORY}/actions/jobs/{job_id}/logs")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # Preserve raw evidence in the private pipe/file, never in a terminal.
    argv = [
        "gh",
        "api",
        "--allow-escape-sequences",
        f"repos/{REPOSITORY}/actions/jobs/{job_id}/logs",
    ]
    started = time.monotonic()
    environment = None
    if http1:
        environment = os.environ.copy()
        environment["GODEBUG"] = ",".join(
            part for part in (environment.get("GODEBUG", ""), "http2client=0") if part
        )
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as error:
        os.close(descriptor)
        _write_log_diagnostic(
            destination,
            {"argv": argv, "spawn_errno": error.errno, "returncode": None},
        )
        raise
    stderr_digest = hashlib.sha256()
    stderr_bytes = 0
    stderr_sample = bytearray()
    stderr_complete = False
    stop_stderr = threading.Event()

    def drain_stderr() -> None:
        nonlocal stderr_bytes, stderr_complete
        assert process.stderr is not None
        try:
            descriptor = process.stderr.fileno()
            os.set_blocking(descriptor, False)
            while not stop_stderr.is_set():
                if not select.select([descriptor], [], [], 0.1)[0]:
                    continue
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    stderr_complete = True
                    return
                stderr_digest.update(chunk)
                stderr_bytes += len(chunk)
                stderr_sample.extend(chunk[: max(0, 65536 - len(stderr_sample))])
        except OSError:
            pass

    reader = threading.Thread(target=drain_stderr, name=f"native-job-log-stderr-{job_id}")
    reader.start()
    deadline = threading.Event()

    def expire() -> None:
        deadline.set()
        if process.poll() is None:
            process.kill()

    timer = threading.Timer(45, expire)
    timer.name = f"native-job-log-deadline-{job_id}"
    timer.start()
    total = 0
    try:
        assert process.stdout is not None
        with os.fdopen(descriptor, "wb") as output:
            while chunk := process.stdout.read(65536):
                total += len(chunk)
                require(
                    total <= maximum_bytes,
                    "native job log exceeds its bounded input",
                )
                output.write(chunk)
        require(process.wait(timeout=5) == 0, "native job log download failed or timed out")
    finally:
        timer.cancel()
        timer.join()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        reader.join(timeout=5)
        stop_stderr.set()
        # The only wait is select(0.1); os.read is nonblocking. Freeze stats before return.
        reader.join()
        if process.stderr is not None:
            process.stderr.close()
        # Never persist arbitrary stderr: it may contain credentials or signed URLs.
        sample = bytes(stderr_sample).lower()
        _write_log_diagnostic(
            destination,
            {
                "argv": argv,
                "returncode": process.returncode,
                "deadline_seconds": 45,
                "deadline_expired": deadline.is_set(),
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "stdout_bytes": total,
                "stderr_bytes": stderr_bytes,
                "stderr_sha256": stderr_digest.hexdigest(),
                "stderr_complete": stderr_complete,
                "stderr_sample_limit": 65536,
                "http_statuses": sorted(
                    {int(match) for match in re.findall(rb"\(http ([1-5][0-9]{2})\)", sample)}
                ),
                "transport_indicators": [
                    name
                    for name, phrase in (
                        ("tls-handshake-timeout", b"tls handshake timeout"),
                        ("unexpected-eof", b"unexpected eof"),
                        ("deadline-exceeded", b"context deadline exceeded"),
                        ("connection-reset", b"connection reset"),
                    )
                    if phrase in sample
                ],
            },
        )


def _recover_active_job_log(job_id: int, destination: Path, expected_job: dict[str, Any]) -> None:
    """Read the same completed job once over HTTP/1 while its parent is active."""
    endpoint = f"repos/{REPOSITORY}/actions/jobs/{job_id}"
    require(
        expected_job.get("id") == job_id
        and expected_job.get("status") == "completed"
        and expected_job.get("conclusion") == "success"
        and api(endpoint) == expected_job,
        "active-run native job identity differs before log recovery",
    )
    recovered = destination.with_name(destination.name + ".active-job-http1")
    _download_job_log_direct(job_id, recovered, http1=True)
    data = recovered.read_bytes()
    require(bool(data), "active-run native job log is empty")
    data.decode("utf-8")
    require(api(endpoint) == expected_job, "active-run native job changed during log recovery")
    failed = destination.with_name(destination.name + ".direct-failed")
    require(destination.is_file() and not failed.exists(), "failed native read custody differs")
    original = destination.read_bytes()
    destination.rename(failed)
    with os.fdopen(
        os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
    ) as output:
        output.write(data)
    receipt = {
        "kind": "native_active_run_completed_job_log_http1_recovery/v1",
        "job_id": job_id,
        "run_id": expected_job["run_id"],
        "attempt": expected_job["run_attempt"],
        "head_sha": expected_job["head_sha"],
        "endpoint": endpoint + "/logs",
        "job_sha256": hashlib.sha256(
            json.dumps(expected_job, sort_keys=True).encode()
        ).hexdigest(),
        "log_bytes": len(data),
        "log_sha256": hashlib.sha256(data).hexdigest(),
        "failed_direct_read_path": str(failed),
        "failed_direct_read_bytes": len(original),
        "failed_direct_read_sha256": hashlib.sha256(original).hexdigest(),
        "recovery_diagnostic_path": str(recovered) + ".native-download.json",
        "maximum_direct_reads": 2,
        "each_read_seconds": 45,
        "each_log_size_bound": 32 * 1024 * 1024,
        "existing_source_checkout_test_and_refusal_assertions_unchanged": True,
    }
    path = destination.with_name(destination.name + ".native-log-recovery.json")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(receipt, output, sort_keys=True)
        output.write("\n")


def download_job_log(
    job_id: int, destination: Path, *, active_job: dict[str, Any] | None = None
) -> None:
    try:
        _download_job_log_direct(job_id, destination)
    except ValueError as error:
        if str(error) != "native job log download failed or timed out":
            raise
        try:
            diagnostic = json.loads(
                destination.with_name(destination.name + ".native-download.json").read_text()
            )
        except (OSError, ValueError):
            raise error from None
        if diagnostic["deadline_expired"] or diagnostic["returncode"] in {None, 0}:
            raise
        if active_job is not None:
            if any(400 <= status < 500 for status in diagnostic.get("http_statuses", [])):
                raise
            _recover_active_job_log(job_id, destination, active_job)
            return
        from saas.scripts.legacy_job_log_archive import recover_job_log

        recover_job_log(job_id, destination)


def _recover_verified_source_build_log(job: dict[str, Any], destination: Path) -> None:
    """Retain a capped read, then recover one already verified original OCI build log."""
    require(
        job.get("name") == "build-candidate"
        and type(job.get("id")) is int
        and job["id"] > 0
        and job.get("status") == "completed"
        and job.get("conclusion") == "success",
        "source build log recovery requires a verified successful original build",
    )
    original = destination.read_bytes()
    diagnostic = json.loads(
        destination.with_name(destination.name + ".native-download.json").read_text()
    )
    require(
        len(original) == 32 * 1024 * 1024
        and diagnostic["stdout_bytes"] > len(original)
        and not diagnostic["deadline_expired"]
        and not diagnostic["http_statuses"],
        "source build log recovery requires the original size-bound refusal",
    )
    endpoint = f"repos/{REPOSITORY}/actions/jobs/{job['id']}"
    require(api(endpoint) == job, "source build job changed before log recovery")
    recovered = destination.with_name(destination.name + ".verified-source-build")
    _download_job_log_direct(job["id"], recovered, maximum_bytes=40 * 1024 * 1024)
    data = recovered.read_bytes()
    require(
        len(data) > len(original) and data.startswith(original),
        "source build log differs from retained bounded read",
    )
    data.decode("utf-8")
    require(api(endpoint) == job, "source build job changed during log recovery")
    failed = destination.with_name(destination.name + ".source-size-rejected")
    require(not failed.exists(), "source build log custody already exists")
    destination.rename(failed)
    with os.fdopen(
        os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
    ) as output:
        output.write(data)
    receipt = {
        "kind": "verified_original_source_build_log_size_recovery/v1",
        "job_id": job["id"],
        "run_id": job["run_id"],
        "attempt": job["run_attempt"],
        "head_sha": job["head_sha"],
        "log_bytes": len(data),
        "log_sha256": hashlib.sha256(data).hexdigest(),
        "retained_rejected_path": str(failed),
        "retained_rejected_sha256": hashlib.sha256(original).hexdigest(),
        "maximum_direct_reads": 2,
        "default_bound_bytes": 32 * 1024 * 1024,
        "verified_original_OCI_build_bound_bytes": 40 * 1024 * 1024,
        "each_read_seconds": 45,
        "source_checkout_matrix_and_qualification_assertions_unchanged": True,
    }
    path = destination.with_name(destination.name + ".source-size-recovery.json")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(receipt, output, sort_keys=True)
        output.write("\n")


def _job_pages(run_id: int, attempt: int) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    total = None
    for page in range(1, 7):
        value = api(
            f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}"
        )
        require(
            type(value.get("total_count")) is int and 0 <= value["total_count"] <= 512,
            "native job count is invalid",
        )
        require(
            total is None or total == value["total_count"],
            "native job pagination changed",
        )
        total = value["total_count"]
        rows = value.get("jobs")
        require(
            isinstance(rows, list) and (bool(rows) or (total == 0 and page == 1)),
            "native job page is missing",
        )
        jobs.extend(cast(list[dict[str, Any]], rows))
        require(len(jobs) <= total, "native job pages contain excess entries")
        if len(jobs) == total:
            require(
                len({row.get("id") for row in jobs}) == total,
                "native jobs are duplicated",
            )
            return jobs
    raise ValueError("native job pagination is incomplete")


def _load_contract(control: Path, profile: dict[str, Any]) -> dict[str, Any]:
    store = control / "saas/supply_chain/legacy-security-ci-profiles.json"
    require(store.is_file() and not store.is_symlink(), "missing trusted native CI profiles")
    data = json.loads(store.read_text())
    require(
        set(data) == {"schema_version", "profiles"}
        and type(data["schema_version"]) is int
        and data["schema_version"] == 1,
        "native CI profile store differs",
    )
    contract = data["profiles"].get(profile["component"])
    require(isinstance(contract, dict), "no reviewed native CI profile for this product")
    require(
        set(contract)
        == {
            "schema_version",
            "component",
            "product_revision",
            "product_tree",
            "validation_pr",
            "validation_base_ref",
            "workflows",
        }
        and type(contract["schema_version"]) is int
        and contract["schema_version"] == 1
        and all(
            contract[key] == profile[key]
            for key in ("component", "product_revision", "product_tree")
        ),
        "native CI profile does not bind the frozen product",
    )
    require(
        type(contract["validation_pr"]) is int
        and contract["validation_pr"] > 0
        and isinstance(contract["validation_base_ref"], str)
        and bool(contract["validation_base_ref"])
        and contract["validation_base_ref"] != "main",
        "native CI profile lacks a reviewed isolated validation PR",
    )
    workflows = contract["workflows"]
    require(
        isinstance(workflows, list) and bool(workflows),
        "native CI workflow set is empty",
    )
    paths = [item.get("path") for item in workflows]
    require(
        len(paths) == len(set(paths)) and set(paths) >= _REQUIRED_WORKFLOWS,
        "mandatory original workflow set is incomplete",
    )
    for item in workflows:
        require(
            set(item)
            in (
                {"path", "name", "source_sha256", "run_id", "attempt", "jobs"},
                {
                    "path",
                    "name",
                    "source_sha256",
                    "run_id",
                    "attempt",
                    "jobs",
                    "trusted_security_policy",
                },
            )
            and _WORKFLOW.fullmatch(item["path"]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", item["source_sha256"]) is not None
            and all(type(item[key]) is int and item[key] > 0 for key in ("run_id", "attempt"))
            and isinstance(item["jobs"], dict)
            and bool(item["jobs"]),
            "native CI workflow contract is malformed",
        )
        for name, job in item["jobs"].items():
            require(isinstance(name, str) and bool(name), "native job name is missing")
            require(
                set(job) == {"labels", "conclusion", "checkouts"}
                and job["conclusion"] in {"success", "skipped"},
                "native job contract differs",
            )
            require(
                isinstance(job["labels"], list) and isinstance(job["checkouts"], list),
                "native job execution contract is missing",
            )
            for step in job["checkouts"]:
                require(
                    set(step) == {"number", "name", "revision"}
                    and type(step["number"]) is int
                    and step["number"] > 0
                    and isinstance(step["name"], str)
                    and bool(step["name"])
                    and (
                        step["revision"] in {"product", "product-merge"}
                        or _SHA.fullmatch(step["revision"]) is not None
                    ),
                    "native checkout contract differs",
                )
        if "trusted_security_policy" in item:
            security.validate_registration(profile, contract, item)
        require(
            any(
                step["revision"] in {"product", "product-merge"}
                for job in item["jobs"].values()
                for step in job["checkouts"]
            )
            or "trusted_security_policy" in item,
            "original workflow has no product checkout proof",
        )
    return contract


def collect_source_ci_bindings(control: Path, component: str, destination: Path) -> dict[str, Any]:
    """Collect live native run, complete matrix and checkout source identities.

    The caller must separately qualify original test selections/results, all-app
    check/status history and exact-product native PostgreSQL. This observation is
    never itself an image or production admission decision.
    """
    profile = load_profile(control, component)
    contract = _load_contract(control, profile)
    pull_endpoint = f"repos/{REPOSITORY}/pulls/{contract['validation_pr']}"
    pull = api(pull_endpoint)
    merge = pull.get("merge_commit_sha")
    require(
        isinstance(merge, str) and _SHA.fullmatch(merge) is not None,
        "native PR merge SHA is missing",
    )
    commit = api(f"repos/{REPOSITORY}/git/commits/{merge}")
    verify_pr_tree(
        pull,
        commit,
        profile,
        number=contract["validation_pr"],
        base_ref=contract["validation_base_ref"],
    )
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    observations = []
    policy_decisions = []
    for specification in contract["workflows"]:
        run_id, attempt = specification["run_id"], specification["attempt"]
        source = api(f"repos/{REPOSITORY}/contents/{specification['path']}?ref={merge}")
        require(
            source.get("path") == specification["path"]
            and source.get("encoding") == "base64"
            and type(source.get("size")) is int
            and source["size"] <= 262144,
            "native workflow source record differs",
        )
        body = base64.b64decode("".join(source["content"].split()), validate=True)
        require(
            len(body) == source["size"]
            and hashlib.sha256(body).hexdigest() == specification["source_sha256"],
            "actual tested workflow bytes differ",
        )
        run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
        verify_run_pull_request(run, profile, contract["validation_pr"])
        jobs = _job_pages(run_id, attempt)
        verify_job_set(run, jobs, specification, profile["product_revision"])
        require(
            run.get("head_branch") == pull["head"]["ref"],
            "native workflow used another PR branch",
        )
        checkouts = []
        for job in jobs:
            steps = specification["jobs"][job["name"]]["checkouts"]
            if not steps:
                continue
            path = destination / f"job-{job['id']}.log"
            try:
                download_job_log(job["id"], path)
            except ValueError as error:
                if (
                    str(error) != "native job log exceeds its bounded input"
                    or specification["path"] != ".github/workflows/saas-image-candidate.yml"
                    or job.get("name") != "build-candidate"
                ):
                    raise
                _recover_verified_source_build_log(job, path)
            log = path.read_text()
            for required in steps:
                actual = [
                    row
                    for row in job.get("steps", [])
                    if row.get("number") == required["number"]
                    and row.get("name") == required["name"]
                ]
                require(len(actual) == 1, "native checkout step identity differs")
                observed = checkout_commit(
                    checkout_step_log(log, actual[0], job["steps"], body), actual[0]
                )
                expected = {
                    "product": profile["product_revision"],
                    "product-merge": merge,
                }.get(required["revision"], required["revision"])
                require(observed == expected, "actual tested checkout commit differs")
                checkouts.append(
                    {
                        "job_id": job["id"],
                        "step": required,
                        "actual_commit": observed,
                        "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        policy_fields = {}
        if "trusted_security_policy" in specification:
            proof = security.collect_policy_decision(
                profile,
                contract,
                specification,
                pull,
                commit,
                run,
                jobs,
                destination / f"job-{jobs[0]['id']}.log",
                destination,
            )
            policy_decisions.append(proof)
            policy_fields["trusted_security_policy_decision"] = proof.receipt
        observations.append(
            {
                **policy_fields,
                "run": run,
                "jobs": jobs,
                "verified_checkouts": checkouts,
                "workflow_sha256": specification["source_sha256"],
            }
        )
    refreshed = api(pull_endpoint)
    verify_pr_tree(
        refreshed,
        commit,
        profile,
        number=contract["validation_pr"],
        base_ref=contract["validation_base_ref"],
    )
    result = {
        "kind": "native_source_ci_identity_observation",
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "merge_commit": merge,
        "workflows": observations,
        "coverage_all_app_PG_image_production_admission": False,
    }
    return security.SourceCIObservation(result, policy_decisions) if policy_decisions else result
