"""Recover a native job log from its exact run-attempt archive."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import threading
import zipfile
from collections import OrderedDict
from pathlib import Path
from typing import cast

from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_source_ci import _job_pages
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

_CACHE: OrderedDict[tuple[int, int], tuple[bytes, Path, bytes]] = OrderedDict()
_LOCK = threading.Lock()
_PREFIX = f"repos/{REPOSITORY}"


def _archive(run_id: int, attempt: int, destination: Path) -> tuple[bytes, Path, bytes]:
    from saas.scripts.legacy_domain_non_execution import _download_run_logs

    key = run_id, attempt
    with _LOCK:
        if key not in _CACHE:
            path = destination.with_name(destination.name + ".native-run.zip")
            _download_run_logs(run_id, attempt, path, 32 * 1024 * 1024)
            data = path.read_bytes()
            require(0 < len(data) <= 32 * 1024 * 1024, "native run log ZIP exceeds bound")
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                entries = bundle.infolist()
                require(
                    0 < len(entries) <= 4096
                    and len(entries) == len({entry.filename for entry in entries})
                    and sum(entry.file_size for entry in entries) <= 256 * 1024 * 1024
                    and all(not entry.flag_bits & 1 for entry in entries),
                    "native run log ZIP inventory exceeds bound or is ambiguous",
                )
                require(bundle.testzip() is None, "native run log ZIP CRC differs")
            catalogue = json.dumps(_job_pages(run_id, attempt), sort_keys=True).encode()
            catalogue_path = path.with_name(path.name + ".jobs.json")
            with os.fdopen(
                os.open(catalogue_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as output:
                output.write(catalogue)
            _CACHE[key] = data, path, catalogue
            if len(_CACHE) > 4:
                _CACHE.popitem(last=False)
        _CACHE.move_to_end(key)
        data, path, catalogue = _CACHE[key]
        catalogue_path = path.with_name(path.name + ".jobs.json")
        require(
            path.is_file()
            and path.read_bytes() == data
            and catalogue_path.is_file()
            and catalogue_path.read_bytes() == catalogue,
            "cached native log archive custody differs",
        )
        return _CACHE[key]


def _archive_name(name: str) -> str:
    return name.replace("/", "_").replace(":", "")


def recover_job_log(job_id: int, destination: Path) -> None:
    """Keep the failed direct read and select one authenticated full-job member."""
    require(type(job_id) is int and job_id > 0, "invalid native job ID")
    endpoint = f"{_PREFIX}/actions/jobs/{job_id}"
    job = api(endpoint)
    run_id, attempt = job.get("run_id"), job.get("run_attempt")
    require(
        job.get("id") == job_id
        and type(run_id) is int
        and run_id > 0
        and type(attempt) is int
        and attempt > 0
        and job.get("run_url") == f"https://api.github.com/{_PREFIX}/actions/runs/{run_id}"
        and isinstance(job.get("head_sha"), str)
        and re.fullmatch(r"[0-9a-f]{40}", job["head_sha"]) is not None
        and job.get("status") == "completed"
        and isinstance(job.get("name"), str)
        and bool(job["name"]),
        "native job cannot identify one completed repository run attempt",
    )
    data, archive, catalogue = _archive(cast(int, run_id), cast(int, attempt), destination)
    jobs = json.loads(catalogue)
    require(
        all(isinstance(row.get("name"), str) and bool(row["name"]) for row in jobs),
        "native run job catalogue contains an invalid name",
    )
    normalized = _archive_name(job["name"])
    matches = [row for row in jobs if _archive_name(row["name"]) == normalized]
    require(
        len(matches) == 1
        and all(
            matches[0].get(field) == job[field]
            for field in ("id", "run_id", "run_attempt", "head_sha", "name", "run_url", "status")
        ),
        "native run job catalogue has no unique matching job identity",
    )
    expected = re.compile(r"[0-9]+_" + re.escape(normalized) + r"\.txt")
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        selected = [entry for entry in bundle.infolist() if expected.fullmatch(entry.filename)]
        require(len(selected) == 1, "native run archive has no unique full-job log")
        member = selected[0]
        require(0 < member.file_size <= 32 * 1024 * 1024, "native full-job log exceeds bound")
        log = bundle.read(member)
    log.decode("utf-8")
    require(api(endpoint) == job, "native job changed during run archive recovery")
    failed = destination.with_name(destination.name + ".direct-failed")
    require(destination.is_file() and not failed.exists(), "failed native read custody differs")
    original = destination.read_bytes()
    destination.rename(failed)
    with os.fdopen(
        os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
    ) as output:
        output.write(log)
    receipt = {
        "kind": "native_job_log_from_exact_run_attempt_archive/v1",
        "job_id": job_id,
        "run_id": run_id,
        "attempt": attempt,
        "head_sha": job["head_sha"],
        "job_sha256": hashlib.sha256(json.dumps(job, sort_keys=True).encode()).hexdigest(),
        "archive_endpoint": f"{_PREFIX}/actions/runs/{run_id}/attempts/{attempt}/logs",
        "archive_path": str(archive),
        "archive_sha256": hashlib.sha256(data).hexdigest(),
        "archive_bytes": len(data),
        "job_catalogue_endpoint": f"{_PREFIX}/actions/runs/{run_id}/attempts/{attempt}/jobs",
        "job_catalogue_path": str(archive.with_name(archive.name + ".jobs.json")),
        "job_catalogue_sha256": hashlib.sha256(catalogue).hexdigest(),
        "member": member.filename,
        "log_bytes": len(log),
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "failed_direct_read_path": str(failed),
        "failed_direct_read_bytes": len(original),
        "failed_direct_read_sha256": hashlib.sha256(original).hexdigest(),
        "existing_source_checkout_test_and_refusal_assertions_unchanged": True,
    }
    path = destination.with_name(destination.name + ".native-log-recovery.json")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(receipt, output, sort_keys=True)
        output.write("\n")
