"""Portable child-process fixtures; these tests do not fetch native evidence."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import time
import zipfile
from collections import OrderedDict

import psutil
import pytest

from saas.scripts import legacy_job_log_archive as archive_reader
from tests.saas.test_legacy_source_ci import reader


@pytest.fixture
def child(monkeypatch):
    original = subprocess.Popen
    processes = []
    commands = []

    def direct_failure(_job, _path):
        raise ValueError("native job log download failed or timed out")

    # These fixtures isolate the original child transport from native metadata reads.
    monkeypatch.setattr(archive_reader, "recover_job_log", direct_failure)

    def run(script):
        scripts = iter([script] if isinstance(script, str) else script)

        def popen(argv, **kwargs):
            commands.append(argv)
            process = original([sys.executable, "-c", next(scripts)], **kwargs)
            processes.append(process)
            return process

        monkeypatch.setattr(reader.subprocess, "Popen", popen)
        return processes, commands

    return run


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "changed_before",
        "changed_after",
        "second_failure",
        "empty",
        "encoding",
        "size",
        "deadline",
    ],
)
def test_active_parent_uses_one_bounded_same_job_http1_read(child, monkeypatch, tmp_path, fault):
    job = {
        "id": 123,
        "run_id": 456,
        "run_attempt": 1,
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
    }
    calls = []

    def api(endpoint):
        assert endpoint == f"repos/{reader.REPOSITORY}/actions/jobs/123"
        calls.append(endpoint)
        value = copy.deepcopy(job)
        if fault == "changed_before" or (fault == "changed_after" and len(calls) == 2):
            value["head_sha"] = "b" * 40
        return value

    monkeypatch.setattr(reader, "api", api)
    monkeypatch.setenv("GODEBUG", "http2client=1,netdns=go")
    second = (
        "import os,sys; assert os.environ['GODEBUG']=='http2client=1,netdns=go,http2client=0'; "
        + (
            "sys.exit(19)"
            if fault == "second_failure"
            else "sys.stdout.write('')"
            if fault == "empty"
            else "sys.stdout.buffer.write(b'\\xff')"
            if fault == "encoding"
            else "sys.stdout.buffer.write(b'x' * (33 * 1024 * 1024))"
            if fault == "size"
            else "import time; time.sleep(60)"
            if fault == "deadline"
            else "sys.stdout.write('original complete native job log\\n')"
        )
    )
    processes, commands = child(
        [
            "import sys; sys.stdout.write('retained partial failure'); "
            "sys.stderr.write('unclassified original transport failure'); sys.exit(1)",
            second,
        ]
    )
    if fault == "deadline":
        timer = threading.Timer
        deadlines = []

        def bounded(seconds, callback):
            deadlines.append(seconds)
            return timer(0.1 if len(deadlines) == 2 else seconds, callback)

        monkeypatch.setattr(reader.threading, "Timer", bounded)
    path = tmp_path / "active.log"
    if fault:
        with pytest.raises(ValueError):
            reader.download_job_log(123, path, active_job=job)
        assert path.read_bytes() == b"retained partial failure"
        assert not path.with_name(path.name + ".native-log-recovery.json").exists()
    else:
        reader.download_job_log(123, path, active_job=job)
        assert path.read_bytes() == b"original complete native job log\n"
        assert (
            path.with_name(path.name + ".direct-failed").read_bytes()
            == b"retained partial failure"
        )
        receipt = json.loads(path.with_name(path.name + ".native-log-recovery.json").read_text())
        assert receipt["head_sha"] == job["head_sha"]
        assert receipt["maximum_direct_reads"] == 2
        assert receipt["log_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert diagnostic(path)["returncode"] == 1
        assert diagnostic(path.with_name(path.name + ".active-job-http1"))["returncode"] == 0
    assert len(processes) == (1 if fault == "changed_before" else 2)
    assert all(process.poll() is not None for process in processes)
    assert len({tuple(command) for command in commands}) == 1
    assert os.environ["GODEBUG"] == "http2client=1,netdns=go"
    if fault == "deadline":
        assert deadlines == [45, 45]
        assert diagnostic(path.with_name(path.name + ".active-job-http1"))["deadline_expired"]


@pytest.mark.parametrize("message", ["gh: Forbidden (HTTP 403)", "gh: Not Found (HTTP 404)"])
def test_active_job_recovery_never_retries_an_explicit_HTTP_refusal(child, tmp_path, message):
    processes, _ = child(f"import sys; sys.stderr.write({message!r}); sys.exit(1)")
    with pytest.raises(ValueError, match="native job log download failed or timed out"):
        reader.download_job_log(123, tmp_path / "refused.log", active_job={"id": 123})
    assert len(processes) == 1


def diagnostic(path):
    sidecar = path.with_name(path.name + ".native-download.json")
    assert sidecar.stat().st_mode & 0o777 == 0o600
    return json.loads(sidecar.read_text())


def test_native_log_download_drains_stderr_without_persisting_secrets(child, tmp_path):
    secret = b"token=unit-fixture-secret https://unit.invalid/?sig=unit-fixture-SAS\n"
    prefix = b"gh: Forbidden (HTTP 403)\n"
    native_log = b"original native log \x1b[32mPASSED\x1b[0m\n"
    stderr = prefix + secret * 32768
    processes, commands = child(
        f"import sys; sys.stderr.buffer.write({prefix!r} + {secret!r} * 32768); "
        f"sys.stderr.flush(); sys.stdout.buffer.write({native_log!r})"
    )
    path = tmp_path / "job.log"
    assert reader.download_job_log(123, path) is None
    assert path.read_bytes() == native_log
    assert path.stat().st_mode & 0o777 == 0o600
    result = diagnostic(path)
    assert (
        result["argv"]
        == commands[0]
        == [
            "gh",
            "api",
            "--allow-escape-sequences",
            f"repos/{reader.REPOSITORY}/actions/jobs/123/logs",
        ]
    )
    assert result["returncode"] == 0 and result["deadline_expired"] is False
    assert result["stderr_complete"] is True
    assert result["stderr_bytes"] == len(stderr)
    assert result["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    assert result["http_statuses"] == [403]
    assert "unit-fixture" not in json.dumps(result)
    assert len(processes) == 1 and processes[0].poll() == 0


@pytest.mark.parametrize(
    ("message", "statuses", "indicators"),
    [
        ("gh: Forbidden (HTTP 403)", [403], []),
        ("net/http: TLS handshake timeout", [], ["tls-handshake-timeout"]),
        ("unexpected EOF", [], ["unexpected-eof"]),
        ("unknown transport failure", [], []),
    ],
)
def test_native_log_failure_has_exact_rc_and_safe_classification(
    child, tmp_path, message, statuses, indicators
):
    processes, _ = child(f"import sys; sys.stderr.write({message!r}); sys.exit(17)")
    path = tmp_path / "job.log"
    with pytest.raises(ValueError, match="native job log download failed or timed out"):
        reader.download_job_log(123, path)
    result = diagnostic(path)
    assert path.read_bytes() == b""
    assert result["returncode"] == 17
    assert result["deadline_expired"] is False and result["deadline_seconds"] == 45
    assert result["http_statuses"] == statuses
    assert result["transport_indicators"] == indicators
    assert len(processes) == 1 and processes[0].poll() == 17


def test_native_log_deadline_kills_and_reaps_exact_child(child, monkeypatch, tmp_path):
    processes, _ = child("import time; time.sleep(60)")
    original = threading.Timer
    deadlines = []

    def timer(seconds, callback):
        deadlines.append(seconds)
        return original(0.1, callback)

    monkeypatch.setattr(reader.threading, "Timer", timer)
    path = tmp_path / "job.log"
    with pytest.raises(ValueError, match="native job log download failed or timed out"):
        reader.download_job_log(123, path)
    result = diagnostic(path)
    assert deadlines == [45]
    assert result["deadline_expired"] is True
    assert result["returncode"] == -9 and processes[0].poll() == -9
    assert len(processes) == 1


def test_native_log_size_bound_retains_original_failure_and_reaps(child, tmp_path):
    processes, _ = child("import sys; sys.stdout.buffer.write(b'x' * (33 * 1024 * 1024))")
    path = tmp_path / "job.log"
    with pytest.raises(ValueError, match="native job log exceeds its bounded input"):
        reader.download_job_log(123, path)
    result = diagnostic(path)
    assert path.stat().st_size <= 32 * 1024 * 1024
    assert result["stdout_bytes"] > 32 * 1024 * 1024
    assert len(processes) == 1 and processes[0].poll() is not None


@pytest.mark.parametrize("rc", [0, 17])
def test_diagnostic_write_failure_does_not_mask_download_or_cleanup(child, tmp_path, rc):
    processes, _ = child(f"import sys; sys.stdout.write('original'); sys.exit({rc})")
    path = tmp_path / "job.log"
    path.with_name(path.name + ".native-download.json").mkdir()
    if rc:
        with pytest.raises(ValueError, match="native job log download failed or timed out"):
            reader.download_job_log(123, path)
    else:
        assert reader.download_job_log(123, path) is None
    assert path.read_text() == "original"
    assert len(processes) == 1 and processes[0].poll() == rc


def test_spawn_failure_retains_errno_and_original_exception(monkeypatch, tmp_path):
    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError(2, "unit fixture unavailable")

    monkeypatch.setattr(reader.subprocess, "Popen", unavailable)
    path = tmp_path / "job.log"
    with pytest.raises(FileNotFoundError):
        reader.download_job_log(123, path)
    result = diagnostic(path)
    assert result["spawn_errno"] == 2 and result["returncode"] is None
    assert "unit fixture" not in json.dumps(result)


def test_existing_log_is_never_overwritten_or_downloaded(child, tmp_path):
    processes, _ = child("raise AssertionError('must not execute')")
    path = tmp_path / "job.log"
    path.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        reader.download_job_log(123, path)
    assert path.read_bytes() == b"original" and processes == []
    assert not path.with_name(path.name + ".native-download.json").exists()


@pytest.mark.parametrize("parent_rc", [0, 17])
def test_inherited_stderr_is_stopped_closed_and_frozen_before_return(child, tmp_path, parent_rc):
    """Real grandchild keeps stderr after its parent exits; it closes within six seconds."""
    pid_path = tmp_path / "owned-grandchild.pid"
    exited = tmp_path / "owned-grandchild.exited"
    descendant = (
        "import os,time; "
        "os.write(2,b'owned early stderr\\n'); time.sleep(6); "
        "\ntry: os.write(2,b'owned late stderr\\n')"
        "\nexcept BrokenPipeError: pass"
        f"\nfrom pathlib import Path; Path({str(exited)!r}).write_text('natural-exit'); "
        "os._exit(0)"
    )
    processes, _ = child(
        "import subprocess,sys; from pathlib import Path; "
        f"descendant=subprocess.Popen([sys.executable,'-c',{descendant!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL); "
        f"Path({str(pid_path)!r}).write_text(str(descendant.pid)); "
        f"sys.stdout.write('original native log'); sys.exit({parent_rc})"
    )
    path = tmp_path / "job.log"
    descendant_pid = None
    started = time.monotonic()
    try:
        if parent_rc:
            with pytest.raises(ValueError, match="native job log download failed or timed out"):
                reader.download_job_log(123, path)
        else:
            assert reader.download_job_log(123, path) is None
        elapsed = time.monotonic() - started
        assert 5 <= elapsed < 8
        descendant_pid = int(pid_path.read_text())
        assert psutil.pid_exists(descendant_pid)
        assert len(processes) == 1 and processes[0].poll() == parent_rc
        assert processes[0].stdout.closed and processes[0].stderr.closed
        assert not any(
            thread.name in {"native-job-log-stderr-123", "native-job-log-deadline-123"}
            for thread in threading.enumerate()
        )
        frozen = path.with_name(path.name + ".native-download.json").read_bytes()
        result = diagnostic(path)
        assert result["returncode"] == parent_rc
        assert result["stderr_complete"] is False
        assert result["stderr_bytes"] == len(b"owned early stderr\n")
        assert result["stderr_sha256"] == hashlib.sha256(b"owned early stderr\n").hexdigest()
        assert result["deadline_expired"] is False and result["deadline_seconds"] == 45
        psutil.Process(descendant_pid).wait(timeout=5)
        assert not psutil.pid_exists(descendant_pid)
        assert exited.read_text() == "natural-exit"
        assert path.with_name(path.name + ".native-download.json").read_bytes() == frozen
    finally:
        if descendant_pid is None and pid_path.exists():
            descendant_pid = int(pid_path.read_text())
        if descendant_pid is not None and psutil.pid_exists(descendant_pid):
            owned = psutil.Process(descendant_pid)
            owned.kill()
            owned.wait(timeout=5)


@pytest.fixture
def archive_recovery(monkeypatch):
    state = {
        "job": {
            "id": 123,
            "run_id": 456,
            "run_attempt": 2,
            "head_sha": "a" * 40,
            "run_url": f"https://api.github.com/repos/{reader.REPOSITORY}/actions/runs/456",
            "status": "completed",
            "name": "gate / Security Gate",
        },
        "members": [("0_gate _ Security Gate.txt", b"original native full-job log\n")],
        "api_calls": [],
        "downloads": [],
        "catalogue_calls": [],
        "jobs": None,
        "changed_job": False,
    }

    def api(endpoint):
        assert endpoint == f"repos/{reader.REPOSITORY}/actions/jobs/123"
        state["api_calls"].append(endpoint)
        job = copy.deepcopy(state["job"])
        if state["changed_job"] and len(state["api_calls"]) == 2:
            job["head_sha"] = "b" * 40
        return job

    def download(run, attempt, path, bound):
        state["downloads"].append((run, attempt, bound))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as bundle:
            for name, content in state["members"]:
                bundle.writestr(name, content)
        path.write_bytes(stream.getvalue())
        path.chmod(0o600)

    def job_pages(run, attempt):
        state["catalogue_calls"].append((run, attempt))
        return copy.deepcopy(state["jobs"] if state["jobs"] is not None else [state["job"]])

    from saas.scripts import legacy_domain_non_execution as nonexecution

    monkeypatch.setattr(archive_reader, "_CACHE", OrderedDict())
    monkeypatch.setattr(archive_reader, "api", api)
    monkeypatch.setattr(archive_reader, "_job_pages", job_pages)
    monkeypatch.setattr(nonexecution, "_download_run_logs", download)
    return state


def test_exact_run_attempt_archive_recovery_keeps_failure_and_reuses_native_bytes(
    archive_recovery, tmp_path
):
    for name in ("first", "second"):
        path = tmp_path / name
        path.write_bytes(b"partial failed direct response")
        path.chmod(0o600)
        archive_reader.recover_job_log(123, path)
        assert path.read_bytes() == b"original native full-job log\n"
        assert path.stat().st_mode & 0o777 == 0o600
        assert (
            path.with_name(name + ".direct-failed").read_bytes()
            == b"partial failed direct response"
        )
        receipt = json.loads(path.with_name(name + ".native-log-recovery.json").read_text())
        assert receipt["job_id"] == 123 and receipt["run_id"] == 456 and receipt["attempt"] == 2
        assert receipt["head_sha"] == "a" * 40
        assert receipt["archive_endpoint"].endswith("/actions/runs/456/attempts/2/logs")
        assert receipt["member"] == "0_gate _ Security Gate.txt"
        assert receipt["log_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert archive_recovery["downloads"] == [(456, 2, 32 * 1024 * 1024)]
    assert len(archive_recovery["api_calls"]) == 4
    assert archive_recovery["catalogue_calls"] == [(456, 2)]


@pytest.mark.parametrize(
    ("job_name", "member"),
    [
        (
            "verify-production-migration-replay "
            "(postgres:16.14-bookworm@sha256:64154d0babcb1741988719e703419a...",
            "3_verify-production-migration-replay "
            "(postgres16.14-bookworm@sha25664154d0babcb1741988719e703419a....txt",
        ),
        (
            "verify-production-migration-replay "
            "(postgres:18.6-trixie@sha256:4ef4dbc939d61acea57712655ddb4b4ab...",
            "5_verify-production-migration-replay "
            "(postgres18.6-trixie@sha2564ef4dbc939d61acea57712655ddb4b4ab....txt",
        ),
    ],
)
def test_native_archive_recovers_observed_postgres_matrix_names(
    archive_recovery, tmp_path, job_name, member
):
    archive_recovery["job"]["name"] = job_name
    archive_recovery["members"] = [(member, b"original PostgreSQL matrix log\n")]
    path = tmp_path / "postgres.log"
    path.write_bytes(b"failed direct response")
    archive_reader.recover_job_log(123, path)
    assert path.read_bytes() == b"original PostgreSQL matrix log\n"


@pytest.mark.parametrize("other_name", ["gate :_ Security Gate", "gate _ Security Gate"])
def test_native_archive_rejects_lossy_name_collisions_even_with_one_member(
    archive_recovery, tmp_path, other_name
):
    other = copy.deepcopy(archive_recovery["job"])
    other.update(id=124, name=other_name)
    archive_recovery["jobs"] = [archive_recovery["job"], other]
    path = tmp_path / "ambiguous.log"
    path.write_bytes(b"retained direct failure")
    with pytest.raises(ValueError, match="catalogue"):
        archive_reader.recover_job_log(123, path)
    assert path.read_bytes() == b"retained direct failure"
    assert not path.with_name(path.name + ".native-log-recovery.json").exists()


@pytest.mark.parametrize("field", ["id", "run_id", "run_attempt", "head_sha", "run_url", "status"])
def test_native_archive_rejects_catalogue_identity_substitution(archive_recovery, tmp_path, field):
    other = copy.deepcopy(archive_recovery["job"])
    other[field] = "different" if isinstance(other[field], str) else other[field] + 1
    archive_recovery["jobs"] = [other]
    path = tmp_path / "substituted.log"
    path.write_bytes(b"retained direct failure")
    with pytest.raises(ValueError, match="catalogue"):
        archive_reader.recover_job_log(123, path)
    assert path.read_bytes() == b"retained direct failure"


@pytest.mark.parametrize(
    "fault",
    [
        "repository",
        "job",
        "run",
        "attempt",
        "head",
        "active",
        "name",
        "missing",
        "ambiguous",
        "changed",
        "encoding",
    ],
)
def test_native_archive_recovery_rejects_identity_member_and_refresh_faults(
    archive_recovery, tmp_path, fault
):
    state = archive_recovery
    if fault == "repository":
        state["job"]["run_url"] = "https://untrusted.invalid/actions/runs/456"
    elif fault in {"job", "run", "attempt"}:
        state["job"][{"job": "id", "run": "run_id", "attempt": "run_attempt"}[fault]] = 0
    elif fault == "head":
        state["job"]["head_sha"] = "unsealed"
    elif fault == "active":
        state["job"]["status"] = "in_progress"
    elif fault == "name":
        state["job"]["name"] = "other job"
    elif fault == "missing":
        state["members"] = [("gate _ Security Gate/1_step.txt", b"step only")]
    elif fault == "ambiguous":
        state["members"].append(("1_gate _ Security Gate.txt", b"other full job"))
    elif fault == "changed":
        state["changed_job"] = True
    elif fault == "encoding":
        state["members"] = [("0_gate _ Security Gate.txt", b"\xff")]
    path = tmp_path / "job.log"
    path.write_bytes(b"retained direct failure")
    with pytest.raises((ValueError, UnicodeError)):
        archive_reader.recover_job_log(123, path)
    assert path.read_bytes() == b"retained direct failure"
    assert not path.with_name(path.name + ".native-log-recovery.json").exists()


def test_native_archive_recovery_rejects_changed_cached_original(archive_recovery, tmp_path):
    first = tmp_path / "first"
    first.write_bytes(b"")
    archive_reader.recover_job_log(123, first)
    first.with_name(first.name + ".native-run.zip").write_bytes(b"changed archive")
    second = tmp_path / "second"
    second.write_bytes(b"second direct failure")
    with pytest.raises(ValueError, match="custody differs"):
        archive_reader.recover_job_log(123, second)
    assert second.read_bytes() == b"second direct failure"


def test_native_archive_recovery_rejects_changed_cached_job_catalogue(archive_recovery, tmp_path):
    first = tmp_path / "first"
    first.write_bytes(b"")
    archive_reader.recover_job_log(123, first)
    first.with_name(first.name + ".native-run.zip.jobs.json").write_bytes(b"[]")
    second = tmp_path / "second"
    second.write_bytes(b"second direct failure")
    with pytest.raises(ValueError, match="custody differs"):
        archive_reader.recover_job_log(123, second)
    assert second.read_bytes() == b"second direct failure"


def test_failed_direct_reader_uses_exact_native_archive_adapter(
    archive_recovery, tmp_path, monkeypatch
):
    def failed(_job, path):
        path.write_bytes(b"failed direct response")
        sidecar = path.with_name(path.name + ".native-download.json")
        sidecar.write_text(json.dumps({"returncode": 1, "deadline_expired": False}))
        raise ValueError("native job log download failed or timed out")

    monkeypatch.setattr(reader, "_download_job_log_direct", failed)
    path = tmp_path / "job.log"
    assert reader.download_job_log(123, path) is None
    assert path.read_bytes() == b"original native full-job log\n"
    assert path.with_name(path.name + ".direct-failed").read_bytes() == b"failed direct response"
    assert archive_recovery["downloads"] == [(456, 2, 32 * 1024 * 1024)]
