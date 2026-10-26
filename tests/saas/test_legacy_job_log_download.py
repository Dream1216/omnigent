"""Portable child-process fixtures; these tests do not fetch native evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import time

import psutil
import pytest

from tests.saas.test_legacy_source_ci import reader


@pytest.fixture
def child(monkeypatch):
    original = subprocess.Popen
    processes = []
    commands = []

    def run(script):
        def popen(argv, **kwargs):
            commands.append(argv)
            process = original([sys.executable, "-c", script], **kwargs)
            processes.append(process)
            return process

        monkeypatch.setattr(reader.subprocess, "Popen", popen)
        return processes, commands

    return run


def diagnostic(path):
    sidecar = path.with_name(path.name + ".native-download.json")
    assert sidecar.stat().st_mode & 0o777 == 0o600
    return json.loads(sidecar.read_text())


def test_native_log_download_drains_stderr_without_persisting_secrets(child, tmp_path):
    secret = b"token=unit-fixture-secret https://unit.invalid/?sig=unit-fixture-SAS\n"
    prefix = b"gh: Forbidden (HTTP 403)\n"
    stderr = prefix + secret * 32768
    processes, commands = child(
        f"import sys; sys.stderr.buffer.write({prefix!r} + {secret!r} * 32768); "
        "sys.stderr.flush(); sys.stdout.buffer.write(b'original native log\\n')"
    )
    path = tmp_path / "job.log"
    assert reader.download_job_log(123, path) is None
    assert path.read_bytes() == b"original native log\n"
    assert path.stat().st_mode & 0o777 == 0o600
    result = diagnostic(path)
    assert (
        result["argv"]
        == commands[0]
        == ["gh", "api", f"repos/{reader.REPOSITORY}/actions/jobs/123/logs"]
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
