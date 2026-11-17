"""Bounded transfer changes preserve native byte admission and legacy defaults."""

import hashlib
import io
import json

import pytest

from saas.scripts import legacy_artifact_download as transfer


@pytest.mark.parametrize(
    "fault", [None, "extended", "deadline", "digest", "short", "oversize", "exit"]
)
def test_native_transfer_deadline_diagnostics_and_exact_bytes(tmp_path, monkeypatch, fault):
    payload = b"original native ZIP bytes"
    original = payload
    if fault == "short":
        payload = payload[:-1]
    if fault == "oversize":
        payload += b"extra"
    if fault == "deadline":
        payload = b""
    processes, timers, reserved = [], [], []

    class Process:
        def __init__(self, argv, **kwargs):
            assert argv == ["gh", "api", "repos/Dream1216/omnigent/actions/artifacts/123/zip"]
            assert kwargs == {
                "stdout": transfer.subprocess.PIPE,
                "stderr": transfer.subprocess.DEVNULL,
            }
            self.stdout = io.BytesIO(payload)
            self.returncode = None
            processes.append(self)

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self, timeout):
            assert timeout == 5
            if self.returncode is None:
                self.returncode = 1 if fault == "exit" else 0
            return self.returncode

    class Timer:
        def __init__(self, seconds, callback):
            self.seconds, self.callback, self.cancelled = seconds, callback, False
            timers.append(self)

        def start(self):
            if fault == "deadline":
                self.callback()

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(transfer.subprocess, "Popen", Process)
    monkeypatch.setattr(transfer.threading, "Timer", Timer)
    monkeypatch.setattr(transfer, "reserve_native_download", reserved.append)
    destination, diagnostic = tmp_path / "artifact.zip", tmp_path / "transfer.json"
    kwargs = {
        "expected_size": len(original),
        "expected_sha256": hashlib.sha256(original).hexdigest(),
        "diagnostic_path": diagnostic,
    }
    if fault == "digest":
        kwargs["expected_sha256"] = "0" * 64
    if fault == "extended":
        kwargs["timeout_seconds"] = 1800
    failed = fault not in {None, "extended"}
    if failed:
        with pytest.raises(ValueError):
            transfer.download_artifact_bytes(123, destination, **kwargs)
        assert not destination.exists()
    else:
        transfer.download_artifact_bytes(123, destination, **kwargs)
        assert destination.read_bytes() == original
    assert len(processes) == len(timers) == len(reserved) == 1
    assert timers[0].seconds == (1800 if fault == "extended" else 600)
    assert timers[0].cancelled
    report = json.loads(diagnostic.read_bytes())
    assert report["complete"] is (not failed)
    assert report["received_bytes"] == len(payload)
    assert report["deadline_expired"] is (fault == "deadline")
    assert report["expected_bytes"] == len(original)
    assert report["artifact_id"] == 123
    assert set(report) == {
        "schema_version",
        "artifact_id",
        "expected_bytes",
        "received_bytes",
        "expected_sha256",
        "received_sha256",
        "timeout_seconds",
        "deadline_expired",
        "elapsed_seconds",
        "process_returncode",
        "complete",
    }
    assert diagnostic.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("deadline", [0, -1, 1801, True, "1800"])
def test_transfer_rejects_unbounded_deadline_before_spawning(tmp_path, monkeypatch, deadline):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid transfer must not spawn or reserve a native download")

    monkeypatch.setattr(transfer.subprocess, "Popen", forbidden)
    monkeypatch.setattr(transfer, "reserve_native_download", forbidden)
    with pytest.raises(ValueError, match="bounded range"):
        transfer.download_artifact_bytes(
            123,
            tmp_path / "zip",
            expected_size=1,
            expected_sha256="a" * 64,
            timeout_seconds=deadline,
        )
    assert not list(tmp_path.iterdir())


def test_legacy_callers_keep_default_deadline_without_diagnostics():
    import inspect

    parameters = inspect.signature(transfer.download_artifact_bytes).parameters
    assert parameters["timeout_seconds"].default == transfer.DOWNLOAD_TIMEOUT_SECONDS == 600
    assert parameters["diagnostic_path"].default is None
