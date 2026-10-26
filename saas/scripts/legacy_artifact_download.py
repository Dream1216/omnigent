"""Download exact native GitHub artifact bytes without artifact-provided URLs."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
from pathlib import Path

from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

DOWNLOAD_TIMEOUT_SECONDS = 600


def download_artifact_bytes(
    artifact_id: int, destination: Path, *, expected_size: int, expected_sha256: str
) -> None:
    """Stream one immutable native ZIP, bound by its authenticated size and hash."""
    require(
        type(artifact_id) is int
        and artifact_id > 0
        and type(expected_size) is int
        and expected_size > 0,
        "invalid native artifact coordinate or size",
    )
    require(
        isinstance(expected_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
        "invalid native artifact SHA256",
    )
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    process = None
    timer = None
    complete = False
    try:
        with os.fdopen(descriptor, "wb") as output:
            process = subprocess.Popen(
                [
                    "gh",
                    "api",
                    f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            timer = threading.Timer(DOWNLOAD_TIMEOUT_SECONDS, process.kill)
            timer.start()
            require(process.stdout is not None, "native artifact stream is missing")
            count = 0
            digest = hashlib.sha256()
            while block := process.stdout.read(65536):
                count += len(block)
                require(
                    count <= expected_size,
                    "native artifact exceeds its original ZIP size",
                )
                digest.update(block)
                output.write(block)
            require(
                process.wait(timeout=5) == 0,
                "native artifact download failed or timed out",
            )
            require(
                count == expected_size and digest.hexdigest() == expected_sha256,
                "native artifact original ZIP size or digest differs",
            )
            output.flush()
            os.fsync(output.fileno())
        complete = True
    finally:
        if timer is not None:
            timer.cancel()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        if not complete:
            destination.unlink(missing_ok=True)
