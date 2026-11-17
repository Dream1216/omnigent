"""Download exact native GitHub artifact bytes without artifact-provided URLs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import BinaryIO, cast

from saas.scripts.legacy_native_evidence import reserve_native_download
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

DOWNLOAD_TIMEOUT_SECONDS = 600


def download_artifact_bytes(
    artifact_id: int,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: int = DOWNLOAD_TIMEOUT_SECONDS,
    diagnostic_path: Path | None = None,
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
    require(
        type(timeout_seconds) is int and 0 < timeout_seconds <= 1800,
        "native artifact transfer deadline is outside its bounded range",
    )
    if diagnostic_path is not None:
        require(
            diagnostic_path != destination and not diagnostic_path.exists(),
            "native transfer diagnostic must be a new separate file",
        )
    reserve_native_download(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    process = None
    timer = None
    complete = False
    count = 0
    digest = hashlib.sha256()
    started = time.monotonic()
    expired = threading.Event()
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

            def expire() -> None:
                expired.set()
                if process is not None and process.poll() is None:
                    process.kill()

            timer = threading.Timer(timeout_seconds, expire)
            timer.start()
            require(process.stdout is not None, "native artifact stream is missing")
            while block := cast(BinaryIO, process.stdout).read(65536):
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
        if diagnostic_path is not None:
            descriptor = os.open(diagnostic_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                json.dump(
                    {
                        "schema_version": 1,
                        "artifact_id": artifact_id,
                        "expected_bytes": expected_size,
                        "received_bytes": count,
                        "expected_sha256": expected_sha256,
                        "received_sha256": digest.hexdigest(),
                        "timeout_seconds": timeout_seconds,
                        "deadline_expired": expired.is_set(),
                        "elapsed_seconds": round(time.monotonic() - started, 6),
                        "process_returncode": process.returncode if process else None,
                        "complete": complete,
                    },
                    output,
                    indent=2,
                )
                output.write("\n")
