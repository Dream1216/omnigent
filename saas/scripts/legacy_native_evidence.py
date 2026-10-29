"""Preserve authenticated native API response objects before admission assertions."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.oci_promotion import require
from saas.scripts.resume_oci_promotion import api as _native_api

_ACTIVE: ContextVar[NativeEvidence | None] = ContextVar("legacy_native_evidence", default=None)


class NativeEvidence:
    def __init__(self, root: Path, evidence_root: Path) -> None:
        self.root = root
        self.evidence_root = evidence_root
        self.stage = "configuration"
        self.records: list[dict[str, Any]] = []
        self.total_bytes = 0
        self._immutable_sources: dict[str, dict[str, Any]] = {}
        self._immutable_source_reuses: dict[str, dict[str, Any]] = {}

    def write(self, endpoint: str, payload: dict[str, Any]) -> None:
        require(len(self.records) < 2048, "native evidence response limit exceeded")
        body = (
            json.dumps(
                {
                    "observed_at": datetime.now(UTC).isoformat(),
                    "stage": self.stage,
                    "endpoint": endpoint,
                    **payload,
                },
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode()
        require(len(body) <= 32 * 1024 * 1024, "native evidence response exceeds bound")
        require(
            self.total_bytes + len(body) <= 512 * 1024 * 1024,
            "native evidence total exceeds bound",
        )
        name = f"response-{len(self.records) + 1:06d}.json"
        _write(self.root / name, body)
        self.records.append(
            {"path": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        )
        self.total_bytes += len(body)

    def finish(self, failure: BaseException | None) -> None:
        files = []
        pin_errors = []
        for path in sorted(self.evidence_root.rglob("*")):
            relative = str(path.relative_to(self.evidence_root))
            if path == self.root / "receipt.json":
                continue
            if path.is_symlink():
                pin_errors.append({"path": relative, "error": "symlink"})
                continue
            if path.is_dir():
                continue
            digest = hashlib.sha256()
            size = 0
            try:
                with path.open("rb") as content:
                    while chunk := content.read(1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                files.append({"path": relative, "bytes": size, "sha256": digest.hexdigest()})
            except OSError as error:
                pin_errors.append({"path": relative, "error": type(error).__name__})
        body = (
            json.dumps(
                {
                    "kind": "legacy_native_api_evidence_receipt/v1",
                    "finished_at": datetime.now(UTC).isoformat(),
                    "stage": self.stage,
                    "invocation_raised": failure is not None or bool(pin_errors),
                    "exception_type": type(failure).__name__ if failure is not None else None,
                    "source_ci_admission": False,
                    "scope": "Native API response objects; evidence capture only.",
                    "records": self.records,
                    "immutable_source_reuses": list(self._immutable_source_reuses.values()),
                    "files": files,
                    "pin_errors": pin_errors,
                },
                indent=2,
            )
            + "\n"
        ).encode()
        _write(self.root / "receipt.json", body)
        require(not pin_errors, "native evidence output cannot be fully fingerprinted")


def _write(path: Path, body: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


@contextmanager
def preserve_native_evidence(root: Path, *, evidence_root: Path | None = None):
    require(_ACTIVE.get() is None, "native evidence capture cannot be nested")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence_root = evidence_root or root
    require(
        root.is_relative_to(evidence_root), "native evidence root is outside invocation output"
    )
    recorder = NativeEvidence(root, evidence_root)
    token = _ACTIVE.set(recorder)
    failure = None
    try:
        yield recorder
    except BaseException as error:
        failure = error
        raise
    finally:
        _ACTIVE.reset(token)
        try:
            recorder.finish(failure)
        except (OSError, TypeError, ValueError) as error:
            if failure is None:
                raise
            failure.add_note("Native evidence receipt write failed: " + type(error).__name__)


def api(endpoint: str) -> dict[str, Any]:
    recorder = _ACTIVE.get()
    # A full commit SHA fixes contents; mutable native observations always refresh.
    source = re.fullmatch(
        r"repos/Dream1216/omnigent/contents/([A-Za-z0-9_./-]+)\?ref=[0-9a-f]{40}",
        endpoint,
    )
    immutable_source = (
        recorder is not None
        and source is not None
        and all(part not in {"", ".", ".."} for part in source[1].split("/"))
    )
    if recorder is not None and immutable_source and endpoint in recorder._immutable_sources:
        recorder._immutable_source_reuses[endpoint]["reuse_count"] += 1
        return copy.deepcopy(recorder._immutable_sources[endpoint])
    try:
        value = _native_api(endpoint)
    except BaseException as error:
        if recorder is not None:
            try:
                recorder.write(endpoint, {"api_exception_type": type(error).__name__})
            except (OSError, TypeError, ValueError) as write_error:
                error.add_note(
                    "Native API failure evidence write failed: " + type(write_error).__name__
                )
        raise
    if recorder is not None:
        recorder.write(endpoint, {"response": value})
        if immutable_source:
            recorder._immutable_sources[endpoint] = copy.deepcopy(value)
            recorder._immutable_source_reuses[endpoint] = {
                "endpoint": endpoint,
                "source_record": recorder.records[-1]["path"],
                "reuse_count": 0,
            }
    return value
