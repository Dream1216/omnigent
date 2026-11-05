"""Preserve authenticated native API response objects before admission assertions."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.scripts.oci_promotion import require
from saas.scripts.resume_oci_promotion import api as _plain_native_api

_ACTIVE: ContextVar[NativeEvidence | None] = ContextVar("legacy_native_evidence", default=None)


_MAX_RESPONSES = 16384


class NativeEvidenceFailure(RuntimeError):
    """Fatal capture failure; never a recoverable per-run governance observation."""


class _HTTPResponse:
    def __init__(self, value, observation, etag):
        self.value = value
        self.observation = observation
        self.etag = etag


class _HTTPFailure(subprocess.CalledProcessError):
    def __init__(self, result, command, observation):
        super().__init__(result.returncode or 1, command, result.stdout, result.stderr)
        self.observation = observation


def _native_api(endpoint: str) -> Any:
    recorder = _ACTIVE.get()
    if recorder is None:
        return _plain_native_api(endpoint)
    prior = recorder._validated_responses.get(endpoint)
    command = ["gh", "api", "--include", endpoint]
    if prior is not None:
        command.extend(["-H", "If-None-Match: " + prior["etag"]])
    result = subprocess.run(command, capture_output=True, timeout=60)
    wire = recorder.write_http(result.stdout)
    header, separator, body = result.stdout.partition(b"\r\n\r\n")
    lines = header.splitlines()
    status_match = re.fullmatch(rb"HTTP/[0-9.]+ ([0-9]{3})[^\r\n]*", lines[0]) if lines else None
    require(bool(separator and status_match), "native HTTP response framing differs")
    assert status_match is not None
    status = int(status_match[1])
    headers = {}
    for line in header.splitlines()[1:]:
        key, colon, value = line.partition(b":")
        require(bool(colon), "native HTTP header is malformed")
        key = key.decode("ascii").lower()
        if key in {"etag", "date", "x-github-request-id", "retry-after"} or key.startswith(
            "x-ratelimit-"
        ):
            require(key not in headers, "native HTTP header is duplicated")
            headers[key] = value.decode("ascii").strip()
    etag = headers.get("etag")
    require(
        etag is None or bool(re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', etag)),
        "native HTTP entity tag is malformed",
    )
    observation = {
        "status": status,
        "headers": headers,
        "conditional_request": prior is not None,
        **wire,
        **({"validated_source_record": prior["source_record"]} if prior is not None else {}),
    }
    if status == 304:
        require(
            prior is not None
            and result.returncode in {0, 1}
            and not body
            and etag is not None
            and etag.removeprefix("W/") == prior["etag"].removeprefix("W/"),
            "native HTTP 304 lacks the exact previously captured representation",
        )
        assert prior is not None
        return _HTTPResponse(copy.deepcopy(prior["response"]), observation, etag)
    if result.returncode or status != 200:
        raise _HTTPFailure(result, command, observation)
    value = json.loads(body)
    require(isinstance(value, (dict, list)), "native HTTP JSON response is not an object or array")
    return _HTTPResponse(value, observation, etag)


class NativeEvidence:
    def __init__(self, root: Path, evidence_root: Path) -> None:
        self.root = root
        self.evidence_root = evidence_root
        self.stage = "configuration"
        self.records: list[dict[str, Any]] = []
        self.total_bytes = 0
        self.requests_started = 0
        self._bootstrap_limits = False
        self.direct_requests: list[str] = []
        self.rate_advisory: dict[str, Any] | None = None
        self._lock = threading.RLock()
        self._source_locks: dict[str, threading.Lock] = {}
        self._failure: NativeEvidenceFailure | None = None
        self._immutable_sources: dict[str, dict[str, Any]] = {}
        self._immutable_source_reuses: dict[str, dict[str, Any]] = {}
        self._validated_responses: dict[str, dict[str, Any]] = {}
        self._http_response_count = 0

    def write_http(self, body: bytes) -> dict[str, Any]:
        with self._lock:
            self.check()
            if len(body) > 32 * 1024 * 1024:
                raise self._fail("native HTTP response exceeds bound")
            if self.total_bytes + len(body) > 512 * 1024 * 1024:
                raise self._fail("native evidence total exceeds bound")
            name = f"http-{self._http_response_count + 1:06d}.PRIVATE.response"
            try:
                _write(self.root / name, body)
            except OSError as error:
                raise self._fail("native HTTP response cannot be preserved") from error
            self._http_response_count += 1
            self.total_bytes += len(body)
            return {
                "raw_http_path": name,
                "raw_http_bytes": len(body),
                "raw_http_sha256": hashlib.sha256(body).hexdigest(),
            }

    def enable_bootstrap_limits(self) -> None:
        with self._lock:
            require(
                not self._bootstrap_limits
                and self.requests_started == 0
                and not self.direct_requests,
                "bootstrap request scope already consumed",
            )
            self._bootstrap_limits = True

    def observe_bootstrap_rate_limit(self) -> None:
        # Advisory only; use the unchanged same-job gh token environment.
        # Never substitute a caller's OAuth/PAT pool or infer a reset from errors.
        require(
            self._bootstrap_limits and self.rate_advisory is None,
            "bootstrap rate advisory scope already consumed",
        )
        if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("GH_TOKEN"):
            self.rate_advisory = {"status": "UNKNOWN", "reason": "no-same-job-token-context"}
            return
        self.reserve()
        try:
            value = _native_api("rate_limit")
            if isinstance(value, _HTTPResponse):
                value = value.value
            if not isinstance(value, dict):
                raise ValueError("native rate advisory is not an object")
            core = value.get("resources", {}).get("core", {})
            fields = ("limit", "remaining", "reset", "used")
            if all(type(core.get(k)) is int and core[k] >= 0 for k in fields):
                self.rate_advisory = {
                    "status": "OBSERVED_ADVISORY_ONLY",
                    "core": {k: core[k] for k in fields},
                }
            else:
                self.rate_advisory = {"status": "UNKNOWN", "reason": "unrecognized-rate-fields"}
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
            self.rate_advisory = {"status": "UNKNOWN", "exception_type": type(error).__name__}
        self.write("rate_limit", {"advisory": self.rate_advisory})

    def bootstrap_usage(self) -> dict[str, Any]:
        return {
            "kind": "proposal-failclosed-safety-cap-not-success-capacity",
            "metadata_limit": 1024,
            "direct_download_limit": 256,
            "metadata_started": self.requests_started,
            "direct_downloads_started": len(self.direct_requests),
            "same_job_rate_advisory": self.rate_advisory,
        }

    def reserve_download(self, endpoint: str) -> None:
        with self._lock:
            if self._bootstrap_limits:
                self.check()
                if len(self.direct_requests) >= 256:
                    raise self._fail("bootstrap direct download safety cap exceeded")
                self.direct_requests.append(endpoint)

    def check(self) -> None:
        with self._lock:
            if self._failure is not None:
                raise self._failure

    def _fail(self, message: str) -> NativeEvidenceFailure:
        # All callers hold the recorder lock; failure stays fatal even if caught.
        if self._failure is None:
            self._failure = NativeEvidenceFailure(message)
        return self._failure

    def reserve(self) -> None:
        with self._lock:
            self.check()
            if self._bootstrap_limits and self.requests_started >= 1024:
                raise self._fail("bootstrap metadata safety cap exceeded")
            if max(self.requests_started, len(self.records)) >= _MAX_RESPONSES:
                raise self._fail("native evidence response limit exceeded")
            self.requests_started += 1

    def source_lock(self, endpoint: str) -> threading.Lock:
        with self._lock:
            self.check()
            return self._source_locks.setdefault(endpoint, threading.Lock())

    def write(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.check()
            if len(self.records) >= _MAX_RESPONSES:
                raise self._fail("native evidence response limit exceeded")
            try:
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
                if len(body) > 32 * 1024 * 1024:
                    raise self._fail("native evidence response exceeds bound")
                if self.total_bytes + len(body) > 512 * 1024 * 1024:
                    raise self._fail("native evidence total exceeds bound")
                name = f"response-{len(self.records) + 1:06d}.json"
                _write(self.root / name, body)
            except (OSError, TypeError, ValueError) as error:
                raise self._fail("native evidence response cannot be preserved") from error
            record = {
                "path": name,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            self.records.append(record)
            self.total_bytes += len(body)
            return dict(record)

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
                    "invocation_raised": failure is not None
                    or self._failure is not None
                    or bool(pin_errors),
                    "exception_type": type(failure).__name__ if failure is not None else None,
                    "source_ci_admission": False,
                    "scope": "Native API response objects; evidence capture only.",
                    "records": self.records,
                    "native_requests_started": self.requests_started,
                    "capture_failed": self._failure is not None,
                    **(
                        {
                            "bootstrap_request_safety": self.bootstrap_usage(),
                            "direct_download_endpoints": self.direct_requests,
                        }
                        if self._bootstrap_limits
                        else {}
                    ),
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
        recorder.check()
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
    if recorder is None:
        return _native_api(endpoint)
    # A full commit SHA fixes contents; mutable native observations always refresh.
    source = re.fullmatch(
        r"repos/Dream1216/omnigent/contents/([A-Za-z0-9_./-]+)\?ref=[0-9a-f]{40}",
        endpoint,
    )
    immutable_source = source is not None and all(
        part not in {"", ".", ".."} for part in source[1].split("/")
    )
    # Mutable checkpoints always contact GitHub; only a native 304 validates reuse.
    with recorder.source_lock(endpoint):
        with recorder._lock:
            recorder.check()
            if immutable_source and endpoint in recorder._immutable_sources:
                recorder._immutable_source_reuses[endpoint]["reuse_count"] += 1
                return copy.deepcopy(recorder._immutable_sources[endpoint])
        recorder.reserve()
        try:
            value = _native_api(endpoint)
        except BaseException as error:
            try:
                recorder.write(
                    endpoint,
                    {
                        "api_exception_type": type(error).__name__,
                        **(
                            {"http_observation": error.observation}
                            if isinstance(error, _HTTPFailure)
                            else {}
                        ),
                    },
                )
            except NativeEvidenceFailure as write_error:
                error.add_note(
                    "Native API failure evidence write failed: " + type(write_error).__name__
                )
            if recorder._bootstrap_limits or (
                isinstance(error, _HTTPFailure) and error.observation["status"] in {403, 429}
            ):
                with recorder._lock:
                    failure = recorder._fail("native request failed; no further requests allowed")
                raise failure from error
            raise
        observed = value if isinstance(value, _HTTPResponse) else None
        if observed is not None:
            value = observed.value
        record = recorder.write(
            endpoint,
            {
                "response": value,
                **({"http_observation": observed.observation} if observed is not None else {}),
            },
        )
        if observed is not None and observed.etag is not None:
            recorder._validated_responses[endpoint] = {
                "etag": observed.etag,
                "response": copy.deepcopy(value),
                "source_record": observed.observation.get(
                    "validated_source_record", record["path"]
                )
                if observed.observation["status"] == 304
                else record["path"],
            }
        elif observed is not None:
            recorder._validated_responses.pop(endpoint, None)
        if immutable_source:
            with recorder._lock:
                recorder.check()
                recorder._immutable_sources[endpoint] = copy.deepcopy(value)
                recorder._immutable_source_reuses[endpoint] = {
                    "endpoint": endpoint,
                    "source_record": record["path"],
                    "reuse_count": 0,
                }
        return value


def reserve_native_download(endpoint: str) -> None:
    """Count direct native streams only within explicit bootstrap safety scope."""
    recorder = _ACTIVE.get()
    if recorder is not None:
        recorder.reserve_download(endpoint)
