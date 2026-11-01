"""Preserve failure responses and propagate the same admission exception."""

from __future__ import annotations

import hashlib
import json
import stat
import sys

import pytest

from tests.saas.test_legacy_source_ci import expected, reader
from tests.saas.test_legacy_source_ci import native as native

capture = sys.modules["saas.scripts.legacy_native_evidence"]


def test_raw_response_is_private_preserved_before_real_failed_job_assertion(
    native, tmp_path, monkeypatch
):
    root = tmp_path / "evidence"
    payloads = {"run": native["original_run"], "jobs": {"jobs": [native["original_job"]]}}
    monkeypatch.setattr(capture, "_native_api", lambda endpoint: payloads[endpoint])
    with pytest.raises(ValueError, match="not a successful"):
        with capture.preserve_native_evidence(root) as evidence:
            evidence.stage = "original-failed-native-job"
            run = capture.api("run")
            jobs = capture.api("jobs")["jobs"]
            reader.verify_job_set(run, jobs, expected(native), jobs[0]["head_sha"])
    receipt = json.loads((root / "receipt.json").read_text())
    assert receipt["invocation_raised"] and receipt["exception_type"] == "ValueError"
    assert receipt["stage"] == "original-failed-native-job"
    assert receipt["source_ci_admission"] is False
    assert len(receipt["records"]) == len(receipt["files"]) == 2
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for row in receipt["records"]:
        path = root / row["path"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_size == row["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
        value = json.loads(path.read_text())
        assert value["response"] == payloads[value["endpoint"]]
    assert (
        json.loads((root / receipt["records"][0]["path"]).read_text())["response"]["conclusion"]
        == "failure"
    )


def test_successful_capture_is_not_qualification_and_pins_partial_non_API_files(
    tmp_path, monkeypatch
):
    root = tmp_path / "output"
    root.mkdir()
    monkeypatch.setattr(
        capture, "_native_api", lambda endpoint: {"id": 91, "conclusion": "failure"}
    )
    with capture.preserve_native_evidence(root / "api", evidence_root=root):
        assert capture.api("original-job")["conclusion"] == "failure"
        (root / "partial.log").write_bytes(b"original unfinished job output\n")
    receipt = json.loads((root / "api/receipt.json").read_text())
    assert not receipt["invocation_raised"]
    assert receipt["source_ci_admission"] is False
    assert {row["path"] for row in receipt["files"]} == {"api/response-000001.json", "partial.log"}


@pytest.mark.parametrize("failure", [ValueError("native API failed"), SystemExit(2)])
def test_native_failure_is_recorded_and_same_exception_propagates(failure, tmp_path, monkeypatch):
    def failed(_endpoint):
        raise failure

    monkeypatch.setattr(capture, "_native_api", failed)
    with pytest.raises(type(failure)) as raised:
        with capture.preserve_native_evidence(tmp_path / "api"):
            capture.api("failed-native-request")
    assert raised.value is failure
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    response = json.loads((tmp_path / "api/response-000001.json").read_text())
    assert response["api_exception_type"] == type(failure).__name__
    assert receipt["exception_type"] == type(failure).__name__


def test_receipt_write_failure_keeps_original_gate_exception(tmp_path, monkeypatch):
    failure = ValueError("original technical refusal")
    real_write = capture._write

    def failed(path, body):
        if path.name == "receipt.json":
            raise OSError("fixture write failure")
        return real_write(path, body)

    monkeypatch.setattr(capture, "_write", failed)
    with pytest.raises(ValueError) as raised:
        with capture.preserve_native_evidence(tmp_path / "api"):
            raise failure
    assert raised.value is failure
    assert any("receipt write failed" in note for note in failure.__notes__)


def test_nested_capture_and_reused_output_are_refused(tmp_path):
    root = tmp_path / "api"
    with pytest.raises(ValueError, match="cannot be nested"):
        with capture.preserve_native_evidence(root):
            with capture.preserve_native_evidence(tmp_path / "nested"):
                pytest.fail("nested evidence must not be entered")
    assert not (tmp_path / "nested").exists()
    with pytest.raises(FileExistsError):
        with capture.preserve_native_evidence(root):
            pytest.fail("old evidence must not be overwritten")


def test_evidence_symlink_is_recorded_without_reading_target_and_cannot_clear(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "bad-link").symlink_to(tmp_path / "private-never-read")
    with pytest.raises(ValueError, match="fully fingerprinted"):
        with capture.preserve_native_evidence(output / "api", evidence_root=output):
            pass
    receipt = json.loads((output / "api/receipt.json").read_text())
    assert receipt["pin_errors"] == [{"path": "bad-link", "error": "symlink"}]
    assert receipt["invocation_raised"] and receipt["source_ci_admission"] is False


def test_commit_contents_reuse_keeps_first_evidence_and_isolates_caller_mutation(
    tmp_path, monkeypatch
):
    endpoint = (
        "repos/Dream1216/omnigent/contents/.github/workflows/saas-n1-merge-gate.yml?ref="
        + "a" * 40
    )
    calls = []

    def read(path):
        calls.append(path)
        return {"content": "original", "links": {"self": "original"}}

    monkeypatch.setattr(capture, "_native_api", read)
    for name in ("first", "independent"):
        with capture.preserve_native_evidence(tmp_path / name) as evidence:
            value = capture.api(endpoint)
            value["content"] = "changed"
            value["links"]["self"] = "changed"
            evidence.stage = "after-mutable-native-refresh"
            cached = capture.api(endpoint)
            assert cached == {"content": "original", "links": {"self": "original"}}
            cached["links"]["self"] = "second mutation"
            assert capture.api(endpoint)["links"]["self"] == "original"
        receipt = json.loads((tmp_path / name / "receipt.json").read_text())
        assert len(receipt["records"]) == 1
        assert receipt["immutable_source_reuses"] == [
            {
                "endpoint": endpoint,
                "source_record": "response-000001.json",
                "reuse_count": 2,
            }
        ]
        original = json.loads((tmp_path / name / "response-000001.json").read_text())
        assert original["stage"] == "configuration"
        assert original["response"] == {
            "content": "original",
            "links": {"self": "original"},
        }
        assert receipt["source_ci_admission"] is False
    assert calls == [endpoint, endpoint]


@pytest.mark.parametrize(
    "suffix",
    [
        "actions/runs/91",
        "actions/runs/91/attempts/1",
        "actions/runs/91/attempts/1/jobs?per_page=100&page=1",
        "check-runs/91",
        "check-suites/91/check-runs?per_page=100&page=1",
        "pulls/91",
        "contents/workflow.yml?ref=main",
        "contents/../../actions/runs/91?ref=" + "a" * 40,
        "contents/./workflow.yml?ref=" + "a" * 40,
        "contents//workflow.yml?ref=" + "a" * 40,
        "contents/path//workflow.yml?ref=" + "a" * 40,
        "contents/path/../workflow.yml?ref=" + "a" * 40,
        "contents/workflow.yml/?ref=" + "a" * 40,
        "contents/workflow.yml?ref=" + "a" * 39,
        "contents/workflow.yml?ref=" + "A" * 40,
        "contents/workflow.yml?ref=" + "a" * 40 + "&extra=1",
    ],
)
def test_mutable_or_nonexact_contents_always_observe_native_changes(suffix, tmp_path, monkeypatch):
    calls = []

    def read(endpoint):
        calls.append(endpoint)
        return {"observation": len(calls)}

    endpoint = "repos/Dream1216/omnigent/" + suffix
    monkeypatch.setattr(capture, "_native_api", read)
    with capture.preserve_native_evidence(tmp_path / "api"):
        assert capture.api(endpoint) == {"observation": 1}
        assert capture.api(endpoint) == {"observation": 2}
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert calls == [endpoint, endpoint]
    assert len(receipt["records"]) == 2
    assert receipt["immutable_source_reuses"] == []


def test_native_contents_failure_is_not_cached_and_no_capture_does_not_reuse(
    tmp_path, monkeypatch
):
    endpoint = "repos/Dream1216/omnigent/contents/workflow.yml?ref=" + "b" * 40
    calls = []
    failure = ValueError("original native failure")

    def read(path):
        calls.append(path)
        if len(calls) == 1:
            raise failure
        return {"observation": len(calls)}

    monkeypatch.setattr(capture, "_native_api", read)
    with capture.preserve_native_evidence(tmp_path / "api"):
        with pytest.raises(ValueError) as raised:
            capture.api(endpoint)
        assert raised.value is failure
        assert capture.api(endpoint) == {"observation": 2}
        assert capture.api(endpoint) == {"observation": 2}
    assert capture.api(endpoint) == {"observation": 3}
    assert capture.api(endpoint) == {"observation": 4}
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert len(receipt["records"]) == 2
    assert receipt["immutable_source_reuses"][0]["source_record"] == "response-000002.json"
    assert receipt["immutable_source_reuses"][0]["reuse_count"] == 1


@pytest.mark.parametrize("bound", ["records", "per-response", "total-bytes"])
def test_new_source_responses_still_obey_all_original_evidence_bounds(
    bound, tmp_path, monkeypatch
):
    endpoint = "repos/Dream1216/omnigent/contents/workflow.yml?ref=" + "c" * 40
    payload = {"content": "x" * (32 * 1024 * 1024 if bound == "per-response" else 1)}
    monkeypatch.setattr(capture, "_native_api", lambda _endpoint: payload)
    message = {
        "records": "response limit exceeded",
        "per-response": "response exceeds bound",
        "total-bytes": "total exceeds bound",
    }[bound]
    # Capacity/persistence failure is now sticky fatal, including when a caller catches it.
    with pytest.raises(capture.NativeEvidenceFailure, match=message):
        with capture.preserve_native_evidence(tmp_path / "api") as evidence:
            if bound == "records":
                evidence.records.extend({} for _ in range(16384))
            if bound == "total-bytes":
                evidence.total_bytes = 512 * 1024 * 1024
            with pytest.raises(capture.NativeEvidenceFailure, match=message):
                capture.api(endpoint)
            assert evidence._immutable_sources == evidence._immutable_source_reuses == {}


def test_different_commit_or_contents_path_cannot_share_source_response(tmp_path, monkeypatch):
    prefix = "repos/Dream1216/omnigent/contents/"
    endpoints = [
        prefix + "first.yml?ref=" + "a" * 40,
        prefix + "first.yml?ref=" + "b" * 40,
        prefix + "second.yml?ref=" + "a" * 40,
    ]
    calls = []

    def read(endpoint):
        calls.append(endpoint)
        return {"endpoint": endpoint, "native_observation": len(calls)}

    monkeypatch.setattr(capture, "_native_api", read)
    with capture.preserve_native_evidence(tmp_path / "api"):
        for n, endpoint in enumerate(endpoints, 1):
            assert capture.api(endpoint)["native_observation"] == n
        for n, endpoint in enumerate(endpoints, 1):
            assert capture.api(endpoint) == {"endpoint": endpoint, "native_observation": n}
    assert calls == endpoints
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert len(receipt["records"]) == len(receipt["immutable_source_reuses"]) == 3
    assert [row["reuse_count"] for row in receipt["immutable_source_reuses"]] == [1, 1, 1]


def test_four_worker_context_preserves_every_mutable_response_and_own_record(
    tmp_path, monkeypatch
):
    import threading

    from saas.scripts import legacy_domain_discovery as discovery

    barrier = threading.Barrier(4)
    lock = threading.Lock()
    calls = []

    def native(endpoint):
        with lock:
            calls.append(endpoint)
            first_four = len(calls) <= 4
        if first_four:
            barrier.wait(timeout=5)
        return {"endpoint": endpoint}

    monkeypatch.setattr(capture, "_native_api", native)
    with capture.preserve_native_evidence(tmp_path / "api") as evidence:
        values = discovery._ordered_parallel(
            lambda n: capture.api(f"mutable-{n}"), list(range(12))
        )
        assert values == [{"endpoint": f"mutable-{n}"} for n in range(12)]
        # Each later checkpoint must actually read the same mutable endpoints again.
        for _ in range(3):
            discovery._ordered_parallel(lambda n: capture.api(f"mutable-{n}"), list(range(4)))
        assert evidence.requests_started == 24
        assert len(evidence.records) == 24
        assert evidence.total_bytes == sum(row["bytes"] for row in evidence.records)
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert receipt["native_requests_started"] == len(receipt["records"]) == 24
    assert receipt["capture_failed"] is receipt["invocation_raised"] is False
    assert len({r["path"] for r in receipt["records"]}) == 24
    assert len(calls) == 24
    assert not any(t.name.startswith("legacy-domain-native") for t in threading.enumerate())
    for row in receipt["records"]:
        path = tmp_path / "api" / row["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
        body = json.loads(path.read_text())
        assert body["response"]["endpoint"] == body["endpoint"]


def test_immutable_single_flight_deepcopies_and_provenance_is_own_write(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context

    endpoint = "repos/Dream1216/omnigent/contents/workflow.yml?ref=" + "d" * 40
    entered, release = threading.Event(), threading.Event()
    calls = []

    def native(path):
        calls.append(path)
        if path == endpoint:
            entered.set()
            assert release.wait(5)
        return {"path": path, "nested": {"original": True}}

    real_write = capture.NativeEvidence.write

    def interleaved_write(self, path, payload):
        own_record = real_write(self, path, payload)
        if path == endpoint:
            # Force the exact former records[-1] race after this write, before caching.
            capture.api("mutable-after-owned-write")
        return own_record

    monkeypatch.setattr(capture.NativeEvidence, "write", interleaved_write)
    monkeypatch.setattr(capture, "_native_api", native)
    with capture.preserve_native_evidence(tmp_path / "api") as evidence:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(copy_context().run, capture.api, endpoint) for _ in range(4)]
            assert entered.wait(5)
            # Interleave another record while the immutable request is in flight.
            capture.api("mutable")
            release.set()
            values = [f.result(timeout=5) for f in futures]
        values[0]["nested"]["original"] = False
        assert all(v["nested"]["original"] for v in values[1:])
        assert capture.api(endpoint)["nested"]["original"] is True
        assert evidence.requests_started == 3
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    reuse = receipt["immutable_source_reuses"][0]
    assert reuse["reuse_count"] == 4
    assert calls.count(endpoint) == 1 and calls.count("mutable") == 1
    assert calls.count("mutable-after-owned-write") == 1
    original = json.loads((tmp_path / "api" / reuse["source_record"]).read_text())
    assert original["endpoint"] == endpoint
    assert original["response"]["nested"]["original"] is True


def test_parallel_limit_reservation_stops_extra_GET_and_stays_fatal(tmp_path, monkeypatch):
    import threading

    from saas.scripts import legacy_domain_discovery as discovery

    assert capture._MAX_RESPONSES == 16384
    monkeypatch.setattr(capture, "_MAX_RESPONSES", 3)
    calls = []
    lock = threading.Lock()

    def native(endpoint):
        with lock:
            calls.append(endpoint)
        return {"endpoint": endpoint}

    monkeypatch.setattr(capture, "_native_api", native)
    with pytest.raises(capture.NativeEvidenceFailure, match="response limit exceeded"):
        with capture.preserve_native_evidence(tmp_path / "api") as evidence:
            with pytest.raises(capture.NativeEvidenceFailure):
                discovery._ordered_parallel(lambda n: capture.api(f"mutable-{n}"), list(range(20)))
            assert len(calls) == evidence.requests_started == 3
            with pytest.raises(capture.NativeEvidenceFailure):
                capture.api("must-not-start")
            assert len(calls) == 3
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert receipt["capture_failed"] and receipt["invocation_raised"]
    assert receipt["exception_type"] == "NativeEvidenceFailure"
    assert receipt["native_requests_started"] == 3
    assert len(receipt["records"]) <= 3
    assert not any(t.name.startswith("legacy-domain-native") for t in threading.enumerate())


def test_persistence_error_cannot_be_swallowed_to_start_another_GET(tmp_path, monkeypatch):
    calls = []
    real_write = capture._write

    def write(path, body):
        if path.name.startswith("response-"):
            raise OSError("owned fixture disk failure")
        real_write(path, body)

    monkeypatch.setattr(capture, "_write", write)
    monkeypatch.setattr(
        capture, "_native_api", lambda endpoint: calls.append(endpoint) or {"id": 1}
    )
    with pytest.raises(capture.NativeEvidenceFailure, match="cannot be preserved"):
        with capture.preserve_native_evidence(tmp_path / "api"):
            with pytest.raises(capture.NativeEvidenceFailure):
                capture.api("first")
            with pytest.raises(capture.NativeEvidenceFailure):
                capture.api("second")
    assert calls == ["first"]
    receipt = json.loads((tmp_path / "api/receipt.json").read_text())
    assert receipt["capture_failed"] and receipt["invocation_raised"]
    assert receipt["native_requests_started"] == 1
    assert receipt["records"] == []


@pytest.mark.parametrize("operation", ["job-log", "run-log", "artifact"])
def test_bootstrap_direct_cap_prevents_each_actual_downloader_spawn(
    operation, tmp_path, monkeypatch
):
    from saas.scripts import legacy_artifact_download as artifacts
    from saas.scripts import legacy_domain_non_execution as audit
    from saas.scripts import legacy_source_ci as source

    def forbidden(*_args, **_kwargs):
        pytest.fail("cap exceeded but downloader spawned a native request")

    monkeypatch.setattr(source.subprocess, "Popen", forbidden)
    with pytest.raises(capture.NativeEvidenceFailure, match="direct download safety cap"):
        with capture.preserve_native_evidence(tmp_path / "counted") as evidence:
            evidence.enable_bootstrap_limits()
            for index in range(256):
                capture.reserve_native_download(f"prior/{index}")
            destination = tmp_path / "must-not-exist"
            if operation == "job-log":
                source.download_job_log(1, destination)
            elif operation == "run-log":
                audit.download_run_logs(1, 1, destination)
            else:
                artifacts.download_artifact_bytes(
                    1, destination, expected_size=1, expected_sha256="a" * 64
                )
    assert not destination.exists()
