"""The frozen-version comparator cannot lower main's gate or write off main."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from saas.scripts import legacy_coverage_status as coverage


@pytest.mark.parametrize("fault", [None, "source", "reference", "path", "command", "setup"])
def test_current_C2_allows_only_exact_setup_and_preserves_original_selection(monkeypatch, fault):
    import hashlib

    original = b"original test matrix and command\n"
    current = coverage._CURRENT_C2_V8_SETUP + original
    monkeypatch.setattr(
        coverage,
        "_CURRENT_C2_PRODUCERS",
        tuple(hashlib.sha256(body).hexdigest() for body in (current, original)),
    )
    source, reference, path = (
        coverage._CURRENT_C2[0],
        coverage.REFERENCES["Compatibility018"][1],
        ".github/workflows/ci.yml",
    )
    if fault == "source":
        source = coverage.REFERENCES["Compatibility018"][0]
    elif fault == "reference":
        reference = "f" * 40
    elif fault == "path":
        path = ".github/workflows/web-tests.yml"
    elif fault == "command":
        current = current.replace(b"test matrix", b"other matrix")
    elif fault == "setup":
        current = current.replace(b"timeout-minutes: 3", b"timeout-minutes: 4")
    assert coverage._same_coverage_producer(source, reference, path, current, original) is (
        fault is None
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_SHA",
    ],
)
def test_only_native_protected_coverage_checkout_may_write(monkeypatch, tmp_path, fault):
    revision = "a" * 40
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": coverage.REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{coverage.REPOSITORY}/{coverage._WORKFLOW}@refs/heads/main",
        "GITHUB_SHA": revision,
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, "untrusted" if name == fault else value)
    monkeypatch.setattr(coverage.subprocess, "check_output", lambda *_a, **_k: revision)
    if fault is None:
        coverage.require_native_main_writer(tmp_path)
    else:
        with pytest.raises(ValueError, match="native protected-main"):
            coverage.require_native_main_writer(tmp_path)


@pytest.mark.parametrize("fault", [None, "source", "workflow", "coverage-config", "version"])
@pytest.mark.parametrize("current,expected", [("86.78", True), ("86.28", True), ("86.27", False)])
def test_real_drop_stays_failure_and_source_selection_cannot_change(
    monkeypatch, tmp_path, fault, current, expected
):
    source = coverage.REFERENCES["Core"][0]
    monkeypatch.setattr(
        coverage,
        "load_profile",
        lambda *_: {"product_revision": "f" * 40 if fault == "source" else source},
    )
    monkeypatch.setattr(
        coverage,
        "_load_contract",
        lambda *_: {
            "workflows": [
                {"path": ".github/workflows/ci.yml", "run_id": 4, "attempt": 1},
                {"path": ".github/workflows/web-tests.yml", "run_id": 5, "attempt": 1},
            ]
        },
    )
    calls = 0

    def original(command, **_kwargs):
        nonlocal calls
        calls += 1
        if command[-1].endswith("pyproject.toml"):
            version = "0.21.0" if fault == "version" else "0.18.0.dev20261006"
            omit = '"changed.py"' if fault == "coverage-config" and calls == 2 else ""
            return (
                f'[project]\nversion="{version}"\n[tool.coverage]\nomit=[{omit}]\n'
                '[tool.pytest]\ntestpaths=["tests"]\n'
            )
        if fault == "workflow" and command[-1].endswith("ci.yml"):
            return command[-1].encode()
        return b"unchanged original config or workflow"

    monkeypatch.setattr(coverage.subprocess, "check_output", original)
    monkeypatch.setattr(
        coverage,
        "_coverage",
        lambda *_a, current=False, **_k: (
            Decimal(globals_current if current else "86.78"),
            {"run_id": 4},
        ),
    )
    globals_current = current
    if fault:
        with pytest.raises(ValueError, match="changed"):
            coverage.compare_originals(tmp_path, "Core", tmp_path)
    else:
        _, rows = coverage.compare_originals(tmp_path, "Core", tmp_path)
        assert all(row["passed"] is expected for row in rows)
        assert all(
            coverage.status_payload("Core", row)["state"] == ("success" if expected else "failure")
            for row in rows
        )


@pytest.mark.parametrize("mode", ["dry-run", "foreign-provider", "wrong-producer", "native"])
def test_all_status_inputs_checked_before_any_native_write(monkeypatch, mode):
    source = coverage.REFERENCES["Core"][0]
    row = {
        "context": "Coverage",
        "passed": True,
        "current_percent": "87",
        "reference_percent": "87",
        "current": {"run_id": 9},
    }
    monkeypatch.setattr(
        coverage,
        "compare_originals",
        lambda *_: (source, [row, dict(row, context="Coverage (ui)")]),
    )
    monkeypatch.setattr(coverage, "require_native_main_writer", lambda *_: None)
    statuses = [
        {
            "id": i,
            "context": context,
            "creator": {"id": 1 if mode == "foreign-provider" else 41898282},
            "target_url": "wrong"
            if mode == "wrong-producer" and i == 2
            else f"https://github.com/{coverage.REPOSITORY}/actions/runs/9",
        }
        for i, context in enumerate(("Coverage", "Coverage (ui)"), 1)
    ]
    monkeypatch.setattr(coverage, "api", lambda *_: statuses)
    writes = []
    monkeypatch.setattr(coverage.subprocess, "run", lambda *a, **k: writes.append((a, k)))
    monkeypatch.setattr(
        "sys.argv", ["coverage", "--component", "Core"] + ([] if mode == "dry-run" else ["--post"])
    )
    if mode in {"foreign-provider", "wrong-producer"}:
        with pytest.raises(ValueError, match="another provider or producing run"):
            coverage.main()
        assert not writes
    else:
        assert coverage.main() == 0
        assert len(writes) == (0 if mode == "dry-run" else 2)
        assert all(json.loads(k["input"])["state"] == "success" for _, k in writes)
        assert all(a[0][-3] == f"repos/{coverage.REPOSITORY}/statuses/{source}" for a, _ in writes)
