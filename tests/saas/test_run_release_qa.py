"""Pinned onsite adapters retain native behavior across the CLI/process boundary."""

import fcntl
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from saas.scripts.run_release_qa import run_operator

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def onsite(tmp_path, monkeypatch):
    script = tmp_path / "operator.py"
    script.write_text(
        "from __future__ import annotations\n"
        "import pathlib, sys\nfrom dataclasses import dataclass\n"
        "@dataclass\nclass Result:\n    marker: pathlib.Path\n"
        "marker = pathlib.Path(sys.argv[sys.argv.index('--marker') + 1])\n"
        "assert Result(marker).marker == marker\n"
        "marker.write_text(marker.read_text() + 'run\\n' if marker.exists() else 'run\\n')\n"
        "print('private operator output')\n"
    )
    dependency = tmp_path / "dependency.py"
    dependency.write_text("# reviewed dependency\n")

    def pin(path):
        body = path.read_bytes()
        return {"path": path.name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}

    registry = tmp_path / "registry.json"
    entry = {
        **pin(script),
        "dependencies": [pin(dependency)],
        "flags": ["--marker"],
        "switches": [],
        "required": ["--marker"],
        "actions": [],
        "timeout_seconds": 10,
    }
    registry.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "root_environment": "TEST_ONSITE_ROOT",
                "operators": {"task": entry},
            }
        )
    )
    monkeypatch.setenv("TEST_ONSITE_ROOT", str(tmp_path))
    monkeypatch.delenv("OMNIGENT_RELEASE_QA_DISABLED", raising=False)
    return tmp_path, registry, script, dependency, entry


def test_unified_pipeline_cli_executes_once_and_keeps_native_output_private(onsite):
    root, registry, _, _, _ = onsite
    repo = root / "repo"
    (repo / ".github").mkdir(parents=True)
    shutil.copy(ROOT / ".github/release-pipeline.json", repo / ".github/release-pipeline.json")
    shutil.copy(registry, repo / ".github/release-qa.json")
    module = repo / "saas/scripts/run_release_qa.py"
    module.parent.mkdir(parents=True)
    shutil.copy(ROOT / "saas/scripts/run_release_qa.py", module)
    arguments = root / "arguments.json"
    marker = root / "marker"
    arguments.write_text(json.dumps(["--marker", str(marker)]))
    command = [
        sys.executable,
        str(ROOT / ".github/scripts/ci/release_pipeline.py"),
        "gate",
        "--repo",
        str(repo),
        "--stage",
        "qa",
        "--operator",
        "task",
        "--arguments-json",
        str(arguments),
        "--operation-id",
        "normal-task",
    ]
    plan = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(plan.stdout)["status"] == "plan"
    assert not marker.exists()
    completed = subprocess.run([*command, "--execute"], capture_output=True, text=True, check=True)
    repeated = subprocess.run([*command, "--execute"], capture_output=True, text=True, check=True)
    assert json.loads(completed.stdout) == json.loads(repeated.stdout)
    assert marker.read_text() == "run\n"
    assert "private operator output" not in completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"] == "completed" and result["production_authority"] is False
    assert (root / ".release-pipeline/normal-task.log").stat().st_mode & 0o077 == 0
    changed = [*command, "--execute"]
    arguments.write_text(json.dumps(["--marker", str(root / "different")]))
    failure = subprocess.run(changed, capture_output=True, text=True)
    assert failure.returncode != 0 and "different inputs" in failure.stderr


@pytest.mark.parametrize("fault", ["source", "dependency", "escape", "symlink", "writable"])
def test_unreviewed_operator_bytes_and_paths_are_rejected(onsite, fault):
    root, registry, script, dependency, _ = onsite
    if fault in {"source", "dependency"}:
        (script if fault == "source" else dependency).write_text("raise SystemExit(0)\n")
    elif fault == "symlink":
        script.unlink()
        script.symlink_to(dependency)
    elif fault == "writable":
        script.chmod(0o666)
    else:
        value = json.loads(registry.read_text())
        value["operators"]["task"]["path"] = "../escape.py"
        registry.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        run_operator("task", ["--marker", str(root / "marker")], registry=registry)


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--unknown", "x"],
        ["--marker"],
        ["--marker", "x", "--marker", "y"],
        ["--marker", "x", "--execute"],
        ["unregistered"],
    ],
)
def test_unregistered_or_incomplete_native_arguments_are_rejected(onsite, arguments):
    _, registry, _, _, _ = onsite
    with pytest.raises(ValueError):
        run_operator("task", arguments, registry=registry)


def test_shared_writer_lock_and_disabled_execution_prevent_launch(onsite, monkeypatch):
    root, registry, _, _, _ = onsite
    marker = root / "marker"
    state = root / ".release-pipeline"
    state.mkdir(mode=0o700)
    arguments = ["--marker", str(marker)]
    with (state / "writer.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            run_operator(
                "task",
                arguments,
                registry=registry,
                execute=True,
                operation_id="locked",
            )
    monkeypatch.setenv("OMNIGENT_RELEASE_QA_DISABLED", "1")
    with pytest.raises(ValueError, match="disabled"):
        run_operator("task", arguments, registry=registry, execute=True, operation_id="disabled")
    assert not marker.exists()


@pytest.mark.parametrize(
    "body,timeout,status",
    [
        ("raise SystemExit(7)\n", 10, "failed"),
        ("import time; time.sleep(20)\n", 0.05, "unknown"),
    ],
)
def test_failed_and_timed_out_actions_require_reconciliation(onsite, body, timeout, status):
    root, registry, script, _, _ = onsite
    script.write_text(body)
    value = json.loads(registry.read_text())
    value["operators"]["task"].update(
        bytes=len(script.read_bytes()),
        sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        timeout_seconds=timeout,
    )
    registry.write_text(json.dumps(value))
    arguments = ["--marker", str(root / "marker")]
    result = run_operator(
        "task", arguments, registry=registry, execute=True, operation_id="failure"
    )
    assert result["status"] == status
    with pytest.raises(ValueError, match="reconciliation"):
        run_operator("task", arguments, registry=registry, execute=True, operation_id="failure")
