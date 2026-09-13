from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from saas.scripts.check_patch_queue import check_patch_queue
from saas.scripts.check_upstream_delta import FileDelta, evaluate_delta


def _manifest():
    return {
        "downstream_owned_prefixes": [
            ".github/actions/compat-smoke-",
            ".github/workflows/saas-",
            "saas/",
            "sdks/saas-",
            "tests/saas/",
        ],
        "forbidden_upstream_prefixes": [
            "omnigent/runner/native/",
            "omnigent/runtime/workflow.py",
        ],
        "source_intrusion_budget": {
            "max_active_patches": 8,
            "max_direct_upstream_files": 10,
            "max_upstream_net_added_loc": 500,
            "min_isolated_custom_code_ratio": 0.85,
        },
    }


def test_isolated_downstream_change_passes_budget() -> None:
    report = evaluate_delta(
        [
            FileDelta("saas/compatibility/runtime_partition.py", 90, 0),
            FileDelta(".github/workflows/saas-upstream-compat.yml", 10, 0),
        ],
        _manifest(),
        active_patch_count=0,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )

    assert report["status"] == "pass"
    assert report["metrics"]["direct_upstream_file_count"] == 0
    assert report["metrics"]["isolated_custom_code_ratio"] == 1.0


def test_saas_workflows_and_sdks_are_owned_without_hiding_official_source() -> None:
    report = evaluate_delta(
        [
            FileDelta(".github/workflows/saas-image-candidate.yml", 100, 0),
            FileDelta("sdks/saas-python/src/omnigent_saas_client/client.py", 200, 0),
            FileDelta("omnigent/db/utils.py", 23, 0),
        ],
        _manifest(),
        active_patch_count=0,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )

    assert report["status"] == "pass"
    assert report["metrics"]["direct_upstream_file_count"] == 1
    assert report["metrics"]["upstream_net_added_loc"] == 23
    assert report["metrics"]["isolated_custom_code_ratio"] == pytest.approx(300 / 323, 0.0001)


def test_forbidden_native_bridge_change_fails_budget() -> None:
    report = evaluate_delta(
        [
            FileDelta("saas/compatibility/runtime_partition.py", 100, 0),
            FileDelta("omnigent/runner/native/orchestration.py", 1, 0),
        ],
        _manifest(),
        active_patch_count=0,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )

    assert report["status"] == "fail"
    assert "forbidden Agent/Harness/Native Bridge paths were modified" in report["violations"]


def test_reverse_dependency_and_patch_overflow_fail_budget() -> None:
    report = evaluate_delta(
        [FileDelta("saas/control_plane/service.py", 100, 0)],
        _manifest(),
        active_patch_count=9,
        reverse_dependencies=["omnigent/server/app.py"],
        lineage_ok=False,
        version_ok=False,
    )

    assert report["status"] == "fail"
    assert "active patch queue budget exceeded" in report["violations"]
    assert "official code imports downstream SaaS packages" in report["violations"]
    assert "upstream baseline is not an ancestor of the product revision" in report["violations"]
    assert "manifest upstream_version does not match pyproject.toml" in report["violations"]


def test_patch_queue_replays_and_covers_every_official_source_change() -> None:
    repo = Path(__file__).resolve().parents[2]
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if shallow == "true":
        pytest.skip("patch replay needs full history and runs in the SaaS compatibility gate")

    report = check_patch_queue(repo)

    assert report["status"] == "pass"
    assert report["patch_count"] == 5
    assert report["covered_paths"] == report["official_source_paths"]


@pytest.mark.parametrize("extra_lines", [0, 1])
@pytest.mark.parametrize("extra_files", [0, 1])
def test_auth_guidance_budget_revision_retains_hard_ceilings(
    extra_lines: int, extra_files: int
) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    budget = manifest["source_intrusion_budget"]
    assert budget["max_upstream_net_added_loc"] == 866
    assert budget["max_direct_upstream_files"] == 32
    assert budget["max_active_patches"] == 8
    assert budget["min_isolated_custom_code_ratio"] == 0.85
    file_count = 32 + extra_files
    report = evaluate_delta(
        [
            FileDelta("omnigent/stores/host_store.py", 866 + extra_lines - file_count + 1, 0),
            *[
                FileDelta(f"omnigent/stores/fixture_{index}.py", 1, 0)
                for index in range(file_count - 1)
            ],
            FileDelta("saas/control_plane/service.py", 10000, 0),
        ],
        manifest,
        active_patch_count=5,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["metrics"]["direct_upstream_file_count"] == file_count
    assert report["metrics"]["upstream_net_added_loc"] == 866 + extra_lines
    assert report["status"] == ("fail" if extra_lines or extra_files else "pass")
    expected = []
    if extra_files:
        expected.append("direct upstream file budget exceeded")
    if extra_lines:
        expected.append("upstream net-added LOC budget exceeded")
    assert report["violations"] == expected


@pytest.mark.parametrize("violation", ["patches", "isolation", "forbidden", "reverse"])
def test_auth_guidance_budget_keeps_other_guards(violation: str) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    path = (
        "omnigent/runner/native/orchestration.py"
        if violation == "forbidden"
        else "omnigent/db/utils.py"
    )
    report = evaluate_delta(
        [
            FileDelta(path, 100, 0),
            FileDelta("saas/fixture.py", 1 if violation == "isolation" else 10000, 0),
        ],
        manifest,
        active_patch_count=9 if violation == "patches" else 5,
        reverse_dependencies=[path] if violation == "reverse" else [],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["status"] == "fail"
    expected = {
        "patches": "active patch queue budget exceeded",
        "isolation": "isolated custom-code ratio is below budget",
        "forbidden": "forbidden Agent/Harness/Native Bridge paths were modified",
        "reverse": "official code imports downstream SaaS packages",
    }
    assert report["violations"] == [expected[violation]]
