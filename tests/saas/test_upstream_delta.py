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
    assert report["patch_count"] == 8
    assert report["covered_paths"] == report["official_source_paths"]


@pytest.mark.parametrize("extra_lines", [0, 1])
def test_ui_e2e_budget_revision_retains_hard_source_ceilings(
    extra_lines: int,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    budget = manifest["source_intrusion_budget"]
    assert budget["max_upstream_net_added_loc"] == 2579
    assert budget["max_direct_upstream_files"] == 88
    assert budget["max_active_patches"] == 8
    assert budget["min_isolated_custom_code_ratio"] == 0.85
    revision = manifest["source_intrusion_budget_revision"]
    assert revision["revision"] == "new-session-catalog-scroll-stability-v18"
    assert revision["previous_max_direct_upstream_files"] == 84
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2382
    assert revision["scoped_ui_delta"] == {
        "tests/e2e_ui/chat/test_slash_menu_skills_loading.py": 3,
        "tests/e2e_ui/chat/test_transcript_scroll_stability.py": 10,
        "web/src/components/chat/Transcript.cleanup.test.tsx": 1,
        "web/src/components/chat/Transcript.tsx": 8,
        "web/src/components/chat/Transcript.virtualList.test.tsx": 23,
        "web/src/shell/NewChatDialog.test.tsx": 43,
        "web/src/shell/NewChatDialog.tsx": 7,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "repository-owner-maintainer-governance-v17"
    assert revision["previous_max_direct_upstream_files"] == 83
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2379
    assert revision["scoped_governance_delta"] == {".github/MAINTAINER": 1}
    revision = revision["previous_revision"]
    assert revision["revision"] == "pi-native-workspace-callback-route-v16"
    assert revision["previous_max_direct_upstream_files"] == 82
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2365
    assert revision["scoped_runtime_delta"] == {"omnigent/harnesses/pi_native/bridge.py": 14}
    revision = revision["previous_revision"]
    assert revision["revision"] == "kiro-readiness-regression-contract-v15"
    assert revision["previous_max_direct_upstream_files"] == 81
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2364
    assert revision["scoped_test_delta"] == {"tests/test_harness_readiness.py": 0}
    revision = revision["previous_revision"]
    assert revision["revision"] == "harness-readiness-release-verification-v14"
    assert revision["previous_max_direct_upstream_files"] == 81
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2313
    assert revision["scoped_harness_delta"] == {
        "omnigent/onboarding/harness_install.py": 2,
        "omnigent/onboarding/harness_readiness.py": 2,
        "tests/onboarding/test_harness_install.py": 25,
        "tests/onboarding/test_harness_readiness.py": 22,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "ui-repl-regression-contract-closure-v13"
    assert revision["previous_max_direct_upstream_files"] == 76
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2229
    assert revision["scoped_test_delta"] == {
        "tests/e2e/test_repl_sessions_approval_e2e.py": 14,
        "tests/e2e_ui/approvals/test_inbox_approval.py": 16,
        "tests/e2e_ui/chat/test_codex_effort_terminal_composer_mirror.py": 21,
        "tests/e2e_ui/chat/test_slash_menu_skills_loading.py": 28,
        "tests/e2e_ui/messages/test_native_claude_render_parity.py": 5,
    }
    previous = revision["previous_revision"]
    assert previous["revision"] == "dual-managed-kubernetes-runtimes-v12"
    assert previous["previous_max_direct_upstream_files"] == 70
    assert previous["previous_max_upstream_net_added_loc"] == 2579
    assert previous["previous_measured_upstream_net_added_loc"] == 2101
    assert previous["scoped_runtime_delta"] == {
        "omnigent/onboarding/sandboxes/kubernetes.py": 32,
        "omnigent/server/managed_hosts.py": 40,
        "tests/cli/test_backend.py": 2,
        "tests/onboarding/sandboxes/test_kubernetes.py": 17,
        "tests/server/helpers.py": 3,
        "tests/server/test_managed_hosts.py": 34,
    }
    previous = previous["previous_revision"]
    assert previous["revision"] == "host-daemon-workspace-selector-v11"
    assert previous["previous_max_direct_upstream_files"] == 69
    assert previous["previous_max_upstream_net_added_loc"] == 2579
    assert previous["previous_measured_upstream_net_added_loc"] == 2099
    assert previous["scoped_runtime_delta"] == {"omnigent/cli.py": 2}
    previous = previous["previous_revision"]
    assert previous["revision"] == "ui-preview-unconfigured-mirror-guard-v10"
    assert previous["previous_max_direct_upstream_files"] == 68
    assert previous["previous_max_upstream_net_added_loc"] == 2579
    assert previous["previous_measured_upstream_net_added_loc"] == 2055
    assert previous["scoped_ci_delta"] == {
        ".github/workflows/ui-preview.yml": 44,
    }
    dependency_revision = previous["previous_revision"]
    assert dependency_revision["revision"] == "candidate-dependency-security-closure-v9"
    assert dependency_revision["previous_max_direct_upstream_files"] == 64
    assert dependency_revision["previous_max_upstream_net_added_loc"] == 2579
    assert dependency_revision["scoped_dependency_delta"] == {
        "editors/vscode/package.json": 0,
        "pnpm-lock.yaml": -457,
        "pnpm-workspace.yaml": 1,
        "uv.lock": 0,
        "web/ios/Gemfile.lock": 20,
        "web/ios/RELEASE.md": 1,
        "web/package.json": 0,
    }
    assert dependency_revision["previous_revision"]["revision"] == "e2e-apt-index-refresh-v8"
    report = evaluate_delta(
        [
            FileDelta("omnigent/stores/host_store.py", 2579 + extra_lines, 0),
            FileDelta("saas/control_plane/service.py", 15000, 0),
        ],
        manifest,
        active_patch_count=8,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["status"] == ("fail" if extra_lines else "pass")
    assert report["violations"] == (
        ["upstream net-added LOC budget exceeded"] if extra_lines else []
    )


@pytest.mark.parametrize("extra_files", [0, 1])
def test_dependency_security_budget_revision_retains_a_hard_file_ceiling(
    extra_files: int,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    file_count = manifest["source_intrusion_budget"]["max_direct_upstream_files"] + extra_files
    report = evaluate_delta(
        [FileDelta(f"omnigent/budget_probe_{index}.py", 0, 0) for index in range(file_count)],
        manifest,
        active_patch_count=7,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["status"] == ("fail" if extra_files else "pass")
    assert report["violations"] == (
        ["direct upstream file budget exceeded"] if extra_files else []
    )


def test_e2e_ui_governance_files_are_downstream_owned() -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    report = evaluate_delta(
        [
            FileDelta(".github/scripts/e2e-ui-required/check.sh", 91, 35),
            FileDelta(".github/workflows/e2e-ui-required.yml", 47, 7),
            FileDelta("tests/ci/test_e2e_ui_required_gate.py", 138, 0),
        ],
        manifest,
        active_patch_count=7,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["status"] == "pass"
    assert report["metrics"]["direct_upstream_file_count"] == 0
    assert report["metrics"]["upstream_net_added_loc"] == 0
    assert report["metrics"]["isolated_custom_code_ratio"] == 1.0
