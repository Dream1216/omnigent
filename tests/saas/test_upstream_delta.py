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
    assert report["patch_count"] == 9
    assert report["covered_paths"] == report["official_source_paths"]


@pytest.mark.parametrize("extra_lines", [0, 1])
def test_next_preview_agent_budget_revision_retains_hard_source_ceilings(
    extra_lines: int,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    budget = manifest["source_intrusion_budget"]
    assert budget["max_upstream_net_added_loc"] == 4576
    assert budget["max_direct_upstream_files"] == 148
    assert budget["max_active_patches"] == 9
    assert budget["min_isolated_custom_code_ratio"] == 0.85
    revision = manifest["source_intrusion_budget_revision"]
    followup = revision["followup"]
    assert followup["revision"] == "runtime-security-dependency-budget-v29"
    assert followup["previous_max_direct_upstream_files"] == 144
    assert followup["previous_measured_direct_upstream_files"] == 143
    assert followup["measured_direct_upstream_files"] == 148
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3221
    assert followup["scoped_paths"] == [
        ".github/workflows/ui-snapshot.yml",
        "deploy/docker/Dockerfile.ubi",
        "package.json",
        "tests/e2e_ui/visual/regen_baseline_docker.sh",
        "tests/test_setup_web_ui_build.py",
    ]
    followup = followup["previous_revision"]
    assert followup["revision"] == "next-agent-gate-missing-bundle-v28"
    assert followup["previous_max_upstream_net_added_loc"] == 4568
    assert followup["measured_upstream_net_added_loc"] == 4576
    assert followup["scoped_delta"] == {
        "omnigent/server/routes/_sessions/orchestration.py": 8,
    }
    assert revision["revision"] == "next-csrf-cross-tab-budget-v27"
    assert revision["previous_max_active_patches"] == 9
    assert revision["previous_max_direct_upstream_files"] == 144
    assert revision["previous_max_upstream_net_added_loc"] == 4518
    assert revision["previous_measured_upstream_net_added_loc"] == 4518
    assert revision["scoped_csrf_delta"] == {
        "web/src/lib/identity.ts": 19,
        "web/src/lib/identity.test.ts": 31,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "next-agent-null-harness-gate-v26"
    assert revision["previous_max_active_patches"] == 9
    assert revision["previous_max_direct_upstream_files"] == 126
    assert revision["previous_max_upstream_net_added_loc"] == 4396
    assert revision["previous_measured_upstream_net_added_loc"] == 4396
    assert revision["scoped_agent_delta"] == {
        "omnigent/server/routes/_sessions/orchestration.py": 5,
        "tests/e2e_ui/chat/test_hide_unconfigured_harnesses.py": 50,
        "tests/e2e_ui/sessions/test_initial_prompt_session_switch.py": 0,
        "tests/e2e_ui/sessions/test_new_session_optimistic_title.py": 0,
        "tests/e2e_ui/start_session/test_codex_bypass_agent_switch.py": 0,
        "tests/e2e_ui/start_session/test_create_agent_focus_ring_clipping.py": 0,
        "tests/e2e_ui/start_session/test_create_custom_agent.py": 0,
        "tests/e2e_ui/start_session/test_project_config_prefill.py": 0,
        "tests/e2e_ui/start_session/test_start_session.py": 0,
        "tests/e2e_ui/visual/test_landing_snapshot.py": 0,
        "tests/e2e_ui/visual/test_sidebar_flyout_snapshot.py": 0,
        "tests/e2e_ui/visual/test_sidebar_snapshot.py": 0,
        "tests/server/routes/test_session_create_project_consistency.py": 6,
        "tests/server/routes/test_sessions_cost_labels.py": 15,
        "web/src/lib/harnessSetup.test.ts": 21,
        "web/src/lib/harnessSetup.ts": 13,
        "web/src/shell/NewChatDialog.flow.test.tsx": 0,
        "web/src/shell/NewChatDialog.projectCreate.test.tsx": 7,
        "web/src/shell/NewChatDialog.projectPrefill.test.tsx": 0,
        "web/src/shell/NewChatDialog.test.tsx": 0,
        "web/src/shell/NewChatDialog.tsx": 5,
        "web/src/shell/NewChatLandingScreen.mobileChrome.test.tsx": 0,
        "web/src/shell/ProjectSettingsDialog.test.tsx": 0,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "next-agent-admission-e2e-closure-v25"
    assert revision["previous_max_active_patches"] == 9
    assert revision["previous_max_direct_upstream_files"] == 122
    assert revision["previous_max_upstream_net_added_loc"] == 4391
    assert revision["previous_measured_upstream_net_added_loc"] == 4391
    revision = revision["previous_revision"]
    assert revision["revision"] == "next-agent-picker-browser-coverage-v24"
    assert revision["previous_max_active_patches"] == 9
    assert revision["previous_max_direct_upstream_files"] == 120
    assert revision["previous_max_upstream_net_added_loc"] == 4327
    assert revision["previous_measured_upstream_net_added_loc"] == 4327
    assert revision["scoped_browser_delta"] == {
        "tests/e2e_ui/chat/test_agent_picker_version.py": 64,
        (
            "tests/e2e_ui/visual/snapshots/test_storybook_snapshot/"
            "test_story_matches_baseline/"
            "test_story_matches_baseline[chromium-components-agents-"
            "agentharnesspicker--needs-setup-badges][linux].png"
        ): 0,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "next-agent-create-readiness-admission-v23"
    assert revision["previous_max_active_patches"] == 9
    assert revision["previous_max_direct_upstream_files"] == 118
    assert revision["previous_max_upstream_net_added_loc"] == 4139
    assert revision["previous_measured_upstream_net_added_loc"] == 4139
    assert revision["scoped_admission_delta"] == {
        "omnigent/server/routes/_sessions/orchestration.py": 59,
        "omnigent/server/routes/sessions/routes_core.py": 14,
        "tests/server/integration/test_session_host_launch.py": 80,
        "web/src/components/composer/HarnessPicker.tsx": 15,
        "web/src/shell/NewChatDialog.test.tsx": 22,
        "web/src/shell/NewChatDialog.tsx": -2,
    }
    previous = revision["previous_revision"]
    assert previous["revision"] == "next-preview-agent-session-reliability-v22"
    assert previous["scoped_agent_delta"] == {
        "omnigent/host/connect.py": -120,
        "omnigent/host/runner_zygote.py": 10,
        "omnigent/onboarding/harness_readiness.py": 251,
        "omnigent/runtime/pending_inputs.py": 52,
        "omnigent/server/routes/_sessions/orchestration.py": 52,
        "omnigent/server/routes/sessions/routes_core.py": 53,
        "tests/host/test_orphan_reaper.py": 227,
        "tests/onboarding/test_harness_readiness.py": 37,
        "tests/runtime/test_pending_inputs.py": 33,
        "tests/server/integration/test_sessions_endpoints.py": 158,
        "web/src/lib/capabilities.test.ts": 7,
        "web/src/lib/capabilities.ts": 1,
        "web/src/lib/harnessSetup.test.ts": 137,
        "web/src/lib/harnessSetup.ts": 90,
        "web/src/shell/NewChatDialog.test.tsx": 75,
        "web/src/shell/NewChatDialog.tsx": 40,
    }
    revision = previous["previous_revision"]
    assert revision["revision"] == "pnpm-cache-only-ci-post-job-v21"
    assert revision["previous_max_direct_upstream_files"] == 106
    assert revision["previous_max_upstream_net_added_loc"] == 3032
    assert revision["previous_measured_upstream_net_added_loc"] == 3032
    assert revision["scoped_ci_delta"] == {
        ".github/actions/setup-pnpm/action.yml": 4,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "bilingual-visual-baselines-v20"
    assert revision["previous_max_direct_upstream_files"] == 101
    assert revision["previous_max_upstream_net_added_loc"] == 3032
    assert revision["previous_measured_upstream_net_added_loc"] == 3032
    assert revision["scoped_visual_delta"] == {
        (
            "tests/e2e_ui/visual/snapshots/test_chat_snapshot/"
            "test_chat_conversation_matches_baseline/"
            "test_chat_conversation_matches_baseline[chromium][linux].png"
        ): 0,
        (
            "tests/e2e_ui/visual/snapshots/test_chat_turn_rail_snapshot/"
            "test_chat_turn_rail_matches_baseline/"
            "test_chat_turn_rail_matches_baseline[chromium][linux].png"
        ): 0,
        (
            "tests/e2e_ui/visual/snapshots/test_landing_snapshot/"
            "test_empty_landing_matches_baseline/"
            "test_empty_landing_matches_baseline[chromium][linux].png"
        ): 0,
        (
            "tests/e2e_ui/visual/snapshots/test_sidebar_flyout_snapshot/"
            "test_pinned_project_flyout_matches_baseline/"
            "test_pinned_project_flyout_matches_baseline[chromium][linux].png"
        ): 0,
        (
            "tests/e2e_ui/visual/snapshots/test_sidebar_snapshot/"
            "test_populated_sidebar_matches_baseline/"
            "test_populated_sidebar_matches_baseline[chromium][linux].png"
        ): 0,
    }
    revision = revision["previous_revision"]
    assert revision["revision"] == "bilingual-authenticated-interface-v19"
    assert revision["previous_max_direct_upstream_files"] == 88
    assert revision["previous_max_upstream_net_added_loc"] == 2579
    assert revision["previous_measured_upstream_net_added_loc"] == 2477
    assert revision["scoped_frontend_delta"] == {
        "tests/e2e_ui/i18n/__init__.py": 0,
        "tests/e2e_ui/i18n/test_language_switching.py": 43,
        "web/src/components/LanguageSwitcher.test.tsx": 47,
        "web/src/components/LanguageSwitcher.tsx": 101,
        "web/src/embed.tsx": 3,
        "web/src/lib/branding.ts": 2,
        "web/src/lib/i18n.test.tsx": 76,
        "web/src/lib/i18n.tsx": 212,
        "web/src/main.tsx": 3,
        "web/src/pages/SettingsPage.tsx": 5,
        "web/src/shell/NewChatDialog.tsx": 25,
        "web/src/shell/Sidebar.test.tsx": 4,
        "web/src/shell/Sidebar.tsx": 3,
        "web/src/shell/SidebarHeaderActions.tsx": 6,
        "web/src/shell/settingsNav.tsx": 25,
    }
    revision = revision["previous_revision"]
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
            FileDelta("omnigent/stores/host_store.py", 4576 + extra_lines, 0),
            FileDelta("saas/control_plane/service.py", 30000, 0),
        ],
        manifest,
        active_patch_count=9,
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
