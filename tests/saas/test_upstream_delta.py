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


def test_controller_budget_keeps_the_frozen_producer_contract(ordinary_m_finite_scope) -> None:
    import hashlib

    root = ordinary_m_finite_scope[0]
    baseline_path = root / "saas/upstream-baseline.json"
    baseline = json.loads(baseline_path.read_bytes())
    controller_path = ".github/workflows/saas-controller-source-budget.json"
    controller = json.loads((root / controller_path).read_text())
    for field in (
        "upstream_revision",
        "upstream_version",
        "adapter_contract_version",
        "patch_queue_directory",
        "downstream_owned_prefixes",
        "forbidden_upstream_prefixes",
    ):
        assert controller[field] == baseline[field]
    scope = controller["controller_budget_scope"]
    assert scope["frozen_product"] == "8c851bdd12829340b2a327cf7542fe4de84d9132"
    assert scope["frozen_product_baseline_sha256"] == (
        "ef11629c2dfed86a63928ba47de133339c41a55ae8abd70c53110cae49a3c77a"
    )
    assert (
        scope["current_controller_baseline_sha256"]
        == hashlib.sha256(baseline_path.read_bytes()).hexdigest()
    )
    assert scope["frozen_producer_control_revision"] == "7463d1eb1657f9f702b30be4ba3d5bcbafc04bf5"
    budget = dict(baseline["source_intrusion_budget"])
    assert scope["frozen_product_file_ceiling"] == 226
    finite = "ordinary_m_native_0142_finite_approval" in baseline
    approved_budget = ordinary_m_finite_scope[1]["source_intrusion_budget"]
    expected_files, expected_loc = (
        (
            approved_budget["max_direct_upstream_files"],
            approved_budget["max_upstream_net_added_loc"],
        )
        if finite
        else (230, 7090)
    )
    assert budget["max_direct_upstream_files"] == expected_files
    assert budget["max_upstream_net_added_loc"] == expected_loc
    assert scope["current_controller_file_ceiling"] == expected_files
    assert controller["source_intrusion_budget"] == budget
    workflow = (root / ".github/workflows/saas-upstream-compat.yml").read_text()
    assert f"--manifest {controller_path}" in workflow
    file_limit = "direct upstream file budget exceeded"
    loc_limit = "upstream net-added LOC budget exceeded"
    for count, loc, violations in (
        (expected_files, expected_loc, []),
        (expected_files + 1, expected_loc, [file_limit]),
        (expected_files, expected_loc + 1, [loc_limit]),
        (expected_files + 1, expected_loc + 1, [file_limit, loc_limit]),
    ):
        deltas = [
            FileDelta(f"tests/controller_case_{index}.py", loc if index == 0 else 0, 0)
            for index in range(count)
        ]
        deltas.append(FileDelta("saas/controller_budget_fixture.py", loc * 6, 0))
        result = evaluate_delta(
            deltas,
            controller,
            active_patch_count=9,
            reverse_dependencies=[],
            lineage_ok=True,
            version_ok=True,
            source_root=root,
        )
        assert result["violations"] == violations
        assert result["status"] == ("fail" if violations else "pass")


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
    ordinary_m_finite_scope,
) -> None:
    repo = ordinary_m_finite_scope[0]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    budget = manifest["source_intrusion_budget"]
    finite = "ordinary_m_native_0142_finite_approval" in manifest
    approved_budget = ordinary_m_finite_scope[1]["source_intrusion_budget"]
    expected_files, expected_loc = (
        (
            approved_budget["max_direct_upstream_files"],
            approved_budget["max_upstream_net_added_loc"],
        )
        if finite
        else (230, 7090)
    )
    assert budget["max_upstream_net_added_loc"] == expected_loc
    assert budget["max_direct_upstream_files"] == expected_files
    assert budget["max_active_patches"] == 9
    assert budget["min_isolated_custom_code_ratio"] == 0.85
    revision = manifest["source_intrusion_budget_revision"]
    recovery = revision["cloud_final_Main6cc_official_CI_recovery"]
    assert recovery["previous_max_upstream_net_added_loc"] == 5439
    assert recovery["max_upstream_net_added_loc"] == 5445
    assert recovery["accepted_main"] == "6cc0b5be7ed26193b1d6b341c246ba22b2b23902"
    composition = revision["aliyun_Main1c2_composition_20261106"]
    assert composition["accepted_main"] == "1c2a98eb0a6fed8cd30d670e8086c3b208eb1798"
    assert composition["max_upstream_net_added_loc"] == 5450
    assert composition["max_direct_upstream_files"] == 206
    locale_boundary = revision["linux_sandbox_locale_last_spawn_20261106"]
    assert locale_boundary["max_upstream_net_added_loc"] == 5577
    current = revision["final_Main579_common_locale_cloud_composition_20261106"]
    assert current["max_upstream_net_added_loc"] == 5593
    vendor = revision["fixed_host_diagnostic_vendor_security_20261106"]
    assert vendor["max_upstream_net_added_loc"] == 5602
    assert current["max_direct_upstream_files"] == 210
    assert locale_boundary["max_direct_upstream_files"] == 210
    managed_start = revision["managed_normal_start_sandbox_binding_20261107"]
    assert managed_start["previous_max_upstream_net_added_loc"] == 5602
    assert managed_start["previous_max_direct_upstream_files"] == 210
    assert managed_start["max_upstream_net_added_loc"] == 6244
    assert managed_start["max_direct_upstream_files"] == 218
    transfer = revision["managed_clear_target_binding_20261107"]
    assert transfer["previous_max_upstream_net_added_loc"] == 6244
    assert transfer["previous_max_direct_upstream_files"] == 218
    assert transfer["max_upstream_net_added_loc"] == 6528
    assert transfer["max_direct_upstream_files"] == 220
    query_scope = revision["managed_binding_query_execution_scope_20261107"]
    assert query_scope["previous_max_upstream_net_added_loc"] == 6528
    assert query_scope["previous_max_direct_upstream_files"] == 220
    assert query_scope["max_upstream_net_added_loc"] == 6529
    assert query_scope["max_direct_upstream_files"] == 220
    fixture_followup = revision["native_COW_optional_binding_fixture_20261107"]
    assert fixture_followup["previous_budget"]["max_direct_upstream_files"] == 220
    assert fixture_followup["previous_budget"]["max_upstream_net_added_loc"] == 6529
    assert fixture_followup["net_added_lines"] == 1
    assert fixture_followup["max_direct_upstream_files"] == 221
    assert fixture_followup["max_upstream_net_added_loc"] == 6530
    host_progress = revision["main_c6_host_progress_existing_budget_20261107"]
    assert host_progress["previous_max_upstream_net_added_loc"] == 5602
    assert host_progress["max_upstream_net_added_loc"] == 5604
    consolidation = revision["main30a_source2cc_consolidation_20261107"]
    assert consolidation["previous_Source_max_upstream_net_added_loc"] == 6530
    assert consolidation["previous_Main_max_upstream_net_added_loc"] == 5604
    assert consolidation["max_upstream_net_added_loc"] == 6532
    search_fixture = revision["content_search_timeout_fixture_isolation_20261108"]
    assert search_fixture["previous_max_direct_upstream_files"] == 221
    assert search_fixture["previous_max_upstream_net_added_loc"] == 6532
    assert search_fixture["max_direct_upstream_files"] == 222
    assert search_fixture["max_upstream_net_added_loc"] == 6542
    ci_recovery = revision["ci_pinned_browser_indexes_and_finished_turn_20261109"]
    assert ci_recovery["previous_max_direct_upstream_files"] == 222
    assert ci_recovery["previous_max_upstream_net_added_loc"] == 6542
    assert ci_recovery["max_direct_upstream_files"] == 223
    assert ci_recovery["max_upstream_net_added_loc"] == 6561
    tcp_recovery = revision["tcp_transport_owned_listener_20261109"]
    assert tcp_recovery["previous_max_direct_upstream_files"] == 223
    assert tcp_recovery["previous_max_upstream_net_added_loc"] == 6561
    assert tcp_recovery["max_direct_upstream_files"] == 226
    assert tcp_recovery["max_upstream_net_added_loc"] == 6685
    timewait = revision["tcp_explicit_port_timewait_compatibility_20261109"]
    assert timewait["previous_max_upstream_net_added_loc"] == 6685
    assert timewait["max_upstream_net_added_loc"] == 6772
    cold_input = revision["cold_native_input_durable_before_policy_20261109"]
    assert cold_input["previous_max_upstream_net_added_loc"] == 6772
    assert cold_input["max_upstream_net_added_loc"] == 6812
    caller_bound = revision["cold_policy_caller_bound_preserves_fast_handshake_20261109"]
    assert caller_bound["previous_max_upstream_net_added_loc"] == 6812
    assert caller_bound["max_upstream_net_added_loc"] == 6841
    host_compat = revision["ordinary_m_host_compat_20261111"]
    assert host_compat["previous_controller_max_direct_upstream_files"] == 229
    assert host_compat["previous_controller_max_upstream_net_added_loc"] == 6841
    assert host_compat["max_direct_upstream_files"] == 230
    assert host_compat["max_upstream_net_added_loc"] == 7090
    assert host_compat["candidate_source"] == "b53109e57c45363ea2cfe213f9ab1e95e7c4e29c"
    assert host_compat["authorization_source"] == {
        "state": "approved_repository_admin_decision",
        "administrator": "Dream1216",
        "approved_head": "3f19c0376366fdeea0a89da23c55d3f5741f3f5d",
    }
    assert "accepted_main" not in host_compat
    assert search_fixture["scope_paths"] == ["tests/runner/test_environment_filesystem.py"]
    assert search_fixture["accepted_main"] == "e86f4e92210468103e0b5c4e37406958498deebe"
    composer_followup = revision["upstream_composer_recovery_budget_followup"]
    assert composer_followup["approved_at"] == "2026-10-24"
    assert composer_followup["previous_max_direct_upstream_files"] == 153
    assert composer_followup["max_direct_upstream_files"] == 154
    assert composer_followup["measured_upstream_net_added_loc"] == 3600
    assert composer_followup["scoped_paths"] == [
        "web/src/pages/ChatPage.tsx",
        "web/src/pages/ChatPage.composer.test.tsx",
    ]
    assert composer_followup["new_official_path"] == "web/src/pages/ChatPage.composer.test.tsx"
    assert composer_followup["upstream_revision"] == "3138c7dfeb24a12f2aaf6d7ffeffc9d491d69df1"
    followup = revision["followup"]
    assert followup["revision"] == "upstream-019-mcp-compat-version-test-budget-v35"
    assert followup["approved_at"] == "2026-10-21"
    assert followup["governance_mode"] == "single_owner_beta"
    assert followup["previous_max_direct_upstream_files"] == 155
    assert followup["measured_direct_upstream_files"] == 156
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3453
    assert followup["scoped_paths"] == ["tests/e2e/test_mcp_registry_compat_e2e.py"]
    followup = followup["previous_revision"]
    assert followup["revision"] == "upstream-019-toast-cleanup-test-budget-v34"
    assert followup["approved_at"] == "2026-10-16"
    assert followup["governance_mode"] == "single_owner_beta"
    assert followup["previous_max_direct_upstream_files"] == 154
    assert followup["measured_direct_upstream_files"] == 155
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3416
    assert followup["scoped_paths"] == ["web/src/shell/archiveUndoToast.test.tsx"]
    followup = followup["previous_revision"]
    assert followup["revision"] == "upstream-019-abrupt-death-test-budget-v33"
    assert followup["approved_at"] == "2026-10-16"
    assert followup["governance_mode"] == "single_owner_beta"
    assert followup["previous_max_direct_upstream_files"] == 153
    assert followup["measured_direct_upstream_files"] == 154
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3415
    assert followup["scoped_paths"] == ["tests/inner/test_brokered_auth_abrupt_death.py"]
    followup = followup["previous_revision"]
    assert followup["revision"] == "upstream-019-terminal-reconnect-test-budget-v32"
    assert followup["approved_at"] == "2026-10-16"
    assert followup["governance_mode"] == "single_owner_beta"
    assert followup["previous_max_direct_upstream_files"] == 152
    assert followup["measured_direct_upstream_files"] == 153
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3409
    assert followup["scoped_paths"] == ["tests/e2e_ui/shells/test_terminal_bridge_reconnect.py"]
    assert followup["previous_revision_reference"] == "upstream-019-reviewed-visual-budget-v31"
    followup = revision["previous_followup"]
    assert followup["revision"] == "upstream-019-reviewed-visual-budget-v31"
    assert followup["approved_at"] == "2026-10-16"
    assert followup["governance_mode"] == "single_owner_beta"
    assert followup["previous_max_direct_upstream_files"] == 150
    assert followup["measured_direct_upstream_files"] == 152
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["measured_upstream_net_added_loc"] == 3389
    assert followup["scoped_paths"] == [
        "web/src/lib/identity.managedRouting.test.ts",
        "web/src/lib/viteProxy.test.ts",
        "tests/e2e_ui/visual/snapshots/test_chat_snapshot/test_chat_conversation_matches_baseline/test_chat_conversation_matches_baseline[chromium][linux].png",
        "tests/e2e_ui/visual/snapshots/test_chat_turn_rail_snapshot/test_chat_turn_rail_matches_baseline/test_chat_turn_rail_matches_baseline[chromium][linux].png",
        "tests/e2e_ui/visual/snapshots/test_landing_snapshot/test_empty_landing_matches_baseline/test_empty_landing_matches_baseline[chromium][linux].png",
        "tests/e2e_ui/visual/snapshots/test_sidebar_flyout_snapshot/test_pinned_project_flyout_matches_baseline/test_pinned_project_flyout_matches_baseline[chromium][linux].png",
        "tests/e2e_ui/visual/snapshots/test_sidebar_snapshot/test_populated_sidebar_matches_baseline/test_populated_sidebar_matches_baseline[chromium][linux].png",
    ]
    followup = followup["previous_revision"]
    assert followup["revision"] == "platform-model-token-renewal-budget-v30"
    assert followup["approved_at"] == "2026-10-15"
    assert followup["previous_max_direct_upstream_files"] == 148
    assert followup["measured_direct_upstream_files"] == 150
    assert followup["previous_max_upstream_net_added_loc"] == 4576
    assert followup["scoped_paths"] == [
        "web/src/components/blocks/StatusBlocks.tsx",
        "web/src/components/blocks/StatusBlocks.test.tsx",
    ]
    followup = followup["previous_revision"]
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
            FileDelta(
                "omnigent/stores/host_store.py",
                budget["max_upstream_net_added_loc"] + extra_lines,
                0,
            ),
            FileDelta(
                "saas/control_plane/service.py", budget["max_upstream_net_added_loc"] * 6, 0
            ),
        ],
        manifest,
        active_patch_count=9,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
        source_root=repo,
    )
    assert report["status"] == ("fail" if extra_lines else "pass")
    assert report["violations"] == (
        ["upstream net-added LOC budget exceeded"] if extra_lines else []
    )


@pytest.mark.parametrize("extra_files", [0, 1])
def test_dependency_security_budget_revision_retains_a_hard_file_ceiling(
    extra_files: int,
    ordinary_m_finite_scope,
) -> None:
    repo = ordinary_m_finite_scope[0]
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    file_count = manifest["source_intrusion_budget"]["max_direct_upstream_files"] + extra_files
    report = evaluate_delta(
        [FileDelta(f"omnigent/budget_probe_{index}.py", 0, 0) for index in range(file_count)],
        manifest,
        active_patch_count=7,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
        source_root=repo,
    )
    assert report["status"] == ("fail" if extra_files else "pass")
    assert report["violations"] == (
        ["direct upstream file budget exceeded"] if extra_files else []
    )


def test_e2e_ui_governance_files_are_downstream_owned(ordinary_m_finite_scope) -> None:
    repo = ordinary_m_finite_scope[0]
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
        source_root=repo,
    )
    assert report["status"] == "pass"
    assert report["metrics"]["direct_upstream_file_count"] == 0
    assert report["metrics"]["upstream_net_added_loc"] == 0
    assert report["metrics"]["isolated_custom_code_ratio"] == 1.0


@pytest.mark.parametrize(("downstream_lines", "expected"), [(566, "fail"), (567, "pass")])
def test_source_isolation_floor_remains_enforced_at_085(
    downstream_lines: int,
    expected: str,
) -> None:
    report = evaluate_delta(
        [
            FileDelta("omnigent/stores/host_store.py", 100, 0),
            FileDelta("saas/control_plane/service.py", downstream_lines, 0),
        ],
        _manifest(),
        active_patch_count=0,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
    )
    assert report["status"] == expected
    assert report["violations"] == (
        ["isolated custom-code ratio is below budget"] if expected == "fail" else []
    )


@pytest.fixture
def ordinary_m_finite_scope(monkeypatch: pytest.MonkeyPatch):
    from saas.scripts import check_upstream_delta as guard

    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "saas/upstream-baseline.json").read_text())
    scope = json.loads((root / guard._ORDINARY_M_SCOPE_PATH).read_text())
    manifest["source_intrusion_budget"] = dict(scope["budgets"])
    # This synthetic unit decision is never written into an adopted manifest.
    manifest[guard._ORDINARY_M_APPROVAL] = {
        "candidate_manifest_sha256": guard._ORDINARY_M_CANDIDATE,
        "decision": "approved",
        "approver": "Dream1216",
        "authority_record_sha256": "1" * 64,
    }
    budget = scope["budgets"]
    deltas = [FileDelta(guard._ORDINARY_M_PROTECTED_PATH, budget["max_upstream_net_added_loc"], 0)]
    deltas.extend(
        FileDelta(f"omnigent/finite_case_{index}.py", 0, 0)
        for index in range(budget["max_direct_upstream_files"] - 1)
    )
    deltas.append(FileDelta("saas/finite_fixture.py", 100000, 0))
    base_changes = [
        FileDelta(path, 1, 0)
        for path in [*(item["path"] for item in scope["files"]), *scope["governance_paths"]]
    ]
    monkeypatch.setattr(guard, "_git", lambda repo, *args: "")
    monkeypatch.setattr(
        guard,
        "collect_deltas",
        lambda repo, revision: base_changes if revision == scope["public_base"] else deltas,
    )
    return root, manifest, deltas, base_changes


@pytest.mark.parametrize(
    "fault",
    [
        "valid",
        "prepared",
        "missing",
        "candidate",
        "author",
        "old-authority",
        "previous-47-authority",
        "scope-bytes",
        "protected-bytes",
        "other-source-bytes",
        "symlink",
    ],
)
def test_ordinary_m_finite_approval_checks_exact_current_sources(
    ordinary_m_finite_scope,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    from saas.scripts import check_upstream_delta as guard

    root, manifest, deltas, _base_changes = ordinary_m_finite_scope
    decision = manifest[guard._ORDINARY_M_APPROVAL]
    if fault == "prepared":
        decision["decision"] = "prepared"
    elif fault == "missing":
        manifest.pop(guard._ORDINARY_M_APPROVAL)
    elif fault == "candidate":
        decision["candidate_manifest_sha256"] = "0" * 64
    elif fault == "author":
        decision["approver"] = "another-user"
    elif fault == "old-authority":
        decision["authority_record_sha256"] = (
            "7eccc6a1d1b7ca911fefe925a7172252380ee504e1fb8fbd71c77cb428f7c480"
        )
    elif fault == "previous-47-authority":
        decision["authority_record_sha256"] = (
            "0c954b1d83804bafaf78142c42a27eef16f63e7be1dbe2cce3eed6a69e14d025"
        )
    target = {
        "scope-bytes": root / guard._ORDINARY_M_SCOPE_PATH,
        "protected-bytes": root / guard._ORDINARY_M_PROTECTED_PATH,
        "other-source-bytes": root / "omnigent/harnesses/codex_native/executor_worker.py",
        "symlink": root / guard._ORDINARY_M_PROTECTED_PATH,
    }.get(fault)
    if target is not None:
        if fault == "symlink":
            original = Path.is_symlink
            monkeypatch.setattr(Path, "is_symlink", lambda path: path == target or original(path))
        else:
            original_read = Path.read_bytes

            def changed_bytes(path):
                data = original_read(path)
                if path != target:
                    return data
                if fault == "scope-bytes":
                    return data + b"changed"
                return data[:-1] + bytes([data[-1] ^ 1])

            monkeypatch.setattr(Path, "read_bytes", changed_bytes)
    result = evaluate_delta(
        deltas,
        manifest,
        active_patch_count=9,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
        source_root=root,
    )
    assert (
        result["metrics"]["direct_upstream_file_count"]
        == manifest["source_intrusion_budget"]["max_direct_upstream_files"]
    )
    assert (
        result["metrics"]["upstream_net_added_loc"]
        == manifest["source_intrusion_budget"]["max_upstream_net_added_loc"]
    )
    assert result["metrics"]["forbidden_upstream_files"] == [guard._ORDINARY_M_PROTECTED_PATH]
    assert result["status"] == ("pass" if fault == "valid" else "fail")
    assert result["approved_protected_sources"] == (
        [guard._ORDINARY_M_PROTECTED_PATH] if fault == "valid" else []
    )


@pytest.mark.parametrize(
    "fault",
    [
        "other-protected",
        "file-overflow",
        "loc-overflow",
        "patch-overflow",
        "isolation-floor",
        "reverse-dependency",
        "lineage",
        "version",
    ],
)
def test_ordinary_m_finite_approval_keeps_other_original_gates(
    ordinary_m_finite_scope,
    fault: str,
) -> None:
    root, manifest, deltas, _base_changes = ordinary_m_finite_scope
    patches, reverse, lineage, version = 9, [], True, True
    if fault == "other-protected":
        deltas.append(FileDelta("omnigent/runner/native/another.py", 0, 0))
    elif fault == "file-overflow":
        deltas.append(FileDelta("omnigent/extra_case.py", 0, 0))
    elif fault == "loc-overflow":
        deltas[0] = FileDelta(
            deltas[0].path,
            manifest["source_intrusion_budget"]["max_upstream_net_added_loc"] + 1,
            0,
        )
    elif fault == "patch-overflow":
        patches = 10
    elif fault == "isolation-floor":
        deltas[-1] = FileDelta("saas/finite_fixture.py", 1, 0)
    elif fault == "reverse-dependency":
        reverse = ["omnigent/forbidden_import.py"]
    elif fault == "lineage":
        lineage = False
    elif fault == "version":
        version = False
    result = evaluate_delta(
        deltas,
        manifest,
        active_patch_count=patches,
        reverse_dependencies=reverse,
        lineage_ok=lineage,
        version_ok=version,
        source_root=root,
    )
    assert result["status"] == "fail"
    if fault == "other-protected":
        assert "omnigent/runner/native/another.py" in result["metrics"]["forbidden_upstream_files"]
        assert "forbidden Agent/Harness/Native Bridge paths were modified" in result["violations"]


def test_ordinary_m_normal_cli_consumes_only_complete_record(
    ordinary_m_finite_scope,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    from saas.scripts import check_upstream_delta as guard

    root, manifest, deltas, _base_changes = ordinary_m_finite_scope

    def read_git(repo, *args):
        if args[:2] == ("merge-base", "--is-ancestor"):
            return ""
        assert args in {
            ("rev-parse", "--show-toplevel"),
            ("rev-parse", "HEAD"),
        }
        return str(root) if args[-1] == "--show-toplevel" else "synthetic-unit-head"

    monkeypatch.setattr(guard, "_git", read_git)
    monkeypatch.setattr(guard, "_load_manifest", lambda path: manifest)
    monkeypatch.setattr(
        guard,
        "collect_deltas",
        lambda repo, revision: _base_changes if revision.startswith("aadd44ed") else deltas,
    )
    monkeypatch.setattr(guard, "scan_reverse_dependencies", lambda repo, paths: [])
    monkeypatch.setattr(guard.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    monkeypatch.setattr(guard.sys, "argv", ["check_upstream_delta.py"])
    assert guard.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["approved_protected_sources"] == [guard._ORDINARY_M_PROTECTED_PATH]
    assert (
        result["metrics"]["direct_upstream_file_count"]
        == manifest["source_intrusion_budget"]["max_direct_upstream_files"]
    )
    manifest[guard._ORDINARY_M_APPROVAL]["decision"] = "prepared"
    assert guard.main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "fail"


@pytest.mark.parametrize("fault", ["existing-source-net-zero", "forbidden-controls"])
def test_ordinary_m_finite_approval_rejects_other_candidate_and_rule_drift(
    ordinary_m_finite_scope,
    fault: str,
) -> None:

    root, manifest, deltas, base_changes = ordinary_m_finite_scope
    if fault == "existing-source-net-zero":
        # Already counted upstream file: same file count and net LOC after an edit.
        deltas[1] = FileDelta("omnigent/cli.py", 1, 1)
        base_changes.append(FileDelta("omnigent/cli.py", 1, 1))
    else:
        manifest["forbidden_upstream_prefixes"] = []
    result = evaluate_delta(
        deltas,
        manifest,
        active_patch_count=9,
        reverse_dependencies=[],
        lineage_ok=True,
        version_ok=True,
        source_root=root,
    )
    assert (
        result["metrics"]["direct_upstream_file_count"]
        == manifest["source_intrusion_budget"]["max_direct_upstream_files"]
    )
    assert (
        result["metrics"]["upstream_net_added_loc"]
        == manifest["source_intrusion_budget"]["max_upstream_net_added_loc"]
    )
    assert result["status"] == "fail"
    assert "ordinary M finite source approval is missing or mismatched" in result["violations"]
