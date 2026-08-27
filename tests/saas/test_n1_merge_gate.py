from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = REPO_ROOT / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
WORKFLOW = REPO_ROOT / ".github/workflows/saas-n1-merge-gate.yml"
GENERAL_MERGE_READY = REPO_ROOT / ".github/workflows/merge-ready.yml"


def _run_early_gate(tmp_path: Path, changed_file: str) -> subprocess.CompletedProcess[str]:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "pr").write_text(f"open\t{'a' * 40}\tmain\t{'b' * 40}\t1\n", encoding="utf-8")
    (fixtures / "files").write_text(f"{changed_file}\t\n", encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'/pulls/123/files'* ]]; then
  cat "$FAKE_GH_FIXTURES/files"
elif [[ "$args" == *'/pulls/123'* ]]; then
  cat "$FAKE_GH_FIXTURES/pr"
else
  echo "unexpected gh invocation: $args" >&2
  exit 2
fi
""",
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)

    env = os.environ.copy()
    env.update(
        {
            "FAKE_GH_FIXTURES": str(fixtures),
            "GH_TOKEN": "test-token",
            "PATH": f"{bin_dir}:{env['PATH']}",
            "PR": "123",
            "REPO": "Dream1216/omnigent",
            "SHA": "a" * 40,
        }
    )
    return subprocess.run(
        ["bash", str(EVALUATOR)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _run_full_gate(
    tmp_path: Path,
    *,
    conclusion: str | None = "success",
    workflow_status: str = "completed",
    workflow_conclusion: str = "success",
    trusted_app: bool = True,
    tamper_workflow: bool = False,
    tamper_harness: bool = False,
    run_base_sha: str | None = None,
    run_attempt: str = "1",
    job_attempt: str | None = None,
    workflow_id: str = "342012814",
    registry_id: str = "342012814",
    registry_name: str = "SaaS N-1 compatibility image",
    registry_path: str = ".github/workflows/saas-n1-compat-image.yml",
    registry_state: str = "active",
    actions_app_id: str = "15368",
    run_check_suite_id: str = "7001",
    check_suite_id: str | None = None,
    observed_job_id: str = "8001",
    older_successful_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    head_sha = "a" * 40
    base_sha = "b" * 40
    observed_base_sha = run_base_sha or base_sha
    observed_job_attempt = job_attempt or run_attempt
    observed_check_suite_id = check_suite_id or run_check_suite_id
    title = f"SaaS N-1 pull_request pr=123 base={observed_base_sha} head={head_sha}"
    (fixtures / "pr").write_text(f"open\t{head_sha}\tmain\t{base_sha}\t1\n", encoding="utf-8")
    (fixtures / "files").write_text(
        "saas/control_plane/postgresql_roles.sql\t\n", encoding="utf-8"
    )
    (fixtures / "workflow").write_text(
        "\t".join((registry_id, registry_name, registry_path, registry_state)) + "\n",
        encoding="utf-8",
    )
    run_rows: list[str] = []
    if older_successful_run:
        run_rows.append(
            "\t".join(
                (
                    "8999",
                    "1",
                    "completed",
                    "success",
                    workflow_id,
                    title,
                    ".github/workflows/saas-n1-compat-image.yml",
                    "pull_request",
                    head_sha,
                )
            )
        )
    run_rows.append(
        "\t".join(
            (
                "9001",
                run_attempt,
                workflow_status,
                workflow_conclusion,
                workflow_id,
                title,
                ".github/workflows/saas-n1-compat-image.yml",
                "pull_request",
                head_sha,
            )
        )
    )
    (fixtures / "runs").write_text("\n".join(run_rows) + "\n", encoding="utf-8")
    if conclusion is None:
        (fixtures / "checks").write_text("", encoding="utf-8")
    else:
        app = "github-actions" if trusted_app else "untrusted-app"
        (fixtures / "checks").write_text(
            "\t".join(
                (
                    "8001",
                    "completed",
                    conclusion,
                    "https://github.com/Dream1216/omnigent/actions/runs/9001/job/8001",
                    actions_app_id,
                    app,
                    observed_check_suite_id,
                )
            )
            + "\n",
            encoding="utf-8",
        )
    (fixtures / "run").write_text(
        "\t".join(
            (
                workflow_id,
                title,
                ".github/workflows/saas-n1-compat-image.yml",
                "pull_request",
                workflow_status,
                workflow_conclusion,
                head_sha,
                "9001",
                run_attempt,
                run_check_suite_id,
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (fixtures / "job").write_text(
        "\t".join(
            (
                observed_job_id,
                "verify-postgresql-n1",
                "completed",
                conclusion or "null",
                head_sha,
                "9001",
                observed_job_attempt,
            )
        )
        + "\n",
        encoding="utf-8",
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'/pulls/123/files'* ]]; then
  cat "$FAKE_GH_FIXTURES/files"
elif [[ "$args" == *'/pulls/123'* ]]; then
  cat "$FAKE_GH_FIXTURES/pr"
elif [[ "$args" == *'/contents/.github/workflows/saas-n1-compat-image.yml?ref='* ]]; then
  if [[ "$FAKE_TAMPER_WORKFLOW" == 1 ]]; then
    printf 'tampered\n'
  else
    grep '^POSTGRESQL_N1_WORKFLOW_SHA256=' "$FAKE_EVALUATOR" | cut -d'"' -f2
  fi
elif [[ "$args" =~ /contents/([^?]+)\?ref= ]]; then
  path="${BASH_REMATCH[1]}"
  if [[ "$path" == tests/saas/test_n1_outbox_admission.py ]] \
    && [[ "$FAKE_TAMPER_HARNESS" == 1 ]]; then
    printf 'tampered\n'
  else
    grep -F "\"$path|" "$FAKE_EVALUATOR" | head -n1 | cut -d'|' -f2 | cut -d'"' -f1
  fi
elif [[ "$args" == *'/actions/workflows/342012814/runs?'* ]]; then
  cat "$FAKE_GH_FIXTURES/runs"
elif [[ "$args" == *'/actions/workflows/342012814'* ]]; then
  cat "$FAKE_GH_FIXTURES/workflow"
elif [[ "$args" == *'/check-runs'* ]]; then
  cat "$FAKE_GH_FIXTURES/checks"
elif [[ "$args" == *'/actions/runs/9001'* ]]; then
  cat "$FAKE_GH_FIXTURES/run"
elif [[ "$args" == *'/actions/jobs/8001'* ]]; then
  cat "$FAKE_GH_FIXTURES/job"
else
  echo "unexpected gh invocation: $args" >&2
  exit 2
fi
""",
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    shasum = bin_dir / "shasum"
    shasum.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
read -r value || true
if [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s  -\n' "$value"
else
  printf '%064d  -\n' 0
fi
""",
        encoding="utf-8",
    )
    shasum.chmod(shasum.stat().st_mode | stat.S_IXUSR)

    env = os.environ.copy()
    env.update(
        {
            "FAKE_EVALUATOR": str(EVALUATOR),
            "FAKE_GH_FIXTURES": str(fixtures),
            "FAKE_TAMPER_HARNESS": "1" if tamper_harness else "0",
            "FAKE_TAMPER_WORKFLOW": "1" if tamper_workflow else "0",
            "GH_TOKEN": "test-token",
            "PATH": f"{bin_dir}:{env['PATH']}",
            "PR": "123",
            "REPO": "Dream1216/omnigent",
            "SHA": head_sha,
        }
    )
    return subprocess.run(
        ["bash", str(EVALUATOR)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_standalone_gate_is_main_side_and_posts_exact_head_status() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {
        "pull_request_target",
        "workflow_run",
    }
    assert workflow["on"]["workflow_run"]["workflows"] == ["SaaS N-1 compatibility image"]
    assert workflow["on"]["workflow_run"]["types"] == [
        "requested",
        "in_progress",
        "completed",
    ]
    job = workflow["jobs"]["evaluate"]
    assert job["permissions"]["statuses"] == "write"
    checkout = next(step for step in job["steps"] if step.get("name") == "Check out trusted gate")
    assert checkout["with"]["ref"] == "main"
    assert checkout["with"]["persist-credentials"] == "false"
    post = next(step for step in job["steps"] if step.get("name") == "Post exact-head gate status")
    assert post["env"]["SHA"] == "${{ steps.context.outputs.sha }}"
    assert 'context="SaaS N-1 Merge Ready"' in post["run"]
    assert '"$CURRENT_BASE_SHA" == "$BASE_SHA"' in post["run"]
    assert '"$CURRENT_HEAD_SHA" == "$SHA"' in post["run"]
    pending = next(
        step for step in job["steps"] if step.get("name") == "Mark non-completed N-1 run pending"
    )
    assert "github.event.action != 'completed'" in pending["if"]
    assert "-f state=pending" in pending["run"]
    assert '-f target_url="$TARGET_URL"' in pending["run"]
    evaluator = EVALUATOR.read_text(encoding="utf-8")
    assert "AUTHORITATIVE_RUN_ATTEMPT" in evaluator
    assert 'POSTGRESQL_N1_WORKFLOW_ID="342012814"' in evaluator
    assert 'POSTGRESQL_N1_ACTIONS_APP_ID="15368"' in evaluator
    assert ".workflow_id | tostring" in evaluator
    assert ".workflow_runs[].name" not in evaluator
    assert ".workflow_name" not in evaluator
    assert "/actions/workflows/$POSTGRESQL_N1_WORKFLOW_ID/runs?" in evaluator
    assert "run_name" not in evaluator
    assert "job_workflow_name" not in evaluator


def test_general_merge_ready_dispatch_cannot_select_an_arbitrary_sha() -> None:
    workflow = yaml.load(GENERAL_MERGE_READY.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert "sha" not in workflow["on"]["workflow_dispatch"]["inputs"]
    resolve = next(
        step
        for step in workflow["jobs"]["evaluate"]["steps"]
        if step.get("name") == "Resolve PR + head SHA"
    )
    assert "SHA_INPUT" not in resolve["env"]
    assert 'SHA=$(gh pr view "$PR"' in resolve["run"]


def test_policy_change_cannot_self_approve(tmp_path: Path) -> None:
    result = _run_early_gate(
        tmp_path,
        ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh",
    )

    assert result.returncode == 1
    assert "gate policy changes require an explicit administrator merge" in result.stdout


def test_committed_virtual_environment_is_rejected(tmp_path: Path) -> None:
    result = _run_early_gate(tmp_path, ".venv/bin/python")

    assert result.returncode == 1
    assert "Committed .uv/.venv state requires an explicit administrator merge" in result.stdout


def test_untrusted_workflow_change_requires_administrator_merge(tmp_path: Path) -> None:
    result = _run_early_gate(tmp_path, ".github/workflows/evil-status.yml")

    assert result.returncode == 1
    assert "GitHub Actions policy changes require an explicit administrator merge" in result.stdout


def test_full_gate_accepts_exact_latest_success(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Trusted PostgreSQL N-1 check accepted" in result.stdout


def test_full_gate_rejects_wrong_workflow_id(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, workflow_id="999999999")

    assert result.returncode == 1
    assert "exact PostgreSQL N-1 workflow run is missing" in result.stdout


@pytest.mark.parametrize(
    "overrides",
    (
        {"registry_id": "999999999"},
        {"registry_name": "renamed"},
        {"registry_path": ".github/workflows/other.yml"},
        {"registry_state": "disabled_manually"},
    ),
)
def test_full_gate_rejects_workflow_registry_drift(
    tmp_path: Path, overrides: dict[str, str]
) -> None:
    result = _run_full_gate(tmp_path, **overrides)

    assert result.returncode == 1
    assert "workflow registry identity drifted" in result.stdout


def test_full_gate_rejects_wrong_actions_app_id(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, actions_app_id="1")

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_check_suite_mismatch(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, check_suite_id="7002")

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_job_id_mismatch(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, observed_job_id="8002")

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_missing_check_run(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, conclusion=None)

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_wrong_actions_app(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, trusted_app=False)

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_newer_in_progress_run_before_old_green(tmp_path: Path) -> None:
    result = _run_full_gate(
        tmp_path,
        workflow_status="in_progress",
        workflow_conclusion="null",
        older_successful_run=True,
    )

    assert result.returncode == 1
    assert "latest PostgreSQL N-1 workflow run 9001 attempt 1 is not successful" in result.stdout


def test_full_gate_rejects_wrong_run_attempt(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, run_attempt="2", job_attempt="1")

    assert result.returncode == 1
    assert "trusted verify-postgresql-n1 check is missing" in result.stdout


def test_full_gate_rejects_wrong_base_binding(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, run_base_sha="c" * 40)

    assert result.returncode == 1
    assert "run title does not bind this PR/base/head" in result.stdout


def test_full_gate_rejects_workflow_hash_drift(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, tamper_workflow=True)

    assert result.returncode == 1
    assert "workflow bytes do not match" in result.stdout


def test_full_gate_rejects_harness_hash_drift(tmp_path: Path) -> None:
    result = _run_full_gate(tmp_path, tamper_harness=True)

    assert result.returncode == 1
    assert "trusted input drift: tests/saas/test_n1_outbox_admission.py" in result.stdout


def test_unrelated_pr_passes_without_n1_check(tmp_path: Path) -> None:
    result = _run_early_gate(tmp_path, "docs/contributing.md")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "not required" in result.stdout
