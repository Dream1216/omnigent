from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = REPO_ROOT / ".github/scripts/merge-ready/evaluate-checks.sh"
REQUIRED = REPO_ROOT / ".github/scripts/merge-ready/required.sh"
SAAS_REQUIRED = REPO_ROOT / ".github/scripts/merge-ready/saas-required.sh"
MERGE_READY_WORKFLOW = REPO_ROOT / ".github/workflows/merge-ready.yml"
N1_WORKFLOW = REPO_ROOT / ".github/workflows/saas-n1-compat-image.yml"


def _required_check_names() -> list[str]:
    command = f'source "{REQUIRED}"; printf "%s\\n" "${{REQUIRED[@]}}"'
    result = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.splitlines()


def _run_evaluator(
    tmp_path: Path,
    *,
    changed_file: str,
    n1_conclusion: str | None,
    evaluated_sha: str = "a" * 40,
    pr_head_sha: str = "a" * 40,
    trusted_n1_identity: bool = True,
    tamper_workflow: bool = False,
    tamper_test_harness: bool = False,
    reported_changed_files: int = 1,
    pr_base_sha: str = "b" * 40,
    run_base_sha: str | None = None,
) -> subprocess.CompletedProcess[str]:
    checks = [
        f"{name}\tcompleted\tsuccess\t2026-08-27T00:00:00Z" for name in _required_check_names()
    ]
    if n1_conclusion is not None:
        checks.append(f"verify-postgresql-n1\tcompleted\t{n1_conclusion}\t2026-08-27T00:00:01Z")

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "files").write_text(f"{changed_file}\n")
    (fixtures / "pr").write_text(
        f"open\t{pr_head_sha}\tmain\t{pr_base_sha}\t{reported_changed_files}\n"
    )
    (fixtures / "checks").write_text("\n".join(checks) + "\n")
    (fixtures / "runs").write_text("")
    workflow_source = N1_WORKFLOW.read_bytes()
    if tamper_workflow:
        workflow_source += b"\n# untrusted workflow mutation\n"
    (fixtures / "workflow").write_bytes(workflow_source)

    if n1_conclusion is None:
        (fixtures / "n1-candidates").write_text("")
        (fixtures / "n1-run").write_text("")
        (fixtures / "n1-job").write_text("")
    else:
        observed_run_base_sha = run_base_sha or pr_base_sha
        details_url = (
            "https://github.com/Dream1216/omnigent/actions/runs/9001/job/8001"
            if trusted_n1_identity
            else "https://github.com/Dream1216/omnigent/actions/runs/6666/job/8001"
        )
        (fixtures / "n1-candidates").write_text(
            "\t".join(
                (
                    "8001",
                    "verify-postgresql-n1",
                    "completed",
                    n1_conclusion,
                    "2026-08-27T00:00:01Z",
                    details_url,
                    "github-actions",
                )
            )
            + "\n"
        )
        (fixtures / "n1-run").write_text(
            "\t".join(
                (
                    "SaaS N-1 compatibility image",
                    (
                        "SaaS N-1 pull_request pr=123 "
                        f"base={observed_run_base_sha} head={evaluated_sha}"
                    ),
                    ".github/workflows/saas-n1-compat-image.yml",
                    "pull_request",
                    "completed",
                    n1_conclusion,
                    evaluated_sha,
                    "9001",
                )
            )
            + "\n"
        )
        (fixtures / "n1-job").write_text(
            "\t".join(
                (
                    "verify-postgresql-n1",
                    "completed",
                    n1_conclusion,
                    evaluated_sha,
                    "9001",
                    "SaaS N-1 compatibility image",
                )
            )
            + "\n"
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
  cat "$FAKE_GH_FIXTURES/workflow"
elif [[ "$args" == *'/contents/tests/saas/test_n1_outbox_admission.py?ref='* ]] \
  && [[ "$FAKE_TAMPER_TEST_HARNESS" == '1' ]]; then
  cat "$FAKE_REPO_ROOT/tests/saas/test_n1_outbox_admission.py"
  printf '\n# untrusted test mutation\n'
elif [[ "$args" =~ /contents/([^?]+)\?ref= ]]; then
  cat "$FAKE_REPO_ROOT/${BASH_REMATCH[1]}"
elif [[ "$args" == *'/check-runs'* && "$args" == *'select(.name'* ]]; then
  cat "$FAKE_GH_FIXTURES/n1-candidates"
elif [[ "$args" == *'/check-runs'* ]]; then
  cat "$FAKE_GH_FIXTURES/checks"
elif [[ "$args" == *'/actions/runs/9001'* ]]; then
  cat "$FAKE_GH_FIXTURES/n1-run"
elif [[ "$args" == *'/actions/jobs/8001'* ]]; then
  cat "$FAKE_GH_FIXTURES/n1-job"
elif [[ "$args" == *'/actions/runs?'* ]]; then
  cat "$FAKE_GH_FIXTURES/runs"
else
  echo "unexpected gh invocation: $args" >&2
  exit 2
fi
"""
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)

    output = tmp_path / "github-output"
    output.touch()
    env = os.environ.copy()
    env.update(
        {
            "FAKE_GH_FIXTURES": str(fixtures),
            "FAKE_REPO_ROOT": str(REPO_ROOT),
            "FAKE_TAMPER_TEST_HARNESS": "1" if tamper_test_harness else "0",
            "GH_TOKEN": "test-token",
            "GITHUB_OUTPUT": str(output),
            "PATH": f"{bin_dir}:{env['PATH']}",
            "PR": "123",
            "REPO": "Dream1216/omnigent",
            "SHA": evaluated_sha,
        }
    )
    return subprocess.run(
        ["bash", str(EVALUATOR)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_n1_scope_matches_workflow_pull_request_paths() -> None:
    workflow = yaml.load(N1_WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    workflow_paths = workflow["on"]["pull_request"]["paths"]
    command = f'source "{SAAS_REQUIRED}"; printf "%s\\n" "${{POSTGRESQL_N1_PATHS[@]}}"'
    result = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.stdout.splitlines() == workflow_paths
    assert workflow_paths == [
        ".github/scripts/merge-ready/**",
        ".github/workflows/merge-ready.yml",
        ".github/workflows/saas-n1-compat-image.yml",
        ".python-version",
        ".uv/**",
        ".venv/**",
        "conftest.py",
        "deploy/docker/Dockerfile",
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "uv.toml",
        "uv.lock",
        "saas/**",
        "tests/conftest.py",
        "tests/saas/**",
    ]


def test_merge_ready_rechecks_when_n1_workflow_completes() -> None:
    workflow = yaml.load(MERGE_READY_WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert "SaaS N-1 compatibility image" in workflow["on"]["workflow_run"]["workflows"]
    evaluate = next(
        step
        for step in workflow["jobs"]["evaluate"]["steps"]
        if step.get("name") == "Evaluate required checks"
    )
    assert evaluate["env"]["PR"] == "${{ steps.ctx.outputs.pr }}"
    assert "sha" not in workflow["on"]["workflow_dispatch"]["inputs"]


def test_related_pr_cannot_pass_when_postgresql_n1_check_is_missing(
    tmp_path: Path,
) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion=None,
    )
    assert result.returncode == 1
    assert "MISSING : verify-postgresql-n1" in result.stdout


def test_related_pr_cannot_pass_when_postgresql_n1_check_is_skipped(
    tmp_path: Path,
) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/n1_outbox_admission.py",
        n1_conclusion="skipped",
    )
    assert result.returncode == 1
    assert "NOT GREEN: verify-postgresql-n1" in result.stdout


def test_related_pr_passes_only_with_successful_postgresql_n1_check(
    tmp_path: Path,
) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="tests/saas/test_n1_compat_patch.py",
        n1_conclusion="success",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_unrelated_pr_does_not_require_postgresql_n1_check(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="docs/contributing.md",
        n1_conclusion=None,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_pr_file_list_cannot_be_mixed_with_another_sha(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        evaluated_sha="b" * 40,
        pr_head_sha="a" * 40,
    )
    assert result.returncode == 1
    assert "exact head SHA" in result.stdout


def test_same_named_check_from_another_workflow_run_is_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        trusted_n1_identity=False,
    )
    assert result.returncode == 1
    assert "MISSING : verify-postgresql-n1" in result.stdout


def test_same_head_check_from_another_base_revision_is_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        run_base_sha="c" * 40,
    )
    assert result.returncode == 1
    assert "MISSING : verify-postgresql-n1" in result.stdout


def test_changed_n1_workflow_bytes_are_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        tamper_workflow=True,
    )
    assert result.returncode == 1
    assert "workflow bytes do not match" in result.stdout


def test_changed_n1_test_harness_bytes_are_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        tamper_test_harness=True,
    )
    assert result.returncode == 1
    assert "trusted input drift: tests/saas/test_n1_outbox_admission.py" in result.stdout


def test_incomplete_pr_file_pagination_is_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file="saas/control_plane/postgresql_roles.sql",
        n1_conclusion="success",
        reported_changed_files=2,
    )
    assert result.returncode == 1
    assert "file pagination is incomplete" in result.stdout


def test_gate_policy_cannot_self_approve_its_successor(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file=".github/scripts/merge-ready/saas-required.sh",
        n1_conclusion="success",
    )
    assert result.returncode == 1
    assert "gate policy changes require an explicit admin merge" in result.stdout


def test_committed_virtual_environment_is_rejected(tmp_path: Path) -> None:
    result = _run_evaluator(
        tmp_path,
        changed_file=".venv/bin/python",
        n1_conclusion="success",
    )
    assert result.returncode == 1
    assert "Committed .uv/.venv state requires an explicit admin merge" in result.stdout
