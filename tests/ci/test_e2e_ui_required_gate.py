"""Contract tests for the base-branch E2E UI policy judge."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / ".github/scripts/e2e-ui-required/check.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


def _run_gate(
    tmp_path: Path,
    *,
    gateway: bool = False,
    partial_gateway: bool = False,
    verdict: str = '{"needs_test":false,"reason":"covered"}',
    files_override: list[dict[str, str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    verdict_file = tmp_path / "verdict"
    verdict_file.write_text(verdict)

    files = json.dumps(
        files_override
        or [
            {
                "status": "modified",
                "filename": "web/example.tsx",
                "patch": "@@ -1 +1 @@\\n-old\\n+new",
            }
        ]
    )
    _write_executable(
        bin_dir / "gh",
        f"""
printf 'gh %s\\n' "$*" >> {calls!s}
if [[ "$1 $2" == "api repos/example/repo/pulls/1/files" ]]; then
  if [[ " $* " == *" --jq "* ]]; then
    printf 'modified\\tweb/example.tsx\\n'
  else
    cat <<'JSON'
{files}
JSON
  fi
elif [[ "$1 $2" == "pr view" ]]; then
  printf 'Example UI change\\n'
else
  echo "unexpected gh invocation: $*" >&2
  exit 97
fi
""",
    )
    _write_executable(
        bin_dir / "curl",
        f"""
printf 'curl %s\\n' "$*" >> {calls!s}
    jq -cn --rawfile content {verdict_file!s} \
  '{{choices:[{{message:{{content:$content}}}}]}}'
""",
    )
    _write_executable(
        bin_dir / "copilot",
        f"""
printf 'copilot %s\\n' "$*" >> {calls!s}
    cat {verdict_file!s}
""",
    )

    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_TOKEN": "test-gh-token",
        "GITHUB_TOKEN": "test-job-token",
        "REPO": "example/repo",
        "PR": "1",
        "MAINTAINERS": "maintainer",
        "RUNNER_TEMP": str(tmp_path / "runner-temp"),
        "COPILOT_BIN": str(bin_dir / "copilot"),
    }
    if gateway or partial_gateway:
        env["OPENAI_BASE_URL"] = "https://gateway.example/v1"
    if gateway:
        env["OPENAI_API_KEY"] = "test-key"
        env["E2E_UI_JUDGE_MODEL"] = "judge-model"

    return subprocess.run(
        ["bash", str(CHECK)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_gateway_backend_remains_preferred(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, gateway=True)

    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls").read_text()
    assert "curl " in calls
    assert "copilot " not in calls


def test_copilot_fallback_isolated_and_tool_limited(tmp_path: Path) -> None:
    result = _run_gate(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls").read_text()
    assert "copilot " in calls
    assert "--available-tools=view" in calls
    assert "--disable-builtin-mcps" in calls
    assert "--no-custom-instructions" in calls
    assert "--no-remote-export" in calls
    assert "curl " not in calls


def test_partial_gateway_configuration_fails_closed(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, partial_gateway=True)

    assert result.returncode == 1
    assert "Incomplete e2e_ui judge gateway configuration" in result.stdout
    calls = (tmp_path / "calls").read_text()
    assert "curl " not in calls
    assert "copilot " not in calls


def test_unparseable_copilot_verdict_fails_closed(tmp_path: Path) -> None:
    result = _run_gate(tmp_path, verdict="not-json")

    assert result.returncode == 1
    assert "unparseable verdict" in result.stdout


def test_multiline_copilot_verdict_is_accepted(tmp_path: Path) -> None:
    result = _run_gate(
        tmp_path,
        verdict='''{
  "needs_test": false,
  "reason": "covered by the existing browser test"
}''',
    )

    assert result.returncode == 0, result.stderr
    assert "no test required" in result.stdout


def test_fenced_multiline_copilot_verdict_is_accepted(tmp_path: Path) -> None:
    result = _run_gate(
        tmp_path,
        verdict='''```json
{
  "needs_test": false,
  "reason": "covered by the existing browser test"
}
```''',
    )

    assert result.returncode == 0, result.stderr
    assert "no test required" in result.stdout


def test_large_pr_index_keeps_late_test_declarations_visible(tmp_path: Path) -> None:
    padding = "\n".join(f"+padding line {i}" for i in range(400))
    files = [
        {
            "status": "modified",
            "filename": "web/example.tsx",
            "patch": "@@ -1 +1 @@\n-old\n+new",
        },
        *[
            {
                "status": "added",
                "filename": f"tests/e2e_ui/agents/test_filler_{i:03}.py",
                "patch": f"@@ -0,0 +1,400 @@\n{padding}",
            }
            for i in range(20)
        ],
        {
            "status": "added",
            "filename": "tests/e2e_ui/zzzz/test_login_recovery.py",
            "patch": (
                "@@ -0,0 +1,2 @@\n"
                "+async def test_login_recovers_after_expired_session(page):\n"
                "+    pass"
            ),
        },
    ]

    result = _run_gate(tmp_path, files_override=files)

    assert result.returncode == 0, result.stderr
    prompt = (tmp_path / "calls").read_text()
    assert "tests/e2e_ui/zzzz/test_login_recovery.py" in prompt
    assert "test_login_recovers_after_expired_session" in prompt
