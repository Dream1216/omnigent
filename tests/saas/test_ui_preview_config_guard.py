from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(".github/workflows/ui-preview.yml").read_text()
JOBS = yaml.safe_load(WORKFLOW)["jobs"]
PREVIEW_CONFIG_JOB = JOBS["preview_config"]
PREVIEW_CONFIG_STEP = next(
    step for step in PREVIEW_CONFIG_JOB["steps"] if step.get("id") == "check"
)


def _run_preview_config(
    tmp_path: Path, configured: dict[str, str]
) -> tuple[subprocess.CompletedProcess[str], str]:
    output = tmp_path / "github-output"
    env = {key: value for key, value in os.environ.items() if not key.startswith("DATABRICKS_")}
    env.pop("BASH_ENV", None)
    env.update(configured)
    env["GITHUB_OUTPUT"] = str(output)
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            PREVIEW_CONFIG_STEP["run"],
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    return result, output.read_text() if output.exists() else ""


def test_preview_jobs_skip_when_databricks_is_unconfigured(tmp_path: Path) -> None:
    result, output = _run_preview_config(tmp_path, {})
    assert result.returncode == 0, result.stdout + result.stderr
    assert output == "configured=false\n"
    for job_name in ("notify", "build", "deploy"):
        assert "needs.preview_config.outputs.configured == 'true'" in JOBS[job_name]["if"]


def test_preview_configuration_requires_the_complete_secret_trio(tmp_path: Path) -> None:
    secret = "must-not-appear-in-output"
    result, output = _run_preview_config(tmp_path, {"DATABRICKS_HOST": secret})
    assert result.returncode != 0
    assert output == ""
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "configuration is incomplete" in result.stdout


def test_preview_configuration_accepts_complete_oauth_m2m_secrets(tmp_path: Path) -> None:
    configured = {
        "DATABRICKS_HOST": "https://workspace.example.com",
        "DATABRICKS_CLIENT_ID": "preview-client",
        "DATABRICKS_CLIENT_SECRET": "preview-secret",
    }
    result, output = _run_preview_config(tmp_path, configured)
    assert result.returncode == 0, result.stdout + result.stderr
    assert output == "configured=true\n"
    assert all(value not in result.stdout + result.stderr for value in configured.values())
    assert PREVIEW_CONFIG_JOB["permissions"] == {}
    assert all("uses" not in step for step in PREVIEW_CONFIG_JOB["steps"])
    assert set(JOBS["deploy"]["needs"]) == {"preview_config", "build"}
