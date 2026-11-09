from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _workflow(name: str) -> dict[str, object]:
    source = (_repo() / ".github/workflows" / name).read_text(encoding="utf-8")
    return yaml.load(source, Loader=yaml.BaseLoader)


def test_image_candidate_runs_on_prs_for_every_repository_build_input() -> None:
    workflow = _workflow("saas-image-candidate.yml")
    events = workflow["on"]  # type: ignore[index]
    assert events["pull_request"] == ""
    assert events["push"] == {"branches": ["main"]}
    settings = json.loads((_repo() / ".github/release-pipeline.json").read_text())
    required = {
        ".dockerignore",
        "deploy/docker/",
        "LICENSE",
        "NOTICE",
        "omnigent/",
        "sdks/",
        "examples/",
        "web/",
        "saas/",
    }
    assert required <= set(settings["image_inputs"])
    selector = workflow["jobs"]["select-candidate-work"]
    assert "if" not in selector
    assert any(
        ".github/scripts/ci/release_pipeline.py plan" in s.get("run", "")
        for s in selector["steps"]
    )


def test_saas_release_workflows_are_pr_eligible() -> None:
    for name in (
        "saas-upstream-compat.yml",
        "saas-image-candidate.yml",
        "saas-n1-compat-image.yml",
    ):
        workflow = _workflow(name)
        events = workflow["on"]  # type: ignore[index]
        assert "pull_request" in events


def test_compatibility_shards_preserve_full_selection_and_isolated_services():
    workflow = _workflow("saas-upstream-compat.yml")
    job = workflow["jobs"]["compatibility-tests"]
    assert job["strategy"] == {"fail-fast": "false", "matrix": {"shard": ["0", "1"]}}
    assert job["timeout-minutes"] == "45"
    assert job["services"]["postgres"]["ports"] == ["5432:5432"]
    assert job["env"]["SHARD_ID"] == "${{ matrix.shard }}"
    command = next(
        s["run"] for s in job["steps"] if s.get("name") == "Run SaaS compatibility tests"
    )
    tokens = shlex.split(command)
    assert tokens[:3] == ["uv", "run", "pytest"]
    assert tokens[3:5] == ["--num-shards=2", "--shard-id=$SHARD_ID"]
    assert tokens[5].startswith("--junitxml=artifacts/saas-compatibility-")
    assert tokens[6:] == [
        "tests/db/test_workspace_scope.py",
        "tests/cli/test_cli.py",
        "tests/runner/transports/ws_tunnel/test_serve.py",
        "tests/server/test_managed_hosts.py",
        "tests/server/integration/test_sessions_archive.py",
        "tests/saas",
    ]
    single_steps = {
        "Run isolated PostgreSQL logical restore contract",
        "Run official zygote and query-context compatibility tests",
        "Run official hard-sandbox and credential-proxy acceptance",
        "Verify SaaS migration CLI",
        "Verify SaaS wheel contents",
        "Replay downstream patch queue",
        "Validate P0-P6 acceptance ledger",
        "Validate P0 production baselines",
        "Enforce source-intrusion budget",
    }
    assert {s["name"] for s in job["steps"] if s.get("if") == "matrix.shard == 0"} == single_steps
    assert not any(s.get("continue-on-error") == "true" for s in job["steps"])


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped", "", "unknown"])
def test_required_compatibility_context_rejects_any_incomplete_shard(result):
    gate = _workflow("saas-upstream-compat.yml")["jobs"]["compatibility-gate"]
    assert gate["if"] == "always()" and gate["needs"] == "compatibility-tests"
    assert gate["steps"][0]["env"] == {"TEST_RESULT": "${{ needs.compatibility-tests.result }}"}
    process = subprocess.run(
        ["bash", "-c", gate["steps"][0]["run"]],
        env={**os.environ, "TEST_RESULT": result},
        check=False,
    )
    assert (process.returncode == 0) == (result == "success")


def test_postgresql_18_workflows_bind_the_exact_service_container() -> None:
    expected_script = "bash saas/scripts/configure_postgresql_18_test_service.sh"
    expected_image = (
        "postgres:18.6-trixie@"
        "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
    )
    for name, job_name in (
        ("saas-upstream-compat.yml", "compatibility-tests"),
        ("saas-image-candidate.yml", "build-server-preflight"),
    ):
        workflow = _workflow(name)
        job = workflow["jobs"][job_name]  # type: ignore[index]
        assert job["services"]["postgres"]["image"] == expected_image
        step = next(
            candidate
            for candidate in job["steps"]
            if candidate.get("name") == "Configure exact PostgreSQL 18 runner contract"
        )
        assert step["run"] == expected_script
        assert step["env"] == {
            "PGPASSWORD": "postgres",
            "PGCONNECT_TIMEOUT": "3",
            "POSTGRES_SERVICE_CONTAINER_ID": "${{ job.services.postgres.id }}",
        }

    assert (
        _workflow("saas-n1-compat-image.yml")["jobs"]["verify-postgresql-current"][  # type: ignore[index]
            "services"
        ]["postgres"]["image"]
        == expected_image
    )
    assert (
        _workflow("saas-enterprise-idp-admission.yml")["jobs"]["provider-evidence-admission"][
            "services"
        ]["postgres"]["image"]  # type: ignore[index]
        == expected_image
    )

    script = (_repo() / "saas/scripts/configure_postgresql_18_test_service.sh").read_text(
        encoding="utf-8"
    )
    assert "docker ps" not in script
    assert "docker inspect" in script
    assert "pg_isready" in script
    assert "--timeout=1" in script
    assert "max_notify_queue_pages" in script
    assert "max_prepared_transactions" in script
    assert "180006" in script
