from __future__ import annotations

from pathlib import Path

import yaml


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _workflow(name: str) -> dict[str, object]:
    source = (_repo() / ".github/workflows" / name).read_text(encoding="utf-8")
    return yaml.load(source, Loader=yaml.BaseLoader)


def test_image_candidate_runs_on_prs_for_every_repository_build_input() -> None:
    workflow = _workflow("saas-image-candidate.yml")
    events = workflow["on"]  # type: ignore[index]
    pull_paths = set(events["pull_request"]["paths"])  # type: ignore[index]
    push_paths = set(events["push"]["paths"])  # type: ignore[index]
    required = {
        ".dockerignore",
        "deploy/docker/Dockerfile",
        "deploy/docker/entrypoint.py",
        "LICENSE",
        "NOTICE",
        "omnigent/**",
        "sdks/**",
        "examples/**",
        "web/**",
        "saas/**",
        "saas/**/*.py",
    }

    assert required <= pull_paths
    assert pull_paths == push_paths


def test_saas_release_workflows_are_pr_eligible() -> None:
    for name in (
        "saas-upstream-compat.yml",
        "saas-image-candidate.yml",
        "saas-n1-compat-image.yml",
    ):
        workflow = _workflow(name)
        events = workflow["on"]  # type: ignore[index]
        assert "pull_request" in events


def test_postgresql_18_workflows_bind_the_exact_service_container() -> None:
    expected_script = "bash saas/scripts/configure_postgresql_18_test_service.sh"
    expected_image = (
        "postgres:18.6-trixie@"
        "sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
    )
    for name, job_name in (
        ("saas-upstream-compat.yml", "compatibility-gate"),
        ("saas-image-candidate.yml", "build-candidate"),
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
