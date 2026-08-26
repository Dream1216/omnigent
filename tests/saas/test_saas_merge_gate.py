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
