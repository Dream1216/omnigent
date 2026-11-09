"""Capacity guards for reproducible multi-architecture OCI candidates."""

import os
import subprocess
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]


def test_static_web_builders_run_on_build_platform() -> None:
    """Architecture-neutral assets must not execute Node under QEMU."""
    dockerfile = (_ROOT / "deploy/docker/Dockerfile").read_text()

    assert "FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web-builder" in dockerfile
    assert "FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS login-web-builder" in dockerfile


def test_candidate_job_covers_two_uncached_multiarch_rebuilds() -> None:
    """The fail-closed timeout must cover Server and Host reproducibility."""
    workflow = yaml.safe_load((_ROOT / ".github/workflows/saas-image-candidate.yml").read_text())

    assert workflow["jobs"]["build-server-preflight"]["timeout-minutes"] == 240
    assert workflow["jobs"]["build-remaining-images"]["strategy"]["max-parallel"] == 3
    assert workflow["jobs"]["build-candidate"]["timeout-minutes"] == 60


def test_superseded_pr_candidates_cancel_without_interrupting_releases() -> None:
    """Only mutable PR heads should replace an in-flight candidate."""
    workflow = yaml.safe_load((_ROOT / ".github/workflows/saas-image-candidate.yml").read_text())

    assert workflow["concurrency"]["cancel-in-progress"] == (
        "${{ github.event_name == 'pull_request' }}"
    )


def test_candidate_preflight_blocks_expensive_builds() -> None:
    """Cheap source gates must finish before a multi-architecture build starts."""
    workflow = yaml.safe_load((_ROOT / ".github/workflows/saas-image-candidate.yml").read_text())
    jobs = workflow["jobs"]
    preflight = jobs["verify-candidate-preflight"]
    build = jobs["build-server-preflight"]

    assert preflight["timeout-minutes"] == 15
    assert build["needs"] == [
        "verify-candidate-preflight",
        "verify-production-migration-replay",
    ]
    names = [step.get("name") for step in preflight["steps"]]
    assert names.index("Type-check SaaS compatibility code") < names.index(
        "Verify image supply-chain policy contracts"
    )


def test_candidate_runs_cheap_compatibility_checks_before_browser_setup() -> None:
    """Source and migration drift should fail before browser installation."""
    workflow = yaml.safe_load((_ROOT / ".github/workflows/saas-image-candidate.yml").read_text())
    names = [step.get("name") for step in workflow["jobs"]["build-server-preflight"]["steps"]]

    assert names.index("Verify migrations and downstream compatibility") < names.index(
        "Install Chromium"
    )


def test_candidate_scan_can_import_admission_in_the_exported_locked_environment(tmp_path) -> None:
    workflow = yaml.safe_load((_ROOT / ".github/workflows/saas-image-candidate.yml").read_text())
    steps = workflow["jobs"]["build-server-preflight"]["steps"]
    install = next(s for s in steps if s.get("name") == "Install locked test dependencies")
    sync, export = install["run"].strip().splitlines()
    assert sync == "uv sync --frozen --extra all --group dev --extra saas --extra e2b"
    path_file = tmp_path / "github-path"
    subprocess.run(
        ["bash", "-c", export],
        cwd=_ROOT,
        env={**os.environ, "GITHUB_PATH": str(path_file)},
        check=True,
    )
    subprocess.run(
        [
            "python",
            "-c",
            "from saas.scripts.runtime_evidence_intake import authenticated_runtime_graph",
        ],
        cwd=_ROOT,
        env={**os.environ, "PATH": path_file.read_text().strip() + os.pathsep + os.defpath},
        check=True,
    )


def test_compatibility_typecheck_is_early_and_not_duplicated_on_pr_branches() -> None:
    """A PR should fail type-checking before starting its expensive acceptance suite."""
    source = (_ROOT / ".github/workflows/saas-upstream-compat.yml").read_text()
    workflow = yaml.safe_load(source)
    events = yaml.load(source, Loader=yaml.BaseLoader)["on"]
    names = [step.get("name") for step in workflow["jobs"]["compatibility-tests"]["steps"]]

    assert events["push"]["branches"] == ["main"]
    assert names.index("Type-check SaaS compatibility code") < names.index(
        "Configure exact PostgreSQL 18 runner contract"
    )
    assert names.index("Type-check SaaS compatibility code") < names.index(
        "Run SaaS compatibility tests"
    )
