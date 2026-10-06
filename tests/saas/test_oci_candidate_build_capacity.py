"""Capacity guards for reproducible multi-architecture OCI candidates."""

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

    assert workflow["jobs"]["build-candidate"]["timeout-minutes"] == 240
