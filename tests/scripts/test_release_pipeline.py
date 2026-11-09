"""Release selection uses real Git inputs; reuse requires native immutable artifacts."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "release_pipeline", ROOT / ".github/scripts/ci/release_pipeline.py"
)
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


@pytest.fixture
def release_repo(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    git("init", "-q")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    git("config", "commit.gpgsign", "false")
    git("config", "core.hooksPath", "/dev/null")
    for path, body in {
        str(pipeline.CONFIG): (ROOT / pipeline.CONFIG).read_text(),
        "saas/supply_chain/release-policy.json": (
            ROOT / "saas/supply_chain/release-policy.json"
        ).read_text(),
        "saas/runtime.py": "value = 1\n",
        "tests/saas/test_runtime.py": "assert True\n",
        "deploy/docker/Dockerfile.dockerignore": "**/*.pyc\n",
        "docs/release.md": "Guide\n",
    }.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    git("add", ".")
    git("commit", "-qm", "base")
    return tmp_path, git


@pytest.mark.parametrize(
    "path,build",
    [
        ("tests/saas/test_runtime.py", False),
        ("docs/release.md", False),
        ("saas/runtime.py", True),
        ("deploy/docker/Dockerfile.dockerignore", True),
        ("unknown-runtime-input", True),
    ],
)
def test_actual_tree_change_selects_only_image_inputs(release_repo, path, build):
    repo, git = release_repo
    base = git("rev-parse", "HEAD")
    (repo / path).write_text("changed\n")
    git("add", ".")
    git("commit", "-qm", "change")
    revision = git("rev-parse", "HEAD")
    result = pipeline.plan(repo, revision=revision, base=base, event="pull_request")
    assert result["candidate_required"] is build
    assert result["production_authority"] is False
    assert (
        pipeline.plan(repo, revision=revision, base=base, event="push")["candidate_required"]
        is False
    )
    assert (
        pipeline.plan(repo, revision=revision, base=base, event="workflow_dispatch")[
            "candidate_required"
        ]
        is True
    )
    assert (
        pipeline.plan(
            repo, revision=revision, base=base, event="workflow_dispatch", reuse_run=123
        )["candidate_required"]
        is False
    )


def test_scope_compares_blob_content_not_commit_identity(release_repo):
    repo, git = release_repo
    base = git("rev-parse", "HEAD")
    git("commit", "--allow-empty", "-qm", "metadata")
    head = git("rev-parse", "HEAD")
    result = pipeline.plan(repo, revision=head, base=base, event="pull_request")
    assert not result["candidate_required"]
    assert result["image_inputs_sha256"] == pipeline.input_digest(
        repo, base, pipeline.config(repo)
    )
    with pytest.raises(ValueError, match="explicit release"):
        pipeline.plan(repo, revision=head, base=base, event="pull_request", reuse_run=123)


@pytest.fixture
def native_candidate(release_repo, monkeypatch):
    repo, git = release_repo
    revision = git("rev-parse", "HEAD")
    manifest = json.dumps(
        {"evidence_kind": "immutable_oci_promotion_candidate", "product_revision": revision}
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("oci-promotion-manifest.json", manifest)
    body = buffer.getvalue()
    root = "repos/Dream1216/omnigent/actions"
    run = {
        "id": 123,
        "head_sha": revision,
        "head_branch": "main",
        "path": ".github/workflows/saas-image-candidate.yml",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "run_attempt": 1,
        "repository": {"full_name": "Dream1216/omnigent"},
    }
    jobs = {
        "total_count": 1,
        "jobs": [{"name": "build-candidate", "conclusion": "success", "run_id": 123}],
    }
    artifacts = []
    for identifier, name, digest in [
        (1, "saas-oci-promotion", "a" * 64),
        (2, "saas-image-candidate", hashlib.sha256(body).hexdigest()),
    ]:
        artifacts.append(
            {
                "id": identifier,
                "name": f"{name}-{revision}",
                "expired": False,
                "size_in_bytes": len(body),
                "digest": "sha256:" + digest,
                "workflow_run": {"id": 123, "head_sha": revision},
            }
        )
    responses = {
        f"{root}/runs/123": run,
        f"{root}/runs/123/attempts/1/jobs?per_page=100": jobs,
        f"{root}/runs/123/artifacts?per_page=100": {"total_count": 2, "artifacts": artifacts},
    }
    monkeypatch.setattr(pipeline, "api", lambda endpoint: copy.deepcopy(responses[endpoint]))

    class Download:
        def __init__(self, args, **kwargs):
            assert args == ["gh", "api", f"{root}/artifacts/2/zip"]
            self.stdout = io.BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def wait(self):
            return 0

        def kill(self):
            raise AssertionError("bounded fixture should not be killed")

    monkeypatch.setattr(pipeline.subprocess, "Popen", Download)
    return repo, revision, responses, artifacts, manifest


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "source",
        "branch",
        "repository",
        "workflow",
        "event",
        "builder",
        "expired",
        "artifact-source",
        "zip-sha",
        "duplicate",
        "pagination",
        "oversized",
    ],
)
def test_resume_never_borrows_foreign_or_unqualified_candidate(native_candidate, fault):
    repo, revision, responses, artifacts, manifest = native_candidate
    root = "repos/Dream1216/omnigent/actions"
    run = responses[f"{root}/runs/123"]
    if fault == "source":
        run["head_sha"] = "b" * 40
    elif fault == "branch":
        run["head_branch"] = "feature"
    elif fault == "repository":
        run["repository"]["full_name"] = "foreign/repo"
    elif fault == "workflow":
        run["path"] = ".github/workflows/untrusted.yml"
    elif fault == "event":
        run["event"] = "pull_request"
    elif fault == "builder":
        responses[f"{root}/runs/123/attempts/1/jobs?per_page=100"]["jobs"][0]["conclusion"] = (
            "failure"
        )
    elif fault == "expired":
        artifacts[0]["expired"] = True
    elif fault == "artifact-source":
        artifacts[0]["workflow_run"]["head_sha"] = "b" * 40
    elif fault == "zip-sha":
        artifacts[1]["digest"] = "sha256:" + "f" * 64
    elif fault == "duplicate":
        artifacts.append(copy.deepcopy(artifacts[0]))
        responses[f"{root}/runs/123/artifacts?per_page=100"]["total_count"] = 3
    elif fault == "pagination":
        responses[f"{root}/runs/123/artifacts?per_page=100"]["total_count"] = 101
    elif fault == "oversized":
        artifacts[1]["size_in_bytes"] = 40 * 1024 * 1024
    if fault:
        with pytest.raises(ValueError):
            pipeline.resolve_candidate(repo, revision=revision, run_id=123)
    else:
        result = pipeline.resolve_candidate(repo, revision=revision, run_id=123)
        assert result == {
            "oci-artifact-id": "1",
            "oci-artifact-sha256": "a" * 64,
            "manifest-sha256": hashlib.sha256(manifest).hexdigest(),
            "candidate-run-id": "123",
        }


def test_existing_workflows_execute_the_shared_policy_and_native_resume():
    workflow = yaml.load(
        (ROOT / ".github/workflows/saas-image-candidate.yml").read_text(), Loader=yaml.BaseLoader
    )
    jobs = workflow["jobs"]
    assert "paths" not in workflow["on"]["push"]
    for name in ("verify-candidate-preflight", "verify-production-migration-replay"):
        assert jobs[name]["needs"] == "select-candidate-work"
        assert "candidate-required == 'true'" in jobs[name]["if"]
    signing = jobs["publish-signed"]
    assert signing["needs"] == ["build-candidate", "resolve-candidate"]
    assert signing["environment"] == "production-image"
    assert "needs.resolve-candidate.result == 'success'" in signing["if"]
    assert any(
        '--run-id "$ORIGINAL_CANDIDATE_RUN_ID"' in s.get("run", "") for s in signing["steps"]
    )
    assert "needs.publish-signed.result == 'success'" in jobs["verify-published-source"]["if"]
    source = "\n".join(s.get("run", "") for s in jobs["build-candidate"]["steps"])
    assert "release_pipeline.py gate --stage source" in source
    production = (ROOT / ".github/workflows/saas-production-admission.yml").read_text()
    assert (
        "release_pipeline.py gate --stage production" in production
        and "--require-ready" in production
    )


def test_configured_gate_executes_real_verifier_and_propagates_failure(monkeypatch):
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        if len(commands) == 2:
            raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(pipeline.subprocess, "run", run)
    monkeypatch.setattr(
        pipeline.sys,
        "argv",
        ["release_pipeline", "gate", "--repo", str(ROOT), "--stage", "source"],
    )
    with pytest.raises(subprocess.CalledProcessError):
        pipeline.main()
    assert [command[2] for command in commands] == [
        "saas.scripts.check_control_plane_migration_cli",
        "saas.scripts.check_patch_queue",
    ]
