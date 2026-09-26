from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github/workflows/saas-upstream-tag-sync.yml"


def test_tag_mirror_is_trusted_scheduled_write_workflow() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"schedule", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["mirror"]
    assert job["if"] == "github.repository == 'Dream1216/omnigent'"
    assert "pull_request" not in workflow["on"]


def test_tag_mirror_requires_dedicated_workflow_scoped_credential() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["mirror"]["steps"]
    preflight = next(step for step in steps if step["name"].startswith("Require workflow"))
    checkout = next(step for step in steps if step["name"].startswith("Check out"))

    assert preflight["env"]["TAG_MIRROR_TOKEN"] == ("${{ secrets.SAAS_UPSTREAM_TAG_PUSH_TOKEN }}")
    assert 'if [ -z "$TAG_MIRROR_TOKEN" ]; then' in preflight["run"]
    assert checkout["with"]["token"] == ("${{ secrets.SAAS_UPSTREAM_TAG_PUSH_TOKEN }}")


def test_tag_mirror_rejects_mutation_and_only_pushes_missing_refs() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["mirror"]["steps"]
    fetch = next(step["run"] for step in steps if step["name"].startswith("Fetch official"))
    mirror = next(step["run"] for step in steps if step["name"].startswith("Reject moved"))

    assert "https://github.com/omnigent-ai/omnigent.git" in fetch
    assert "+refs/tags/*:refs/saas-official-tags/*" in fetch
    assert 'if [ "$local_oid" != "$official_oid" ]' in mirror
    assert "Official tag moved or downstream tag conflicts" in mirror
    assert 'missing+=("$official_ref:$local_ref")' in mirror
    assert 'git push --atomic origin "${missing[@]}"' in mirror
    assert "--force" not in mirror
