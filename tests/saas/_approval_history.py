from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


def require_current_approval_history(repo: Path) -> None:
    """Skip history-bound assertions only in a confirmed shallow checkout.

    The protected SaaS gates retain full-history, fail-closed validation. A
    missing object in a non-shallow checkout must still reach the validator and
    fail instead of being converted into a skip.
    """

    baseline = json.loads((repo / "saas/production/baseline.json").read_text(encoding="utf-8"))
    record_value = baseline.get("approval", {}).get("record")
    if not isinstance(record_value, str):
        return
    record = json.loads((repo / record_value).read_text(encoding="utf-8"))
    reviewed_commit = record.get("reviewed_commit_sha")
    merge_commit = record.get("merge_commit_sha")
    reviewed = subprocess.run(
        ["git", "cat-file", "-e", f"{reviewed_commit}:saas/production/baseline.json"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    merged = subprocess.run(
        ["git", "merge-base", "--is-ancestor", str(merge_commit), "HEAD"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=repo,
        capture_output=True,
        check=False,
        text=True,
    )
    if (
        shallow.returncode == 0
        and shallow.stdout.strip() == "true"
        and (reviewed.returncode != 0 or merged.returncode != 0)
    ):
        pytest.skip(
            "current ADR approval requires full Git history; "
            "the protected SaaS compatibility and image gates use fetch-depth 0"
        )
