from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = REPO_ROOT / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
N1_WORKFLOW = REPO_ROOT / ".github/workflows/saas-n1-compat-image.yml"
FROZEN_POLICY_REVISION = "73e8d4fba01a3b0a7183c172f44961928376805c"


def _array_values(source: str, name: str) -> list[str]:
    match = re.search(rf"^{name}=\(\n(?P<body>.*?)^\)$", source, re.MULTILINE | re.DOTALL)
    assert match is not None
    return re.findall(r'^\s+"([^"]+)"$', match.group("body"), re.MULTILINE)


def test_candidate_workflow_matches_trusted_main_digest_and_scope() -> None:
    policy = EVALUATOR.read_text(encoding="utf-8")
    expected_digest = re.search(
        r'^POSTGRESQL_N1_WORKFLOW_SHA256="([0-9a-f]{64})"$', policy, re.MULTILINE
    )
    assert expected_digest is not None
    assert hashlib.sha256(N1_WORKFLOW.read_bytes()).hexdigest() == expected_digest.group(1)

    workflow = yaml.load(N1_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    policy_paths = _array_values(policy, "POSTGRESQL_N1_PATHS")
    assert workflow["on"]["pull_request"]["paths"] == policy_paths
    assert workflow["on"]["push"]["paths"] == policy_paths


def test_frozen_trusted_candidate_inputs_match_main_policy_hashes() -> None:
    policy = EVALUATOR.read_text(encoding="utf-8")
    trusted_inputs = _array_values(policy, "POSTGRESQL_N1_TRUSTED_INPUTS")

    aliyun_inputs = _array_values(policy, "POSTGRESQL_N1_ALIYUN_TRUSTED_INPUTS")
    aliyun_hashes = dict(row.split("|", 1) for row in aliyun_inputs)
    assert len(aliyun_inputs) == len(aliyun_hashes) == 4
    assert set(aliyun_hashes) == {
        "pyproject.toml",
        "uv.lock",
        "tests/saas/test_image_supply_chain.py",
        "saas/scripts/compare_oci_rebuilds.py",
    }
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in aliyun_hashes.values())
    assert len(trusted_inputs) == 21
    for trusted_input in trusted_inputs:
        path, expected_digests = trusted_input.split("|", 1)
        allowed_digests = expected_digests.split(",")
        assert 1 <= len(allowed_digests) <= 2
        assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in allowed_digests)
        source = subprocess.check_output(
            ["git", "show", f"{FROZEN_POLICY_REVISION}:{path}"], cwd=REPO_ROOT
        )
        observed_digest = hashlib.sha256(source).hexdigest()
        assert observed_digest in allowed_digests or observed_digest == aliyun_hashes.get(path), (
            f"trusted input digest drift for {path}: "
            f"observed {observed_digest}, expected one of {allowed_digests}"
        )


def test_upgrade_inputs_do_not_inherit_frozen_policy_approval() -> None:
    policy = EVALUATOR.read_text(encoding="utf-8")
    approved = {}
    for name in ("POSTGRESQL_N1_TRUSTED_INPUTS", "POSTGRESQL_N1_ALIYUN_TRUSTED_INPUTS"):
        for row in _array_values(policy, name):
            path, digests = row.split("|", 1)
            approved.setdefault(path, set()).update(digests.split(","))
    for path in (
        "pyproject.toml",
        "uv.lock",
        "tests/conftest.py",
        "tests/saas/test_image_supply_chain.py",
    ):
        actual = hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest()
        assert actual not in approved[path]


def test_every_workflow_pytest_source_is_a_trusted_candidate_input() -> None:
    policy = EVALUATOR.read_text(encoding="utf-8")
    trusted_paths = {
        row.split("|", 1)[0] for row in _array_values(policy, "POSTGRESQL_N1_TRUSTED_INPUTS")
    }
    workflow_test_sources = set(
        re.findall(
            r"tests/(?:[A-Za-z0-9_.-]+/)*test_[A-Za-z0-9_.-]+\.py",
            N1_WORKFLOW.read_text(encoding="utf-8"),
        )
    )

    assert workflow_test_sources
    assert workflow_test_sources <= trusted_paths


def test_candidate_run_title_binds_pr_base_and_head() -> None:
    source = N1_WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)

    assert "pr=${{ github.event.pull_request.number || 'none' }}" in source
    assert "base=${{ github.event.pull_request.base.sha || github.sha }}" in source
    assert "head=${{ github.event.pull_request.head.sha || github.sha }}" in source
    assert "verify-postgresql-n1" in workflow["jobs"]
    assert workflow["jobs"]["publish-candidate"]["needs"] == [
        "verify-candidate",
        "verify-postgresql-current",
        "verify-postgresql-n1",
    ]
