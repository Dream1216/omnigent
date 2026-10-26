"""Check native checkout identity and reject failed or substituted CI records."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# The control modules are not installed in the canonical product environment.
for name in ("legacy_native_evidence", "protected_legacy_initial_build", "legacy_source_ci"):
    qualified = "saas.scripts." + name
    if name == "legacy_native_evidence" and qualified in sys.modules:
        continue
    specification = importlib.util.spec_from_file_location(
        qualified, ROOT / "saas/scripts" / (name + ".py")
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[qualified] = module
    specification.loader.exec_module(module)
reader = sys.modules["saas.scripts.legacy_source_ci"]


@pytest.fixture
def native():
    return json.loads(
        (
            ROOT / "tests/saas/resources/native_source_ci/retained-failed-server-rest.json"
        ).read_text()
    )


def test_native_checkout_proves_merge_commit_and_keeps_failed_run_failed(native):
    job = native["original_job"]
    step = next(row for row in job["steps"] if row["name"] == "Check out repo")
    commit = reader.checkout_commit(native["checkout_log"], step)
    assert commit == native["actual_merge"]["sha"]
    assert commit != job["head_sha"]
    assert native["actual_merge"]["tree"]["sha"] == "b723086c158cc3501d7377fcafb7eb25b6a71770"
    assert [row["sha"] for row in native["actual_merge"]["parents"]] == [
        "2c5a9a45f1a576439fc9c5aa0a91022d461389ab",
        job["head_sha"],
    ]
    assert native["original_run"]["conclusion"] == job["conclusion"] == "failure"
    with pytest.raises(ValueError, match="not a successful"):
        reader.verify_job_set(native["original_run"], [job], expected(native), job["head_sha"])


@pytest.mark.parametrize(
    "corruption",
    [
        "unpinned_action",
        "no_final_command",
        "no_result",
        "short_result",
        "duplicate",
        "outside_window",
        "failed_step",
        "reversed_time",
    ],
)
def test_checkout_rejects_ambiguous_or_misattributed_native_data(native, corruption):
    step = next(row for row in native["original_job"]["steps"] if row["name"] == "Check out repo")
    log = native["checkout_log"]
    if corruption == "unpinned_action":
        log = log.replace(reader.CHECKOUT_REVISION, "v7")
    if corruption == "no_final_command":
        log = "\n".join(row for row in log.splitlines() if "git log -1" not in row)
    if corruption == "no_result":
        log = "\n".join(
            row for row in log.splitlines() if not row.endswith(native["actual_merge"]["sha"])
        )
    if corruption == "short_result":
        log = log.replace(native["actual_merge"]["sha"], "ee47a95")
    if corruption == "duplicate":
        log += "\n" + log
    if corruption == "outside_window":
        step["completed_at"] = "2026-10-24T14:35:37Z"
    if corruption == "failed_step":
        step["conclusion"] = "failure"
    if corruption == "reversed_time":
        step["started_at"] = "2026-10-24T14:35:39Z"
    with pytest.raises(ValueError):
        reader.checkout_commit(log, step)


def test_checkout_accepts_native_fractional_completion_and_windows_git_quoting(native):
    step = next(row for row in native["original_job"]["steps"] if row["name"] == "Check out repo")
    log = native["checkout_log"].replace(
        "[command]/usr/bin/git log -1 --format=%H",
        '[command]"C:\\Program Files\\Git\\bin\\git.exe" log -1 --format=%H',
    )
    assert reader.checkout_commit(log, step) == native["actual_merge"]["sha"]


def expected(native):
    run, job = native["original_run"], native["original_job"]
    return {
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "path": run["path"],
        "name": run["name"],
        "jobs": {
            job["name"]: {
                "conclusion": "success",
                "labels": ["ubuntu-latest"],
                "checkouts": [],
            }
        },
    }


@pytest.mark.parametrize(
    "corruption",
    [
        None,
        "fork",
        "push",
        "head",
        "attempt",
        "job_head",
        "job_attempt",
        "job_failure",
        "job_skipped",
        "self_hosted",
        "missing_matrix",
        "duplicate_job",
    ],
)
def test_job_contract_rejects_source_role_matrix_and_execution_swaps(native, corruption):
    # Synthetic success exercises validation only; the original failure is retained.
    run, job = native["original_run"], native["original_job"]
    run["conclusion"] = job["conclusion"] = "success"
    specification = expected(native)
    jobs = [job]
    if corruption == "fork":
        run["head_repository"]["full_name"] = "other/omnigent"
    if corruption == "push":
        run["event"] = "push"
    if corruption == "head":
        run["head_sha"] = "a" * 40
    if corruption == "attempt":
        run["run_attempt"] += 1
    if corruption == "job_head":
        job["head_sha"] = "a" * 40
    if corruption == "job_attempt":
        job["run_attempt"] += 1
    if corruption == "job_failure":
        job["conclusion"] = "failure"
    if corruption == "job_skipped":
        job["conclusion"] = "skipped"
    if corruption == "self_hosted":
        job["labels"] = ["self-hosted", "ubuntu-latest"]
    if corruption == "missing_matrix":
        specification["jobs"]["Pytest (another shard)"] = copy.deepcopy(
            next(iter(specification["jobs"].values()))
        )
    if corruption == "duplicate_job":
        jobs.append(copy.deepcopy(job))
    product = "a3020c625fd14c083337329b2031582fd8f14161"
    if corruption:
        with pytest.raises(ValueError):
            reader.verify_job_set(run, jobs, specification, product)
    else:
        reader.verify_job_set(run, jobs, specification, product)


def test_empty_control_profiles_deny_before_any_remote_API_call(tmp_path, monkeypatch):
    store = tmp_path / "saas/supply_chain/legacy-security-build-profiles.json"
    store.parent.mkdir(parents=True)
    store.write_text('{"schema_version":1,"profiles":{}}')

    def unexpected(*_args):
        raise AssertionError("unapproved profile must not call native APIs")

    monkeypatch.setattr(reader, "api", unexpected)
    with pytest.raises(ValueError, match="no approved profile"):
        reader.collect_source_ci_bindings(tmp_path, "Core", tmp_path / "observations")
    assert not (tmp_path / "observations").exists()


@pytest.mark.parametrize("corruption", [None, "wrong_PR", "moved_base", "ambiguous", "fork"])
def test_native_run_cannot_borrow_another_PR_with_the_same_head(native, corruption):
    run = native["original_run"]
    profile = {
        "product_revision": run["head_sha"],
        "baseline_revision": "2c5a9a45f1a576439fc9c5aa0a91022d461389ab",
    }
    if corruption == "wrong_PR":
        run["pull_requests"][0]["number"] = 160
    if corruption == "moved_base":
        run["pull_requests"][0]["base"]["sha"] = "a" * 40
    if corruption == "ambiguous":
        run["pull_requests"].append(copy.deepcopy(run["pull_requests"][0]))
    if corruption == "fork":
        run["pull_requests"][0]["head"]["repo"]["url"] = (
            "https://api.github.com/repos/other/omnigent"
        )
    if corruption:
        with pytest.raises(ValueError):
            reader.verify_run_pull_request(run, profile, 185)
    else:
        reader.verify_run_pull_request(run, profile, 185)


@pytest.mark.parametrize(
    "corruption",
    [None, "changed_base", "workflow_blob", "run_fork", "duplicate_job_page"],
)
def test_collector_binds_control_profiles_native_pages_sources_and_final_PR(
    tmp_path, monkeypatch, native, corruption
):
    # No catalog primitive supplies authenticated Actions records. Reuse the
    # retained native job/step shape with explicit synthetic source coordinates.
    product, tree, merge = "2" * 40, "3" * 40, "4" * 40
    baseline = "dc1e9a9735d4c996b74e601ed7f4ecb49e83f9ec"
    repository = {"full_name": reader.REPOSITORY}
    repository_url = "https://api.github.com/repos/" + reader.REPOSITORY
    pull = {
        "number": 999,
        "state": "open",
        "draft": False,
        "head": {"sha": product, "ref": "codex/test-materials", "repo": repository},
        "base": {"sha": baseline, "ref": "codex/frozen-core", "repo": repository},
        "merge_commit_sha": merge,
    }
    profile = {
        "schema_version": 1,
        "repository": reader.REPOSITORY,
        "component": "Core",
        "baseline_revision": baseline,
        "product_revision": product,
        "product_tree": tree,
        "source_date_epoch": 1792575662,
        "source_delta": [
            {
                "path": "uv.toml",
                "before": {"mode": "100644", "sha256": "a" * 64},
                "after": {"mode": "100644", "sha256": "b" * 64},
            }
        ],
        "application_version": "0.18.0.dev20261006",
    }
    body = b"name: Fixture CI\non: pull_request\njobs: {}\n"
    checkouts = [{"number": 2, "name": "Check out repo", "revision": "product-merge"}]
    workflows = [
        {
            "path": path,
            "name": "Fixture CI",
            "source_sha256": hashlib.sha256(body).hexdigest(),
            "run_id": 1000 + index,
            "attempt": 1,
            "jobs": {
                "Pytest (server-rest)": {
                    "labels": ["ubuntu-latest"],
                    "conclusion": "success",
                    "checkouts": checkouts,
                }
            },
        }
        for index, path in enumerate(sorted(reader._REQUIRED_WORKFLOWS))
    ]
    contract = {
        "schema_version": 1,
        "component": "Core",
        "product_revision": product,
        "product_tree": tree,
        "validation_pr": 999,
        "validation_base_ref": "codex/frozen-core",
        "workflows": workflows,
    }
    directory = tmp_path / "saas/supply_chain"
    directory.mkdir(parents=True)
    for filename, value in [
        ("legacy-security-build-profiles.json", profile),
        ("legacy-security-ci-profiles.json", contract),
    ]:
        (directory / filename).write_text(
            json.dumps({"schema_version": 1, "profiles": {"Core": value}})
        )
    by_id = {row["run_id"]: row for row in workflows}
    calls = []
    snapshots = 0

    def api(endpoint):
        nonlocal snapshots
        calls.append(endpoint)
        if endpoint.endswith("/pulls/999"):
            snapshots += 1
            value = copy.deepcopy(pull)
            if corruption == "changed_base" and snapshots == 2:
                value["base"]["sha"] = "5" * 40
            return value
        if "/git/commits/" in endpoint:
            return {
                "sha": merge,
                "tree": {"sha": tree},
                "parents": [{"sha": baseline}, {"sha": product}],
            }
        if "/contents/" in endpoint:
            path = endpoint.split("/contents/", 1)[1].split("?", 1)[0]
            payload = body + (b"changed" if corruption == "workflow_blob" else b"")
            return {
                "path": path,
                "encoding": "base64",
                "size": len(payload),
                "content": base64.b64encode(payload).decode(),
            }
        identifier = int(endpoint.split("/actions/runs/", 1)[1].split("/", 1)[0])
        specification = by_id[identifier]
        if "/jobs?" in endpoint:
            job = copy.deepcopy(native["original_job"])
            job.update(
                id=identifier + 10000,
                run_id=identifier,
                head_sha=product,
                conclusion="success",
            )
            return {
                "total_count": 2 if corruption == "duplicate_job_page" else 1,
                "jobs": [job],
            }
        run = copy.deepcopy(native["original_run"])
        run.update(
            id=identifier,
            path=specification["path"],
            name="Fixture CI",
            head_sha=product,
            head_branch=pull["head"]["ref"],
            conclusion="success",
        )
        run["pull_requests"] = [
            {
                "number": 999,
                "url": repository_url + "/pulls/999",
                "head": {"sha": product, "repo": {"url": repository_url}},
                "base": {"sha": baseline, "repo": {"url": repository_url}},
            }
        ]
        if corruption == "run_fork":
            run["head_repository"]["full_name"] = "other/omnigent"
        return run

    def download(_identifier, path):
        path.write_text(native["checkout_log"].replace(native["actual_merge"]["sha"], merge))

    monkeypatch.setattr(reader, "api", api)
    monkeypatch.setattr(reader, "download_job_log", download)
    if corruption:
        with pytest.raises(ValueError):
            reader.collect_source_ci_bindings(tmp_path, "Core", tmp_path / "observations")
    else:
        value = reader.collect_source_ci_bindings(tmp_path, "Core", tmp_path / "observations")
        assert value["product_revision"] == product
        assert value["product_tree"] == tree
        assert len(value["workflows"]) == len(reader._REQUIRED_WORKFLOWS)
        assert all(
            row["verified_checkouts"][0]["actual_commit"] == merge for row in value["workflows"]
        )
        assert value["coverage_all_app_PG_image_production_admission"] is False
        assert snapshots == 2
