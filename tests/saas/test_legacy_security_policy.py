"""Portable unit native transports; these fixtures are never native qualification."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import sys

import pytest

from saas.scripts import legacy_security_policy as policy
from tests.saas.test_legacy_source_qualification import ROOT, invoke, owner_main_sources, qualifier
from tests.saas.test_legacy_source_qualification import scenario as scenario


def _step(number, name, second, conclusion="success"):
    return {
        "number": number,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "started_at": f"2026-10-24T13:59:{second:02d}Z",
        "completed_at": f"2026-10-24T13:59:{second + 1:02d}Z",
    }


def _checkout(reader, revision, second=10):
    return "".join(
        f"2026-10-24T13:59:{second:02d}.{index:03d}Z {line}\n"
        for index, line in enumerate(
            [
                f"##[group]Run actions/checkout@{reader.CHECKOUT_REVISION}",
                "##[endgroup]",
                "[command]/usr/bin/git log -1 --format=%H",
                revision,
            ]
        )
    )


def _owner_log(reader, revision):
    lines = [
        "##[group]Run # Before this lands on main the scripts are absent there -- proceed",
        "echo scan=false",
        "shell: /usr/bin/bash -e {0}",
        "env:",
        "  UV_INDEX_URL: https://pypi.org/simple",
        "  EVENT_NAME: pull_request",
        "  AUTHOR_ASSOCIATION: OWNER",
        "  PR_AUTHOR: Dream1216",
        "  GH_TOKEN: ***",
        "  REPO: Dream1216/omnigent",
        "  PR: 9001",
        "  MAINTAINERS: fixture-maintainer",
        "##[endgroup]",
        "scan=false (trusted author (author_association=OWNER))",
    ]
    return (
        _checkout(reader, revision)
        + "2026-10-24T13:59:13.100Z Loaded maintainers from MAINTAINER@main: fixture-maintainer\n"
        + "".join(f"2026-10-24T13:59:16.{i:03d}Z {line}\n" for i, line in enumerate(lines))
    ).encode()


def _persist(data, monkeypatch):
    data["policy"]["identity_contract_sha256"] = qualifier._digest(data["identity"])
    for name, value in [
        ("legacy-security-ci-profiles", data["identity"]),
        ("legacy-source-qualification-profiles", data["policy"]),
    ]:
        (data["control"] / "saas/supply_chain" / (name + ".json")).write_text(
            json.dumps({"schema_version": 1, "profiles": {"Core": value}})
        )
    subprocess.run(["git", "add", "."], cwd=data["control"], check=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "unit reviewed policy"],
        cwd=data["control"],
        check=True,
    )
    data["control_sha"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=data["control"], text=True
    ).strip()
    monkeypatch.setenv("GITHUB_SHA", data["control_sha"])


@pytest.fixture(params=(policy.MAIN, "95ad31ca3a45b52ec7c071beeb4351f5e39a39fe"))
def owner(scenario, monkeypatch, request):
    # Reuse the owning immutable-Git scenario and substitute only API/log transport.
    data = scenario
    trusted_checkout = request.param
    fixed_main_sources = owner_main_sources(ROOT)
    reader = sys.modules["saas.scripts.legacy_source_ci"]
    monkeypatch.setitem(
        reader.verify_pr_tree.__globals__["BASELINES"],
        "Core",
        data["profile"]["baseline_revision"],
    )
    data["pull"].update(user={"login": "Dream1216"}, author_association="OWNER")
    data["pull"]["head"]["ref"] = "unit-legacy-source"
    data["logs"] = {}
    for spec, observed in zip(data["identity"]["workflows"], data["observations"], strict=True):
        run, job = observed["run"], observed["jobs"][0]
        run.update(
            name=spec["name"],
            head_branch=data["pull"]["head"]["ref"],
            head_repository={"full_name": "Dream1216/omnigent"},
            jobs_url=f"{policy.URL}/actions/runs/{run['id']}/attempts/1/jobs",
            logs_url=f"{policy.URL}/actions/runs/{run['id']}/attempts/1/logs",
        )
        run["pull_requests"] = [
            {
                "number": 9001,
                "url": policy.URL + "/pulls/9001",
                "head": {"sha": data["profile"]["product_revision"], "repo": {"url": policy.URL}},
                "base": {"sha": data["profile"]["baseline_revision"], "repo": {"url": policy.URL}},
            }
        ]
        job.update(runner_group_name="GitHub Actions", labels=["ubuntu-latest"])
        job["steps"].insert(0, _step(2, "Original checkout", 10))
        data["logs"][job["id"]] = (
            _checkout(reader, data["commit"]["sha"])
            + "2026-10-24T14:00:01Z 1 worker [1 item]\n"
            + "2026-10-24T14:00:02Z [gw0] [100%] PASSED tests/unit/test_original.py::test_one\n"
        ).encode()
    spec = next(s for s in data["identity"]["workflows"] if s["path"] == policy.WORKFLOW)
    observed = next(o for o in data["observations"] if o["run"]["path"] == policy.WORKFLOW)
    run, job = observed["run"], observed["jobs"][0]
    spec["name"] = run["name"] = "Security Scan"
    spec["jobs"] = {
        "Security Scan": {
            "labels": ["ubuntu-latest"],
            "conclusion": "success",
            "checkouts": [
                {"number": 2, "name": "Check out scanner from main", "revision": trusted_checkout}
            ],
        }
    }
    job["name"] = "Security Scan"
    job["steps"] = [
        _step(
            n,
            name,
            {1: 5, 2: 10, 3: 13, 4: 16}.get(n, 20),
            "skipped" if 5 <= n <= 14 else "success",
        )
        for n, name in policy._NAMES.items()
    ]
    check = next(c for c in data["snapshots"]["head"]["checks"] if c["id"] == job["id"])
    check.update(
        name="Security Scan",
        details_url=f"https://github.com/Dream1216/omnigent/actions/runs/{run['id']}/job/{job['id']}",
    )
    data["logs"][job["id"]] = _owner_log(reader, trusted_checkout)
    row = {
        "kind": policy.KIND,
        **{
            k: data["profile"][k]
            for k in ("component", "product_revision", "product_tree", "baseline_revision")
        },
        **{k: data["identity"][k] for k in ("validation_pr", "validation_base_ref")},
        "workflow_sha256": policy.SOURCES[policy.WORKFLOW],
        "trusted_checkout_revision": trusted_checkout,
        "should_scan_sha256": policy.SOURCES[".github/scripts/security-scan/should-scan.sh"],
        "load_maintainers_sha256": policy.SOURCES[
            ".github/scripts/merge-ready/load-maintainers.sh"
        ],
        "run_id": run["id"],
        "attempt": 1,
        "job_id": job["id"],
        "check_id": check["id"],
        "check_suite_id": run["check_suite_id"],
        "run_sha256": policy.digest(run),
        "job_sha256": policy.digest(job),
        "check_sha256": policy.digest(check),
        "job_log_sha256": hashlib.sha256(data["logs"][job["id"]]).hexdigest(),
    }
    spec["trusted_security_policy"] = row
    data["policy"]["job_evidence"][policy.WORKFLOW] = {
        "Security Scan": {
            "kind": "control-metadata",
            "reason": "Original OWNER policy decision; product not fetched or scanned",
            "execution_steps": copy.deepcopy(policy.EXECUTION_STEPS),
            "pytest": None,
        }
    }
    data.update(
        spec=spec, run=run, job=job, check=check, reader=reader, trusted_checkout=trusted_checkout
    )

    def api(endpoint):
        if "/contents/" in endpoint:
            path, revision = endpoint.split("/contents/", 1)[1].split("?ref=", 1)
            body = (
                fixed_main_sources[path]
                if revision == trusted_checkout
                else (data["product"] / path).read_bytes()
            )
            return {
                "type": "file",
                "path": path,
                "encoding": "base64",
                "size": len(body),
                "content": base64.b64encode(body).decode(),
            }
        if "/check-runs/" in endpoint:
            return copy.deepcopy(data["check"])
        if "/actions/runs/" in endpoint:
            number = int(re.search(r"/actions/runs/(\d+)", endpoint)[1])
            observed = next(o for o in data["observations"] if o["run"]["id"] == number)
            return copy.deepcopy(
                {"total_count": len(observed["jobs"]), "jobs": observed["jobs"]}
                if "/jobs?" in endpoint
                else observed["run"]
            )
        if "/artifacts/" in endpoint:
            return copy.deepcopy(data["artifact"])
        if "/pulls/" in endpoint:
            return copy.deepcopy(data["pull"])
        if "/git/commits/" in endpoint:
            return copy.deepcopy(data["commit"])
        raise AssertionError(endpoint)

    def download(job_id, path):
        with path.open("xb") as stream:
            stream.write(data["logs"][job_id])

    monkeypatch.setattr(reader, "api", api)
    monkeypatch.setattr(policy, "api", api)
    monkeypatch.setattr(reader, "download_job_log", download)
    monkeypatch.setattr(qualifier, "api", api)
    monkeypatch.setattr(qualifier, "collect_source_ci_bindings", reader.collect_source_ci_bindings)
    _persist(data, monkeypatch)
    return data


def _verify(data):
    return policy.verify_policy_decision(
        data["profile"],
        data["identity"],
        data["spec"],
        data["pull"],
        data["commit"],
        data["run"],
        [data["job"]],
        data["check"],
        data["logs"][data["job"]["id"]],
    )


@pytest.mark.parametrize("scenario", [{"owner_security_policy": True}], indirect=True)
def test_actual_reader_qualifier_and_all_app_join_preserve_not_scanned(owner, tmp_path):
    result = invoke(owner, tmp_path)
    assert result["source_ci_pass"] is True and result["technical_workflows"] == 16
    (decision,) = result["trusted_security_policy_decisions"]
    assert decision == result["all_apps"]["verified_original_security_policy_decisions"][0]
    assert decision["policy_result"] == "trusted-author-OWNER-not-scanned"
    assert (
        decision["product_input_fetched"]
        is decision["scan_performed"]
        is decision["detectors_executed"]
        is False
    )
    assert len(decision["original_skipped_steps"]) == 10
    assert result["test_artifacts"][0]["result"]["logical_cases"] == 1
    assert (
        result["exact_product_PG_pass"]
        is result["image_admission"]
        is result["production_admission"]
        is False
    )


@pytest.mark.parametrize("scenario", [{"owner_security_policy": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "product",
        "tree",
        "baseline",
        "main_domain",
        "other_workflow",
        "policy_hash",
        "unreviewed_main",
        "extra_field",
        "wrong_event",
        "other_author",
        "wrong_PR",
        "check_provider",
        "check_source",
        "suite",
        "failed_detector",
        "executed_detector",
        "wrong_checkout",
        "wrong_output",
        "shell_echo",
        "outside_window",
        "duplicate_output",
        "wrong_ENV",
        "missing_ENV",
        "duplicate_ENV",
        "maintainers",
        "job_tuple",
        "run_tuple",
        "check_tuple",
    ],
)
def test_original_owner_predicate_rejects_inexact_native_evidence(owner, fault):
    row = owner["spec"]["trusted_security_policy"]
    job_id = owner["job"]["id"]
    log = owner["logs"][job_id].decode()
    if fault in {"product", "tree", "baseline", "main_domain", "policy_hash", "extra_field"}:
        key, value = {
            "product": ("product_revision", "a" * 40),
            "tree": ("product_tree", "a" * 40),
            "baseline": ("baseline_revision", "a" * 40),
            "main_domain": ("validation_base_ref", "main"),
            "policy_hash": ("should_scan_sha256", "a" * 64),
            "extra_field": ("allow", True),
        }[fault]
        row[key] = value
    if fault == "unreviewed_main":
        row["trusted_checkout_revision"] = "a" * 40
        owner["spec"]["jobs"]["Security Scan"]["checkouts"][0]["revision"] = "a" * 40
        log = log.replace(owner["trusted_checkout"], "a" * 40)
    if fault == "other_workflow":
        owner["spec"]["path"] = ".github/workflows/lint.yml"
    if fault == "wrong_event":
        owner["run"]["event"] = "workflow_run"
    if fault == "other_author":
        owner["pull"]["user"]["login"] = "other"
    if fault == "wrong_PR":
        owner["run"]["pull_requests"][0]["number"] += 1
    if fault == "check_provider":
        owner["check"]["app"]["id"] = 42
    if fault == "check_source":
        owner["check"]["head_sha"] = "a" * 40
    if fault == "suite":
        owner["check"]["check_suite"]["id"] += 1
    if fault in {"failed_detector", "executed_detector"}:
        owner["job"]["steps"][5]["conclusion"] = (
            "failure" if fault == "failed_detector" else "success"
        )
    if fault == "wrong_checkout":
        log = log.replace(owner["trusted_checkout"], "a" * 40)
    if fault == "wrong_output":
        log = log.replace("scan=false (trusted author", "scan=true (trusted author")
    if fault == "shell_echo":
        lines = log.splitlines()
        decision = lines.pop()
        lines.insert(next(i for i, s in enumerate(lines) if s.endswith("env:")), decision)
        log = "\n".join(lines) + "\n"
    if fault == "outside_window":
        log = log.replace("13:59:16.", "14:01:16.")
    if fault == "duplicate_output":
        log += log.splitlines()[-1] + "\n"
    if fault == "wrong_ENV":
        log = log.replace("AUTHOR_ASSOCIATION: OWNER", "AUTHOR_ASSOCIATION: MEMBER")
    if fault == "missing_ENV":
        log = "\n".join(line for line in log.splitlines() if "EVENT_NAME:" not in line) + "\n"
    if fault == "duplicate_ENV":
        log = log.replace("env:", "env:\n2026-10-24T13:59:16.100Z   EVENT_NAME: pull_request")
    if fault == "maintainers":
        log = log.replace("MAINTAINERS: fixture-maintainer", "MAINTAINERS: different")
    owner["logs"][job_id] = log.encode()
    # Rebind reviewed object hashes for semantic corruptions: parser assertions must still reject.
    row.update(
        run_sha256=policy.digest(owner["run"]),
        job_sha256=policy.digest(owner["job"]),
        check_sha256=policy.digest(owner["check"]),
        job_log_sha256=hashlib.sha256(log.encode()).hexdigest(),
    )
    if fault in {"job_tuple", "run_tuple", "check_tuple"}:
        row[fault.replace("_tuple", "_sha256")] = "a" * 64
    with pytest.raises(ValueError):
        _verify(owner)


@pytest.mark.parametrize("scenario", [{"owner_security_policy": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "missing_typed",
        "unregistered",
        "wrong_plan",
        "all_app",
        "policy_bytes",
        "late_run",
        "late_log",
    ],
)
def test_full_consumer_rejects_missing_capability_and_changed_late_native_data(
    owner, tmp_path, monkeypatch, fault
):
    reader = owner["reader"]
    if fault in {"unregistered", "wrong_plan"}:
        if fault == "unregistered":
            del owner["spec"]["trusted_security_policy"]
        else:
            owner["policy"]["job_evidence"][policy.WORKFLOW]["Security Scan"][
                "execution_steps"
            ].pop()
        _persist(owner, monkeypatch)
    if fault == "all_app":
        owner["check"]["app"]["id"] = 42
    if fault == "policy_bytes":
        original_api = policy.api

        def changed(endpoint):
            result = original_api(endpoint)
            if "/contents/.github/scripts/security-scan/should-scan.sh?" in endpoint:
                result["content"] = base64.b64encode(b"changed policy\n").decode()
                result["size"] = len(b"changed policy\n")
            return result

        monkeypatch.setattr(policy, "api", changed)
    if fault in {"missing_typed", "late_run", "late_log"}:
        actual = reader.collect_source_ci_bindings

        def collect(*args):
            observed = actual(*args)
            if fault == "missing_typed":
                return dict(observed)
            if fault == "late_run":
                owner["run"]["unexpected_late_change"] = True
            if fault == "late_log":
                owner["logs"][owner["job"]["id"]] += b"2026-10-24T13:59:16.900Z changed late\n"
            return observed

        monkeypatch.setattr(qualifier, "collect_source_ci_bindings", collect)
    with pytest.raises(ValueError):
        invoke(owner, tmp_path)
