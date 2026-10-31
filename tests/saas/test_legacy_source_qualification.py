"""Join complete reviewed source-CI contracts and preserve governance refusals."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for name in (
    "legacy_native_evidence",
    "protected_legacy_initial_build",
    "legacy_source_ci",
    "legacy_check_history",
    "legacy_pytest_results",
    "legacy_artifact_download",
    "legacy_pr_candidate",
    "legacy_build_controller",
    "legacy_domain_eligibility",
    "legacy_source_qualification",
):
    key = "saas.scripts." + name
    if name == "legacy_native_evidence" and key in sys.modules:
        continue
    spec = importlib.util.spec_from_file_location(key, ROOT / "saas/scripts" / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
core = sys.modules["saas.scripts.protected_legacy_initial_build"]
qualifier = sys.modules["saas.scripts.legacy_source_qualification"]
GOV = ".github/workflows/saas-n1-merge-gate.yml"


def owner_main_sources(root):
    from saas.scripts import legacy_security_policy as security

    fixture = json.loads((root / "tests/saas/resources/owner-fixed-main-sources.json").read_text())
    assert set(fixture) == {"schema_version", "source_revision", "sources"}
    assert type(fixture["schema_version"]) is int and fixture["schema_version"] == 1
    assert fixture["source_revision"] == security.MAIN
    assert set(fixture["sources"]) == set(security.SOURCES)
    sources = {}
    for path, expected in security.SOURCES.items():
        row = fixture["sources"][path]
        assert set(row) == {"sha256", "text"}
        body = row["text"].encode()
        assert row["sha256"] == hashlib.sha256(body).hexdigest() == expected
        sources[path] = body
    return sources


@pytest.fixture
def scenario(tmp_path, monkeypatch, request):
    # No matching immutable Git primitive exists; this fixture owns its two
    # product commits and one control commit, with native APIs substituted.
    product = tmp_path / "product"
    product.mkdir()

    def git(root, *args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    def init(root):
        git(root, "init", "-q")
        git(root, "config", "user.name", "Source contract fixture")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "commit.gpgsign", "false")

    init(product)
    workflow_root = product / ".github/workflows"
    workflow_root.mkdir(parents=True)
    for path in [*qualifier._MANDATORY_TECHNICAL, GOV]:
        (product / path).write_text("name: Original fixture\non: pull_request\njobs: {}\n")
    if getattr(request, "param", {}).get("main_domain"):
        (product / GOV).write_bytes(
            (ROOT / "tests/saas/resources/main-domain-merge-gate.yml").read_bytes()
        )
    if getattr(request, "param", {}).get("owner_security_policy"):
        (product / ".github/workflows/security-scan.yml").write_bytes(
            owner_main_sources(ROOT)[".github/workflows/security-scan.yml"]
        )
    pg_paths = []
    if getattr(request, "param", {}).get("pg_inputs"):
        for index in range(21):
            path = f"fixtures/pg-input-{index:02d}.txt"
            target = product / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"original fixture input {index}\n")
            pg_paths.append(path)
    (product / "uv.toml").write_text('resolution="highest"\n')
    git(product, "add", ".")
    git(product, "commit", "-qm", "baseline fixture")
    base = git(product, "rev-parse", "HEAD")
    (product / "uv.toml").write_text('resolution="lowest-direct"\n')
    git(product, "add", "uv.toml")
    git(product, "commit", "-qm", "material fixture")
    revision, tree = (
        git(product, "rev-parse", "HEAD"),
        git(product, "rev-parse", "HEAD^{tree}"),
    )
    monkeypatch.setitem(core.BASELINES, "Core", base)
    profile = {
        "schema_version": 1,
        "repository": core.REPOSITORY,
        "component": "Core",
        "baseline_revision": base,
        "product_revision": revision,
        "product_tree": tree,
        "source_date_epoch": int(git(product, "show", "-s", "--format=%ct", revision)),
        "application_version": "0.18.0.dev20261006",
        "source_delta": [
            {
                "path": "uv.toml",
                "before": {
                    "mode": "100644",
                    "sha256": hashlib.sha256(b'resolution="highest"\n').hexdigest(),
                },
                "after": {
                    "mode": "100644",
                    "sha256": hashlib.sha256(b'resolution="lowest-direct"\n').hexdigest(),
                },
            }
        ],
    }
    catalog = qualifier.workflow_catalog(product, revision)
    identity = {
        "schema_version": 1,
        "component": "Core",
        "product_revision": revision,
        "product_tree": tree,
        "validation_pr": 9001,
        "validation_base_ref": "codex/legacy-validation-core-dc1e9a97",
        "workflows": [],
    }
    plans = {}
    observations = []
    checks = []
    runs = []
    for index, path in enumerate(sorted(qualifier._MANDATORY_TECHNICAL)):
        number = 1000 + index
        job_id = 2000 + index
        is_pytest = path == ".github/workflows/ci.yml"
        step = {
            "number": 9,
            "name": "Run pytest" if is_pytest else "Run original command",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-24T14:00:00Z",
            "completed_at": "2026-10-24T14:00:05Z",
        }
        upload = {
            "number": 11,
            "name": "Upload pytest artifacts",
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-10-24T14:00:06Z",
            "completed_at": "2026-10-24T14:00:07Z",
        }
        job = {
            "id": job_id,
            "name": "Original tests",
            "run_id": number,
            "run_attempt": 1,
            "head_sha": revision,
            "status": "completed",
            "conclusion": "success",
            "check_run_url": f"https://api.github.com/repos/{core.REPOSITORY}/check-runs/{job_id}",
            "steps": [step] + ([upload] if is_pytest else []),
        }
        run = {
            "id": number,
            "workflow_id": 3000 + index,
            "path": path,
            "run_attempt": 1,
            "head_sha": revision,
            "event": "pull_request",
            "check_suite_id": 4000 + index,
            "status": "completed",
            "conclusion": "success",
            "pull_requests": [{"number": 9001}],
            "repository": {"full_name": core.REPOSITORY},
        }
        runs.append(run)
        checks.append(
            {
                "id": job_id,
                "head_sha": revision,
                "name": job["name"],
                "app": {"id": 15368},
                "check_suite": {"id": run["check_suite_id"]},
                "status": "completed",
                "conclusion": "success",
            }
        )
        identity["workflows"].append(
            {
                "path": path,
                "name": "Original fixture",
                "source_sha256": catalog[path],
                "run_id": number,
                "attempt": 1,
                "jobs": {
                    job["name"]: {
                        "labels": ["ubuntu-latest"],
                        "conclusion": "success",
                        "checkouts": [
                            {
                                "number": 2,
                                "name": "Original checkout",
                                "revision": "product-merge",
                            }
                        ],
                    }
                },
            }
        )
        artifact = (
            {
                "artifact_id": 5000,
                "artifact_name": "original-pytest",
                "xml_member": "pytest.xml",
                "test_step": {"number": 9, "name": "Run pytest"},
                "upload_step": {"number": 11, "name": "Upload pytest artifacts"},
                "approved_skips": [],
                "approved_reruns": [],
            }
            if is_pytest
            else None
        )
        plans[path] = {
            job["name"]: {
                "kind": "pytest" if is_pytest else "native-command",
                "reason": "Original complete command preserved",
                "execution_steps": [{"number": 9, "name": step["name"]}],
                "pytest": artifact,
            }
        }
        observations.append({"run": run, "jobs": [job]})
    policy = {
        "component": "Core",
        "product_revision": revision,
        "product_tree": tree,
        "identity_contract_sha256": qualifier._digest(identity),
        "workflow_catalog": {
            path: {
                "sha256": digest,
                "disposition": "original-governance" if path == GOV else "required-technical",
                "reason": "Original eligibility reviewed",
            }
            for path, digest in catalog.items()
        },
        "job_evidence": plans,
        "other_checks": [],
        "statuses": [],
        "domain_not_applicable": {},
    }
    merge = "d" * 40
    snapshots = {
        "head": {"revision": revision, "checks": checks, "runs": runs, "statuses": []},
        "merge": {"revision": merge, "checks": [], "runs": [], "statuses": []},
    }
    xml = (
        b'<testsuites><testsuite tests="1" failures="0" erro'
        b'rs="0" skipped="0"><testcase classname="tests.unit'
        b'.test_original" name="test_one"/></testsuite></tes'
        b"tsuites>"
    )
    fixture_zip = tmp_path / "native-test.zip"
    with zipfile.ZipFile(fixture_zip, "w") as bundle:
        bundle.writestr("pytest.xml", xml)
    ci = next(item for item in observations if item["run"]["path"] == ".github/workflows/ci.yml")
    artifact_meta = {
        "id": 5000,
        "name": "original-pytest",
        "expired": False,
        "size_in_bytes": fixture_zip.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(fixture_zip.read_bytes()).hexdigest(),
        "workflow_run": {"id": ci["run"]["id"], "head_sha": revision},
        "created_at": "2026-10-24T14:00:07Z",
    }
    control = tmp_path / "control"
    store = control / "saas/supply_chain"
    store.mkdir(parents=True)
    for name, value in [
        ("legacy-security-build-profiles", profile),
        ("legacy-security-ci-profiles", identity),
        ("legacy-source-qualification-profiles", policy),
    ]:
        (store / (name + ".json")).write_text(
            json.dumps({"schema_version": 1, "profiles": {"Core": value}})
        )
    if pg_paths:
        generic = control / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
        generic.parent.mkdir(parents=True)
        generic.write_text(
            "POSTGRESQL_N1_TRUSTED_INPUTS=(\n"
            + "".join(f'  "{path}|{"f" * 64}"\n' for path in pg_paths)
            + ")\n"
        )
        pg = {key: profile[key] for key in ("component", "product_revision", "product_tree")}
        pg["trusted_inputs"] = {
            path: hashlib.sha256((product / path).read_bytes()).hexdigest() for path in pg_paths
        }
        (store / "legacy-security-pg-profiles.json").write_text(
            json.dumps({"schema_version": 1, "profiles": {"Core": pg}})
        )
    if getattr(request, "param", {}).get("control_workflow"):
        path = control / ".github/workflows/saas-legacy-security-build.yml"
        path.parent.mkdir(parents=True)
        path.write_bytes((ROOT / ".github/workflows/saas-legacy-security-build.yml").read_bytes())
    init(control)
    git(control, "add", ".")
    git(control, "commit", "-qm", "control fixture")
    control_sha = git(control, "rev-parse", "HEAD")
    for name, value in {
        "GITHUB_REPOSITORY": core.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": control_sha,
    }.items():
        monkeypatch.setenv(name, value)
    repository = {"full_name": core.REPOSITORY}
    pull = {
        "number": 9001,
        "state": "open",
        "draft": False,
        "head": {"sha": revision, "repo": repository},
        "base": {
            "sha": base,
            "ref": identity["validation_base_ref"],
            "repo": repository,
        },
        "merge_commit_sha": merge,
    }
    commit = {
        "sha": merge,
        "tree": {"sha": tree},
        "parents": [{"sha": base}, {"sha": revision}],
    }
    data = {
        "profile": profile,
        "identity": identity,
        "policy": policy,
        "catalog": catalog,
        "snapshots": snapshots,
        "observations": observations,
        "pull": pull,
        "commit": commit,
        "artifact": artifact_meta,
        "control": control,
        "control_sha": control_sha,
        "product": product,
        "fixture_zip": fixture_zip,
    }

    def source_identity(_control, component, destination):
        assert component == "Core"
        destination.mkdir()
        (destination / f"job-{ci['jobs'][0]['id']}.log").write_text(
            "2026-10-24T14:00:01Z 1 worker [1 item]\n2026-10-24T"
            "14:00:02Z [gw0] [100%] PASSED tests/unit/test_orig"
            "inal.py::test_one\n"
        )
        return {
            "product_revision": revision,
            "product_tree": tree,
            "merge_commit": merge,
            "workflows": copy.deepcopy(data["observations"]),
        }

    def api(endpoint):
        if "/artifacts/" in endpoint:
            return copy.deepcopy(data["artifact"])
        if "/pulls/" in endpoint:
            return copy.deepcopy(data["pull"])
        if "/git/commits/" in endpoint:
            return copy.deepcopy(data["commit"])
        raise AssertionError(endpoint)

    monkeypatch.setattr(qualifier, "collect_source_ci_bindings", source_identity)
    monkeypatch.setattr(
        qualifier,
        "collect_snapshot",
        lambda sha: copy.deepcopy(data["snapshots"]["head" if sha == revision else "merge"]),
    )
    monkeypatch.setattr(qualifier, "api", api)
    monkeypatch.setattr(
        qualifier,
        "download_artifact_bytes",
        lambda _id, path, **kwargs: path.write_bytes(data["fixture_zip"].read_bytes()),
    )
    return data


def invoke(scenario, tmp_path):
    return qualifier.qualify_source_ci(
        scenario["control"],
        scenario["product"],
        "Core",
        scenario["control_sha"],
        tmp_path / "qualified",
    )


def test_complete_source_join_uses_real_Git_and_keeps_PG_image_production_separate(
    scenario, tmp_path
):
    result = invoke(scenario, tmp_path)
    assert result["source_ci_pass"] is True and result["technical_workflows"] == 16
    assert result["test_artifacts"][0]["result"]["logical_cases"] == 1
    assert (
        result["exact_product_PG_pass"] is False
        and result["image_admission"] is False
        and result["production_admission"] is False
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing_catalog",
        "catalog_hash",
        "demote_workflow",
        "missing_job_plan",
        "step_not_executed",
        "artifact_id",
        "expired_artifact",
        "moved_PR",
        "source_dirty",
    ],
)
def test_full_join_rejects_missing_policy_native_execution_and_final_source_drift(
    scenario, tmp_path, monkeypatch, fault
):
    if fault in {
        "missing_catalog",
        "catalog_hash",
        "demote_workflow",
        "missing_job_plan",
    }:
        policy = copy.deepcopy(scenario["policy"])
        path = ".github/workflows/ci.yml"
        if fault == "missing_catalog":
            policy["workflow_catalog"].pop(path)
        if fault == "catalog_hash":
            policy["workflow_catalog"][path]["sha256"] = "0" * 64
        if fault == "demote_workflow":
            policy["workflow_catalog"][path]["disposition"] = "original-informational"
        if fault == "missing_job_plan":
            policy["job_evidence"][path] = {}
        with pytest.raises(ValueError):
            qualifier.validate_qualification_policy(
                policy, scenario["identity"], scenario["catalog"]
            )
        return
    if fault == "step_not_executed":
        scenario["observations"][0]["jobs"][0]["steps"][0]["conclusion"] = "skipped"
    if fault == "artifact_id":
        scenario["artifact"]["id"] = 9999
    if fault == "expired_artifact":
        scenario["artifact"]["expired"] = True
    if fault == "moved_PR":
        scenario["pull"]["base"]["sha"] = "f" * 40
    if fault == "source_dirty":
        (scenario["product"] / "uv.toml").write_text("unsealed\n")
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)


def test_original_governance_refusal_is_preserved_and_not_source_clearance(
    scenario, tmp_path, monkeypatch
):
    head = scenario["snapshots"]["head"]
    revision = scenario["profile"]["product_revision"]
    head["runs"].append(
        {
            "id": 9009,
            "workflow_id": 9909,
            "path": GOV,
            "run_attempt": 1,
            "head_sha": revision,
            "event": "pull_request_target",
            "check_suite_id": 7009,
            "status": "completed",
            "conclusion": "failure",
            "pull_requests": [{"number": 9001}],
        }
    )
    head["checks"].append(
        {
            "id": 8009,
            "head_sha": revision,
            "name": "evaluate",
            "app": {"id": 15368},
            "check_suite": {"id": 7009},
            "status": "completed",
            "conclusion": "failure",
        }
    )
    scenario["policy"]["other_checks"] = [
        {
            "role": "head",
            "app_id": 15368,
            "suite_id": 7009,
            "name": "evaluate",
            "scope": "original-governance",
            "expected_conclusion": None,
            "reason": "Original protected policy requires administrator scope",
        }
    ]
    monkeypatch.setattr(qualifier, "load_qualification_policy", lambda *_: scenario["policy"])
    result = invoke(scenario, tmp_path)
    assert result["status"] == "blocked-governance" and result["source_ci_pass"] is False
    assert result["all_apps"]["governance_refusals"][0]["conclusion"] == "failure"
    monkeypatch.setattr(qualifier, "qualify_source_ci", lambda *_: result)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualification",
            "--control",
            str(scenario["control"]),
            "--product",
            str(scenario["product"]),
            "--component",
            "Core",
            "--control-revision",
            scenario["control_sha"],
            "--destination",
            str(tmp_path / "other"),
        ],
    )
    assert qualifier.main() == 2


@pytest.mark.parametrize(
    "fault",
    [
        "unknown_check",
        "wrong_status_creator",
        "failed_required_status",
        "changed_snapshot",
    ],
)
def test_unified_check_policy_cannot_ignore_new_checks_creators_or_new_failures(
    scenario, tmp_path, monkeypatch, fault
):
    head = scenario["snapshots"]["head"]
    if fault == "unknown_check":
        head["checks"].append(
            {
                "id": 9001,
                "head_sha": head["revision"],
                "name": "External",
                "app": {"id": 888},
                "check_suite": {"id": 9001},
                "status": "completed",
                "conclusion": "success",
            }
        )
    if fault in {"wrong_status_creator", "failed_required_status"}:
        head["statuses"].append(
            {
                "id": 8001,
                "context": "Original status",
                "creator": {"id": 222},
                "state": "failure" if fault == "failed_required_status" else "success",
            }
        )
        scenario["policy"]["statuses"] = [
            {
                "role": "head",
                "context": "Original status",
                "creator_id": 111 if fault == "wrong_status_creator" else 222,
                "scope": "required-technical",
                "reason": "Original required provider",
            }
        ]
        monkeypatch.setattr(qualifier, "load_qualification_policy", lambda *_: scenario["policy"])
    if fault == "changed_snapshot":
        calls = []

        def snapshot(sha):
            calls.append(sha)
            value = copy.deepcopy(
                scenario["snapshots"]["head" if sha == head["revision"] else "merge"]
            )
            if len(calls) > 2 and value["checks"]:
                value["checks"][0]["conclusion"] = "failure"
            return value

        monkeypatch.setattr(qualifier, "collect_snapshot", snapshot)
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)


def test_empty_default_qualification_store_does_not_register_any_source(tmp_path):
    store = tmp_path / "saas/supply_chain"
    store.mkdir(parents=True)
    empty = {"schema_version": 1, "profiles": {}}
    path = store / "legacy-source-qualification-profiles.json"
    path.write_text(json.dumps(empty))
    assert json.loads(path.read_text()) == empty
    with pytest.raises(ValueError):
        qualifier.load_qualification_policy(
            tmp_path,
            {
                "component": "Core",
                "product_revision": "a" * 40,
                "product_tree": "b" * 40,
            },
        )


@pytest.mark.parametrize("fault", ["early_native_failure", "artifact_metadata_failure"])
def test_unified_failure_always_preserves_stage_native_response_and_same_refusal(
    scenario, tmp_path, monkeypatch, fault
):
    capture = sys.modules["saas.scripts.legacy_native_evidence"]
    if fault == "early_native_failure":
        original = copy.deepcopy(scenario["observations"][0]["run"])
        original["conclusion"] = "failure"
        initial_api = qualifier.api
        monkeypatch.setattr(
            capture,
            "_native_api",
            lambda endpoint: (
                original if endpoint == "native-source-run" else initial_api(endpoint)
            ),
        )
        monkeypatch.setattr(qualifier, "api", capture.api)

        def failed_reader(_control, _component, _destination):
            run = capture.api("native-source-run")
            assert run["conclusion"] == "failure"
            raise ValueError("original technical failure")

        monkeypatch.setattr(qualifier, "collect_source_ci_bindings", failed_reader)
        expected_stage = "source-identity-reader"
    else:
        scenario["artifact"]["expired"] = True
        monkeypatch.setattr(capture, "_native_api", qualifier.api)
        monkeypatch.setattr(qualifier, "api", capture.api)
        expected_stage = "pytest-artifact"
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    # Invoke uses an owned destination; find its unique capture independently.
    receipts = list(tmp_path.rglob("native-api/receipt.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text())
    assert expected_stage in receipt["stage"]
    assert receipt["invocation_raised"] and receipt["exception_type"] == "ValueError"
    assert receipt["source_ci_admission"] is False
    assert len(receipt["records"]) == 3
    record = json.loads((receipts[0].parent / receipt["records"][-1]["path"]).read_text())
    if fault == "early_native_failure":
        assert record["response"]["conclusion"] == "failure"
    else:
        assert record["response"]["expired"] is True
    assert (receipts[0].parent.parent / "native-checks-before.json").is_file()
    assert any(row["path"] == "native-checks-before.json" for row in receipt["files"])
    assert not (receipts[0].parent.parent / "source-qualification.json").exists()


@pytest.mark.parametrize("boundary", ["metadata", "direct"])
def test_bootstrap_request_safety_caps_count_real_boundaries_and_latch_failure(
    tmp_path, monkeypatch, boundary
):
    from saas.scripts import legacy_native_evidence as capture

    calls = []
    monkeypatch.setattr(
        capture, "_native_api", lambda endpoint: calls.append(endpoint) or {"ok": True}
    )
    with pytest.raises(capture.NativeEvidenceFailure, match="safety cap"):
        with capture.preserve_native_evidence(tmp_path / "native") as evidence:
            evidence.enable_bootstrap_limits()
            if boundary == "metadata":
                for index in range(1024):
                    capture.api(f"metadata/{index}")
                with pytest.raises(capture.NativeEvidenceFailure, match="metadata safety cap"):
                    capture.api("metadata/1025")
                assert len(calls) == 1024
            else:
                for index in range(256):
                    capture.reserve_native_download(f"direct/{index}")
                with pytest.raises(
                    capture.NativeEvidenceFailure, match="direct download safety cap"
                ):
                    capture.reserve_native_download("direct/257")
                assert evidence.bootstrap_usage()["direct_downloads_started"] == 256
            with pytest.raises(capture.NativeEvidenceFailure):
                capture.api("must-not-submit-after-fatal")
    receipt = json.loads((tmp_path / "native/receipt.json").read_text())
    assert receipt["invocation_raised"] is receipt["capture_failed"] is True
    assert receipt["bootstrap_request_safety"]["metadata_started"] == len(calls)


def test_bootstrap_native_403_preserves_first_exception_and_stops_submissions(
    tmp_path, monkeypatch
):
    from saas.scripts import legacy_native_evidence as capture

    failure = subprocess.CalledProcessError(1, ["gh", "api", "fixed"], stderr=b"HTTP 403")
    calls = []

    def failed(endpoint):
        calls.append(endpoint)
        raise failure

    monkeypatch.setattr(capture, "_native_api", failed)
    with pytest.raises(capture.NativeEvidenceFailure):
        with capture.preserve_native_evidence(tmp_path / "native") as evidence:
            evidence.enable_bootstrap_limits()
            with pytest.raises(subprocess.CalledProcessError) as raised:
                capture.api("fixed")
            assert raised.value is failure
            with pytest.raises(capture.NativeEvidenceFailure):
                capture.api("must-not-submit")
            assert calls == ["fixed"]


def test_bootstrap_rate_advisory_is_same_job_only_and_unknown_is_not_a_gate(tmp_path, monkeypatch):
    from saas.scripts import legacy_native_evidence as capture

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GH_TOKEN", "fixture-never-a-real-token")
    calls = []

    def failed(endpoint):
        calls.append(endpoint)
        raise subprocess.CalledProcessError(1, ["gh", "api", endpoint])

    monkeypatch.setattr(capture, "_native_api", failed)
    with capture.preserve_native_evidence(tmp_path / "native") as evidence:
        evidence.enable_bootstrap_limits()
        evidence.observe_bootstrap_rate_limit()
        assert evidence.rate_advisory == {
            "status": "UNKNOWN",
            "exception_type": "CalledProcessError",
        }
        assert calls == ["rate_limit"] and evidence._failure is None
