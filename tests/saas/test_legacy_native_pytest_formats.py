"""Small unit transcripts and archives; no native or source-CI qualification."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import xml.etree.ElementTree as ET
import zipfile

import pytest

from tests.saas import test_legacy_pytest_results as original

reader = original.reader
source_ci = importlib.import_module("saas.scripts.legacy_source_ci")
qualifier = importlib.import_module("saas.scripts.legacy_source_qualification")


def unit_arguments(tmp_path, label):
    """Own a tiny ZIP and API-shaped records; no external artifacts or collector."""
    root = ET.fromstring(original.junit([("test_pass", "passed"), ("test_skip", "skipped")]))
    suite = root.find("testsuite")
    native_log = original.raw_log(
        [".s [100%]", "================= 1 passed, 1 skipped in 0.10s ================="],
        count=2,
    )
    ordinary_hash = hashlib.sha256(
        json.dumps(
            {
                "attributes": {"message": "original known reason"},
                "text": "original reason",
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    skips = {(original.CLASS, "test_skip"): ordinary_hash}
    if label == "slack":
        for case in suite:
            case.set("classname", "integrations.slack.tests.unit_fixture")
            if len(case):
                case.remove(case[0])
        suite.set("skipped", "0")
        skips = {}
        native_log = original.raw_log(
            [
                "[gw0] [ 50%] PASSED integrations/slack/tests/unit_fixture.py::test_pass",
                "[gw0] [100%] PASSED integrations/slack/tests/unit_fixture.py::test_skip",
            ],
            count=2,
        )
    elif label == "misc":
        suite.append(copy.deepcopy(original.UNIT_COLLECTION))
        suite.set("tests", "4")
        suite.set("skipped", "2")
        skips.update(original.COLLECTION_APPROVAL)
        native_log = original.raw_log(
            [
                original.event("test_pass", "RERUN"),
                original.event("test_pass", "RERUN"),
                original.event("test_pass"),
                original.event("test_skip", "SKIPPED"),
                "[gw0] [100%] SUBPASSED(value='unit') tests/unit/test_example.py::test_pass",
            ],
            count=2,
        )
        lines = native_log.splitlines()
        lines[3] = "\ufeff" + lines[3]
        native_log = "\n".join(lines)
    archive = tmp_path / (label + "-unit.zip")
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("pytest-unit.xml", ET.tostring(root))
    revision = "a" * 40
    test = original.STEP | {"number": 9, "name": "Run pytest"}
    upload = {
        "number": 11,
        "name": "Upload pytest artifacts",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-10-24T14:00:11Z",
        "completed_at": "2026-10-24T14:00:12Z",
    }
    run = {
        "id": 41,
        "run_attempt": 1,
        "head_sha": revision,
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/ci.yml",
        "repository": {"full_name": "Dream1216/omnigent"},
    }
    job = {
        "id": 88,
        "name": f"Pytest ({label})",
        "run_id": 41,
        "run_attempt": 1,
        "head_sha": revision,
        "status": "completed",
        "conclusion": "success",
        "steps": [test, upload],
    }
    metadata = {
        "id": 121,
        "name": "pytest-unit-fixture-41",
        "expired": False,
        "workflow_run": {"id": 41, "head_sha": revision},
        "size_in_bytes": archive.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
        "created_at": "2026-10-24T14:00:12Z",
    }
    return {
        "metadata": metadata,
        "run": run,
        "job": job,
        "revision": revision,
        "artifact_name": metadata["name"],
        "upload_step": {"number": 11, "name": upload["name"]},
        "archive": archive,
        "xml_member": "pytest-unit.xml",
        "native_log": native_log,
        "test_step": {"number": 9, "name": test["name"]},
        "approved_skips": skips,
        "approved_reruns": {},
    }


def owned_review_contract(args):
    """Unit fixture only; never write a trusted store or claim human approval."""
    return {
        "kind": "legacy_native_pytest_compact_summary/v1",
        "source_revision": args["revision"],
        "workflow_path": args["run"]["path"],
        "run_id": args["run"]["id"],
        "attempt": args["run"]["run_attempt"],
        "job_id": args["job"]["id"],
        "job_name": args["job"]["name"],
        "test_step": copy.deepcopy(args["test_step"]),
        "upload_step": copy.deepcopy(args["upload_step"]),
        "artifact_id": args["metadata"]["id"],
        "artifact_sha256": args["metadata"]["digest"][7:],
        "xml_member": args["xml_member"],
        "native_log_text_sha256": hashlib.sha256(args["native_log"].encode()).hexdigest(),
    }


@pytest.mark.parametrize("label", ["stores-mysql", "stores-postgres", "stores-crdb-23.2.28"])
def test_unit_compact_fixtures_require_explicit_owned_contract_and_never_invent_verbose_cases(
    label, tmp_path
):
    args = unit_arguments(tmp_path, label)
    with pytest.raises(ValueError, match="omits collected tests"):
        reader.verify_pytest_evidence(**args)
    result = reader.verify_pytest_evidence(**args, native_log_contract=owned_review_contract(args))
    assert result["logical_cases"] == 2
    assert result["native_per_case_outcome_evidence"] is False
    assert result["skipped"] == 1
    assert result["reruns"] == 0
    assert "cases" not in result


@pytest.mark.parametrize(
    "fault",
    [
        "expired",
        "wrong_artifact_digest",
        "wrong_source",
        "wrong_run",
        "wrong_job",
        "wrong_attempt",
        "bool_attempt",
        "wrong_XML",
        "wrong_step",
        "wrong_upload",
        "unknown_kind",
        "unknown_job",
        "unknown_workflow",
        "no_exact_transcript",
        "unreviewed_skip",
        "changed_skip",
        "unproved_retry",
        "failed_job",
        "bad_created_interval",
        "missing_ZIP",
    ],
)
def test_compact_binding_and_existing_native_artifact_guards_still_reject(fault, tmp_path):
    args = unit_arguments(tmp_path, "stores-mysql")
    contract = owned_review_contract(args)
    if fault == "expired":
        args["metadata"]["expired"] = True
    elif fault == "wrong_artifact_digest":
        args["metadata"]["digest"] = "sha256:" + "0" * 64
    elif fault == "wrong_source":
        contract["source_revision"] = "0" * 40
    elif fault == "wrong_run":
        contract["run_id"] += 1
    elif fault == "wrong_job":
        contract["job_id"] += 1
    elif fault == "wrong_attempt":
        contract["attempt"] += 1
    elif fault == "bool_attempt":
        contract["attempt"] = True
    elif fault == "wrong_XML":
        contract["xml_member"] = "other.xml"
    elif fault == "wrong_step":
        contract["test_step"]["number"] += 1
    elif fault == "wrong_upload":
        contract["upload_step"]["number"] += 1
    elif fault == "unknown_kind":
        contract["kind"] += "-unknown"
    elif fault == "unknown_job":
        contract["job_name"] = "Pytest (unregistered)"
    elif fault == "unknown_workflow":
        contract["workflow_path"] = ".github/workflows/unknown.yml"
    elif fault == "no_exact_transcript":
        args["native_log"] += "\n"
    elif fault == "unreviewed_skip":
        args["approved_skips"] = {}
    elif fault == "changed_skip":
        args["approved_skips"][next(iter(args["approved_skips"]))] = "0" * 64
    elif fault == "unproved_retry":
        args["approved_reruns"] = {("tests.x", "test_a"): 1}
    elif fault == "failed_job":
        args["job"]["conclusion"] = "failure"
    elif fault == "bad_created_interval":
        args["metadata"]["created_at"] = "2000-01-01T00:00:00Z"
    else:
        args["archive"] = tmp_path / "absent.zip"
    with pytest.raises(ValueError):
        reader.verify_pytest_evidence(**args, native_log_contract=contract)


@pytest.mark.parametrize(
    "fault",
    [
        "bad_marks",
        "missing_marks",
        "bad_percentage",
        "wrong_summary",
        "unknown_summary",
        "duplicate_summary",
        "extra_collection",
        "unknown_interleaved_format",
        "XML_failure",
    ],
)
def test_even_owned_registered_compact_transcripts_cannot_hide_failed_or_incomplete_counts(
    fault, tmp_path
):
    args = unit_arguments(tmp_path, "stores-mysql")
    log = args["native_log"]
    if fault == "bad_marks":
        log = log.replace(".s [100%]", "Fs [100%]", 1)
    elif fault == "missing_marks":
        log = log.replace(".s [100%]", ". [ 50%]", 1)
    elif fault == "bad_percentage":
        log = log.replace("[100%]", "[ 99%]", 1)
    elif fault == "wrong_summary":
        log = log.replace("1 passed, 1 skipped in", "0 passed, 2 skipped in", 1)
    elif fault == "unknown_summary":
        log = log.replace("1 passed, 1 skipped in", "1 passed, 1 skipped, 1 warning in", 1)
    elif fault == "duplicate_summary":
        line = next(line for line in log.splitlines() if "1 passed, 1 skipped in" in line)
        log = log.replace(line, line + "\n" + line, 1)
    elif fault == "extra_collection":
        line = next(line for line in log.splitlines() if "4 workers [2 items]" in line)
        log = log.replace(line, line + "\n" + line, 1)
    elif fault == "unknown_interleaved_format":
        log = log.replace(".s [100%]", "unknown-progress\n2026-10-24T14:00:02Z .s [100%]", 1)
    # This pure branch test is below native ZIP identity. Its XML corruption is
    # rejected independently; the public entry separately rejects ZIP tampering.
    args["native_log"] = log
    contract = owned_review_contract(args)
    xml = reader.read_junit_member(args["archive"], args["xml_member"])
    if fault == "XML_failure":
        root = ET.fromstring(xml)
        root.find("testsuite").set("failures", "1")
        ET.SubElement(root.find("testsuite/testcase"), "failure", message="unit failure")
        xml = ET.tostring(root)
    step = next(s for s in args["job"]["steps"] if s["number"] == args["test_step"]["number"])
    with pytest.raises(ValueError):
        reader._verify_compact_results(
            xml,
            log,
            step,
            contract=contract,
            approved_skips=args["approved_skips"],
            approved_reruns={},
        )


def test_unit_slack_and_internal_single_BOM_join_preserves_retry_and_collection_skip(tmp_path):
    slack = reader.verify_pytest_evidence(**unit_arguments(tmp_path, "slack"))
    assert slack["logical_cases"] == 2
    misc = unit_arguments(tmp_path, "misc")
    misc["approved_reruns"] = {(original.CLASS, "test_pass"): 2}
    result = reader.verify_pytest_evidence(**misc)
    assert result["native_collected_cases"] == 2
    assert result["logical_cases"] == 3 and result["collection_skips"] == 1
    assert result["skipped"] == 2 and result["reruns"] == 2
    assert result["native_passed_subtests"] == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "integrations/discord/tests/",
        "integrations/slack/tests/../",
        "integrations/slack/tests//",
        "integrations/slack/tests/./",
        "integrations/slack/test/",
        "other/tests/",
    ],
)
def test_unknown_or_traversing_source_roots_still_reject(prefix):
    log = original.raw_log([f"[gw0] [100%] PASSED {prefix}unit.py::test_one"], count=1)
    with pytest.raises(ValueError):
        reader.pytest_log_inventory(log, original.STEP)


@pytest.mark.parametrize(
    "bad",
    [
        "\ufeff\ufeff2026-10-24T14:00:01Z",
        "\ufeffbad-time",
        "\ufeff2026-99-24T14:00:01Z",
        "\ufeff2026-10-24T14:00:01Zjunk",
    ],
)
def test_BOM_is_only_one_prefix_on_an_exact_valid_native_timestamp(bad):
    log = original.raw_log([original.event("test_a")], count=1)
    with pytest.raises(ValueError):
        reader.pytest_log_inventory(log + "\n" + bad + " unknown body", original.STEP)


def test_compact_policy_option_keeps_legacy_shape_and_rejects_unreviewed_or_misclassified_variants(
    tmp_path,
):
    args = unit_arguments(tmp_path, "stores-mysql")
    contract = owned_review_contract(args)
    workflows = []
    plans = {}
    catalog = {}
    for i, path in enumerate(sorted(qualifier._MANDATORY_TECHNICAL)):
        name = args["job"]["name"] if path.endswith("/ci.yml") else "Owned original command"
        workflows.append(
            {
                "path": path,
                "run_id": args["run"]["id"] if path.endswith("/ci.yml") else 1000 + i,
                "attempt": 1,
                "jobs": {name: {"conclusion": "success", "checkouts": [{"revision": "product"}]}},
            }
        )
        plans[path] = {
            name: {
                "kind": "native-command",
                "reason": "owned local fixture",
                "execution_steps": [{"number": 1, "name": "Owned command"}],
                "pytest": None,
            }
        }
        catalog[path] = {
            "sha256": "a" * 64,
            "disposition": "required-technical",
            "reason": "owned local fixture",
        }
    path = ".github/workflows/ci.yml"
    name = args["job"]["name"]
    plan = plans[path][name]
    plan.update(
        kind="pytest",
        pytest={
            "artifact_id": args["metadata"]["id"],
            "artifact_name": args["artifact_name"],
            "xml_member": args["xml_member"],
            "test_step": args["test_step"],
            "upload_step": args["upload_step"],
            "approved_skips": [],
            "approved_reruns": [],
        },
    )
    identity = {"workflows": workflows}
    policy = {
        "product_revision": args["revision"],
        "identity_contract_sha256": qualifier._digest(identity),
        "workflow_catalog": catalog,
        "job_evidence": plans,
        "other_checks": [],
        "statuses": [],
        "domain_not_applicable": {},
    }
    actual = {k: v["sha256"] for k, v in catalog.items()}
    qualifier.validate_qualification_policy(policy, identity, actual)
    plan["native_log_contract"] = contract
    qualifier.validate_qualification_policy(policy, identity, actual)
    for mutate in ("wrong_source", "unknown_field", "native_command"):
        changed = copy.deepcopy(policy)
        target = changed["job_evidence"][path][name]
        if mutate == "wrong_source":
            target["native_log_contract"]["source_revision"] = "0" * 40
        elif mutate == "unknown_field":
            target["native_log_contract"]["unknown"] = True
        else:
            target["kind"] = "native-command"
            target["pytest"] = None
        with pytest.raises(ValueError):
            qualifier.validate_qualification_policy(changed, identity, actual)


@pytest.mark.parametrize("review_hash_updated", [False, True])
def test_compact_diagnostic_footer_is_bound_to_the_full_reviewed_transcript(
    tmp_path, review_hash_updated
):
    args = unit_arguments(tmp_path, "stores-mysql")
    contract = owned_review_contract(args)
    lines = args["native_log"].splitlines()
    summary = next(index for index, line in enumerate(lines) if "1 passed, 1 skipped" in line)
    timestamp = lines[summary].partition(" ")[0]
    lines.insert(summary, timestamp + " unit unknown diagnostic footer")
    args["native_log"] = "\n".join(lines)
    if not review_hash_updated:
        with pytest.raises(ValueError, match="transcript changed"):
            reader.verify_pytest_evidence(**args, native_log_contract=contract)
        return
    # A different fixture review hash illustrates the approved-text boundary;
    # this test grants no real profile, source-CI or native transcript authority.
    contract["native_log_text_sha256"] = hashlib.sha256(args["native_log"].encode()).hexdigest()
    result = reader.verify_pytest_evidence(**args, native_log_contract=contract)
    assert result["logical_cases"] == 2
    assert result["skipped"] == 1
    assert result["native_per_case_outcome_evidence"] is False
