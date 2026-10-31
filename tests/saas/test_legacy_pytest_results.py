"""Bind full pytest selection, subtests and redacted parameters to XML."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
for name in (
    "legacy_native_evidence",
    "protected_legacy_initial_build",
    "legacy_source_ci",
    "legacy_pytest_results",
):
    key = "saas.scripts." + name
    if name == "legacy_native_evidence" and key in sys.modules:
        continue
    spec = importlib.util.spec_from_file_location(key, ROOT / "saas/scripts" / (name + ".py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
reader = sys.modules["saas.scripts.legacy_pytest_results"]
STEP = {
    "status": "completed",
    "conclusion": "success",
    "started_at": "2026-10-24T14:00:00Z",
    "completed_at": "2026-10-24T14:00:10Z",
}
CLASS = "tests.unit.test_example"


def raw_log(events, *, count, extra=()):
    lines = [f"4 workers [{count} items]", *events, *extra]
    return "\n".join(
        f"2026-10-24T14:00:01.{index:07d}Z {line}" for index, line in enumerate(lines)
    )


def event(name, outcome="PASSED"):
    return f"[gw0] [ 50%] {outcome} tests/unit/test_example.py::{name} "


def junit(cases, *, extra_tests=0):
    root = ET.Element("testsuites")
    failures = sum(outcome == "failure" for _, outcome in cases)
    skips = sum(outcome == "skipped" for _, outcome in cases)
    suite = ET.SubElement(
        root,
        "testsuite",
        tests=str(len(cases) + extra_tests),
        failures=str(failures),
        errors="0",
        skipped=str(skips),
    )
    for name, outcome in cases:
        case = ET.SubElement(suite, "testcase", classname=CLASS, name=name)
        if outcome != "passed":
            ET.SubElement(case, outcome, message="original known reason").text = "original reason"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def test_full_log_and_XML_inventory_keep_main_tests_and_subtests_distinct():
    log = raw_log(
        [event("test_a"), event("test_b")],
        count=2,
        extra=["[gw0] [ 50%] SUBPASSED(value='one') tests/unit/test_example.py::test_a"],
    )
    native = reader.pytest_log_inventory(log, STEP)
    xml = junit([("test_a", "passed"), ("test_b", "passed")], extra_tests=1)
    result = reader.verify_test_results(xml, native, approved_skips={}, approved_reruns={})
    assert result["logical_cases"] == 2 and result["native_passed_subtests"] == 1


@pytest.mark.parametrize(
    "fault",
    [
        "missing_case",
        "duplicate_case",
        "wrong_outcome",
        "extra_counter",
        "failed_case",
        "unreviewed_skip",
        "DTD",
        "foreign_root",
    ],
)
def test_XML_cannot_hide_missing_or_failed_cases_or_unreviewed_skips(fault):
    native = reader.pytest_log_inventory(
        raw_log([event("test_a"), event("test_b")], count=2), STEP
    )
    cases = [("test_a", "passed"), ("test_b", "passed")]
    if fault == "missing_case":
        cases.pop()
    if fault == "duplicate_case":
        cases[1] = cases[0]
    if fault in {"wrong_outcome", "failed_case"}:
        cases[1] = ("test_b", "failure")
    if fault == "unreviewed_skip":
        cases[1] = ("test_b", "skipped")
    xml = junit(cases, extra_tests=1 if fault == "extra_counter" else 0)
    if fault == "DTD":
        xml = b'<!DOCTYPE testsuites [<!ENTITY x "value">]>' + xml
    if fault == "foreign_root":
        xml = b'<other><testsuite tests="0" failures="0" skipped="0" errors="0"/></other>'
    with pytest.raises(ValueError):
        reader.verify_test_results(xml, native, approved_skips={}, approved_reruns={})


@pytest.mark.parametrize(
    "fault",
    [
        "empty",
        "missing_terminal",
        "duplicate_terminal",
        "unfinished_retry",
        "two_collections",
        "masked_function",
        "masked_retry",
    ],
)
def test_native_inventory_rejects_incomplete_or_ambiguous_step_output(fault):
    count = 1
    events = [event("test_a")]
    extra = []
    if fault == "empty":
        count = 0
        events = []
    if fault == "missing_terminal":
        count = 2
    if fault == "duplicate_terminal":
        events *= 2
    if fault == "unfinished_retry":
        events = [event("test_a", "RERUN")]
    if fault == "two_collections":
        extra = ["4 workers [1 items]"]
    if fault == "masked_function":
        events = [event("test_***[one]")]
    if fault == "masked_retry":
        events = [event("test_a[***]", "RERUN"), event("test_a[***]")]
    with pytest.raises(ValueError):
        reader.pytest_log_inventory(raw_log(events, count=count, extra=extra), STEP)


def test_native_redacted_parameter_collisions_cover_exact_distinct_XML_cases():
    native = reader.pytest_log_inventory(raw_log([event("test_a[***]")] * 3, count=3), STEP)
    xml = junit([(f"test_a[{value}]", "passed") for value in ("first", "second", "third")])
    result = reader.verify_test_results(xml, native, approved_skips={}, approved_reruns={})
    assert result["logical_cases"] == 3 and result["redacted_native_parameters"] == 3
    bad = junit(
        [
            ("test_a[first]", "passed"),
            ("test_a[second]", "passed"),
            ("test_other[third]", "passed"),
        ]
    )
    with pytest.raises(ValueError, match="redacted native parameters"):
        reader.verify_test_results(bad, native, approved_skips={}, approved_reruns={})


def test_overlapping_redaction_patterns_require_complete_bipartite_matching():
    native = reader.pytest_log_inventory(
        raw_log([event("test_a[a***]"), event("test_a[***b]")], count=2), STEP
    )
    result = reader.verify_test_results(
        junit([("test_a[ab]", "passed"), ("test_a[ac]", "passed")]),
        native,
        approved_skips={},
        approved_reruns={},
    )
    assert result["redacted_native_parameters"] == 2


def test_skip_reason_and_retry_counts_require_exact_reviewed_inventory():
    xml = junit([("test_a", "skipped")])
    native = reader.pytest_log_inventory(raw_log([event("test_a", "SKIPPED")], count=1), STEP)
    skip = reader.inspect_junit(xml)["cases"][0]["skip_reason_sha256"]
    with pytest.raises(ValueError, match="skip inventory"):
        reader.verify_test_results(xml, native, approved_skips={}, approved_reruns={})
    assert (
        reader.verify_test_results(
            xml, native, approved_skips={(CLASS, "test_a"): skip}, approved_reruns={}
        )["skipped"]
        == 1
    )
    retry_log = raw_log([event("test_a", "RERUN"), event("test_a")], count=1)
    retry_native = reader.pytest_log_inventory(retry_log, STEP)
    passed = junit([("test_a", "passed")])
    with pytest.raises(ValueError, match="retry inventory"):
        reader.verify_test_results(passed, retry_native, approved_skips={}, approved_reruns={})
    assert (
        reader.verify_test_results(
            passed,
            retry_native,
            approved_skips={},
            approved_reruns={(CLASS, "test_a"): 1},
        )["reruns"]
        == 1
    )


def test_serial_selected_counts_and_completed_step_window_are_bound():
    log = "\n".join(
        [
            "2026-10-24T13:59:59.999Z 4 workers [99 items]",
            "2026-10-24T14:00:01.000Z collected 3 items / 2 deselected / 1 selected",
            (
                "2026-10-24T14:00:02.000Z tests/unit/test_example.p"
                "y::TestClass::test_a[value::inner] PASSED [100%]"
            ),
        ]
    )
    native = reader.pytest_log_inventory(log, STEP)
    assert native["collected"] == 1
    assert native["cases"][0]["classname"] == CLASS + ".TestClass"
    assert native["cases"][0]["name"] == "test_a[value::inner]"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"<testsuites><failure/></testsuites>",
        (
            b'<testsuites><testsuite tests="1" failures="0" erro'
            b'rs="0" skipped="0"><other/></testsuite></testsuite'
            b"s>"
        ),
    ],
)
def test_missing_or_stray_XML_payload_never_qualifies(payload):
    with pytest.raises(ValueError):
        reader.inspect_junit(payload)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "failed_run",
        "foreign_repository",
        "old_attempt",
        "expired",
        "old_upload",
        "wrong_digest",
        "failed_step",
    ],
)
def test_native_artifact_gate_binds_success_source_upload_attempt_and_original_ZIP(
    tmp_path, fault
):
    revision = "a" * 40
    xml = junit([("test_a", "passed")])
    archive = tmp_path / "original.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("pytest.xml", xml)
        bundle.writestr("progress/log.txt", "retained diagnostic only")
    test_step = STEP | {"number": 9, "name": "Run pytest"}
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
        "repository": {"full_name": "Dream1216/omnigent"},
    }
    job = {
        "id": 88,
        "run_id": 41,
        "run_attempt": 1,
        "head_sha": revision,
        "status": "completed",
        "conclusion": "success",
        "steps": [test_step, upload],
    }
    metadata = {
        "id": 121,
        "name": "pytest-current-41",
        "expired": False,
        "workflow_run": {"id": 41, "head_sha": revision},
        "size_in_bytes": archive.stat().st_size,
        "digest": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
        "created_at": "2026-10-24T14:00:12Z",
    }
    if fault == "failed_run":
        run["conclusion"] = "failure"
    if fault == "foreign_repository":
        run["repository"]["full_name"] = "other/repository"
    if fault == "old_attempt":
        job["run_attempt"] = 2
    if fault == "expired":
        metadata["expired"] = True
    if fault == "old_upload":
        metadata["created_at"] = "2026-10-24T13:00:12Z"
    if fault == "wrong_digest":
        metadata["digest"] = "sha256:" + "0" * 64
    if fault == "failed_step":
        test_step["conclusion"] = "failure"
    arguments = {
        "metadata": metadata,
        "run": run,
        "job": job,
        "revision": revision,
        "artifact_name": "pytest-current-41",
        "upload_step": {"number": 11, "name": "Upload pytest artifacts"},
        "archive": archive,
        "xml_member": "pytest.xml",
        "native_log": raw_log([event("test_a")], count=1),
        "test_step": {"number": 9, "name": "Run pytest"},
        "approved_skips": {},
        "approved_reruns": {},
    }
    if fault:
        with pytest.raises(ValueError):
            reader.verify_pytest_evidence(**arguments)
    else:
        assert reader.verify_pytest_evidence(**arguments)["logical_cases"] == 1
        assert reader.read_junit_member(archive, "pytest.xml") == xml
        assert not (tmp_path / "progress").exists()


@pytest.mark.parametrize(
    "collection",
    [
        "1 worker [1 item]",
        "2 workers [1 item]",
        "collected 1 item",
        "collecting ... collected 1 item",
    ],
)
def test_native_singular_collection_formats_keep_complete_case_binding(collection):
    log = raw_log([event("test_a")], count=1).replace("4 workers [1 items]", collection)
    native = reader.pytest_log_inventory(log, STEP)
    assert (
        reader.verify_test_results(
            junit([("test_a", "passed")]),
            native,
            approved_skips={},
            approved_reruns={},
        )["logical_cases"]
        == 1
    )


# Bounded local parser fixtures; these never execute the skipped transport test.
UNIT_FIXTURE_XML = (ROOT / "tests/saas/resources/unit-collection-skip.xml").read_bytes()
UNIT_COLLECTION = next(
    row for row in ET.fromstring(UNIT_FIXTURE_XML).iter("testcase") if row.get("classname") == ""
)
COLLECTION_NAME = UNIT_COLLECTION.get("name")
COLLECTION_KEY = ("", COLLECTION_NAME)
COLLECTION_REASON = {
    "attributes": dict(UNIT_COLLECTION.find("skipped").attrib),
    "text": UNIT_COLLECTION.find("skipped").text or "",
}
COLLECTION_HASH = hashlib.sha256(
    json.dumps(COLLECTION_REASON, sort_keys=True).encode()
).hexdigest()
COLLECTION_APPROVAL = {COLLECTION_KEY: COLLECTION_HASH}
_plan_tree = ast.parse((ROOT / "saas/scripts/legacy_source_qualification.py").read_bytes())
_plan_function = next(
    n
    for n in _plan_tree.body
    if isinstance(n, ast.FunctionDef) and n.name == "_validate_pytest_plan"
)
_plan_env = {"require": reader.require, "re": re, "Any": Any}
exec(
    compile(
        ast.Module(body=[_plan_function], type_ignores=[]), "exact_proposal_plan_function", "exec"
    ),
    _plan_env,
)
validate_plan = _plan_env["_validate_pytest_plan"]


def collection_xml(*, ordinary="passed"):
    root = ET.fromstring(junit([("test_a", ordinary)]))
    suite = root.find("testsuite")
    suite.append(copy.deepcopy(UNIT_COLLECTION))
    suite.set("tests", "2")
    suite.set("skipped", str(1 + (ordinary == "skipped")))
    return root


def collection_plan():
    # Step coordinates here are local validator fixture inputs, never a profile.
    return {
        "artifact_id": 121,
        "artifact_name": "pytest-unit-fixture-41",
        "xml_member": "pytest-misc.xml",
        "test_step": {"number": 1, "name": "LOCAL_FIXTURE_ONLY"},
        "upload_step": {"number": 2, "name": "LOCAL_FIXTURE_ONLY"},
        "approved_skips": [
            {"classname": "", "name": COLLECTION_NAME, "reason_sha256": COLLECTION_HASH}
        ],
        "approved_reruns": [],
    }


def test_standard_collection_skip_unit_XML_requires_literal_review_and_preserves_it():
    with pytest.raises(ValueError, match="collection skip inventory"):
        reader.inspect_junit(UNIT_FIXTURE_XML)
    result = reader.inspect_junit(UNIT_FIXTURE_XML, approved_collection_skips=COLLECTION_APPROVAL)
    selected = [r for r in result["cases"] if r["classname"] == ""]
    assert selected == [
        {
            "classname": "",
            "name": COLLECTION_NAME,
            "outcome": "skipped",
            "skip_reason_sha256": COLLECTION_HASH,
        }
    ]
    assert result["logical_cases"] == 2 and result["skipped_cases"] == 1
    assert result["failed_cases"] == 0 and result["extra_reported_tests"] == 1
    assert result["complete_source_CI_admission"] is False


def test_standard_collection_skip_never_invents_a_native_runnable_testcase():
    native = reader.pytest_log_inventory(raw_log([event("test_a")], count=1), STEP)
    result = reader.verify_test_results(
        ET.tostring(collection_xml()),
        native,
        approved_skips=COLLECTION_APPROVAL,
        approved_reruns={},
    )
    assert result["logical_cases"] == 2 and result["native_collected_cases"] == 1
    assert result["collection_skips"] == 1 and result["skipped"] == 1
    assert all(case["classname"] for case in native["cases"])
    validate_plan(collection_plan())


@pytest.mark.parametrize(
    "fault",
    [
        "empty_class_pass",
        "empty_class_error",
        "missing_class",
        "mixed_error",
        "mixed_system_out",
        "nested_skip_payload",
        "unknown_name",
        "changed_message",
        "changed_reason",
        "unregistered",
        "wrong_review_hash",
        "duplicate_collection",
    ],
)
def test_standard_collection_skip_rejects_malformed_or_unreviewed_payload(fault):
    root = collection_xml()
    suite = root.find("testsuite")
    case = suite[-1]
    approved = COLLECTION_APPROVAL
    if fault in {"empty_class_pass", "empty_class_error"}:
        case.remove(case[0])
        if fault == "empty_class_error":
            ET.SubElement(case, "error").text = "collection failed"
        suite.set("skipped", "0")
        suite.set("errors", "1" if fault.endswith("error") else "0")
    elif fault == "missing_class":
        del case.attrib["classname"]
    elif fault == "mixed_error":
        ET.SubElement(case, "error").text = "must not be hidden"
        suite.set("errors", "1")
    elif fault == "mixed_system_out":
        ET.SubElement(case, "system-out").text = "unexpected collection child"
    elif fault == "nested_skip_payload":
        ET.SubElement(case[0], "error").text = "unexpected nested child"
    elif fault == "unknown_name":
        case.set("name", "tests.saas.test_unreviewed_collection")
    elif fault == "changed_message":
        case[0].set("message", "runtime skipped")
    elif fault == "changed_reason":
        case[0].text += " changed"
    elif fault == "unregistered":
        approved = {}
    elif fault == "wrong_review_hash":
        approved = {COLLECTION_KEY: "0" * 64}
    elif fault == "duplicate_collection":
        suite.append(copy.deepcopy(case))
        suite.set("tests", "3")
        suite.set("skipped", "2")
    with pytest.raises(ValueError):
        reader.inspect_junit(ET.tostring(root), approved_collection_skips=approved)


@pytest.mark.parametrize(
    "fault",
    ["invented_native_collection", "missing_native_runnable", "missing_reviewed_XML_collection"],
)
def test_standard_collection_skip_keeps_complete_native_and_reviewed_inventories(fault):
    native = reader.pytest_log_inventory(raw_log([event("test_a")], count=1), STEP)
    root = collection_xml()
    if fault == "invented_native_collection":
        native["cases"].append(
            {
                "classname": "",
                "name": COLLECTION_NAME,
                "outcome": "skipped",
                "native_outcome": "SKIPPED",
                "reruns": 0,
            }
        )
        native["collected"] += 1
    elif fault == "missing_native_runnable":
        native["cases"] = []
        native["collected"] = 0
    else:
        suite = root.find("testsuite")
        suite.remove(suite[-1])
        suite.set("tests", "1")
        suite.set("skipped", "0")
    with pytest.raises(ValueError):
        reader.verify_test_results(
            ET.tostring(root), native, approved_skips=COLLECTION_APPROVAL, approved_reruns={}
        )


@pytest.mark.parametrize(
    "fault",
    ["empty_class_retry", "invalid_module", "extra_key", "bad_reason_hash", "duplicate_approval"],
)
def test_standard_collection_skip_plan_rejects_nonexplicit_or_retry_exceptions(fault):
    plan = collection_plan()
    if fault == "empty_class_retry":
        plan["approved_skips"] = []
        plan["approved_reruns"] = [{"classname": "", "name": COLLECTION_NAME, "count": 1}]
    elif fault == "invalid_module":
        plan["approved_skips"][0]["name"] = "tests/saas/test_delivery_authorization_transport.py"
    elif fault == "extra_key":
        plan["approved_skips"][0]["kind"] = "wildcard"
    elif fault == "bad_reason_hash":
        plan["approved_skips"][0]["reason_sha256"] = "unknown"
    else:
        plan["approved_skips"] *= 2
    with pytest.raises(ValueError):
        validate_plan(plan)


@pytest.mark.parametrize("ordinary", ["skipped", "error"])
def test_standard_collection_skip_cannot_hide_ordinary_unreviewed_skip_or_error(ordinary):
    outcome = "SKIPPED" if ordinary == "skipped" else "ERROR"
    native = reader.pytest_log_inventory(raw_log([event("test_a", outcome)], count=1), STEP)
    root = collection_xml(ordinary=ordinary)
    if ordinary == "error":
        root.find("testsuite").set("errors", "1")
    with pytest.raises(ValueError):
        reader.verify_test_results(
            ET.tostring(root), native, approved_skips=COLLECTION_APPROVAL, approved_reruns={}
        )


def test_standard_collection_skip_only_XML_cannot_qualify_empty_native_inventory():
    root = collection_xml()
    suite = root.find("testsuite")
    suite.remove(suite[0])
    suite.set("tests", "1")
    native = {"collected": 0, "cases": [], "subtests": []}
    with pytest.raises(ValueError, match="native runnable pytest inventory is empty"):
        reader.verify_test_results(
            ET.tostring(root), native, approved_skips=COLLECTION_APPROVAL, approved_reruns={}
        )
