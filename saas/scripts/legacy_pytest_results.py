"""Cross-check native pytest output, XML cases and reviewed skip/retry policy."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from saas.scripts.legacy_source_ci import _instant, completed_step_lines
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY
from saas.scripts.scan_oci_candidates import file_sha256

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_XDIST = re.compile(
    r"^\[gw[0-9]+\]\s+\[\s*[0-9]+%\]\s+(?P<outcome>[A-Z]+)"
    r"(?P<parameters>\(.*\))?\s+(?P<node>(?:tests/|integrations/slack/tests/).*\.py::.+?)\s*$"
)
_SERIAL = re.compile(
    r"^(?P<node>(?:tests/|integrations/slack/tests/).*\.py::.+?)\s+"
    r"(?P<outcome>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS|RERUN)\s+\[\s*[0-9]+%\]\s*$"
)
_OUTCOMES = {
    "PASSED": "passed",
    "XPASS": "passed",
    "SKIPPED": "skipped",
    "XFAIL": "skipped",
    "FAILED": "failure",
    "ERROR": "error",
}


def verify_pytest_artifact_identity(
    metadata: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    revision: str,
    artifact_name: str,
    upload_step: dict[str, Any],
    archive: Path,
) -> None:
    """Retain the completed-run requirement for original source-CI artifacts."""
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "test artifact has no successful exact-source native job",
    )
    verify_job_artifact_identity(
        metadata,
        run,
        job,
        revision=revision,
        artifact_name=artifact_name,
        upload_step=upload_step,
        archive=archive,
    )


def verify_job_artifact_identity(
    metadata: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    revision: str,
    artifact_name: str,
    upload_step: dict[str, Any],
    archive: Path,
) -> None:
    """Bind one successful native job artifact; the caller enforces run lifecycle."""
    require(
        re.fullmatch(r"[0-9a-f]{40}", revision) is not None
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and type(run.get("id")) is int
        and run["id"] > 0
        and type(job.get("id")) is int
        and job["id"] > 0
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] > 0
        and run.get("head_sha") == job.get("head_sha") == revision
        and job.get("run_id") == run.get("id")
        and job.get("run_attempt") == run.get("run_attempt")
        and job.get("status") == "completed"
        and job.get("conclusion") == "success",
        "test artifact has no successful exact-source native job",
    )
    require(
        type(metadata.get("id")) is int
        and metadata["id"] > 0
        and metadata.get("name") == artifact_name
        and isinstance(artifact_name, str)
        and bool(artifact_name)
        and metadata.get("expired") is False
        and metadata.get("workflow_run", {}).get("id") == run["id"]
        and metadata.get("workflow_run", {}).get("head_sha") == revision
        and type(metadata.get("size_in_bytes")) is int
        and metadata["size_in_bytes"] > 0
        and isinstance(metadata.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["digest"]) is not None,
        "native test artifact identity differs",
    )
    matching = [
        row
        for row in job.get("steps", [])
        if row.get("number") == upload_step["number"] and row.get("name") == upload_step["name"]
    ]
    require(
        len(matching) == 1
        and matching[0].get("status") == "completed"
        and matching[0].get("conclusion") == "success",
        "native test upload step differs",
    )
    started, completed = (
        _instant(matching[0].get("started_at")),
        _instant(matching[0].get("completed_at")),
    )
    created = _instant(metadata.get("created_at"))
    require(
        started <= completed and started <= created < completed + timedelta(seconds=1),
        "test artifact came from another native upload attempt",
    )
    require(
        archive.is_file()
        and not archive.is_symlink()
        and archive.stat().st_size == metadata["size_in_bytes"]
        and file_sha256(archive) == metadata["digest"].removeprefix("sha256:"),
        "test artifact original ZIP bytes differ",
    )


def read_junit_member(archive: Path, member: str) -> bytes:
    """Read only the exact reviewed XML member, without extracting other payloads."""
    path = PurePosixPath(member)
    require(
        not path.is_absolute() and ".." not in path.parts and "\\" not in member,
        "unsafe reviewed JUnit member",
    )
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        require(
            len(names) == len(set(names)) and member in names,
            "JUnit artifact members are missing or duplicated",
        )
        item = bundle.getinfo(member)
        require(
            not item.is_dir()
            and (item.external_attr >> 16) & 0o170000 in {0, 0o100000}
            and 0 < item.file_size <= 32 * 1024 * 1024,
            "JUnit artifact member is not a bounded regular file",
        )
        return bundle.read(item)


def _identity(node: str) -> tuple[str, str]:
    path, separator, tail = node.partition(".py::")
    require(
        bool(separator)
        and path.startswith(("tests/", "integrations/slack/tests/"))
        and (
            not path.startswith("integrations/")
            or (all(part not in {"", ".", ".."} for part in path.split("/")) and "\\" not in path)
        ),
        "unsupported native pytest node identity",
    )
    qualified, bracket, parameters = tail.partition("[")
    parts = qualified.split("::")
    require(all(parts), "native pytest node identity is incomplete")
    classname = path.replace("/", ".") + ("." + ".".join(parts[:-1]) if len(parts) > 1 else "")
    return classname, parts[-1] + bracket + parameters


def pytest_log_inventory(log: str, step: dict[str, Any]) -> dict[str, Any]:
    selected = [_ANSI.sub("", line) for line in completed_step_lines(log, step)]
    collected = []
    events: dict[tuple[str, str], list[str]] = {}
    subtests = []
    for line in selected:
        match = re.fullmatch(r"[0-9]+ workers? \[([0-9]+) items?\]", line)
        if match:
            collected.append(int(match.group(1)))
        serial = re.fullmatch(
            (
                "(?:collecting \\.\\.\\. )?collected ([0-9]+) items?(?"
                ": / ([0-9]+) deselected / ([0-9]+) selected)?"
            ),
            line,
        )
        if serial:
            total, deselected, count = serial.groups()
            require(
                count is None or int(total) == int(deselected) + int(count),
                "native pytest selected count differs",
            )
            collected.append(int(count or total))
        result = _XDIST.fullmatch(line) or _SERIAL.fullmatch(line)
        if not result:
            continue
        outcome, node = result.group("outcome"), result.group("node")
        identity = _identity(node)
        if outcome.startswith("SUB"):
            require(
                outcome in {"SUBPASSED", "SUBFAILED", "SUBSKIPPED"},
                "unknown native subtest result",
            )
            subtests.append(
                {
                    "classname": identity[0],
                    "name": identity[1],
                    "outcome": outcome,
                    "parameters": result.groupdict().get("parameters") or "",
                }
            )
        else:
            require(
                outcome in _OUTCOMES or outcome == "RERUN",
                "unknown native pytest outcome",
            )
            events.setdefault(identity, []).append(outcome)
    require(
        len(collected) == 1 and collected[0] > 0,
        "native pytest collection is empty or ambiguous",
    )
    cases = []
    for identity, outcomes in events.items():
        if "***" in identity[1]:
            require(
                "***" not in identity[0]
                and "[" in identity[1]
                and "***" not in identity[1].partition("[")[0]
                and all(value in _OUTCOMES for value in outcomes),
                "masked native retry or non-parameter identity is ambiguous",
            )
            cases.extend(
                {
                    "classname": identity[0],
                    "name": identity[1],
                    "outcome": _OUTCOMES[value],
                    "native_outcome": value,
                    "reruns": 0,
                }
                for value in outcomes
            )
            continue
        require(
            bool(outcomes)
            and outcomes[-1] in _OUTCOMES
            and all(value == "RERUN" for value in outcomes[:-1]),
            "native pytest has duplicate terminals or an unfinished retry",
        )
        cases.append(
            {
                "classname": identity[0],
                "name": identity[1],
                "outcome": _OUTCOMES[outcomes[-1]],
                "native_outcome": outcomes[-1],
                "reruns": len(outcomes) - 1,
            }
        )
    require(len(cases) == collected[0], "native pytest case output omits collected tests")
    keys = {(row["classname"], row["name"]) for row in cases}
    require(
        all((row["classname"], row["name"]) in keys for row in subtests),
        "native subtest has no collected parent",
    )
    return {
        "collected": collected[0],
        "cases": sorted(cases, key=lambda row: (row["classname"], row["name"])),
        "subtests": subtests,
        "subtest_counts": dict(Counter(row["outcome"] for row in subtests)),
        "complete_source_CI_admission": False,
    }


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def inspect_junit(
    body: bytes, *, approved_collection_skips: dict[tuple[str, str], str] | None = None
) -> dict[str, Any]:
    collection_approvals = {} if approved_collection_skips is None else approved_collection_skips
    require(
        isinstance(collection_approvals, dict)
        and all(
            isinstance(key, tuple)
            and len(key) == 2
            and key[0] == ""
            and isinstance(key[1], str)
            and re.fullmatch(r"tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+", key[1]) is not None
            and isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for key, value in collection_approvals.items()
        ),
        "reviewed collection skip inventory differs",
    )
    observed_collection_skips = {}
    require(
        isinstance(body, bytes) and 0 < len(body) <= 32 * 1024 * 1024,
        "JUnit XML exceeds its bounded input",
    )
    text = body.decode("utf-8")
    require(
        "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(),
        "JUnit entities or DTD are forbidden",
    )
    root = ET.fromstring(text)
    require(_local(root.tag) in {"testsuites", "testsuite"}, "unsupported JUnit root")
    if _local(root.tag) == "testsuites":
        require(
            all(_local(row.tag) == "testsuite" for row in root),
            "unexpected JUnit root payload",
        )
    require(
        not any(
            "rerun" in _local(row.tag).lower() or "flaky" in _local(row.tag).lower()
            for row in root.iter()
        ),
        "JUnit retry records require native reconciliation",
    )
    cases = []
    suites = []
    for suite in root.iter():
        if _local(suite.tag) != "testsuite":
            continue
        counts = {}
        for key in ("tests", "failures", "errors", "skipped"):
            value = suite.get(key)
            require(
                isinstance(value, str) and re.fullmatch(r"[0-9]+", value) is not None,
                "JUnit suite counter is missing or malformed",
            )
            counts[key] = int(value)
        direct = [row for row in suite if _local(row.tag) == "testcase"]
        require(
            all(
                _local(row.tag) in {"testcase", "properties", "system-out", "system-err"}
                for row in suite
            ),
            "unexpected JUnit suite payload",
        )
        require(
            not any(_local(row.tag) == "testsuite" for row in suite),
            "nested JUnit suites require explicit inventory",
        )
        for case in direct:
            name, classname = case.get("name"), case.get("classname")
            require(
                isinstance(name, str) and bool(name) and isinstance(classname, str),
                "JUnit case identity is missing",
            )
            results = [row for row in case if _local(row.tag) in {"failure", "error", "skipped"}]
            require(len(results) <= 1, "JUnit case has ambiguous outcomes")
            outcome = _local(results[0].tag) if results else "passed"
            skip_hash = ""
            if outcome == "skipped":
                reason = {
                    "attributes": dict(results[0].attrib),
                    "text": results[0].text or "",
                }
                skip_hash = hashlib.sha256(json.dumps(reason, sort_keys=True).encode()).hexdigest()
            if not classname:
                require(
                    len(case) == 1
                    and len(results) == 1
                    and outcome == "skipped"
                    and dict(results[0].attrib) == {"message": "collection skipped"}
                    and not list(results[0])
                    and bool((results[0].text or "").strip())
                    and not (case.text or "").strip()
                    and not (results[0].tail or "").strip()
                    and re.fullmatch(r"tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+", name) is not None,
                    "empty-class JUnit case is not a standard collection skip",
                )
                key = classname, name
                require(
                    collection_approvals.get(key) == skip_hash,
                    "unreviewed or changed collection skip inventory",
                )
                observed_collection_skips[key] = skip_hash
            cases.append(
                {
                    "classname": classname,
                    "name": name,
                    "outcome": outcome,
                    "skip_reason_sha256": skip_hash,
                }
            )
        actual = Counter(
            _local(row.tag)
            for case in direct
            for row in case
            if _local(row.tag) in {"failure", "error", "skipped"}
        )
        require(
            all(
                actual[tag] == counts[field]
                for tag, field in (
                    ("failure", "failures"),
                    ("error", "errors"),
                    ("skipped", "skipped"),
                )
            ),
            "JUnit suite outcome counters differ from cases",
        )
        require(counts["tests"] >= len(direct), "JUnit suite counter omits actual cases")
        suites.append(counts)
    require(
        observed_collection_skips == collection_approvals,
        "reviewed collection skip inventory is missing",
    )
    keys = [(case["classname"], case["name"]) for case in cases]
    require(
        bool(cases) and len(keys) == len(set(keys)),
        "JUnit case inventory is empty or duplicated",
    )
    return {
        "cases": sorted(cases, key=lambda row: (row["classname"], row["name"])),
        "logical_cases": len(cases),
        "reported_tests": sum(row["tests"] for row in suites),
        "extra_reported_tests": sum(row["tests"] for row in suites) - len(cases),
        "failed_cases": sum(case["outcome"] in {"failure", "error"} for case in cases),
        "skipped_cases": sum(case["outcome"] == "skipped" for case in cases),
        "complete_source_CI_admission": False,
    }


def reconcile_case_inventory(
    native: list[dict[str, Any]], xml: list[dict[str, Any]]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Bind redacted parameters by exact cardinality, outcome and full matching."""
    require(len(native) == len(xml), "native and XML case counts differ")
    remaining = {(row["classname"], row["name"]): row for row in xml}
    require(len(remaining) == len(xml), "XML case inventory is duplicated")
    result = {}
    masked = []
    for row in native:
        key = row["classname"], row["name"]
        if "***" in row["name"]:
            masked.append(row)
            continue
        require(
            key in remaining and remaining[key]["outcome"] == row["outcome"],
            "native/XML identity or outcome differs",
        )
        remaining.pop(key)
        result[key] = row
    choices = []
    for row in masked:
        require(
            "***" not in row["classname"]
            and "[" in row["name"]
            and "***" not in row["name"].partition("[")[0]
            and row["reruns"] == 0,
            "masked native identity cannot be safely reconciled",
        )
        pattern = re.escape(row["name"]).replace(re.escape("***"), ".*")
        choices.append(
            [
                key
                for key, expected in remaining.items()
                if key[0] == row["classname"]
                and re.fullmatch(pattern, key[1])
                and row["outcome"] == expected["outcome"]
            ]
        )
    assigned: dict[tuple[str, str], int] = {}

    def assign(index: int, seen: set[tuple[str, str]]) -> bool:
        for key in choices[index]:
            if key not in seen and key not in assigned:
                seen.add(key)
                assigned[key] = index
                return True
        for key in choices[index]:
            if key in seen:
                continue
            seen.add(key)
            if key not in assigned or assign(assigned[key], seen):
                assigned[key] = index
                return True
        return False

    require(
        all(assign(index, set()) for index in range(len(masked)))
        and len(assigned) == len(remaining),
        "redacted native parameters do not cover the exact XML inventory",
    )
    result.update({key: masked[index] for key, index in assigned.items()})
    return result


def verify_test_results(
    xml: bytes,
    native: dict[str, Any],
    *,
    approved_skips: dict[tuple[str, str], str],
    approved_reruns: dict[tuple[str, str], int],
) -> dict[str, Any]:
    """The native step inventory and reviewed exceptions must both match XML."""
    result = inspect_junit(
        xml,
        approved_collection_skips={
            key: value for key, value in approved_skips.items() if key[0] == ""
        },
    )
    xml_cases = {(row["classname"], row["name"]): row for row in result["cases"]}
    # Collection skips have no runnable native testcase; never invent one.
    runnable = [row for row in result["cases"] if row["classname"]]
    require(bool(runnable), "native runnable pytest inventory is empty")
    native_cases = reconcile_case_inventory(native["cases"], runnable)
    require(
        {(row["classname"], row["name"]) for row in runnable} == set(native_cases)
        and len(runnable) == native["collected"],
        "JUnit does not cover the complete actual native selection",
    )
    require(
        all(row["outcome"] == "SUBPASSED" for row in native["subtests"]),
        "native subtest failed or skipped",
    )
    require(
        result["extra_reported_tests"] == len(native["subtests"]),
        "JUnit extra counters do not match actual native passed subtests",
    )
    require(
        result["failed_cases"] == 0,
        "actual required native test failure blocks admission",
    )
    actual_skips = {}
    actual_reruns = {}
    for key, case in xml_cases.items():
        if not key[0]:
            actual_skips[key] = case["skip_reason_sha256"]
            continue
        observed = native_cases[key]
        require(case["outcome"] == observed["outcome"], "JUnit/native test outcome differs")
        if case["outcome"] == "skipped":
            actual_skips[key] = case["skip_reason_sha256"]
        if observed["reruns"]:
            actual_reruns[key] = observed["reruns"]
    require(actual_skips == approved_skips, "unreviewed or changed original skip inventory")
    require(actual_reruns == approved_reruns, "unreviewed or changed native retry inventory")
    return {
        "logical_cases": result["logical_cases"],
        "native_collected_cases": native["collected"],
        "collection_skips": len(result["cases"]) - len(runnable),
        "native_passed_subtests": len(native["subtests"]),
        "redacted_native_parameters": sum("***" in row["name"] for row in native["cases"]),
        "skipped": len(actual_skips),
        "reruns": sum(actual_reruns.values()),
        "XML_sha256": hashlib.sha256(xml).hexdigest(),
        "native_case_inventory_sha256": hashlib.sha256(
            json.dumps(native["cases"], sort_keys=True).encode()
        ).hexdigest(),
        "scope": (
            "One exact native step/XML inventory only; not all-"
            "workflow source CI, PG, images or production admis"
            "sion."
        ),
    }


def validate_compact_log_contract(contract: dict[str, Any], expected: dict[str, Any]) -> None:
    """Only a trusted reviewed policy may select this exact compact transcript."""
    require(
        isinstance(contract, dict)
        and set(contract)
        == {
            "kind",
            "source_revision",
            "workflow_path",
            "run_id",
            "attempt",
            "job_id",
            "job_name",
            "test_step",
            "upload_step",
            "artifact_id",
            "artifact_sha256",
            "xml_member",
            "native_log_text_sha256",
        }
        and contract["kind"] == "legacy_native_pytest_compact_summary/v1"
        and contract["workflow_path"] == ".github/workflows/ci.yml"
        and contract["job_name"]
        in {
            "Pytest (stores-mysql)",
            "Pytest (stores-postgres)",
            "Pytest (stores-crdb-23.2.28)",
        }
        and all(
            type(contract[key]) is int and contract[key] > 0
            for key in ("run_id", "attempt", "job_id", "artifact_id")
        )
        and isinstance(contract["source_revision"], str)
        and re.fullmatch(r"[0-9a-f]{40}", contract["source_revision"]) is not None
        and all(
            isinstance(contract[key], dict)
            and set(contract[key]) == {"number", "name"}
            and type(contract[key]["number"]) is int
            and contract[key]["number"] > 0
            and isinstance(contract[key]["name"], str)
            and bool(contract[key]["name"])
            for key in ("test_step", "upload_step")
        )
        and all(contract.get(key) == value for key, value in expected.items())
        and all(
            isinstance(contract[key], str)
            and re.fullmatch(r"[0-9a-f]{64}", contract[key]) is not None
            for key in ("artifact_sha256", "native_log_text_sha256")
        ),
        "unregistered or mismatched reviewed compact pytest contract",
    )


def _verify_compact_results(
    xml: bytes,
    log: str,
    step: dict[str, Any],
    *,
    contract: dict[str, Any],
    approved_skips: dict[tuple[str, str], str],
    approved_reruns: dict[tuple[str, str], int],
) -> dict[str, Any]:
    """Join aggregate native counts to authenticated XML; never invent test lines."""
    require(
        hashlib.sha256(log.encode()).hexdigest() == contract["native_log_text_sha256"],
        "compact native transcript changed from its exact reviewed text",
    )
    require(not approved_reruns, "compact output cannot prove per-case retries")
    result = inspect_junit(xml)
    require(
        result["failed_cases"] == 0 and result["extra_reported_tests"] == 0,
        "compact XML contains failed tests or unproved subtests",
    )
    selected = [_ANSI.sub("", line) for line in completed_step_lines(log, step)]
    collections = [
        (index, re.fullmatch(r"[0-9]+ workers? \[([0-9]+) items?\]", line))
        for index, line in enumerate(selected)
        if re.fullmatch(r"[0-9]+ workers? \[([0-9]+) items?\]", line)
    ]
    require(
        len(collections) == 1
        and not any(re.match(r"(?:collecting \.\.\. )?collected ", line) for line in selected),
        "compact pytest requires one exact xdist selection",
    )
    start, collection = collections[0]
    collected = int(collection.group(1))
    summary_pattern = re.compile(
        r"=+ ([0-9]+) passed(?:, ([0-9]+) skipped)? in "
        r"[0-9]+\.[0-9]+s(?: \([0-9]+:[0-5][0-9](?::[0-5][0-9])?\))? =+"
    )
    summaries = [
        (index, summary_pattern.fullmatch(line))
        for index, line in enumerate(selected)
        if summary_pattern.fullmatch(line)
    ]
    require(
        len(summaries) == 1 and summaries[0][0] > start,
        "compact pytest final summary is missing or ambiguous",
    )
    finish, summary = summaries[0]
    progress_pattern = re.compile(r"([.s]+) +\[ *([0-9]+)%\]")
    progress = [
        (index, progress_pattern.fullmatch(line))
        for index, line in enumerate(selected)
        if progress_pattern.fullmatch(line)
    ]
    require(bool(progress), "compact pytest progress is missing")
    first, last = progress[0][0], progress[-1][0]
    require(
        start < first <= last < finish
        and all(not line for line in selected[start + 1 : first])
        and len(progress) == last - first + 1,
        "unknown or interleaved compact pytest output",
    )
    marks = ""
    for _, match in progress:
        marks += match.group(1)
        require(
            collected > 0
            and len(marks) <= collected
            and int(match.group(2)) == 100 * len(marks) // collected,
            "compact pytest progress/selection counts differ",
        )
    passed, skipped = int(summary.group(1)), int(summary.group(2) or 0)
    require(
        len(marks) == collected == result["logical_cases"] == passed + skipped
        and marks.count(".") == passed
        and marks.count("s") == skipped == result["skipped_cases"],
        "compact progress, summary and complete XML inventory differ",
    )
    actual_skips = {
        (case["classname"], case["name"]): case["skip_reason_sha256"]
        for case in result["cases"]
        if case["outcome"] == "skipped"
    }
    require(actual_skips == approved_skips, "unreviewed or changed compact skip inventory")
    return {
        "native_output_contract": contract["kind"],
        "logical_cases": result["logical_cases"],
        "native_collected_cases": collected,
        "skipped": skipped,
        "reruns": 0,
        "native_per_case_outcome_evidence": False,
        "XML_sha256": hashlib.sha256(xml).hexdigest(),
        "scope": (
            "Exact native compact counts and authenticated XML; "
            "not per-node native outcomes or source/production admission."
        ),
    }


def verify_pytest_evidence(
    metadata: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    revision: str,
    artifact_name: str,
    upload_step: dict[str, Any],
    archive: Path,
    xml_member: str,
    native_log: str,
    test_step: dict[str, Any],
    approved_skips: dict[tuple[str, str], str],
    approved_reruns: dict[tuple[str, str], int],
    native_log_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One native job's evidence; checkout/latest/full matrix remain outer checks."""
    verify_pytest_artifact_identity(
        metadata,
        run,
        job,
        revision=revision,
        artifact_name=artifact_name,
        upload_step=upload_step,
        archive=archive,
    )
    matching = [
        row
        for row in job.get("steps", [])
        if row.get("number") == test_step["number"] and row.get("name") == test_step["name"]
    ]
    require(
        len(matching) == 1
        and matching[0].get("status") == "completed"
        and matching[0].get("conclusion") == "success",
        "required native pytest step did not succeed",
    )
    if native_log_contract is not None:
        validate_compact_log_contract(
            native_log_contract,
            {
                "source_revision": revision,
                "workflow_path": run.get("path"),
                "run_id": run["id"],
                "attempt": run["run_attempt"],
                "job_id": job["id"],
                "job_name": job["name"],
                "test_step": test_step,
                "upload_step": upload_step,
                "artifact_id": metadata["id"],
                "artifact_sha256": metadata["digest"][7:],
                "xml_member": xml_member,
            },
        )
        return _verify_compact_results(
            read_junit_member(archive, xml_member),
            native_log,
            matching[0],
            contract=native_log_contract,
            approved_skips=approved_skips,
            approved_reruns=approved_reruns,
        )
    native = pytest_log_inventory(native_log, matching[0])
    return verify_test_results(
        read_junit_member(archive, xml_member),
        native,
        approved_skips=approved_skips,
        approved_reruns=approved_reruns,
    )
