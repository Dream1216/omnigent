"""Shared strict native facts for legacy domain discovery and refusal checks."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_source_ci import _instant
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY

MAIN_WORKFLOW = ".github/workflows/saas-n1-merge-gate.yml"
MAIN_WORKFLOW_SHA256 = "36db03f8a9a0242a2e2020e39806d2008c960ca52ef2c2dd950df6b96c0beca3"
_GATE = ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
_ERROR = "##[error]resolved PR is not an open main-targeting PR"


_SHA = re.compile(r"[0-9a-f]{40}")
_STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\S+) (.*)$")
_ENV = re.compile(r"  ([A-Z][A-Z0-9_]*): (.*)")
_EVENTS = ("pull_request_target", "workflow_run")
_ROOT = f"repos/{REPOSITORY}"
_REPO_URL = f"https://api.github.com/repos/{REPOSITORY}"
_ENV_KEYS = {
    "REPO",
    "EVENT_NAME",
    "EVENT_PR",
    "EVENT_HEAD_SHA",
    "WORKFLOW_HEAD_SHA",
    "WORKFLOW_PRS",
}


def native_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def trigger_environment(log: str, step: dict[str, Any]) -> dict[str, Any]:
    """Read one bounded runner environment group, preserving raw JSON lines.

    Untimestamped lines belong only to an already-open WORKFLOW_PRS JSON value.
    Its following timestamp and the runner endgroup must remain inside the native
    step window. Generic checkout/source-CI log parsing stays unchanged.
    """
    require(
        step.get("name") == "Resolve current PR head"
        and step.get("status") == "completed"
        and step.get("conclusion") in {"success", "failure"},
        "domain trigger step did not execute to completion",
    )
    require(len(log.encode()) <= 12 * 1024 * 1024, "domain native log exceeds bound")
    started, completed = _instant(step.get("started_at")), _instant(step.get("completed_at"))
    require(started <= completed, "domain trigger step time is reversed")
    end = completed + timedelta(seconds=1)
    groups, active, environment = 0, False, False
    values: dict[str, Any] = {}
    pending: list[str] | None = None
    pending_bytes = 0

    def finish_json() -> None:
        nonlocal pending, pending_bytes
        if pending is not None:
            text = "\n".join(pending)
            require(len(text.encode()) <= 65536, "domain trigger JSON exceeds bound")

            def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, item in pairs:
                    require(key not in result, "domain trigger JSON repeats an object key")
                    result[key] = item
                return result

            value = json.loads(text, object_pairs_hook=unique_pairs)
            require(
                value is None or isinstance(value, list), "domain trigger PR JSON is not a list"
            )
            values["WORKFLOW_PRS"] = value
            pending = None
            pending_bytes = 0

    lines = log.splitlines()
    require(len(lines) <= 200000, "domain native log has too many lines")
    for line in lines:
        match = _STAMP.fullmatch(line)
        if match is None:
            if active:
                require(
                    environment and pending is not None, "unframed native environment continuation"
                )
                pending.append(line)
                pending_bytes += len(line.encode()) + 1
                require(
                    pending_bytes <= 65536,
                    "domain trigger JSON exceeds bound",
                )
            continue
        observed, body = _instant(match[1]), match[2]
        if active:
            require(
                started <= observed < end, "domain environment crosses its native step boundary"
            )
            finish_json()
        if body == "##[group]Run set -euo pipefail" and started <= observed < end:
            require(not active, "nested domain runner group")
            groups += 1
            active = True
            environment = False
            continue
        if not active:
            continue
        require(not body.startswith("##[group]"), "nested domain runner group")
        if body == "##[endgroup]":
            require(environment, "domain runner group has no environment")
            active = False
            continue
        if body == "env:":
            require(not environment, "domain runner environment is duplicated")
            environment = True
            continue
        if not environment:
            continue
        entry = _ENV.fullmatch(body)
        require(entry is not None, "domain runner environment framing differs")
        name, value = entry[1], entry[2]
        if name not in _ENV_KEYS:
            continue
        require(name not in values, "domain trigger environment is duplicated")
        if name == "WORKFLOW_PRS":
            pending = [value]
            pending_bytes = len(value.encode())
            require(pending_bytes <= 65536, "domain trigger JSON exceeds bound")
        else:
            values[name] = value
    require(
        not active and pending is None and groups == 1,
        "domain runner group is missing or unterminated",
    )
    require(set(values) == _ENV_KEYS, "domain trigger environment is incomplete")
    require(values["REPO"] == REPOSITORY, "domain trigger repository differs")
    return values


def _pr_numbers(rows: Any) -> list[int]:
    require(isinstance(rows, list) and len(rows) <= 100, "domain PR association is malformed")
    numbers = []
    for row in rows:
        require(
            isinstance(row, dict)
            and type(row.get("number")) is int
            and row["number"] > 0
            and row.get("url") == f"{_REPO_URL}/pulls/{row['number']}",
            "domain PR association belongs to another repository",
        )
        numbers.append(row["number"])
    require(len(numbers) == len(set(numbers)), "domain PR association is duplicated")
    return numbers


def trigger_identity(environment: dict[str, Any], event: str) -> tuple[int, str]:
    """Keep the original event source separate from mutable API PR head fields."""
    require(
        event in _EVENTS and environment["EVENT_NAME"] == event, "domain trigger event differs"
    )
    if event == "pull_request_target":
        number = environment["EVENT_PR"]
        require(
            isinstance(number, str) and re.fullmatch(r"[1-9][0-9]*", number) is not None,
            "domain target event PR is missing",
        )
        source = environment["EVENT_HEAD_SHA"]
        require(
            environment["WORKFLOW_HEAD_SHA"] == "" and environment["WORKFLOW_PRS"] is None,
            "domain target event has conflicting workflow coordinates",
        )
        number = int(number)
    else:
        require(
            environment["EVENT_PR"] == environment["EVENT_HEAD_SHA"] == "",
            "domain workflow event has conflicting target coordinates",
        )
        source = environment["WORKFLOW_HEAD_SHA"]
        pulls = environment["WORKFLOW_PRS"]
        numbers = _pr_numbers(pulls)
        require(len(numbers) == 1, "domain workflow trigger PR cannot be uniquely authenticated")
        number = numbers[0]
        require(
            pulls[0].get("head", {}).get("sha") == source
            and pulls[0].get("head", {}).get("repo", {}).get("url") == _REPO_URL
            and pulls[0].get("base", {}).get("repo", {}).get("url") == _REPO_URL,
            "domain workflow trigger snapshot source or repository differs",
        )
    require(
        isinstance(source, str) and _SHA.fullmatch(source) is not None,
        "domain original event source SHA is missing",
    )
    return number, source


def _native_file(
    path: str, revision: str, *, read: Callable[[str], dict[str, Any]] | None = None
) -> bytes:
    value = (read or api)(f"repos/{REPOSITORY}/contents/{path}?ref={revision}")
    require(
        value.get("type") == "file"
        and value.get("path") == path
        and value.get("encoding") == "base64"
        and isinstance(value.get("content"), str)
        and len(value["content"]) <= 360000
        and type(value.get("size")) is int
        and 0 < value["size"] <= 262144,
        "native domain workflow or gate is not a bounded regular file",
    )
    body = base64.b64decode(value["content"].replace("\n", ""), validate=True)
    require(len(body) == value["size"], "native domain source size differs")
    return body


def _latest_matches_attempt(latest: dict[str, Any], attempt: dict[str, Any]) -> bool:
    prefix = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{attempt['id']}"
    for field, suffix in (("jobs_url", "jobs"), ("logs_url", "logs")):
        require(
            latest.get(field) == f"{prefix}/{suffix}"
            and attempt.get(field) == f"{prefix}/attempts/{attempt['run_attempt']}/{suffix}",
            "native domain run endpoint URLs differ",
        )
    excluded = {"jobs_url", "logs_url"}
    return {key: value for key, value in latest.items() if key not in excluded} == {
        key: value for key, value in attempt.items() if key not in excluded
    }
