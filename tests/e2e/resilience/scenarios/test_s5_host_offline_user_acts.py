"""S5: the host is offline while the user, elsewhere, keeps using the session.

The host's links are down (refused, as when the laptop has no network) and the
server and browser are fine. The user sends a message, answers a pending
approval, or stops a running turn. Contract: each action is either applied
exactly once when the host returns, or refused at once so the user knows to
retry. It is never silently dropped or applied twice.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from itertools import islice
from pathlib import Path
from typing import Any

import httpx
import pytest

from omnigent.process_logging import redact_log_text
from tests.e2e.resilience.lab.driver import SessionDriver
from tests.e2e.resilience.lab.events import EventLog
from tests.e2e.resilience.lab.lab import Harness, Lab
from tests.e2e.resilience.lab.observe import Observation, SessionWatcher
from tests.e2e.resilience.lab.proxy import Fault
from tests.e2e.resilience.lab.report import ScenarioReport, report_dir
from tests.e2e.resilience.scenarios import _contract as contract

_ACTIONS = {
    "send": contract.IDLE,
    "approve": contract.APPROVAL_PENDING,
    "stop": contract.TOOL_RUNNING,
}
_KNOWN_GAPS = {
    **contract.gaps(
        "R2: the permission hook gives up after ~90s of failed re-POSTs, so an approval "
        "given while the host was offline never reaches Claude",
        [("approve", 150)],
    ),
}
#: A refusal slower than this is not "at once" for a user waiting on a button.
_PROMPT_REFUSAL_S = 35.0


def _host_offline(lab: Lab) -> list[Fault]:
    links = (lab.proxies.host, lab.proxies.model)
    faults = [link.refuse() for link in links]
    for link in links:
        link.reset()
    return faults


def _restore_after(faults: list[Fault], deadline: float, cancel: threading.Event) -> float:
    cancel.wait(max(0.0, deadline - time.monotonic()))
    for fault in faults:
        fault.clear()
    return time.monotonic()


@pytest.mark.timeout(900)
@pytest.mark.parametrize(
    ("harness", "action", "outage_s"),
    contract.cases(_ACTIONS, contract.outages([20], [150]), _KNOWN_GAPS),
)
def test_s5_host_offline_user_acts(
    lab_factory: Callable[..., Lab], harness: Harness, action: str, outage_s: int
) -> None:
    lab = lab_factory()
    assert lab.client is not None
    lab.client.headers["x-omnigent-hold-when-host-offline"] = "on"
    driver = SessionDriver.create(lab, harness)
    session_id = driver.session_id
    report = ScenarioReport(
        "S5 host offline, user acts", {"harness": harness, "action": action, "outage_s": outage_s}
    )
    with contract.observe(lab, driver, report) as watcher:
        assert contract.eventually(
            lambda: True if lab.snapshot(session_id).get("runner_online") is True else None,
            timeout=contract.RECOVERY_S,
        ), "The runner must connect before the setup turn and fault injection"
        entered = contract.enter(driver, _ACTIONS[action], outage_s=outage_s)
        if action == "send":
            assert contract.eventually(
                lambda: True if lab.snapshot(session_id).get("status") == "idle" else None,
                timeout=contract.SETTLE_S,
            ), "The initial turn must settle idle before the outage begins"
        started = time.time()
        outage_started = time.monotonic()
        faults = _host_offline(lab)
        cancel_restore = threading.Event()
        with ThreadPoolExecutor(max_workers=1) as executor:
            restored = executor.submit(
                _restore_after, faults, outage_started + outage_s, cancel_restore
            )
            try:
                time.sleep(2.0)
                response, elapsed = _act(driver, entered, action)
                accepted = response is not None and response.status_code < 400
                status = response.status_code if response is not None else "timeout"
                report.check(
                    "action_accepted_or_refused_promptly",
                    accepted or elapsed <= _PROMPT_REFUSAL_S,
                    f"HTTP {status} after {elapsed:.1f}s",
                )
                restored_at = restored.result()
            finally:
                cancel_restore.set()
                restored.result()
        actual_outage = restored_at - outage_started
        report.check(
            "outage_duration_matches_requested",
            abs(actual_outage - outage_s) <= 2.0,
            f"requested {outage_s}s, observed {actual_outage:.2f}s",
        )
        ended = time.time()
        _check_outcome(report, lab, driver, entered, action, accepted)
        idle_started = time.time()
        contract.check_settled_idle(report, lab, session_id)
        idle_ended = time.time()
        next_turn = contract.eventually_round_trip(driver)
        next_turn_ended = time.time()
        report.check(
            "next_turn_round_trips",
            next_turn is not None,
            "" if next_turn else "a new message after recovery got no reply",
        )
        if outage_s < contract.GRACE_S:
            contract.check_no_failure(
                report, watcher, started, max(time.time(), ended + contract.SETTLE_S)
            )
    if (harness, action, outage_s) == ("codex", "send", 20):
        try:
            assert lab.model is not None and entered.turn is not None
            markers = [entered.turn.marker]
            if next_turn is not None:
                markers.append(next_turn.marker)
            payload = _observation_summary(
                session_id,
                report=report,
                watcher=watcher,
                events=lab.events,
                requests=lab.model.requests(),
                items=lab.items(session_id),
                markers=markers,
                phase_times={
                    "idle_started": idle_started,
                    "idle_ended": idle_ended,
                    "next_turn_ended": next_turn_ended,
                },
            )
            payload["process_logs"] = _redacted_process_logs(lab.root, session_id=session_id)
            path = report_dir() / f"{report.file_stem()}.diagnostic.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2) + "\n")
        except Exception as error:
            print(f"S5 observation collection failed: {type(error).__name__}")
    report.require()


def _act(
    driver: SessionDriver, entered: contract.Phase, action: str
) -> tuple[httpx.Response | None, float]:
    started = time.monotonic()
    try:
        if action == "send":
            entered.turn = driver.text_turn()
            response = driver.send_raw(entered.turn, timeout=120)
        elif action == "approve":
            assert entered.approval_id is not None
            response = driver.approve(entered.approval_id)
        else:
            assert driver.lab.client is not None
            driver.lab.events.emit("user", "stop", action="clicks Stop")
            response = driver.lab.client.post(
                f"/v1/sessions/{driver.session_id}/events",
                json={"type": "stop_session", "data": {}},
                timeout=120,
            )
    except httpx.HTTPError:
        response = None
    return response, time.monotonic() - started


def _check_outcome(
    report: ScenarioReport,
    lab: Lab,
    driver: SessionDriver,
    entered: contract.Phase,
    action: str,
    accepted: bool,
) -> None:
    turn = entered.turn
    assert turn is not None
    if action == "stop":
        if not accepted:
            # A refused Stop must leave the turn alone: it finishes normally.
            contract.check_turn_completes(report, driver, turn)
            return
        stopped = contract.eventually(
            lambda: True if lab.snapshot(driver.session_id).get("status") != "running" else None,
            timeout=contract.RECOVERY_S,
        )
        report.check(
            "stop_takes_effect",
            bool(stopped),
            f"status={lab.snapshot(driver.session_id).get('status')}",
        )
        # The tool outlives the outage by about 20 s (longer for a Codex chain that
        # stalled on hooks); finishing at any point proves it was only shown as stopped.
        assert turn.done is not None
        done = turn.done
        ran_on = contract.eventually(
            lambda: (
                True if done.exists() or driver.count_text(turn.reply, role="assistant") else None
            ),
            timeout=contract.RECOVERY_S + 30,
        )
        report.check(
            "stopped_turn_does_not_finish",
            not ran_on,
            "the stopped turn finished on the host after it returned" if ran_on else "",
        )
        return
    if action == "approve" and not accepted:
        # A refused approval leaves the prompt for the user to answer once reachable.
        pending = contract.eventually(
            lambda: driver.pending_approval(turn), timeout=contract.SETTLE_S
        )
        report.check(
            "refused_approval_can_be_answered_again",
            pending is not None,
            "" if pending else "no pending approval after the host returned",
        )
        if pending is not None:
            driver.approve(str(pending["elicitation_id"]))
    if action == "send" and not accepted:
        copies = driver.count_text(turn.marker, role="user")
        report.check("refused_message_not_delivered", copies == 0, f"{copies} copies")
        return
    contract.check_turn_completes(report, driver, turn)


def _observation_summary(
    session_id: str,
    *,
    report: ScenarioReport,
    watcher: SessionWatcher,
    events: EventLog,
    requests: list[dict[str, Any]],
    items: list[dict[str, Any]],
    markers: list[str],
    phase_times: dict[str, float],
) -> dict[str, Any]:
    """Retain public correlation and timing without prompts, headers or environment."""
    event_fields = {
        "process",
        "pid",
        "graceful",
        "session_id",
        "harness",
        "conn",
        "tag",
        "reason",
        "age_s",
        "c2s_bytes",
        "s2c_bytes",
        "fault",
        "tags",
        "connections",
    }

    def marker_matches(value: object) -> list[str]:
        text = json.dumps(value, sort_keys=True)
        return [marker for marker in markers if marker in text]

    return {
        "schema_version": 1,
        "session_id": session_id,
        "phase_times": phase_times,
        "markers": markers,
        "checks": [{"name": check.name, "passed": check.passed} for check in report.checks],
        "observations": [asdict(row) for row in watcher.between(report.started, float("inf"))],
        "events": [
            {
                "wall": row.wall,
                "mono": row.mono,
                "source": row.source,
                "kind": row.kind,
                **{key: value for key, value in row.fields.items() if key in event_fields},
            }
            for row in events.events()
        ],
        "mock_requests": [
            {
                "index": index,
                "input_sha256": hashlib.sha256(
                    json.dumps(request, sort_keys=True).encode()
                ).hexdigest(),
                "markers": marker_matches(request.get("messages") or request.get("input")),
                "tool_count": len(request.get("tools") or []),
            }
            for index, request in enumerate(requests)
        ],
        "items": [
            {
                **{
                    key: item[key]
                    for key in ("id", "type", "role", "turn_id", "call_id", "created_at")
                    if key in item
                },
                "markers": marker_matches(item),
            }
            for item in items
        ],
    }


@pytest.mark.parametrize("settled", [False, True])
def test_s5_observation_keeps_outcome_and_ids_without_raw_payloads(settled: bool) -> None:
    report = ScenarioReport("S5", {}, started=0)
    report.check("status_settles_idle", settled, "private detail must not be retained")
    watcher = SessionWatcher("", "session")
    watcher._record(Observation(15.5, "snapshot", status="running"))
    response_id = "codex_turn_01a1db42-b89b-7702-8492-49aa3586d946"
    for value in (response_id, ["private"], "private " + "x" * 160, "private"):
        watcher._consume(
            "data: "
            + json.dumps(
                {
                    "type": "session.status",
                    "status": "idle",
                    "response_id": value,
                    "source": "private producer",
                    "content": "private payload",
                }
            )
        )
    events = EventLog()
    events.emit("lab", "process_start", process="runner", pid=42, environment="private env")
    payload = _observation_summary(
        "session",
        report=report,
        watcher=watcher,
        events=events,
        requests=[
            {
                "messages": [{"content": "MARKER private prompt"}],
                "headers": {"Authorization": "private credential"},
                "tools": [{"name": "exec_command"}],
            }
        ],
        items=[
            {
                "id": "item",
                "turn_id": "turn",
                "type": "message",
                "role": "assistant",
                "content": "MARKER private reply",
            }
        ],
        markers=["MARKER"],
        phase_times={"idle_started": 0, "idle_ended": 15, "next_turn_ended": 16},
    )
    assert payload["checks"] == [{"name": "status_settles_idle", "passed": settled}]
    assert payload["observations"][0]["status"] == "running"
    assert [row["response_id"] for row in payload["observations"]] == [
        None,
        response_id,
        None,
        None,
        None,
    ]
    assert payload["observations"][1]["source"] == "stream"
    assert payload["events"][0]["pid"] == 42
    assert payload["items"][0]["turn_id"] == "turn"
    assert payload["mock_requests"][0]["markers"] == ["MARKER"]
    assert len(payload["mock_requests"][0]["input_sha256"]) == 64
    assert "private" not in json.dumps(payload)


def _redacted_process_logs(root: Path, *, session_id: str) -> dict[str, Any]:
    """Project known session log tails and collection counts without copying messages."""
    prefix = re.compile(
        r"^(?:DEBUG|INFO|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?)[ \t]+"
        r"(?P<time>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) [^|\n]+ \| (?P<message>.*)$"
    )
    identifier = r"(?:[0-9a-f-]{1,64}|turn_[0-9a-f]{1,64}|None)"
    source = (
        r"(?:turn/(?:started|completed|failed)(?::turn-(?:error|failed))?"
        r"|thread/resume(?::turn-error)?|delta:recovered|error(?::certificate)?)"
    )
    lifecycle = re.compile(
        rf"Codex forwarder publishing turn status: source=(?P<source>{source}) "
        rf"turn_id=(?P<turn_id>{identifier}) status=(?P<status>running|idle|failed)"
    )
    rejected = re.compile(
        r"failed to post Codex session event: type=external_session_status "
        r"status=(?P<http_status>[1-5]\d{2}) body="
    )
    retry = re.compile(
        r"retrying idempotent Codex session event until delivery: "
        rf"session=(?P<session_id>{identifier}) type=external_session_status "
        r"attempt=(?P<attempt>\d{1,8}) http_status=(?P<http_status>[1-5]\d{2}|None) error="
    )
    directory = root / "logs"
    runner_directory = root / "data" / "logs" / "runner"
    runner_safe = not root.is_symlink() and all(
        path.is_dir() and not path.is_symlink()
        for path in (root / "data", root / "data" / "logs", runner_directory)
    )
    valid_session = re.fullmatch(r"[0-9a-f]{32}", session_id) is not None
    launch_name = re.compile(
        rf"runner-{re.escape(session_id)}-\d{{8}}-\d{{6}}-\d{{6}}(?:-\d+)?\.log"
    )
    paths = [
        (name, directory / f"{name}.log", not root.is_symlink() and not directory.is_symlink())
        for name in ("host", "host-process", "runner", "runner-process", "server")
    ]
    matching = (
        list(
            islice(
                (
                    path
                    for path in runner_directory.glob(f"runner-{session_id}-*.log")
                    if launch_name.fullmatch(path.name)
                ),
                5,
            )
        )
        if valid_session and runner_safe
        else []
    )
    result: dict[str, Any] = {
        "session_runner": {
            "valid_session": valid_session,
            "directory_present": runner_directory.is_dir(),
            "directory_safe": runner_safe,
            "matching_files_seen": len(matching),
            "file_limit": 4,
            "overflow": len(matching) > 4,
        },
        "files": {},
    }
    if len(matching) <= 4:
        paths.extend((path.name, path, True) for path in sorted(matching))
    for name, path, safe_directory in paths:
        entry: dict[str, Any] = {
            "present": False,
            "state": "unsafe_directory" if not safe_directory else "absent",
            "read_bytes": 0,
            "lines": 0,
            "formatted": 0,
            "matched": 0,
            "events": [],
        }
        result["files"][name] = entry
        if not safe_directory:
            continue
        try:
            before = path.lstat()
            entry["present"] = True
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
            ):
                entry["state"] = "unsafe_file"
                continue
            with os.fdopen(
                os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb"
            ) as stream:
                opened = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    entry["state"] = "changed_file"
                    continue
                stream.seek(max(0, opened.st_size - 65536))
                raw = stream.read(65536)
            entry["read_bytes"] = len(raw)
            entry["state"] = "read"
        except OSError as error:
            entry["error_errno"] = error.errno
            entry["state"] = "absent" if error.errno == errno.ENOENT else "unreadable"
            continue
        text = redact_log_text(raw.decode(errors="replace"), include_whitespace_credentials=True)
        rows: list[dict[str, str | int]] = []
        lines = text.splitlines()
        entry["lines"] = len(lines)
        for line_number, line in enumerate(lines):
            record = prefix.fullmatch(line)
            if record is None:
                continue
            entry["formatted"] += 1
            message = record["message"]
            match = lifecycle.fullmatch(message)
            event = "turn_status"
            if match is None:
                match = rejected.match(message)
                event = "status_post_rejected"
            if match is None:
                match = retry.match(message)
                event = "status_post_retry"
            if match is not None:
                rows.append(
                    {
                        "time": record["time"],
                        "line": line_number,
                        "event": event,
                        **match.groupdict(),
                    }
                )
        entry["matched"] = len(rows)
        entry["events"] = rows[-256:]
    return result


def test_s5_owned_log_tails_are_bounded_and_redacted(tmp_path: Path) -> None:
    directory = tmp_path / "logs"
    directory.mkdir()
    session_id = "19d62c1e77c7496fb197eade75852432"
    prefix = "INFO  11-14 12:34:56.789 codex_native.forwarder _post_turn_status_edge | "
    warning = prefix.replace("INFO  ", "WARN  ")
    completed = (
        "Codex forwarder publishing turn status: "
        "source=turn/completed turn_id=turn_abc123 status=idle"
    )
    (directory / "host.log").write_text(
        prefix + completed + "\n" + "x" * 70000 + "\n"
        "Authorization: Bearer sample-private-key\n"
        + prefix
        + completed
        + "\n"
        + warning
        + "failed to post Codex session event: type=external_session_status "
        "status=503 body=private-prompt Authorization=private-header env=private-env "
        "turn_id=turn_dead status=running\n"
        + prefix
        + "Codex elicitation hook returned non-object result: "
        "method=turn/completed result={'prompt': 'private-result'}\n"
        + prefix
        + completed
        + " body=private-tail\n"
    )
    (directory / "host-process.log").write_text(
        prefix + "Codex forwarder publishing turn status: "
        "source=turn/started turn_id=turn_def456 status=running\n"
        + warning
        + "retrying idempotent Codex session event until delivery: "
        "session=19d62c1e77c7496fb197eade75852432 type=external_session_status "
        "attempt=2 http_status=503 error=private-error\n"
    )
    (directory / "other.log").write_text("unrelated private log")
    (directory / "server.log").symlink_to(directory / "other.log")
    collection = _redacted_process_logs(tmp_path, session_id=session_id)
    files = collection["files"]
    logs = {name: entry["events"] for name, entry in files.items() if entry["state"] == "read"}
    assert set(logs) == {"host", "host-process"}
    assert [row["event"] for row in logs["host"]] == ["turn_status", "status_post_rejected"]
    assert logs["host"][0]["turn_id"] == "turn_abc123"
    assert logs["host"][0]["status"] == "idle"
    assert logs["host"][0]["time"] == "11-14 12:34:56.789"
    assert logs["host"][1]["http_status"] == "503"
    assert logs["host-process"][0]["source"] == "turn/started"
    assert logs["host-process"][1]["session_id"] == "19d62c1e77c7496fb197eade75852432"
    assert logs["host-process"][1]["attempt"] == "2"
    encoded = json.dumps(logs)
    assert len(encoded.encode()) <= 65536
    assert "private" not in encoded and "turn_dead" not in encoded

    assert not collection["session_runner"]["directory_present"]
    assert files["host"]["read_bytes"] == 65536
    assert files["host"]["formatted"] == 4 and files["host"]["matched"] == 2
    assert files["runner"]["state"] == "absent"
    assert files["server"]["state"] == "unsafe_file"

    runner_directory = tmp_path / "data" / "logs" / "runner"
    runner_directory.mkdir(parents=True)
    launch = f"runner-{session_id}-20261115-000000-000000.log"
    (runner_directory / launch).write_text(prefix + completed + "\n")
    (runner_directory / "runner-other-session-20261115-000000-000000.log").write_text(
        "private foreign"
    )
    (runner_directory / f"runner-{session_id}-not-a-launch.log").write_text("private invalid name")
    (runner_directory / f"runner-{session_id}-20261115-000000-000001.log").symlink_to(
        directory / "other.log"
    )
    collection = _redacted_process_logs(tmp_path, session_id=session_id)
    assert collection["session_runner"]["matching_files_seen"] == 2
    assert not collection["session_runner"]["overflow"]
    assert collection["files"][launch]["matched"] == 1
    assert collection["files"][launch]["events"][0]["turn_id"] == "turn_abc123"
    assert (
        collection["files"][launch.replace("000000.log", "000001.log")]["state"] == "unsafe_file"
    )
    assert "private" not in json.dumps(collection)
    assert (
        _redacted_process_logs(tmp_path, session_id="../other")["session_runner"][
            "matching_files_seen"
        ]
        == 0
    )
    for index in range(2, 5):
        (runner_directory / f"runner-{session_id}-20261115-000000-{index:06d}.log").write_text("")
    collection = _redacted_process_logs(tmp_path, session_id=session_id)
    assert collection["session_runner"]["overflow"]
    assert not any(
        name.startswith("runner-") and name.endswith(".log") for name in collection["files"]
    )
    runner_directory.rename(runner_directory.with_name("saved"))
    runner_directory.symlink_to(directory, target_is_directory=True)
    assert not _redacted_process_logs(tmp_path, session_id=session_id)["session_runner"][
        "directory_safe"
    ]
