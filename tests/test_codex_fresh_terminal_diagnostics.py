"""Pure mocked coverage of the native test's passive request diagnostics."""

from __future__ import annotations

import inspect
import json
import traceback
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from _pytest.junitxml import LogXML
from _pytest.reports import TestReport as _TestReport

from omnigent.harnesses.codex_native import bridge as bridge_module
from omnigent.harnesses.codex_native.bridge import (
    CodexNativeBridgeState,
    CodexNativeBridgeStateRead,
)
from tests.e2e import test_codex_native_supported_efforts_e2e as subject

_PRIVATE = "synthetic-private-fresh-turn"


class _Scenario:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.events = []
        self.frames = []
        self.errors = []
        self.ticks = 0
        self.state = CodexNativeBridgeState("session-under-test", _PRIVATE, _PRIVATE, None)
        self.prep_state = self.state
        self.pane = None
        self.literal = ""
        self.bridge_results = [CodexNativeBridgeStateRead(self.state, "ready")]
        self.mode = "ready"
        self.payload = {"requests": []}
        self.session = subject._Session("session-under-test", Path("unused-bridge"), {})
        self.session.tmux = Mock(side_effect=self.tmux)
        self.model = Mock(spec=httpx.Client)
        self.model.get.side_effect = self.get
        self.model.post.return_value = httpx.Response(
            200, json={"released": False}, request=httpx.Request("POST", "http://example.test")
        )
        self.read = Mock(side_effect=self.read_bridge)
        self.native = Mock(side_effect=AssertionError("Native observation is forbidden"))
        monkeypatch.setattr(subject, "read_bridge_state_result", self.read)
        monkeypatch.setattr(subject, "client_for_transport", self.native)
        monkeypatch.setattr(
            subject, "time", SimpleNamespace(monotonic=self.monotonic, sleep=self.sleep)
        )
        self.logs = tmp_path / ".omnigent/logs/runner"
        self.logs.mkdir(parents=True)
        self.log = self.logs / "runner.log"
        self.log.write_text(
            f"Codex thread {_PRIVATE} is not ready yet (no/empty rollout); retrying subscription"
        )

        def read_state(_bridge):
            return self.prep_state

        monkeypatch.setattr(subject, "read_bridge_state", read_state)
        monkeypatch.setattr(bridge_module, "read_bridge_state", read_state)
        self.rig = SimpleNamespace(model=self.model, stack=SimpleNamespace(runner_home=tmp_path))

        @contextmanager
        def session(*_args, **_kwargs):
            yield self.session

        monkeypatch.setattr(subject, "_session", session)

    def tmux(self, *args: str) -> str:
        if args[:2] == ("send-keys", "-l"):
            self.literal = args[2]
        return self.pane if self.pane is not None else f"› {self.literal}"

    def monotonic(self) -> float:
        return self.ticks / 10

    def sleep(self, seconds: float) -> None:
        self.events.append(("sleep", seconds))
        self.ticks += round(seconds * 10)

    def read_bridge(self, bridge: Path) -> CodexNativeBridgeStateRead:
        self.events.append("bridge")
        assert bridge == self.session.bridge
        frame = inspect.currentframe()
        while frame is not None and frame.f_code is not subject._fresh_terminal_sample.__code__:
            frame = frame.f_back
        assert frame is not None
        self.frames.append(frame)
        if self.mode == "bridge":
            raise OSError(_PRIVATE)
        result = self.bridge_results[0]
        if len(self.bridge_results) > 1:
            self.bridge_results.pop(0)
        return result

    def get(self, path: str) -> httpx.Response:
        self.events.append("get")
        assert path == "/mock/requests"
        request = httpx.Request("GET", f"http://example.test/{_PRIVATE}")
        if self.mode == "nested":
            try:
                raise ValueError(_PRIVATE)
            except ValueError as inner:
                self.errors.append(inner)
                outer = RuntimeError(_PRIVATE)
                outer.add_note(_PRIVATE)
                self.errors.append(outer)
                raise outer from inner
        if self.mode == "transport":
            error = httpx.ConnectError(_PRIVATE, request=request)
            self.errors.append(error)
            raise error
        if self.mode == "group":
            error = ExceptionGroup(_PRIVATE, [ValueError(_PRIVATE)])
            self.errors.extend([error, *error.exceptions])
            raise error
        if self.mode == "interrupt":
            raise KeyboardInterrupt(_PRIVATE)
        if self.mode == "exit":
            raise SystemExit(_PRIVATE)
        if self.mode == "http":
            return httpx.Response(503, text=_PRIVATE, request=request)
        if self.mode == "decode":
            return httpx.Response(200, text=f"{_PRIVATE}{{", request=request)
        return httpx.Response(200, text=json.dumps(self.payload), request=request)

    def sample(self, ordinal: int = 1):
        return subject._fresh_terminal_sample(
            self.model, self.session.bridge, self.session.id, ordinal
        )

    def wait(self):
        return subject._wait_for_fresh_terminal_request(self.model, self.session)

    def downstream(self) -> None:
        self.wait()
        raise AssertionError("Deliberate failure after successful decode")

    def owning_case(self) -> None:
        subject.test_fresh_terminal_turn_reports_running_before_first_model_output(self.rig)


@pytest.fixture
def scenario(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Scenario:
    return _Scenario(monkeypatch, tmp_path)


def _capture(action) -> pytest.ExceptionInfo:
    try:
        action()
    except AssertionError:
        return pytest.ExceptionInfo.from_current()
    raise AssertionError("The mocked action must fail")


def _render_failure(info: pytest.ExceptionInfo, directory: Path) -> dict[str, str]:
    formatted = "".join(
        traceback.TracebackException.from_exception(info.value, capture_locals=True).format()
    )
    showlocals = info.getrepr(showlocals=True, style="long", tbfilter=False)
    xml_path = directory / "synthetic-failure.xml"
    xml = LogXML(str(xml_path), prefix=None)
    xml.pytest_sessionstart()
    common = {
        "nodeid": "tests/synthetic.py::test_failure",
        "location": ("tests/synthetic.py", 0, "test_failure"),
        "keywords": {},
    }
    xml.pytest_runtest_logreport(
        _TestReport(**common, outcome="failed", longrepr=showlocals, when="call")
    )
    xml.pytest_runtest_logreport(
        _TestReport(**common, outcome="passed", longrepr=None, when="teardown")
    )
    xml.pytest_sessionfinish()
    assert ET.parse(xml_path).find(".//failure") is not None
    return {"traceback": formatted, "showlocals": str(showlocals), "junit": xml_path.read_text()}


def _mixed_requests(matching: int) -> list[dict]:
    entries = [
        {},
        {"prompt_cache_key": None},
        {"prompt_cache_key": ""},
        {"prompt_cache_key": 7},
        {"prompt_cache_key": []},
        {"prompt_cache_key": f"{_PRIVATE}-other"},
        *[{"prompt_cache_key": _PRIVATE} for _ in range(matching)],
    ]
    for entry in entries:
        entry["input"] = [{"content": _PRIVATE, "arguments": _PRIVATE}]
        entry["credentials"] = _PRIVATE
    return entries


@pytest.mark.parametrize("matching", [0, 1, 2])
def test_same_response_counts_and_immutable_scalars(scenario: _Scenario, matching: int) -> None:
    scenario.payload = {"requests": _mixed_requests(matching), "unknown": _PRIVATE}
    state, sample = scenario.sample(7)
    assert asdict(sample) == {
        "ordinal": 7,
        "bridge_read_status": "ready",
        "bridge_errno": None,
        "thread_present": True,
        "session_matches": True,
        "mock_read_status": "ready",
        "total": 6 + matching,
        "key_present": 5 + matching,
        "nonempty_string": 1 + matching,
        "matching": matching,
    }
    assert (state is scenario.state) == (matching == 1)
    assert scenario.events == ["bridge", "get"]
    assert _PRIVATE not in repr(sample)
    with pytest.raises(FrozenInstanceError):
        sample.total = 0


def test_empty_ledger_and_session_match_are_observations(scenario: _Scenario) -> None:
    state, sample = scenario.sample()
    assert state is None
    assert (sample.total, sample.key_present, sample.nonempty_string, sample.matching) == (
        0,
        0,
        0,
        0,
    )
    scenario.state = CodexNativeBridgeState("another-session", _PRIVATE, _PRIVATE, _PRIVATE)
    scenario.bridge_results = [CodexNativeBridgeStateRead(scenario.state, "ready")]
    scenario.payload = {"requests": [{"prompt_cache_key": _PRIVATE}]}
    state, sample = scenario.sample()
    assert sample.session_matches is False
    assert sample.matching == 1
    assert state is scenario.state


@pytest.mark.parametrize(
    "status,errno",
    [
        ("missing", 2),
        ("not_file", None),
        ("unreadable", 13),
        ("invalid_encoding", None),
        ("invalid_json", None),
        ("invalid_state", None),
    ],
)
def test_bridge_unavailability_preserves_one_ledger_read(
    scenario: _Scenario, status: str, errno: int | None
) -> None:
    scenario.bridge_results = [CodexNativeBridgeStateRead(None, status, errno)]
    scenario.payload = {"requests": [{"prompt_cache_key": None}]}
    state, sample = scenario.sample()
    assert state is None
    assert (sample.bridge_read_status, sample.bridge_errno) == (status, errno)
    assert sample.thread_present is sample.session_matches is False
    assert sample.total == sample.key_present == 1
    assert sample.matching == sample.nonempty_string == 0
    assert scenario.events == ["bridge", "get"]


def test_poll_uses_the_identity_from_each_single_bridge_read(scenario: _Scenario) -> None:
    second = CodexNativeBridgeState("session-under-test", _PRIVATE, f"{_PRIVATE}-second", _PRIVATE)
    scenario.bridge_results.append(CodexNativeBridgeStateRead(second, "ready"))
    scenario.payload = {"requests": [{"prompt_cache_key": second.thread_id}]}
    assert scenario.wait() is second
    assert scenario.events == ["bridge", "get", ("sleep", 0.1), "bridge", "get"]
    assert scenario.read.call_count == scenario.model.get.call_count == 2
    scenario.native.assert_not_called()


def test_fresh_preparation_retains_bounded_redacted_failure_evidence(scenario: _Scenario) -> None:
    scenario.pane = (
        "x" * 9000 + "\nAuthorization: Bearer synthetic-private-token\n› Input disabled."
    )
    with pytest.raises(pytest.fail.Exception, match="current fresh thread"):
        subject._start_fresh_terminal_turn(scenario.rig, scenario.session, "FRESH_MARKER")
    evidence = json.loads((scenario.logs / "fresh-terminal-input.log").read_text())
    assert len(evidence) == 1
    assert len(evidence[0]["pane"]) <= 8192
    assert "synthetic-private-token" not in evidence[0]["pane"]
    assert "Input disabled." in evidence[0]["pane"]
    assert not any(call.args[0] == "send-keys" for call in scenario.session.tmux.call_args_list)
    scenario.native.assert_not_called()


@pytest.mark.parametrize("matching", [0, 1, 2])
def test_original_count_one_oracle_and_bounded_history(scenario: _Scenario, matching: int) -> None:
    scenario.payload = {"requests": _mixed_requests(matching)}
    if matching == 1:
        assert scenario.wait() is scenario.state
        assert scenario.read.call_count == scenario.model.get.call_count == 1
    else:
        info = _capture(scenario.wait)
        ended = info.traceback[-1].frame.f_locals
        samples, omitted = ended["samples"], ended["omitted"]
        if matching:
            assert len(samples) == 1 and omitted == 0
            assert scenario.read.call_count == scenario.model.get.call_count == 1
        else:
            assert [sample.ordinal for sample in samples] == list(range(193, 201))
            assert omitted == 192
            assert scenario.read.call_count == scenario.model.get.call_count == 200
            assert scenario.ticks == 200
        assert all(sample.matching == matching for sample in samples)
        assert info.value.__cause__ is info.value.__context__ is None
    scenario.native.assert_not_called()


@pytest.mark.parametrize(
    "mode,payload,status",
    [
        ("ready", None, "invalid_response"),
        ("ready", [], "invalid_response"),
        ("ready", {}, "invalid_response"),
        ("ready", {"requests": {"private": _PRIVATE}}, "invalid_response"),
        ("ready", {"requests": [{}, _PRIVATE]}, "invalid_entry"),
        ("transport", None, "transport_error"),
        ("http", None, "http_error"),
        ("decode", None, "decode_error"),
        ("nested", None, "transport_error"),
        ("group", None, "transport_error"),
        ("bridge", None, "bridge_error"),
    ],
)
def test_read_failures_still_fail_without_retry(
    scenario: _Scenario, mode: str, payload: object, status: str, tmp_path: Path
) -> None:
    scenario.mode, scenario.payload = mode, payload
    info = _capture(scenario.wait)
    ended = info.traceback[-1].frame.f_locals
    samples, omitted = ended["samples"], ended["omitted"]
    assert len(samples) == 1 and omitted == 0
    assert samples[0].mock_read_status == status
    assert samples[0].matching is None
    assert scenario.read.call_count == 1
    assert scenario.model.get.call_count == (0 if mode == "bridge" else 1)
    assert scenario.ticks == 0
    assert info.value.__cause__ is info.value.__context__ is None
    for error in scenario.errors:
        assert error.__traceback__ is error.__cause__ is error.__context__ is None
    for renderer, output in _render_failure(info, tmp_path).items():
        assert _PRIVATE not in output, renderer
    scenario.native.assert_not_called()


@pytest.mark.parametrize("mode", ["zero", "multiple", "downstream"])
def test_failure_rendering_excludes_private_payloads(
    scenario: _Scenario, mode: str, tmp_path: Path
) -> None:
    scenario.payload = {"requests": _mixed_requests(2 if mode == "multiple" else 0)}
    action = scenario.wait
    if mode == "downstream":
        scenario.payload = {"requests": _mixed_requests(1)}
        action = scenario.downstream
    info = _capture(action)
    for renderer, output in _render_failure(info, tmp_path).items():
        assert _PRIVATE not in output, renderer
    assert info.value.__cause__ is info.value.__context__ is None


@pytest.mark.parametrize("mode", ["ready", "nested", "decode", "http", "bridge"])
def test_sample_clears_sensitive_frame_references_on_every_exit(
    scenario: _Scenario, mode: str
) -> None:
    scenario.mode = mode
    scenario.payload = {"requests": _mixed_requests(1)}
    scenario.sample()
    for frame in scenario.frames:
        for name in (
            "model",
            "bridge",
            "session_id",
            "result",
            "state",
            "response",
            "payload",
            "requests",
            "current",
            "linked",
        ):
            assert frame.f_locals[name] is None, name
        assert frame.f_locals["errors"] == []
        assert "error" not in frame.f_locals


@pytest.mark.parametrize(
    "mode,exception", [("interrupt", KeyboardInterrupt), ("exit", SystemExit)]
)
def test_control_flow_errors_are_cleared_and_remain_failures(
    scenario: _Scenario, mode: str, exception: type[BaseException]
) -> None:
    scenario.mode = mode
    with pytest.raises(exception) as caught:
        scenario.wait()
    if mode == "exit":
        assert isinstance(caught.value, SystemExit)
        assert caught.value.code == 1
    assert _PRIVATE not in str(caught.value)
    assert caught.value.__context__ is caught.value.__cause__ is None
    assert scenario.read.call_count == scenario.model.get.call_count == 1


def test_real_owning_case_keeps_input_order_cleanup_and_observer_gate(scenario: _Scenario) -> None:
    info = _capture(scenario.owning_case)
    assert "input acceptance unknown" in str(info.value)
    calls = scenario.session.tmux.call_args_list
    sends = [call for call in calls if call.args[0] == "send-keys"]
    assert len(sends) == 2
    assert sends[0].args[:2] == ("send-keys", "-l")
    assert sends[0].args[2].startswith("Reply with FRESH_QUIET_")
    assert sends[1].args == ("send-keys", "Enter")
    assert scenario.events[0] == ("sleep", 0.5)
    assert scenario.events[1:3] == ["bridge", "get"]
    assert scenario.model.get.call_count == scenario.read.call_count == 200
    assert [call.args[0] for call in scenario.model.post.call_args_list] == [
        "/mock/reset",
        "/mock/configure",
        "/gate/release",
    ]
    scenario.native.assert_not_called()


@pytest.mark.parametrize("unready", ["old_thread", "wrong_session", "disabled_composer"])
def test_fresh_preparation_rejects_unrelated_or_disabled_terminal(
    scenario: _Scenario, unready: str
) -> None:
    if unready == "old_thread":
        scenario.log.write_text(
            "Codex thread previous-thread is not ready yet "
            "(no/empty rollout); retrying subscription"
        )
    elif unready == "wrong_session":
        scenario.prep_state = CodexNativeBridgeState("another-session", _PRIVATE, _PRIVATE, None)
    else:
        scenario.pane = "› Input disabled."
    with pytest.raises(pytest.fail.Exception, match="current fresh thread"):
        subject._start_fresh_terminal_turn(scenario.rig, scenario.session, "FRESH_MARKER")
    assert not any(call.args[0] == "send-keys" for call in scenario.session.tmux.call_args_list)
    assert scenario.ticks == 100
    scenario.model.get.assert_not_called()
    scenario.native.assert_not_called()


def test_fresh_preparation_stops_on_thread_change_before_enter(scenario: _Scenario) -> None:
    def change_after_literal(*args: str) -> str:
        pane = scenario.tmux(*args)
        if args[:2] == ("send-keys", "-l"):
            scenario.prep_state = CodexNativeBridgeState(
                scenario.session.id, _PRIVATE, "replacement-thread", None
            )
        return pane

    scenario.session.tmux.side_effect = change_after_literal
    with pytest.raises(AssertionError, match="identity changed before Enter"):
        subject._start_fresh_terminal_turn(scenario.rig, scenario.session, "FRESH_MARKER")
    sends = [
        call.args for call in scenario.session.tmux.call_args_list if call.args[0] == "send-keys"
    ]
    assert sends == [("send-keys", "-l", "Reply with FRESH_MARKER")]
    scenario.model.get.assert_not_called()
    scenario.native.assert_not_called()


@pytest.mark.parametrize("same_thread", [True, False])
def test_fresh_preparation_sends_once_and_binds_observed_request(
    scenario: _Scenario, monkeypatch: pytest.MonkeyPatch, same_thread: bool
) -> None:
    observed = (
        scenario.state
        if same_thread
        else CodexNativeBridgeState(scenario.session.id, _PRIVATE, "replacement-thread", None)
    )
    wait = Mock(return_value=observed)
    monkeypatch.setattr(subject, "_wait_for_fresh_terminal_request", wait)
    if same_thread:
        assert (
            subject._start_fresh_terminal_turn(scenario.rig, scenario.session, "FRESH_MARKER")
            is observed
        )
    else:
        with pytest.raises(AssertionError, match="another session or thread"):
            subject._start_fresh_terminal_turn(scenario.rig, scenario.session, "FRESH_MARKER")
    sends = [
        call.args for call in scenario.session.tmux.call_args_list if call.args[0] == "send-keys"
    ]
    assert sends == [("send-keys", "-l", "Reply with FRESH_MARKER"), ("send-keys", "Enter")]
    wait.assert_called_once_with(scenario.model, scenario.session)
    evidence = json.loads((scenario.logs / "fresh-terminal-input.log").read_text())
    assert [sample["phase"] for sample in evidence] == [
        "before_input",
        "literal_rendered",
        "before_enter",
        "awaiting_request",
    ]
    assert evidence[1]["marker_visible"] and evidence[1]["composer_enabled"]
    assert all(len(sample["pane"]) <= 8192 for sample in evidence)
    scenario.native.assert_not_called()
