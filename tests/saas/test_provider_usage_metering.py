from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
from collections.abc import Coroutine
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

import saas.runner_adapter.managed_entry as managed_entry_module
import saas.runner_adapter.metering as metering_module
import saas.runner_adapter.process_policy as process_policy_module
from omnigent.host.connect import HostProcess
from omnigent.host.frames import HostLaunchRunnerFrame
from omnigent.host.identity import HostIdentity
from omnigent.llms.client import Client, _ResponsesNamespace
from omnigent.llms.types import MessageOutput, OutputText, Response, Usage
from omnigent.runner.identity import RUNNER_ID_ENV_VAR, token_bound_runner_id
from saas.runner_adapter.managed_entry import main as managed_entry_main
from saas.runner_adapter.metering import (
    MANAGED_METERING_ENVELOPE_ENV_VAR,
    ManagedMeteringError,
    ManagedMeteringGrant,
    ProviderUsageMeter,
    StagedManagedRunnerLaunchAuthority,
    consume_metering_envelope,
    write_metering_envelope,
)
from saas.runner_adapter.process_policy import ManagedHostProcess


class _FakeClient:
    def __init__(self, *, fail: bool = False, fail_once_on: str | None = None) -> None:
        self.fail = fail
        self.fail_once_on = fail_once_on
        self.calls: list[dict[str, object]] = []
        self.closed = False

    def record_usage(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        meter = kwargs["meter"]
        if self.fail or self.fail_once_on == meter:
            if self.fail_once_on == meter:
                self.fail_once_on = None
            raise RuntimeError("synthetic transport outage")
        return object()

    def close(self) -> None:
        self.closed = True


def _grant(
    tmp_path: Path, *, capability: str = "capability-must-not-be-spooled"
) -> ManagedMeteringGrant:
    return ManagedMeteringGrant(
        session_id=uuid4(),
        run_id=uuid4(),
        runner_id=uuid4(),
        capability_token=capability,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        metering_base_url="https://billing-metering.internal",
        expected_host="billing-metering.internal",
        ca_certificate_path=(tmp_path / "ca.pem").absolute(),
        client_certificate_path=(tmp_path / "client.pem").absolute(),
        client_key_path=(tmp_path / "client-key.pem").absolute(),
        spool_directory=(tmp_path / "spool").absolute(),
    )


async def _official_response(model: str = "anthropic/claude-test") -> None:
    await Client().responses.create(input=[], model=model)


@pytest.mark.parametrize("model", ["o1-preview", "o3-mini", "o4-mini"])
def test_provider_detection_covers_openai_reasoning_model_family(model: str) -> None:
    assert metering_module._provider_from_model(model) == "openai"


def _run_async(coroutine: Coroutine[Any, Any, Any]) -> Any:
    values: list[Any] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            values.append(asyncio.run(coroutine))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run, name="provider-metering-test-loop")
    worker.start()
    worker.join(timeout=15)
    if worker.is_alive():
        raise TimeoutError("provider metering test loop did not stop")
    if errors:
        raise errors[0]
    return values[0]


def test_official_client_usage_is_spooled_and_metered_without_total_double_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    response = Response(
        output=[MessageOutput(content=[OutputText(text="content-never-enters-metering")])],
        model="anthropic/claude-test",
        usage=Usage(input_tokens=11, output_tokens=4, total_tokens=15),
    )

    async def fake_create(self: Any, *args: Any, **kwargs: Any) -> Response:
        return response

    monkeypatch.setattr(_ResponsesNamespace, "_do_create", fake_create, raising=True)
    grant = _grant(tmp_path)
    client = _FakeClient()
    meter = ProviderUsageMeter(grant=grant, client=client, retry_interval_seconds=60)
    try:
        _run_async(_official_response())
        assert meter.flush()
    finally:
        assert meter.close()

    assert [call["meter"] for call in client.calls] == [
        "llm.input_tokens",
        "llm.output_tokens",
    ]
    assert [call["quantity"] for call in client.calls] == [11, 4]
    assert {call["provider"] for call in client.calls} == {"anthropic"}
    assert {call["run_id"] for call in client.calls} == {grant.run_id}
    assert not any(grant.capability_token in str(call["attributes"]) for call in client.calls)
    assert list(grant.spool_directory.glob("*.pending.json")) == []
    assert client.closed


def test_official_client_fails_closed_when_required_usage_cannot_persist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    response = Response(
        output=[MessageOutput(content=[OutputText(text="provider-completed")])],
        model="openai/gpt-test",
        usage=Usage(input_tokens=2, output_tokens=1, total_tokens=3),
    )

    async def fake_create(self: Any, *args: Any, **kwargs: Any) -> Response:
        return response

    def fail_persist(document: dict[str, object], event_id: object) -> None:
        del document, event_id
        raise ManagedMeteringError(
            "managed_metering_spool_unavailable", "managed metering spool is unavailable"
        )

    monkeypatch.setattr(_ResponsesNamespace, "_do_create", fake_create, raising=True)
    grant = _grant(tmp_path)
    client = _FakeClient()
    meter = ProviderUsageMeter(grant=grant, client=client, retry_interval_seconds=60)
    monkeypatch.setattr(meter, "_persist", fail_persist)
    try:
        with pytest.raises(ManagedMeteringError) as failed:
            _run_async(_official_response("openai/gpt-test"))
        assert failed.value.code == "managed_metering_spool_unavailable"
    finally:
        assert meter.close()
    assert client.calls == []


def test_spool_survives_restart_with_stable_idempotency_and_no_capability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    response = Response(
        output=[MessageOutput(content=[OutputText(text="sensitive-output")])],
        model="gpt-5",
        usage=Usage(input_tokens=7, output_tokens=3, total_tokens=10),
    )

    async def fake_create(self: Any, *args: Any, **kwargs: Any) -> Response:
        return response

    monkeypatch.setattr(_ResponsesNamespace, "_do_create", fake_create, raising=True)
    grant = _grant(tmp_path)
    unavailable = _FakeClient(fail=True)
    first = ProviderUsageMeter(grant=grant, client=unavailable, retry_interval_seconds=60)
    _run_async(_official_response("gpt-5"))
    assert not first.flush(0.01)
    assert not first.close(0.01)

    pending = list(grant.spool_directory.glob("*.pending.json"))
    assert len(pending) == 1
    encoded = pending[0].read_text(encoding="utf-8")
    assert grant.capability_token not in encoded
    assert "sensitive-output" not in encoded
    document = json.loads(encoded)
    stable_keys = [meter["idempotency_key"] for meter in document["meters"]]

    recovered = _FakeClient()
    second = ProviderUsageMeter(grant=grant, client=recovered, retry_interval_seconds=60)
    try:
        assert second.flush()
    finally:
        assert second.close()
    assert [call["idempotency_key"] for call in recovered.calls] == stable_keys
    assert list(grant.spool_directory.glob("*.pending.json")) == []


def test_partial_delivery_replays_same_idempotency_before_deleting_batch(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    client = _FakeClient(fail_once_on="llm.output_tokens")
    meter = ProviderUsageMeter(grant=grant, client=client, retry_interval_seconds=60)
    try:
        meter._observe(
            model="gemini-2.5",
            input_tokens=5,
            output_tokens=2,
            total_tokens=7,
        )
        assert meter.flush()
    finally:
        assert meter.close()

    input_calls = [call for call in client.calls if call["meter"] == "llm.input_tokens"]
    assert len(input_calls) == 2
    assert input_calls[0]["idempotency_key"] == input_calls[1]["idempotency_key"]
    assert input_calls[0]["provider_request_id"] == input_calls[1]["provider_request_id"]


def test_spool_rejects_symlink_and_non_allowlisted_metering_document(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    unavailable = _FakeClient(fail=True)
    first = ProviderUsageMeter(grant=grant, client=unavailable, retry_interval_seconds=60)
    first._observe(model="gpt-5", input_tokens=3, output_tokens=0, total_tokens=3)
    assert not first.flush(0.01)
    assert not first.close(0.01)

    pending = next(grant.spool_directory.glob("*.pending.json"))
    document = json.loads(pending.read_text(encoding="utf-8"))
    document["attributes"]["prompt"] = "must-not-dispatch"
    pending.write_text(json.dumps(document), encoding="utf-8")
    pending.chmod(0o600)

    outside = tmp_path / "outside.pending.json"
    outside.write_text(json.dumps(document), encoding="utf-8")
    linked = grant.spool_directory / "linked.pending.json"
    linked.symlink_to(outside)

    recovered = _FakeClient()
    second = ProviderUsageMeter(grant=grant, client=recovered, retry_interval_seconds=60)
    try:
        assert second.flush()
    finally:
        assert second.close()
    assert recovered.calls == []
    assert outside.exists()
    assert len(list(grant.spool_directory.glob("*.rejected.json"))) == 2


def test_one_time_envelope_is_private_bound_and_unlinked(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    directory = (tmp_path / "envelopes").absolute()
    official_runner = "runner_official_binding"
    path = write_metering_envelope(directory, grant=grant, official_runner_id=official_runner)

    assert path.stat().st_mode & 0o777 == 0o600
    loaded = consume_metering_envelope(path, official_runner_id=official_runner)

    assert loaded == grant
    assert not path.exists()
    with pytest.raises(ManagedMeteringError) as replay:
        consume_metering_envelope(path, official_runner_id=official_runner)
    assert replay.value.code == "managed_metering_envelope_missing"


def test_envelope_rejects_symlink_duplicate_unknown_and_wrong_runner(tmp_path: Path) -> None:
    grant = _grant(tmp_path)
    directory = (tmp_path / "envelopes").absolute()
    official_runner = "runner_official_binding"
    path = write_metering_envelope(directory, grant=grant, official_runner_id=official_runner)
    symlink = directory / "symlink.json"
    symlink.symlink_to(path)
    with pytest.raises(ManagedMeteringError) as linked:
        consume_metering_envelope(symlink, official_runner_id=official_runner)
    assert linked.value.code == "managed_metering_envelope_invalid"

    with pytest.raises(ManagedMeteringError) as mismatch:
        consume_metering_envelope(path, official_runner_id="runner_wrong")
    assert mismatch.value.code == "managed_metering_envelope_invalid"
    assert not path.exists()

    unknown = write_metering_envelope(directory, grant=grant, official_runner_id=official_runner)
    payload = json.loads(unknown.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    unknown.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(unknown, 0o600)
    with pytest.raises(ManagedMeteringError) as extra:
        consume_metering_envelope(unknown, official_runner_id=official_runner)
    assert extra.value.code == "managed_metering_envelope_invalid"

    duplicate = directory / "duplicate.json"
    duplicate.write_text('{"version":1,"version":1}', encoding="utf-8")
    duplicate.chmod(0o600)
    with pytest.raises(ManagedMeteringError) as repeated:
        consume_metering_envelope(duplicate, official_runner_id=official_runner)
    assert repeated.value.code == "managed_metering_envelope_invalid"


def test_staged_authority_is_one_time_and_managed_host_injects_only_envelope_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    grant = _grant(tmp_path)
    authority = StagedManagedRunnerLaunchAuthority()
    authority.stage(grant)
    official_runner = "runner_official_binding"
    claimed = authority.claim_metering_grant(
        session_id=str(grant.session_id), official_runner_id=official_runner
    )
    assert claimed == grant
    with pytest.raises(ManagedMeteringError) as replay:
        authority.claim_metering_grant(
            session_id=str(grant.session_id), official_runner_id=official_runner
        )
    assert replay.value.code == "managed_metering_grant_missing"

    captured: dict[str, str] = {}

    class _Process:
        pid = 123

    def fake_spawn(
        self: HostProcess, env: dict[str, str], session_slug: str, workspace: Path
    ) -> tuple[_Process, Path]:
        del self, session_slug, workspace
        captured.update(env)
        return _Process(), tmp_path / "runner.log"

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", fake_spawn)
    host = ManagedHostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="managed"),
        "https://control-plane.invalid",
        launch_authority=authority,
        envelope_directory=(tmp_path / "host-envelopes").absolute(),
    )
    host._pending_metering[official_runner] = grant
    host._spawn_runner_proc(
        {RUNNER_ID_ENV_VAR: official_runner},
        "session-",
        tmp_path,
    )

    assert grant.capability_token not in str(captured)
    envelope_path = Path(captured[MANAGED_METERING_ENVELOPE_ENV_VAR])
    loaded = consume_metering_envelope(envelope_path, official_runner_id=official_runner)
    assert loaded == grant


def test_managed_host_claims_staged_grant_on_official_launch_frame(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    grant = _grant(tmp_path)
    authority = StagedManagedRunnerLaunchAuthority()
    authority.stage(grant)
    captured: dict[str, str] = {}

    class _Process:
        pid = 456
        returncode = None

        def poll(self) -> None:
            return None

    def fake_spawn(
        self: HostProcess, env: dict[str, str], session_slug: str, workspace: Path
    ) -> tuple[_Process, Path]:
        del self, session_slug, workspace
        captured.update(env)
        return _Process(), tmp_path / "runner.log"

    monkeypatch.setattr(HostProcess, "_spawn_runner_proc", fake_spawn)
    host = ManagedHostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="managed"),
        "https://control-plane.invalid",
        launch_authority=authority,
        envelope_directory=(tmp_path / "host-envelopes").absolute(),
    )
    binding_token = "scheduler-bound-official-runner-token"

    async def launch() -> object:
        result = await host._handle_launch(
            HostLaunchRunnerFrame(
                request_id="launch-1",
                binding_token=binding_token,
                workspace=str(tmp_path),
                session_id=str(grant.session_id),
            )
        )
        try:
            assert result.status == "launched"
            assert result.runner_id == token_bound_runner_id(binding_token)
            assert result.runner_id is not None
            envelope_path = Path(captured[MANAGED_METERING_ENVELOPE_ENV_VAR])
            assert (
                consume_metering_envelope(envelope_path, official_runner_id=result.runner_id)
                == grant
            )
            return result
        finally:
            for watcher in tuple(host._watcher_tasks):
                watcher.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watcher

    _run_async(launch())


def test_managed_entry_fails_closed_without_one_time_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(MANAGED_METERING_ENVELOPE_ENV_VAR, raising=False)
    monkeypatch.setenv(RUNNER_ID_ENV_VAR, "runner_missing_envelope")
    with pytest.raises(ManagedMeteringError) as error:
        managed_entry_main()
    assert error.value.code == "managed_metering_envelope_missing"


def test_managed_entry_fails_closed_with_undelivered_usage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    grant = _grant(tmp_path)
    client = _FakeClient()

    class _UndrainedMeter:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs == {"grant": grant, "client": client}

        def close(self) -> bool:
            return False

    monkeypatch.setenv(MANAGED_METERING_ENVELOPE_ENV_VAR, str(tmp_path / "envelope"))
    monkeypatch.setenv(RUNNER_ID_ENV_VAR, "runner_undrained")
    monkeypatch.setattr(managed_entry_module, "consume_metering_envelope", lambda *_a, **_k: grant)
    monkeypatch.setattr(managed_entry_module, "build_metering_client", lambda _grant: client)
    monkeypatch.setattr(managed_entry_module, "ProviderUsageMeter", _UndrainedMeter)
    monkeypatch.setattr(managed_entry_module, "official_runner_main", lambda: None)

    with pytest.raises(ManagedMeteringError) as error:
        managed_entry_main()
    assert error.value.code == "managed_metering_delivery_incomplete"


def test_managed_host_returns_failed_frame_when_envelope_cannot_be_published(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    grant = _grant(tmp_path)
    authority = StagedManagedRunnerLaunchAuthority()
    authority.stage(grant)

    def fail_envelope(*_args: object, **_kwargs: object) -> Path:
        raise ManagedMeteringError(
            "managed_metering_directory_invalid", "managed metering directory is unavailable"
        )

    monkeypatch.setattr(process_policy_module, "write_metering_envelope", fail_envelope)
    host = ManagedHostProcess(
        HostIdentity(host_id="0123456789abcdef0123456789abcdef", name="managed"),
        "https://control-plane.invalid",
        launch_authority=authority,
        envelope_directory=(tmp_path / "host-envelopes").absolute(),
    )
    result = _run_async(
        host._handle_launch(
            HostLaunchRunnerFrame(
                request_id="launch-envelope-failure",
                binding_token="scheduler-bound-envelope-failure",
                workspace=str(tmp_path),
                session_id=str(grant.session_id),
            )
        )
    )
    assert result.status == "failed"
    assert result.error == (
        "failed to spawn runner: managed Runner metering envelope is unavailable"
    )
    assert grant.capability_token not in str(result)
