from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from saas.production.interactive_controller_adapter import load_interactive_metering_credentials
from saas.production.runner_control import RunnerControlError
from tests.saas.test_billing_metering_transport import _certificate_fixture


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_recovery", [False, True])
async def test_recovery_allows_host_ingress_without_claiming_before_exact_stop(
    credentials, tmp_path, monkeypatch, invalid_recovery
):
    from saas.production import interactive_controller_adapter as module

    runner_id, control, _, source, _ = credentials
    source.update(
        OMNIGENT_SAAS_INTERACTIVE_METERING_URL="https://billing-metering.internal",
        OMNIGENT_SAAS_INTERACTIVE_RECOVERY_DIRECTORY=str(tmp_path / "private-journal"),
    )
    host_connected, recovered, claimed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    recovery_attempted = asyncio.Event()

    class Executor:
        def __init__(self, **kwargs):
            pass

        async def reconcile_physical_gc(self, *, limit):
            recovery_attempted.set()
            if invalid_recovery:
                raise RunnerControlError("isolated_bad_recovery_certificate", "Unavailable")
            if host_connected.is_set():
                recovered.set()
            return int(recovered.is_set())

        def assert_claimable(self):
            if not recovered.is_set():
                raise RunnerControlError("interactive_controller_recovery_pending", "Unavailable")

        async def shutdown(self):
            pass

    class Agent:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, stop):
            assert recovered.is_set()
            claimed.set()
            await stop.wait()

    monkeypatch.setattr(module, "ProductionInteractiveExecutor", Executor)
    monkeypatch.setattr(module, "ProductionRunnerAgent", Agent)
    monkeypatch.setattr(
        module,
        "OfficialInteractiveDriver",
        lambda **_: SimpleNamespace(observe_runtime_status=lambda *args: None),
    )
    adapter = object.__new__(module.ProductionInteractiveControllerAdapter)
    adapter._source, adapter._bound, adapter._task = source, False, None
    adapter._release = SimpleNamespace(
        public_origin="https://next.test", adapter_contract_version="0.2.0"
    )
    adapter._config = SimpleNamespace(
        runner_id=runner_id,
        client_certificate_path=control.certificate,
        connection_generation=1,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
        physical_gc_limit=32,
        poll_interval_seconds=0.1,
        heartbeat_interval_seconds=5,
        shutdown_timeout_seconds=2,
        physical_gc_interval_seconds=30,
    )
    adapter._client, adapter._sessions = object(), object()
    adapter._engine = SimpleNamespace(dispose=lambda: None)
    runtime = SimpleNamespace(create_authority=lambda **_: object())
    app = FastAPI()
    app.state.production_interactive_conversation_store = SimpleNamespace()

    @app.post("/isolated-host-ready")
    async def ready():
        host_connected.set()
        return {"connected": True}

    adapter._bind_runtime(app=app, runtime=runtime, official=object())
    async with app.router.lifespan_context(app):
        assert not adapter._bound and not claimed.is_set()
        await asyncio.wait_for(recovery_attempted.wait(), 2)
        assert not adapter._bound and not claimed.is_set()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://next.test"
        ) as client:
            assert (await client.post("/isolated-host-ready")).status_code == 200
        if invalid_recovery:
            with pytest.raises(RunnerControlError, match="Unavailable"):
                await asyncio.wait_for(asyncio.shield(adapter._task), 2)
            assert not adapter._bound and not claimed.is_set()
        else:
            await asyncio.wait_for(claimed.wait(), 2)
            assert recovered.is_set() and adapter._bound


@pytest.fixture
def credentials(tmp_path):
    runner_id, other_runner_id = uuid4(), uuid4()
    root = tmp_path / "metering"
    root.mkdir()
    leaves = _certificate_fixture(root, (runner_id, other_runner_id))
    control_root = tmp_path / "control"
    control_root.mkdir()
    control = _certificate_fixture(control_root, (runner_id,))["runner-0"]
    meter = leaves["runner-0"]
    meter.private_key.chmod(0o600)
    source = {
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CA_FILE": str(meter.ca),
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE": str(meter.certificate),
        "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE": str(meter.private_key),
    }
    return runner_id, control, meter, source, leaves["runner-1"]


def test_metering_uses_a_separate_identity_bound_leaf_and_key(credentials):
    runner_id, control, meter, source, _ = credentials
    selected = load_interactive_metering_credentials(
        source, runner_id=runner_id, control_certificate=control.certificate
    )
    assert (selected.ca, selected.certificate, selected.key) == (
        meter.ca,
        meter.certificate,
        meter.private_key,
    )
    assert selected.certificate.read_bytes() != control.certificate.read_bytes()


@pytest.mark.parametrize("missing", ["CA", "CLIENT_CERTIFICATE", "CLIENT_KEY"])
def test_control_credentials_are_not_an_implicit_metering_fallback(credentials, missing):
    runner_id, control, _, source, _ = credentials
    source.pop(f"OMNIGENT_SAAS_INTERACTIVE_METERING_{missing}_FILE")
    with pytest.raises(RunnerControlError, match="Interactive execution is unavailable"):
        load_interactive_metering_credentials(
            source, runner_id=runner_id, control_certificate=control.certificate
        )


@pytest.mark.parametrize(
    "tamper", ["same_leaf", "same_leaf_reencoded", "foreign", "key", "mode", "symlink"]
)
def test_metering_rejects_cross_purpose_or_unsafe_credentials(credentials, tamper, tmp_path):
    runner_id, control, meter, source, foreign = credentials
    certificate = "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE"
    if tamper == "same_leaf":
        source[certificate] = str(control.certificate)
    elif tamper == "same_leaf_reencoded":
        duplicate = tmp_path / "duplicate.pem"
        duplicate.write_bytes(b"\n" + control.certificate.read_bytes() + b"\n")
        source[certificate] = str(duplicate)
    elif tamper == "foreign":
        source[certificate] = str(foreign.certificate)
    elif tamper == "key":
        foreign.private_key.chmod(0o600)
        source["OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE"] = str(foreign.private_key)
    elif tamper == "mode":
        meter.private_key.chmod(0o644)
    else:
        link = tmp_path / "certificate-link.pem"
        link.symlink_to(meter.certificate)
        source[certificate] = str(link)
    with pytest.raises(RunnerControlError) as error:
        load_interactive_metering_credentials(
            source, runner_id=runner_id, control_certificate=control.certificate
        )
    assert error.value.code == "interactive_controller_unavailable"
    assert str(meter.private_key) not in str(error.value)


@pytest.mark.asyncio
async def test_adapter_binds_metering_paths_to_grant_and_recovery(
    credentials, tmp_path, monkeypatch
):
    from saas.production import interactive_controller_adapter as module

    runner_id, control, meter, source, _ = credentials
    source.update(
        OMNIGENT_SAAS_INTERACTIVE_METERING_URL="https://billing-metering.internal",
        OMNIGENT_SAAS_INTERACTIVE_RECOVERY_DIRECTORY=str(tmp_path / "private-journal"),
    )
    captured, recovered, pulses = {}, [], []

    def executor(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace()

    async def heartbeat():
        pulses.append("heartbeat")

    monkeypatch.setattr(module, "ProductionInteractiveExecutor", executor)
    monkeypatch.setattr(
        module,
        "OfficialInteractiveDriver",
        lambda **_: SimpleNamespace(observe_runtime_status=lambda *args: None),
    )
    adapter = object.__new__(module.ProductionInteractiveControllerAdapter)
    adapter._source = source
    adapter._release = SimpleNamespace(
        public_origin="https://next.test", adapter_contract_version="0.2.0"
    )
    adapter._config = SimpleNamespace(
        runner_id=runner_id,
        client_certificate_path=control.certificate,
        connection_generation=1,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
    )
    adapter._client = SimpleNamespace(heartbeat_runner=heartbeat)
    adapter._sessions = object()
    authority = SimpleNamespace(verify_recovery=lambda record: recovered.append(record))
    runtime = SimpleNamespace(create_authority=lambda **_: authority)
    app = FastAPI()
    app.state.production_interactive_conversation_store = SimpleNamespace()
    adapter._bind_runtime(app=app, runtime=runtime, official=object())
    try:
        authorized = SimpleNamespace(
            runtime=SimpleNamespace(
                tenant_id=uuid4(), space_id=uuid4(), runtime_partition_id=uuid4()
            ),
            session_id="a" * 32,
        )
        lease = SimpleNamespace(
            run_id=uuid4(),
            capability_token="synthetic-capability-only",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=45),
        )
        grant = captured["grant_for_run"](authorized, lease)
        assert (
            grant.ca_certificate_path,
            grant.client_certificate_path,
            grant.client_key_path,
        ) == (meter.ca, meter.certificate, meter.private_key)
        record = SimpleNamespace(run_id=lease.run_id, grant=grant)
        await captured["verify_recovery"](record)
        assert recovered == [record] and pulses == ["heartbeat"]
        record.grant = replace(grant, client_certificate_path=control.certificate)
        with pytest.raises(RunnerControlError):
            await captured["verify_recovery"](record)
        assert len(recovered) == len(pulses) == 1
    finally:
        adapter._journal.close()


def test_actual_adapter_constructs_the_runtime_session_factory_contract(
    credentials, tmp_path, monkeypatch
):
    from omnigent import _build_info
    from saas.production.interactive_controller_adapter import (
        ProductionInteractiveControllerAdapter,
    )

    runner_id, control, _, _, _ = credentials
    control.private_key.chmod(0o600)

    def secret(name, value):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o400)
        return str(path)

    for name, value in {
        "OMNIGENT_SAAS_RUNNER_READINESS_HOST": "readiness.svc",
        "OMNIGENT_SAAS_RUNNER_READINESS_SERVER_NAME": "readiness.svc",
        "OMNIGENT_SAAS_RUNNER_READINESS_PORT": "9445",
        "OMNIGENT_SAAS_RUNNER_READINESS_CA_CERTIFICATE_FILE": str(control.ca),
    }.items():
        monkeypatch.setenv(name, value)
    source = {
        "OMNIGENT_SAAS_RUNNER_ID": str(runner_id),
        "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION": "1",
        "OMNIGENT_SAAS_RUNNER_CONNECTION_TOKEN_FILE": secret("connection", "x" * 48),
        "OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE": secret(
            "database-url",
            f"postgresql+psycopg://runner_{runner_id.hex}_g1:isolated@postgresql.lab/fleet"
            "?sslmode=verify-full&sslrootcert=/runtime/postgresql-ca.crt",
        ),
        "OMNIGENT_SAAS_RUNNER_CONTROL_HOST": "localhost",
        "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME": "localhost",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE": str(control.ca),
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_CERTIFICATE_FILE": str(control.certificate),
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_KEY_FILE": str(control.private_key),
    }
    release = SimpleNamespace(
        product_revision=_build_info.COMMIT_SHA, image_digest="sha256:" + "a" * 64
    )
    adapter = ProductionInteractiveControllerAdapter(config=release, source=source)
    try:
        assert adapter._sessions.kw["bind"] is adapter._engine
        assert adapter._sessions.kw["expire_on_commit"] is False
        with adapter._sessions() as database:
            assert database.get_bind() is adapter._engine
    finally:
        adapter.close()
