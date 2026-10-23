from __future__ import annotations

import json

import pytest

import saas.runner_adapter.metering as module
from saas.control_plane.model_gateway_metering import gateway_call_reservation_id
from saas.runner_adapter.metering import ProviderUsageMeter
from tests.saas.test_provider_usage_metering import _grant


class ReferenceClient:
    def __init__(self, *, available=False, check=True):
        self.available, self.check = available, check
        self.calls = []

    def gateway_usage(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["action"] == "check":
            if not self.check:
                raise RuntimeError("isolated preflight failure")
            return {"status": "ready"}
        if not self.available:
            raise RuntimeError("isolated delivery outage")
        return {"status": "settled"}

    def close(self):
        pass


def test_gateway_reference_survives_worker_recreation_without_observer_or_secrets(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        module,
        "add_required_observer",
        lambda _callback: pytest.fail("Gateway installed legacy Observer"),
    )
    grant = _grant(tmp_path)
    first = ReferenceClient()
    meter = ProviderUsageMeter(
        grant=grant, client=first, gateway_managed=True, retry_interval_seconds=60
    )
    call = meter.prepare_gateway_call()
    path = grant.spool_directory / f"{call}.pending.json"
    body = path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    assert (
        grant.capability_token not in body and "quantity" not in body and "credential" not in body
    )
    assert json.loads(body)["reservation_id"] == str(
        gateway_call_reservation_id(grant.run_id, call)
    )
    assert not meter.close(timeout_seconds=0)
    second = ReferenceClient(available=True)
    recovered = ProviderUsageMeter(grant=grant, client=second, gateway_managed=True)
    try:
        assert recovered.flush(timeout_seconds=1)
        assert not path.exists()
        assert all(
            row["run_id"] == grant.run_id and row["capability_token"] == grant.capability_token
            for row in second.calls
        )
    finally:
        recovered.close(timeout_seconds=0)


def test_failed_preflight_never_creates_a_pending_call(tmp_path):
    grant = _grant(tmp_path)
    meter = ProviderUsageMeter(
        grant=grant, client=ReferenceClient(check=False), gateway_managed=True
    )
    try:
        with pytest.raises(RuntimeError, match="preflight"):
            meter.prepare_gateway_call()
        assert not list(grant.spool_directory.glob("*.pending.json"))
    finally:
        meter.close(timeout_seconds=0)


def test_gateway_reference_rejects_caller_selected_usage_and_retains_rejected_file(tmp_path):
    grant = _grant(tmp_path)
    meter = ProviderUsageMeter(grant=grant, client=ReferenceClient(), gateway_managed=True)
    call = meter.prepare_gateway_call()
    path = grant.spool_directory / f"{call}.pending.json"
    try:
        document = json.loads(path.read_text())
        document["quantity"] = 999
        path.write_text(json.dumps(document))
        assert meter.flush(timeout_seconds=1)
        assert list(grant.spool_directory.glob("*.rejected.json"))
    finally:
        meter.close(timeout_seconds=0)
