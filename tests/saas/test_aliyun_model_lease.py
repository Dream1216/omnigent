from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from saas.production.aliyun_model_lease import HostModelLeaseAuthority, HostModelLeaseError
from tests.saas.test_tenant_sandbox import _runtime

_HOST = "host-model-test"
_TOKEN = "t" * 43


def _issue(authority, runtime=None, **kwargs):
    return authority.issue(
        host_id=_HOST,
        launch_token=_TOKEN,
        runtime=runtime or _runtime(),
        ttl_seconds=5400,
        now=1000,
        **kwargs,
    )


def test_lease_round_trip_survives_replica_restart_without_exporting_key():
    runtime = _runtime()
    authority = HostModelLeaseAuthority(b"s" * 32)
    token = _issue(authority, runtime)
    restarted = HostModelLeaseAuthority(b"s" * 32)
    lease = restarted.verify(token, host_id=_HOST, launch_token=_TOKEN, now=1001)
    assert lease.runtime == runtime
    assert lease.expires_at == 6400
    assert _TOKEN not in token
    assert b"s" * 32 not in token.encode()
    assert "ssssssss" not in repr(authority)


@pytest.mark.parametrize("change", ["host", "launch-token", "signer", "payload", "signature"])
def test_wrong_host_token_signer_and_tampering_fail_closed(change):
    authority = HostModelLeaseAuthority(b"s" * 32)
    token = _issue(authority)
    host, launch_token = _HOST, _TOKEN
    if change == "host":
        host = "another-host"
    elif change == "launch-token":
        launch_token = "x" * 43
    elif change == "signer":
        authority = HostModelLeaseAuthority(b"x" * 32)
    elif change == "payload":
        token = "X" + token[1:]
    else:
        payload, signature = token.split(".")
        token = payload + "." + ("x" if signature[0] != "x" else "y") + signature[1:]
    with pytest.raises(HostModelLeaseError):
        authority.verify(token, host_id=host, launch_token=launch_token, now=1001)


@pytest.mark.parametrize("now", [0, True, 969, 6400, 10000])
def test_expired_or_invalid_time_is_rejected(now):
    authority = HostModelLeaseAuthority(b"s" * 32)
    with pytest.raises(HostModelLeaseError):
        authority.verify(_issue(authority), host_id=_HOST, launch_token=_TOKEN, now=now)


@pytest.mark.parametrize("ttl", [0, True, -1, 59, 7201, 86400])
def test_lease_lifetime_cannot_exceed_qualified_host_window(ttl):
    authority = HostModelLeaseAuthority(b"s" * 32)
    with pytest.raises(ValueError, match="lifetime"):
        authority.issue(
            host_id=_HOST, launch_token=_TOKEN, runtime=_runtime(), ttl_seconds=ttl, now=1000
        )


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": UUID(int=0)},
        {"actor_id": UUID(int=0)},
        {"physical_workspace_id": True},
        {"physical_workspace_id": 0},
        {"placement_generation": 0},
        {"runtime_user_key": ""},
        {"source_revision": "bad\x00revision"},
    ],
)
def test_invalid_runtime_context_is_not_signed(change):
    authority = HostModelLeaseAuthority(b"s" * 32)
    with pytest.raises(ValueError):
        _issue(authority, replace(_runtime(), **change))


def test_project_identity_is_preserved_without_changing_lease_recipient():
    authority = HostModelLeaseAuthority(b"s" * 32)
    runtime = replace(_runtime(), project_id=uuid4())
    lease = authority.verify(
        _issue(authority, runtime), host_id=_HOST, launch_token=_TOKEN, now=1000
    )
    assert lease.runtime.project_id == runtime.project_id


@pytest.mark.parametrize(
    "raw",
    ["", "a.b.c", "x" * 16385, "not-a-token"],
    ids=["empty", "too-many-parts", "oversized", "unsigned"],
)
def test_malformed_lease_has_redacted_error(raw):
    with pytest.raises(HostModelLeaseError, match="invalid"):
        HostModelLeaseAuthority(b"s" * 32).verify(
            raw, host_id=_HOST, launch_token=_TOKEN, now=1000
        )
