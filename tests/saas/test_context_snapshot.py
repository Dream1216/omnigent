from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from saas.compatibility import RuntimeContext
from saas.control_plane import (
    ContextSnapshotError,
    ContextSnapshotPolicy,
    ContextSnapshotService,
    ValidatedAuthSession,
)


@dataclass
class _Clock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now


def _facts(clock: _Clock) -> tuple[ValidatedAuthSession, RuntimeContext]:
    user_id = uuid4()
    session = ValidatedAuthSession(
        session_id=uuid4(),
        user_id=user_id,
        security_version=7,
        authn_method="password",
        authenticated_at=clock.now - timedelta(minutes=1),
        expires_at=clock.now + timedelta(hours=1),
    )
    runtime = RuntimeContext(
        actor_id=user_id,
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=None,
        user_security_version=7,
        tenant_membership_version=11,
        space_membership_version=13,
        runtime_partition_id=uuid4(),
        placement_id=uuid4(),
        placement_generation=17,
        binding_generation=19,
        data_region="cn-east-1",
        physical_workspace_id=41,
        runtime_user_key="opaque-runtime-alias",
        runtime_type="omnigent",
        source_revision="15dd7becff2bda8ee2b9afd5d16abc4feafb9552",
        adapter_contract_version="0.2.0",
        trace_id="snapshot-unit-trace",
    )
    return session, runtime


def _service(clock: _Clock, *, active_key_id: str = "v2") -> ContextSnapshotService:
    return ContextSnapshotService(
        ContextSnapshotPolicy(
            active_key_id=active_key_id,
            keys={
                "v1": b"context-snapshot-unit-key-material-v1",
                "v2": b"context-snapshot-unit-key-material-v2",
            },
            issuer="omnigent-saas-test",
            audience="omnigent-api-test",
            ttl=timedelta(seconds=60),
            clock=clock,
        )
    )


def test_snapshot_is_opaque_replica_verifiable_and_key_rotatable() -> None:
    clock = _Clock(datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc))
    session, runtime = _facts(clock)
    old_replica = _service(clock, active_key_id="v1")
    issued = old_replica.issue(
        auth_token="opaque-session-token",
        session=session,
        runtime_context=runtime,
    )

    assert str(runtime.tenant_id) not in issued.token
    assert str(runtime.placement_id) not in issued.token
    assert "opaque-runtime-alias" not in issued.token
    assert ".41." not in issued.token

    rotated_replica = _service(clock, active_key_id="v2")
    verified = rotated_replica.verify(
        token=issued.token,
        auth_token="opaque-session-token",
    )
    assert verified.session == session
    assert verified.runtime_context == runtime
    assert verified.expires_at - verified.issued_at == timedelta(seconds=60)


def test_snapshot_rejects_tamper_other_session_and_expiry() -> None:
    clock = _Clock(datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc))
    session, runtime = _facts(clock)
    service = _service(clock)
    issued = service.issue(
        auth_token="opaque-session-token",
        session=session,
        runtime_context=runtime,
    )

    with pytest.raises(ContextSnapshotError) as token_error:
        service.verify(token=issued.token, auth_token="another-session-token")
    assert token_error.value.code == "snapshot_token_binding_invalid"

    header, payload, signature = issued.token.split(".")
    replacement = "A" if payload[-1] != "A" else "B"
    tampered = f"{header}.{payload[:-1]}{replacement}.{signature}"
    with pytest.raises(ContextSnapshotError) as tamper_error:
        service.verify(token=tampered, auth_token="opaque-session-token")
    assert tamper_error.value.code in {
        "snapshot_signature_invalid",
        "context_snapshot_invalid",
    }

    clock.now += timedelta(seconds=61)
    with pytest.raises(ContextSnapshotError) as expiry_error:
        service.verify(token=issued.token, auth_token="opaque-session-token")
    assert expiry_error.value.code == "context_snapshot_expired"


def test_snapshot_rejects_noncanonical_base64url() -> None:
    with pytest.raises(ValueError, match="not canonical"):
        ContextSnapshotService._unb64("AB")


def test_snapshot_policy_refuses_lifetime_over_sixty_seconds() -> None:
    with pytest.raises(ValueError, match="between 1 and 60 seconds"):
        ContextSnapshotPolicy(
            active_key_id="v1",
            keys={"v1": b"context-snapshot-unit-key-material-v1"},
            issuer="issuer",
            audience="audience",
            ttl=timedelta(seconds=61),
        )
