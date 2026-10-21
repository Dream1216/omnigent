from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane import ContextSnapshotError, ContextSnapshotService
from saas.control_plane.api_credential_models import ServiceAccountRecord
from saas.control_plane.api_credentials import ApiCredentialError, ApiCredentialService
from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.outbox_delivery_models import RevocationReplicaAppliedRecord
from saas.control_plane.revocation import (
    REVOCATION_ROUTES,
    AuthorizationInvalidations,
    ReplicaRevocationConsumer,
    RevocationCacheUnavailable,
    _hash,
)
from tests.saas.test_api_credentials import _NOW, _PEPPER, _create_account, _fixture, _issue
from tests.saas.test_context_snapshot import _Clock, _facts, _service


def _source(factory, *, kind, entity, floor, deleted=False):
    event_id = uuid4()
    body = {"kind": kind, "entity_id": str(entity), "version_floor": floor}
    if deleted:
        body["deleted"] = True
    aggregate, event = REVOCATION_ROUTES[kind]
    with factory.begin() as db:
        db.add(
            ControlPlaneOutboxEvent(
                id=event_id,
                tenant_id=None,
                aggregate_type=aggregate,
                aggregate_key=str(entity),
                event_type=event,
                payload=body,
                request_hash=_hash(body),
                idempotency_key=f"typed-test:{event_id}",
            )
        )
    return event_id


def test_actual_two_replica_snapshot_invalidation_and_new_boot_needs_new_cache_ack():
    factory, ids = _fixture()
    clock = _Clock(datetime(2026, 8, 4, 8, tzinfo=UTC))
    original_session, runtime = _facts(clock)
    session = replace(original_session, user_id=ids["owner"], security_version=1)
    runtime = replace(runtime, actor_id=ids["owner"], user_security_version=1)
    monotonic = [100.0]
    caches = [AuthorizationInvalidations(clock=lambda: monotonic[0]) for _ in range(2)]
    for cache in caches:
        cache.begin_listener_epoch()
    monotonic[0] += 65.0
    services = [ContextSnapshotService(_service(clock)._policy, invalidations=c) for c in caches]
    issued = services[0].issue(
        auth_token="actual-snapshot-token", session=session, runtime_context=runtime
    )
    with pytest.raises(ContextSnapshotError, match="not current"):
        services[1].require_invalidation_ready()
    with factory.begin() as db:
        db.get(GlobalUser, ids["owner"]).security_version = 2
    event_id = _source(factory, kind="user", entity=ids["owner"], floor=2)
    consumers = [
        ReplicaRevocationConsumer(factory, c, product_revision="a" * 40, replica_uid=uuid4())
        for c in caches
    ]
    assert consumers[0].consume(event_id)
    assert (
        services[1]
        .verify(token=issued.token, auth_token="actual-snapshot-token")
        .session.security_version
        == 1
    )
    assert consumers[1].consume(event_id)
    for cache, service in zip(caches, services, strict=True):
        cache.caught_up()
        service.require_invalidation_ready()
        with pytest.raises(ContextSnapshotError) as denied:
            service.verify(token=issued.token, auth_token="actual-snapshot-token")
        assert denied.value.code == "snapshot_security_version_stale"
    assert not consumers[0].consume(event_id)
    replacement = ReplicaRevocationConsumer(
        factory,
        AuthorizationInvalidations(),
        product_revision="a" * 40,
        replica_uid=consumers[0].replica_uid,
    )
    assert replacement.process_boot_uid != consumers[0].process_boot_uid
    assert replacement.consume(event_id)  # Old Pod UID ACK is not a new cache ACK.
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord)) == 3
        )
        source = db.get(ControlPlaneOutboxEvent, event_id)
        assert source.published_at is None and source.attempt_count == 0


def test_actual_api_key_and_account_floor_invalidation_preserves_live_db_revalidation():
    factory, ids = _fixture()
    cache = AuthorizationInvalidations()
    native = ApiCredentialService(factory, credential_pepper=_PEPPER, invalidations=cache)
    account = _create_account(native, ids)
    issued = _issue(native, ids, account.id, networks=())
    native.authenticate(issued.token, source_ip="127.0.0.1", now=_NOW)
    cache.apply("service_account", account.id, 2)
    with pytest.raises(ApiCredentialError):
        native.authenticate(issued.token, source_ip="127.0.0.1", now=_NOW)
    cache = AuthorizationInvalidations()
    native = ApiCredentialService(factory, credential_pepper=_PEPPER, invalidations=cache)
    cache.apply("api_credential", issued.credential_id, 1)
    with pytest.raises(ApiCredentialError):
        native.authenticate(issued.token, source_ip="127.0.0.1", now=_NOW)
    # The absence of a hint never authorizes without the original database checks.
    with factory.begin() as db:
        db.get(ServiceAccountRecord, account.id).status = "suspended"
    unhinted = ApiCredentialService(
        factory, credential_pepper=_PEPPER, invalidations=AuthorizationInvalidations()
    )
    with pytest.raises(ApiCredentialError):
        unhinted.authenticate(issued.token, source_ip="127.0.0.1", now=_NOW)


def test_forged_or_uncommitted_revocation_never_becomes_ready_or_ack():
    factory, ids = _fixture()
    cache = AuthorizationInvalidations()
    cache.caught_up()
    consumer = ReplicaRevocationConsumer(
        factory, cache, product_revision="a" * 40, replica_uid=uuid4()
    )
    event_id = _source(factory, kind="user", entity=ids["owner"], floor=2)
    with pytest.raises(OutboxPublishError) as denied:
        consumer.consume(event_id)
    assert denied.value.code == "revocation_version_uncommitted" and not cache.ready
    assert cache.minimum("user", ids["owner"]) == 0
    with factory.begin() as db:
        source = db.get(ControlPlaneOutboxEvent, event_id)
        source.request_hash = "0" * 64
    with pytest.raises(OutboxPublishError) as denied:
        consumer.consume(event_id)
    assert denied.value.code == "revocation_source_mismatch"
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(RevocationReplicaAppliedRecord)) == 0
        )


def test_bounded_cache_overflow_disconnect_and_expiry_do_not_enable_fallback():
    clock = [100.0]
    cache = AuthorizationInvalidations(maximum_records=1, clock=lambda: clock[0])
    cache.begin_listener_epoch()
    clock[0] += 65.0
    first, second = uuid4(), uuid4()
    cache.apply("user", first, 4)
    assert cache.apply("user", first, 2) == 4
    cache.caught_up()
    with pytest.raises(RevocationCacheUnavailable, match="capacity"):
        cache.apply("user", second, 1)
    assert not cache.ready
    clock[0] = 286.0
    assert cache.minimum("user", first) == 0
    assert not cache.ready  # Expired local hints cannot assert reconnect/catch-up.
    assert cache.apply("user", second, 1) == 1


def test_new_listener_epoch_requires_original_snapshot_expiry_not_only_typed_catchup():
    monotonic = [100.0]
    cache = AuthorizationInvalidations(clock=lambda: monotonic[0])
    cache.caught_up()
    assert not cache.ready  # An arbitrary caught-up flag cannot bypass a native epoch.
    cache.begin_listener_epoch()
    cache.caught_up()
    for elapsed in (0.0, 59.999, 60.0, 64.999):
        monotonic[0] = 100.0 + elapsed
        assert not cache.ready
    monotonic[0] = 165.0
    assert cache.ready
    cache.unavailable()
    assert not cache.ready
    cache.begin_listener_epoch()
    cache.caught_up()
    assert not cache.ready  # Reconnect/boot never inherits the earlier elapsed interval.
    monotonic[0] = 229.999
    assert not cache.ready
    monotonic[0] = 230.0
    assert cache.ready


def test_legacy_no_typed_event_snapshot_expires_before_new_epoch_allows_fallback():
    monotonic = [100.0]
    reader_clock = _Clock(datetime(2026, 8, 4, 8, tzinfo=UTC))
    issuer_clock = _Clock(reader_clock.now + timedelta(seconds=5))
    session, runtime = _facts(issuer_clock)
    issued = _service(issuer_clock).issue(
        auth_token="legacy-P15-snapshot", session=session, runtime_context=runtime
    )
    cache = AuthorizationInvalidations(clock=lambda: monotonic[0])
    service = ContextSnapshotService(_service(reader_clock)._policy, invalidations=cache)
    cache.begin_listener_epoch()
    cache.caught_up()  # No typed event exists for a P15 writer's change.
    for elapsed in (0, 60, 64.999):
        monotonic[0] = 100.0 + elapsed
        reader_clock.now = issuer_clock.now - timedelta(seconds=5) + timedelta(seconds=elapsed)
        assert service.verify(token=issued.token, auth_token="legacy-P15-snapshot")
        with pytest.raises(ContextSnapshotError, match="not current"):
            service.require_invalidation_ready()
    monotonic[0] = 165.0
    reader_clock.now = issuer_clock.now + timedelta(seconds=60)
    service.require_invalidation_ready()
    with pytest.raises(ContextSnapshotError) as expired:
        service.verify(token=issued.token, auth_token="legacy-P15-snapshot")
    assert expired.value.code == "context_snapshot_expired"
    fresh_session, fresh_runtime = _facts(reader_clock)
    fresh = service.issue(
        auth_token="new-live-DB-validated", session=fresh_session, runtime_context=fresh_runtime
    )
    assert service.verify(token=fresh.token, auth_token="new-live-DB-validated")
    with pytest.raises(ContextSnapshotError) as wrong_binding:
        service.verify(token=fresh.token, auth_token="wrong-session")
    assert wrong_binding.value.code == "snapshot_token_binding_invalid"
