from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError

from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.retained_model_audit import (
    _CONTRACTS,
    RetainedModelAuditPublisher,
    verify_retained_model_audit_functions,
)


def _row(contract, oid=42):
    return (
        oid,
        True,
        "f",
        "plpgsql",
        ["search_path=pg_catalog, pg_temp"],
        "boolean",
        contract.source_hash,
        "schema_owner",
        True,
        "v",
        "u",
        False,
        False,
    )


def _acls():
    return [
        ("schema_owner", "schema_owner", "EXECUTE", False),
        ("saas_dispatcher", "schema_owner", "EXECUTE", False),
    ]


def _result(row=None, acls=None, model_tables=(False, False, False, False)):
    result = MagicMock()
    result.one_or_none.return_value = row
    result.all.return_value = acls
    result.one.return_value = model_tables
    return result


def test_retained_schema_cannot_borrow_p0_absence_after_all_functions_are_removed():
    db = MagicMock()
    schema = _result()
    schema.one.return_value = (True, True, True, True)
    db.execute.side_effect = [*[_result() for _ in _CONTRACTS], schema]
    with pytest.raises(RuntimeError, match="function_set_incomplete"):
        verify_retained_model_audit_functions(db)


def test_p0_absence_and_complete_retained_function_set_are_distinct():
    db = MagicMock()
    db.execute.side_effect = [_result() for _ in range(len(_CONTRACTS) + 1)]
    assert verify_retained_model_audit_functions(db) == ()
    db.execute.side_effect = [
        *[
            result
            for i, contract in enumerate(_CONTRACTS)
            for result in (_result(_row(contract, 42 + i)), _result(acls=_acls()))
        ],
        _result(model_tables=(True, True, True, True)),
    ]
    assert verify_retained_model_audit_functions(db) == (42, 43, 44)


@pytest.mark.parametrize(
    "index,value",
    [
        (1, False),
        (2, "p"),
        (3, "sql"),
        (4, ["search_path=public"]),
        (5, "text"),
        (6, "0" * 64),
        (8, False),
        (9, "s"),
        (10, "s"),
        (11, True),
        (12, True),
    ],
)
def test_retained_function_source_owner_and_flags_cannot_be_borrowed(index, value):
    row = list(_row(_CONTRACTS[0]))
    row[index] = value
    db = MagicMock()
    db.execute.side_effect = [_result(tuple(row)), _result(acls=_acls())]
    with pytest.raises(RuntimeError, match="function_contract_rejected"):
        verify_retained_model_audit_functions(db)


@pytest.mark.parametrize(
    "acls",
    [
        [*_acls(), ("PUBLIC", "schema_owner", "EXECUTE", False)],
        [_acls()[0], ("saas_dispatcher", "other_grantor", "EXECUTE", False)],
        [_acls()[0], ("saas_dispatcher", "schema_owner", "EXECUTE", True)],
        _acls()[:1],
        [*_acls(), _acls()[1]],
    ],
)
def test_retained_function_acl_must_be_exact_and_not_delegable(acls):
    db = MagicMock()
    db.execute.side_effect = [_result(_row(_CONTRACTS[0])), _result(acls=acls)]
    with pytest.raises(RuntimeError, match="function_contract_rejected"):
        verify_retained_model_audit_functions(db)


def test_partial_retained_schema_cannot_start_a_dispatcher():
    db = MagicMock()
    db.execute.side_effect = [
        _result(_row(_CONTRACTS[0])),
        _result(acls=_acls()),
        _result(),
        _result(),
        _result(model_tables=(True, True, True, True)),
    ]
    with pytest.raises(RuntimeError, match="function_set_incomplete"):
        verify_retained_model_audit_functions(db)


def _publisher(contract):
    engine, fallback = MagicMock(), MagicMock(spec=["publish", "close"])
    engine.dialect.name = "postgresql"
    identity = str(uuid4())
    payload = {"event_type": contract.event, contract.reference: identity}
    if contract.reference == "reservation_id":
        payload.update(tenant_id=str(uuid4()), evidence_id=str(uuid4()), evidence_sha256="a" * 64)
    else:
        payload["schema_version"] = 1
    event = {
        "event_id": uuid4(),
        "event_type": contract.event,
        "aggregate_type": contract.aggregate,
        "aggregate_key": identity,
        "payload": payload,
    }
    return RetainedModelAuditPublisher(engine, fallback), engine, fallback, event


@pytest.mark.parametrize("contract", _CONTRACTS)
@pytest.mark.parametrize("replayed", [False, True])
def test_retained_audit_is_committed_before_ack_without_external_redelivery(contract, replayed):
    publisher, engine, fallback, event = _publisher(contract)
    db = engine.begin.return_value.__enter__.return_value
    db.scalar.return_value = not replayed
    publisher.publish(**event)
    assert (
        str(db.scalar.call_args.args[0])
        == f"SELECT {contract.function}(:event_id,CAST(:payload AS jsonb))"
    )
    engine.begin.return_value.__exit__.assert_called_once_with(None, None, None)
    fallback.publish.assert_not_called()
    publisher.close()
    fallback.close.assert_called_once_with()
    engine.dispose.assert_not_called()


@pytest.mark.parametrize("contract", _CONTRACTS)
@pytest.mark.parametrize("mutation", ["extra", "event", "aggregate", "key", "identity", "payload"])
def test_retained_audit_malformed_envelopes_never_reach_database_or_fallback(contract, mutation):
    publisher, engine, fallback, event = _publisher(contract)
    if mutation == "extra":
        event["payload"]["api_key"] = "must-not-leak"
    elif mutation == "event":
        event["event_type"] = "another.event"
    elif mutation == "aggregate":
        event["aggregate_type"] = "another.aggregate"
    elif mutation == "key":
        event["aggregate_key"] = str(uuid4())
    elif mutation == "identity":
        event["event_id"] = UUID(int=0)
    else:
        key = "evidence_sha256" if contract.reference == "reservation_id" else "schema_version"
        event["payload"][key] = True
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.pre_side_effect and not rejected.value.retryable
    assert "must-not-leak" not in str(rejected.value)
    engine.begin.assert_not_called()
    fallback.publish.assert_not_called()


def test_retained_audit_delegates_only_unrelated_events():
    publisher, engine, fallback, _ = _publisher(_CONTRACTS[0])
    event = {
        "event_id": uuid4(),
        "event_type": "other.event",
        "aggregate_type": "other",
        "aggregate_key": "other",
        "payload": {"event_type": "other.event"},
    }
    publisher.publish(**event)
    fallback.publish.assert_called_once_with(**event)
    engine.begin.assert_not_called()


@pytest.mark.parametrize("code,retryable", [("22023", False), ("08006", True), ("23514", True)])
def test_retained_audit_database_errors_are_content_blind(code, retryable):
    publisher, engine, fallback, event = _publisher(_CONTRACTS[0])
    original = RuntimeError("private database detail")
    original.sqlstate = code
    engine.begin.return_value.__enter__.return_value.scalar.side_effect = OperationalError(
        "private statement", {}, original
    )
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.retryable is retryable
    assert rejected.value.pre_side_effect is not retryable
    assert "private" not in str(rejected.value)
    fallback.publish.assert_not_called()


def test_retained_audit_never_accepts_a_non_boolean_ack():
    publisher, engine, fallback, event = _publisher(_CONTRACTS[0])
    engine.begin.return_value.__enter__.return_value.scalar.return_value = 1
    with pytest.raises(RuntimeError, match="result_invalid"):
        publisher.publish(**event)
    fallback.publish.assert_not_called()


def test_retained_audit_startup_validates_functions_even_when_the_p0_set_is_absent():
    publisher, engine, _, _ = _publisher(_CONTRACTS[0])
    db = engine.connect.return_value.__enter__.return_value
    db.execute.side_effect = [_result() for _ in range(len(_CONTRACTS) + 1)]
    publisher.validate_outbox_configuration()
    assert db.execute.call_count == len(_CONTRACTS) + 1
    engine.dialect.name = "sqlite"
    with pytest.raises(RuntimeError, match="requires_postgresql"):
        publisher.validate_outbox_configuration()


@pytest.mark.parametrize("missing", range(4))
def test_partial_model_table_set_is_rejected_even_without_any_audit_function(missing):
    db = MagicMock()
    tables = [True] * 4
    tables[missing] = False
    db.execute.side_effect = [
        *[_result() for _ in _CONTRACTS],
        _result(model_tables=tuple(tables)),
    ]
    with pytest.raises(RuntimeError, match="schema_contract_rejected"):
        verify_retained_model_audit_functions(db)


def test_retained_claim_routes_require_successful_explicit_validation(monkeypatch):
    import saas.control_plane.retained_model_audit as retained

    publisher, engine, fallback, _ = _publisher(_CONTRACTS[0])
    engine.connect.assert_not_called()
    with pytest.raises(RuntimeError, match="routes_not_validated"):
        _ = publisher.claim_routes
    monkeypatch.setattr(retained, "verify_retained_model_audit_functions", lambda db: ())
    publisher.validate_outbox_configuration()
    assert publisher.claim_routes is None
    monkeypatch.setattr(
        retained,
        "verify_retained_model_audit_functions",
        lambda db: (_ for _ in ()).throw(RuntimeError("native_contract_rejected")),
    )
    with pytest.raises(RuntimeError, match="native_contract_rejected"):
        publisher.validate_outbox_configuration()
    with pytest.raises(RuntimeError, match="routes_not_validated"):
        _ = publisher.claim_routes
    fallback.publish.assert_not_called()


@pytest.mark.parametrize("retained_present", [False, True])
@pytest.mark.parametrize("fallback_kind", ["typed", "onboarding"])
def test_retained_wrapper_preserves_bounded_sql_claims(
    monkeypatch, retained_present, fallback_kind
):
    from datetime import UTC, datetime
    from types import SimpleNamespace

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import saas.control_plane.retained_model_audit as retained
    from saas.control_plane.db_models import ControlPlaneOutboxEvent
    from saas.control_plane.onboarding import OnboardingOutboxPublisher
    from saas.control_plane.outbox import OutboxDispatcher
    from saas.control_plane.outbox_delivery import (
        PlatformAuditJournalConsumer,
        UsageReconciliationConsumer,
    )
    from saas.control_plane.revocation import RevocationFanoutPublisher

    routes = (
        *UsageReconciliationConsumer.claim_routes,
        *PlatformAuditJournalConsumer.claim_routes,
        *RevocationFanoutPublisher.claim_routes,
    )
    if fallback_kind == "onboarding":
        routes = OnboardingOutboxPublisher(
            registrations=None, coordinator=None, envelopes=None, email_sender=None
        ).claim_routes
    fallback = SimpleNamespace(claim_routes=routes, publish=lambda **kwargs: None)
    native = MagicMock()
    native.dialect.name = "postgresql"
    publisher = RetainedModelAuditPublisher(native, fallback)
    monkeypatch.setattr(
        retained,
        "verify_retained_model_audit_functions",
        lambda db: (42, 43, 44) if retained_present else (),
    )
    publisher.validate_outbox_configuration()
    original_routes = routes
    assert publisher.claim_routes[: len(routes)] == original_routes
    assert len(publisher.claim_routes) == len(routes) + (3 if retained_present else 0)
    # A later mutation cannot turn this validated bounded publisher into a global worker.
    fallback.claim_routes = None
    assert publisher.claim_routes is not None
    engine = sa.create_engine("sqlite://", poolclass=StaticPool)
    ControlPlaneOutboxEvent.__table__.create(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    owned, unowned = set(), set()
    with factory.begin() as db:
        for route in (
            *routes,
            *(retained.OutboxClaimRoute(c.aggregate, c.event, c.event) for c in _CONTRACTS),
        ):
            for event_type, payload_type in (
                (route.event_type, route.payload_event_type or route.event_type),
                (route.event_type + ".unknown", route.payload_event_type or route.event_type),
                *([(route.event_type, "unknown.payload")] if route.payload_event_type else []),
            ):
                event_id = uuid4()
                accepted = any(
                    candidate.aggregate_type == route.aggregate_type
                    and candidate.event_type == event_type
                    and (
                        candidate.payload_event_type is None
                        or candidate.payload_event_type == payload_type
                    )
                    for candidate in publisher.claim_routes
                )
                (owned if accepted else unowned).add(event_id)
                db.add(
                    ControlPlaneOutboxEvent(
                        id=event_id,
                        tenant_id=None,
                        aggregate_type=route.aggregate_type,
                        aggregate_key=str(uuid4()),
                        event_type=event_type,
                        idempotency_key=str(event_id),
                        request_hash="a" * 64,
                        payload={"event_type": payload_type},
                        attempt_count=0,
                    )
                )
    dispatcher = OutboxDispatcher(factory, publisher, claim_routes=publisher.claim_routes)
    claimed = dispatcher._claim(claim_token=uuid4(), batch_size=100, now=datetime.now(UTC))
    assert {event.id for event in claimed} == owned
    with factory() as db:
        for event_id in unowned:
            row = db.get(ControlPlaneOutboxEvent, event_id)
            assert row.attempt_count == 0 and row.claim_token is None
            assert row.claimed_at is None and row.published_at is None
            assert row.quarantined_at is None
    engine.dispose()


@pytest.mark.parametrize("routes", [(), ("invalid",), "invalid"])
def test_retained_wrapper_rejects_empty_or_untyped_fallback_routes(monkeypatch, routes):
    import saas.control_plane.retained_model_audit as retained

    publisher, _, fallback, _ = _publisher(_CONTRACTS[0])
    fallback.claim_routes = routes
    monkeypatch.setattr(retained, "verify_retained_model_audit_functions", lambda db: ())
    with pytest.raises(RuntimeError, match="fallback_routes_rejected"):
        publisher.validate_outbox_configuration()
    with pytest.raises(RuntimeError, match="routes_not_validated"):
        _ = publisher.claim_routes


@pytest.mark.parametrize("kind", ["duplicate", "broad_overlap", "retained_overlap"])
def test_retained_wrapper_rejects_duplicate_and_overlapping_claim_routes(monkeypatch, kind):
    import saas.control_plane.retained_model_audit as retained
    from saas.control_plane.outbox import OutboxClaimRoute

    publisher, _, fallback, _ = _publisher(_CONTRACTS[0])
    route = OutboxClaimRoute("billing", "billing.usage.recorded")
    fallback.claim_routes = (route, route)
    if kind == "broad_overlap":
        fallback.claim_routes = (
            route,
            OutboxClaimRoute(*(route.aggregate_type, route.event_type, "nested.event")),
        )
    elif kind == "retained_overlap":
        contract = _CONTRACTS[0]
        fallback.claim_routes = (OutboxClaimRoute(contract.aggregate, contract.event),)
    monkeypatch.setattr(retained, "verify_retained_model_audit_functions", lambda db: (42, 43, 44))
    with pytest.raises(RuntimeError, match="claim_routes_overlap"):
        publisher.validate_outbox_configuration()
