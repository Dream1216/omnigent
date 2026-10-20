from __future__ import annotations

from hashlib import sha256
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError

from saas.control_plane.model_gateway_audit import (
    GATEWAY_AUDIT_SOURCE_SHA256,
    ModelGatewayAuditPublisher,
)
from saas.control_plane.model_gateway_evidence import (
    GATEWAY_EVIDENCE_AGGREGATE,
    GATEWAY_EVIDENCE_EVENT,
)
from saas.control_plane.outbox import OutboxPublishError


def _fixture():
    engine, fallback = MagicMock(), MagicMock()
    engine.dialect.name = "postgresql"
    engine.begin.return_value.__enter__.return_value.scalar.return_value = True
    reservation = str(uuid4())
    event = {
        "event_id": uuid4(),
        "event_type": GATEWAY_EVIDENCE_EVENT,
        "aggregate_type": GATEWAY_EVIDENCE_AGGREGATE,
        "aggregate_key": reservation,
        "payload": {
            "event_type": GATEWAY_EVIDENCE_EVENT,
            "tenant_id": str(uuid4()),
            "reservation_id": reservation,
            "evidence_id": str(uuid4()),
            "evidence_sha256": "a" * 64,
        },
    }
    return ModelGatewayAuditPublisher(engine, fallback), engine, fallback, event


def test_gateway_audit_source_pin_matches_the_versioned_migration_body():
    predecessor = import_module(
        "saas.control_plane.migrations.versions.lm2c00000001_gateway_evidence_audit"
    )
    migration = import_module(
        "saas.control_plane.migrations.versions.lm2q00000001_bounded_model_documents"
    )
    prefix = "CREATE OR REPLACE FUNCTION public.saas_audit_model_gateway_evidence_v1("
    bodies = []
    for statements in (migration._OLD_FUNCTIONS, migration._NEW_FUNCTIONS):
        matches = [sql for sql in statements if sql.startswith(prefix)]
        assert len(matches) == 1
        bodies.append(matches[0].split(" AS $function$", 1)[1].removesuffix("$function$"))
    assert bodies[0] == predecessor._FUNCTION_BODY
    assert sha256(bodies[0].encode()).hexdigest() == (
        "29e4dcdc4732fb13cada9977c9813657df950f84edeb08ad7aaecdd9c3d40ff3"
    )
    assert bodies[0] != bodies[1]
    assert sha256(bodies[1].encode()).hexdigest() == GATEWAY_AUDIT_SOURCE_SHA256


@pytest.mark.parametrize("replayed", (False, True))
def test_gateway_audit_commits_the_narrow_rpc_before_ack_and_keeps_engine_ownership(replayed):
    publisher, engine, fallback, event = _fixture()
    db = engine.begin.return_value.__enter__.return_value
    db.scalar.return_value = not replayed
    publisher.publish(**event)
    assert "saas_audit_model_gateway_evidence_v1" in str(db.scalar.call_args.args[0])
    engine.begin.return_value.__exit__.assert_called_once_with(None, None, None)
    fallback.publish.assert_not_called()
    publisher.close()
    fallback.close.assert_called_once_with()
    engine.dispose.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    (
        {"event_id": UUID(int=0)},
        {"event_type": "another.event"},
        {"aggregate_type": "another_aggregate"},
        {"aggregate_key": str(uuid4())},
        {"payload_override": {"tenant_id": "invalid"}},
        {"payload_override": {"evidence_id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}},
        {"payload_override": {"evidence_sha256": 123}},
        {"payload_override": {"evidence_sha256": "Z" * 64}},
        {"payload_override": {"api_key": "must-not-be-persisted"}},
    ),
)
def test_gateway_audit_rejects_malformed_envelopes_before_any_side_effect(mutation):
    publisher, engine, fallback, event = _fixture()
    payload_override = mutation.get("payload_override", {})
    event = {
        **event,
        **{key: value for key, value in mutation.items() if key != "payload_override"},
    }
    event["payload"] = {**event["payload"], **payload_override}
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.code == "model_gateway_audit_envelope_rejected"
    assert not rejected.value.retryable and rejected.value.pre_side_effect
    assert "must-not-be-persisted" not in str(rejected.value)
    engine.begin.assert_not_called()
    fallback.publish.assert_not_called()


def test_gateway_audit_delegates_unrelated_events_without_silently_acknowledging():
    publisher, engine, fallback, event = _fixture()
    event.update(event_type="another.event", aggregate_type="another_aggregate", payload={})
    publisher.publish(**event)
    fallback.publish.assert_called_once_with(**event)
    engine.begin.assert_not_called()


@pytest.mark.parametrize("code,retryable", (("22023", False), ("08006", True), ("23514", True)))
def test_gateway_audit_classifies_database_failures_without_exposing_bind_values(code, retryable):
    publisher, engine, _, event = _fixture()

    class DatabaseError(Exception):
        sqlstate = code

    engine.begin.return_value.__enter__.return_value.scalar.side_effect = OperationalError(
        "synthetic SQL", {"credential": "must-not-be-persisted"}, DatabaseError("secret")
    )
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.retryable is retryable
    assert rejected.value.pre_side_effect is (not retryable)
    assert "must-not-be-persisted" not in str(rejected.value)


def test_generic_outbox_process_installs_gateway_audit_before_claiming(monkeypatch):
    from saas import outbox_worker
    from saas.control_plane.model_disablement_audit import ModelDisablementAuditPublisher
    from saas.control_plane.model_revocation_audit import ModelRevocationAuditPublisher

    _, engine, fallback, _ = _fixture()
    captured = []
    monkeypatch.setenv("OMNIGENT_SAAS_OUTBOX_PUBLISHER", "isolated:publisher")
    monkeypatch.setenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL", "postgresql://isolated")
    monkeypatch.delenv("OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL_FILE", raising=False)
    monkeypatch.setattr(outbox_worker.sa, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(outbox_worker, "verify_dispatcher_database_role", lambda _engine: None)
    monkeypatch.setattr(outbox_worker, "_load_publisher", lambda _reference: fallback)
    monkeypatch.setattr(outbox_worker.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(
        "saas.control_plane.model_gateway_audit.verify_gateway_audit_function", lambda _db: 1
    )
    monkeypatch.setattr(
        "saas.control_plane.model_disablement_audit.verify_disablement_audit_function",
        lambda _db: 2,
    )
    monkeypatch.setattr(
        "saas.control_plane.model_revocation_audit.verify_revocation_audit_function",
        lambda _db: 3,
    )

    class Worker:
        def __init__(self, dispatcher, **_kwargs):
            captured.append(dispatcher._publisher)

        def run(self, _stop):
            return SimpleNamespace(cycles=0)

    monkeypatch.setattr(outbox_worker, "OutboxWorker", Worker)
    assert outbox_worker.main() == 0
    assert len(captured) == 1 and isinstance(captured[0], ModelRevocationAuditPublisher)
    assert isinstance(captured[0]._fallback, ModelDisablementAuditPublisher)
    assert isinstance(captured[0]._fallback._fallback, ModelGatewayAuditPublisher)
    assert captured[0]._fallback._fallback._fallback is fallback
    fallback.close.assert_called_once_with()
    engine.dispose.assert_called_once_with()
