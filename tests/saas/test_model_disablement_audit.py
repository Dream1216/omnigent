from __future__ import annotations

from hashlib import sha256
from importlib import import_module
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError

from saas.control_plane.model_disablement import DISABLEMENT_EVENT
from saas.control_plane.model_disablement_audit import (
    DISABLEMENT_AUDIT_SOURCE_SHA256,
    ModelDisablementAuditPublisher,
)
from saas.control_plane.outbox import OutboxPublishError


def _fixture():
    engine, fallback = MagicMock(), MagicMock()
    engine.dialect.name = "postgresql"
    engine.begin.return_value.__enter__.return_value.scalar.return_value = True
    identity = str(uuid4())
    event = {
        "event_id": uuid4(),
        "event_type": DISABLEMENT_EVENT,
        "aggregate_type": "platform_model",
        "aggregate_key": identity,
        "payload": {
            "event_type": DISABLEMENT_EVENT,
            "schema_version": 1,
            "disablement_id": identity,
        },
    }
    return ModelDisablementAuditPublisher(engine, fallback), engine, fallback, event


def test_disablement_audit_source_pin_matches_migration():
    migration = import_module(
        "saas.control_plane.migrations.versions.lm2m00000001_model_disablement_audit"
    )
    assert sha256(migration._FUNCTION_BODY.encode()).hexdigest() == DISABLEMENT_AUDIT_SOURCE_SHA256


@pytest.mark.parametrize("replayed", (False, True))
def test_disablement_audit_commits_before_ack_and_preserves_shared_engine(replayed):
    publisher, engine, fallback, event = _fixture()
    db = engine.begin.return_value.__enter__.return_value
    db.scalar.return_value = not replayed
    publisher.publish(**event)
    assert "saas_audit_model_disablement_v1" in str(db.scalar.call_args.args[0])
    engine.begin.return_value.__exit__.assert_called_once_with(None, None, None)
    fallback.publish.assert_not_called()
    publisher.close()
    fallback.close.assert_called_once_with()
    engine.dispose.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    (
        {"event_id": UUID(int=0)},
        {"event_type": "other.event"},
        {"aggregate_type": "other_aggregate"},
        {"aggregate_key": str(uuid4())},
        {"payload_override": {"event_type": "other.event"}},
        {"payload_override": {"schema_version": True}},
        {"payload_override": {"schema_version": 2}},
        {"payload_override": {"disablement_id": None}},
        {"payload_override": {"disablement_id": "invalid"}},
        {"payload_override": {"api_key": "must-not-persist"}},
    ),
)
def test_disablement_audit_rejects_malformed_envelope_before_database(mutation):
    publisher, engine, fallback, event = _fixture()
    event = {**event, **{k: v for k, v in mutation.items() if k != "payload_override"}}
    event["payload"] = {**event["payload"], **mutation.get("payload_override", {})}
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.code == "model_disablement_audit_envelope_rejected"
    assert rejected.value.pre_side_effect and not rejected.value.retryable
    engine.begin.assert_not_called()
    fallback.publish.assert_not_called()


@pytest.mark.parametrize("code,retryable", (("22023", False), ("08006", True), ("23514", True)))
def test_disablement_audit_database_errors_are_content_blind(code, retryable):
    publisher, engine, _, event = _fixture()

    class DatabaseError(Exception):
        sqlstate = code

    engine.begin.return_value.__enter__.return_value.scalar.side_effect = OperationalError(
        "synthetic SQL", {"credential": "must-not-persist"}, DatabaseError("secret")
    )
    with pytest.raises(OutboxPublishError) as rejected:
        publisher.publish(**event)
    assert rejected.value.retryable is retryable
    assert rejected.value.pre_side_effect is not retryable
    assert "secret" not in str(rejected.value) and "must-not-persist" not in str(rejected.value)


def test_disablement_audit_delegates_unrelated_model_events():
    publisher, engine, fallback, event = _fixture()
    event.update(event_type="platform.model_projection.requested", payload={})
    publisher.publish(**event)
    fallback.publish.assert_called_once_with(**event)
    engine.begin.assert_not_called()


@pytest.mark.parametrize("result", (None, "true", 1))
def test_disablement_audit_never_accepts_an_ambiguous_database_result(result):
    publisher, engine, fallback, event = _fixture()
    engine.begin.return_value.__enter__.return_value.scalar.return_value = result
    with pytest.raises(RuntimeError, match="audit_result_invalid"):
        publisher.publish(**event)
    fallback.publish.assert_not_called()


def test_disablement_audit_refuses_missing_rpc_and_non_postgresql(monkeypatch):
    publisher, engine, _, _ = _fixture()
    monkeypatch.setattr(
        "saas.control_plane.model_disablement_audit.verify_disablement_audit_function",
        lambda _db: None,
    )
    with pytest.raises(RuntimeError, match="function_unavailable"):
        publisher.validate_outbox_configuration()
    engine.dialect.name = "sqlite"
    with pytest.raises(RuntimeError, match="requires_postgresql"):
        publisher.validate_outbox_configuration()
