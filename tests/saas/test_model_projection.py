from __future__ import annotations

import json
from uuid import UUID, uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
    LiteLLMManagementError,
)
from saas.control_plane.model_connections import CreateModelConnection
from saas.control_plane.model_projection import (
    MODEL_CREDENTIAL_PROJECTION_ROUTE,
    ModelCredentialProjectionPublisher,
)
from saas.control_plane.model_routing_models import ModelProjectionTransitionRecord
from saas.control_plane.outbox import OutboxDispatcher, OutboxPublishError
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord
from tests.saas.test_model_connections import _KEY, _fixture


def _projection(handler):
    service, factory, actor, cipher, _client, _headers = _fixture()
    operation = service.create(
        actor, command=CreateModelConnection("candidate", _KEY), idempotency_key="project-001"
    )
    with factory() as db:
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(operation.id)
            )
        )
        assert event is not None
        envelope = {
            "event_id": event.id,
            "event_type": event.event_type,
            "aggregate_type": event.aggregate_type,
            "aggregate_key": event.aggregate_key,
            "payload": event.payload,
        }
    management = LiteLLMManagementClient(
        LiteLLMManagementConfiguration(
            base_url="https://litellm.test", management_key="isolated-management-test-secret"
        ),
        transport=httpx.MockTransport(handler),
    )
    publisher = ModelCredentialProjectionPublisher(
        factory.kw["bind"], secret_cipher=cipher, management=management
    )
    return service, factory, actor, publisher, envelope, operation


def test_projection_is_acknowledged_once_without_verifying_or_publishing_runtime():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == "/credentials"
        assert json.loads(request.content)["credential_values"]["api_key"] == _KEY
        return httpx.Response(200, json={"status": "success"})

    service, factory, actor, publisher, envelope, operation = _projection(handler)
    publisher.publish(**envelope)
    publisher.publish(**envelope)
    result = service.operation(actor, operation.id)
    assert result.status == "applied" and result.version == 3
    assert _KEY not in repr(result)
    assert service.list(actor)[0].runtime_enabled is False
    assert len(calls) == 1
    with factory() as db:
        receipts = db.scalars(
            sa.select(ModelProjectionTransitionRecord).order_by(
                ModelProjectionTransitionRecord.version
            )
        ).all()
        assert [(row.previous_status, row.status, row.version) for row in receipts] == [
            ("requested", "applying", 2),
            ("applying", "applied", 3),
        ]
        assert all(row.event_id == envelope["event_id"] for row in receipts)
        assert all(row.actor_principal_id == actor.principal_id for row in receipts)
        assert _KEY not in repr(receipts)


@pytest.mark.parametrize(
    "status,expected", ((401, "failed"), (409, "uncertain"), (503, "uncertain"))
)
def test_management_rejection_never_replays_or_treats_conflict_as_same_key(status, expected):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"detail": _KEY})

    service, _factory, actor, publisher, envelope, operation = _projection(handler)
    publisher.publish(**envelope)
    publisher.publish(**envelope)
    result = service.operation(actor, operation.id)
    assert result.status == expected
    assert _KEY not in repr(result)
    assert len(calls) == 1
    if status == 409:
        assert result.error_code == "litellm_projection_conflict_unverified"


def test_post_write_receipt_failure_recovers_as_uncertain_without_second_external_write(
    monkeypatch,
):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"status": "success"})

    service, _factory, actor, publisher, envelope, operation = _projection(handler)
    original = publisher._finish

    def fail_receipt(*args, **kwargs):
        raise RuntimeError("isolated DB write failed after external acknowledgement")

    monkeypatch.setattr(publisher, "_finish", fail_receipt)
    with pytest.raises(RuntimeError):
        publisher.publish(**envelope)
    assert service.operation(actor, operation.id).status == "applying"
    monkeypatch.setattr(publisher, "_finish", original)
    publisher.publish(**envelope)
    result = service.operation(actor, operation.id)
    assert result.status == "uncertain"
    assert result.error_code == "litellm_projection_interrupted"
    assert len(calls) == 1


def test_late_acknowledgement_cannot_overwrite_a_concurrent_unknown_outcome():
    calls = []

    def handler(request):
        calls.append(request)
        publisher.publish(**envelope)
        return httpx.Response(200, json={"status": "success"})

    service, _factory, actor, publisher, envelope, operation = _projection(handler)
    publisher.publish(**envelope)
    assert service.operation(actor, operation.id).status == "uncertain"
    assert len(calls) == 1


def test_actor_revocation_prevents_projection_before_external_access():
    def handler(_request):
        pytest.fail("revoked Staff must not change LiteLLM")

    _service, factory, actor, publisher, envelope, operation = _projection(handler)
    with factory.begin() as db:
        db.execute(
            sa.update(PlatformStaffPrincipalRecord)
            .where(PlatformStaffPrincipalRecord.id == actor.principal_id)
            .values(status="suspended")
        )
    publisher.publish(**envelope)
    with factory() as db:
        from saas.control_plane.model_routing_models import ModelProjectionOperationRecord

        record = db.get(ModelProjectionOperationRecord, operation.id)
        assert record is not None
        assert record.status == "failed" and record.error_code == "model_projection_actor_revoked"


@pytest.mark.parametrize("change", ("route", "payload", "identifier", "unknown_event"))
def test_invalid_event_is_terminal_before_any_management_request(change):
    def handler(_request):
        pytest.fail("invalid envelope must not reach LiteLLM")

    _service, _factory, _actor, publisher, envelope, _operation = _projection(handler)
    if change == "route":
        envelope["aggregate_type"] = "unrelated"
    elif change == "payload":
        envelope["payload"] = {**envelope["payload"], "api_key": "must-not-be-an-event"}
    elif change == "identifier":
        envelope["event_id"] = UUID(int=0)
    else:
        envelope["event_id"] = uuid4()
    with pytest.raises(OutboxPublishError) as error:
        publisher.publish(**envelope)
    assert error.value.retryable is False and error.value.pre_side_effect is True


def test_dispatcher_claims_only_the_exact_model_projection_route():
    def handler(_request):
        return httpx.Response(200, json={"status": "success"})

    _service, factory, _actor, publisher, _envelope, _operation = _projection(handler)
    unrelated_id = uuid4()
    with factory.begin() as db:
        db.add(
            ControlPlaneOutboxEvent(
                id=unrelated_id,
                tenant_id=None,
                aggregate_type="unrelated",
                aggregate_key="untouched",
                event_type="unrelated.event",
                idempotency_key="unrelated",
                request_hash="a" * 64,
                payload={},
            )
        )
    dispatcher = OutboxDispatcher(
        factory, publisher, claim_routes=(MODEL_CREDENTIAL_PROJECTION_ROUTE,)
    )
    result = dispatcher.dispatch_once()
    assert (result.claimed, result.published, result.failed) == (1, 1, 0)
    with factory() as db:
        unrelated = db.get(ControlPlaneOutboxEvent, unrelated_id)
        assert unrelated is not None and unrelated.published_at is None
        assert unrelated.attempt_count == 0 and unrelated.claim_token is None


def test_unrecognized_management_error_cannot_persist_secret_content(monkeypatch):
    service, _factory, actor, publisher, envelope, operation = _projection(
        lambda _: httpx.Response(200, json={})
    )

    async def reject(**kwargs):
        raise LiteLLMManagementError(_KEY, uncertain=False)

    monkeypatch.setattr(publisher._management, "create_deepseek_credential", reject)
    publisher.publish(**envelope)
    result = service.operation(actor, operation.id)
    assert result.status == "uncertain"
    assert result.error_code == "litellm_projection_outcome_unknown"
    assert _KEY not in repr(result)
