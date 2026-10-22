from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_budget import ModelProviderBudgetError
from saas.control_plane.model_gateway_evidence import (
    GatewayRequestEvidence,
    canonical_gateway_evidence,
)
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
    ModelProviderMonthlyBudgetRecord,
)
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from tests.saas.test_platform_model_gateway import SESSION_ID, TENANT_ID, _configuration
from tests.saas.test_platform_model_gateway_attempts import _body, _fixture, _row


def _retained(budgets, sessions):
    row = _row(sessions)
    return budgets.gateway_evidence(reservation_id=row.id, tenant_id=TENANT_ID, run_id=SESSION_ID)


@pytest.mark.parametrize("responses", (False, True))
def test_gateway_retains_request_before_egress_and_atomic_final_usage_without_content(
    tmp_path, responses
):
    assert ModelGatewayEvidenceRecord.__tablename__ in CONTROL_PLANE_RLS_TABLES

    def handler(_request):
        assert [fact.phase for fact in _retained(budgets, sessions)] == ["request", "in_flight"]
        return httpx.Response(
            200, content=_body(responses=responses), headers={"content-type": "text/event-stream"}
        )

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler, responses=responses)
    assert client.post(path, **request).status_code == 200
    facts = _retained(budgets, sessions)
    assert [fact.phase for fact in facts] == ["request", "in_flight", "settled"]
    documents = [json.loads(fact.canonical_evidence) for fact in facts]
    assert documents[0]["request"]["wire_api"] == (
        "openai_responses" if responses else "openai_chat_completions"
    )
    assert documents[0]["request"]["output_token_limit"] == 32
    assert documents[0]["admission"]["admitted_microusd"] == _row(sessions).admitted_microusd
    assert documents[0]["admission"]["admitted_microusd"] > documents[2]["actual_microusd"]
    assert documents[2]["usage"] == asdict(ModelTokenUsage(10, 0, 10, 3, 13))
    assert documents[2]["actual_microusd"] == 13
    assert documents[2]["request_evidence_sha256"] == facts[0].evidence_sha256
    assert _row(sessions).outcome_evidence_sha256 == facts[2].evidence_sha256
    assert all(
        sha256(fact.canonical_evidence.encode()).hexdigest() == fact.evidence_sha256
        for fact in facts
    )
    with sessions() as db:
        events = db.scalars(
            sa.select(ControlPlaneOutboxEvent).order_by(ControlPlaneOutboxEvent.created_at)
        ).all()
        assert len(events) == 3
        assert {event.payload["evidence_id"] for event in events} == {
            str(fact.id) for fact in facts
        }
        assert all(
            set(event.payload)
            == {"event_type", "tenant_id", "reservation_id", "evidence_id", "evidence_sha256"}
            for event in events
        )
    retained = canonical_gateway_evidence(documents)
    assert "hello" not in retained and _configuration().api_key not in retained
    for wrong in ({"tenant_id": uuid4()}, {"run_id": uuid4()}):
        with pytest.raises(ModelProviderBudgetError, match="scope"):
            budgets.gateway_evidence(
                reservation_id=facts[0].reservation_id,
                **{"tenant_id": TENANT_ID, "run_id": SESSION_ID, **wrong},
            )


@pytest.mark.parametrize(
    "failure_at,expected_phases",
    (
        (1, []),
        (2, ["request", "released"]),
        (3, ["request", "in_flight", "uncertain"]),
    ),
)
def test_outbox_failure_rolls_back_its_budget_and_evidence_transaction(
    tmp_path, failure_at, expected_phases
):
    calls, inserts = [], []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler)

    def fail_one_insert(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO saas_control_plane_outbox"):
            inserts.append(statement)
            if len(inserts) == failure_at:
                raise OSError("isolated Outbox persistence failure")

    engine = sessions.kw["bind"]
    sa.event.listen(engine, "before_cursor_execute", fail_one_insert)
    try:
        response = client.post(path, **request)
    finally:
        sa.event.remove(engine, "before_cursor_execute", fail_one_insert)
    with sessions() as db:
        facts = db.scalars(
            sa.select(ModelGatewayEvidenceRecord).order_by(
                ModelGatewayEvidenceRecord.budget_version
            )
        ).all()
        assert [fact.phase for fact in facts] == expected_phases
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == len(
            facts
        )
        assert db.scalar(
            sa.select(sa.func.count()).select_from(ModelProviderBudgetReservationRecord)
        ) == (1 if facts else 0)
        counter = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord))
        assert counter is None or counter.settled_microusd == 0
    assert len(calls) == (1 if failure_at == 3 else 0)
    assert response.status_code == (200 if failure_at == 3 else 503)
    if failure_at == 3:
        assert _row(sessions).status == "uncertain"
        assert budgets.recover_expired(now=datetime.now(timezone.utc) + timedelta(days=1)) == ()


def test_gateway_usage_replay_checks_the_full_normalized_receipt_and_never_settles_twice(tmp_path):
    def handler(_request):
        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler)
    assert client.post(path, **request).status_code == 200
    row = _row(sessions)
    kwargs = {
        "reservation_id": row.id,
        "actual_tokens": 13,
        "actual_microusd": 13,
        "evidence_sha256": None,
        "gateway_usage": ModelTokenUsage(10, 0, 10, 3, 13),
    }
    assert budgets.resolve_attempt(**kwargs).replayed
    with pytest.raises(ModelProviderBudgetError, match="conflicts"):
        budgets.resolve_attempt(**{**kwargs, "gateway_usage": ModelTokenUsage(10, 2, 8, 3, 13)})
    assert len(_retained(budgets, sessions)) == 3
    with sessions() as db:
        counter = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord))
        assert counter.reserved_microusd == 0 and counter.settled_microusd == 13


@pytest.mark.parametrize("mutation", ("hash_only", "output_limit"))
def test_gateway_requires_bound_usage_and_the_actual_output_limit(tmp_path, mutation):
    def handler(_request):
        if mutation == "hash_only":
            row = _row(sessions)
            with pytest.raises(ModelProviderBudgetError):
                budgets.resolve_attempt(
                    reservation_id=row.id,
                    actual_microusd=13,
                    actual_tokens=13,
                    evidence_sha256="e" * 64,
                )
        return httpx.Response(
            200,
            content=_body().replace(b":3", b":33").replace(b":13", b":43"),
            headers={"content-type": "text/event-stream"},
        )

    client, path, request, budgets, sessions, _ = _fixture(tmp_path, handler)
    assert client.post(path, **request).status_code == 200
    assert _row(sessions).status == "uncertain"
    assert [fact.phase for fact in _retained(budgets, sessions)] == [
        "request",
        "in_flight",
        "uncertain",
    ]


def test_gateway_request_idempotency_binds_price_model_protocol_and_limit(tmp_path):
    client, path, request, budgets, sessions, _ = _fixture(
        tmp_path, lambda _request: httpx.Response(401)
    )
    assert client.post(path, **request).status_code == 502
    first = json.loads(_retained(budgets, sessions)[0].canonical_evidence)["request"]
    from saas.control_plane.model_pricing import PlatformModelPrice

    bound = GatewayRequestEvidence(
        first["public_model_id"],
        first["wire_api"],
        first["pricing_revision"],
        PlatformModelPrice(**first["model_price"]),
        first["output_token_limit"],
    )
    original = {
        "tenant_id": TENANT_ID,
        "run_id": SESSION_ID,
        "operation_key": "bound-idempotency",
        "requested_microusd": 100,
        "requested_tokens": 100,
        "ttl": timedelta(minutes=1),
        "gateway_request": bound,
    }
    row = budgets.reserve(**original)
    assert budgets.reserve(**original).id == row.id
    with pytest.raises(ModelProviderBudgetError, match="another request"):
        budgets.reserve(**{**original, "gateway_request": replace(bound, output_token_limit=31)})
    with pytest.raises(ModelProviderBudgetError):
        budgets.settle(reservation_id=row.id, actual_microusd=1, actual_tokens=1)
