from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.model_budget import ModelProviderBudgetError
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord as Reservation
from tests.saas.test_model_test_funding import _funding_fixture, _request


@pytest.fixture
def test_day():
    funding, budget, factory, actor, policy = _funding_fixture(
        monthly_budget_microusd=10**9,
        daily_test_budget_microusd=10**9,
        daily_test_token_limit=10**9,
        daily_test_attempt_limit=1000,
    )
    at = datetime.now(timezone.utc)
    request = _request(actor, requested_microusd=1, requested_tokens=1, now=at)
    first = budget.reserve_platform_test(**request)
    budget.release(reservation_id=first.id, now=at + timedelta(seconds=1))
    with factory() as db:
        source = db.get(Reservation, first.id)
        template = {
            column.name: getattr(source, column.name) for column in Reservation.__table__.columns
        }

    def seed(count, *, rejected=False):
        with factory.begin() as db:
            values = []
            for _ in range(count):
                record = {
                    **template,
                    "id": uuid4(),
                    "operation_key": uuid4().hex,
                    "test_operation_id": uuid4(),
                }
                if rejected:
                    record.update(
                        admitted_microusd=0,
                        admitted_tokens=0,
                        released_microusd=0,
                        released_tokens=0,
                        status="rejected",
                        rejection_code="synthetic-rejection",
                    )
                values.append(record)
            db.execute(sa.insert(Reservation), values)

    try:
        yield funding, budget, factory, actor, policy, at, seed
    finally:
        factory.kw["bind"].dispose()


def test_daily_attempt_ceiling_counts_released_holds_across_policy_versions(test_day):
    funding, budget, factory, actor, policy, at, seed = test_day
    seed(999)
    seed(3000, rejected=True)
    funding.configure(actor, expected_version=1, policy=replace(policy, max_test_tokens=800))
    engine, queries = factory.kw["bind"], []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if (
            "FROM saas_model_provider_budget_reservations" in statement
            and "admitted_microusd >" in statement
        ):
            queries.append((statement, parameters))

    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        result = budget.reserve_platform_test(
            **_request(
                actor,
                requested_microusd=1,
                requested_tokens=1,
                now=at,
            )
        )
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert result.status == "rejected"
    assert result.rejection_code == "platform_model_test_daily_attempts_exhausted"
    assert len(queries) == 1
    sql, parameters = queries[0]
    assert "LIMIT" in sql and "sum(" not in sql.lower() and "count(" not in sql.lower()
    with engine.connect() as connection:
        plan = connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, parameters).all()
    assert any("ix_model_budget_admitted_test_day" in row[-1] for row in plan)
    assert all("TEMP B-TREE" not in row[-1] for row in plan)


def test_overfull_daily_history_fails_closed_instead_of_returning_partial_financial_totals(
    test_day,
):
    _funding, budget, factory, actor, _policy, at, seed = test_day
    seed(1000)
    with factory() as db:
        before = db.scalar(sa.select(sa.func.count()).select_from(Reservation))
    with pytest.raises(ModelProviderBudgetError) as error:
        budget.reserve_platform_test(
            **_request(
                actor,
                requested_microusd=1,
                requested_tokens=1,
                now=at,
            )
        )
    assert error.value.code == "platform_model_test_history_inconsistent"
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(Reservation)) == before
