"""Static contracts complement the real four-authority PostgreSQL regression."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

policy = importlib.import_module(
    "saas.control_plane.migrations.versions.lm2t00000001_model_budget_owner_settlement"
)


def test_budget_settlement_policy_is_owner_and_exact_context_scoped(monkeypatch):
    statements = []
    monkeypatch.setattr(
        policy.op, "get_bind", lambda: SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    )
    monkeypatch.setattr(policy.op, "execute", statements.append)
    policy.upgrade()
    assert len(statements) == 1
    sql = statements[0]
    assert "FOR UPDATE" in sql and "WITH CHECK" in sql
    for fragment in (
        "current_user = pg_catalog.pg_get_userbyid",
        "app.model_budget_reservation_id",
        "app.metering_tenant_id",
        "app.metering_run_id",
        "provider_id = 'deepseek'",
        "purpose = 'tenant_run'",
        "status = 'reserved'",
        "expires_at > CURRENT_TIMESTAMP",
    ):
        assert sql.count(fragment) == 2
    assert "GRANT" not in sql and "BYPASSRLS" not in sql and "NO FORCE" not in sql
    assert policy.down_revision == "lm2s00000001"


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
def test_budget_settlement_policy_is_postgresql_only(monkeypatch, dialect):
    monkeypatch.setattr(
        policy.op, "get_bind", lambda: SimpleNamespace(dialect=SimpleNamespace(name=dialect))
    )
    monkeypatch.setattr(policy.op, "execute", lambda _sql: pytest.fail("unexpected policy DDL"))
    policy.upgrade()
    policy.downgrade()


@pytest.mark.parametrize("retained", [None, 1])
def test_downgrade_does_not_remove_policy_from_retained_budgets(monkeypatch, retained):
    queries, statements = [], []

    def scalar(query):
        queries.append(str(query))
        return retained

    monkeypatch.setattr(
        policy.op,
        "get_bind",
        lambda: SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), scalar=scalar),
    )
    monkeypatch.setattr(policy.op, "execute", statements.append)
    if retained is None:
        policy.downgrade()
        assert statements == [f"DROP POLICY {policy._POLICY} ON {policy._TABLE}"]
    else:
        with pytest.raises(RuntimeError, match="retained model budgets require"):
            policy.downgrade()
        assert statements == []
    assert queries == [f"SELECT 1 FROM {policy._TABLE} LIMIT 1"]
