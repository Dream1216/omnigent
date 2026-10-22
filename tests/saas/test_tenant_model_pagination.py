from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.model_routing_models import ModelPublicationDisablementRecord
from saas.control_plane.tenant_model_catalog import TenantModelCatalog, TenantModelCatalogError
from saas.production.tenant_model_catalog import create_tenant_model_catalog_router
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login
from tests.saas.test_model_pagination import publication_page as publication_page


def _catalog(fixture):
    _service, factory, _actor, tenant, _foreign = fixture
    return TenantModelCatalog(factory.kw["bind"]), replace(_runtime(), tenant_id=tenant)


def test_customer_catalog_pages_preserve_sparse_continuations_and_latest_versions(
    publication_page,
):
    catalog, runtime = _catalog(publication_page)
    cursor, seen, empty_pages = None, [], 0
    for _ in range(4):
        page = catalog.page(runtime, limit=1, cursor=cursor)
        seen.extend((row["model_id"], row["generation"]) for row in page.items)
        if not page.items:
            empty_pages += 1
            assert page.next_cursor is not None
        cursor = UUID(page.next_cursor) if page.next_cursor else None
    assert cursor is None and empty_pages == 2
    assert seen == [("deepseek-history", 3), ("deepseek-other", 1)]


def test_customer_cursor_cannot_cross_tenant_or_reference_an_unknown_row(publication_page):
    catalog, runtime = _catalog(publication_page)
    for cursor in (UUID(int=7001), uuid4(), UUID(int=0)):
        with pytest.raises(TenantModelCatalogError, match="page invalid"):
            catalog.page(runtime, limit=1, cursor=cursor)


@pytest.mark.parametrize("limit", (True, False, 0, 101))
def test_customer_page_limits_are_validated_before_database_work(publication_page, limit):
    catalog, runtime = _catalog(publication_page)
    with pytest.raises(TenantModelCatalogError, match="page invalid"):
        catalog.page(runtime, limit=limit)


def test_customer_catalog_does_not_fall_back_to_a_disabled_older_generation(publication_page):
    catalog, runtime = _catalog(publication_page)
    _service, factory, actor, _tenant, _foreign = publication_page
    with factory.begin() as db:
        db.add(
            ModelPublicationDisablementRecord(
                id=uuid4(),
                tenant_id=runtime.tenant_id,
                public_model_id="deepseek-history",
                wire_api="openai_chat_completions",
                through_generation=3,
                principal_id=actor.principal_id,
                staff_session_id=actor.session_id,
                staff_security_version=actor.security_version,
                idempotency_key="synthetic-customer-page-cutoff",
                request_hash="a" * 64,
                created_at=datetime.now(timezone.utc),
            )
        )
    first = catalog.page(runtime, limit=1)
    assert first.items == () and first.next_cursor == str(UUID(int=6004))
    assert [row["model_id"] for row in catalog.list(runtime)] == ["deepseek-other"]


def test_customer_page_queries_have_bounded_indexed_traversals(publication_page):
    catalog, runtime = _catalog(publication_page)
    engine, queries = publication_page[1].kw["bind"], []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM saas_model_publication_versions" in statement:
            queries.append((statement, parameters))

    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        catalog.page(runtime, limit=1)
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert len(queries) == 2
    assert all("GROUP BY" not in sql and "LIMIT" in sql for sql, _ in queries)
    with engine.connect() as connection:
        plans = [
            connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params).all()
            for sql, params in queries
        ]
    assert any("ix_model_publication_tenant_page" in row[-1] for row in plans[0])
    assert all("TEMP B-TREE" not in row[-1] for plan in plans for row in plan)


def test_customer_http_separates_paging_from_target_and_keeps_errors_content_free():
    app, _scope = _build_fastapi_app()
    app.include_router(
        create_tenant_model_catalog_router(
            auth_provider=app.state.saas_test_auth,
            catalog=TenantModelCatalog(app.state.saas_test_engine),
        ),
        prefix="/v1",
    )
    with TestClient(app) as client:
        _login(client)
        result = client.get("/v1/managed-model-catalog", params={"limit": 1})
        assert result.status_code == 200
        assert result.json() == {"models": [], "runtime_enabled": False, "next_cursor": None}
        assert result.headers["cache-control"] == "private, no-store"
        for params in (
            {"limit": "no"},
            {"limit": 0},
            {"limit": 101},
            {"cursor": "not-a-uuid"},
            {"cursor": str(uuid4())},
            {"cursor": str(UUID(int=0))},
            [("limit", "1"), ("limit", "2")],
            {"limit": 1, "tenant_id": "sensitive"},
        ):
            response = client.get("/v1/managed-model-catalog", params=params)
            assert response.status_code == 400, response.text
            assert response.json() == {"detail": {"code": "model_catalog_request_invalid"}}
