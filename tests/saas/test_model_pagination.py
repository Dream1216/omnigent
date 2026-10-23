from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import Tenant
from saas.control_plane.model_deployments import compile_model_deployment_draft
from saas.control_plane.model_publications import ModelPublicationService
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelPublicationVersionRecord,
)
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
)
from tests.saas.test_model_connections import _fixture
from tests.saas.test_model_deployments import _draft_fixture
from tests.saas.test_model_verifications import _pricing


@pytest.fixture
def connection_page():
    service, factory, actor, _cipher, client, _headers = _fixture()
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        db.add_all(
            ModelConnectionRecord(
                id=UUID(int=index),
                display_name=f"Synthetic connection {index}",
                provider_id="deepseek",
                base_url="https://api.deepseek.com",
                version=1,
                credential_generation=1,
                updated_by_principal_id=actor.principal_id,
                created_at=now,
                updated_at=now,
            )
            for index in range(1, 102)
        )
    try:
        yield service, factory, actor, client
    finally:
        client.close()
        factory.kw["bind"].dispose()


def test_connection_http_page_honors_limit_and_exposes_continuation(connection_page):
    _service, _factory, _actor, client = connection_page
    response = client.get("/v2/platform-admin/model-connections", params={"limit": 1})
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["next_cursor"] == str(UUID(int=1))
    assert "api_key_ciphertext" not in response.text


def test_connection_http_page_reaches_the_last_row_beyond_the_first_hundred(connection_page):
    _service, _factory, _actor, client = connection_page
    response = client.get(
        "/v2/platform-admin/model-connections",
        params={"limit": 1, "cursor": str(UUID(int=100))},
    )
    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["items"]] == [str(UUID(int=101))]
    assert body["next_cursor"] is None


def test_equal_timestamps_have_deterministic_duplicate_free_continuation(connection_page):
    _service, _factory, _actor, client = connection_page
    cursor, seen = None, []
    for _page in range(5):
        parameters = {"limit": 25}
        if cursor is not None:
            parameters["cursor"] = cursor
        response = client.get("/v2/platform-admin/model-connections", params=parameters)
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) <= 25
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
    assert cursor is None
    assert seen == [str(UUID(int=index)) for index in range(1, 102)]


@pytest.mark.parametrize("limit", (-1, 0, 101, "not-a-number"))
def test_connection_http_page_rejects_invalid_limits(connection_page, limit):
    _service, _factory, _actor, client = connection_page
    response = client.get("/v2/platform-admin/model-connections", params={"limit": limit})
    assert response.status_code == 422


def test_connection_http_page_rejects_invalid_cursor_syntax(connection_page):
    _service, _factory, _actor, client = connection_page
    response = client.get("/v2/platform-admin/model-connections", params={"cursor": "not-a-uuid"})
    assert response.status_code == 422


def test_connection_http_page_rejects_an_unknown_anchor_without_echoing_it(connection_page):
    _service, _factory, _actor, client = connection_page
    cursor = str(uuid4())
    response = client.get("/v2/platform-admin/model-connections", params={"cursor": cursor})
    assert response.status_code == 400
    assert cursor not in response.text


def test_connection_pages_still_require_staff_authentication(connection_page):
    _service, _factory, _actor, client = connection_page
    client.cookies.clear()
    response = client.get("/v2/platform-admin/model-connections", params={"limit": 1})
    assert response.status_code in (401, 403)
    assert "items" not in response.json()


def test_connection_keyset_query_uses_the_page_index_without_a_temporary_sort(connection_page):
    service, factory, actor, _client = connection_page
    engine = factory.kw["bind"]
    captured = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM saas_model_connections" in statement:
            captured.append((statement, parameters))

    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        page = service.page(actor, limit=2, cursor=UUID(int=50))
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert [item.id for item in page.items] == [UUID(int=51), UUID(int=52)]
    assert page.next_cursor == str(UUID(int=52))
    statement, parameters = captured[-1]
    with engine.connect() as connection:
        plan = connection.exec_driver_sql("EXPLAIN QUERY PLAN " + statement, parameters).all()
    assert any("ix_model_connection_page" in row[-1] for row in plan)
    assert all("TEMP B-TREE" not in row[-1] for row in plan)


@pytest.fixture
def credential_page():
    _service, factory, actor, _cipher, client, _headers = _fixture()
    now, connection_id = datetime.now(timezone.utc), UUID(int=1000)
    with factory.begin() as db:
        db.add(
            ModelConnectionRecord(
                id=connection_id,
                display_name="Synthetic history",
                provider_id="deepseek",
                base_url="https://api.deepseek.com",
                version=101,
                credential_generation=101,
                updated_by_principal_id=actor.principal_id,
                created_at=now,
                updated_at=now,
            )
        )
        for generation in range(1, 102):
            identifier = UUID(int=2000 + generation)
            db.add(
                ModelCredentialVersionRecord(
                    id=identifier,
                    connection_id=connection_id,
                    generation=generation,
                    credential_name=f"synthetic-{identifier.hex}",
                    api_key_ciphertext="ciphertext:synthetic-metadata-only",
                    created_by_principal_id=actor.principal_id,
                    created_at=now,
                )
            )
            db.add(
                ModelProjectionOperationRecord(
                    id=UUID(int=3000 + generation),
                    connection_id=connection_id,
                    credential_version_id=identifier,
                    deployment_version_id=None,
                    action="create_connection" if generation == 1 else "rotate_credential",
                    actor_principal_id=actor.principal_id,
                    idempotency_key=f"synthetic-credential-page-{generation}",
                    request_hash="a" * 64,
                    status="applied" if generation % 2 else "requested",
                    version=2 if generation % 2 else 1,
                    created_at=now,
                    updated_at=now,
                )
            )
    try:
        yield factory, actor, client, connection_id
    finally:
        client.close()
        factory.kw["bind"].dispose()


def test_credential_history_pages_keep_projection_state_and_never_select_ciphertext(
    credential_page,
):
    factory, _actor, client, connection_id = credential_page
    engine, captured = factory.kw["bind"], []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        if "FROM saas_model_credential_versions" in statement:
            captured.append(statement)

    cursor, generations = None, []
    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        for _page in range(5):
            parameters = {"limit": 25, **({"cursor": cursor} if cursor else {})}
            response = client.get(
                f"/v2/platform-admin/model-connections/{connection_id}/credential-versions",
                params=parameters,
            )
            assert response.status_code == 200
            body = response.json()
            assert len(body["items"]) <= 25
            for row in body["items"]:
                assert row["projected"] is bool(row["generation"] % 2)
                generations.append(row["generation"])
            cursor = body["next_cursor"]
            assert "ciphertext:" not in response.text
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert cursor is None and generations == list(range(101, 0, -1))
    assert captured and all("api_key_ciphertext" not in statement for statement in captured)


def test_credential_history_cursor_cannot_be_rebound_to_another_connection(credential_page):
    _factory, _actor, client, connection_id = credential_page
    response = client.get(
        f"/v2/platform-admin/model-connections/{uuid4()}/credential-versions",
        params={"cursor": str(UUID(int=2101))},
    )
    assert response.status_code == 400
    assert str(connection_id) not in response.text


@pytest.fixture
def deployment_page():
    _connections, service, factory, actor, command = _draft_fixture()
    now, identifiers = datetime.now(timezone.utc), []
    with factory.begin() as db:
        for index in range(1, 4):
            identifier = UUID(int=4000 + index)
            compiled = compile_model_deployment_draft(
                replace(command, public_model_id=f"deepseek-page-{index}"),
                deployment_id=identifier,
            )
            identifiers.append(identifier)
            db.add(
                ModelDeploymentVersionRecord(
                    id=identifier,
                    public_model_id=compiled.public_model_id,
                    display_name=compiled.display_name,
                    provider_model=compiled.public_model_id,
                    connection_id=compiled.connection_id,
                    credential_version_id=compiled.credential_version_id,
                    generation=compiled.generation,
                    deployment_alias=compiled.alias,
                    wire_api=compiled.wire_api,
                    max_output_tokens=compiled.max_output_tokens,
                    configuration_sha256=compiled.configuration_sha256,
                    canonical_configuration=compiled.canonical_configuration,
                    created_by_principal_id=actor.principal_id,
                    created_at=now,
                )
            )
            db.add(
                ModelProjectionOperationRecord(
                    id=UUID(int=5000 + index),
                    connection_id=compiled.connection_id,
                    credential_version_id=compiled.credential_version_id,
                    deployment_version_id=identifier,
                    action="create_deployment",
                    actor_principal_id=actor.principal_id,
                    idempotency_key=f"synthetic-deployment-page-{index}",
                    request_hash=compiled.request_hash,
                    status="applied",
                    version=2,
                    created_at=now,
                    updated_at=now,
                )
            )
    try:
        yield service, factory, actor, identifiers
    finally:
        factory.kw["bind"].dispose()


def test_deployment_pages_have_stable_reverse_ties_and_bounded_operation_reads(deployment_page):
    service, factory, actor, identifiers = deployment_page
    engine, statements = factory.kw["bind"], []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        if "FROM saas_model_projection_operations" in statement:
            statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        first = service.page(actor, limit=1)
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert [item.id for item in first.items] == [identifiers[-1]]
    assert len(statements) == 2 and all("LIMIT" in query for query in statements)
    second = service.page(actor, limit=1, cursor=UUID(first.next_cursor))
    third = service.page(actor, limit=1, cursor=UUID(second.next_cursor))
    assert [item.id for item in second.items + third.items] == identifiers[-2::-1]
    assert third.next_cursor is None


def test_sparse_deployment_page_keeps_a_continuation_without_fabricating_an_operation(
    deployment_page,
):
    service, factory, actor, identifiers = deployment_page
    with factory.begin() as db:
        db.execute(
            sa.delete(ModelProjectionOperationRecord).where(
                ModelProjectionOperationRecord.id == UUID(int=5002)
            )
        )
    sparse = service.page(actor, limit=1, cursor=identifiers[-1])
    assert sparse.items == () and sparse.next_cursor == str(identifiers[1])
    last = service.page(actor, limit=1, cursor=UUID(sparse.next_cursor))
    assert [row.id for row in last.items] == [identifiers[0]] and last.next_cursor is None


def test_model_pages_reject_non_integer_limits_before_database_work(connection_page):
    service, _factory, actor, _client = connection_page
    for limit in (True, False, 0, 101):
        with pytest.raises(PlatformSecurityError, match="Model page is invalid"):
            service.page(actor, limit=limit)


def test_current_deployment_generation_does_not_depend_on_the_loaded_page(deployment_page):
    service, _factory, actor, _identifiers = deployment_page
    assert service.page(actor, limit=1).items[0].public_model_id == "deepseek-page-3"
    assert service.current_generation(actor, "deepseek-page-1") == 1
    assert service.current_generation(actor, "deepseek-not-present") == 0
    with pytest.raises(PlatformSecurityError):
        service.current_generation(actor, "untrusted/provider")


@pytest.fixture
def publication_page():
    _service, factory, actor, _cipher, client, _headers = _fixture()
    now, tenant_id, foreign_tenant = datetime.now(timezone.utc), UUID(int=8000), UUID(int=8001)
    with factory.begin() as db:
        for tenant in (tenant_id, foreign_tenant):
            db.add(
                Tenant(
                    id=tenant, slug=f"synthetic-{tenant.hex}", name="Synthetic", home_region="test"
                )
            )
        for identifier, tenant, model, generation in (
            (6001, tenant_id, "deepseek-other", 1),
            (6002, tenant_id, "deepseek-history", 1),
            (6003, tenant_id, "deepseek-history", 2),
            (6004, tenant_id, "deepseek-history", 3),
            (7001, foreign_tenant, "deepseek-foreign", 1),
        ):
            snapshot = json.dumps(
                {
                    "schema_version": 1,
                    "tenant_id": str(tenant),
                    "public_model_id": model,
                    "wire_api": "openai_chat_completions",
                    "generation": generation,
                    "provider_id": "deepseek",
                    "channel_id": "deepseek",
                    "transport": "litellm",
                    "display_name": f"Synthetic {model}",
                    "provider_cost": {"pricing_revision": "synthetic"},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            db.add(
                ModelPublicationVersionRecord(
                    id=UUID(int=identifier),
                    operation_id=uuid4(),
                    tenant_id=tenant,
                    deployment_version_id=uuid4(),
                    public_model_id=model,
                    wire_api="openai_chat_completions",
                    generation=generation,
                    configuration_sha256="a" * 64,
                    price_sha256="b" * 64,
                    inventory_sha256="c" * 64,
                    canonical_snapshot=snapshot,
                    snapshot_sha256=sha256(snapshot.encode()).hexdigest(),
                    canonical_readiness="{}",
                    readiness_sha256=sha256(b"{}").hexdigest(),
                    created_at=now,
                )
            )
    service = ModelPublicationService(
        factory.kw["bind"], authorization=PlatformAuthorizationService(factory), pricing=_pricing()
    )
    try:
        yield service, factory, actor, tenant_id, foreign_tenant
    finally:
        client.close()
        factory.kw["bind"].dispose()


def test_publication_history_pages_preserve_latest_versions_and_sparse_continuation(
    publication_page,
):
    service, _factory, actor, tenant_id, _foreign = publication_page
    cursor, seen, empty_pages = None, [], 0
    for _page in range(4):
        page = service.page(actor, tenant_id=tenant_id, limit=1, cursor=cursor)
        seen.extend((row.public_model_id, row.generation) for row in page.items)
        if not page.items:
            empty_pages += 1
            assert page.next_cursor is not None
        cursor = None if page.next_cursor is None else UUID(page.next_cursor)
    assert cursor is None and empty_pages == 2
    assert seen == [("deepseek-history", 3), ("deepseek-other", 1)]


def test_publication_cursor_is_bound_to_the_checked_tenant(publication_page):
    service, _factory, actor, tenant_id, _foreign = publication_page
    with pytest.raises(PlatformSecurityError, match="Model page is invalid"):
        service.page(actor, tenant_id=tenant_id, limit=1, cursor=UUID(int=7001))
    assert (
        service.current_generation(
            actor,
            tenant_id=tenant_id,
            public_model_id="deepseek-history",
            wire_api="openai_chat_completions",
        )
        == 3
    )
    assert (
        service.current_generation(
            actor,
            tenant_id=tenant_id,
            public_model_id="deepseek-foreign",
            wire_api="openai_chat_completions",
        )
        == 0
    )


@pytest.mark.parametrize("scoped", (False, True))
def test_publication_source_page_and_latest_lookup_use_separate_bounded_indexes(
    publication_page, scoped
):
    service, factory, actor, tenant_id, _foreign = publication_page
    engine, queries = factory.kw["bind"], []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM saas_model_publication_versions" in statement:
            queries.append((statement, parameters))

    sa.event.listen(engine, "before_cursor_execute", capture)
    try:
        service.page(actor, tenant_id=tenant_id if scoped else None, limit=1)
    finally:
        sa.event.remove(engine, "before_cursor_execute", capture)
    assert len(queries) == 2 and all("GROUP BY" not in sql for sql, _params in queries)
    with engine.connect() as connection:
        plans = [
            connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params).all()
            for sql, params in queries
        ]
    expected = "ix_model_publication_tenant_page" if scoped else "ix_model_publication_page"
    assert any(expected in row[-1] for row in plans[0])
    assert all("TEMP B-TREE" not in row[-1] for plan in plans for row in plan)
