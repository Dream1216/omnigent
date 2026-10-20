from __future__ import annotations

import json
from dataclasses import replace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.db_models import SpaceMembership, TenantMembership
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.tenant_model_catalog import TenantModelCatalog, TenantModelCatalogError
from tests.saas import test_model_projection
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_model_connections import _fixture as _connections_fixture
from tests.saas.test_model_publications import _envelope, _fixture
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def _published(priced_execution, monkeypatch):
    fixture = priced_execution
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connections_fixture(engine=fixture.engine)
    )
    service, worker, factory, actor, request, _ = _fixture()
    request["tenant_id"] = fixture.scope.tenant_id
    operation = service.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    runtime = replace(
        _runtime(),
        actor_id=fixture.scope.owner_id,
        tenant_id=fixture.scope.tenant_id,
        space_id=fixture.scope.space_id,
        project_id=fixture.scope.project_id,
    )
    return TenantModelCatalog(fixture.app), runtime


def test_actual_app_login_reads_only_active_customer_scope_and_cannot_manage_models(
    priced_execution, monkeypatch
):
    f = priced_execution
    catalog, runtime = _published(f, monkeypatch)
    rows = catalog.list(runtime)
    assert len(rows) == 1 and rows[0]["available"] is False
    assert rows[0]["unavailable_reason"] == "runtime_not_enabled"
    with f.factory() as db:
        publication = db.scalars(sa.select(ModelPublicationVersionRecord)).one()
        reference = {
            "public_model_id": publication.public_model_id,
            "wire_api": publication.wire_api,
            "generation": publication.generation,
            "snapshot_sha256": publication.snapshot_sha256,
        }
    catalog.require_version(runtime, reference)
    selection = catalog.resolve_selection(
        runtime,
        model_id=rows[0]["model_id"],
        configuration_revision=rows[0]["configuration_revision"],
    )
    assert selection == {"schema_version": 1, **reference}
    for field in ("tenant_id", "space_id", "actor_id"):
        assert catalog.list(replace(runtime, **{field: uuid4()})) == []
        with pytest.raises(TenantModelCatalogError):
            catalog.require_version(replace(runtime, **{field: uuid4()}), reference)
        with pytest.raises(TenantModelCatalogError):
            catalog.resolve_selection(
                replace(runtime, **{field: uuid4()}),
                model_id=rows[0]["model_id"],
                configuration_revision=rows[0]["configuration_revision"],
            )
    with f.app.connect() as connection:
        assert connection.exec_driver_sql("SELECT current_user=session_user").scalar_one()
        assert (
            connection.exec_driver_sql(
                "SELECT public_model_id FROM public.saas_model_publication_versions"
            ).all()
            == []
        )
    for statement in (
        "SELECT canonical_readiness FROM public.saas_model_publication_versions",
        "SELECT id FROM public.saas_model_credential_versions",
        "UPDATE public.saas_model_publication_versions SET generation=generation+1",
        "INSERT INTO public.saas_model_publication_versions DEFAULT VALUES",
    ):
        with pytest.raises(sa.exc.DBAPIError, match="permission denied"):
            with f.app.begin() as connection:
                connection.exec_driver_sql(statement)
    with f.engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {f.table_owner}")
        connection.exec_driver_sql(f.role_sql.read_text())


@pytest.mark.parametrize("membership", [TenantMembership, SpaceMembership])
def test_actual_app_catalog_rechecks_customer_membership_each_read(
    priced_execution, monkeypatch, membership
):
    f = priced_execution
    catalog, runtime = _published(f, monkeypatch)
    rows = catalog.list(runtime)
    assert len(rows) == 1
    with f.factory.begin() as db:
        db.execute(
            sa.update(membership)
            .where(
                membership.tenant_id == runtime.tenant_id, membership.user_id == runtime.actor_id
            )
            .values(status="suspended")
        )
    assert catalog.list(runtime) == []
    with pytest.raises(TenantModelCatalogError):
        catalog.resolve_selection(
            runtime,
            model_id=rows[0]["model_id"],
            configuration_revision=rows[0]["configuration_revision"],
        )


@pytest.mark.parametrize("active", (False, True))
def test_actual_customer_page_plan_bounds_history_with_live_or_suspended_membership(
    priced_execution, monkeypatch, record_property, active
):
    f = priced_execution
    monkeypatch.setattr(
        test_model_projection, "_fixture", lambda: _connections_fixture(engine=f.engine)
    )
    service, worker, factory, actor, request, calls = _fixture()
    request["tenant_id"] = f.scope.tenant_id
    before = list(calls)
    for generation in range(129):
        operation = service.admit(
            actor,
            **{
                **request,
                "expected_generation": generation,
                "idempotency_key": f"catalog-page-plan-{generation:03}",
            },
        )
        worker.publish(**_envelope(factory, operation.id))
    assert calls == before
    runtime = replace(
        _runtime(),
        actor_id=f.scope.owner_id,
        tenant_id=f.scope.tenant_id,
        space_id=f.scope.space_id,
        project_id=f.scope.project_id,
    )
    if not active:
        with f.factory.begin() as db:
            db.execute(
                sa.update(TenantMembership)
                .where(
                    TenantMembership.tenant_id == runtime.tenant_id,
                    TenantMembership.user_id == runtime.actor_id,
                )
                .values(status="suspended")
            )
    with f.engine.begin() as connection:
        connection.exec_driver_sql("ANALYZE public.saas_model_publication_versions")
    captured = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM saas_model_publication_versions" in statement:
            captured.append((statement, parameters))

    sa.event.listen(f.app, "before_cursor_execute", capture)
    try:
        page = TenantModelCatalog(f.app).page(runtime, limit=1)
    finally:
        sa.event.remove(f.app, "before_cursor_execute", capture)
    assert bool(page.items) is active
    if active:
        assert page.items[0]["generation"] == 129 and page.next_cursor is not None
    assert len(captured) == (2 if active else 1)

    def nodes(plan):
        yield plan
        for child in plan.get("Plans", []):
            yield from nodes(child)

    for number, (statement, parameters) in enumerate(captured):
        with Session(f.app) as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=runtime.actor_id,
                    tenant_id=runtime.tenant_id,
                    space_id=runtime.space_id,
                    project_id=runtime.project_id,
                ),
            )
            plan = (
                db.connection()
                .exec_driver_sql("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + statement, parameters)
                .scalar_one()[0]["Plan"]
            )
        scans = [
            node
            for node in nodes(plan)
            if node.get("Relation Name") == "saas_model_publication_versions"
        ]
        assert scans
        record_property(
            f"publication_scan_{number}",
            json.dumps(
                [
                    {
                        key: node.get(key)
                        for key in (
                            "Node Type",
                            "Index Name",
                            "Actual Rows",
                            "Actual Loops",
                            "Rows Removed by Filter",
                            "Rows Removed by Index Recheck",
                        )
                    }
                    for node in scans
                ],
                sort_keys=True,
            ),
        )
        for scan in scans:
            if not scan["Actual Loops"]:
                continue
            examined = (
                sum(
                    scan.get(key, 0)
                    for key in (
                        "Actual Rows",
                        "Rows Removed by Filter",
                        "Rows Removed by Index Recheck",
                    )
                )
                * scan["Actual Loops"]
            )
            assert examined <= 2
            assert scan.get("Index Name") in {
                "ix_model_publication_tenant_page",
                "uq_model_publication_generation",
            }
