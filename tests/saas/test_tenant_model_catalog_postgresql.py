from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import SpaceMembership, TenantMembership
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
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
