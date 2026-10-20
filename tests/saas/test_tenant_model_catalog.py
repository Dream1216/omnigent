from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from saas.control_plane.tenant_model_catalog import TenantModelCatalog, TenantModelCatalogError
from saas.production.tenant_model_catalog import create_tenant_model_catalog_router
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login
from tests.saas.test_model_publications import _envelope, _fixture


@pytest.mark.parametrize("responses", [False, True])
def test_tenant_catalog_reads_only_latest_safe_metadata_without_enabling_inference(responses):
    service, worker, factory, actor, request, calls = _fixture(responses=responses)
    first = service.admit(actor, **request)
    worker.publish(**_envelope(factory, first.id))
    later = service.admit(
        actor, **{**request, "expected_generation": 1, "idempotency_key": "next-publication-001"}
    )
    worker.publish(**_envelope(factory, later.id))
    before = len(calls)
    catalog = TenantModelCatalog(factory.kw["bind"])
    runtime = replace(_runtime(), tenant_id=request["tenant_id"])
    rows = catalog.list(runtime)
    assert len(rows) == 1 and rows[0]["generation"] == 2
    assert rows[0]["available"] is False
    assert rows[0]["unavailable_reason"] == "runtime_not_enabled"
    assert rows[0]["transport"] == "litellm"
    assert set(rows[0]) == {
        "model_id",
        "display_name",
        "provider_id",
        "channel_id",
        "transport",
        "wire_api",
        "generation",
        "configuration_revision",
        "available",
        "unavailable_reason",
    }
    assert catalog.list(replace(runtime, tenant_id=uuid4())) == []
    assert catalog.list(runtime) == rows and len(calls) == before
    serialized = json.dumps(rows)
    assert str(request["deployment_id"]) not in serialized
    assert "provider_cost" not in serialized and "credential" not in serialized


@pytest.mark.parametrize("bad_snapshot", [False, True])
def test_tenant_catalog_rejects_bad_digest_or_misbound_metadata(bad_snapshot):
    service, worker, factory, actor, request, _ = _fixture()
    operation = service.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    with factory.begin() as db:
        row = db.scalar(sa.select(ModelPublicationVersionRecord))
        if bad_snapshot:
            snapshot = json.loads(row.canonical_snapshot)
            snapshot["tenant_id"] = str(uuid4())
            row.canonical_snapshot = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
            row.snapshot_sha256 = sha256(row.canonical_snapshot.encode("ascii")).hexdigest()
        else:
            row.snapshot_sha256 = "0" * 64
    with pytest.raises(TenantModelCatalogError, match="unavailable"):
        TenantModelCatalog(factory.kw["bind"]).list(
            replace(_runtime(), tenant_id=request["tenant_id"])
        )


def test_catalog_route_requires_live_runtime_auth_and_does_not_accept_scope_from_query():
    app, scope = _build_fastapi_app()
    app.include_router(
        create_tenant_model_catalog_router(
            auth_provider=app.state.saas_test_auth,
            catalog=TenantModelCatalog(app.state.saas_test_engine),
        ),
        prefix="/v1",
    )
    with TestClient(app) as client:
        assert client.get("/v1/managed-model-catalog").status_code == 401
        _login(client)
        result = client.get("/v1/managed-model-catalog")
        assert result.status_code == 200
        assert result.json() == {"models": [], "runtime_enabled": False, "next_cursor": None}
        assert result.headers["cache-control"] == "private, no-store"
        assert (
            client.get(
                "/v1/managed-model-catalog", params={"tenant_id": scope["tenant_id"]}
            ).status_code
            == 400
        )
        assert client.get(
            "/v1/managed-model-catalog",
            headers={"x-saas-tenant-id": str(uuid4()), "x-saas-space-id": scope["space_id"]},
        ).status_code in {401, 403}


def test_stored_publication_verification_pins_the_exact_immutable_version():
    service, worker, factory, actor, request, calls = _fixture()
    first = service.admit(actor, **request)
    worker.publish(**_envelope(factory, first.id))
    with factory() as db:
        row = db.scalars(sa.select(ModelPublicationVersionRecord)).one()
        reference = {
            "public_model_id": row.public_model_id,
            "wire_api": row.wire_api,
            "generation": row.generation,
            "snapshot_sha256": row.snapshot_sha256,
        }
    later = service.admit(
        actor, **{**request, "expected_generation": 1, "idempotency_key": "next-publication-001"}
    )
    worker.publish(**_envelope(factory, later.id))
    runtime = replace(_runtime(), tenant_id=request["tenant_id"])
    catalog = TenantModelCatalog(factory.kw["bind"])
    before = list(calls)
    catalog.require_version(runtime, reference)
    selection = catalog.list(runtime)[0]
    selected = catalog.resolve_selection(
        runtime,
        model_id=selection["model_id"],
        configuration_revision=selection["configuration_revision"],
    )
    assert selected["generation"] == 2 and selected["schema_version"] == 1
    for invalid_model, invalid_revision in (
        (
            selection["model_id"],
            f"managed-model:{reference['wire_api']}:1:{reference['snapshot_sha256']}",
        ),
        ("unpublished", selection["configuration_revision"]),
        (selection["model_id"], selection["configuration_revision"] + ":extra"),
        (selection["model_id"], "managed-model:openai_responses:01:" + "a" * 64),
    ):
        with pytest.raises(TenantModelCatalogError):
            catalog.resolve_selection(
                runtime, model_id=invalid_model, configuration_revision=invalid_revision
            )
    with pytest.raises(TenantModelCatalogError):
        catalog.resolve_selection(
            replace(runtime, tenant_id=uuid4()),
            model_id=selection["model_id"],
            configuration_revision=selection["configuration_revision"],
        )
    for invalid in (
        {**reference, "generation": True},
        {**reference, "generation": 3},
        {**reference, "wire_api": "other"},
        {**reference, "snapshot_sha256": "0" * 64},
    ):
        with pytest.raises(TenantModelCatalogError):
            catalog.require_version(runtime, invalid)
    with pytest.raises(TenantModelCatalogError):
        catalog.require_version(replace(runtime, tenant_id=uuid4()), reference)
    assert calls == before
