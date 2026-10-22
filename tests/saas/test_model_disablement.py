from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_disablement import DISABLEMENT_EVENT
from saas.control_plane.model_routing_models import (
    ModelPublicationDisablementRecord,
    ModelPublicationVersionRecord,
)
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.tenant_model_catalog import TenantModelCatalog, TenantModelCatalogError
from tests.saas.test_agent_catalog import _runtime
from tests.saas.test_model_publications import _envelope, _fixture, _http_fixture


def test_disabled_model_disappears_and_frozen_version_cannot_authorize():
    service, worker, factory, actor, request, calls = _fixture()
    operation = service.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    runtime = replace(_runtime(), tenant_id=request["tenant_id"])
    catalog = TenantModelCatalog(factory.kw["bind"])
    selected = catalog.list(runtime)[0]
    marker = catalog.resolve_selection(
        runtime,
        model_id=selected["model_id"],
        configuration_revision=selected["configuration_revision"],
    )
    with factory() as db:
        publication = db.scalars(sa.select(ModelPublicationVersionRecord)).one()
        publication_id = publication.id
    before = list(calls)
    service.disable(
        actor,
        publication_id=publication_id,
        expected_generation=1,
        idempotency_key="disable-published-001",
    )
    assert catalog.list(runtime) == []
    with pytest.raises(TenantModelCatalogError):
        catalog.require_version(runtime, marker)
    with pytest.raises(TenantModelCatalogError):
        catalog.resolve_selection(
            runtime,
            model_id=selected["model_id"],
            configuration_revision=selected["configuration_revision"],
        )
    assert calls == before


def _published():
    service, worker, factory, actor, request, calls = _fixture()
    operation = service.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    return service, worker, factory, actor, request, calls


def _command(service, actor):
    row = service.list(actor)[0]
    return {
        "publication_id": row.id,
        "expected_generation": row.generation,
        "idempotency_key": "disable-published-001",
    }


def test_disablement_is_durable_idempotent_and_keeps_the_published_snapshot():
    service, _, factory, actor, _, calls = _published()
    command = _command(service, actor)
    before = list(calls)
    with factory() as db:
        original = db.get(ModelPublicationVersionRecord, command["publication_id"])
        frozen = original.canonical_snapshot, original.snapshot_sha256
    receipt = service.disable(actor, **command)
    assert service.disable(actor, **command) == receipt
    assert receipt["disabled"] is True and receipt["runtime_enabled"] is False
    with pytest.raises(PlatformSecurityError, match="changed"):
        service.disable(actor, **{**command, "expected_generation": 2})
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationDisablementRecord))
            == 1
        )
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == DISABLEMENT_EVENT
                )
            )
        )
        assert len(events) == 1
        assert events[0].payload == {
            "event_type": DISABLEMENT_EVENT,
            "schema_version": 1,
            "disablement_id": str(receipt["disablement_id"]),
        }
        assert db.scalar(sa.text("SELECT count(*) FROM saas_customer_ledger_entries")) == 0
        original = db.get(ModelPublicationVersionRecord, command["publication_id"])
        assert (original.canonical_snapshot, original.snapshot_sha256) == frozen
    assert calls == before


def test_new_publication_does_not_resurrect_a_disabled_frozen_generation():
    service, worker, factory, actor, request, _ = _published()
    runtime = replace(_runtime(), tenant_id=request["tenant_id"])
    catalog = TenantModelCatalog(factory.kw["bind"])
    old = catalog.list(runtime)[0]
    marker = catalog.resolve_selection(
        runtime, model_id=old["model_id"], configuration_revision=old["configuration_revision"]
    )
    service.disable(actor, **_command(service, actor))
    newer = service.admit(
        actor,
        **{**request, "expected_generation": 1, "idempotency_key": "publish-after-disable-002"},
    )
    worker.publish(**_envelope(factory, newer.id))
    current = catalog.list(runtime)[0]
    assert current["generation"] == 2
    selected = catalog.resolve_selection(
        runtime,
        model_id=current["model_id"],
        configuration_revision=current["configuration_revision"],
    )
    catalog.require_version(runtime, selected)
    with pytest.raises(TenantModelCatalogError, match="disabled"):
        catalog.require_version(runtime, marker)


@pytest.mark.parametrize(
    "change", ["generation", "missing", "bool", "zero", "key", "fresh", "role"]
)
def test_disablement_rejects_stale_or_unauthorized_commands_without_a_cutoff(change):
    service, _, factory, actor, _, _ = _published()
    command = _command(service, actor)
    if change == "generation":
        command["expected_generation"] = 2
    elif change == "missing":
        command["publication_id"] = uuid4()
    elif change == "bool":
        command["expected_generation"] = True
    elif change == "zero":
        command["publication_id"] = UUID(int=0)
    elif change == "key":
        command["idempotency_key"] = "bad key"
    elif change == "fresh":
        actor = replace(actor, authenticated_at=actor.authenticated_at - timedelta(minutes=6))
    else:
        with factory.begin() as db:
            db.scalar(sa.select(PlatformRoleAssignmentRecord)).status = "revoked"
    with pytest.raises(PlatformSecurityError):
        service.disable(actor, **command)
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationDisablementRecord))
            == 0
        )


@pytest.mark.parametrize("change", [None, "csrf", "origin", "tenant", "extra", "bool", "auditor"])
def test_http_disablement_uses_staff_csrf_freshness_and_exact_command(change):
    client, headers, publish_path, body, factory, _, worker, calls = _http_fixture()
    result = client.post(publish_path, headers=headers, json=body)
    assert result.status_code == 202, result.text
    worker.publish(**_envelope(factory, result.json()["id"]))
    with factory() as db:
        publication_id = db.scalars(sa.select(ModelPublicationVersionRecord.id)).one()
    path = f"/v2/platform-admin/model-publications/{publication_id}/disable"
    headers["Idempotency-Key"] = "disable-http-001"
    command = {"expected_generation": 1}
    if change == "csrf":
        headers.pop("X-CSRF-Token")
    elif change == "origin":
        headers["Origin"] = "https://tenant.example.test"
    elif change == "tenant":
        client.cookies.clear()
        client.cookies.set("__Host-omnigent_saas_session", "not-a-staff-token")
    elif change == "extra":
        command["tenant_id"] = str(uuid4())
    elif change == "bool":
        command["expected_generation"] = True
    elif change == "auditor":
        with factory.begin() as db:
            db.scalar(sa.select(PlatformRoleAssignmentRecord)).role = "platform_security_auditor"
    before = list(calls)
    response = client.post(path, json=command, headers=headers)
    expected = {
        None: 200,
        "csrf": 403,
        "origin": 401,
        "tenant": 401,
        "extra": 400,
        "bool": 400,
        "auditor": 403,
    }
    assert response.status_code == expected[change], response.text
    assert calls == before
    with factory() as db:
        assert db.scalar(
            sa.select(sa.func.count()).select_from(ModelPublicationDisablementRecord)
        ) == (1 if change is None else 0)
    if change is None:
        assert (
            client.post(path, json=command, headers=headers).json()["disablement_id"]
            == response.json()["disablement_id"]
        )
