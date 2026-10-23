from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.model_routing_models import (
    ModelPublicationRevocationRecord,
    ModelPublicationVersionRecord,
)
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import PlatformSecurityError
from tests.saas.test_model_disablement import _command, _published
from tests.saas.test_model_disablement_receipts import _http_disabled
from tests.saas.test_model_publications import _envelope, _http_fixture


def test_staff_can_escalate_a_cutoff_to_a_distinct_durable_security_intent():
    client, headers, path, body, factory, _, worker, calls = _http_fixture()
    published = client.post(path, headers=headers, json=body)
    assert published.status_code == 202
    worker.publish(**_envelope(factory, published.json()["id"]))
    with factory() as db:
        publication_id = db.scalars(sa.select(ModelPublicationVersionRecord.id)).one()
    headers["Idempotency-Key"] = "cutoff-before-security-001"
    cutoff = client.post(
        f"/v2/platform-admin/model-publications/{publication_id}/disable",
        headers=headers,
        json={"expected_generation": 1},
    )
    assert cutoff.status_code == 200
    disablement_id = cutoff.json()["disablement_id"]
    headers["Idempotency-Key"] = "security-revocation-001"
    path = f"/v2/platform-admin/model-publication-disablements/{disablement_id}/revoke"
    before = list(calls)
    result = client.post(path, headers=headers, json={"expected_generation": 1})
    assert result.status_code == 202, result.text
    receipt = result.json()
    assert UUID(receipt["revocation_id"]).int
    assert receipt["disablement_id"] == disablement_id
    assert receipt["revocation_requested"] is True
    assert receipt["execution_complete"] is False
    assert calls == before
    replay = client.post(path, headers=headers, json={"expected_generation": 1})
    assert replay.status_code == 202 and replay.json()["revocation_id"] == receipt["revocation_id"]
    with factory() as db:
        events = list(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type
                    == "platform.model_publication.revocation_requested"
                )
            )
        )
        assert len(events) == 1
        assert events[0].payload == {
            "event_type": "platform.model_publication.revocation_requested",
            "schema_version": 1,
            "revocation_id": receipt["revocation_id"],
        }
    found = client.get(
        "/v2/platform-admin/model-publication-revocations",
        params={"idempotency_key": headers["Idempotency-Key"]},
    )
    assert (
        found.status_code == 200
        and found.json()["revocation"]["revocation_id"] == receipt["revocation_id"]
    )
    read = client.get(
        f"/v2/platform-admin/model-publication-revocations/{receipt['revocation_id']}"
    )
    assert read.status_code == 200 and read.json()["execution_complete"] is False
    assert "operation_id" not in read.json()


@pytest.mark.parametrize(
    "change", ("csrf", "origin", "realm", "auditor", "generation", "bool", "extra", "missing")
)
def test_revocation_http_rejects_unauthorized_or_changed_scope_without_intent(change):
    client, headers, _, cutoff, factory, _, calls = _http_disabled()
    headers["Idempotency-Key"] = "security-reject-001"
    command = {"expected_generation": 1}
    identifier = cutoff["disablement_id"]
    if change == "csrf":
        headers.pop("X-CSRF-Token")
    elif change == "origin":
        headers["Origin"] = "https://tenant.example.test"
    elif change == "realm":
        client.cookies.clear()
        client.cookies.set("__Host-omnigent_saas_session", "not-a-staff-session")
    elif change == "auditor":
        with factory.begin() as db:
            db.scalar(sa.select(PlatformRoleAssignmentRecord)).role = "platform_security_auditor"
    elif change == "generation":
        command["expected_generation"] = 2
    elif change == "bool":
        command["expected_generation"] = True
    elif change == "extra":
        command["tenant_id"] = str(uuid4())
    else:
        identifier = str(uuid4())
    before = list(calls)
    result = client.post(
        f"/v2/platform-admin/model-publication-disablements/{identifier}/revoke",
        headers=headers,
        json=command,
    )
    assert (
        result.status_code
        == {
            "csrf": 403,
            "origin": 401,
            "realm": 401,
            "auditor": 403,
            "generation": 409,
            "bool": 400,
            "extra": 400,
            "missing": 409,
        }[change]
    ), result.text
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationRevocationRecord))
            == 0
        )
    assert calls == before


@pytest.mark.parametrize("change", ("stale", "expired", "role", "key", "zero"))
def test_service_rechecks_current_staff_and_freshness_before_retaining_intent(change):
    service, _, factory, actor, _, calls = _published()
    cutoff = service.disable(actor, **_command(service, actor))
    command = {
        "disablement_id": cutoff["disablement_id"],
        "expected_generation": 1,
        "idempotency_key": "security-current-001",
    }
    if change == "stale":
        actor = replace(actor, authenticated_at=actor.authenticated_at - timedelta(minutes=6))
    elif change == "expired":
        actor = replace(actor, expires_at=actor.authenticated_at - timedelta(seconds=1))
    elif change == "role":
        with factory.begin() as db:
            db.scalar(sa.select(PlatformRoleAssignmentRecord)).status = "revoked"
    elif change == "key":
        command["idempotency_key"] = "bad key"
    else:
        command["disablement_id"] = UUID(int=0)
    before = list(calls)
    with pytest.raises(PlatformSecurityError):
        service.security_revocations.request(actor, **command)
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationRevocationRecord))
            == 0
        )
    assert calls == before
