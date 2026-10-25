from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import PlatformSecurityError, PlatformSessionService
from tests.saas.test_model_disablement import _command, _published
from tests.saas.test_model_publications import _envelope, _http_fixture


def test_staff_catalog_and_original_publication_receipt_show_current_disablement():
    service, worker, factory, actor, request, calls = _published()
    publication = service.list(actor)[0]
    assert publication.disabled is False and publication.disablement_id is None
    command = _command(service, actor)
    before = list(calls)
    disabled = service.disable(actor, **command)
    current = service.list(actor)[0]
    assert current.disabled is True
    assert current.disablement_id == disabled["disablement_id"]
    assert current.disabled_through_generation == 1
    assert current.disabled_at == disabled["created_at"]
    assert service.receipt(actor, publication.operation_id)["publication"]["disabled"] is True
    assert service.find_disablement(actor, idempotency_key=command["idempotency_key"]) == disabled
    assert service.disablement_receipt(actor, disabled["disablement_id"]) == disabled
    assert calls == before
    operation = service.admit(
        actor, **{**request, "expected_generation": 1, "idempotency_key": "new-after-disable"}
    )
    worker.publish(**_envelope(factory, operation.id))
    assert service.list(actor)[0].generation == 2
    assert service.list(actor)[0].disabled is False
    original = service.receipt(actor, publication.operation_id)["publication"]
    assert (
        original["disabled"] is True and original["disablement_id"] == disabled["disablement_id"]
    )
    assert asdict(current)["runtime_enabled"] is False


@pytest.mark.parametrize("key", ("", "bad key", "x" * 129))
def test_disablement_lookup_rejects_invalid_opaque_command_keys(key):
    service, _, _, actor, _, _ = _published()
    with pytest.raises(PlatformSecurityError, match="prerequisites") as rejected:
        service.find_disablement(actor, idempotency_key=key)
    assert rejected.value.code == "platform_model_disablement_invalid"


def _http_disabled():
    client, headers, path, body, factory, actor, worker, calls = _http_fixture()
    operation = client.post(path, headers=headers, json=body).json()
    worker.publish(**_envelope(factory, operation["id"]))
    publication = client.get("/v2/platform-admin/model-publications").json()["items"][0]
    headers = {**headers, "Idempotency-Key": "disable-receipt-http-001"}
    result = client.post(
        f"/v2/platform-admin/model-publications/{publication['id']}/disable",
        headers=headers,
        json={"expected_generation": 1},
    )
    assert result.status_code == 200, result.text
    return client, headers, publication, result.json(), factory, actor, calls


def test_disablement_http_recovers_synchronous_receipt_without_creating_an_operation():
    client, headers, publication, receipt, _, _, calls = _http_disabled()
    before = list(calls)
    found = client.get(
        "/v2/platform-admin/model-publication-disablements",
        params={"idempotency_key": headers["Idempotency-Key"]},
    )
    assert found.status_code == 200, found.text
    assert found.json()["disablement"]["disablement_id"] == receipt["disablement_id"]
    read = client.get(
        f"/v2/platform-admin/model-publication-disablements/{receipt['disablement_id']}"
    )
    assert read.status_code == 200, read.text
    assert read.json()["disablement_id"] == receipt["disablement_id"]
    assert "operation_id" not in read.json()
    assert (
        client.get(
            "/v2/platform-admin/model-publication-disablements",
            params={"idempotency_key": "unknown-but-valid"},
        ).json()["disablement"]
        is None
    )
    item = client.get("/v2/platform-admin/model-publications").json()["items"][0]
    assert item["disabled"] is True and item["id"] == publication["id"]
    assert item["disablement_id"] == receipt["disablement_id"]
    assert calls == before


@pytest.mark.parametrize("lookup", ("command", "receipt"))
def test_disablement_receipt_requires_staff_realm(lookup):
    client, headers, _, receipt, _, _, calls = _http_disabled()
    client.cookies.clear()
    client.cookies.set("__Host-omnigent_saas_session", "not-a-staff-session")
    path = (
        "/v2/platform-admin/model-publication-disablements?idempotency_key="
        + headers["Idempotency-Key"]
        if lookup == "command"
        else f"/v2/platform-admin/model-publication-disablements/{receipt['disablement_id']}"
    )
    before = list(calls)
    assert client.get(path).status_code == 401
    assert calls == before


def test_disablement_command_lookup_is_principal_bound_and_auditor_receipts_are_readonly():
    client, headers, publication, receipt, factory, actor, calls = _http_disabled()
    origin, now = "https://staff.example.test", datetime.now(timezone.utc)
    sessions = PlatformSessionService(factory, origin=origin, audience="model-management")
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    principal = passwords.provision_account(
        username="receipt-auditor", password="isolated-receipt-auditor-password", now=now
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal,
                role="platform_security_auditor",
                status="active",
                version=1,
                assigned_by_principal_id=actor.principal_id,
                approval_ref="isolated-test",
                reason="isolated receipt reader",
                created_at=now,
                updated_at=now,
            )
        )
    issued = passwords.authenticate(
        "receipt-auditor", "isolated-receipt-auditor-password", now=now
    )
    with TestClient(client.app, base_url=origin) as auditor:
        auditor.cookies.set("__Host-omnigent_platform_session", issued.token)
        found = auditor.get(
            "/v2/platform-admin/model-publication-disablements",
            params={"idempotency_key": headers["Idempotency-Key"]},
        )
        assert found.status_code == 200 and found.json()["disablement"] is None
        read = auditor.get(
            f"/v2/platform-admin/model-publication-disablements/{receipt['disablement_id']}"
        )
        assert read.status_code == 200 and read.json()["disabled"] is True
        before = list(calls)
        denied = auditor.post(
            f"/v2/platform-admin/model-publications/{publication['id']}/disable",
            headers={
                "Origin": origin,
                "X-CSRF-Token": issued.csrf_token,
                "Idempotency-Key": "auditor-must-not-disable",
            },
            json={"expected_generation": 1},
        )
        assert denied.status_code == 403 and calls == before
