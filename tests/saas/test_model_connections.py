from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import ControlPlaneOutboxEvent, SaasBase
from saas.control_plane.model_connections import CreateModelConnection, ModelConnectionService
from saas.control_plane.model_deployments import ModelDeploymentService
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelProjectionOperationRecord,
)
from saas.control_plane.model_test_funding import ModelTestFundingService
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSecurityError,
    PlatformSessionService,
)

_ORIGIN = "https://staff.example.test"
_KEY = "test-connection-secret-not-public"


class _Cipher:
    def __init__(self):
        self.values = {}
        self.fail = False

    def encrypt(self, plaintext, *, context):
        if self.fail:
            raise RuntimeError("private KMS details " + plaintext)
        assert context["account_id"].startswith("model_connection:")
        token = "ciphertext:" + uuid4().hex
        self.values[token] = (plaintext, context)
        return token

    def decrypt(self, ciphertext, *, context):
        value, expected = self.values[ciphertext]
        assert expected == context
        return value


def _fixture(*, enabled=True, engine=None):
    if engine is None:
        engine = sa.create_engine(
            "sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=_ORIGIN, audience="model-management")
    passwords = PlatformPasswordAuthenticationService(factory, sessions)
    principal_id = passwords.provision_account(
        username="model-operator", password="model-operator-test-password", now=now
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal_id,
                assigned_by_principal_id=principal_id,
                role="platform_operator",
                status="active",
                version=1,
                approval_ref="test-bootstrap",
                reason="isolated fixture",
                created_at=now,
                updated_at=now,
            )
        )
    issued = passwords.authenticate("model-operator", "model-operator-test-password", now=now)
    actor = sessions.validate_session(issued.token, origin=_ORIGIN, audience="model-management")
    cipher = _Cipher()
    service = ModelConnectionService(factory, authorization=authorization, secret_cipher=cipher)
    config = PlatformHttpConfig(enabled=True, origin=_ORIGIN, audience="model-management")
    app = create_platform_admin_app(
        config=config,
        sessions=sessions,
        authorization=authorization,
        projections=PlatformProjectionService(factory),
        model_connections=service if enabled else None,
        model_deployments=ModelDeploymentService(engine, authorization=authorization)
        if enabled
        else None,
        model_test_funding=ModelTestFundingService(engine, authorization=authorization)
        if enabled
        else None,
    )
    client = TestClient(app, base_url=_ORIGIN)
    client.cookies.set(config.cookie_name, issued.token)
    headers = {
        "Origin": _ORIGIN,
        "X-CSRF-Token": issued.csrf_token,
        "Idempotency-Key": "create-001",
    }
    return service, factory, actor, cipher, client, headers


def _payload(**overrides):
    return {
        "expected_version": 0,
        "display_name": "DeepSeek production candidate",
        "provider_id": "deepseek",
        "base_url": "https://api.deepseek.com",
        "api_key": _KEY,
        **overrides,
    }


def test_connection_http_admits_one_durable_operation_and_never_enables_runtime():
    service, factory, actor, _cipher, client, headers = _fixture()
    response = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload()
    )
    assert response.status_code == 202
    assert response.json()["status"] == "requested"
    duplicate = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload()
    )
    assert duplicate.status_code == 202
    assert duplicate.json()["id"] == response.json()["id"]
    found = client.get(
        "/v2/platform-admin/model-operations", params={"idempotency_key": "create-001"}
    )
    assert found.status_code == 200
    assert found.json()["operation"]["id"] == response.json()["id"]
    missing = client.get(
        "/v2/platform-admin/model-operations", params={"idempotency_key": "not-submitted"}
    )
    assert missing.json()["operation"] is None
    operation = client.get("/v2/platform-admin/model-operations/" + response.json()["id"])
    assert operation.json()["status"] == "requested"
    listing = client.get("/v2/platform-admin/model-connections")
    assert listing.status_code == 200
    assert listing.json()["items"][0]["credential_configured"] is True
    assert listing.json()["items"][0]["runtime_enabled"] is False
    assert _KEY not in response.text + listing.text + operation.text + repr(service.list(actor))
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelConnectionRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelCredentialVersionRecord)) == 1
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelProjectionOperationRecord)) == 1
        )
        event = db.scalar(sa.select(ControlPlaneOutboxEvent))
        assert event is not None and event.tenant_id is None
        assert event.published_at is None and event.attempt_count == 0
        assert set(event.payload) == {
            "event_type",
            "operation_id",
            "credential_version_id",
            "schema_version",
        }
        assert _KEY not in json.dumps(event.payload)
        credential = db.scalar(sa.select(ModelCredentialVersionRecord))
        assert credential is not None and _KEY not in credential.api_key_ciphertext
    assert "test-connection-secret" not in repr(CreateModelConnection("candidate", _KEY))


@pytest.mark.parametrize(
    "overrides", ({"display_name": "different"}, {"api_key": "different-test-secret-value"})
)
def test_idempotency_conflict_checks_plaintext_without_persisting_a_secret_hash(overrides):
    _service, _factory, _actor, _cipher, client, headers = _fixture()
    assert (
        client.post(
            "/v2/platform-admin/model-connections", headers=headers, json=_payload()
        ).status_code
        == 202
    )
    response = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload(**overrides)
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "platform_model_operation_conflict"
    assert _KEY not in response.text


def test_rotation_is_append_only_cas_protected_and_does_not_replay_old_operation():
    service, factory, actor, _cipher, client, headers = _fixture()
    original = service.create(
        actor, command=CreateModelConnection("candidate", _KEY), idempotency_key="create-original"
    )
    key = "next-connection-secret-not-public"
    path = f"/v2/platform-admin/model-connections/{original.connection_id}/credential-versions"
    payload = {"expected_version": 1, "api_key": key}
    created = client.post(path, headers=headers, json=payload)
    assert created.status_code == 202
    assert client.post(path, headers=headers, json=payload).json()["id"] == created.json()["id"]
    stale_headers = {**headers, "Idempotency-Key": "different-command"}
    assert client.post(path, headers=stale_headers, json=payload).status_code == 409
    replay = service.create(
        actor, command=CreateModelConnection("candidate", _KEY), idempotency_key="create-original"
    )
    assert asdict(replay) == asdict(original)
    with factory() as db:
        records = db.scalars(
            sa.select(ModelCredentialVersionRecord).order_by(
                ModelCredentialVersionRecord.generation
            )
        ).all()
        assert [row.generation for row in records] == [1, 2]
        assert records[0].credential_name != records[1].credential_name
    assert service.list(actor)[0].version == 2


@pytest.mark.parametrize("condition", ("expired", "stale", "revoked", "roleless"))
def test_live_staff_authority_is_required_before_secret_storage(condition):
    service, factory, actor, cipher, _client, _headers = _fixture()
    now = datetime.now(timezone.utc)
    if condition == "expired":
        actor = replace(actor, expires_at=now - timedelta(seconds=1))
    elif condition == "stale":
        actor = replace(actor, authenticated_at=now - timedelta(minutes=6))
    elif condition == "roleless":
        actor = replace(actor, permissions=frozenset())
    else:
        with factory.begin() as db:
            db.execute(sa.update(PlatformRoleAssignmentRecord).values(status="revoked"))
    with pytest.raises(PlatformSecurityError):
        service.create(
            actor,
            command=CreateModelConnection("candidate", _KEY),
            idempotency_key="rejected",
            now=now,
        )
    assert not cipher.values
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 0


def test_secret_backend_failure_is_atomic_and_redacted():
    _service, factory, _actor, cipher, client, headers = _fixture()
    cipher.fail = True
    response = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload()
    )
    assert response.status_code == 503
    assert _KEY not in response.text and "KMS" not in response.text
    with factory() as db:
        for table in (
            ModelConnectionRecord,
            ModelCredentialVersionRecord,
            ModelProjectionOperationRecord,
            ControlPlaneOutboxEvent,
        ):
            assert db.scalar(sa.select(sa.func.count()).select_from(table)) == 0


@pytest.mark.parametrize(
    "headers_to_remove", (("X-CSRF-Token",), ("Origin",), ("Idempotency-Key",))
)
def test_http_rejects_missing_boundary_headers(headers_to_remove):
    _service, _factory, _actor, cipher, client, headers = _fixture()
    for name in headers_to_remove:
        headers.pop(name)
    response = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload()
    )
    assert response.status_code in {400, 401, 403}
    assert not cipher.values


@pytest.mark.parametrize(
    "overrides",
    (
        {"base_url": "http://169.254.169.254"},
        {"api_key": "short"},
        {"display_name": "line\nbreak"},
        {"expected_version": True},
        {"api_base": "https://unapproved.test"},
    ),
)
def test_strict_request_contract_is_redacted_before_admission(overrides):
    _service, _factory, _actor, cipher, client, headers = _fixture()
    response = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload(**overrides)
    )
    assert response.status_code == 400
    assert _KEY not in response.text
    assert not cipher.values


def test_missing_composition_is_explicitly_unavailable():
    _service, _factory, _actor, _cipher, client, headers = _fixture(enabled=False)
    assert (
        client.get("/v2/platform-admin/context").json()["capabilities"][
            "model_connections_enabled"
        ]
        is False
    )
    assert client.get("/v2/platform-admin/model-connections").status_code == 503
    assert (
        client.post(
            "/v2/platform-admin/model-connections", headers=headers, json=_payload()
        ).status_code
        == 503
    )


def test_unknown_operation_is_not_found():
    _service, _factory, _actor, _cipher, client, _headers = _fixture()
    response = client.get(f"/v2/platform-admin/model-operations/{UUID(int=1)}")
    assert response.status_code == 404
