from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_deployments import (
    CreateModelDeploymentDraft,
    ModelDeploymentService,
    ModelDeploymentValidationError,
    compile_model_deployment_draft,
)
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_routing_models import (
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
)
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_MAX_OUTPUT_TOKENS
from tests.saas.test_model_connections import _KEY, _Cipher, _fixture, _payload
from tests.saas.test_model_projection import _projection


def _command() -> CreateModelDeploymentDraft:
    return CreateModelDeploymentDraft(
        public_model_id="deepseek-isolated-contract",
        display_name="DeepSeek 隔离候选",
        connection_id=uuid4(),
        credential_version_id=uuid4(),
        expected_generation=0,
        wire_api="openai_chat_completions",
        max_output_tokens=32,
    )


def test_draft_is_deterministic_immutable_and_never_advertises_runtime_availability():
    command, identifier = _command(), uuid4()
    compiled = compile_model_deployment_draft(command, deployment_id=identifier)
    assert compiled == compile_model_deployment_draft(command, deployment_id=identifier)
    assert compiled.runtime_enabled is False and compiled.verification_status == "not_tested"
    assert compiled.public_model_id == command.public_model_id
    assert compiled.alias == "platform-model-" + identifier.hex
    assert compiled.generation == 1
    assert (
        compiled.configuration_sha256
        == sha256(compiled.canonical_configuration.encode("ascii")).hexdigest()
    )
    document = compiled.configuration_document()
    assert document["num_retries"] == document["max_retries"] == 0
    assert document["credential_version_id"] == str(command.credential_version_id)
    assert not {"api_key", "management_key", "credential_values"} & set(document)
    document["max_output_tokens"] = 1_000_000
    assert compiled.configuration_document()["max_output_tokens"] == 32


def test_generated_deployment_identity_does_not_break_request_idempotency():
    command = _command()
    first = compile_model_deployment_draft(command, deployment_id=uuid4())
    second = compile_model_deployment_draft(command, deployment_id=uuid4())
    assert first.request_hash == second.request_hash
    assert first.configuration_sha256 != second.configuration_sha256
    for change in (
        {"credential_version_id": uuid4()},
        {"max_output_tokens": 31},
        {"wire_api": "openai_responses"},
        {"expected_generation": 1},
    ):
        changed = compile_model_deployment_draft(
            replace(command, **change), deployment_id=first.deployment_id
        )
        assert changed.request_hash != first.request_hash
        assert changed.configuration_sha256 != first.configuration_sha256


@pytest.mark.parametrize(
    "change",
    (
        {"public_model_id": "untrusted/provider"},
        {"public_model_id": "deepseek-invalid/key"},
        {"display_name": " hidden "},
        {"display_name": "bad\nlabel"},
        {"connection_id": UUID(int=0)},
        {"credential_version_id": UUID(int=0)},
        {"expected_generation": True},
        {"expected_generation": -1},
        {"expected_generation": (1 << 31) - 1},
        {"wire_api": "custom"},
        {"max_output_tokens": True},
        {"max_output_tokens": 0},
        {"max_output_tokens": PLATFORM_MODEL_MAX_OUTPUT_TOKENS + 1},
    ),
)
def test_invalid_draft_never_echoes_the_payload(change):
    with pytest.raises(ModelDeploymentValidationError) as rejected:
        compile_model_deployment_draft(replace(_command(), **change), deployment_id=uuid4())
    assert str(rejected.value) == "platform_model_deployment_invalid"


def test_deployment_identifier_must_be_nonzero_uuid():
    with pytest.raises(ModelDeploymentValidationError):
        compile_model_deployment_draft(_command(), deployment_id=UUID(int=0))


def _draft_fixture(*, apply_credential=True):
    connections, factory, actor, publisher, envelope, operation = _projection(
        lambda _: httpx.Response(200, json={"status": "success"})
    )
    if apply_credential:
        publisher.publish(**envelope)
    service = ModelDeploymentService(
        factory.kw["bind"], authorization=PlatformAuthorizationService(factory)
    )
    command = replace(
        _command(),
        connection_id=operation.connection_id,
        credential_version_id=operation.credential_version_id,
    )
    return connections, service, factory, actor, command


def test_draft_admission_is_atomic_idempotent_and_never_claims_verification():
    _connections, service, factory, actor, command = _draft_fixture()
    first = service.create(actor, command=command, idempotency_key="create-draft")
    assert first == service.create(actor, command=command, idempotency_key="create-draft")
    assert first.status == "requested" and first.deployment_version_id is not None
    views = service.list(actor)
    assert len(views) == 1 and views[0].id == first.deployment_version_id
    assert views[0].public_model_id == command.public_model_id
    assert views[0].runtime_enabled is False and views[0].verification_status == "not_tested"
    assert service.credential_versions(actor, command.connection_id)[0].projected is True
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelDeploymentVersionRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 2
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(first.id)
            )
        )
        assert event is not None and set(event.payload) == {
            "event_type",
            "operation_id",
            "credential_version_id",
            "schema_version",
        }


def test_draft_generations_use_cas_and_one_idempotency_namespace():
    _connections, service, _factory, actor, command = _draft_fixture()
    first = service.create(actor, command=command, idempotency_key="create-draft")
    for updated, key, code in (
        (
            replace(command, max_output_tokens=31),
            "create-draft",
            "platform_model_operation_conflict",
        ),
        (command, "another-draft", "platform_model_deployment_conflict"),
    ):
        with pytest.raises(PlatformSecurityError) as rejected:
            service.create(actor, command=updated, idempotency_key=key)
        assert rejected.value.code == code
    second = service.create(
        actor, command=replace(command, expected_generation=1), idempotency_key="next-draft"
    )
    assert second.deployment_version_id != first.deployment_version_id
    assert {row.generation for row in service.list(actor)} == {1, 2}
    assert {row.public_model_id for row in service.list(actor)} == {command.public_model_id}


def test_unacknowledged_credential_cannot_admit_a_deployment():
    _connections, service, factory, actor, command = _draft_fixture(apply_credential=False)
    assert service.credential_versions(actor, command.connection_id)[0].projected is False
    with pytest.raises(PlatformSecurityError) as rejected:
        service.create(actor, command=command, idempotency_key="not-ready")
    assert rejected.value.code == "platform_model_credential_not_projected"
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelDeploymentVersionRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent)) == 1


def test_draft_projection_does_not_substitute_for_credential_acknowledgement():
    _connections, service, factory, actor, command = _draft_fixture()
    operation = service.create(actor, command=command, idempotency_key="create-draft")
    with factory.begin() as db:
        db.execute(
            sa.update(ModelProjectionOperationRecord)
            .where(ModelProjectionOperationRecord.action == "create_connection")
            .values(status="uncertain")
        )
        db.execute(
            sa.update(ModelProjectionOperationRecord)
            .where(ModelProjectionOperationRecord.id == operation.id)
            .values(status="applied")
        )
    assert service.credential_versions(actor, command.connection_id)[0].projected is False


def test_draft_requires_the_same_live_fresh_staff_authority():
    _connections, service, _factory, actor, command = _draft_fixture()
    stale = replace(actor, authenticated_at=datetime.now(timezone.utc) - timedelta(minutes=6))
    with pytest.raises(PlatformSecurityError) as rejected:
        service.create(stale, command=command, idempotency_key="stale-draft")
    assert rejected.value.code == "platform_fresh_auth_required"
    assert service.list(actor) == ()


def _http_draft_fixture(*, projected=True):
    connections, factory, _actor, cipher, client, headers = _fixture()
    admitted = client.post(
        "/v2/platform-admin/model-connections", headers=headers, json=_payload()
    )
    assert admitted.status_code == 202
    operation = admitted.json()
    if projected:
        with factory() as db:
            event = db.scalar(sa.select(ControlPlaneOutboxEvent))
            envelope = {
                name: getattr(event, name)
                for name in ("id", "event_type", "aggregate_type", "aggregate_key", "payload")
            }
        envelope["event_id"] = envelope.pop("id")
        publisher = ModelCredentialProjectionPublisher(
            factory.kw["bind"],
            secret_cipher=cipher,
            management=LiteLLMManagementClient(
                LiteLLMManagementConfiguration(
                    base_url="https://litellm.test", management_key="isolated-test-management"
                ),
                transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})),
            ),
        )
        publisher.publish(**envelope)
    command = replace(
        _command(),
        connection_id=UUID(operation["connection_id"]),
        credential_version_id=UUID(operation["credential_version_id"]),
    )
    payload = {
        name: str(value) if isinstance(value, UUID) else value
        for name, value in asdict(command).items()
    }
    return connections, factory, client, {**headers, "Idempotency-Key": "http-draft"}, payload


def test_draft_http_exposes_separate_admission_projection_and_verification_states():
    _connections, _factory, client, headers, payload = _http_draft_fixture()
    metadata = client.get(
        f"/v2/platform-admin/model-connections/{payload['connection_id']}/credential-versions"
    )
    assert metadata.status_code == 200
    assert metadata.json()["items"] == [
        {"id": payload["credential_version_id"], "generation": 1, "projected": True}
    ]
    admitted = client.post("/v2/platform-admin/model-deployments", headers=headers, json=payload)
    assert admitted.status_code == 202
    assert admitted.json()["deployment_version_id"] is not None
    duplicate = client.post("/v2/platform-admin/model-deployments", headers=headers, json=payload)
    assert duplicate.status_code == 202 and duplicate.json()["id"] == admitted.json()["id"]
    recovered = client.get(
        "/v2/platform-admin/model-operations", params={"idempotency_key": "http-draft"}
    )
    assert recovered.json()["operation"]["id"] == admitted.json()["id"]
    listing = client.get("/v2/platform-admin/model-deployments")
    assert listing.status_code == 200
    draft = listing.json()["items"][0]
    assert draft["projection_status"] == "requested"
    assert draft["runtime_enabled"] is False and draft["verification_status"] == "not_tested"
    assert _KEY not in listing.text + metadata.text + admitted.text + recovered.text
    conflict = client.post(
        "/v2/platform-admin/model-deployments",
        headers={**headers, "Idempotency-Key": "stale-generation"},
        json=payload,
    )
    assert conflict.status_code == 409


@pytest.mark.parametrize("missing", ("Origin", "X-CSRF-Token", "Idempotency-Key"))
def test_draft_http_preserves_write_boundary_headers(missing):
    _connections, _factory, client, headers, payload = _http_draft_fixture()
    headers.pop(missing)
    response = client.post("/v2/platform-admin/model-deployments", headers=headers, json=payload)
    assert response.status_code in {400, 401, 403}
    assert client.get("/v2/platform-admin/model-deployments").json()["items"] == []


def test_draft_http_rejects_secrets_in_request_without_echoing_them():
    _connections, _factory, client, headers, payload = _http_draft_fixture()
    response = client.post(
        "/v2/platform-admin/model-deployments",
        headers=headers,
        json={**payload, "api_key": _KEY},
    )
    assert response.status_code == 400 and _KEY not in response.text


def test_draft_http_rechecks_current_staff_role_for_metadata_and_admission():
    _connections, factory, client, headers, payload = _http_draft_fixture()
    with factory.begin() as db:
        db.execute(
            sa.update(PlatformRoleAssignmentRecord).values(role="platform_security_auditor")
        )
    assert client.get("/v2/platform-admin/model-deployments").status_code == 200
    assert (
        client.get(
            f"/v2/platform-admin/model-connections/{payload['connection_id']}/credential-versions"
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v2/platform-admin/model-deployments", headers=headers, json=payload
        ).status_code
        == 403
    )


def test_draft_http_requires_acknowledged_credential_and_explicit_composition():
    _connections, _factory, client, headers, payload = _http_draft_fixture(projected=False)
    response = client.post("/v2/platform-admin/model-deployments", headers=headers, json=payload)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "platform_model_credential_not_projected"
    _connections, _factory, _actor, _cipher, disabled, headers = _fixture(enabled=False)
    context = disabled.get("/v2/platform-admin/context").json()
    assert context["capabilities"]["model_deployments_enabled"] is False
    assert disabled.get("/v2/platform-admin/model-deployments").status_code == 503
    assert (
        disabled.post(
            "/v2/platform-admin/model-deployments", headers=headers, json=payload
        ).status_code
        == 503
    )


@pytest.mark.parametrize("status,expected", ((200, "applied"), (409, "uncertain")))
def test_model_projection_uses_only_named_credentials_once_and_never_verifies(status, expected):
    import json

    _connections, service, factory, actor, command = _draft_fixture()
    operation = service.create(actor, command=command, idempotency_key="project-draft")
    calls = []

    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert request.url.path == "/model/new"
        assert body["model_info"]["id"] == str(operation.deployment_version_id)
        assert body["model_name"] == "platform-model-" + operation.deployment_version_id.hex
        assert body["litellm_params"]["model"] == "deepseek/" + command.public_model_id
        assert (
            body["litellm_params"]["litellm_credential_name"]
            == "platform-credential-" + command.credential_version_id.hex
        )
        assert body["litellm_params"]["num_retries"] == body["litellm_params"]["max_retries"] == 0
        assert "api_key" not in body["litellm_params"]
        return httpx.Response(status, json={"status": "success"})

    management = LiteLLMManagementClient(
        LiteLLMManagementConfiguration(
            base_url="https://litellm.test", management_key="isolated-management-test-secret"
        ),
        transport=httpx.MockTransport(handler),
    )
    # An empty cipher cannot decrypt the stored canonical key; deployment must not need it.
    publisher = ModelCredentialProjectionPublisher(
        factory.kw["bind"], secret_cipher=_Cipher(), management=management
    )
    with factory() as db:
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(operation.id)
            )
        )
        envelope = {
            "event_id": event.id,
            "event_type": event.event_type,
            "aggregate_type": event.aggregate_type,
            "aggregate_key": event.aggregate_key,
            "payload": event.payload,
        }
    publisher.publish(**envelope)
    publisher.publish(**envelope)
    view = service.list(actor)[0]
    assert view.projection_status == expected and view.runtime_enabled is False
    assert view.verification_status == "not_tested" and len(calls) == 1


def test_tampered_draft_fingerprint_is_rejected_before_model_management_access():
    _connections, service, factory, actor, command = _draft_fixture()
    operation = service.create(actor, command=command, idempotency_key="project-draft")
    with factory.begin() as db:
        db.execute(sa.update(ModelDeploymentVersionRecord).values(configuration_sha256="f" * 64))
    management = LiteLLMManagementClient(
        LiteLLMManagementConfiguration(
            base_url="https://litellm.test", management_key="isolated-management-test-secret"
        ),
        transport=httpx.MockTransport(
            lambda _: pytest.fail("tampered draft must not reach LiteLLM")
        ),
    )
    publisher = ModelCredentialProjectionPublisher(
        factory.kw["bind"], secret_cipher=_Cipher(), management=management
    )
    with factory() as db:
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(operation.id)
            )
        )
        envelope = {
            "event_id": event.id,
            "event_type": event.event_type,
            "aggregate_type": event.aggregate_type,
            "aggregate_key": event.aggregate_key,
            "payload": event.payload,
        }
    publisher.publish(**envelope)
    assert service.list(actor)[0].projection_status == "failed"
    with factory() as db:
        record = db.get(ModelProjectionOperationRecord, operation.id)
        assert record.error_code == "model_deployment_projection_invalid"
