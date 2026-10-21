from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from saas.control_plane.db_models import ControlPlaneOutboxEvent, Tenant
from saas.control_plane.litellm_client import LiteLLMManagementConfiguration
from saas.control_plane.model_connections import ModelConnectionService
from saas.control_plane.model_publications import ModelPublicationService
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelPublicationCommandRecord,
    ModelPublicationVersionRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    PlatformAuthSessionRecord,
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_password_auth import PlatformPasswordAuthenticationService
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSecurityError,
    PlatformSessionService,
)
from saas.production.litellm_replica_readiness import (
    LiteLLMReplicaObservation,
    LiteLLMReplicaReadiness,
    LiteLLMReplicaReadinessError,
    _inventory_digest,
)
from saas.production.model_publication import (
    ModelPublicationPublisher,
    load_litellm_replica_inventory,
    model_publication_enabled,
)
from tests.saas.test_model_verification_worker import _StoredAttestor, _worker_fixture


class _Readiness:
    def __init__(self, hook=None, *, stale=False, clock=None):
        self.calls, self.hook, self.stale, self.unavailable = 0, hook, stale, False
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.endpoints = [(f"replica-{n}", str(n + 1) * 64) for n in range(2)]
        self.inventory_sha256 = _inventory_digest(self.endpoints)

    async def attest(self, *, draft, credential_name, expected_api_key):
        self.calls += 1
        assert expected_api_key == "test-connection-secret-not-public"
        assert credential_name
        if self.unavailable:
            raise LiteLLMReplicaReadinessError("litellm_replica_readiness_unavailable")
        if self.hook:
            self.hook()
        now = self.clock() - timedelta(seconds=31 if self.stale else 0)
        return LiteLLMReplicaReadiness(
            draft.deployment_id,
            draft.credential_version_id,
            draft.configuration_sha256,
            "a" * 64,
            self.inventory_sha256,
            tuple(
                LiteLLMReplicaObservation(name, endpoint, now) for name, endpoint in self.endpoints
            ),
            now,
            now,
        )


def _fixture(*, stored=True, settle=True, hook=None, stale=False, responses=False):
    verifier, test_event, _, factory, verification, actor, test, calls = _worker_fixture(
        attestor=_StoredAttestor() if stored else None, responses=responses
    )
    if settle:
        verifier.publish(**test_event)
    tenant_id = uuid4()
    with factory.begin() as db:
        db.add(Tenant(id=tenant_id, slug="publication-test", name="Isolated", home_region="test"))
    service = ModelPublicationService(
        factory.kw["bind"],
        authorization=PlatformAuthorizationService(factory),
        pricing=verification._pricing,
    )

    def readiness_clock():
        engine = factory.kw["bind"]
        if engine.dialect.name == "postgresql":
            with engine.connect() as connection:
                return connection.scalar(sa.select(sa.func.clock_timestamp()))
        return datetime.now(timezone.utc)

    readiness = _Readiness(hook, stale=stale, clock=readiness_clock)
    worker = ModelPublicationPublisher(
        factory.kw["bind"],
        secret_cipher=verifier._cipher,
        readiness=readiness,
        pricing=verification._pricing,
    )
    request = {
        "deployment_id": test.deployment_version_id,
        "tenant_id": tenant_id,
        "verification_operation_id": test.id,
        "configuration_sha256": verification.receipt(actor, test.id)["configuration_sha256"],
        "expected_generation": 0,
        "idempotency_key": "publish-isolated-001",
    }
    return service, worker, factory, actor, request, calls


def _envelope(factory, operation_id):
    with factory() as db:
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(operation_id)
            )
        )
        return {
            "event_id": event.id,
            **{
                name: getattr(event, name)
                for name in ("event_type", "aggregate_type", "aggregate_key", "payload")
            },
        }


@pytest.mark.parametrize("responses", (False, True))
def test_publication_is_durable_tenant_scoped_and_never_infers_or_charges_again(responses):
    service, worker, factory, actor, request, calls = _fixture(responses=responses)
    before = list(calls)
    operation = service.admit(actor, **request)
    assert service.admit(actor, **request).id == operation.id
    assert service.list(actor) == ()
    envelope = _envelope(factory, operation.id)
    worker.publish(**envelope)
    worker.publish(**envelope)
    receipt = service.receipt(actor, operation.id)
    assert receipt["operation"]["status"] == "applied"
    assert receipt["runtime_enabled"] is False
    assert receipt["publication"]["tenant_id"] == request["tenant_id"]
    assert receipt["publication"]["generation"] == 1
    assert len(service.list(actor, tenant_id=request["tenant_id"])) == 1
    assert service.list(actor, tenant_id=uuid4()) == ()
    assert worker._readiness.calls == 1 and calls == before
    assert "test-connection-secret-not-public" not in json.dumps(receipt, default=str)
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationCommandRecord)) == 1
        )
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationVersionRecord)) == 1
        )
        assert db.scalar(sa.text("SELECT COUNT(*) FROM saas_customer_ledger_entries")) == 0
        budget = db.scalar(sa.select(ModelProviderBudgetReservationRecord))
        assert budget.status == "settled" and budget.settled_microusd == 14


@pytest.mark.parametrize("change", ("unsettled", "no_stored_proof", "tenant", "config", "price"))
def test_invalid_prerequisites_never_enqueue_publication(change):
    service, worker, factory, actor, request, _ = _fixture(
        stored=change != "no_stored_proof", settle=change != "unsettled"
    )
    if change == "tenant":
        request["tenant_id"] = uuid4()
    elif change == "config":
        request["configuration_sha256"] = "b" * 64
    elif change == "price":
        service._pricing = replace(service._pricing, revision="changed")
    with pytest.raises(PlatformSecurityError):
        service.admit(actor, **request)
    assert worker._readiness.calls == 0
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationCommandRecord)) == 0
        )


@pytest.mark.parametrize(
    "change", ("session", "security", "role", "tenant", "credential", "receipt")
)
def test_authority_or_inputs_revoked_during_readiness_cannot_commit(change):
    service, worker, factory, actor, request, calls = _fixture()
    operation = service.admit(actor, **request)

    def revoke():
        with factory.begin() as db:
            if change == "session":
                db.get(PlatformAuthSessionRecord, actor.session_id).revoked_at = datetime.now(
                    timezone.utc
                )
            elif change == "security":
                db.get(PlatformStaffPrincipalRecord, actor.principal_id).security_version += 1
            elif change == "role":
                db.scalar(sa.select(PlatformRoleAssignmentRecord)).status = "revoked"
            elif change == "tenant":
                db.get(Tenant, request["tenant_id"]).status = "suspended"
            elif change == "credential":
                db.scalar(sa.select(ModelConnectionRecord)).credential_generation += 1
            else:
                db.get(
                    ModelVerificationReceiptRecord, request["verification_operation_id"]
                ).canonical_evidence = "{}"

    worker._readiness.hook = revoke
    before = list(calls)
    envelope = _envelope(factory, operation.id)
    worker.publish(**envelope)
    worker.publish(**envelope)
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationVersionRecord)) == 0
        )
        assert (
            db.scalar(
                sa.text(
                    "SELECT status FROM saas_model_projection_operations "
                    "WHERE action='publish_deployment'"
                )
            )
            == "failed"
        )
    assert calls == before


def test_unavailable_replica_can_retry_read_only_then_publish_exactly_once():
    service, worker, factory, actor, request, calls = _fixture()
    operation = service.admit(actor, **request)
    worker._readiness.unavailable = True
    before = list(calls)
    event = _envelope(factory, operation.id)
    with pytest.raises(OutboxPublishError, match="waiting_for_replicas"):
        worker.publish(**event)
    assert service.receipt(actor, operation.id)["operation"]["status"] == "applying"
    worker._readiness.unavailable = False
    worker.publish(**event)
    assert service.receipt(actor, operation.id)["operation"]["status"] == "applied"
    assert worker._readiness.calls == 2 and calls == before


def test_stale_readiness_or_expired_command_never_publishes():
    service, worker, factory, actor, request, _ = _fixture(stale=True)
    operation = service.admit(actor, **request)
    worker.publish(**_envelope(factory, operation.id))
    assert service.receipt(actor, operation.id)["operation"]["status"] == "failed"
    assert service.list(actor) == ()


def test_expired_fresh_auth_window_fails_before_any_replica_request(monkeypatch):
    from saas.production import model_publication as production

    service, worker, factory, actor, request, _ = _fixture()
    operation = service.admit(actor, **request)

    class ExpiredClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(minutes=6)

    monkeypatch.setattr(production, "datetime", ExpiredClock)
    worker.publish(**_envelope(factory, operation.id))
    assert worker._readiness.calls == 0
    assert service.receipt(actor, operation.id)["operation"]["status"] == "failed"
    assert service.list(actor) == ()


def test_lost_commit_ack_recovers_existing_generation_without_repeat_checks():
    service, worker, factory, actor, request, calls = _fixture()
    operation = service.admit(actor, **request)
    original = worker._session
    lost = False

    @contextmanager
    def lose_ack(name):
        nonlocal lost
        with original(name) as db:
            yield db
        if name == "commit_one_tenant_publication_version" and not lost:
            lost = True
            raise sa.exc.OperationalError(
                "isolated lost commit acknowledgement", None, RuntimeError()
            )

    worker._session = lose_ack
    event = _envelope(factory, operation.id)
    before = list(calls)
    with pytest.raises(OutboxPublishError, match="storage_unavailable"):
        worker.publish(**event)
    worker.publish(**event)
    assert len(service.list(actor)) == 1
    assert service.receipt(actor, operation.id)["operation"]["status"] == "applied"
    assert worker._readiness.calls == 1 and calls == before


def test_competing_expected_generation_only_one_command_can_publish():
    service, worker, factory, actor, request, _ = _fixture()
    first = service.admit(actor, **request)
    second = service.admit(actor, **{**request, "idempotency_key": "publish-competing"})
    worker.publish(**_envelope(factory, first.id))
    worker.publish(**_envelope(factory, second.id))
    assert service.receipt(actor, first.id)["operation"]["status"] == "applied"
    assert service.receipt(actor, second.id)["operation"]["status"] == "failed"
    assert len(service.list(actor)) == 1
    with pytest.raises(PlatformSecurityError, match="changed"):
        service.admit(actor, **{**request, "idempotency_key": "publish-old-generation"})


def _http_fixture(*, enabled=True):
    service, worker, factory, actor, request, calls = _fixture()
    origin = "https://staff.example.test"
    sessions = PlatformSessionService(factory, origin=origin, audience="model-management")
    issued = PlatformPasswordAuthenticationService(factory, sessions).authenticate(
        "model-operator", "model-operator-test-password"
    )
    authorization = PlatformAuthorizationService(factory)
    app = create_platform_admin_app(
        config=PlatformHttpConfig(enabled=True, origin=origin, audience="model-management"),
        sessions=sessions,
        authorization=authorization,
        projections=PlatformProjectionService(factory),
        model_connections=ModelConnectionService(
            factory, authorization=authorization, secret_cipher=worker._cipher
        ),
        model_publications=service if enabled else None,
    )
    client = TestClient(app, base_url=origin)
    client.cookies.set("__Host-omnigent_platform_session", issued.token)
    headers = {
        "Origin": origin,
        "X-CSRF-Token": issued.csrf_token,
        "Idempotency-Key": request.pop("idempotency_key"),
    }
    deployment = request.pop("deployment_id")
    body = {name: str(value) if name.endswith("_id") else value for name, value in request.items()}
    path = f"/v2/platform-admin/model-deployments/{deployment}/publish"
    return client, headers, path, body, factory, actor, worker, calls


def test_http_publication_receipt_and_idempotent_operation_recovery():
    client, headers, path, body, factory, _, worker, _ = _http_fixture()
    result = client.post(path, headers=headers, json=body)
    assert result.status_code == 202, result.text
    operation = result.json()
    assert client.post(path, headers=headers, json=body).json()["id"] == operation["id"]
    recovered = client.get(
        "/v2/platform-admin/model-operations",
        params={"idempotency_key": headers["Idempotency-Key"]},
    )
    assert recovered.json()["operation"]["id"] == operation["id"]
    worker.publish(**_envelope(factory, operation["id"]))
    receipt = client.get(f"/v2/platform-admin/model-operations/{operation['id']}/publication")
    assert receipt.status_code == 200 and receipt.json()["operation"]["status"] == "applied"
    assert receipt.json()["runtime_enabled"] is False
    catalog = client.get(
        "/v2/platform-admin/model-publications", params={"tenant_id": body["tenant_id"]}
    )
    assert len(catalog.json()["items"]) == 1
    with factory.begin() as db:
        db.scalar(sa.select(PlatformRoleAssignmentRecord)).role = "platform_security_auditor"
    assert client.get("/v2/platform-admin/model-publications").status_code == 200
    assert client.post(path, headers=headers, json=body).status_code == 403


@pytest.mark.parametrize(
    "change", ("csrf", "origin", "tenant_cookie", "extra_key", "extra_proof", "bool", "disabled")
)
def test_http_publication_rejects_untrusted_context_or_browser_proof(change):
    client, headers, path, body, factory, _, worker, _ = _http_fixture(
        enabled=change != "disabled"
    )
    if change == "csrf":
        headers.pop("X-CSRF-Token")
    elif change == "origin":
        headers["Origin"] = "https://tenant.example.test"
    elif change == "tenant_cookie":
        client.cookies.clear()
        client.cookies.set("__Host-omnigent_saas_session", "tenant-owner-token")
    elif change == "extra_key":
        body["api_key"] = "browser-must-not-provide-key"
    elif change == "extra_proof":
        body["readiness"] = {"verified": True}
    elif change == "bool":
        body["expected_generation"] = False
    response = client.post(path, headers=headers, json=body)
    assert response.status_code in {400, 401, 403, 503}, response.text
    assert "browser-must-not-provide-key" not in response.text
    assert worker._readiness.calls == 0
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelPublicationCommandRecord)) == 0
        )


@pytest.mark.parametrize("change", (None, "mode", "revision", "secret", "http", "version", "one"))
def test_publication_inventory_is_worker_only_readonly_and_exact_revision(tmp_path, change):
    source = {"OMNIGENT_SAAS_SOURCE_SHA": "a" * 40}
    document = {
        "schema_version": 1,
        "source_sha": "a" * 40,
        "replicas": [
            {"replica_id": f"replica-{n}", "base_url": f"https://replica-{n}.litellm.test"}
            for n in range(2)
        ],
    }
    if change == "revision":
        document["source_sha"] = "b" * 40
    elif change == "secret":
        document["replicas"][0]["api_key"] = "forbidden-browser-key"
    elif change == "http":
        document["replicas"][0]["base_url"] = "http://public.example.test"
    elif change == "version":
        document["schema_version"] = True
    elif change == "one":
        document["replicas"] = document["replicas"][:1]
    path = tmp_path / "worker-inventory.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600 if change == "mode" else 0o400)
    source["OMNIGENT_SAAS_LITELLM_REPLICA_INVENTORY_FILE"] = str(path)
    management = LiteLLMManagementConfiguration(
        base_url="https://litellm.test", management_key="isolated-management-key"
    )
    assert model_publication_enabled({}) is False
    if change is None:
        replicas = load_litellm_replica_inventory(source, management=management)
        assert len(replicas) == 2
        assert "isolated-management-key" not in repr(replicas)
    else:
        with pytest.raises(ValueError, match="model_publication_inventory_invalid"):
            load_litellm_replica_inventory(source, management=management)
