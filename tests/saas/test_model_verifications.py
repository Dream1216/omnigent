from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_deployments import compile_model_deployment_draft
from saas.control_plane.model_pricing import (
    PlatformModelPrice,
    PlatformModelPricingPolicy,
    token_cost_microusd,
)
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_routing_models import (
    ModelVerificationCommandRecord,
)
from saas.control_plane.model_test_funding import ModelTestFundingPolicy, ModelTestFundingService
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.model_verification_contract import (
    compile_model_verification,
    restore_model_verification,
)
from saas.control_plane.model_verifications import ModelVerificationService
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
)
from tests.saas.test_model_connections import _Cipher
from tests.saas.test_model_deployments import _command, _draft_fixture


def _pricing(model="deepseek-isolated-contract"):
    return PlatformModelPricingPolicy(
        "contract-cost-v1",
        sha256(json.dumps([model], separators=(",", ":")).encode()).hexdigest(),
        (PlatformModelPrice(sha256(model.encode()).hexdigest(), 2, 3, 7, 1, 2, 6),),
    )


def _verification_fixture(
    *, project=True, funding=True, pricing=None, wire_api="openai_chat_completions"
):
    connections, deployments, factory, actor, draft_command = _draft_fixture()
    draft_command = replace(draft_command, wire_api=wire_api)
    operation = deployments.create(
        actor, command=draft_command, idempotency_key="verification-draft"
    )
    if project:
        with factory() as db:
            event = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_key == str(operation.id)
                )
            )
            envelope = {
                "event_id": event.id,
                **{
                    name: getattr(event, name)
                    for name in ("event_type", "aggregate_type", "aggregate_key", "payload")
                },
            }
        ModelCredentialProjectionPublisher(
            factory.kw["bind"],
            secret_cipher=_Cipher(),
            management=LiteLLMManagementClient(
                LiteLLMManagementConfiguration(
                    base_url="https://litellm.test", management_key="isolated-draft-projection-key"
                ),
                transport=httpx.MockTransport(
                    lambda _: httpx.Response(200, json={"status": "success"})
                ),
            ),
        ).publish(**envelope)
    engine = factory.kw["bind"]
    authorization = PlatformAuthorizationService(factory)
    if funding:
        ModelTestFundingService(engine, authorization=authorization).configure(
            actor,
            expected_version=0,
            policy=ModelTestFundingPolicy(True, 1_000_000, 100_000, 10_000, 10000, 1056, 10),
        )
    service = ModelVerificationService(
        engine, authorization=authorization, pricing=pricing or _pricing()
    )
    draft = deployments.list(actor)[0]
    request = {
        "deployment_id": draft.id,
        "configuration_sha256": draft.configuration_sha256,
        "expected_funding_policy_version": 1,
        "idempotency_key": "one-paid-verification",
    }
    return service, factory, actor, request, connections


def test_verification_snapshot_is_priced_immutable_and_covers_component_rounding():
    draft = compile_model_deployment_draft(_command(), deployment_id=uuid4())
    plan = compile_model_verification(draft, pricing=_pricing(), funding_policy_version=1)
    assert plan.requested_tokens == 1056 and plan.output_token_limit == 32
    usage = ModelTokenUsage(1024, 512, 512, 32, 1056)
    actual = plan.actual_cost(usage, at=datetime(2026, 10, 16, 1, tzinfo=timezone.utc))
    assert actual == plan.requested_microusd == 3
    assert (
        restore_model_verification(
            draft, canonical_price=plan.canonical_price, funding_policy_version=1
        )
        == plan
    )
    assert plan == compile_model_verification(draft, pricing=_pricing(), funding_policy_version=1)
    assert (
        compile_model_verification(
            draft, pricing=_pricing(), funding_policy_version=2
        ).request_hash
        != plan.request_hash
    )


@pytest.mark.parametrize("value", ("{}", "[]", "invalid", '{"api_key":"not-public"}'))
def test_untrusted_price_snapshot_has_a_stable_redacted_failure(value):
    draft = compile_model_deployment_draft(_command(), deployment_id=uuid4())
    with pytest.raises(ValueError, match="model_verification_price_invalid"):
        restore_model_verification(draft, canonical_price=value, funding_policy_version=1)


def test_money_is_exact_beyond_the_float_integer_range():
    count, rate = (1 << 63) - 1, 10**12
    assert token_cost_microusd(count, rate) == (count * rate + 999999) // 1000000
    assert token_cost_microusd(0, 1) == 0
    with pytest.raises(ValueError):
        token_cost_microusd(True, 1)


def test_admission_writes_one_immutable_priced_command_and_reference_only_outbox():
    service, factory, actor, request, _connections = _verification_fixture()
    first = service.admit(actor, **request)
    assert first.status == "requested" and first.action == "verify_deployment"
    assert service.admit(actor, **request) == first
    with factory() as db:
        command = db.get(ModelVerificationCommandRecord, first.id)
        assert command.configuration_sha256 == request["configuration_sha256"]
        assert command.requested_microusd == 3 and command.requested_tokens == 1056
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelVerificationCommandRecord)) == 1
        )
        event = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(first.id)
            )
        )
        assert (
            event.event_type == "platform.model_verification.requested" and event.tenant_id is None
        )
        assert set(event.payload) == {
            "schema_version",
            "operation_id",
            "credential_version_id",
            "event_type",
        }
    receipt = service.receipt(actor, first.id)
    assert receipt["evidence"] is None and receipt["runtime_enabled"] is False


@pytest.mark.parametrize(
    "change",
    (
        {"configuration_sha256": "b" * 64},
        {"expected_funding_policy_version": 2},
        {"deployment_id": uuid4()},
    ),
)
def test_shared_idempotency_key_cannot_change_the_paid_test(change):
    service, _factory, actor, request, _connections = _verification_fixture()
    service.admit(actor, **request)
    with pytest.raises(PlatformSecurityError) as conflict:
        service.admit(actor, **{**request, **change})
    assert conflict.value.code == "platform_model_operation_conflict"


@pytest.mark.parametrize(
    "condition", ("stale", "expiring", "revoked", "auditor", "unprojected", "unfunded", "unpriced")
)
def test_preconditions_reject_before_any_test_is_enqueued(condition):
    service, factory, actor, request, _connections = _verification_fixture(
        project=condition != "unprojected", funding=condition != "unfunded"
    )
    if condition == "stale":
        actor = replace(actor, authenticated_at=datetime.now(timezone.utc) - timedelta(minutes=6))
    elif condition == "expiring":
        actor = replace(actor, expires_at=datetime.now(timezone.utc) + timedelta(seconds=30))
    elif condition in {"revoked", "auditor"}:
        with factory.begin() as db:
            db.execute(
                sa.update(PlatformRoleAssignmentRecord).values(
                    **(
                        {"status": "revoked"}
                        if condition == "revoked"
                        else {"role": "platform_security_auditor"}
                    )
                )
            )
    elif condition == "unpriced":
        service = ModelVerificationService(
            factory.kw["bind"],
            authorization=PlatformAuthorizationService(factory),
            pricing=_pricing("deepseek-another-contract"),
        )
    with pytest.raises(PlatformSecurityError):
        service.admit(actor, **request)
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelVerificationCommandRecord)) == 0
        )
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(ControlPlaneOutboxEvent)
                .where(
                    ControlPlaneOutboxEvent.event_type == "platform.model_verification.requested"
                )
            )
            == 0
        )


def test_http_admission_and_receipt_preserve_staff_and_browser_boundaries():
    from saas.control_plane.model_connections import CreateModelConnection
    from saas.control_plane.model_deployments import ModelDeploymentService
    from tests.saas.test_model_connections import _KEY, _fixture

    connections, factory, actor, cipher, client, headers = _fixture(pricing=_pricing())
    management = LiteLLMManagementClient(
        LiteLLMManagementConfiguration(
            base_url="https://litellm.test", management_key="isolated-http-model-management"
        ),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"status": "success"})),
    )
    projection = ModelCredentialProjectionPublisher(
        factory.kw["bind"], secret_cipher=cipher, management=management
    )

    def project(operation_id):
        with factory() as db:
            event = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.aggregate_key == str(operation_id)
                )
            )
            envelope = {
                "event_id": event.id,
                **{
                    name: getattr(event, name)
                    for name in ("event_type", "aggregate_type", "aggregate_key", "payload")
                },
            }
        projection.publish(**envelope)

    credential = connections.create(
        actor,
        command=CreateModelConnection("http candidate", _KEY),
        idempotency_key="http-connection",
    )
    project(credential.id)
    deployments = ModelDeploymentService(
        factory.kw["bind"], authorization=connections._authorization
    )
    operation = deployments.create(
        actor,
        command=replace(
            _command(),
            connection_id=credential.connection_id,
            credential_version_id=credential.credential_version_id,
        ),
        idempotency_key="http-draft",
    )
    project(operation.id)
    draft = deployments.list(actor)[0]
    ModelTestFundingService(
        factory.kw["bind"], authorization=connections._authorization
    ).configure(
        actor,
        expected_version=0,
        policy=ModelTestFundingPolicy(True, 1000, 1000, 10000, 1000, 1056, 10),
    )
    body = {
        "configuration_sha256": draft.configuration_sha256,
        "expected_funding_policy_version": 1,
    }
    path = f"/v2/platform-admin/model-deployments/{draft.id}/test"
    headers = {**headers, "Idempotency-Key": "http-priced-verification"}
    response = client.post(path, headers=headers, json=body)
    assert response.status_code == 202 and response.json()["status"] == "requested"
    assert client.post(path, headers=headers, json=body).json()["id"] == response.json()["id"]
    receipt = client.get(
        "/v2/platform-admin/model-operations/" + response.json()["id"] + "/verification"
    )
    assert receipt.status_code == 200 and receipt.json()["evidence"] is None
    assert receipt.json()["runtime_enabled"] is False
    assert (
        client.get("/v2/platform-admin/context").json()["capabilities"][
            "model_verification_enabled"
        ]
        is True
    )
    for missing, status in (("Origin", 401), ("X-CSRF-Token", 403), ("Idempotency-Key", 400)):
        assert (
            client.post(
                path,
                headers={key: value for key, value in headers.items() if key != missing},
                json=body,
            ).status_code
            == status
        )
    rejected = client.post(path, headers=headers, json={**body, "api_key": "never-return-this"})
    assert rejected.status_code == 400 and "never-return-this" not in rejected.text


def test_unconfigured_verification_is_explicitly_unavailable():
    from tests.saas.test_model_connections import _fixture

    _connections, _factory, _actor, _cipher, client, _headers = _fixture()
    assert (
        client.get("/v2/platform-admin/context").json()["capabilities"][
            "model_verification_enabled"
        ]
        is False
    )
    assert (
        client.get(f"/v2/platform-admin/model-operations/{uuid4()}/verification").status_code
        == 503
    )
