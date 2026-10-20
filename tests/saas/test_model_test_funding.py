from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from saas.control_plane.model_budget import (
    ModelProviderBudgetAdmissionService,
    ModelProviderBudgetError,
)
from saas.control_plane.model_test_funding import ModelTestFundingPolicy, ModelTestFundingService
from saas.control_plane.platform_models import (
    ModelProviderBudgetReservationRecord,
    ModelProviderConfigurationRecord,
    ModelProviderMonthlyBudgetRecord,
    ModelProviderTenantDailyUsageRecord,
    ModelTestFundingPolicyRecord,
    PlatformRoleAssignmentRecord,
)
from saas.control_plane.platform_security import PlatformSecurityError
from tests.saas.test_model_connections import _fixture


def _funding_fixture(**limits):
    _connections, factory, actor, _cipher, _client, _headers = _fixture()
    funding = ModelTestFundingService(
        factory.kw["bind"], authorization=_connections._authorization
    )
    policy = ModelTestFundingPolicy(
        **{
            "enabled": True,
            "monthly_budget_microusd": 1000,
            "daily_test_budget_microusd": 1000,
            "daily_test_token_limit": 1000,
            "max_test_microusd": 900,
            "max_test_tokens": 900,
            "daily_test_attempt_limit": 2,
            **limits,
        }
    )
    assert funding.get(actor).version == 0
    assert funding.configure(actor, expected_version=0, policy=policy).version == 1
    return funding, ModelProviderBudgetAdmissionService(factory), factory, actor, policy


def _request(actor, **overrides):
    return {
        "verification_id": uuid4(),
        "actor_principal_id": actor.principal_id,
        "configuration_sha256": "e" * 64,
        "operation_key": uuid4().hex,
        "requested_microusd": 600,
        "requested_tokens": 700,
        "ttl": timedelta(minutes=2),
        **overrides,
    }


def test_test_funding_is_keyless_versioned_and_cas_recoverable():
    funding, _budget, factory, actor, policy = _funding_fixture()
    assert funding.configure(actor, expected_version=0, policy=policy).version == 1
    with pytest.raises(PlatformSecurityError, match="changed"):
        funding.configure(actor, expected_version=0, policy=replace(policy, enabled=False))
    assert (
        funding.configure(actor, expected_version=1, policy=replace(policy, enabled=False)).version
        == 2
    )
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelTestFundingPolicyRecord)) == 2
        assert set(ModelTestFundingPolicyRecord.__table__.columns.keys()).isdisjoint(
            {"api_key", "api_key_ciphertext", "tenant_id"}
        )


def test_platform_test_has_no_tenant_run_or_customer_counter_and_keeps_unknown_cost():
    _funding, budget, factory, actor, _policy = _funding_fixture()
    now = datetime.now(timezone.utc)
    request = _request(actor, now=now)
    hold = budget.reserve_platform_test(**request)
    assert hold.purpose == "platform_test" and hold.tenant_id is None and hold.run_id is None
    assert hold.test_operation_id == request["verification_id"]
    assert hold.test_configuration_sha256 == request["configuration_sha256"]
    assert hold.test_policy_version == 1
    assert budget.reserve_platform_test(**request).replayed
    with pytest.raises(ModelProviderBudgetError, match="evidence"):
        budget.settle(reservation_id=hold.id, actual_microusd=10, actual_tokens=10)
    budget.begin_attempt(reservation_id=hold.id, now=now)
    budget.mark_uncertain(reservation_id=hold.id, now=now + timedelta(days=1))
    assert budget.recover_expired(now=now + timedelta(days=1)) == ()
    with pytest.raises(ModelProviderBudgetError):
        budget.release(reservation_id=hold.id)
    denied = budget.reserve_platform_test(
        **_request(actor, requested_microusd=500, requested_tokens=1)
    )
    assert denied.rejection_code == "platform_model_monthly_budget_exhausted"
    result = budget.resolve_attempt(
        reservation_id=hold.id, actual_microusd=450, actual_tokens=650, evidence_sha256="a" * 64
    )
    assert result.status == "settled" and result.released_microusd == 150
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ModelProviderTenantDailyUsageRecord))
            == 0
        )
        monthly = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord))
        assert (monthly.reserved_microusd, monthly.settled_microusd) == (0, 450)
        assert db.scalar(sa.text("SELECT COUNT(*) FROM saas_customer_ledger_entries")) == 0


@pytest.mark.parametrize(
    ("limits", "overrides", "code"),
    (
        (
            {"daily_test_budget_microusd": 900},
            {"requested_microusd": 400, "requested_tokens": 1},
            "platform_model_test_daily_budget_exhausted",
        ),
        (
            {},
            {"requested_microusd": 1, "requested_tokens": 301},
            "platform_model_test_daily_tokens_exhausted",
        ),
        (
            {"daily_test_attempt_limit": 1},
            {"requested_microusd": 1, "requested_tokens": 1},
            "platform_model_test_daily_attempts_exhausted",
        ),
    ),
)
def test_global_platform_test_daily_limits(limits, overrides, code):
    _funding, budget, _factory, actor, _policy = _funding_fixture(**limits)
    first = budget.reserve_platform_test(**_request(actor))
    if code.endswith("attempts_exhausted"):
        budget.release(reservation_id=first.id)
    rejected = budget.reserve_platform_test(**_request(actor, **overrides))
    assert rejected.status == "rejected" and rejected.rejection_code == code


def test_funding_disabled_or_reconfigured_before_dispatch_prevents_send_authority():
    funding, budget, _factory, actor, policy = _funding_fixture()
    hold = budget.reserve_platform_test(**_request(actor))
    funding.configure(actor, expected_version=1, policy=replace(policy, enabled=False))
    with pytest.raises(ModelProviderBudgetError) as denied:
        budget.begin_attempt(reservation_id=hold.id)
    assert denied.value.code == "platform_model_test_funding_changed"
    with pytest.raises(ModelProviderBudgetError) as unavailable:
        budget.reserve_platform_test(**_request(actor))
    assert unavailable.value.code == "platform_model_test_funding_unavailable"
    assert budget.release(reservation_id=hold.id).status == "released"


@pytest.mark.parametrize("change", ("different_key", "configuration", "amount", "actor"))
def test_verification_funding_cannot_be_rebound_or_reserved_twice(change):
    _funding, budget, _factory, actor, _policy = _funding_fixture()
    request = _request(actor)
    budget.reserve_platform_test(**request)
    field, value = {
        "different_key": ("operation_key", uuid4().hex),
        "configuration": ("configuration_sha256", "f" * 64),
        "amount": ("requested_microusd", 500),
        "actor": ("actor_principal_id", uuid4()),
    }[change]
    with pytest.raises(ModelProviderBudgetError) as conflict:
        budget.reserve_platform_test(**{**request, field: value})
    assert conflict.value.code == "platform_model_budget_idempotency_conflict"


@pytest.mark.parametrize("condition", ("stale", "expired", "revoked", "auditor"))
def test_only_current_fresh_staff_operator_can_fund_tests(condition):
    funding, _budget, factory, actor, policy = _funding_fixture()
    if condition == "stale":
        actor = replace(actor, authenticated_at=datetime.now(timezone.utc) - timedelta(minutes=6))
    elif condition == "expired":
        actor = replace(actor, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    else:
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
    with pytest.raises(PlatformSecurityError):
        funding.configure(actor, expected_version=1, policy=policy)


def test_database_rejects_borrowing_staff_identity_as_a_customer_funding_scope():
    _funding, budget, factory, actor, _policy = _funding_fixture()
    hold = budget.reserve_platform_test(**_request(actor))
    with pytest.raises(IntegrityError), factory.begin() as db:
        db.execute(
            sa.update(ModelProviderBudgetReservationRecord)
            .where(ModelProviderBudgetReservationRecord.id == hold.id)
            .values(tenant_id=actor.principal_id)
        )


@pytest.mark.parametrize(
    "limits",
    (
        {"max_test_tokens": True},
        {"max_test_tokens": 2049},
        {"max_test_microusd": 1001},
        {"daily_test_attempt_limit": 1001},
        {"enabled": "true"},
    ),
)
def test_limits_are_strict_and_bounded(limits):
    with pytest.raises(PlatformSecurityError) as invalid:
        _funding_fixture(**limits)
    assert invalid.value.code == "platform_model_test_funding_invalid"


def test_staff_http_funding_receipt_is_recoverable_and_contains_no_model_enablement():
    _connections, factory, actor, _cipher, client, headers = _fixture()
    _funding, _budget, _factory, _actor, policy = _funding_fixture()
    path = "/v2/platform-admin/model-test-funding"
    assert client.get(path).json()["version"] == 0
    body = {"expected_version": 0, **asdict(policy)}
    created = client.put(path, headers=headers, json=body)
    assert created.status_code == 200
    receipt = created.json()
    assert receipt["version"] == 1 and receipt["actor_principal_id"] == str(actor.principal_id)
    assert (
        client.put(path, headers=headers, json=body).json()["request_hash"]
        == receipt["request_hash"]
    )
    assert client.get(path).json()["request_hash"] == receipt["request_hash"]
    assert client.get("/v2/platform-admin/model-deployments").json()["items"] == []
    assert not any("key" in name or "runtime" in name for name in receipt)
    for invalid in (
        {"max_test_tokens": True},
        {"api_key": "never-expose-this"},
        {"expected_version": "1"},
    ):
        response = client.put(path, headers=headers, json={**body, **invalid})
        assert response.status_code == 400 and "never-expose-this" not in response.text
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelTestFundingPolicyRecord)) == 1


@pytest.mark.parametrize(("missing", "status"), (("Origin", 401), ("X-CSRF-Token", 403)))
def test_funding_http_preserves_browser_mutation_boundary(missing, status):
    _connections, factory, _actor, _cipher, client, headers = _fixture()
    headers.pop(missing)
    response = client.put("/v2/platform-admin/model-test-funding", headers=headers, json={})
    assert response.status_code == status
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(ModelTestFundingPolicyRecord)) == 0


def test_disabled_composition_does_not_offer_funding_authority():
    _connections, _factory, _actor, _cipher, client, _headers = _fixture(enabled=False)
    assert (
        client.get("/v2/platform-admin/context").json()["capabilities"][
            "model_test_funding_enabled"
        ]
        is False
    )
    assert client.get("/v2/platform-admin/model-test-funding").status_code == 503


@pytest.mark.parametrize("first_scope", ("tenant_run", "platform_test"))
def test_platform_and_customer_admission_share_the_same_monthly_cap(first_scope):
    _funding, budget, factory, actor, _policy = _funding_fixture()
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        db.add(
            ModelProviderConfigurationRecord(
                provider_id="deepseek",
                enabled=True,
                base_url="https://api.deepseek.com",
                api_type="openai_chat_completions",
                api_key_ciphertext="isolated-not-a-key",
                allowed_models=["deepseek-contract"],
                default_model="deepseek-contract",
                monthly_budget_microusd=1000,
                per_tenant_daily_token_limit=1000,
                verification_status="verified",
                last_verified_model="deepseek-contract",
                last_verified_at=now,
                version=1,
                updated_by_principal_id=actor.principal_id,
                updated_at=now,
            )
        )

    def reserve(scope, amount):
        if scope == "platform_test":
            return budget.reserve_platform_test(**_request(actor, requested_microusd=amount))
        return budget.reserve(
            tenant_id=uuid4(),
            run_id=uuid4(),
            operation_key=uuid4().hex,
            requested_microusd=amount,
            requested_tokens=700,
            ttl=timedelta(minutes=2),
        )

    assert reserve(first_scope, 600).status == "reserved"
    other_scope = "tenant_run" if first_scope == "platform_test" else "platform_test"
    assert reserve(other_scope, 500).rejection_code == "platform_model_monthly_budget_exhausted"


def test_test_funding_does_not_enable_an_unconfigured_customer_provider():
    _funding, budget, _factory, actor, _policy = _funding_fixture()
    assert budget.reserve_platform_test(**_request(actor)).status == "reserved"
    with pytest.raises(ModelProviderBudgetError) as denied:
        budget.reserve(
            tenant_id=uuid4(),
            run_id=uuid4(),
            operation_key=uuid4().hex,
            requested_microusd=1,
            requested_tokens=1,
            ttl=timedelta(minutes=1),
        )
    assert denied.value.code == "platform_model_provider_unavailable"
