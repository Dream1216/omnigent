from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.host.frames import HostHelloFrame
from saas.compatibility import bind_runtime_context
from saas.control_plane import AdmissionQuotaRecord, ProjectMembershipRecord
from saas.control_plane.billing_models import (
    BillingSubscriptionRecord,
    PricingSnapshotRecord,
    UsageEventRecord,
)
from saas.control_plane.execution_models import (
    ExecutionSessionRecord,
    QuotaReservationRecord,
    RunRecord,
    TaskRecord,
)
from tests.saas.test_gateway_machine_metering import _customer_prices
from tests.saas.test_interactive_execution_http import _managed_create
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http


def _setup(f):
    body = _managed_create(f)
    f.app.state.production_interactive_conversation_store = f.store
    f.store.runtime_readiness_check = lambda: None
    price = _customer_prices(f.factory, actor=f.runtime.actor_id, tenant=f.runtime.tenant_id)
    target = {
        "project_id": body["project_id"],
        "agent_id": body["agent_id"],
        "harness": "openai-agents",
        "host_type": "managed",
        "sandbox_provider": "kubernetes",
    }
    return target, price


def _assert_preview(f, target, *, reason=None, enabled=True):
    calls = list(f.calls)
    before = _effects(f)
    response = f.client.get("/v1/managed-model-catalog", params=target)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    result = response.json()
    assert result["runtime_enabled"] is enabled
    assert len(result["models"]) == 1
    row = result["models"][0]
    assert row["available"] is (reason is None)
    assert row["unavailable_reason"] == reason
    assert row["configuration_revision"].endswith(f.marker["snapshot_sha256"])
    assert set(row) == {
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
    assert _effects(f) == before
    assert f.calls == calls
    return result


def _effects(f):
    with f.factory() as db:
        counts = tuple(
            db.scalar(sa.select(sa.func.count()).select_from(model))
            for model in (
                ExecutionSessionRecord,
                TaskRecord,
                RunRecord,
                QuotaReservationRecord,
                UsageEventRecord,
            )
        )
        quota = db.scalars(sa.select(AdmissionQuotaRecord)).one()
        return counts, quota.version, quota.reserved_units, quota.consumed_units


@pytest.mark.parametrize("interactive_http", [False, True], indirect=True)
def test_read_only_target_preview_does_not_admit_or_infer(interactive_http):
    f = interactive_http
    target, _ = _setup(f)
    _assert_preview(f, target)
    # A saved-session/catalog-only reader has no target selection or authority.
    _assert_preview(f, {}, reason="runtime_not_enabled", enabled=False)


@pytest.mark.parametrize("provider", ["kubernetes", "agent_sandbox", "external"])
def test_preview_uses_actual_target_owner_connection_and_harness_readiness(
    interactive_http, provider
):
    f = interactive_http
    target, _ = _setup(f)
    if provider == "agent_sandbox":
        from omnigent.server.managed_hosts import ManagedSandboxConfig, ManagedSandboxDeployment

        f.app.state.sandbox_config = ManagedSandboxDeployment.single(
            ManagedSandboxConfig(
                server_url="http://isolated.invalid",
                token_ttl_s=3600,
                provider=provider,
                launcher_factory=lambda: pytest.fail("preview launched sandbox"),
            )
        )
        target["sandbox_provider"] = provider
    elif provider == "external":
        host_id = uuid4().hex
        target.pop("sandbox_provider")
        target.update(host_type="external", host_id=host_id)
        with bind_runtime_context(f.runtime):
            f.dependencies["host_store"].upsert_on_connect(
                host_id,
                "synthetic-host",
                f.runtime.runtime_user_key,
                configured_harnesses={"openai-agents": True},
            )
            f.app.state.host_registry.register(
                host_id=host_id,
                ws=SimpleNamespace(),
                owner=f.runtime.runtime_user_key,
                hello=HostHelloFrame(version="isolated", frame_protocol_version=1, name="test"),
            )
    _assert_preview(f, target)
    if provider == "external":
        with bind_runtime_context(f.runtime):
            f.dependencies["host_store"].update_harness_readiness(
                host_id, {"openai-agents": "binary-missing"}
            )
        _assert_preview(f, target, reason="host_unavailable")
        other_host_id = uuid4().hex
        with bind_runtime_context(f.runtime):
            f.dependencies["host_store"].upsert_on_connect(
                other_host_id,
                "other-host",
                "another-user",
                configured_harnesses={"openai-agents": True},
            )
        target["host_id"] = other_host_id
        _assert_preview(f, target, reason="host_unavailable")
        target["host_id"] = uuid4().hex
        _assert_preview(f, target, reason="host_unavailable")
    else:
        f.app.state.sandbox_config = None
        _assert_preview(f, target, reason="sandbox_unavailable")


@pytest.mark.parametrize(
    "failure,reason",
    [
        ("disabled", "runtime_not_enabled"),
        ("controller_missing", "runtime_unavailable"),
        ("controller_failed", "runtime_unavailable"),
        ("project_missing", "project_required"),
        ("project_foreign", "project_not_accessible"),
        ("project_revoked", "project_not_accessible"),
        ("agent_missing", "model_harness_unsupported"),
        ("harness_unsupported", "sandbox_unavailable"),
        ("subscription_suspended", "pricing_unavailable"),
        ("price_expired", "pricing_unavailable"),
        ("price_future", "pricing_unavailable"),
        ("price_wrong_plan", "pricing_unavailable"),
        ("price_overlap", "pricing_unavailable"),
        ("price_missing_rate", "pricing_unavailable"),
    ],
)
def test_preview_is_fail_closed_for_current_scope_runtime_and_prices(
    interactive_http, failure, reason
):
    f = interactive_http
    target, price = _setup(f)
    if failure == "disabled":
        f.store._runtime_enabled = False
    elif failure == "controller_missing":
        f.store.runtime_readiness_check = None
    elif failure == "controller_failed":

        def unavailable():
            raise RuntimeError("internal-only controller diagnostic")

        f.store.runtime_readiness_check = unavailable
    elif failure == "project_missing":
        target["project_id"] = ""
    elif failure == "project_foreign":
        target["project_id"] = uuid4().hex
    elif failure == "project_revoked":
        with f.factory.begin() as db:
            db.execute(sa.update(ProjectMembershipRecord).values(status="revoked", version=2))
    elif failure == "agent_missing":
        target["agent_id"] = uuid4().hex
    elif failure == "harness_unsupported":
        target["harness"] = "claude"
    elif failure == "subscription_suspended" or failure.startswith("price_"):
        with f.factory.begin() as db:
            if failure == "subscription_suspended":
                db.execute(sa.update(BillingSubscriptionRecord).values(status="suspended"))
            else:
                row = db.get(PricingSnapshotRecord, price)
                if failure == "price_expired":
                    row.effective_until = datetime.now(timezone.utc) - timedelta(minutes=1)
                elif failure == "price_future":
                    row.effective_from = datetime.now(timezone.utc) + timedelta(minutes=1)
                elif failure == "price_wrong_plan":
                    row.plan_key = "another-plan"
                elif failure == "price_overlap":
                    db.add(
                        PricingSnapshotRecord(
                            id=uuid4(),
                            tenant_id=row.tenant_id,
                            plan_key=row.plan_key,
                            currency=row.currency,
                            rates=row.rates,
                            version=row.version + 1,
                            effective_from=row.effective_from,
                            effective_until=row.effective_until,
                            created_by=row.created_by,
                        )
                    )
                else:
                    row.rates = {}
    _assert_preview(f, target, reason=reason, enabled=failure != "disabled")


@pytest.mark.parametrize("interactive_http", [{"catalog_billing": False}], indirect=True)
def test_preview_without_billing_login_is_not_available(interactive_http):
    f = interactive_http
    target, _ = _setup(f)
    _assert_preview(f, target, reason="pricing_unavailable")


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": "caller-supplied"},
        {"project_id": "x" * 129},
        {"host_type": "unknown"},
        {"host_id": "a" * 32},
        {"host_type": "external", "host_id": "not-a-host"},
        {"sandbox_provider": "unsupported"},
        {"harness": ""},
    ],
)
def test_preview_rejects_scope_injection_and_ambiguous_targets(interactive_http, change):
    f = interactive_http
    target, _ = _setup(f)
    before = _effects(f)
    response = f.client.get("/v1/managed-model-catalog", params={**target, **change})
    assert response.status_code == 400, response.text
    assert response.json() == {"detail": {"code": "model_catalog_request_invalid"}}
    assert _effects(f) == before


def test_preview_rejects_duplicate_parameters_and_redacts_backend_failures(
    interactive_http, monkeypatch
):
    f = interactive_http
    target, _ = _setup(f)
    duplicate = [*target.items(), ("project_id", uuid4().hex)]
    assert f.client.get("/v1/managed-model-catalog", params=duplicate).status_code == 400

    def fail(*_args, **_kwargs):
        raise RuntimeError("postgresql://sensitive-database-credentials")

    monkeypatch.setattr(f.store._admission, "require_selection_project", fail)
    response = f.client.get("/v1/managed-model-catalog", params=target)
    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "managed_model_catalog_unavailable"}}
