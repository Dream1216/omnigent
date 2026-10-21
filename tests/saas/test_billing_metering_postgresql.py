from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session, sessionmaker

from omnigent.llms.client import Client, _ResponsesNamespace
from omnigent.llms.types import MessageOutput, OutputText, Response, Usage
from saas.billing_metering_transport import (
    BillingMeteringTransportError,
    MutualTlsBillingMeteringServer,
)
from saas.compatibility import RequestContext
from saas.control_plane import (
    BillingControlPlane,
    BillingMeteringAuthority,
    BillingMeteringError,
    EgressPolicyRecord,
    ExecutionControlPlane,
    ExecutionProfileRecord,
    ExecutionRevisionSet,
    GlobalUser,
    ModelProviderBudgetAdmissionService,
    ModelProviderConfigurationRecord,
    PlatformStaffPrincipalRecord,
    ProjectMembershipRecord,
    ProjectRecord,
    RunnerCertificateAuthority,
    RuntimePlacementRecord,
    SchedulingControlPlane,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.schema_revision import CONTROL_PLANE_SCHEMA_REVISION
from saas.runner_adapter.metering import (
    ManagedMeteringGrant,
    ProviderUsageMeter,
    build_metering_client,
)
from tests.saas.test_billing_metering_transport import (
    _certificate_fixture,
    _server_context,
    _ServerThread,
)


def _postgres_url() -> str:
    url = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for metering RLS acceptance")
    return url


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(engine: sa.Engine, role: str) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _set_role(_session: Session, _transaction: object, connection: sa.Connection) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return factory


@pytest.mark.parametrize("freeze_before_run", (False, True), ids=("legacy", "frozen-price"))
def test_real_postgresql_machine_metering_exact_identity_rls_and_fencing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    isolated_postgres_url: str,
    freeze_before_run: bool,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url, pool_size=4, max_overflow=2)
    suffix = uuid4().hex[:12]
    roles = {
        name: f"saas_{name}_metering_acceptance_{suffix}"
        for name in ("platform", "app", "billing", "executor", "metering")
    }
    metering_password = "isolated-receipt-recovery-test-only"
    with engine.begin() as connection:
        _migrate(connection, root)
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        for base, child in roles.items():
            authentication = (
                f"LOGIN PASSWORD '{metering_password}'" if base == "metering" else "NOLOGIN"
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {child} {authentication} NOSUPERUSER NOBYPASSRLS INHERIT; "
                f"GRANT saas_{base} TO {child}"
            )
        connection.exec_driver_sql(
            f'GRANT CONNECT ON DATABASE "{sa.make_url(isolated_postgres_url).database}" '
            f"TO {roles['metering']}"
        )

    platform_factory = _role_factory(engine, roles["platform"])
    app_factory = _role_factory(engine, roles["app"])
    billing_factory = _role_factory(engine, roles["billing"])
    executor_factory = _role_factory(engine, roles["executor"])
    metering_engine = sa.create_engine(
        sa.make_url(isolated_postgres_url).set(
            username=roles["metering"], password=metering_password
        )
    )
    metering_factory = sessionmaker(metering_engine, expire_on_commit=False)
    with metering_engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT current_user=session_user").scalar_one()
    execution = ExecutionControlPlane(app_factory)
    platform_scheduling = SchedulingControlPlane(platform_factory)
    scheduling = SchedulingControlPlane(executor_factory)
    billing = BillingControlPlane(billing_factory)
    authority = BillingMeteringAuthority(metering_factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    owner_id, tenant_id, space_id, project_id, placement_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    execution_profile_id = uuid4()
    execution_profile_hash = "5" * 64
    other_owner, other_tenant = uuid4(), uuid4()
    context = RequestContext(
        actor_id=owner_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="postgres-machine-metering",
    )
    with platform_factory.begin() as db:
        db.add_all(
            [
                GlobalUser(id=owner_id, status="active", security_version=1),
                GlobalUser(id=other_owner, status="active", security_version=1),
                RuntimePlacementRecord(
                    id=placement_id,
                    runtime_type="omnigent",
                    data_region="cn-east-1",
                    failure_domain="cn-east-1a",
                    database_cluster_ref="db-a",
                    object_store_ref="objects-a",
                    kms_key_ref="kms-a",
                    official_schema_revision="runtime-schema-v1",
                    capacity_class="shared-medium",
                    status="active",
                ),
                Tenant(
                    id=tenant_id,
                    slug=f"metering-a-{suffix}",
                    name="Metering A",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
                Tenant(
                    id=other_tenant,
                    slug=f"metering-b-{suffix}",
                    name="Metering B",
                    status="active",
                    plan="team",
                    home_region="cn-east-1",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                TenantMembership(
                    tenant_id=other_tenant,
                    user_id=other_owner,
                    role="owner",
                    status="active",
                    version=1,
                ),
                Space(
                    id=space_id,
                    tenant_id=tenant_id,
                    slug="engineering",
                    name="Engineering",
                    status="active",
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                SpaceMembership(
                    tenant_id=tenant_id,
                    space_id=space_id,
                    user_id=owner_id,
                    role="owner",
                    status="active",
                    version=1,
                ),
                ProjectRecord(
                    id=project_id,
                    tenant_id=tenant_id,
                    space_id=space_id,
                    name="Metering project",
                    visibility="restricted",
                    created_by=owner_id,
                    status="active",
                    authorization_version=1,
                ),
            ]
        )
        db.flush()
        db.add(
            ProjectMembershipRecord(
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                subject_type="user",
                subject_id=owner_id,
                role="owner",
                status="active",
                created_by=owner_id,
                version=1,
            )
        )
        egress_policy_id = uuid4()
        db.add(
            EgressPolicyRecord(
                id=egress_policy_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                created_by=owner_id,
                name="metering-default-deny",
                rules=[],
                rules_hash="0" * 64,
                allow_private_destinations=False,
                status="active",
                version=1,
            )
        )
        db.flush()
        db.add(
            ExecutionProfileRecord(
                id=execution_profile_id,
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                egress_policy_id=egress_policy_id,
                created_by=owner_id,
                name="metering-managed-default",
                sandbox_backend="linux_bwrap",
                network_mode="proxy_only",
                root_read_only=True,
                run_as_uid=65532,
                run_as_gid=65532,
                no_new_privileges=True,
                host_socket_access=False,
                syscall_profile_ref="oci-default-v1",
                cpu_millis=1000,
                memory_bytes=512 * 1024 * 1024,
                pids_limit=128,
                allowed_tools=["shell"],
                approval_required_tools=[],
                denied_tools=[],
                config_hash=execution_profile_hash,
                status="active",
                version=1,
            )
        )

    def configure_pricing():
        for current_tenant, current_owner, label in (
            (tenant_id, owner_id, "a"),
            (other_tenant, other_owner, "b"),
        ):
            billing.configure_subscription(
                actor_id=current_owner,
                tenant_id=current_tenant,
                plan_key="team-v1",
                status="active",
                current_period_start=now - timedelta(hours=1),
                current_period_end=now + timedelta(days=30),
                expected_version=None,
                idempotency_key=f"metering-subscription-{label}-{suffix}",
            )
            billing.create_pricing_snapshot(
                actor_id=current_owner,
                tenant_id=current_tenant,
                plan_key="team-v1",
                currency="USD",
                rates={
                    "llm.input_tokens": {
                        "unit": "tokens",
                        "unit_size": "1000",
                        "minor_per_unit": 25,
                    }
                },
                effective_from=now - timedelta(hours=1),
                effective_until=now + timedelta(days=30),
                idempotency_key=f"metering-pricing-{label}-{suffix}",
            )

    if freeze_before_run:
        configure_pricing()
    execution.configure_quota(
        context,
        project_id=project_id,
        resource="run_units",
        limit_units=10,
    )
    task_id = execution.create_task(context, project_id=project_id, title="Metered Run")
    run_id = execution.admit_run(
        context,
        project_id=project_id,
        task_id=task_id,
        session_id=None,
        input_payload={"prompt": "billing role and metering role must never read this"},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key=f"metered-run-{suffix}",
        revisions=ExecutionRevisionSet(
            product_revision="product",
            upstream_revision="upstream",
            schema_revision="p6a000000009",
            adapter_contract_version="0.2.0",
        ),
    ).run_id
    pool_id = platform_scheduling.create_pool(
        placement_id=placement_id,
        name=f"metering-pool-{suffix}",
        queue_class="interactive",
        capacity_slots=2,
        reserved_slots=0,
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
    )
    scheduling.configure_tenant_share(
        tenant_id=tenant_id,
        pool_id=pool_id,
        weight=1,
        max_concurrent=1,
        burst_limit=1,
    )
    scheduling.prepare_dispatch(
        run_id=run_id,
        pool_id=pool_id,
        required_capabilities=["shell"],
        execution_profile_id=execution_profile_id,
        execution_profile_hash=execution_profile_hash,
        eligible_at=now - timedelta(seconds=1),
        maximum_wait=timedelta(hours=1),
    )
    runner = scheduling.register_runner(
        pool_id=pool_id,
        instance_key=f"runner-{suffix}",
        failure_domain="cn-east-1a",
        protocol_version=2,
        source_revision="upstream",
        schema_revision="runtime-schema-v1",
        adapter_contract_version="0.2.0",
        capabilities=["shell"],
        max_concurrency=1,
        now=now,
    )
    lease = scheduling.claim_fair_run(
        runner_id=runner.runner_id,
        connection_generation=runner.connection_generation,
        connection_token=runner.connection_token,
        lease_duration=timedelta(minutes=10),
        capability_actions=["billing.usage.record"],
        capability_resource_scope={"billing_meter": "llm.input_tokens"},
        now=now + timedelta(seconds=1),
    )
    assert lease is not None
    certificates = _certificate_fixture(tmp_path, (runner.runner_id,))
    runner_certificate = x509.load_pem_x509_certificate(
        certificates["runner-0"].certificate.read_bytes()
    )
    runner_certificate_der = runner_certificate.public_bytes(serialization.Encoding.DER)
    certificate_platform = RunnerCertificateAuthority(
        platform_factory, accepted_trust_bundle_versions=("test-v1",)
    )
    certificate_metering = RunnerCertificateAuthority(
        metering_factory, accepted_trust_bundle_versions=("test-v1",)
    )
    activated = certificate_platform.activate_certificate(
        runner_id=runner.runner_id,
        runner_connection_generation=runner.connection_generation,
        purpose="billing_metering",
        certificate_der=runner_certificate_der,
        trust_bundle_version="test-v1",
        now=now,
    )
    fingerprint = activated.fingerprint_sha256
    if not freeze_before_run:
        configure_pricing()
    platform_model_principal = uuid4()
    with platform_factory.begin() as db:
        db.add(
            PlatformStaffPrincipalRecord(
                id=platform_model_principal,
                identity_connection_ref=f"metering-model:{suffix}",
                issuer="https://staff-idp.example.test",
                subject=f"metering-model-{suffix}",
                status="active",
                security_version=1,
            )
        )
        db.flush()
        db.add(
            ModelProviderConfigurationRecord(
                provider_id="deepseek",
                enabled=True,
                base_url="https://api.deepseek.com",
                api_type="openai_chat_completions",
                api_key_ciphertext="encrypted-platform-model-key",
                allowed_models=["deepseek-v4-flash"],
                default_model="deepseek-v4-flash",
                monthly_budget_microusd=1_000_000,
                per_tenant_daily_token_limit=10_000,
                verification_status="verified",
                last_verified_model="deepseek-v4-flash",
                last_verified_at=now,
                version=1,
                updated_by_principal_id=platform_model_principal,
                updated_at=now,
            )
        )

    metering_server = MutualTlsBillingMeteringServer(
        authority,
        _server_context(certificates["server"]),
        certificate_metering,
    )
    server_thread = _ServerThread(metering_server)
    server_thread.start()
    grant = ManagedMeteringGrant(
        session_id=uuid4(),
        run_id=run_id,
        runner_id=runner.runner_id,
        capability_token=lease.capability_token,
        expires_at=now + timedelta(minutes=10),
        metering_base_url=f"https://127.0.0.1:{metering_server.port}",
        expected_host="billing-metering.internal",
        ca_certificate_path=certificates["runner-0"].ca.absolute(),
        client_certificate_path=certificates["runner-0"].certificate.absolute(),
        client_key_path=certificates["runner-0"].private_key.absolute(),
        spool_directory=(tmp_path / "provider-spool").absolute(),
    )
    response = Response(
        output=[MessageOutput(content=[OutputText(text="never persisted in billing")])],
        model="openai/gpt-test",
        usage=Usage(input_tokens=1500, output_tokens=0, total_tokens=1500),
    )

    async def provider_response(*_args: object, **_kwargs: object) -> Response:
        return response

    monkeypatch.setattr(_ResponsesNamespace, "_do_create", provider_response, raising=True)
    provider_meter = ProviderUsageMeter(
        grant=grant,
        client=build_metering_client(grant),
        retry_interval_seconds=60,
    )
    try:
        asyncio.run(Client().responses.create(input=[], model="openai/gpt-test"))
        assert provider_meter.flush()
    finally:
        assert provider_meter.close()
        server_thread.close()

    with platform_factory() as db:
        provider_usage = db.execute(
            sa.text(
                "SELECT meter, quantity, customer_charge_minor, attributes "
                "FROM saas_usage_events WHERE run_id = :run "
                "AND provider_request_id LIKE 'omnigent-observer-%'"
            ),
            {"run": run_id},
        ).one()
    assert provider_usage[:3] == ("llm.input_tokens", 1500, 38)
    assert provider_usage.attributes == {
        "model": "openai/gpt-test",
        "operation": "responses.create",
    }

    request: dict[str, Any] = {
        "runner_id": runner.runner_id,
        "certificate_fingerprint_sha256": fingerprint,
        "capability_token": lease.capability_token,
        "run_id": run_id,
        "meter": "llm.input_tokens",
        "quantity": "1500",
        "unit": "tokens",
        "provider": "openai",
        "provider_request_id": f"provider-{suffix}",
        "idempotency_key": f"metering-{suffix}",
        "occurred_at": now + timedelta(seconds=2),
        "attributes": {"model": "gpt-5"},
        "now": now + timedelta(seconds=2),
    }
    created = authority.record_usage(**request)
    replayed = authority.record_usage(**request)
    assert created.customer_charge_minor == 38
    assert replayed.receipt_id == created.receipt_id
    assert replayed.replayed is True

    model_budget = ModelProviderBudgetAdmissionService(billing_factory)
    reservation = model_budget.reserve(
        tenant_id=tenant_id,
        run_id=run_id,
        operation_key=f"metering-platform-model-{suffix}",
        requested_microusd=500_000,
        requested_tokens=2_000,
        ttl=timedelta(minutes=5),
        now=now + timedelta(seconds=2),
    )
    model_request = {
        **request,
        "provider": "deepseek",
        "provider_request_id": f"deepseek-provider-{suffix}",
        "idempotency_key": f"deepseek-metering-{suffix}",
        "quantity": "1000",
        "model_budget_reservation_id": reservation.id,
    }
    model_usage = authority.record_usage(**model_request)
    assert model_usage.model_budget_reservation_id == reservation.id
    finalized = model_budget.release(
        reservation_id=reservation.id,
        now=now + timedelta(seconds=3),
    )
    assert (finalized.settled_microusd, finalized.settled_tokens) == (250_000, 1_000)
    assert (finalized.released_microusd, finalized.released_tokens) == (250_000, 1_000)

    billing.configure_subscription(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v2",
        status="active",
        current_period_start=now - timedelta(hours=1),
        current_period_end=now + timedelta(days=30),
        expected_version=1,
        idempotency_key=f"plan-change-{suffix}",
    )
    changed = billing.create_pricing_snapshot(
        actor_id=owner_id,
        tenant_id=tenant_id,
        plan_key="team-v2",
        currency="USD",
        rates={"llm.input_tokens": {"unit": "tokens", "unit_size": "1000", "minor_per_unit": 250}},
        effective_from=now - timedelta(hours=1),
        effective_until=now + timedelta(days=30),
        idempotency_key=f"changed-price-{suffix}",
    )
    after_change = authority.record_usage(
        **{
            **request,
            "provider_request_id": f"changed-{suffix}",
            "idempotency_key": f"changed-{suffix}",
        }
    )
    assert after_change.customer_charge_minor == (38 if freeze_before_run else 375)
    assert (after_change.pricing_snapshot_id == changed.id) is not freeze_before_run
    assert authority.record_usage(**request).receipt_id == created.receipt_id
    if freeze_before_run:
        original_pricing = BillingMeteringAuthority._effective_pricing

        def legacy_pricing(db, *, tenant_id, happened, run):
            return original_pricing(
                db,
                tenant_id=tenant_id,
                happened=happened,
                run=replace(run, customer_pricing_frozen=False, customer_pricing_snapshot_id=None),
            )

        with monkeypatch.context() as legacy:
            legacy.setattr(
                BillingMeteringAuthority, "_effective_pricing", staticmethod(legacy_pricing)
            )
            with pytest.raises(sa.exc.DBAPIError, match="frozen customer pricing"):
                authority.record_usage(
                    **{
                        **request,
                        "provider_request_id": f"legacy-producer-{suffix}",
                        "idempotency_key": f"legacy-producer-{suffix}",
                    }
                )

    capability_hash = sha256(lease.capability_token.encode()).hexdigest()
    with engine.begin() as connection:
        connection.exec_driver_sql(f"SET LOCAL ROLE {roles['metering']}")
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_capability_tokens")).scalar_one()
            == 0
        )
        connection.execute(
            sa.text("SELECT set_config('app.capability_token_hash', :digest, true)"),
            {"digest": capability_hash},
        )
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_capability_tokens")).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_billing_subscriptions")
            ).scalar_one()
            == 1
        )
        privileges = connection.execute(
            sa.text(
                "SELECT "
                "has_column_privilege(current_user, 'saas_runs', 'input', 'SELECT'), "
                "has_table_privilege(current_user, 'saas_projects', 'SELECT'), "
                "has_table_privilege(current_user, 'saas_secret_bindings', 'SELECT'), "
                "has_table_privilege(current_user, 'saas_api_credentials', 'SELECT'), "
                "has_table_privilege(current_user, 'saas_customer_ledger_entries', 'SELECT')"
            )
        ).one()
        assert privileges == (False, False, False, False, False)

    with pytest.raises(sa.exc.DBAPIError, match="row-level security policy"):
        with engine.begin() as connection:
            connection.exec_driver_sql(f"SET LOCAL ROLE {roles['metering']}")
            connection.execute(
                sa.text(
                    "SELECT "
                    "set_config('app.presented_certificate_fingerprint', :fingerprint, true), "
                    "set_config('app.presented_certificate_purpose', 'billing_metering', true)"
                ),
                {"fingerprint": fingerprint},
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_runner_registrations SET updated_at = updated_at "
                    "WHERE id = :runner"
                ),
                {"runner": runner.runner_id},
            )

    with platform_factory.begin() as db:
        db.execute(
            sa.text("UPDATE saas_runs SET fence_token = fence_token + 1 WHERE id = :run"),
            {"run": run_id},
        )
    with pytest.raises(BillingMeteringError) as stale:
        authority.record_usage(
            **{  # type: ignore[bad-argument-type]
                **request,
                "provider_request_id": f"provider-stale-{suffix}",
                "idempotency_key": f"metering-stale-{suffix}",
            }
        )
    assert stale.value.code == "metering_fence_stale"

    def financial_counts():
        with engine.connect() as connection:
            return connection.exec_driver_sql(
                "SELECT (SELECT count(*) FROM saas_usage_events),"
                "(SELECT count(*) FROM saas_billing_metering_receipts),"
                "(SELECT count(*) FROM saas_control_plane_outbox "
                "WHERE event_type='billing.usage.recorded')"
            ).one()

    counts_before_recovery = financial_counts()

    # A lost confirmation remains recoverable after the actual Run terminalizes.
    with platform_factory() as db:
        row = db.execute(
            sa.text("SELECT lease_token,fence_token FROM saas_runs WHERE id=:run"),
            {"run": run_id},
        ).one()
    terminalizer = ExecutionControlPlane(platform_factory)
    for status in ("starting", "running", "succeeded"):
        terminalizer.transition_run(
            run_id=run_id,
            lease_token=row.lease_token,
            fence_token=row.fence_token,
            target_status=status,
            trace_id="receipt-recovery",
            now=now + timedelta(seconds=3),
        )
    recovered = authority.record_usage(**request)
    assert recovered.replayed and recovered.receipt_id == created.receipt_id
    assert recovered.customer_charge_minor == created.customer_charge_minor
    assert (
        authority.record_usage(**{**request, "now": now + timedelta(minutes=11)}).receipt_id
        == created.receipt_id
    )
    for changed_request in (
        {"quantity": "1501"},
        {"idempotency_key": f"late-new-fact-{suffix}"},
        {"provider_request_id": f"different-provider-request-{suffix}"},
        {"certificate_fingerprint_sha256": "f" * 64},
    ):
        with pytest.raises(BillingMeteringError):
            authority.record_usage(**{**request, **changed_request})
    assert authority.record_usage(**model_request).receipt_id == model_usage.receipt_id
    assert model_budget.release(reservation_id=reservation.id).settled_microusd == 250_000

    recovery_server = MutualTlsBillingMeteringServer(
        authority, _server_context(certificates["server"]), certificate_metering
    )
    recovery_thread = _ServerThread(recovery_server)
    recovery_thread.start()
    recovery_client = build_metering_client(
        replace(grant, metering_base_url=f"https://127.0.0.1:{recovery_server.port}")
    )
    wire_request = {
        key: value
        for key, value in request.items()
        if key not in {"certificate_fingerprint_sha256", "now"}
    }
    try:
        wire_receipt = recovery_client.record_usage(**wire_request)
        assert wire_receipt.replayed and wire_receipt.receipt_id == created.receipt_id
        with pytest.raises(BillingMeteringTransportError):
            recovery_client.record_usage(
                **{**wire_request, "idempotency_key": f"terminal-new-fact-{suffix}"}
            )
    finally:
        recovery_client.close()
        recovery_thread.close()
    assert financial_counts() == counts_before_recovery

    with pytest.raises(sa.exc.DBAPIError, match="Billing fact is append-only"):
        with platform_factory.begin() as db:
            db.execute(
                sa.text(
                    "UPDATE saas_billing_metering_receipts SET request_hash = request_hash "
                    "WHERE id = :receipt"
                ),
                {"receipt": created.receipt_id},
            )

    metering_engine.dispose()
    with engine.begin() as connection:
        connection.exec_driver_sql(
            f'REVOKE CONNECT ON DATABASE "{sa.make_url(isolated_postgres_url).database}" '
            f"FROM {roles['metering']}"
        )
        posture = connection.execute(
            sa.text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname IN ('saas_metering', :child) ORDER BY rolname"
            ),
            {"child": roles["metering"]},
        ).all()
        assert len(posture) == 2
        assert all(not superuser and not bypass for _role, superuser, bypass in posture)

        config = Config(root / "saas/control_plane/alembic.ini")
        config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
        config.attributes["connection"] = connection
        before = _retained_metering_snapshot(connection)
        with pytest.raises(
            RuntimeError,
            match=(
                r"^(retained execution schema cannot be downgraded|"
                r"retained model budgets require owner settlement policy)$"
            ),
        ):
            with connection.begin_nested():
                command.downgrade(config, "p6a000000008")
        assert _retained_metering_snapshot(connection) == before
        assert (
            connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
            == CONTROL_PLANE_SCHEMA_REVISION
        )
        for base, child in reversed(tuple(roles.items())):
            connection.exec_driver_sql(f"REVOKE saas_{base} FROM {child}")
            connection.exec_driver_sql(f"DROP ROLE {child}")
    engine.dispose()


def _retained_metering_snapshot(connection: sa.Connection) -> dict[str, str]:
    tables = (
        "saas_execution_sessions",
        "saas_runs",
        "saas_run_dispatches",
        "saas_runner_certificates",
        "saas_usage_events",
        "saas_billing_metering_receipts",
        "saas_customer_ledger_entries",
        "saas_control_plane_outbox",
    )
    return {
        table: sha256(
            connection.exec_driver_sql(
                "SELECT COALESCE(jsonb_agg(to_jsonb(retained) "
                "ORDER BY to_jsonb(retained)::text), '[]'::jsonb)::text "
                f"FROM {table} AS retained"
            )
            .scalar_one()
            .encode()
        ).hexdigest()
        for table in tables
    }
