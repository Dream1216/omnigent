from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_connections import CreateModelConnection, ModelConnectionService
from saas.control_plane.model_deployments import (
    ModelDeploymentService,
    compile_stored_model_deployment,
)
from saas.control_plane.model_projection import ModelCredentialProjectionPublisher
from saas.control_plane.model_routing_models import (
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelVerificationBudgetBindingRecord,
)
from saas.control_plane.model_test_funding import ModelTestFundingPolicy, ModelTestFundingService
from saas.control_plane.model_verifications import ModelVerificationService
from saas.control_plane.platform_security import PlatformAuthorizationService
from saas.production.model_protocol_probe import (
    ModelProtocolProbe,
    ModelProtocolProbeConfiguration,
)
from saas.production.model_verification import ModelVerificationPublisher
from tests.saas.test_model_connections import _KEY, _fixture
from tests.saas.test_model_deployments import _command
from tests.saas.test_model_protocol_probe import _body, _events
from tests.saas.test_model_verification_worker import _StoredAttestor
from tests.saas.test_model_verifications import _pricing


def test_real_postgresql_empty_verification_downgrade_restores_authority(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    roles = (root / "saas/control_plane/postgresql_roles.sql").read_text()

    def authority(connection):
        return {
            "guard": connection.scalar(
                sa.text(
                    "SELECT pg_get_functiondef("
                    "'public.saas_model_projection_transition_guard()'::regprocedure)"
                )
            ),
            "policies": connection.execute(
                sa.text(
                    "SELECT tablename, policyname, roles::text, cmd, qual, with_check "
                    "FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname"
                )
            ).all(),
            "rls": connection.execute(
                sa.text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relnamespace = 'public'::regnamespace "
                    "AND relkind = 'r' ORDER BY relname"
                )
            ).all(),
            "column_grants": connection.execute(
                sa.text(
                    "SELECT table_name, column_name, privilege_type "
                    "FROM information_schema.column_privileges "
                    "WHERE grantee = 'saas_model_projection' ORDER BY 1, 2, 3"
                )
            ).all(),
            "constraints": connection.execute(
                sa.text(
                    "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) "
                    "FROM pg_constraint WHERE connamespace = 'public'::regnamespace "
                    "ORDER BY 1, 2"
                )
            ).all(),
        }

    try:
        with engine.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "lm1e00000001")
            connection.exec_driver_sql(roles)
            baseline = authority(connection)
            command.upgrade(config, "head")
            connection.exec_driver_sql(roles)
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM pg_class "
                        "WHERE relnamespace = 'public'::regnamespace "
                        "AND relname IN ('saas_model_verification_commands', "
                        "'saas_model_verification_budget_bindings', "
                        "'saas_model_verification_receipts') "
                        "AND relrowsecurity AND relforcerowsecurity"
                    )
                )
                == 3
            )
            command.downgrade(config, "lm1e00000001")
            connection.exec_driver_sql(roles)
            assert authority(connection) == baseline
            command.upgrade(config, "head")
            connection.exec_driver_sql(roles)
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "lm1f00000001"
            )
    finally:
        engine.dispose()


def test_real_postgresql_model_test_requires_staff_projection_and_billing_identities(
    isolated_postgres_url: str, monkeypatch
) -> None:
    root = Path(__file__).resolve().parents[2]
    owner = sa.create_engine(isolated_postgres_url)
    roles = {
        role: "verification_" + uuid4().hex
        for role in ("saas_platform_app", "saas_model_projection", "saas_billing")
    }
    password = "isolated-verification-role-contract-only"
    quote = owner.dialect.identifier_preparer.quote
    database = sa.make_url(isolated_postgres_url).database
    assert database is not None
    engines = {}
    try:
        with owner.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            for role, login in roles.items():
                connection.exec_driver_sql(
                    f"CREATE ROLE {quote(login)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
                )
                connection.exec_driver_sql(
                    f"GRANT {role} TO {quote(login)} WITH INHERIT TRUE, SET FALSE"
                )
                connection.exec_driver_sql(
                    f"GRANT CONNECT ON DATABASE {quote(database)} TO {quote(login)}"
                )
        _connections, factory, actor, cipher, _client, _headers = _fixture(engine=owner)
        for role, login in roles.items():
            engines[role] = sa.create_engine(
                sa.make_url(isolated_postgres_url).set(username=login, password=password)
            )
        staff, worker, billing = (engines[role] for role in roles)
        staff_factory = sessionmaker(staff, expire_on_commit=False)
        authorization = PlatformAuthorizationService(staff_factory)
        connections = ModelConnectionService(
            staff_factory, authorization=authorization, secret_cipher=cipher
        )
        deployments = ModelDeploymentService(staff, authorization=authorization)
        funding = ModelTestFundingService(staff, authorization=authorization)
        funding.configure(
            actor,
            expected_version=0,
            policy=ModelTestFundingPolicy(True, 1000, 1000, 10000, 1000, 1056, 10),
        )
        models, calls = {}, []

        def manage(request):
            calls.append(request.url.path)
            if request.url.path == "/model/info":
                return httpx.Response(200, json={"data": list(models.values())})
            payload = json.loads(request.content)
            if request.url.path == "/model/new":
                models[payload["model_name"]] = payload
            if request.url.path == "/key/generate":
                return httpx.Response(200, json={"key": "isolated-verification-inference-key"})
            return httpx.Response(200, json={"status": "success"})

        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url="https://litellm.test", management_key="isolated-management-role-key"
            ),
            transport=httpx.MockTransport(manage),
        )
        projection = ModelCredentialProjectionPublisher(
            worker, secret_cipher=cipher, management=management
        )

        def envelope(operation_id):
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

        credential = connections.create(
            actor,
            command=CreateModelConnection("verification provider", _KEY),
            idempotency_key="pg-verified-connection",
        )
        projection.publish(**envelope(credential.id))
        draft_op = deployments.create(
            actor,
            command=replace(
                _command(),
                connection_id=credential.connection_id,
                credential_version_id=credential.credential_version_id,
            ),
            idempotency_key="pg-verification-draft",
        )
        projection.publish(**envelope(draft_op.id))
        with factory() as db:
            draft = compile_stored_model_deployment(
                db.get(ModelDeploymentVersionRecord, draft_op.deployment_version_id)
            )
        service = ModelVerificationService(staff, authorization=authorization, pricing=_pricing())
        test_request = {
            "deployment_id": draft.deployment_id,
            "configuration_sha256": draft.configuration_sha256,
            "expected_funding_policy_version": 1,
            "idempotency_key": "pg-priced-test",
        }
        operation = service.admit(actor, **test_request)
        assert service.admit(actor, **test_request) == operation
        budget = ModelProviderBudgetAdmissionService(sessionmaker(billing, expire_on_commit=False))
        inference_calls = []

        def infer(request):
            inference_calls.append(request.url.path)
            with billing.connect() as observer:
                assert observer.scalar(sa.text("SELECT current_user")) == roles["saas_billing"]
                assert (
                    observer.scalar(
                        sa.text("SELECT status FROM saas_model_provider_budget_reservations")
                    )
                    == "in_flight"
                )
            with worker.connect() as observer:
                assert (
                    observer.scalar(sa.text("SELECT current_user"))
                    == roles["saas_model_projection"]
                )
                assert (
                    observer.scalar(
                        sa.text("SELECT count(*) FROM saas_model_verification_budget_bindings")
                    )
                    == 1
                )
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, content=_body(_events(draft))
            )

        publisher = ModelVerificationPublisher(
            worker,
            management=management,
            budget=budget,
            attestor=_StoredAttestor(),
            secret_cipher=cipher,
            probe=ModelProtocolProbe(
                ModelProtocolProbeConfiguration(base_url="https://litellm.test"),
                transport=httpx.MockTransport(infer),
            ),
        )
        original = budget.resolve_attempt
        failed = False

        def unavailable(**kwargs):
            nonlocal failed
            if not failed:
                failed = True
                raise RuntimeError("isolated financial service unavailable")
            return original(**kwargs)

        monkeypatch.setattr(budget, "resolve_attempt", unavailable)
        with pytest.raises(RuntimeError, match="financial service"):
            publisher.publish(**envelope(operation.id))
        with worker.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT outcome FROM saas_model_verification_receipts"))
                == "passed"
            )
        with pytest.raises(DBAPIError) as gated, worker.begin() as connection:
            connection.execute(
                sa.update(ModelProjectionOperationRecord)
                .where(ModelProjectionOperationRecord.id == operation.id)
                .values(status="verified", version=3)
            )
        assert getattr(gated.value.orig, "sqlstate", None) == "23514"
        publisher.publish(**envelope(operation.id))
        publisher.publish(**envelope(operation.id))
        assert inference_calls == ["/v1/chat/completions"]
        assert service.receipt(actor, operation.id)["operation"]["status"] == "verified"
        for engine, statement in (
            (staff, "INSERT INTO saas_model_verification_receipts DEFAULT VALUES"),
            (staff, "UPDATE saas_model_verification_commands SET requested_tokens=1"),
            (worker, "UPDATE saas_model_verification_receipts SET actual_microusd=0"),
            (worker, "SELECT tenant_id FROM saas_model_provider_budget_reservations"),
            (worker, "UPDATE saas_model_provider_budget_reservations SET settled_microusd=0"),
            (billing, "SELECT api_key_ciphertext FROM saas_model_credential_versions"),
            (billing, "SET ROLE saas_model_projection"),
        ):
            with pytest.raises(DBAPIError) as denied, engine.connect() as connection:
                connection.exec_driver_sql(statement)
            assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        another = service.admit(
            actor, **{**test_request, "idempotency_key": "pg-cross-budget-binding"}
        )
        claim = publisher._claim(
            another.id, another.credential_version_id, envelope(another.id)["event_id"]
        )
        assert claim is not None and claim.send
        third = service.admit(actor, **{**test_request, "idempotency_key": "pg-real-other-budget"})
        other_budget = budget.reserve_platform_test(
            verification_id=third.id,
            actor_principal_id=actor.principal_id,
            configuration_sha256=draft.configuration_sha256,
            expected_policy_version=1,
            operation_key="real-other-command-hold",
            requested_microusd=3,
            requested_tokens=1056,
            ttl=timedelta(minutes=2),
        )
        with pytest.raises(DBAPIError) as wrong_binding, worker.begin() as connection:
            connection.execute(
                sa.insert(ModelVerificationBudgetBindingRecord).values(
                    operation_id=another.id,
                    budget_reservation_id=other_budget.id,
                    configuration_sha256=draft.configuration_sha256,
                    funding_policy_version=1,
                    admitted_at=sa.func.now(),
                )
            )
        assert getattr(wrong_binding.value.orig, "sqlstate", None) == "23503"
        with pytest.raises(RuntimeError, match="retained model verification evidence"):
            with owner.begin() as connection:
                config.attributes["connection"] = connection
                command.downgrade(config, "lm1e00000001")
        with owner.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_customer_ledger_entries"))
                == 0
            )
    finally:
        for engine in engines.values():
            engine.dispose()
        with owner.begin() as connection:
            for role, login in roles.items():
                if connection.scalar(
                    sa.text("SELECT 1 FROM pg_roles WHERE rolname=:login"), {"login": login}
                ):
                    connection.exec_driver_sql(
                        f"REVOKE CONNECT ON DATABASE {quote(database)} FROM {quote(login)}"
                    )
                    connection.exec_driver_sql(f"REVOKE {role} FROM {quote(login)}")
                    connection.exec_driver_sql(f"DROP ROLE {quote(login)}")
        owner.dispose()
