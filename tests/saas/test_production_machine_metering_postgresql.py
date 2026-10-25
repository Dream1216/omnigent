"""Declared-role production receiver with real TLS PG/mTLS and synthetic inference.

This reuses the maintained model/spool scenario without its ephemeral service
logins. The native test builds the production server, not the mounted-path CLI
or an actual packaged revision; those remain separate release gates.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.execution import ExecutionControlPlane
from saas.production import machine_metering as production
from saas.production import postgresql_migration as migration
from saas.production.model_run_credentials import ModelRunCredentialService
from tests.saas import test_production_migration_replay as replay
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_gateway_machine_metering import _customer_prices
from tests.saas.test_interactive_execution_postgresql import _interactive_postgresql_case
from tests.saas.test_model_run_credentials_postgresql import _claim
from tests.saas.test_model_run_inference_postgresql import _exercise_run_inference
from tests.saas.test_model_run_inference_postgresql import funded_publication as funded_publication
from tests.saas.test_model_run_inference_postgresql import (
    publication_protocol as publication_protocol,
)

production_replay = replay.production_replay


@pytest.mark.parametrize("production_replay", ["projection"], indirect=True)
@pytest.mark.parametrize("preview", [False, True], ids=["clean", "reviewed-preview"])
def test_declared_receiver_restarts_preserve_usage_and_uncertain_spool(
    production_replay,
    tmp_path,
    monkeypatch,
    record_property,
    funded_publication,
    preview,
    retained_checkpoint=None,
):
    plan = replay._with_machine_metering_profile(production_replay, tmp_path)
    receipt = migration.run_production_postgresql_migration(plan)
    if preview:
        preview_admin = sa.create_engine(
            sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
                database=plan.saas_owner.url.database,
                query=plan.saas_owner.url.query,
            ),
            hide_parameters=True,
        )
        try:
            with preview_admin.begin() as connection:
                connection.exec_driver_sql(
                    (
                        Path(replay.__file__).parent / "fixtures/production_preview_authority.sql"
                    ).read_text()
                )
        finally:
            preview_admin.dispose()
        receipt = migration.run_production_postgresql_migration(plan, verify_only=True)
    config, application_engines = replay._startup_config(plan, receipt, tmp_path)
    bootstrap = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
        database=plan.saas_owner.url.database, query=plan.saas_owner.url.query
    )
    seed = sa.create_engine(bootstrap, hide_parameters=True)
    engines = {}
    builds = []
    try:
        sessions = {}
        for service in ("app", "authenticator", "dispatcher", "executor", "billing", "metering"):
            binding = plan.service_role_graph.by_service[service]
            engine = sa.create_engine(
                plan.saas_owner.url.set(username=binding.login), hide_parameters=True
            )
            engines[service] = engine
            migration._inspect_service_login(
                engine, expected_login=binding.login, expected_role=binding.base_role
            )
            sessions[service] = sessionmaker(engine, expire_on_commit=False)
        factory, _, scope, context = _execution_fixture(seed, create_schema=False)
        base = SimpleNamespace(
            engine=seed,
            factory=factory,
            app=engines["app"],
            app_factory=sessions["app"],
            service=ExecutionControlPlane(sessions["app"]),
            scope=scope,
            context=context,
        )
        fixture = _interactive_postgresql_case(base, monkeypatch)
        _customer_prices(factory, actor=fixture.runtime.actor_id, tenant=fixture.runtime.tenant_id)
        claimed = _claim(
            fixture,
            {name: sessions[name] for name in ("dispatcher", "executor")},
            include_controller=True,
        )
        assert len(claimed) == 5
        runtime, authorized, lease, _control, machine = claimed
        credentials = ModelRunCredentialService(
            app_sessions=sessions["app"],
            authenticator_sessions=sessions["authenticator"],
            compatibility=runtime._resolver._compatibility_policy,
        )

        async def provision():
            return await asyncio.to_thread(credentials.issue, authorized, lease)

        binding = SimpleNamespace(
            authorized=authorized,
            lease=lease,
            credentials=credentials,
            machine=machine,
            provision=provision,
        )

        def receiver(certificates, recorder):
            files = certificates["server"]
            files.private_key.chmod(0o600)
            native_config = production.ProductionMachineMeteringConfig(
                product_revision=plan.product_revision,
                official_schema_revision=receipt.official_head,
                control_plane_schema_revision=receipt.saas_head,
                service_role_bindings=plan.service_role_bindings,
                service_role_graph=plan.service_role_graph,
                migration_receipt=config.migration_receipt,
                database_url=engines["metering"].url.render_as_string(hide_password=False),
                ca_certificate_path=files.ca,
                server_certificate_path=files.certificate,
                server_key_path=files.private_key,
                trust_bundle_version="test-v1",
                bind_host="127.0.0.1",
                bind_port=9446,
                expected_host="billing-metering.internal",
                request_timeout_seconds=5,
            )
            server = production.build_production_machine_metering_server(
                native_config, engines["metering"]
            )
            assert isinstance(server._authority, BillingMeteringAuthority)
            # Delegate every business operation to the actual production object;
            # the existing recorder only drops the post-commit acknowledgement.
            recorder.authority = server._authority
            server._authority = recorder
            builds.append(
                {
                    "graph_sha256": plan.service_role_graph.sha256,
                    "login": engines["metering"].url.username,
                }
            )
            return server

        unknown = {}
        retained = _exercise_run_inference(
            fixture,
            tmp_path,
            True,
            factory_state=binding,
            billing_sessions=sessions["billing"],
            metering_sessions=sessions["metering"],
            metering_server_factory=receiver,
            unknown_retention=unknown,
            retained_checkpoint=retained_checkpoint,
        )
        assert len(builds) == 3
        assert {item["login"] for item in builds} == {
            plan.service_role_graph.login_for("metering")
        }
        assert unknown["positive_hold_microusd"] > 0 and unknown["positive_hold_tokens"] > 0
        assert retained is not None
        assert len(retained) == len(unknown["nonempty_model_facts"]) == 7
        migration.verify_production_postgresql_state(engines=application_engines, config=config)
        final = migration.run_production_postgresql_migration(plan, verify_only=True)
        assert final.catalog_sha256 == receipt.catalog_sha256
        record_property(
            "declared_receiver_recovery",
            json.dumps(
                {
                    "receiver_builds": builds,
                    "reviewed_preview_state": preview,
                    "receiver_restarts_same_endpoint": 2,
                    "known_ack_loss_preserved": retained,
                    "unknown_hold": unknown,
                    "final_catalog_sha256": final.catalog_sha256,
                    "synthetic_upstream_and_execution_revision": True,
                    "mounted_path_CLI_or_packaged_revision_or_production_acceptance": False,
                },
                sort_keys=True,
            ),
        )
    finally:
        for engine in (*engines.values(), *application_engines.values()):
            engine.dispose()
        seed.dispose()
