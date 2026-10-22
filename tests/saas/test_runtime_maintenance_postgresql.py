"""Direct-owner/RLS replay on the original fresh four-authority PG fixture.

Requires independently derived P18 source gold. Backup/provider callbacks below
are explicit database-test doubles, never installed as production authority.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest
import sqlalchemy as sa
from psycopg import sql
from sqlalchemy.orm import Session

from saas.control_plane.db_models import (
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunnerPoolRecord,
    RunnerRegistrationRecord,
)
from saas.production import postgresql_migration as migration
from saas.production import postgresql_preserving_adapter as db
from saas.production import postgresql_preserving_native as native
from saas.production import postgresql_runtime_maintenance as runtime
from saas.production import postgresql_runtime_maintenance_native as runtime_native
from saas.production.postgresql_preserving_recovery import RecoveryOperation, _migrate
from tests.saas import test_production_migration_replay as replay
from tests.saas.test_scheduling_postgresql import _seed_scope

production_replay = replay.production_replay


def test_native_owner_maintenance_preserves_complete_scope_and_reverses_policy_contract(
    production_replay,
):
    plan = production_replay
    receipt = migration.run_production_postgresql_migration(plan)
    assert receipt.saas_head == "p0s000000018"
    # Original fixture enforces a fresh dedicated cluster and owns teardown.
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
        database=plan.saas_owner.url.database,
        query=sa.make_url(plan.saas_owner.url).query,
    )
    admin_engine = sa.create_engine(admin_url)
    owner = native.connect_url(plan.saas_owner.url)
    maintenance = native.connect_url(admin_url.render_as_string(hide_password=False))
    engines = migration._create_engines(plan)
    placement_id = uuid4()
    try:
        identity = db.database_identity(owner, maintenance)
        assert identity["server_major"] in (16, 18)
        with admin_engine.begin() as connection:
            scopes = []
            run_ids = []
            for suffix in ("a", "b"):
                actor, tenant, space, project, task, run, egress, profile = (
                    uuid4() for _ in range(8)
                )
                _seed_scope(
                    connection,
                    actor_id=actor,
                    tenant_id=tenant,
                    space_id=space,
                    project_id=project,
                    task_id=task,
                    run_id=run,
                    egress_policy_id=egress,
                    execution_profile_id=profile,
                    execution_profile_hash=suffix * 64,
                    suffix=suffix,
                )
                connection.execute(
                    sa.text(
                        "UPDATE saas_runs SET status='succeeded',terminal_at=now() WHERE id=:id"
                    ),
                    {"id": run},
                )
                scopes.append((actor, tenant, space, project))
                run_ids.append(run)
        with Session(admin_engine) as session, session.begin():
            session.add(
                RuntimePlacementRecord(
                    id=placement_id,
                    runtime_type="omnigent",
                    data_region="fixture",
                    failure_domain="fixture",
                    database_cluster_ref="unchanged-db",
                    object_store_ref="unchanged-objects",
                    kms_key_ref="unchanged-kms",
                    official_schema_revision="mm1a2b3c4d5e",
                    capacity_class="team",
                    status="active",
                )
            )
            session.flush()
            for actor, tenant, space, project in scopes:
                partition = RuntimePartitionRecord(
                    id=uuid4(),
                    tenant_id=tenant,
                    space_id=space,
                    placement_id=placement_id,
                    runtime_type="omnigent",
                    runtime_version="0.18",
                    physical_partition_key=str(uuid4()),
                    placement_generation=1,
                    source_revision="0" * 40,
                    adapter_contract_version="0.2.0",
                    status="active",
                )
                session.add(partition)
                session.flush()
                session.add(
                    RuntimeIdentityAliasRecord(
                        runtime_partition_id=partition.id,
                        user_id=actor,
                        runtime_user_key=str(uuid4()),
                        status="active",
                    )
                )
                session.add(
                    RuntimeResourceBindingRecord(
                        id=uuid4(),
                        runtime_partition_id=partition.id,
                        tenant_id=tenant,
                        space_id=space,
                        project_id=project,
                        resource_type="project",
                        runtime_resource_id=str(uuid4()),
                        saas_resource_id=project,
                        partition_generation=1,
                        binding_generation=1,
                        status="active",
                    )
                )
        key = (identity["server_major"], receipt.official_head, receipt.saas_head)
        source_gold = {
            "inventory": migration._PUBLIC_SCHEMA_INVENTORY_SHA256[key],
            "security": migration._source_security_catalog_baselines(plan.service_role_graph)[key],
        }
        recovery = RecoveryOperation(
            str(uuid4()),
            plan.product_revision,
            "sha256:" + "b" * 64,
            "c" * 40,
            "sha256:" + "d" * 64,
            identity,
            "fixture://database-only-no-real-backup-claim",
            "fixture-version",
            "e" * 64,
            "f" * 64,
            "fixture-kms",
            1,
            "1" * 64,
            "2" * 64,
            db.sha(db.canonical(source_gold)),
        )
        operation = runtime.RuntimeMaintenanceOperation(
            recovery,
            "isolation",
            "fixture",
            str(uuid4()),
            str(uuid4()),
            str(placement_id),
            "0.19.fixture",
            "3" * 40,
            receipt.official_head,
            "0.2.0",
            "fixture://database-test-only-no-provider-proof",
            "4" * 64,
        )
        checkpoints = []
        control = runtime.RuntimePlacementMaintenance(
            plan=plan,
            engines=engines,
            owner=owner,
            maintenance=maintenance,
            operation=operation,
            source_gold=source_gold,
            verify_runtime=lambda *_: None,
            before_mutation=lambda *_: None,
            checkpoint=lambda phase, state: checkpoints.append((phase, state)),
            max_rows=20,
        )
        state = control.prepare()
        with admin_engine.connect() as history_connection:
            run_history_before = history_connection.execute(
                sa.text("SELECT to_jsonb(r) FROM saas_runs r ORDER BY id")
            ).all()
        for service in ("app", "executor", "onboarding"):
            service_url = plan.saas_owner.url.set(
                username=plan.service_role_graph.login_for(service),
                password="production-replay-test",
            )
            with native.connect_url(service_url) as service_connection:
                try:
                    with service_connection.transaction():
                        service_connection.execute(
                            "SELECT set_config('app.tenant_id',%s,true)",
                            (str(scopes[0][1]),),
                        )
                        changed = service_connection.execute(
                            "UPDATE public.saas_runtime_placements "
                            "SET official_schema_revision=official_schema_revision WHERE id=%s",
                            (placement_id,),
                        ).rowcount
                        assert changed == 0
                except psycopg.errors.InsufficientPrivilege:
                    pass  # Existing table privilege denial is equally authoritative.

        def actual_state():
            with owner.transaction():
                control._settings(read_only=True)
                return control._scope(), owner.execute(
                    "SELECT count(*) FROM public.saas_control_plane_outbox "
                    "WHERE aggregate_type='runtime_placement'"
                ).fetchone()[0]

        def unchanged():
            current, events = actual_state()
            assert current == state["before"]
            assert events == 0

        # These are new disposable fixture rows only; all original scope rows,
        # aliases, Runs and history stay in place throughout every negative.
        extra_id = uuid4()
        original = state["before"]["bindings"][0]
        with Session(admin_engine) as session, session.begin():
            session.add(
                RuntimeResourceBindingRecord(
                    id=extra_id,
                    runtime_partition_id=original["runtime_partition_id"],
                    tenant_id=original["tenant_id"],
                    space_id=original["space_id"],
                    project_id=original["project_id"],
                    resource_type="fixture-extra",
                    runtime_resource_id=str(uuid4()),
                    saas_resource_id=uuid4(),
                    partition_generation=1,
                    binding_generation=1,
                    status="active",
                )
            )
        with pytest.raises(db.Refused, match="complete_placement_CAS_failed"):
            control.apply(state)
        with admin_engine.begin() as connection:
            assert (
                connection.execute(
                    sa.text("DELETE FROM saas_runtime_resource_bindings WHERE id=:id"),
                    {"id": extra_id},
                ).rowcount
                == 1
            )
        unchanged()

        # Caller-supplied cross-tenant shape is rejected, never used as authority.
        import copy

        foreign = copy.deepcopy(state)
        foreign["before"]["bindings"][0]["tenant_id"] = str(uuid4())
        foreign["before_sha256"] = db.sha(db.canonical(foreign["before"]))
        with pytest.raises(db.Refused, match="binding_scope_mismatch"):
            control.apply(foreign)
        unchanged()

        # A real outstanding Run lease prevents even a terminal Run being ignored.
        with admin_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_runs SET lease_expires_at=now()+interval '5 minutes' WHERE id=:id"
                ),
                {"id": run_ids[0]},
            )
        with pytest.raises(db.Refused, match="placement_not_drained"):
            control.apply(state)
        with admin_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runs SET lease_expires_at=NULL WHERE id=:id"),
                {"id": run_ids[0]},
            )
        unchanged()

        now, pool_id, runner_id, capability_id = datetime.now(UTC), uuid4(), uuid4(), uuid4()
        with Session(admin_engine) as session, session.begin():
            session.add(
                RunnerPoolRecord(
                    id=pool_id,
                    placement_id=placement_id,
                    failure_domain="fixture",
                    name="maintenance-fixture",
                    queue_class="interactive",
                    capacity_slots=1,
                    status="active",
                    protocol_version=1,
                    source_revision=plan.product_revision,
                    schema_revision=receipt.official_head,
                    adapter_contract_version="0.2.0",
                )
            )
            session.flush()
            session.add(
                RunnerRegistrationRecord(
                    id=runner_id,
                    pool_id=pool_id,
                    placement_id=placement_id,
                    instance_key=str(uuid4()),
                    failure_domain="fixture",
                    status="draining",
                    connection_generation=1,
                    connection_token_hash="5" * 64,
                    protocol_version=1,
                    source_revision=plan.product_revision,
                    schema_revision=receipt.official_head,
                    adapter_contract_version="0.2.0",
                    capabilities=[],
                    capabilities_hash="6" * 64,
                    max_concurrency=1,
                    active_leases=1,
                    last_heartbeat_at=now,
                    registered_at=now,
                )
            )
        with pytest.raises(db.Refused, match="placement_not_drained"):
            control.apply(state)
        with admin_engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_runner_registrations SET active_leases=0 WHERE id=:id"),
                {"id": runner_id},
            )
        actor, tenant, space, project = scopes[0]
        with Session(admin_engine) as session, session.begin():
            session.add(
                CapabilityTokenRecord(
                    id=capability_id,
                    token_hash="7" * 64,
                    tenant_id=tenant,
                    space_id=space,
                    project_id=project,
                    run_id=run_ids[0],
                    runner_id=runner_id,
                    runner_connection_generation=1,
                    dispatch_generation=1,
                    fence_token=1,
                    allowed_actions=["worktree.read"],
                    resource_scope={},
                    issued_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(minutes=5),
                )
            )
        with pytest.raises(db.Refused, match="placement_not_drained"):
            control.apply(state)
        with admin_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_capability_tokens SET revoked_at=now(),"
                    "revocation_reason='fixture-cleanup' WHERE id=:id"
                ),
                {"id": capability_id},
            )
        unchanged()

        # Real write transaction rollback, before SQL and again after SQL but
        # before COMMIT. Provider checks do not read uncommitted target metadata.
        def no_proof(*_):
            raise TimeoutError("fixture external authority unavailable")

        for callback in ("before_mutation", "verify_runtime", "checkpoint"):
            original_callback = getattr(control, callback)
            setattr(control, callback, no_proof)
            with pytest.raises(TimeoutError, match="authority unavailable"):
                control.apply(state)
            setattr(control, callback, original_callback)
            unchanged()
        for callback in ("before_mutation", "verify_runtime"):
            original_callback = getattr(control, callback)
            calls = 0

            def expire_during_sql(*_):
                nonlocal calls
                calls += 1
                if calls == 2:
                    # This independent observer sees the committed BEFORE state.
                    with admin_engine.connect() as observer:
                        current_version = observer.execute(
                            sa.text(
                                "SELECT official_schema_revision FROM saas_runtime_placements "
                                "WHERE id=:id"
                            ),
                            {"id": placement_id},
                        ).scalar_one()
                    assert (
                        current_version
                        == state["before"]["placements"][0]["official_schema_revision"]
                    )
                    raise TimeoutError("fixture proof expired before COMMIT")

            setattr(control, callback, expire_during_sql)
            with pytest.raises(TimeoutError, match="expired before COMMIT"):
                control.apply(state)
            setattr(control, callback, original_callback)
            unchanged()

        assert len(state["before"]["partitions"]) == 2
        assert len(state["before"]["bindings"]) == 2
        before_aliases = state["before"]["aliases"]
        search_path = owner.execute("SHOW search_path").fetchone()[0]
        policies = runtime_native.policy_snapshot(owner)
        assert owner.execute("SHOW search_path").fetchone()[0] == search_path
        with owner.transaction():
            owner.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            assert runtime_native.policy_snapshot(owner) == policies
        assert owner.execute("SHOW search_path").fetchone()[0] == search_path
        # Actual role drift must still refuse before any DROP/head change.
        table, policy, _command = runtime_native.contract.POLICIES[0]
        alter = sql.SQL("ALTER POLICY {} ON public.{} TO ").format(
            sql.Identifier(policy), sql.Identifier(table)
        )
        owner.execute(alter + sql.SQL("CURRENT_USER"))
        try:
            with pytest.raises(db.Refused, match="p18_policy_contract_drift"):
                runtime_native.remove_p18_policies(owner, policies)
            assert native.head(owner) == "p0s000000018"
        finally:
            owner.execute(alter + sql.SQL("PUBLIC"))
        assert runtime_native.policy_snapshot(owner) == policies
        runtime_native.remove_p18_policies(owner, policies)
        assert native.head(owner) == "p0s000000017"
        with owner.transaction():
            assert (
                owner.execute(
                    "UPDATE public.saas_runtime_placements "
                    "SET official_schema_revision=official_schema_revision WHERE id=%s",
                    (placement_id,),
                ).rowcount
                == 0
            )
            assert (
                owner.execute(
                    "UPDATE public.saas_runtime_partitions SET runtime_version=runtime_version "
                    "WHERE placement_id=%s",
                    (placement_id,),
                ).rowcount
                == 0
            )
        _migrate(engines["saas_owner"], "saas", "p0s000000018")
        migration.run_production_postgresql_migration(plan, verify_only=True)
        assert len(runtime_native.policy_snapshot(owner)) == 4

        # Lose only the client acknowledgement AFTER a real PostgreSQL COMMIT.
        # No database/proxy result is forged, and the real stable receipt is read.
        class LostCommitAcknowledgement:
            def __init__(self, connection):
                self.connection, self.armed = connection, True

            def __getattr__(self, name):
                return getattr(self.connection, name)

            @contextmanager
            def transaction(self):
                with self.connection.transaction():
                    yield
                if self.armed:
                    self.armed = False
                    raise ConnectionError("fixture commit acknowledgement lost")

        control.owner = LostCommitAcknowledgement(owner)
        with pytest.raises(ConnectionError, match="acknowledgement lost"):
            control.apply(state)
        result = control.reconcile(state)
        assert control.reconcile(state) == result
        assert control.apply(state) == result
        assert result["production_admitted"] is False
        with owner.transaction():
            assert control._scope()["aliases"] == before_aliases
            assert (
                owner.execute(
                    "SELECT count(*) FROM public.saas_control_plane_outbox "
                    "WHERE idempotency_key=%s",
                    ("runtime-maintenance:" + recovery.operation_id,),
                ).fetchone()[0]
                == 1
            )
        with pytest.raises(
            db.Refused, match="retained_runtime_facts_require_original_database_restore"
        ):
            runtime_native.require_source_inverse_possible(
                owner, maintenance=maintenance, expected_identity=identity
            )
        assert native.head(owner) == "p0s000000018"
        # A different operation's stale complete set cannot rebind old projects.
        stale_control = runtime.RuntimePlacementMaintenance(
            plan=plan,
            engines=engines,
            owner=owner,
            maintenance=maintenance,
            operation=replace(operation, recovery=replace(recovery, operation_id=str(uuid4()))),
            source_gold=source_gold,
            verify_runtime=lambda *_: None,
            before_mutation=lambda *_: None,
            checkpoint=lambda *_: None,
            max_rows=20,
        )
        stale_state = {
            **state,
            "operation": asdict(stale_control.operation),
        }
        with pytest.raises(db.Refused, match="complete_placement_CAS_failed"):
            stale_control.apply(stale_state)
        assert checkpoints[-1][0] == "runtime_metadata_committed"
        # Two real owner sessions prepare the same complete current set. One
        # serializable transaction wins; the other must refuse or serialize-fail.
        barrier = Barrier(2)
        racing = []
        race_connections = []
        try:
            for _ in range(2):
                race_owner = native.connect_url(plan.saas_owner.url)
                race_reader = native.connect_url(admin_url)
                race_connections.extend((race_owner, race_reader))
                race_operation = replace(
                    operation, recovery=replace(recovery, operation_id=str(uuid4()))
                )

                def race_fence(_operation, phase):
                    if phase == "upgrade_runtime_metadata":
                        barrier.wait(timeout=5)

                racer = runtime.RuntimePlacementMaintenance(
                    plan=plan,
                    engines=engines,
                    owner=race_owner,
                    maintenance=race_reader,
                    operation=race_operation,
                    source_gold=source_gold,
                    verify_runtime=lambda *_: None,
                    before_mutation=race_fence,
                    checkpoint=lambda *_: None,
                    max_rows=20,
                )
                racing.append((racer, racer.prepare()))
            successes = 0
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(racer.apply, prepared) for racer, prepared in racing]
                for future in futures:
                    try:
                        assert future.result()["phase"] == "runtime_metadata_committed"
                        successes += 1
                    except db.Refused as error:
                        assert str(error) == "complete_placement_CAS_failed"
                    except psycopg.errors.SerializationFailure:
                        pass  # Real PostgreSQL SERIALIZABLE concurrent-write denial.
            assert successes == 1
            with owner.transaction():
                assert (
                    owner.execute(
                        "SELECT count(*) FROM public.saas_control_plane_outbox "
                        "WHERE aggregate_type='runtime_placement'"
                    ).fetchone()[0]
                    == 2
                )
            with admin_engine.connect() as history_connection:
                assert (
                    history_connection.execute(
                        sa.text("SELECT to_jsonb(r) FROM saas_runs r ORDER BY id")
                    ).all()
                    == run_history_before
                )
        finally:
            for connection in race_connections:
                connection.close()
    finally:
        owner.close()
        maintenance.close()
        admin_engine.dispose()
        for engine in engines.values():
            engine.dispose()


@pytest.mark.parametrize("production_replay", ["admin"], indirect=True)
@pytest.mark.parametrize("retained", ["budget_without_run", "publication_audit_without_run"])
def test_retained_facts_without_any_run_refuse_before_all_inverse_mutation(
    production_replay,
    retained,
):
    """Reuse the original strict fresh fixture; no grants or weakened RLS."""
    from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
    from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord

    plan = production_replay
    migration.run_production_postgresql_migration(plan)
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
        database=plan.saas_owner.url.database,
        query=plan.saas_owner.url.query,
    )
    engine = sa.create_engine(admin_url)
    owner = native.connect_url(plan.saas_owner.url)
    maintenance = native.connect_url(admin_url)
    app = native.connect_url(
        plan.saas_owner.url.set(
            username=plan.service_role_graph.login_for("app"),
            password="production-replay-test",
        )
    )
    try:
        identity = db.database_identity(owner, maintenance)
        # Verify the empty fresh state first with the actual unfiltered reader.
        assert (
            runtime_native.require_source_inverse_possible(
                owner,
                maintenance=maintenance,
                expected_identity=identity,
            )["all_relations_unfiltered"]
            is True
        )
        for table in ("saas_runs", "saas_execution_sessions"):
            assert maintenance.execute(f"SELECT count(*) FROM public.{table}").fetchone()[0] == 0
        now = datetime.now(UTC)
        with Session(engine) as session, session.begin():
            if retained == "budget_without_run":
                session.add(
                    ModelProviderBudgetReservationRecord(
                        id=uuid4(),
                        provider_id="deepseek",
                        tenant_id=uuid4(),
                        run_id=uuid4(),
                        operation_key="retained-without-run",
                        request_hash="a" * 64,
                        configuration_version=1,
                        period_start=now.date().replace(day=1),
                        usage_date=now.date(),
                        requested_microusd=1,
                        requested_tokens=1,
                        status="rejected",
                        rejection_code="fixture_refused",
                        expires_at=now + timedelta(minutes=1),
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                # Use the original append/hash-chain implementation solely to seed
                # retained audit facts; this is not a production authorization.
                service = object.__new__(PlatformGovernedAccessService)
                service._append_audit(
                    session,
                    tenant_id=None,
                    actor_type="staff",
                    actor_id=uuid4(),
                    event_type="platform.model_publication.revocation_requested",
                    target_type="model_publication_revocation",
                    target_id=uuid4(),
                    operation_id=None,
                    payload={"fixture": "retained-admin-publication"},
                    occurred_at=now,
                )
        policies = runtime_native.policy_snapshot(owner)
        with engine.connect() as connection:
            before = {
                table: connection.execute(
                    sa.text(f"SELECT to_jsonb(r) FROM public.{table} r ORDER BY 1")
                ).all()
                for table in (
                    *runtime_native.INVERSE_RETAINED_TABLES,
                    "saas_platform_audit_events",
                    "saas_platform_audit_chain_heads",
                    "saas_control_plane_outbox",
                )
            }
        # Even if its FORCE-RLS view is empty, an ordinary app is not a full reader.
        with pytest.raises(
            db.Refused,
            match=r"existing_maintenance_full_visibility_required|source_inverse_full_reader_unavailable",
        ):
            runtime_native.require_source_inverse_possible(
                owner,
                maintenance=app,
                expected_identity=identity,
            )
        with pytest.raises(db.Refused, match=r"requires?_original_database_restore"):
            runtime_native.require_source_inverse_possible(
                owner,
                maintenance=maintenance,
                expected_identity=identity,
            )
        assert native.head(owner) == "p0s000000018"
        assert runtime_native.policy_snapshot(owner) == policies
        with engine.connect() as connection:
            after = {
                table: connection.execute(
                    sa.text(f"SELECT to_jsonb(r) FROM public.{table} r ORDER BY 1")
                ).all()
                for table in before
            }
        assert after == before
        assert before["saas_runs"] == before["saas_execution_sessions"] == []
    finally:
        app.close()
        owner.close()
        maintenance.close()
        engine.dispose()
