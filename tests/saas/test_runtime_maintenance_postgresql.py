"""Direct-owner/RLS replay on the original fresh four-authority PG fixture.

Requires independently derived P18 source gold. Backup/provider callbacks below
are explicit database-test doubles, never installed as production authority.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
import sqlalchemy as sa
from alembic import command
from psycopg import sql
from sqlalchemy.orm import Session, sessionmaker

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
        # The same retained rows cannot pass P15, but are legal T facts because
        # no T migration or data guard is crossed by an explicit T inverse.
        tables = tuple(
            sorted(
                name
                for name in sa.inspect(engine).get_table_names(schema="public")
                if name not in {"alembic_version", "saas_alembic_version"}
            )
        )
        snapshot = runtime_native.capture_t_preserved_facts(
            owner,
            maintenance=maintenance,
            expected_identity=identity,
            expected_tables=tables,
            max_copy_bytes=16 * 1024 * 1024,
            expected_head="p0s000000018",
        )
        retained_table = (
            "saas_model_provider_budget_reservations"
            if retained == "budget_without_run"
            else "saas_platform_audit_events"
        )
        assert snapshot["tables"][retained_table]["row_count"] == 1
        assert (
            runtime_native.capture_t_preserved_facts(
                owner,
                maintenance=maintenance,
                expected_identity=identity,
                expected_tables=tables,
                max_copy_bytes=16 * 1024 * 1024,
                expected_head="p0s000000018",
            )
            == snapshot
        )
        with pytest.raises(db.Refused):
            runtime_native.capture_t_preserved_facts(
                owner,
                maintenance=app,
                expected_identity=identity,
                expected_tables=tables,
                max_copy_bytes=16 * 1024 * 1024,
                expected_head="p0s000000018",
            )
        assert native.head(owner) == "p0s000000018"
        assert runtime_native.policy_snapshot(owner) == policies
    finally:
        app.close()
        owner.close()
        maintenance.close()
        engine.dispose()


def _derive_clean_original_t(plan, temporary_root):
    """Clean T source resources plus the byte-identical original 3264 verifier.

    3264 packages P15 and explicitly accepts verify-only T. Fixed main254 owns
    T's actual DDL/bootstrap. Both original modules have the same pinned bytes;
    no expected head, map or verifier is patched to derive target role/ACL gold.
    """
    from saas.production.postgresql_preserving_recovery import _source_projection

    repository = Path(__file__).resolve().parents[2]
    revisions = (
        "3264a645a0fce33ea2c6477ea92044f8491051bf",
        "254151b742667a95f0ec8a94e312f03924f56c80",
    )
    configured = os.environ.get("OMNIGENT_SAAS_TEST_ORIGINAL_T_GIT_DIR")
    if configured:
        public_git = Path(configured)
        assert public_git.is_absolute() and public_git.is_dir() and not public_git.is_symlink()
        location = ["--git-dir=" + str(public_git)]
        assert (
            subprocess.run(
                ["git", *location, "rev-parse", "--is-bare-repository"],
                check=True,
                capture_output=True,
                timeout=10,
            ).stdout
            == b"true\n"
        )
    else:
        location = ["-C", str(repository)]
    if any(
        subprocess.run(
            ["git", *location, "cat-file", "-e", value + "^{commit}"],
            check=False,
            capture_output=True,
            timeout=10,
        ).returncode
        for value in revisions
    ):
        assert not configured, "pre-staged fixed public Git objects are incomplete"
        private_git = temporary_root / "original-t-objects.git"
        subprocess.run(
            ["git", "init", "--bare", str(private_git)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        location = ["--git-dir=" + str(private_git)]
        # One bounded public fetch, exact objects only; no origin/branch/HEAD.
        subprocess.run(
            [
                "git",
                *location,
                "fetch",
                "--no-tags",
                "--depth=1",
                "https://github.com/Dream1216/omnigent.git",
                *revisions,
            ],
            check=True,
            capture_output=True,
            timeout=90,
        )

    def git(*arguments):
        return subprocess.run(
            ["git", *location, *arguments], check=True, capture_output=True, timeout=30
        ).stdout

    def load_original(revision, directory, *, migration_tree, bootstrap_hashes):
        assert git("rev-parse", revision + "^{commit}").decode().strip() == revision
        for name, expected in {
            "saas/control_plane/migrations": migration_tree,
            "omnigent/db/migrations": "b58e06dcda862826dfbf49d4197ad520d87189ac",
            "saas/runtime_rls": "3f948aa91c426d23856828e47782a5f244e24559",
        }.items():
            assert git("rev-parse", revision + ":" + name).decode().strip() == expected
        directory.mkdir()
        raw = git(
            "archive",
            "--format=tar",
            revision,
            "saas/production/postgresql_migration.py",
            "saas/control_plane",
            "saas/runtime_rls",
            "omnigent/db",
        )
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive:
                if member.isdir():
                    continue
                assert (
                    member.isfile()
                    and not Path(member.name).is_absolute()
                    and ".." not in Path(member.name).parts
                )
                destination = directory / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
        pins = {
            "saas/production/postgresql_migration.py": (
                "e9c5e9210da07c1825d62cc8f198e5471e0e41001a87a7b318206ac28ce91127"
            ),
            **{"saas/control_plane/" + key: value for key, value in bootstrap_hashes.items()},
        }
        for name, expected in pins.items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected
        # These shared imports are byte-identical to both original sources.
        for filename in (directory / "saas/runtime_rls").rglob("*"):
            if filename.is_file():
                assert (
                    filename.read_bytes()
                    == (repository / filename.relative_to(directory)).read_bytes()
                )
        name = "saas.production._native_original_t_" + uuid4().hex
        specification = importlib.util.spec_from_file_location(
            name, directory / "saas/production/postgresql_migration.py"
        )
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        specification.loader.exec_module(module)
        module.files = lambda package: directory.joinpath(*package.split("."))
        return module

    old = load_original(
        revisions[0],
        temporary_root / "original-3264-p15-source",
        migration_tree="47855752f994cd8d5d7529fa9fd0c61333ea6a88",
        bootstrap_hashes={
            "postgresql_roles.sql": (
                "bdcdd886c2705e13cb52611bdb94077d1142863183286fd2ec911ccf02748f5b"
            ),
            "postgresql_principals.sql": (
                "b313f0bc489b757ebdbec4c6f3284eb348a9c74a84f29c08544618eb227bfcd7"
            ),
            "postgresql_database.sql": (
                "2fa946b02430c485202d47be106ad060591ff24e962e34bb30e5c9f0aa65b585"
            ),
        },
    )
    source = load_original(
        revisions[1],
        temporary_root / "original-main254-t-source",
        migration_tree="2a8ff3a59a4241ea9dfd943639cc05261293fc41",
        bootstrap_hashes={
            "postgresql_roles.sql": (
                "583e46f78c21d9a6cd77e6f1805b23b898004a8ccfff746222352921a482773a"
            ),
            "postgresql_principals.sql": (
                "b231e2177878f0f00d5252370cf66f4436f47b31e1949847db5195c291848c0a"
            ),
            "postgresql_database.sql": (
                "72d8e0a8d56a92fccb8c37ee590efefdec444fe2fee5c4b99ddf3206779a2312"
            ),
        },
    )
    assert old._expected_head("saas") == "p0s000000015"
    assert source._expected_head("saas") == "lm2t00000001"
    assert old._expected_head("official") == source._expected_head("official") == "mm1a2b3c4d5e"
    old_plan = replace(
        plan, business_delivery_service_role_bindings=None, verification_saas_head="lm2t00000001"
    )
    engines = source._create_engines(old_plan)
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
        database=plan.saas_owner.url.database, query=plan.saas_owner.url.query
    )
    reader = native.connect_url(admin_url)
    database_owner = native.connect_url(plan.database_owner.url)
    owner = native.connect_url(plan.saas_owner.url)
    try:
        source._apply_principals(
            engines["principal_operator"],
            bindings=old_plan.service_role_graph,
            principal_operator=plan.principal_operator.login,
        )
        source._apply_database_authority(
            engines["database_owner"],
            principal_operator=plan.principal_operator.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bindings=old_plan.service_role_graph,
        )
        for kind in ("official", "saas"):
            with engines[kind + "_owner"].connect() as connection:
                config = source._migration_config(kind)
                config.attributes["connection"] = connection
                command.upgrade(config, "head")
        source._apply_runtime_authority(engines["official_owner"])
        source._apply_control_plane_authority(engines["saas_owner"])
        source._finalize_database_authority(
            engines["database_owner"],
            principal_operator=plan.principal_operator.login,
            official_owner=plan.official_owner.login,
            saas_owner=plan.saas_owner.login,
            bindings=old_plan.service_role_graph,
        )
        verified = old._verify_state(old_plan, engines)  # Original 3264 explicit-T runtime path.
        assert (verified.official_head, verified.saas_head) == ("mm1a2b3c4d5e", "lm2t00000001")
        projection = _source_projection(old_plan, engines)
        major = db.database_identity(owner, reader)["server_major"]
        key = (major, "mm1a2b3c4d5e", "lm2t00000001")
        assert projection["inventory_sha256"] == old._PUBLIC_SCHEMA_INVENTORY_SHA256[key]
        assert (
            projection["security_sha256"]
            == old._source_security_catalog_baselines(old_plan.service_role_graph)[key]
        )
        # Clean T intentionally has no P17 receipt relations. Read only the
        # original builtin/ACL using the same catalog projection as preservation;
        # never weaken the P18 full-inventory guard to collect target Gold.
        db.require_idle(reader)
        with reader.transaction():
            reader.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            reader.execute("SET LOCAL row_security=on")
            reader.execute("SET LOCAL search_path=pg_catalog,pg_temp")
            builtin = db.one(
                reader,
                "SELECT p.oid::bigint,pg_get_userbyid(p.proowner) AS owner,"
                "p.proacl::text AS raw_acl FROM pg_catalog.pg_proc p "
                "WHERE p.oid=to_regprocedure('pg_catalog.pg_notify(text,text)')",
            )
            builtin["entries"] = db.rows(
                reader,
                "SELECT pg_get_userbyid(a.grantor) AS grantor,"
                "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END "
                "AS grantee,a.privilege_type,a.is_grantable FROM pg_catalog.pg_proc p "
                "CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a "
                "WHERE p.oid=to_regprocedure('pg_catalog.pg_notify(text,text)') "
                "ORDER BY 1,2,3,4",
            )
        return {
            "old_inventory_sha256": projection["inventory_sha256"],
            "old_security_sha256": projection["security_sha256"],
            "old_role_edges": native.role_edges(reader),
            "old_access": native.object_access(database_owner),
            "old_builtin_pg_notify": {
                key: value for key, value in builtin.items() if key not in {"oid", "raw_acl"}
            }
            | {"acl_is_null": builtin["raw_acl"] is None},
        }
    finally:
        for connection in (reader, database_owner, owner):
            connection.close()
        source._dispose_engines(engines)
        for module in (old, source):
            sys.modules.pop(module.__name__, None)


def _seed_t_delivery_receipts(engine, plan, scopes):
    """Real consumer commits for preservation; local crypto/store are test-only."""
    from saas.control_plane.billing import BillingControlPlane
    from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser, TenantMembership
    from saas.control_plane.outbox_delivery import (
        PlatformAuditJournalConsumer,
        UsageReconciliationConsumer,
    )
    from saas.control_plane.platform_governed_access import PlatformGovernedAccessService
    from saas.control_plane.revocation import AuthorizationInvalidations, ReplicaRevocationConsumer
    from tests.saas.test_audit_journal_delivery import _Cipher, _Signer
    from tests.saas.test_billing_control_plane import NOW, _bootstrap
    from tests.saas.test_outbox_delivery_postgresql import _outbox
    from tests.saas.test_slo_observability import _Store

    admin = sessionmaker(engine, expire_on_commit=False)
    billing = BillingControlPlane(admin)
    audit_consumer = PlatformAuditJournalConsumer(
        admin, _Store(), _Cipher(), _Signer(), product_revision=plan.product_revision
    )
    usage_consumer = UsageReconciliationConsumer(admin, product_revision=plan.product_revision)
    revocation = ReplicaRevocationConsumer(
        admin,
        AuthorizationInvalidations(),
        product_revision=plan.product_revision,
        replica_uid=uuid4(),
    )
    for actor, tenant, _space, _project in scopes:
        with admin.begin() as session:
            session.add(
                TenantMembership(
                    tenant_id=tenant, user_id=actor, role="owner", status="active", version=1
                )
            )
        pricing, _ = _bootstrap(billing, tenant, actor)
        usage = billing.record_usage(
            actor_id=actor,
            tenant_id=tenant,
            pricing_snapshot_id=pricing,
            meter="llm.input_tokens",
            quantity="1000",
            unit="tokens",
            provider="openai",
            provider_request_id="t-preserving-" + tenant.hex,
            idempotency_key="t-preserving-usage",
            occurred_at=NOW + timedelta(minutes=1),
        )
        with admin.begin() as session:
            service = PlatformGovernedAccessService(admin)
            audit = service._append_audit(
                session,
                tenant_id=tenant,
                actor_type="customer",
                actor_id=actor,
                event_type="native.t-preserving.acceptance",
                target_type="tenant",
                target_id=tenant,
                operation_id=None,
                payload={"fixture": "t-preserving-only"},
                occurred_at=datetime.now(UTC),
            )
            session.flush()
            audit_id = audit.id
            session.get(GlobalUser, actor).security_version = 2
        with admin() as session:
            usage_event = _outbox(
                session.scalar(
                    sa.select(ControlPlaneOutboxEvent).where(
                        ControlPlaneOutboxEvent.event_type == "billing.usage.recorded",
                        ControlPlaneOutboxEvent.aggregate_key == str(usage.id),
                    )
                )
            )
            audit_event = _outbox(
                session.scalar(
                    sa.select(ControlPlaneOutboxEvent).where(
                        ControlPlaneOutboxEvent.event_type == "platform.audit.persisted",
                        ControlPlaneOutboxEvent.aggregate_key == str(audit_id),
                    )
                )
            )
            revoke_id = session.scalar(
                sa.select(ControlPlaneOutboxEvent.id).where(
                    ControlPlaneOutboxEvent.aggregate_type == "authorization_user",
                    ControlPlaneOutboxEvent.aggregate_key == str(actor),
                )
            )
        usage_consumer.publish(**usage_event)
        audit_consumer.publish(**audit_event)
        assert revocation.consume(revoke_id, recovery=True)


@contextmanager
def _native_t_rebinding_fixture(production_replay, *, derive_t_gold_at=None):
    """Actual SQL/RLS/COMMIT phase, not original-image or provider qualification."""
    from omnigent.version import VERSION
    from saas.control_plane.bindings import RuntimeBindingService
    from saas.control_plane.resolver import RuntimeCompatibilityPolicy
    from saas.production.postgresql_preserving_recovery import (
        T_PROTOCOL,
        ExplicitTRecoveryOperation,
        _source_projection,
    )

    plan = production_replay
    old_gold = _derive_clean_original_t(plan, derive_t_gold_at) if derive_t_gold_at else None
    receipt = migration.run_production_postgresql_migration(plan)
    admin_url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
        database=plan.saas_owner.url.database,
        query=plan.saas_owner.url.query,
    )
    engine = sa.create_engine(admin_url)
    owner = native.connect_url(plan.saas_owner.url)
    reader = native.connect_url(admin_url)
    engines = migration._create_engines(plan)
    placement_id = uuid4()
    try:
        with engine.begin() as connection:
            scopes = []
            for suffix in ("t_a", "t_b"):
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
                    execution_profile_hash="a" * 64,
                    suffix=suffix,
                )
                connection.execute(
                    sa.text(
                        "UPDATE saas_runs SET status='succeeded',terminal_at=now() WHERE id=:id"
                    ),
                    {"id": run},
                )
                scopes.append((actor, tenant, space, project))
        with Session(engine) as session, session.begin():
            session.add(
                RuntimePlacementRecord(
                    id=placement_id,
                    runtime_type="omnigent",
                    data_region="fixture",
                    failure_domain="fixture",
                    database_cluster_ref="same-db",
                    object_store_ref="same-objects",
                    kms_key_ref="same-kms",
                    official_schema_revision="nf12ab34cd56",
                    capacity_class="team",
                    status="active",
                )
            )
            session.flush()
            for index, (actor, tenant, space, project) in enumerate(scopes, 1):
                partition = RuntimePartitionRecord(
                    id=uuid4(),
                    tenant_id=tenant,
                    space_id=space,
                    placement_id=placement_id,
                    runtime_type="omnigent",
                    runtime_version=VERSION,
                    physical_partition_key=str(index),
                    placement_generation=11,
                    source_revision="3db749d784ff044304473939acaae3a65c0fec61",
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
                        partition_generation=11,
                        binding_generation=19,
                        status="active",
                    )
                )
        identity = db.database_identity(owner, reader)
        complete_gold = None
        if old_gold is not None:
            verified = migration._verify_state(plan, engines)
            assert (verified.official_head, verified.saas_head) == ("nf12ab34cd56", "p0s000000018")
            projection = _source_projection(plan, engines)
            key = (identity["server_major"], verified.official_head, verified.saas_head)
            assert projection["inventory_sha256"] == migration._PUBLIC_SCHEMA_INVENTORY_SHA256[key]
            assert (
                projection["security_sha256"]
                == migration._source_security_catalog_baselines(plan.service_role_graph)[key]
            )
            database_owner = native.connect_url(plan.database_owner.url)
            try:
                complete_gold = {
                    **old_gold,
                    "candidate_inventory_sha256": projection["inventory_sha256"],
                    "candidate_security_sha256": projection["security_sha256"],
                    "candidate_role_edges": native.role_edges(reader),
                    "candidate_access": native.object_access(database_owner),
                }
            finally:
                database_owner.close()
        _seed_t_delivery_receipts(engine, plan, scopes)
        gold = {
            "inventory": migration._PUBLIC_SCHEMA_INVENTORY_SHA256[
                (identity["server_major"], receipt.official_head, receipt.saas_head)
            ],
            "security": migration._source_security_catalog_baselines(plan.service_role_graph)[
                (identity["server_major"], receipt.official_head, receipt.saas_head)
            ],
        }
        operation = ExplicitTRecoveryOperation(
            str(uuid4()),
            plan.product_revision,
            "sha256:" + "b" * 64,
            "3264a645a0fce33ea2c6477ea92044f8491051bf",
            "sha256:adb1d0987d74b59d2d7121a61c5bc7112bd49fe5a2921b7373b827946d29d041",
            identity,
            "fixture://native-metadata-only-not-real-backup",
            "fixture-version",
            "e" * 64,
            "f" * 64,
            "fixture-kms",
            1,
            "1" * 64,
            "2" * 64,
            db.sha(db.canonical(gold)),
            contract_version=T_PROTOCOL,
            rollback_saas_target="lm2t00000001",
            rollback_host_digest="sha256:1c969bb11a41edcf3ec8f16090a6ebd7956ef80de060697f76ce4ea02a140b69",
            rollback_upstream_revision="825f8500d7cc8e997e5562fa55694cd146165f3c",
            rollback_adapter_contract_version="0.2.0",
        )
        selected = runtime.FencedTRuntimeOperation(
            recovery=operation,
            realm="isolation",
            namespace="fixture",
            namespace_uid=str(uuid4()),
            cluster_uid=str(uuid4()),
            placement_id=str(placement_id),
            runtime_version="0.18.0.dev20261006",
            upstream_revision=operation.rollback_upstream_revision,
            official_schema_revision="mm1a2b3c4d5e",
            adapter_contract_version="0.2.0",
            runtime_observation_ref="fixture://provider-not-qualified",
            runtime_observation_sha256="4" * 64,
            direction="to_t",
            source_official_schema_revision="nf12ab34cd56",
        )
        control = runtime.RuntimePlacementMaintenance(
            plan=plan,
            engines=engines,
            owner=owner,
            maintenance=reader,
            operation=selected,
            source_gold=gold,
            verify_runtime=lambda *_: None,
            before_mutation=lambda *_: None,
            checkpoint=lambda *_: None,
            max_rows=20,
        )
        projection = _source_projection(plan, engines)
        tables = tuple(
            sorted(
                row[1][2:]
                for row in projection["inventory"]
                if row[0] == "relation"
                and row[1].startswith("r:")
                and row[1][2:] not in {"alembic_version", "saas_alembic_version"}
            )
        )

        def facts():
            return runtime_native.capture_t_preserved_facts(
                owner,
                maintenance=reader,
                expected_identity=identity,
                expected_tables=tables,
                max_copy_bytes=16 * 1024 * 1024,
                expected_head="p0s000000018",
            )

        yield SimpleNamespace(
            plan=plan,
            engine=engine,
            owner=owner,
            reader=reader,
            engines=engines,
            placement_id=placement_id,
            scopes=scopes,
            identity=identity,
            gold=gold,
            operation=operation,
            selected=selected,
            control=control,
            facts=facts,
            complete_gold=complete_gold,
            RuntimeBindingService=RuntimeBindingService,
            RuntimeCompatibilityPolicy=RuntimeCompatibilityPolicy,
        )
    finally:
        owner.close()
        reader.close()
        engine.dispose()
        for database_engine in engines.values():
            database_engine.dispose()


def assert_fenced_t_rebinding_preserves_same_projects_all_other_facts_and_commit_outcome(
    production_replay,
):
    """Actual SQL/RLS/COMMIT phase, not original-image or provider qualification."""
    with _native_t_rebinding_fixture(production_replay) as context:
        control = context.control
        facts = context.facts
        reader = context.reader
        identity = context.identity
        owner = context.owner
        engine = context.engine
        placement_id = context.placement_id
        operation = context.operation
        selected = context.selected
        RuntimeBindingService = context.RuntimeBindingService
        RuntimeCompatibilityPolicy = context.RuntimeCompatibilityPolicy
        before = facts()
        before_rows = runtime_native.runtime_rows_snapshot(
            reader, expected_identity=identity, owner=owner, maximum=20
        )
        state = control.prepare()
        # Only the distinct fenced T operation may stage mm before nf inverse.
        ordinary = runtime.RuntimeMaintenanceOperation(
            **{
                key: value
                for key, value in asdict(selected).items()
                if key not in {"direction", "source_official_schema_revision", "recovery"}
            },
            recovery=selected.recovery,
        )
        ordinary_control = runtime.RuntimePlacementMaintenance(
            plan=context.plan,
            engines=context.engines,
            owner=owner,
            maintenance=reader,
            operation=ordinary,
            source_gold=context.gold,
            verify_runtime=lambda *_: None,
            before_mutation=lambda *_: None,
            checkpoint=lambda *_: None,
            max_rows=20,
        )
        with pytest.raises(db.Refused, match="installed_source_and_runtime_heads_required"):
            ordinary_control.prepare()

        class LostAck:
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
                    raise ConnectionError("native T transition commit acknowledgement lost")

        control.owner = LostAck(owner)
        with pytest.raises(ConnectionError, match="acknowledgement lost"):
            control.apply(state)
        outcome = control.reconcile(state)
        assert control.reconcile(state) == outcome
        assert outcome["phase"] == "runtime_metadata_committed"
        after = facts()
        actual = runtime_native.runtime_rows_snapshot(
            reader, expected_identity=identity, owner=owner, maximum=20
        )
        delta = runtime_native.assert_runtime_transition_facts(
            before,
            after,
            expected_rows=runtime.upgraded_scope(before_rows, selected),
            actual_rows=actual,
            maintenance=reader,
            expected_request_hash=db.sha(
                db.canonical(
                    {"operation": state["operation"], "before_sha256": state["before_sha256"]}
                )
            ),
            expected_payload=control._payload(state),
            idempotency_key="runtime-maintenance:" + operation.operation_id,
            maximum=16 * 1024 * 1024,
        )
        assert delta["event"]["published_at"] is None
        assert {row["project_id"] for row in before_rows["bindings"]} == {
            row["project_id"] for row in actual["bindings"]
        }
        service = object.__new__(RuntimeBindingService)
        service._compatibility_policy = RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({selected.runtime_version}),
            allowed_source_revisions=frozenset({selected.upstream_revision}),
            allowed_schema_revisions=frozenset({selected.official_schema_revision}),
            adapter_contract_version="0.2.0",
        )
        with Session(engine) as session:
            placement = session.get(RuntimePlacementRecord, placement_id)
            for partition in session.scalars(
                sa.select(RuntimePartitionRecord).where(
                    RuntimePartitionRecord.placement_id == placement_id
                )
            ):
                assert service.validate_target_records(partition, placement) in (1, 2)
        drift = copy.deepcopy(after)
        drift["tables"]["saas_runs"]["copy_sha256"] = "0" * 64
        with pytest.raises(db.Refused, match="nonruntime_fact_changed"):
            runtime_native.assert_runtime_transition_facts(
                before,
                drift,
                expected_rows=actual,
                actual_rows=actual,
                maintenance=reader,
                expected_request_hash="0" * 64,
                expected_payload={},
                idempotency_key="unused",
                maximum=1,
            )


class _TGuardObserver:
    """Test-only, failure-only metadata from the original maintenance connection."""

    _guard = (
        "SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_prepared_xacts "
        "WHERE database=current_database()) AND NOT EXISTS("
        "SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=current_database() "
        "AND pid<>pg_backend_pid() AND xact_start IS NOT NULL)"
    )

    def __init__(self, connection):
        self._connection = connection
        self._reported = False

    def execute(self, statement, *args, **kwargs):
        cursor = self._connection.execute(statement, *args, **kwargs)
        return _TGuardCursor(cursor, self) if statement == self._guard else cursor

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def record_failure(self):
        # One bounded first-False record for this borrowed scope, even if the
        # public reader legitimately reobserves more than once.
        if self._reported:
            return
        self._reported = True
        # Do not clear statistics or leave the original observer transaction.
        result = {
            "original_guard_boolean": False,
            "observed_at": datetime.now(UTC).isoformat(),
            "observer_backend_pid": self._connection.info.backend_pid,
            "transaction_status": self._connection.info.transaction_status.name,
        }
        try:
            remaining = 64
            for key, statement in (
                (
                    "activity",
                    "SELECT pid,backend_type,state,xact_start,query_start,state_change,"
                    "backend_xid::text,backend_xmin::text,wait_event_type,wait_event,"
                    "pg_catalog.pg_blocking_pids(pid) AS blocker_pids "
                    "FROM pg_catalog.pg_stat_activity WHERE datname=current_database() "
                    "AND pid<>pg_backend_pid() AND xact_start IS NOT NULL ORDER BY pid",
                ),
                (
                    "prepared",
                    "SELECT transaction::text AS transaction_id,prepared "
                    "FROM pg_catalog.pg_prepared_xacts WHERE database=current_database() "
                    "ORDER BY prepared,transaction::text",
                ),
            ):
                with self._connection.cursor() as cursor:
                    cursor.execute(statement + " LIMIT " + str(remaining + 1))
                    names = [column.name for column in cursor.description]
                    rows = cursor.fetchall()
                result[key] = [dict(zip(names, row, strict=True)) for row in rows[:remaining]]
                result[key + "_truncated"] = len(rows) > remaining
                remaining -= len(result[key])
        except Exception as exc:
            # Never emit query text, parameters, appname, GID, URLs or exception messages.
            result["diagnostic_error_type"] = type(exc).__name__
        try:
            payload = json.dumps(result, default=str)
            prefix = "OMNIGENT_T_INFLIGHT_METADATA "
            if len((prefix + payload + "\n").encode()) > 65536:
                payload = (
                    '{"original_guard_boolean":false,"diagnostic_error_type":"BoundExceeded"}'
                )
            print(prefix + payload, flush=True)
        except Exception:
            pass  # Diagnostic failure must not replace the original False/Refused.


class _TGuardCursor:
    def __init__(self, cursor, observer):
        self._cursor = cursor
        self._observer = observer

    def fetchone(self, *args, **kwargs):
        row = self._cursor.fetchone(*args, **kwargs)
        if row is not None and row[0] is False:
            try:
                self._observer.record_failure()
            except Exception:
                return row  # Observer/encoding failures preserve original False/Refused.
        return row

    def __getattr__(self, name):
        return getattr(self._cursor, name)


def _assert_native_t_readonly_observation(context, coordinator, state):
    """Real client transactions; no provider, paired image or backup claim."""
    capture = {
        "expected_identity": context.identity,
        "expected_tables": tuple(sorted(state["before_runtime_facts"]["tables"])),
        "max_copy_bytes": coordinator.preserving.maximum,
        "expected_head": "p0s000000018",
    }
    blocker = native.connect_url(context.plan.saas_owner.url)
    try:
        with blocker.transaction():
            blocker.execute("SELECT 1")
            started = time.monotonic()
            with pytest.raises(
                db.Refused, match=r"^t_recovery_has_inflight_or_prepared_transactions$"
            ):
                runtime_native.capture_t_preserved_facts(
                    context.owner, maintenance=context.reader, **capture
                )
            assert time.monotonic() - started >= 5.0
            assert context.reader.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    finally:
        blocker.close()

    ready, release = Barrier(2), Event()
    project_id = context.scopes[0][3]

    def commit_new_business_fact():
        with context.engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL statement_timeout='5s'")
            changed = connection.execute(
                sa.text("UPDATE saas_projects SET name=:name WHERE id=:id"),
                {"id": project_id, "name": "fresh-observation-" + uuid4().hex},
            ).rowcount
            ready.wait(timeout=10)
            assert release.wait(timeout=10), "observer never encountered the live transaction"
        return changed  # The actual COMMIT has completed before this return.

    class ReleaseAfterOriginalFalse(_TGuardObserver):
        def record_failure(self):
            release.set()  # No SQL, snapshot clearing or fake guard result.

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(commit_new_business_fact)
        try:
            ready.wait(timeout=10)
            fresh = runtime_native.capture_t_preserved_facts(
                context.owner,
                maintenance=ReleaseAfterOriginalFalse(context.reader),
                **capture,
            )
        finally:
            release.set()
        assert future.result(timeout=10) == 1
    assert release.is_set()
    assert (
        fresh["tables"]["saas_projects"]["copy_sha256"]
        != state["before_runtime_facts"]["tables"]["saas_projects"]["copy_sha256"]
    )
    before_rows = coordinator._rows()
    with pytest.raises(db.Refused, match=r"^t_runtime_prepared_CAS_failed$"):
        coordinator.inverse(state)
    assert coordinator._rows() == before_rows
    assert native.head(context.owner) == "p0s000000018"
    # Accept the independently observed committed data only through a new full
    # prepare. All original inverse/old verifier/reattach assertions still run.
    return coordinator.prepare()


def assert_fenced_t_complete_inverse_and_reattach_derives_independent_target_gold(
    production_replay, tmp_path
):
    """Full real SQL, not real images/provider/backup/65-second readiness."""
    from saas.production.postgresql_preserving_recovery import PreservingPostgreSqlRecovery

    with _native_t_rebinding_fixture(production_replay, derive_t_gold_at=tmp_path) as context:
        gold = {**context.complete_gold, "rollback_target": context.operation.target_contract()}
        (tmp_path / "independent-source-gold.fixture.json").write_text(
            json.dumps(gold, sort_keys=True, indent=2) + "\n"
        )
        operation = replace(context.operation, source_gold_sha256=db.sha(db.canonical(gold)))
        database_owner = native.connect_url(context.plan.database_owner.url)
        checkpoints, callbacks = [], []

        def fixture_fence(actual, phase):
            assert actual == operation
            callbacks.append(phase)  # Fixture only: no real backup/fence claim.

        preserving = PreservingPostgreSqlRecovery(
            plan=context.plan,
            engines=context.engines,
            owner=context.owner,
            database_owner=database_owner,
            maintenance=_TGuardObserver(context.reader),
            operation=operation,
            source_gold=gold,
            before_mutation=fixture_fence,
            checkpoint=lambda phase, state: checkpoints.append((phase, copy.deepcopy(state))),
            max_copy_bytes=16 * 1024 * 1024,
        )
        target = runtime.RuntimeMaintenanceOperation(
            **{
                key: value
                for key, value in asdict(context.selected).items()
                if key not in {"direction", "source_official_schema_revision", "recovery"}
            },
            recovery=operation,  # Replace the staged old tuple with actual candidate template.
        )
        from omnigent.version import VERSION

        target = replace(
            target,
            runtime_version=VERSION,
            upstream_revision="3db749d784ff044304473939acaae3a65c0fec61",
            official_schema_revision="nf12ab34cd56",
        )

        def fixture_transition(parent, child, before):
            assert parent == operation and before["placements"][0]["id"] == target.placement_id
            assert native.head(context.owner) == "p0s000000018"
            with context.engines["official_owner"].connect() as official:
                assert (
                    official.exec_driver_sql(
                        "SELECT version_num FROM public.alembic_version"
                    ).scalar_one()
                    == "nf12ab34cd56"
                )

        def fixture_pair(parent, state):
            assert parent == operation
            assert state["phase"] in {
                "t_inverse_original_pair_verification_required",
                "t_original_pair_same_projects_verified",
            }
            assert native.head(context.owner) == "lm2t00000001"
            with context.engines["official_owner"].connect() as official:
                assert (
                    official.exec_driver_sql(
                        "SELECT version_num FROM public.alembic_version"
                    ).scalar_one()
                    == "mm1a2b3c4d5e"
                )
            # Actual old-image startup is a separate required operator callback.
            actual = runtime_native.runtime_rows_snapshot(
                context.reader, expected_identity=context.identity, owner=context.owner, maximum=20
            )
            assert {row["project_id"] for row in actual["bindings"]} == {
                row["project_id"] for row in state["before_runtime_rows"]["bindings"]
            }

        coordinator = runtime.FencedTRuntimeRecovery(
            preserving=preserving,
            runtime_operations=[target],
            verify_transition=fixture_transition,
            verify_pair=fixture_pair,
            max_rows=20,
        )
        try:
            state = coordinator.prepare()
            state = _assert_native_t_readonly_observation(context, coordinator, state)
            original = state["before_runtime_facts"]
            for table in db.TABLES:
                assert original["tables"][table]["row_count"] == 2
            old = coordinator.inverse(state)
            assert {fact["schema"] for fact in old["preserving"]["before"]["tables"].values()} == {
                "public"
            }
            assert old["preserving"]["archived"]["tables"] == {
                table: {**fact, "schema": db.archive_name(operation.operation_id)}
                for table, fact in old["preserving"]["before"]["tables"].items()
            }
            # Source verifier acceptance is distinct from original paired-image startup.
            old_directory = tmp_path / "original-3264-p15-source"
            old_module_path = old_directory / "saas/production/postgresql_migration.py"
            assert hashlib.sha256(old_module_path.read_bytes()).hexdigest() == (
                "e9c5e9210da07c1825d62cc8f198e5471e0e41001a87a7b318206ac28ce91127"
            )
            module_name = "saas.production._native_original_t_verify_" + uuid4().hex
            specification = importlib.util.spec_from_file_location(module_name, old_module_path)
            original_verifier = importlib.util.module_from_spec(specification)
            sys.modules[module_name] = original_verifier
            try:
                specification.loader.exec_module(original_verifier)
                original_verifier.files = lambda package: old_directory.joinpath(
                    *package.split(".")
                )
                old_plan = replace(
                    context.plan,
                    business_delivery_service_role_bindings=None,
                    verification_saas_head="lm2t00000001",
                )
                assert (
                    original_verifier._verify_state(old_plan, context.engines).saas_head
                    == "lm2t00000001"
                )
            finally:
                sys.modules.pop(module_name, None)
            quoted_owner = context.engine.dialect.identifier_preparer.quote(
                context.plan.saas_owner.login
            )
            for changed_sql, restore_sql in (
                ("ALTER ROLE saas_usage_consumer LOGIN", "ALTER ROLE saas_usage_consumer NOLOGIN"),
                (
                    f"GRANT saas_usage_consumer TO {quoted_owner} WITH ADMIN FALSE",
                    f"REVOKE saas_usage_consumer FROM {quoted_owner} GRANTED BY CURRENT_USER",
                ),
                (
                    "GRANT SELECT ON public.saas_runs TO saas_usage_consumer",
                    "REVOKE SELECT ON public.saas_runs FROM saas_usage_consumer",
                ),
            ):
                with context.engine.begin() as connection:
                    connection.exec_driver_sql(changed_sql)
                try:
                    with pytest.raises(db.Refused):
                        preserving._t_old_catalog(old["preserving"])
                finally:
                    with context.engine.begin() as connection:
                        connection.exec_driver_sql(restore_sql)
                preserving._t_old_catalog(old["preserving"])
            verified = coordinator.verify_original_pair(old)
            restored = coordinator.reattach(verified)
            final = coordinator._facts()
            assert {key: final["tables"][key] for key in db.TABLES} == {
                key: original["tables"][key] for key in db.TABLES
            }
            rows = coordinator._rows()
            assert rows["aliases"] == state["before_runtime_rows"]["aliases"]
            for name, generation in (
                ("partitions", "placement_generation"),
                ("bindings", "binding_generation"),
            ):
                for before, after in zip(
                    state["before_runtime_rows"][name], rows[name], strict=True
                ):
                    assert after[generation] == before[generation] + 2
            assert len(restored["completed_transitions"]) == 2
            assert final["tables"]["saas_runs"] == original["tables"]["saas_runs"]
            assert (
                migration._verify_state(context.plan, context.engines).saas_head == "p0s000000018"
            )
            assert callbacks and checkpoints
        finally:
            database_owner.close()
