"""Effect ordering and scope preservation; SQL/RLS semantics require native replay."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from threading import Barrier, RLock
from types import SimpleNamespace
from uuid import uuid4

import pytest

from saas.production import postgresql_preserving_adapter as db
from saas.production import postgresql_runtime_maintenance as runtime
from tests.saas import test_postgresql_preserving_recovery as recovery_tests

recovery_boundary = recovery_tests.recovery_boundary


@pytest.fixture
def runtime_boundary(recovery_boundary, monkeypatch):
    recovery = recovery_boundary.operation
    operation = runtime.RuntimeMaintenanceOperation(
        recovery=recovery,
        realm="isolation",
        namespace="fixture-isolated-runtime",
        namespace_uid=str(uuid4()),
        cluster_uid=str(uuid4()),
        placement_id=str(uuid4()),
        runtime_version="0.19.0.fixture",
        upstream_revision="3" * 40,
        official_schema_revision="nf12ab34cd56",
        adapter_contract_version="0.2.0",
        runtime_observation_ref="fixture://explicit-unit-only-provider-readback",
        runtime_observation_sha256="4" * 64,
    )
    before = {
        "placements": [
            {
                "id": operation.placement_id,
                "status": "active",
                "official_schema_revision": "mm1a2b3c4d5e",
                "database_cluster_ref": "keep-existing-cluster",
            }
        ],
        "partitions": [],
        "bindings": [],
        "aliases": [],
    }
    for _ in range(2):
        tenant, space, partition = (str(uuid4()) for _ in range(3))
        before["partitions"].append(
            {
                "id": partition,
                "placement_id": operation.placement_id,
                "tenant_id": tenant,
                "space_id": space,
                "status": "active",
                "physical_partition_key": str(uuid4()),
                "placement_generation": 4,
                "runtime_version": "0.18",
                "source_revision": "0" * 40,
                "adapter_contract_version": "0.1.0",
            }
        )
        before["bindings"].append(
            {
                "id": str(uuid4()),
                "runtime_partition_id": partition,
                "tenant_id": tenant,
                "space_id": space,
                "project_id": str(uuid4()),
                "runtime_resource_id": str(uuid4()),
                "status": "active",
                "partition_generation": 4,
                "binding_generation": 7,
            }
        )
        before["aliases"].append(
            {
                "runtime_partition_id": partition,
                "user_id": str(uuid4()),
                "runtime_user_key": str(uuid4()),
            }
        )
    retired = {
        **before["bindings"][0],
        "id": str(uuid4()),
        "status": "retired",
        "partition_generation": 2,
    }
    before["bindings"].append(retired)
    store = SimpleNamespace(current=copy.deepcopy(before), receipts=[], events=[], failure=None)
    lock = RLock()

    # Unit-only transaction double: tests inject commit/outbox faults. This is
    # not a parser, native SQL/RLS test, database identity or production adapter.
    class Owner:
        @contextmanager
        def transaction(self):
            with lock:
                old = copy.deepcopy((store.current, store.receipts))
                try:
                    yield
                except BaseException:
                    store.current, store.receipts = old
                    raise
                if store.failure == "commit_ack":
                    store.failure = None
                    raise ConnectionError("commit acknowledgement lost")

        def execute(self, statement, values=()):
            text = statement if isinstance(statement, str) else statement.as_string(None)
            store.events.append(text.split()[0])
            if text.startswith("UPDATE"):
                old = values[-1].obj
                for name, fields in (
                    ("placements", ("official_schema_revision",)),
                    (
                        "partitions",
                        (
                            "runtime_version",
                            "source_revision",
                            "adapter_contract_version",
                            "placement_generation",
                        ),
                    ),
                    ("bindings", ("partition_generation", "binding_generation")),
                ):
                    for row in store.current[name]:
                        if row["id"] == values[-2]:
                            assert row == old
                            row.update(zip(fields, values, strict=False))
                            return SimpleNamespace(rowcount=1)
                raise AssertionError("unknown fixture row")
            if text.startswith("INSERT"):
                if store.failure == "outbox":
                    raise OSError("durable outbox insert failed")
                store.receipts.append((values[-2], values[-1], values[2].obj))
            return SimpleNamespace(rowcount=1)

    monkeypatch.setattr(runtime.RuntimePlacementMaintenance, "_identity", lambda self: None)
    monkeypatch.setattr(runtime.RuntimePlacementMaintenance, "_settings", lambda self, **_: None)
    monkeypatch.setattr(
        runtime.RuntimePlacementMaintenance, "_scope", lambda self: copy.deepcopy(store.current)
    )
    monkeypatch.setattr(
        runtime.RuntimePlacementMaintenance,
        "_receipt",
        lambda self: copy.deepcopy(
            [
                row[1:]
                for row in store.receipts
                if row[0] == "runtime-maintenance:" + self.operation.recovery.operation_id
            ]
        ),
    )
    monkeypatch.setattr(runtime.RuntimePlacementMaintenance, "_quiescent", lambda self: None)
    monkeypatch.setattr(
        runtime.migration,
        "_verify_state",
        lambda *_: SimpleNamespace(
            saas_head=runtime.HEAD, official_head=operation.official_schema_revision
        ),
    )

    def make(*, before_mutation=None, verify_runtime=None, checkpoint=None, selected=operation):
        return runtime.RuntimePlacementMaintenance(
            plan=SimpleNamespace(product_revision=recovery.candidate_product_revision),
            engines={},
            owner=Owner(),
            maintenance=None,
            operation=selected,
            source_gold=recovery_boundary.gold,
            before_mutation=before_mutation or (lambda *_: None),
            verify_runtime=verify_runtime or (lambda *_: None),
            checkpoint=checkpoint or (lambda *_: None),
            max_rows=10,
        )

    return SimpleNamespace(make=make, operation=operation, before=before, store=store)


def test_all_old_projects_workspaces_identities_and_retired_history_survive(runtime_boundary):
    fixture = runtime_boundary
    control = fixture.make()
    state = control.prepare()
    result = control.apply(state)
    assert result["production_admitted"] is False
    assert len(fixture.store.receipts) == 1
    assert fixture.store.current["aliases"] == fixture.before["aliases"]
    assert fixture.store.current["bindings"][-1] == fixture.before["bindings"][-1]
    for old, new in zip(
        fixture.before["partitions"], fixture.store.current["partitions"], strict=True
    ):
        assert new["placement_generation"] == old["placement_generation"] + 1
        assert {
            k: v
            for k, v in new.items()
            if k
            not in {
                "placement_generation",
                "runtime_version",
                "source_revision",
                "adapter_contract_version",
            }
        } == {
            k: v
            for k, v in old.items()
            if k
            not in {
                "placement_generation",
                "runtime_version",
                "source_revision",
                "adapter_contract_version",
            }
        }
    assert control.apply(state) == result
    assert len(fixture.store.receipts) == 1


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize("boundary", ["before_mutation", "verify_runtime"])
def test_boolean_flags_never_authorize_mutation(runtime_boundary, flag, boundary):
    control = runtime_boundary.make()
    state = control.prepare()
    setattr(control, boundary, lambda *_: flag)
    with pytest.raises(db.Refused, match=r"not_return_authorized_flag|not_return_flag"):
        control.apply(state)
    assert runtime_boundary.store.events == []


@pytest.mark.parametrize("boundary", ["before_mutation", "verify_runtime", "checkpoint"])
def test_failed_existing_authority_or_journal_prevents_any_sql(runtime_boundary, boundary):
    control = runtime_boundary.make()
    state = control.prepare()

    def fail(*_):
        raise OSError("existing external authority unavailable")

    setattr(control, boundary, fail)
    with pytest.raises(OSError, match="unavailable"):
        control.apply(state)
    assert runtime_boundary.store.events == []


def test_stale_complete_set_and_second_concurrent_operation_fail_closed(runtime_boundary):
    control = runtime_boundary.make()
    first = control.prepare()
    second = runtime_boundary.make(
        selected=replace(
            runtime_boundary.operation,
            recovery=replace(runtime_boundary.operation.recovery, operation_id=str(uuid4())),
        )
    )
    stale = second.prepare()
    barrier = Barrier(2)

    def synchronize(_operation, phase):
        if phase == "upgrade_runtime_metadata":
            barrier.wait(timeout=5)

    control.before_mutation = second.before_mutation = synchronize
    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(control.apply, first), executor.submit(second.apply, stale)]
        for future in futures:
            try:
                outcomes.append(future.result())
            except db.Refused as error:
                assert str(error) == "complete_placement_CAS_failed"
                outcomes.append(None)
    assert sum(value is not None for value in outcomes) == 1
    assert len(runtime_boundary.store.receipts) == 1


@pytest.mark.parametrize("corruption", ["extra_binding", "wrong_tenant", "stale_generation"])
def test_changed_membership_or_scope_is_never_silently_omitted(runtime_boundary, corruption):
    control = runtime_boundary.make()
    state = control.prepare()
    if corruption == "extra_binding":
        runtime_boundary.store.current["bindings"].append(
            {**runtime_boundary.before["bindings"][0], "id": str(uuid4())}
        )
    elif corruption == "wrong_tenant":
        runtime_boundary.store.current["bindings"][0]["tenant_id"] = str(uuid4())
    else:
        runtime_boundary.store.current["partitions"][0]["placement_generation"] += 1
    with pytest.raises(db.Refused, match="complete_placement_CAS_failed"):
        control.apply(state)
    assert not runtime_boundary.store.receipts


def test_outbox_failure_rolls_back_the_entire_metadata_transaction(runtime_boundary):
    control = runtime_boundary.make()
    state = control.prepare()
    runtime_boundary.store.failure = "outbox"
    with pytest.raises(OSError, match="outbox"):
        control.apply(state)
    assert runtime_boundary.store.current == runtime_boundary.before
    assert runtime_boundary.store.receipts == []


def test_unknown_commit_is_reconciled_without_writing_or_duplicate_event(runtime_boundary):
    control = runtime_boundary.make()
    state = control.prepare()
    runtime_boundary.store.failure = "commit_ack"
    with pytest.raises(ConnectionError, match="acknowledgement"):
        control.apply(state)
    runtime_boundary.store.events.clear()
    result = control.reconcile(state)
    assert result["phase"] == "runtime_metadata_committed"
    assert runtime_boundary.store.events == []
    assert len(runtime_boundary.store.receipts) == 1


@pytest.mark.parametrize(
    "change", [{"realm": "unverified"}, {"placement_id": "generated-placeholder"}]
)
def test_invalid_scope_rejected_before_any_sql(runtime_boundary, change):
    with pytest.raises((db.Refused, ValueError)):
        runtime_boundary.make(selected=replace(runtime_boundary.operation, **change))
    assert runtime_boundary.store.events == []


@pytest.mark.parametrize(
    "retained",
    [
        None,
        "saas_model_provider_budget_reservations",
        "saas_model_publication_commands",
        "saas_model_publication_versions",
        "saas_model_gateway_evidence",
        "saas_model_run_tokens",
        "saas_model_publication_disablements",
        "saas_model_publication_revocations",
        "saas_model_connections",
        "saas_model_credential_versions",
        "saas_model_deployment_versions",
        "saas_model_projection_operations",
        "saas_model_projection_transitions",
        "saas_model_test_funding_policies",
        "saas_model_verification_budget_bindings",
        "saas_model_verification_commands",
        "saas_model_verification_receipts",
        "saas_runs",
        "saas_execution_sessions",
        "audit:model_gateway.evidence_retained",
        "audit:platform.model_publication.disabled",
        "audit:platform.model_publication.revocation_requested",
    ],
)
def test_retained_fact_preflight_uses_independent_unfiltered_reader(monkeypatch, retained):
    from psycopg.pq import TransactionStatus

    from saas.production import postgresql_runtime_maintenance_native as inverse

    statements = []
    identity = {"system_identifier": "fixture-only", "database_oid": 42}

    class Connection:
        def __init__(self, user):
            self.info = SimpleNamespace(user=user, transaction_status=TransactionStatus.IDLE)

        @contextmanager
        def transaction(self):
            self.info.transaction_status = TransactionStatus.INTRANS
            try:
                yield
            finally:
                self.info.transaction_status = TransactionStatus.IDLE

        def execute(self, statement, values=()):
            text = statement if isinstance(statement, str) else statement.as_string(None)
            statements.append(text)
            if text.startswith("SELECT EXISTS"):
                exists = (
                    retained is not None
                    and retained.startswith("audit:")
                    and "saas_platform_audit_events" in text
                    and retained[6:] in values[0]
                ) or (retained is not None and f'public."{retained}"' in text)
                return SimpleNamespace(fetchone=lambda: (exists,))
            return SimpleNamespace()

    owner, reader = Connection("direct_owner"), Connection("existing_backup_reader")
    monkeypatch.setattr(inverse.native, "head", lambda _: "p0s000000018")
    monkeypatch.setattr(inverse.db, "database_identity", lambda *_: identity)

    def catalog(connection, statement, values=()):
        assert connection is reader
        if "session_user" in statement:
            return {"login": reader.info.user, "session_login": reader.info.user}
        return {"relkind": "r", "can_select": True, "rls_active": False}

    monkeypatch.setattr(inverse.db, "one", catalog)
    if retained is not None:
        with pytest.raises(db.Refused, match=r"requires?_original_database_restore"):
            inverse.require_source_inverse_possible(
                owner, maintenance=reader, expected_identity=identity
            )
    else:
        result = inverse.require_source_inverse_possible(
            owner, maintenance=reader, expected_identity=identity
        )
        assert result["all_relations_unfiltered"] is True
        assert result["row_security"] == "on"
    assert (
        owner.info.transaction_status == reader.info.transaction_status == TransactionStatus.IDLE
    )
    assert not any(
        text.startswith(("DROP", "ALTER", "UPDATE", "INSERT", "DELETE")) for text in statements
    )


@pytest.mark.parametrize(
    "coverage",
    [
        {"relkind": "r", "can_select": True, "rls_active": True},
        {"relkind": "r", "can_select": False, "rls_active": False},
        {"relkind": "v", "can_select": True, "rls_active": False},
    ],
)
def test_partial_or_unprivileged_reader_cannot_authorize_empty_preflight(monkeypatch, coverage):
    from psycopg.pq import TransactionStatus

    from saas.production import postgresql_runtime_maintenance_native as inverse

    statements = []

    class Reader:
        info = SimpleNamespace(user="existing_reader", transaction_status=TransactionStatus.IDLE)

        @contextmanager
        def transaction(self):
            yield

        def execute(self, statement):
            statements.append(statement)

    reader = Reader()
    owner = SimpleNamespace(
        info=SimpleNamespace(user="owner", transaction_status=TransactionStatus.IDLE)
    )
    monkeypatch.setattr(inverse.native, "head", lambda _: "p0s000000018")
    monkeypatch.setattr(inverse.db, "database_identity", lambda *_: {})
    monkeypatch.setattr(
        inverse.db,
        "one",
        lambda _c, statement, *_: (
            {"login": "existing_reader", "session_login": "existing_reader"}
            if "session_user" in statement
            else coverage
        ),
    )
    with pytest.raises(db.Refused, match="existing_maintenance_full_visibility_required"):
        inverse.require_source_inverse_possible(owner, maintenance=reader, expected_identity={})
    assert not any(text.startswith("SELECT EXISTS") for text in statements)
    assert all(text.startswith("SET ") for text in statements)


def test_p18_inverse_catalog_cas_fails_before_any_drop_or_head_stamp(monkeypatch):
    from psycopg.pq import TransactionStatus

    from saas.production import postgresql_runtime_maintenance_native as inverse

    statements = []

    class Connection:
        info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

        @contextmanager
        def transaction(self):
            yield

        def execute(self, statement, values=()):
            text = statement if isinstance(statement, str) else statement.as_string(None)
            statements.append(text)
            return SimpleNamespace(fetchone=lambda: ("p0s000000018",))

    monkeypatch.setattr(inverse, "policy_snapshot", lambda _: [{"actual": "drifted"}])
    with pytest.raises(db.Refused, match="p18_policy_CAS_failed"):
        inverse.remove_p18_policies(Connection(), [{"expected": "source-verified"}])
    assert not any(statement.startswith(("DROP", "UPDATE")) for statement in statements)


@pytest.mark.parametrize("boundary", ["before_mutation", "verify_runtime"])
def test_authority_expiry_after_sql_rolls_back_before_commit(runtime_boundary, boundary):
    control = runtime_boundary.make()
    state = control.prepare()
    calls = 0

    def expire(*_):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError("existing proof expired during metadata SQL")

    setattr(control, boundary, expire)
    with pytest.raises(TimeoutError, match="expired during"):
        control.apply(state)
    assert "INSERT" in runtime_boundary.store.events
    assert runtime_boundary.store.current == runtime_boundary.before
    assert runtime_boundary.store.receipts == []
