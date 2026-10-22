"""Coordinator failures must prevent the next destructive recovery operation.

Database identity/catalog/row preservation has a separate real PostgreSQL replay;
these unit cases exercise the public API's effect ordering with no database I/O.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict, replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from psycopg.pq import TransactionStatus

from saas.production import postgresql_preserving_adapter as adapter
from saas.production import postgresql_preserving_native as native
from saas.production import postgresql_preserving_recovery as recovery


@pytest.fixture
def recovery_boundary(monkeypatch):
    identity = {
        "system_identifier": "fixture-system",
        "database_name": "fixture_recovery",
        "database_oid": 42,
        "database_owner": "fixture_database",
        "server_major": 16,
    }
    gold = {"fixture": "no production catalog or backup evidence"}
    operation = recovery.RecoveryOperation(
        operation_id=str(uuid4()),
        candidate_product_revision="a" * 40,
        candidate_server_digest="sha256:" + "b" * 64,
        rollback_product_revision="c" * 40,
        rollback_server_digest="sha256:" + "d" * 64,
        database_identity=identity,
        backup_object_uri="fixture://explicit-unit-test-only",
        backup_object_version="fixture-version",
        backup_ciphertext_sha256="e" * 64,
        backup_manifest_sha256="f" * 64,
        backup_kms_key_version="fixture-kms-version",
        fence_generation=1,
        fence_scope_sha256="1" * 64,
        fence_record_sha256="2" * 64,
        source_gold_sha256=adapter.sha(adapter.canonical(gold)),
    )
    # Isolate installed-build and direct-DB checks only in this unit fixture.
    # No fixture adapter is installed as a production default.
    monkeypatch.setattr(recovery.migration, "_validate_plan", lambda _plan: None)
    monkeypatch.setattr(adapter, "database_identity", lambda *_args: identity)
    events = []

    def prepare_archive(*_args, **_kwargs):
        events.append("archive")
        return {}

    def move_receipts(*_args, **_kwargs):
        events.append("move")
        raise AssertionError("the next SQL phase must not run")

    monkeypatch.setattr(
        recovery.runtime_native, "require_source_inverse_possible", lambda *_, **__: {}
    )
    monkeypatch.setattr(recovery.runtime_native, "remove_p18_policies", lambda *_: None)
    monkeypatch.setattr(adapter, "prepare_archive", prepare_archive)
    monkeypatch.setattr(adapter, "move_receipts", move_receipts)

    def connection(user):
        return SimpleNamespace(
            info=SimpleNamespace(user=user, transaction_status=TransactionStatus.IDLE)
        )

    def make(*, before=None, checkpoint=None, supplied_operation=None, supplied_gold=None):
        selected = operation if supplied_operation is None else supplied_operation
        control = recovery.PreservingPostgreSqlRecovery(
            plan=SimpleNamespace(
                product_revision=operation.candidate_product_revision,
                saas_owner=SimpleNamespace(login="fixture_table_owner"),
                database_owner=SimpleNamespace(login="fixture_database"),
            ),
            engines={},
            owner=connection("fixture_table_owner"),
            database_owner=connection("fixture_database"),
            maintenance=connection("fixture_maintenance"),
            operation=selected,
            source_gold=gold if supplied_gold is None else supplied_gold,
            before_mutation=(lambda *_args: None) if before is None else before,
            checkpoint=(lambda *_args: None) if checkpoint is None else checkpoint,
            max_copy_bytes=1024,
        )
        state = {
            "phase": "prepared",
            "operation": asdict(selected),
            "before": {"tables": {}},
            "p18_policy_snapshot": [],
        }
        return control, state

    return SimpleNamespace(make=make, operation=operation, gold=gold, events=events)


@pytest.mark.parametrize("failure", [RuntimeError, ConnectionError])
def test_stale_fence_or_unreadable_backup_stops_before_any_archive_or_move(
    recovery_boundary, failure
):
    def failed_revalidation(_operation, phase):
        recovery_boundary.events.append(phase)
        raise failure("existing recovery authority is unavailable or stale")

    control, state = recovery_boundary.make(before=failed_revalidation)
    with pytest.raises(failure, match="unavailable or stale"):
        control.inverse(state)
    assert recovery_boundary.events == ["preflight_source_inverse"]


@pytest.mark.parametrize("flag", [True, False])
def test_callback_boolean_does_not_authorize_any_archive_or_move(recovery_boundary, flag):
    control, state = recovery_boundary.make(before=lambda *_args: flag)
    with pytest.raises(adapter.Refused, match="not_return_authorized_flag"):
        control.inverse(state)
    assert recovery_boundary.events == []


def test_failed_durable_checkpoint_stops_before_the_next_sql_phase(recovery_boundary):
    def failed_checkpoint(phase, _state):
        recovery_boundary.events.append(phase)
        raise OSError("recovery journal fsync failed")

    control, state = recovery_boundary.make(checkpoint=failed_checkpoint)
    with pytest.raises(OSError, match="fsync failed"):
        control.inverse(state)
    assert recovery_boundary.events == ["source_inverse_preflight_passed"]


@pytest.mark.parametrize(
    "changes", [{"fence_generation": 0}, {"candidate_server_digest": "mutable:latest"}]
)
def test_bad_operation_is_rejected_before_any_archive_or_move(recovery_boundary, changes):
    with pytest.raises(adapter.Refused):
        recovery_boundary.make(supplied_operation=replace(recovery_boundary.operation, **changes))
    assert recovery_boundary.events == []


def test_source_gold_digest_mismatch_is_rejected_before_any_archive_or_move(recovery_boundary):
    with pytest.raises(adapter.Refused, match="source_gold_bytes_mismatch"):
        recovery_boundary.make(supplied_gold={"unreviewed": "catalog"})
    assert recovery_boundary.events == []


def test_state_from_another_operation_is_rejected_before_revalidation(recovery_boundary):
    def forbidden_revalidation(*_args):
        raise AssertionError("wrong operation must fail before authority checks")

    control, state = recovery_boundary.make(before=forbidden_revalidation)
    state["operation"]["operation_id"] = str(uuid4())
    with pytest.raises(adapter.Refused, match="prepared_operation_required"):
        control.inverse(state)
    assert recovery_boundary.events == []


@pytest.mark.parametrize("driver", ["postgresql", "postgresql+psycopg"])
def test_native_connection_preserves_escaped_identity_and_strict_tls_parameters(
    monkeypatch, driver
):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    observed = []
    sentinel = object()

    def connect(*args, autocommit, **kwargs):
        observed.append((conninfo_to_dict(make_conninfo(*args, **kwargs)), autocommit))
        return sentinel

    monkeypatch.setattr(native.psycopg, "connect", connect)
    url = (
        f"{driver}://fixture_login:synthetic%3A%40password@127.0.0.1:5433/fixture_db"
        "?sslmode=verify-full&sslrootcert=%2Ffixture%2Froot.crt"
        "&application_name=preserving%20recovery&connect_timeout=2"
    )
    assert native.connect_url(url) is sentinel
    assert observed == [
        (
            {
                "host": "127.0.0.1",
                "port": "5433",
                "user": "fixture_login",
                "password": "synthetic:@password",
                "dbname": "fixture_db",
                "sslmode": "verify-full",
                "sslrootcert": "/fixture/root.crt",
                "application_name": "preserving recovery",
                "connect_timeout": "2",
            },
            True,
        )
    ]


def test_retained_guard_failure_prevents_every_inverse_mutation(recovery_boundary, monkeypatch):
    control, state = recovery_boundary.make(
        before=lambda _operation, phase: recovery_boundary.events.append(phase)
    )

    def retained(*_, **__):
        raise adapter.Refused("retained_runtime_facts_require_original_database_restore")

    def mutation(*_, **__):
        raise AssertionError("no policy/archive/detach mutation may precede preflight")

    monkeypatch.setattr(recovery.runtime_native, "require_source_inverse_possible", retained)
    monkeypatch.setattr(recovery.runtime_native, "remove_p18_policies", mutation)
    with pytest.raises(adapter.Refused, match="require_original_database_restore"):
        control.inverse(state)
    assert recovery_boundary.events == ["preflight_source_inverse"]


def test_policy_snapshot_uses_canonical_context_and_restores_caller(monkeypatch):
    inverse = recovery.runtime_native
    sentinel = object()

    class Connection:
        search_path = "public,fixture"

        @contextmanager
        def transaction(self, *, force_rollback):
            assert force_rollback is True
            old = self.search_path
            try:
                yield
            finally:
                self.search_path = old

        def execute(self, statement):
            assert statement == "SET LOCAL search_path=pg_catalog,pg_temp"
            self.search_path = "pg_catalog,pg_temp"

    def read(connection, statement, parameters):
        assert connection.search_path == "pg_catalog,pg_temp"
        row = next(p for p in inverse.contract.POLICIES if p[1] == parameters[1])
        return {
            "polcmd": "w" if row[2] == "UPDATE" else "r",
            "polpermissive": True,
            "polroles": "{0}",
            "relrowsecurity": True,
            "relforcerowsecurity": True,
            "raw_ast_and_OID_and_deparsed_fields": sentinel,
        }

    monkeypatch.setattr(inverse.db, "one", read)
    connection = Connection()
    snapshots = inverse.policy_snapshot(connection)
    assert connection.search_path == "public,fixture"
    assert len(snapshots) == 4
    assert all(row["raw_ast_and_OID_and_deparsed_fields"] is sentinel for row in snapshots)


def _explicit_t_fixture(boundary, **changes):
    operation = recovery.ExplicitTRecoveryOperation(
        **{
            **asdict(boundary.operation),
            "contract_version": recovery.T_PROTOCOL,
            "rollback_saas_target": recovery.T_HEAD,
            "rollback_host_digest": "sha256:" + "5" * 64,
            "rollback_upstream_revision": "6" * 40,
            "rollback_adapter_contract_version": "0.2.0",
            **changes,
        }
    )
    gold = {**boundary.gold, "rollback_target": operation.target_contract()}
    operation = replace(operation, source_gold_sha256=adapter.sha(adapter.canonical(gold)))
    return operation, gold


def test_original_p15_operation_json_fields_remain_exact(recovery_boundary):
    operation = replace(
        recovery_boundary.operation, operation_id="00000000-0000-0000-0000-000000000001"
    )
    assert tuple(asdict(operation)) == (
        "operation_id",
        "candidate_product_revision",
        "candidate_server_digest",
        "rollback_product_revision",
        "rollback_server_digest",
        "database_identity",
        "backup_object_uri",
        "backup_object_version",
        "backup_ciphertext_sha256",
        "backup_manifest_sha256",
        "backup_kms_key_version",
        "fence_generation",
        "fence_scope_sha256",
        "fence_record_sha256",
        "source_gold_sha256",
    )
    document = adapter.canonical(asdict(operation))
    assert adapter.sha(document) == (
        "29e8514fda8fb96f2c201f4419b570317490d50c733353a6d026796ae54fbd0f"
    )
    decoded = recovery.load_operation_document(json.loads(document))
    assert type(decoded) is recovery.RecoveryOperation
    assert adapter.canonical(asdict(decoded)) == document
    control, state = recovery_boundary.make(supplied_operation=decoded)
    records = []
    control.checkpoint = lambda phase, value: records.append(
        adapter.canonical({"checkpoint_phase": phase, "state": value})
    )
    control._save("prepared", state)
    assert adapter.sha(records[0]) == (
        "4e8018d9759724428ba25d5aaa9087063053b4a8649c5bcc3bb12ad614e8b040"
    )


def test_explicit_t_json_roundtrip_is_versioned_and_bound(recovery_boundary):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    raw = adapter.canonical(asdict(operation))
    document = json.loads(raw)
    assert len(document) == 20
    assert type(document["contract_version"]) is str
    assert type(document["rollback_saas_target"]) is str
    decoded = recovery.load_operation_document(document)
    assert type(decoded) is recovery.ExplicitTRecoveryOperation
    assert adapter.canonical(asdict(decoded)) == raw
    control, state = recovery_boundary.make(supplied_operation=decoded, supplied_gold=gold)
    recovery.require_checkpoint_operation(json.loads(adapter.canonical(state)), decoded)
    assert gold["rollback_target"]["contract_version"] == recovery.T_PROTOCOL
    assert recovery._rollback_revision(control.operation) == "lm2t00000001"
    assert recovery._rollback_revision(recovery_boundary.operation) == "p0s000000015"
    assert recovery_boundary.events == []


@pytest.mark.parametrize(
    "change",
    [
        {"contract_version": "unknown"},
        {"rollback_saas_target": "p0s000000015"},
        {"rollback_saas_target": True},
        {"rollback_host_digest": "mutable:latest"},
        {"rollback_upstream_revision": "unknown"},
        {"rollback_adapter_contract_version": "unknown"},
    ],
)
def test_explicit_t_unknown_contract_or_pair_stops_before_io(recovery_boundary, change):
    operation, gold = _explicit_t_fixture(recovery_boundary, **change)
    with pytest.raises(adapter.Refused):
        recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    assert recovery_boundary.events == []


@pytest.mark.parametrize("document", [None, True, [], "unknown"])
def test_operation_loader_rejects_non_objects(document):
    with pytest.raises(adapter.Refused, match="operation_document_must_be_object"):
        recovery.load_operation_document(document)


@pytest.mark.parametrize("variation", ["extra", "missing", "unknown-version", "old-enum-shape"])
def test_operation_loader_never_repairs_unknown_shapes(recovery_boundary, variation):
    operation, _gold = _explicit_t_fixture(recovery_boundary)
    document = json.loads(adapter.canonical(asdict(operation)))
    if variation == "extra":
        document["extra"] = "unknown"
    elif variation == "missing":
        del document["rollback_host_digest"]
    elif variation == "unknown-version":
        document["contract_version"] = "unknown"
    else:
        document = {
            **asdict(recovery_boundary.operation),
            "rollback_saas_target": "p0s000000015",
            "rollback_host_digest": None,
            "rollback_upstream_revision": None,
            "rollback_adapter_contract_version": None,
        }
    before = adapter.canonical(document)
    with pytest.raises(adapter.Refused, match="operation_document_version_or_shape_unknown"):
        recovery.load_operation_document(document)
    assert adapter.canonical(document) == before
    assert recovery_boundary.events == []


@pytest.mark.parametrize(
    "change", [{"fence_generation": True}, {"database_identity": None}, {"operation_id": "bad"}]
)
def test_operation_loader_invalid_values_fail_closed(recovery_boundary, change):
    document = {**asdict(recovery_boundary.operation), **change}
    with pytest.raises(adapter.Refused, match="operation_document_"):
        recovery.load_operation_document(document)
    assert recovery_boundary.events == []


def test_loader_preserves_bad_gold_and_source_pins_for_original_checks(recovery_boundary):
    for field, value, reason in [
        ("source_gold_sha256", "0" * 64, "source_gold_bytes_mismatch"),
        ("candidate_product_revision", "0" * 40, "candidate_product_mismatch"),
    ]:
        operation = recovery.load_operation_document(
            {**asdict(recovery_boundary.operation), field: value}
        )
        assert getattr(operation, field) == value
        with pytest.raises(adapter.Refused, match=reason):
            recovery_boundary.make(supplied_operation=operation)
    assert recovery_boundary.events == []


def test_unknown_operation_subclass_is_not_a_target_authority(recovery_boundary):
    class UnknownOperation(recovery.RecoveryOperation):
        pass

    with pytest.raises(adapter.Refused, match="operation_type_unknown"):
        recovery_boundary.make(
            supplied_operation=UnknownOperation(**asdict(recovery_boundary.operation))
        )
    assert recovery_boundary.events == []


def test_t_checkpoint_cannot_cross_target_or_fence(recovery_boundary):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    _control, state = recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    for expected in [recovery_boundary.operation, replace(operation, fence_generation=2)]:
        with pytest.raises(adapter.Refused, match="checkpoint_operation_mismatch"):
            recovery.require_checkpoint_operation(json.loads(adapter.canonical(state)), expected)
    with pytest.raises(adapter.Refused, match="checkpoint_operation_mismatch"):
        recovery.require_checkpoint_operation(
            {"operation": asdict(recovery_boundary.operation)}, operation
        )
    assert recovery_boundary.events == []


def test_explicit_t_requires_versioned_target_gold(recovery_boundary):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    gold = {**gold, "rollback_target": {**gold["rollback_target"]}}
    del gold["rollback_target"]["contract_version"]
    operation = replace(operation, source_gold_sha256=adapter.sha(adapter.canonical(gold)))
    with pytest.raises(adapter.Refused, match="explicit_t_target_gold_mismatch"):
        recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    assert recovery_boundary.events == []


@pytest.mark.parametrize("callback", ["before", "checkpoint"])
def test_explicit_t_has_no_missing_callback_default(recovery_boundary, callback):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    with pytest.raises(adapter.Refused, match="coordinator_callbacks_required"):
        recovery_boundary.make(
            supplied_operation=operation, supplied_gold=gold, **{callback: False}
        )
    assert recovery_boundary.events == []


def test_wrong_t_source_gold_stops_before_source_preflight(recovery_boundary, monkeypatch):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    gold = {**gold, "old_inventory_sha256": "0" * 64, "old_security_sha256": "0" * 64}
    operation = replace(operation, source_gold_sha256=adapter.sha(adapter.canonical(gold)))
    control, state = recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    monkeypatch.setattr(
        recovery, "replace", lambda *_args, **_kw: SimpleNamespace(service_role_graph=None)
    )
    with pytest.raises(adapter.Refused, match="explicit_t_old_source_gold_required"):
        control.inverse(json.loads(adapter.canonical(state)))
    assert recovery_boundary.events == []


@pytest.mark.parametrize("method", ["inverse", "reattach"])
def test_explicit_t_unknown_phase_stops_before_callbacks(recovery_boundary, method):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    control, state = recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    state["phase"] = "unknown"
    with pytest.raises(adapter.Refused, match=r"operation_required|inverse_state_required"):
        getattr(control, method)(json.loads(adapter.canonical(state)))
    assert recovery_boundary.events == []


def test_explicit_t_json_dispatches_only_to_t_then_mm(recovery_boundary, monkeypatch):
    """Real API/JSON phase wiring only; COPY and signed-stack require the PG drill."""
    operation, gold = _explicit_t_fixture(recovery_boundary)
    gold = {
        **gold,
        "old_role_edges": [],
        "candidate_role_edges": [],
        "old_access": {},
        "candidate_access": {},
    }
    operation = replace(operation, source_gold_sha256=adapter.sha(adapter.canonical(gold)))
    control, state = recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    facts = {"tables": {}, "builtin_pg_notify": {"raw_acl": None}}
    state.update(
        t_before=facts,
        p17_source_snapshot={},
        archive=adapter.archive_name(operation.operation_id),
    )
    migrations = []
    monkeypatch.setattr(control, "_t_source_gold", lambda: None)
    monkeypatch.setattr(control, "_t_old_catalog", lambda: None)
    monkeypatch.setattr(control, "_t_facts", lambda *_args, **_kwargs: facts)
    monkeypatch.setattr(control, "_capture", lambda *_args: {"tables": {}})
    monkeypatch.setattr(adapter, "move_receipts", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(adapter, "archive_catalog", lambda *_args: {})
    monkeypatch.setattr(native, "remove_sources", lambda *_args: None)
    monkeypatch.setattr(native, "reverse_additive_role_edges", lambda *_args: None)
    monkeypatch.setattr(native, "change_additive_access", lambda *_args: None)
    monkeypatch.setattr(native, "head", lambda *_args: "lm2t00000001")
    monkeypatch.setattr(
        recovery.runtime_native,
        "require_source_inverse_possible",
        lambda *_args, **_kwargs: pytest.fail("explicit T must not cross T's retained guard"),
    )
    monkeypatch.setattr(
        recovery,
        "_migrate",
        lambda engine, kind, revision, **kw: migrations.append(
            (kind, revision, kw.get("down", False))
        ),
    )
    control.engines = {"official_owner": object(), "saas_owner": object()}
    assert (
        control.inverse(json.loads(adapter.canonical(state)))["phase"]
        == "inverse_complete_old_signed_image_verification_required"
    )
    assert migrations == [("saas", "lm2t00000001", True), ("official", "mm1a2b3c4d5e", True)]


def test_t_gold_mutation_is_refused_before_callbacks(recovery_boundary):
    operation, gold = _explicit_t_fixture(recovery_boundary)
    control, state = recovery_boundary.make(supplied_operation=operation, supplied_gold=gold)
    gold["unexpected-change"] = "not a new source-gold authority"
    with pytest.raises(adapter.Refused, match="explicit_t_source_gold_binding_changed"):
        control.inverse(json.loads(adapter.canonical(state)))
    assert recovery_boundary.events == []
