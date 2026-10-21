"""Coordinator failures must prevent the next destructive recovery operation.

Database identity/catalog/row preservation has a separate real PostgreSQL replay;
these unit cases exercise the public API's effect ordering with no database I/O.
"""

from __future__ import annotations

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
    assert recovery_boundary.events == ["prepare_archive"]


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
    assert recovery_boundary.events == ["archive", "archive_prepared"]


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
