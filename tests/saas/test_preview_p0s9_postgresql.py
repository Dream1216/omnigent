from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from omnigent.runner.identity import token_bound_runner_id


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


def _set_local(connection: sa.Connection, setting: str, value: str) -> None:
    connection.execute(
        sa.text("SELECT set_config(:setting, :value, true)"),
        {"setting": setting, "value": value},
    )


def _seed_ready_preview(connection: sa.Connection) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    identifiers: dict[str, Any] = {
        "execution_id": uuid4(),
        "tenant_id": uuid4(),
        "space_id": uuid4(),
        "project_id": uuid4(),
        "other_project_id": uuid4(),
        "actor_id": uuid4(),
        "other_actor_id": uuid4(),
        "source_run_id": uuid4(),
        "child_run_id": uuid4(),
        "changeset_id": uuid4(),
        "worktree_id": uuid4(),
        "runner_id": uuid4(),
        "placement_id": uuid4(),
        "pool_id": uuid4(),
        "tunnel_placement_id": uuid4(),
        "gateway_id": "preview-owner-a",
        "gateway_token": "7" * 64,
        "exchange_hash": "1" * 64,
        "now": now,
        "expires_at": now + timedelta(hours=1),
    }
    # This acceptance test isolates the P0S9 RLS/functions, so pre-P0S9 parent
    # rows are represented by UUIDs while PostgreSQL trigger-based FKs are
    # suspended only for fixture setup. CHECK constraints remain enforced.
    connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
    connection.execute(
        sa.text(
            "INSERT INTO saas_runtime_placements ("
            "id, runtime_type, data_region, failure_domain, database_cluster_ref, "
            "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
            "status, created_at, updated_at) VALUES ("
            ":placement_id, 'omnigent', 'cn-east-1', 'zone-a', 'database-a', "
            "'objects-a', 'kms-a', 'p0s000000009', 'preview', 'active', :now, :now)"
        ),
        identifiers,
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_preview_gateway_instances ("
            "id, connect_host, connect_port, server_name, failure_domain, "
            "source_revision, adapter_contract_version, registration_token_hash, "
            "status, registered_at, activated_at, last_heartbeat_at, lease_expires_at, "
            "created_at, updated_at) VALUES ("
            ":gateway_id, 'preview-owner.omnigent.svc.cluster.local', 9443, "
            "'preview-owner.omnigent.svc.cluster.local', 'zone-a', :revision, 'v1', "
            ":gateway_token, 'active', :now, :now, :now, :expires_at, :now, :now)"
        ),
        {**identifiers, "revision": "a" * 64},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_runner_registrations ("
            "id, pool_id, placement_id, instance_key, failure_domain, status, "
            "connection_generation, connection_token_hash, protocol_version, "
            "source_revision, schema_revision, adapter_contract_version, capabilities, "
            "capabilities_hash, max_concurrency, active_leases, last_heartbeat_at, "
            "registered_at, updated_at) VALUES ("
            ":runner_id, :pool_id, :placement_id, 'runner-a', 'zone-a', 'online', 4, "
            ":runner_token, 1, :revision, 'p0s000000009', 'v1', "
            "CAST('[\"preview.static_web_v1\"]' AS json), :capabilities_hash, "
            "4, 1, :now, :now, :now)"
        ),
        {
            **identifiers,
            "runner_token": "2" * 64,
            "revision": "a" * 64,
            "capabilities_hash": "3" * 64,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_runner_tunnel_placements ("
            "id, runner_id, runner_connection_generation, routing_generation, "
            "gateway_instance_id, relay_subject, ownership_token_hash, status, "
            "claimed_at, last_heartbeat_at, lease_expires_at, created_at, updated_at) "
            "VALUES (:tunnel_placement_id, :runner_id, 4, 1, :gateway_id, "
            "'runner-a-generation-4', :ownership_hash, 'active', :now, :now, "
            ":expires_at, :now, :now)"
        ),
        {**identifiers, "ownership_hash": "4" * 64},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_preview_executions ("
            "id, tenant_id, space_id, project_id, source_run_id, child_run_id, "
            "change_set_id, created_by, profile, idempotency_key_hash, request_hash, "
            "opaque_preview_key, preview_host, status, command_generation, runner_id, "
            "placement_id, worktree_id, run_fence_token, runner_connection_generation, "
            "worktree_lease_generation, exchange_token_hash, exchange_issued_at, "
            "expires_at, ready_at, version, created_at, updated_at) VALUES ("
            ":execution_id, :tenant_id, :space_id, :project_id, :source_run_id, "
            ":child_run_id, :changeset_id, :actor_id, 'static_web_v1', :idem_hash, "
            ":request_hash, 'opaque-preview-a', 'preview-a.example.test', 'ready', 1, "
            ":runner_id, :placement_id, :worktree_id, 9, 4, 2, :exchange_hash, :now, "
            ":expires_at, :now, 1, :now, :now)"
        ),
        {**identifiers, "idem_hash": "5" * 64, "request_hash": "6" * 64},
    )
    connection.exec_driver_sql("SET LOCAL session_replication_role = origin")
    return identifiers


def _exchange(
    engine: sa.Engine,
    *,
    exchange_hash: str,
    session_id: UUID,
    session_hash: str,
    now: datetime,
    expires_at: datetime,
) -> sa.RowMapping | None:
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_edge")
        return (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_exchange_v1("
                    ":exchange_hash, :session_id, :session_hash, :expires_at, :now)"
                ),
                {
                    "exchange_hash": exchange_hash,
                    "session_id": session_id,
                    "session_hash": session_hash,
                    "expires_at": expires_at,
                    "now": now,
                },
            )
            .mappings()
            .one_or_none()
        )


def test_preview_exchange_is_single_consumer_and_session_rotation_is_independent(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)

    first_hash, second_hash = "8" * 64, "9" * 64
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                _exchange,
                engine,
                exchange_hash=str(facts["exchange_hash"]),
                session_id=uuid4(),
                session_hash=session_hash,
                now=facts["now"],
                expires_at=facts["expires_at"],
            )
            for session_hash in (first_hash, second_hash)
        ]
        results = [future.result(timeout=10) for future in futures]

    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    winner = winners[0]
    assert winner["preview_execution_id"] == facts["execution_id"]
    assert winner["tenant_id"] == facts["tenant_id"]
    assert winner["space_id"] == facts["space_id"]
    assert winner["project_id"] == facts["project_id"]
    assert winner["opaque_preview_key"] == "opaque-preview-a"
    assert winner["preview_host"] == "preview-a.example.test"
    assert winner["runner_connection_generation"] == 4
    assert winner["gateway_instance_id"] == facts["gateway_id"]
    assert winner["relay_subject"] == "runner-a-generation-4"
    active_hash = first_hash if results[0] is not None else second_hash
    replay = _exchange(
        engine,
        exchange_hash=str(facts["exchange_hash"]),
        session_id=uuid4(),
        session_hash="a" * 64,
        now=facts["now"],
        expires_at=facts["expires_at"],
    )
    assert replay is None

    # The standalone relay Owner has only the same content-blind authorize
    # function as Edge.  It can rebuild an active route but cannot read the
    # session or execution tables directly.
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        owner_route = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": active_hash, "now": facts["now"]},
            )
            .mappings()
            .one()
        )
        assert owner_route["preview_execution_id"] == facts["execution_id"]
    with pytest.raises(sa.exc.ProgrammingError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
            connection.exec_driver_sql("SELECT * FROM saas_preview_sessions")

    rotated_hash = "b" * 64
    operation_start = facts["now"]
    assert isinstance(operation_start, datetime)
    rotation_at = operation_start + timedelta(minutes=6)
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_edge")
        authorized = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": active_hash, "now": facts["now"]},
            )
            .mappings()
            .one()
        )
        assert authorized["session_generation"] == 1
        rotated = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_rotate_session_v1("
                    ":old_hash, :new_hash, 'preview-a.example.test', :expires_at, :now)"
                ),
                {
                    "old_hash": active_hash,
                    "new_hash": rotated_hash,
                    "expires_at": facts["expires_at"],
                    "now": rotation_at,
                },
            )
            .mappings()
            .one()
        )
        assert rotated["session_generation"] == 2
        assert rotated["rotated"] is True
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": active_hash, "now": rotation_at + timedelta(seconds=1)},
            )
            .mappings()
            .one()["session_generation"]
            == 2
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": active_hash, "now": rotation_at + timedelta(seconds=31)},
            ).one_or_none()
            is None
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'forged.example.test', :now)"
                ),
                {"token_hash": rotated_hash, "now": rotation_at},
            ).one_or_none()
            is None
        )
        assert (
            connection.scalar(
                sa.text("SELECT public.saas_preview_revoke_session_v1(:token_hash, :now)"),
                {"token_hash": rotated_hash, "now": rotation_at},
            )
            is True
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": rotated_hash, "now": rotation_at},
            ).one_or_none()
            is None
        )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": rotated_hash, "now": rotation_at},
            ).one_or_none()
            is None
        )
    engine.dispose()


def test_preview_rls_blocks_cross_actor_raw_edge_dml_and_stale_runner_generation(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_app")
        for setting in ("tenant_id", "space_id", "project_id", "actor_id"):
            _set_local(connection, f"app.{setting}", str(facts[setting]))
        assert (
            connection.scalar(
                sa.text("SELECT id FROM saas_preview_executions WHERE id = :id"),
                {"id": facts["execution_id"]},
            )
            == facts["execution_id"]
        )
        _set_local(connection, "app.actor_id", str(facts["other_actor_id"]))
        assert (
            connection.scalar(
                sa.text("SELECT id FROM saas_preview_executions WHERE id = :id"),
                {"id": facts["execution_id"]},
            )
            is None
        )
        _set_local(connection, "app.actor_id", str(facts["actor_id"]))
        _set_local(connection, "app.project_id", str(facts["other_project_id"]))
        assert (
            connection.scalar(
                sa.text("SELECT id FROM saas_preview_executions WHERE id = :id"),
                {"id": facts["execution_id"]},
            )
            is None
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        _set_local(connection, "app.preview_gateway_instance_id", str(facts["gateway_id"]))
        _set_local(
            connection,
            "app.preview_gateway_registration_token_hash",
            str(facts["gateway_token"]),
        )
        assert (
            connection.scalar(
                sa.text("SELECT id FROM saas_preview_executions WHERE id = :id"),
                {"id": facts["execution_id"]},
            )
            == facts["execution_id"]
        )
        _set_local(connection, "app.preview_gateway_instance_id", "preview-owner-b")
        assert (
            connection.scalar(
                sa.text("SELECT id FROM saas_preview_executions WHERE id = :id"),
                {"id": facts["execution_id"]},
            )
            is None
        )

    with pytest.raises(sa.exc.ProgrammingError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_edge")
            connection.exec_driver_sql("SELECT * FROM saas_preview_sessions")
    with pytest.raises(sa.exc.ProgrammingError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_edge")
            connection.exec_driver_sql("UPDATE saas_preview_executions SET status = 'revoked'")

    session_hash = "c" * 64
    assert (
        _exchange(
            engine,
            exchange_hash=str(facts["exchange_hash"]),
            session_id=uuid4(),
            session_hash=session_hash,
            now=facts["now"],
            expires_at=facts["expires_at"],
        )
        is not None
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "UPDATE saas_runner_registrations SET connection_generation = 5 "
                "WHERE id = :runner_id"
            ),
            {"runner_id": facts["runner_id"]},
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_edge")
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_authorize_session_v1("
                    ":token_hash, 'preview-a.example.test', :now)"
                ),
                {"token_hash": session_hash, "now": facts["now"]},
            ).one_or_none()
            is None
        )
    engine.dispose()


def test_preview_app_narrow_functions_bind_actor_and_command_fields(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "UPDATE saas_preview_executions SET exchange_token_hash = NULL, "
                "exchange_issued_at = NULL WHERE id = :execution_id"
            ),
            {"execution_id": facts["execution_id"]},
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")

    issued_hash = "d" * 64
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_app")
        for setting in ("tenant_id", "space_id", "project_id", "actor_id"):
            _set_local(connection, f"app.{setting}", str(facts[setting]))
        issued = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_issue_exchange_v1("
                    ":execution_id, :token_hash, :now)"
                ),
                {
                    "execution_id": facts["execution_id"],
                    "token_hash": issued_hash,
                    "now": facts["now"],
                },
            )
            .mappings()
            .one()
        )
        assert issued["preview_execution_id"] == facts["execution_id"]
        assert issued["preview_host"] == "preview-a.example.test"
        assert issued["replayed"] is False
        replay = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_issue_exchange_v1("
                    ":execution_id, :token_hash, :now)"
                ),
                {
                    "execution_id": facts["execution_id"],
                    "token_hash": issued_hash,
                    "now": facts["now"],
                },
            )
            .mappings()
            .one()
        )
        assert replay["replayed"] is True
        _set_local(connection, "app.actor_id", str(facts["other_actor_id"]))
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_issue_exchange_v1("
                    ":execution_id, :token_hash, :now)"
                ),
                {
                    "execution_id": facts["execution_id"],
                    "token_hash": issued_hash,
                    "now": facts["now"],
                },
            ).one_or_none()
            is None
        )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "UPDATE saas_preview_executions SET status = 'queued', "
                "command_generation = 0, exchange_token_hash = NULL, "
                "exchange_issued_at = NULL, ready_at = NULL "
                "WHERE id = :execution_id"
            ),
            {"execution_id": facts["execution_id"]},
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")
    command_id = uuid4()
    request_hash = "e" * 64
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_app")
        for setting in ("tenant_id", "space_id", "project_id", "actor_id"):
            _set_local(connection, f"app.{setting}", str(facts[setting]))
        created = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_create_command_v1("
                    ":execution_id, :command_id, 'start', :request_hash, :now)"
                ),
                {
                    "execution_id": facts["execution_id"],
                    "command_id": command_id,
                    "request_hash": request_hash,
                    "now": facts["now"],
                },
            )
            .mappings()
            .one()
        )
        assert created["command_id"] == command_id
        assert created["command_generation"] == 1
        assert created["replayed"] is False
        replay = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_create_command_v1("
                    ":execution_id, :other_command_id, 'start', :request_hash, :now)"
                ),
                {
                    "execution_id": facts["execution_id"],
                    "other_command_id": uuid4(),
                    "request_hash": request_hash,
                    "now": facts["now"],
                },
            )
            .mappings()
            .one()
        )
        assert replay["command_id"] == command_id
        assert replay["replayed"] is True
    with pytest.raises(sa.exc.ProgrammingError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_app")
            connection.exec_driver_sql(
                "INSERT INTO saas_preview_commands (id) VALUES (gen_random_uuid())"
            )
    engine.dispose()


def test_preview_tunnel_registration_is_one_use_generation_and_owner_bound(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    official_runner_id = "runner_preview_token_bound_1"
    registration_hash = "f" * 64
    fingerprint = "a" * 64
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_certificates ("
                "id, runner_id, runner_connection_generation, purpose, "
                "fingerprint_sha256, spki_sha256, serial_hex, spiffe_id, "
                "trust_bundle_version, rotation_generation, certificate_not_before, "
                "certificate_not_after, status, activated_at, created_at, updated_at) "
                "VALUES (:id, :runner_id, 4, 'runner_control', :fingerprint, :spki, "
                "'01', :spiffe, 'bundle-v1', 1, :not_before, :not_after, 'active', "
                ":now, :now, :now)"
            ),
            {
                **facts,
                "id": uuid4(),
                "fingerprint": fingerprint,
                "spki": "b" * 64,
                "spiffe": f"spiffe://omnigent/runner/{facts['runner_id']}",
                "not_before": facts["now"] - timedelta(minutes=1),
                "not_after": facts["expires_at"],
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_preview_tunnel_registrations ("
                "id, runner_id, placement_id, connection_generation, "
                "gateway_instance_id, certificate_fingerprint_sha256, audience, "
                "jti_hash, token_hash, official_runner_id, status, expires_at, "
                "created_at, updated_at) VALUES ("
                ":id, :runner_id, :placement_id, 4, :gateway_id, :fingerprint, "
                "'preview-owner.example.test', :jti_hash, :token_hash, "
                ":official_runner_id, 'issued', :expires_at, :now, :now)"
            ),
            {
                **facts,
                "id": uuid4(),
                "fingerprint": fingerprint,
                "jti_hash": "c" * 64,
                "token_hash": registration_hash,
                "official_runner_id": official_runner_id,
            },
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")

    new_placement_id = uuid4()
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        authorized = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_preauthorize_tunnel_v1("
                    ":registration_hash, :official_runner_id, :gateway_id, "
                    ":gateway_token, :now)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                },
            )
            .mappings()
            .one()
        )
        assert authorized["runner_id"] == facts["runner_id"]
        assert authorized["connection_generation"] == 4
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_preauthorize_tunnel_v1("
                    ":registration_hash, :official_runner_id, 'wrong-owner', "
                    ":gateway_token, :now)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                },
            ).one_or_none()
            is None
        )
        redeemed = (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_redeem_tunnel_v1("
                    ":registration_hash, :official_runner_id, :gateway_id, "
                    ":gateway_token, :new_placement_id, :ownership_hash, :now)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                    "new_placement_id": new_placement_id,
                    "ownership_hash": "d" * 64,
                },
            )
            .mappings()
            .one()
        )
        assert redeemed["tunnel_placement_id"] == new_placement_id
        assert redeemed["runner_id"] == facts["runner_id"]
        assert (
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_preview_redeem_tunnel_v1("
                    ":registration_hash, :official_runner_id, :gateway_id, "
                    ":gateway_token, :other_placement_id, :ownership_hash, :now)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                    "other_placement_id": uuid4(),
                    "ownership_hash": "e" * 64,
                },
            ).one_or_none()
            is None
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_heartbeat_tunnel_v1("
                    ":registration_hash, :official_runner_id, :gateway_id, "
                    ":gateway_token, :heartbeat_at)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                    "heartbeat_at": facts["now"] + timedelta(seconds=1),
                },
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_disconnect_tunnel_v1("
                    ":registration_hash, :official_runner_id, :gateway_id, "
                    ":gateway_token, :disconnected_at)"
                ),
                {
                    **facts,
                    "registration_hash": registration_hash,
                    "official_runner_id": official_runner_id,
                    "disconnected_at": facts["now"] + timedelta(seconds=2),
                },
            )
            is True
        )
    with engine.begin() as connection:
        assert (
            connection.scalar(
                sa.text(
                    "SELECT status FROM saas_runner_tunnel_placements WHERE id = :placement_id"
                ),
                {"placement_id": new_placement_id},
            )
            == "released"
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT status FROM saas_preview_tunnel_registrations "
                    "WHERE token_hash = :token_hash"
                ),
                {"token_hash": registration_hash},
            )
            == "disconnected"
        )
    engine.dispose()


def test_preview_owner_gateway_lease_is_token_cas_and_raw_dml_is_denied(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "UPDATE saas_preview_gateway_instances "
                "SET lease_expires_at = registered_at + INTERVAL '5 seconds' "
                "WHERE id = :gateway_id"
            ),
            facts,
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_owner_heartbeat_gateway_v1("
                    ":gateway_id, :gateway_token)"
                ),
                facts,
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_owner_heartbeat_gateway_v1("
                    ":gateway_id, :wrong_token)"
                ),
                {**facts, "wrong_token": "8" * 64},
            )
            is False
        )

    with engine.begin() as connection:
        remaining = connection.scalar(
            sa.text(
                "SELECT lease_expires_at - CURRENT_TIMESTAMP "
                "FROM saas_preview_gateway_instances WHERE id = :gateway_id"
            ),
            facts,
        )
        assert remaining is not None
        assert remaining > timedelta(seconds=40)

    with pytest.raises(sa.exc.ProgrammingError):
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances SET status = 'released' "
                    "WHERE id = :gateway_id"
                ),
                facts,
            )

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_preview_owner")
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_owner_release_gateway_v1("
                    ":gateway_id, :gateway_token)"
                ),
                facts,
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT public.saas_preview_owner_release_gateway_v1("
                    ":gateway_id, :gateway_token)"
                ),
                facts,
            )
            is False
        )

    with engine.begin() as connection:
        row = connection.execute(
            sa.text(
                "SELECT status, release_reason FROM saas_preview_gateway_instances "
                "WHERE id = :gateway_id"
            ),
            facts,
        ).one()
        assert row == ("released", "preview_owner_shutdown")
    engine.dispose()


def test_preview_executor_registration_is_narrow_and_runner_incarnation_bound(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    runner_a_connection = "runner-a-connection-" + "a" * 48
    runner_b_connection = "runner-b-connection-" + "b" * 48
    runner_a_certificate = "a" * 64
    runner_b_certificate = "b" * 64
    runner_b_id = uuid4()
    registration_a = uuid4()
    registration_b = uuid4()
    registration_a_token = "registration-a-" + "c" * 48
    registration_b_token = "registration-b-" + "d" * 48
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        facts = _seed_ready_preview(connection)
        connection.exec_driver_sql("SET LOCAL session_replication_role = replica")
        connection.execute(
            sa.text(
                "UPDATE saas_runner_registrations SET connection_token_hash = :token "
                "WHERE id = :runner_id"
            ),
            {
                **facts,
                "token": hashlib.sha256(runner_a_connection.encode("ascii")).hexdigest(),
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_registrations ("
                "id, pool_id, placement_id, instance_key, failure_domain, status, "
                "connection_generation, connection_token_hash, protocol_version, "
                "source_revision, schema_revision, adapter_contract_version, "
                "capabilities, capabilities_hash, max_concurrency, active_leases, "
                "last_heartbeat_at, registered_at, updated_at) VALUES ("
                ":runner_b_id, :pool_id, :placement_id, 'runner-b', 'zone-a', "
                "'online', 9, :token, 1, :revision, 'p0s000000009', 'v1', "
                "CAST('[\"preview.static_web_v1\"]' AS json), :capabilities_hash, "
                "4, 0, :now, :now, :now)"
            ),
            {
                **facts,
                "runner_b_id": runner_b_id,
                "token": hashlib.sha256(runner_b_connection.encode("ascii")).hexdigest(),
                "revision": "a" * 64,
                "capabilities_hash": "9" * 64,
            },
        )
        for runner_id, generation, fingerprint, spki in (
            (facts["runner_id"], 4, runner_a_certificate, "c" * 64),
            (runner_b_id, 9, runner_b_certificate, "d" * 64),
        ):
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_certificates ("
                    "id, runner_id, runner_connection_generation, purpose, "
                    "fingerprint_sha256, spki_sha256, serial_hex, spiffe_id, "
                    "trust_bundle_version, rotation_generation, certificate_not_before, "
                    "certificate_not_after, status, activated_at, created_at, updated_at) "
                    "VALUES (:id, :runner_id, :generation, 'runner_control', "
                    ":fingerprint, :spki, :serial, :spiffe, 'bundle-v1', 1, "
                    ":not_before, :not_after, 'active', :now, :now, :now)"
                ),
                {
                    **facts,
                    "id": uuid4(),
                    "runner_id": runner_id,
                    "generation": generation,
                    "fingerprint": fingerprint,
                    "spki": spki,
                    "serial": f"{generation:02x}",
                    "spiffe": f"spiffe://omnigent/runner/{runner_id}",
                    "not_before": facts["now"] - timedelta(minutes=1),
                    "not_after": facts["expires_at"],
                },
            )
        connection.exec_driver_sql("SET LOCAL session_replication_role = origin")

    def issue(
        *,
        runner_id: UUID,
        generation: int,
        connection_token: str,
        fingerprint: str,
        registration_id: UUID,
        registration_token: str,
    ) -> sa.RowMapping | None:
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_executor")
            return (
                connection.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_issue_tunnel_registration_v1("
                        ":runner_id, :generation, :connection_hash, :fingerprint, "
                        ":registration_id, :jti_hash, :token_hash, "
                        ":official_runner_id, 60)"
                    ),
                    {
                        "runner_id": runner_id,
                        "generation": generation,
                        "connection_hash": hashlib.sha256(
                            connection_token.encode("ascii")
                        ).hexdigest(),
                        "fingerprint": fingerprint,
                        "registration_id": registration_id,
                        "jti_hash": hashlib.sha256(registration_id.bytes).hexdigest(),
                        "token_hash": hashlib.sha256(
                            registration_token.encode("ascii")
                        ).hexdigest(),
                        "official_runner_id": token_bound_runner_id(registration_token),
                    },
                )
                .mappings()
                .one_or_none()
            )

    issued_a = issue(
        runner_id=facts["runner_id"],
        generation=4,
        connection_token=runner_a_connection,
        fingerprint=runner_a_certificate,
        registration_id=registration_a,
        registration_token=registration_a_token,
    )
    assert issued_a is not None
    assert issued_a["runner_id"] == facts["runner_id"]
    assert issued_a["gateway_instance_id"] == facts["gateway_id"]

    assert (
        issue(
            runner_id=runner_b_id,
            generation=9,
            connection_token=runner_a_connection,
            fingerprint=runner_a_certificate,
            registration_id=uuid4(),
            registration_token="forged-registration-" + "x" * 48,
        )
        is None
    )

    issued_b = issue(
        runner_id=runner_b_id,
        generation=9,
        connection_token=runner_b_connection,
        fingerprint=runner_b_certificate,
        registration_id=registration_b,
        registration_token=registration_b_token,
    )
    assert issued_b is not None

    for statement in (
        "SELECT * FROM saas_preview_tunnel_registrations",
        "INSERT INTO saas_preview_tunnel_registrations (id) VALUES "
        "('00000000-0000-4000-8000-000000000001')",
        "UPDATE saas_preview_tunnel_registrations SET status = 'revoked'",
        "DELETE FROM saas_preview_tunnel_registrations",
    ):
        with pytest.raises(sa.exc.ProgrammingError):
            with engine.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_executor")
                connection.exec_driver_sql(statement)

    revoke_sql = sa.text(
        "SELECT public.saas_preview_revoke_tunnel_registration_v1("
        ":runner_id, :generation, :connection_hash, :fingerprint, "
        ":registration_id, :token_hash)"
    )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_executor")
        assert (
            connection.scalar(
                revoke_sql,
                {
                    "runner_id": facts["runner_id"],
                    "generation": 4,
                    "connection_hash": hashlib.sha256(
                        runner_a_connection.encode("ascii")
                    ).hexdigest(),
                    "fingerprint": runner_a_certificate,
                    "registration_id": registration_b,
                    "token_hash": hashlib.sha256(registration_b_token.encode("ascii")).hexdigest(),
                },
            )
            is False
        )
    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_executor")
        legal_parameters = {
            "runner_id": runner_b_id,
            "generation": 9,
            "connection_hash": hashlib.sha256(runner_b_connection.encode("ascii")).hexdigest(),
            "fingerprint": runner_b_certificate,
            "registration_id": registration_b,
            "token_hash": hashlib.sha256(registration_b_token.encode("ascii")).hexdigest(),
        }
        assert connection.scalar(revoke_sql, legal_parameters) is True
        assert connection.scalar(revoke_sql, legal_parameters) is False

    with engine.begin() as connection:
        rows = connection.execute(
            sa.text(
                "SELECT id, runner_id, status FROM saas_preview_tunnel_registrations ORDER BY id"
            )
        ).all()
        assert {row[0]: (row[1], row[2]) for row in rows} == {
            registration_a: (facts["runner_id"], "issued"),
            registration_b: (runner_b_id, "revoked"),
        }
    engine.dispose()
