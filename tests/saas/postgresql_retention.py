"""Assert a refused migration preserves retained rows and database authority."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory


def snapshot_nonempty_model_facts(connection: sa.Connection) -> dict[str, dict[str, int | str]]:
    """Fingerprint actual lifecycle facts without exporting stored row values."""
    result: dict[str, dict[str, int | str]] = {}
    quote = connection.dialect.identifier_preparer.quote
    for table in (
        "saas_model_provider_budget_reservations",
        "saas_model_gateway_evidence",
        "saas_usage_events",
        "saas_billing_metering_receipts",
        "saas_pricing_snapshots",
        "saas_model_publication_versions",
        "saas_model_run_tokens",
    ):
        relation = "public." + quote(table)
        count = connection.exec_driver_sql(f"SELECT count(*) FROM {relation}").scalar_one()
        assert 0 < count <= 64, (table, count)
        digest = hashlib.sha256()
        driver = connection.connection.driver_connection
        assert driver is not None
        with driver.cursor() as cursor:
            with cursor.copy(
                f"COPY (SELECT * FROM {relation} ORDER BY id) TO STDOUT (FORMAT BINARY)"
            ) as copy:
                for block in copy:
                    digest.update(block)
        result[table] = {
            "relation_oid": connection.exec_driver_sql(
                "SELECT %s::regclass::oid", (relation,)
            ).scalar_one(),
            "row_count": count,
            "binary_copy_sha256": digest.hexdigest(),
        }
    return result


def assert_owned_model_backup_restore(engine: sa.Engine, directory: Path) -> dict:
    """Physically restore an owned cluster without rewriting object authority."""
    import shlex
    import shutil

    from tests._helpers.live_server import reserve_port

    owner_root = Path(os.environ["OMNIGENT_SAAS_TEST_POSTGRES_OWNER_ROOT"])
    tools = Path(os.environ["OMNIGENT_SAAS_TEST_POSTGRES_TOOLS"])
    assert os.environ.get("OMNIGENT_SAAS_TEST_ALLOW_DISPOSABLE_RESTORE") == "true"
    assert engine.url.host == "127.0.0.1" and engine.url.query["sslmode"] == "verify-full"
    assert owner_root.is_absolute() and owner_root.resolve() == owner_root
    assert (owner_root / "data/postmaster.pid").is_file()
    directory.mkdir(mode=0o700)
    archive, restored_data = directory / "basebackup", directory / "restored-cluster"
    restored = None
    environment = {
        **os.environ,
        "PGPASSWORD": engine.url.password or "",
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": str(engine.url.query["sslrootcert"]),
    }

    def pg_tool(name, *arguments):
        result = subprocess.run(
            [str(tools / name), *arguments], env=environment, capture_output=True, timeout=180
        )
        (directory / (name + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0, (name, result.returncode)

    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            assert Path(connection.exec_driver_sql("SHOW data_directory").scalar_one()) == (
                owner_root / "data"
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
                ).scalar_one()
                is True
            )
            major = (
                int(connection.exec_driver_sql("SHOW server_version_num").scalar_one()) // 10000
            )
            assert (
                tools == Path("/Applications/Postgres.app/Contents/Versions") / str(major) / "bin"
            )
            source_details = {}
            original = _snapshot(connection, details=source_details)
            (directory / "source-snapshot.json").write_text(
                json.dumps(source_details, default=str, sort_keys=True)
            )
            facts = snapshot_nonempty_model_facts(connection)
            system_id = str(
                connection.exec_driver_sql(
                    "SELECT system_identifier FROM pg_control_system()"
                ).scalar_one()
            )
        pg_tool(
            "pg_basebackup",
            "--host=127.0.0.1",
            "--port=" + str(engine.url.port),
            "--username=" + str(engine.url.username),
            "--no-password",
            "--pgdata=" + str(archive),
            "--wal-method=stream",
            "--checkpoint=fast",
            "--manifest-checksums=SHA256",
        )
        assert not any(path.is_symlink() for path in archive.rglob("*"))
        pg_tool("pg_verifybackup", "--exit-on-error", "--quiet", str(archive))
        manifest = (archive / "backup_manifest").read_bytes()
        manifest_data = json.loads(manifest)
        assert manifest_data["Files"] and manifest_data["WAL-Ranges"]
        shutil.copytree(archive, restored_data)
        with reserve_port() as reservation:
            port = reservation.getsockname()[1]
            options = shlex.join(
                [
                    "-h",
                    "127.0.0.1",
                    "-p",
                    str(port),
                    "-k",
                    "",
                    "-c",
                    "ssl=on",
                    "-c",
                    "ssl_cert_file=" + str(owner_root / "server.crt"),
                    "-c",
                    "ssl_key_file=" + str(owner_root / "server.key"),
                    "-c",
                    "shared_buffers=64MB",
                ]
            )
            reservation.close()
            pg_tool(
                "pg_ctl",
                "-D",
                str(restored_data),
                "-l",
                str(directory / "restore.log"),
                "-o",
                options,
                "-w",
                "start",
            )
        restored = sa.create_engine(engine.url.set(port=port), hide_parameters=True)
        with restored.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            assert (
                Path(connection.exec_driver_sql("SHOW data_directory").scalar_one())
                == restored_data
            )
            assert (
                str(
                    connection.exec_driver_sql(
                        "SELECT system_identifier FROM pg_control_system()"
                    ).scalar_one()
                )
                == system_id
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
                ).scalar_one()
                is True
            )
            restored_details = {}
            recovered_snapshot = _snapshot(connection, details=restored_details)
            (directory / "restored-snapshot.json").write_text(
                json.dumps(restored_details, default=str, sort_keys=True)
            )
            assert recovered_snapshot == original
            assert snapshot_nonempty_model_facts(connection) == facts
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            assert _snapshot(connection) == original
        pg_tool("pg_verifybackup", "--exit-on-error", "--quiet", str(archive))
        assert (archive / "backup_manifest").read_bytes() == manifest
        return {
            "backup_kind": "physical_cluster_basebackup_with_streamed_WAL",
            "backup_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "backup_file_count": len(manifest_data["Files"]),
            "full_backup_verified_including_WAL_before_and_after": True,
            "complete_public_schema_rows_and_authority_sha256": original,
            "seven_nonempty_model_facts": facts,
            "original_cluster_roles_physically_restored": True,
            "original_relation_OIDs_owner_ACL_RLS_triggers_constraints_preserved": True,
            "distinct_target_cluster": True,
            "source_unchanged": True,
            "logical_restore_qualification": False,
        }
    finally:
        if restored is not None:
            restored.dispose()
        if (restored_data / "postmaster.pid").exists():
            pg_tool("pg_ctl", "-D", str(restored_data), "-m", "fast", "-w", "stop")


def _snapshot(connection: sa.Connection, *, details: dict | None = None) -> str:
    tables = connection.exec_driver_sql(
        "SELECT relname,relowner,relacl::text,relrowsecurity,relforcerowsecurity "
        "FROM pg_class WHERE relnamespace='public'::regnamespace "
        "AND relkind IN ('r','p') ORDER BY relname"
    ).all()
    quote = connection.dialect.identifier_preparer.quote
    rows = [
        (
            table[0],
            connection.exec_driver_sql(
                "SELECT md5(COALESCE(jsonb_agg(to_jsonb(retained_row) "
                "ORDER BY to_jsonb(retained_row))::text,'[]')) "
                f"FROM public.{quote(table[0])} retained_row"
            ).scalar_one(),
        )
        for table in tables
    ]
    catalogs = [
        connection.exec_driver_sql(query).all()
        for query in (
            "SELECT nspname,nspowner,nspacl::text FROM pg_namespace "
            "WHERE nspname='public' ORDER BY nspname",
            "SELECT attrelid::regclass::text,attnum,attname,atttypid::regtype::text,"
            "attnotnull,attacl::text,attisdropped,attidentity,attgenerated,"
            "pg_get_expr(adbin,adrelid) FROM pg_attribute "
            "JOIN pg_class ON pg_class.oid=attrelid "
            "LEFT JOIN pg_attrdef ON adrelid=attrelid AND adnum=attnum "
            "WHERE relnamespace='public'::regnamespace AND relkind IN ('r','p') "
            "AND attnum>0 ORDER BY attrelid::regclass::text,attnum",
            "SELECT relname,relowner,relacl::text FROM pg_class "
            "WHERE relnamespace='public'::regnamespace AND relkind='S' ORDER BY relname",
            "SELECT granted.rolname,member.rolname,grantor.rolname,"
            "membership.admin_option,membership.inherit_option,membership.set_option "
            "FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=roleid "
            "JOIN pg_roles member ON member.oid=membership.member "
            "JOIN pg_roles grantor ON grantor.oid=membership.grantor ORDER BY 1,2,3",
            "SELECT tablename,policyname,roles::text,cmd,qual,with_check FROM pg_policies "
            "WHERE schemaname='public' ORDER BY tablename,policyname",
            "SELECT oid::regprocedure::text,proowner,proacl::text,pg_get_functiondef(oid) "
            "FROM pg_proc WHERE pronamespace='public'::regnamespace AND prokind='f' "
            "ORDER BY oid::regprocedure::text",
            "SELECT conrelid::regclass::text,conname,pg_get_constraintdef(oid) "
            "FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1,2",
            "SELECT tgrelid::regclass::text,tgname,pg_get_triggerdef(oid),tgenabled "
            "FROM pg_trigger WHERE NOT tgisinternal "
            "AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace) "
            "ORDER BY 1,2",
        )
    ]
    payload = [[tuple(row) for row in tables], rows]
    payload.extend([[tuple(row) for row in catalog] for catalog in catalogs])
    if details is not None:
        details.update(
            zip(
                (
                    "relations",
                    "data_hashes",
                    "schemas",
                    "columns",
                    "sequences",
                    "role_graph",
                    "rls",
                    "functions",
                    "constraints",
                    "triggers",
                ),
                payload,
                strict=True,
            )
        )
    return hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()


def assert_retained_downgrade_refused(
    engine: sa.Engine,
    target: str,
    *,
    expected_pattern: str,
    guard_revision: str | None = None,
    blocking_guard_pattern: str | None = None,
) -> None:
    """Keep release refusal and explicit feature guards separate and non-destructive."""
    with engine.begin() as connection:
        before = _snapshot(connection)
        owner_policy = connection.scalar(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM pg_policy WHERE "
                "polrelid=to_regclass('public.saas_model_provider_budget_reservations') "
                "AND polname='rls_model_budget_owner_settlement')"
            )
        )
        retained_budgets = owner_policy and connection.scalar(
            sa.text("SELECT EXISTS(SELECT 1 FROM public.saas_model_provider_budget_reservations)")
        )
        config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
        config.attributes["connection"] = connection
        head = connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
        release_guard_pattern = (
            r"^P18 downgrade requires reviewed runtime-maintenance inverse; "
            r"never remove policy contracts implicitly$"
            if head == "p0s000000018"
            else blocking_guard_pattern
        )
        if release_guard_pattern is not None and guard_revision is not None:
            with (
                pytest.raises(RuntimeError, match=release_guard_pattern),
                connection.begin_nested(),
            ):
                command.downgrade(config, target)
            assert _snapshot(connection) == before
            scripts = ScriptDirectory.from_config(config)
            path = {step.revision for step in scripts.iterate_revisions(head, target)}
            guards = [(guard_revision, expected_pattern)]
            if retained_budgets:
                guards.insert(
                    0,
                    (
                        "lm2t00000001",
                        r"^retained model budgets require owner settlement policy$",
                    ),
                )
            # Component probes roll back every change without crossing the release barrier.
            for revision, pattern in guards:
                assert revision in path
                script = scripts.get_revision(revision)
                assert script is not None
                with (
                    pytest.raises(RuntimeError, match=pattern),
                    connection.begin_nested(),
                    Operations.context(MigrationContext.configure(connection)),
                ):
                    script.module.downgrade()
                assert _snapshot(connection) == before
            return
        if retained_budgets:
            expected_pattern = r"^retained model budgets require owner settlement policy$"
        with pytest.raises(RuntimeError, match=expected_pattern), connection.begin_nested():
            command.downgrade(config, target)
        assert _snapshot(connection) == before
