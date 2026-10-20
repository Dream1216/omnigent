"""Opt-in source-level P0 application/R schema handoff on a disposable cluster."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import sqlalchemy as sa

from saas.production import postgresql_migration as migration
from saas.production.service_bindings import (
    EXPECTED_MODEL_PROJECTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    render_production_service_role_bindings,
)
from tests.saas.test_production_migration_replay import (
    _startup_config,
)
from tests.saas.test_production_migration_replay import (
    production_replay as production_replay,
)

_P0 = "p0s000000015"
_R = "lm2r00000001"


def _producer_source():
    value = os.environ.get("OMNIGENT_SAAS_R_SCHEMA_SOURCE_REPO")
    revision = os.environ.get("OMNIGENT_SAAS_R_SCHEMA_SOURCE_SHA")
    if not value or not revision:
        pytest.skip("requires an exact R schema producer source checkout")
    root = Path(value)
    assert root.is_absolute() and root.is_dir()
    observed = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert len(revision) == 40 and observed == revision
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=root)
    return root, revision


def _produce_schema():
    from saas.production.service_bindings import (
        load_model_projection_service_role_bindings,
        load_platform_admin_service_role_bindings,
        load_platform_model_service_role_bindings,
        load_production_service_role_bindings,
    )

    document = json.load(sys.stdin)
    root = Path(document["source_root"])
    revision = document["source_revision"]
    assert Path(migration.__file__).resolve().is_relative_to(root)
    assert (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        == revision
    )
    assert migration._expected_head("saas") == _R
    urls = document["urls"]
    for value in urls.values():
        url = sa.make_url(value)
        assert url.host in {"127.0.0.1", "localhost"} and url.port
        assert url.database == "admission_replay"
        assert isinstance(url.username, str) and url.username.startswith("replay_")
        assert url.query.get("sslmode") == "verify-full"
    source = document["bindings"]
    # Source tests substitute build identity; signed binary admission remains separate.
    migration._installed_product_revision = lambda: revision
    plan = migration.ProductionPostgreSqlPlan.from_urls(
        product_revision=revision,
        **urls,
        service_role_bindings=load_production_service_role_bindings(source),
        platform_model_service_role_bindings=load_platform_model_service_role_bindings(source),
        platform_admin_service_role_bindings=load_platform_admin_service_role_bindings(source),
        model_projection_service_role_bindings=load_model_projection_service_role_bindings(source),
    )
    receipt = migration.run_production_postgresql_migration(plan)
    print(json.dumps(receipt.to_dict()))


def _upgrade_runner_schema_if_requested(engine, *, schema_owner: str) -> str:
    requested = os.environ.get("OMNIGENT_SAAS_RUNNER_SCHEMA_REPLAY")
    if requested in {None, "p0"}:
        return _P0
    assert requested == "r"
    root, revision = _producer_source()
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR") if key in os.environ}
    environment.update(PYTHONPATH=str(root), OMNIGENT_SKIP_WEB_UI="true")
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--produce-runner"],
        cwd=root,
        env=environment,
        input=json.dumps(
            {
                "source_root": str(root),
                "source_revision": revision,
                "database_url": engine.url.render_as_string(hide_password=False),
                "schema_owner": schema_owner,
            }
        ),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, "R Runner fixture migration failed in the source subprocess"
    assert json.loads(result.stdout) == {"saas_head": _R, "source_revision": revision}
    return _R


def _produce_runner_schema() -> None:
    from tests.saas.test_scheduling_postgresql import _migrate

    document = json.load(sys.stdin)
    root = Path(document["source_root"])
    revision = document["source_revision"]
    assert Path(migration.__file__).resolve().is_relative_to(root)
    assert (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        == revision
    )
    assert migration._expected_head("saas") == _R
    url = sa.make_url(document["database_url"])
    assert url.host in {"127.0.0.1", "localhost"} and url.port and url.username == "postgres"
    assert isinstance(url.database, str) and re.fullmatch(
        r"omnigent_isolated_[0-9a-f]{32}", url.database
    )
    assert url.query.get("sslmode") == "verify-full"
    owner = document["schema_owner"]
    assert re.fullmatch(r"saas_test_fleet_owner_[0-9a-f]{12}", owner)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_principals.sql").read_text()
            )
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == _R
            )
    finally:
        engine.dispose()
    print(json.dumps({"saas_head": _R, "source_revision": revision}))


def test_p0_source_reissues_its_own_receipt_and_verifies_r_through_narrow_logins(
    production_replay, tmp_path
):
    root, revision = _producer_source()
    assert migration._expected_head("saas") == _P0
    plan = production_replay
    initial = migration.run_production_postgresql_migration(plan)
    assert initial.saas_head == _P0
    known = {row.service: row for row in plan.service_role_graph.bindings}
    rows = tuple(
        known[service]
        if service in known
        else ProductionServiceRoleBinding(
            service=service, login="replay_model_projection", base_role=role
        )
        for service, role in sorted(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES.items())
    )
    path = tmp_path / "projection-bindings.json"
    path.write_text(render_production_service_role_bindings(rows))
    path.chmod(0o400)
    profile = ProductionServiceRoleBindings(
        path, hashlib.sha256(path.read_bytes()).hexdigest(), rows
    )
    admin = sa.create_engine(
        sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
            query=plan.saas_owner.url.query
        ),
        isolation_level="AUTOCOMMIT",
    )
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(
                "CREATE ROLE replay_model_projection LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'production-replay-test'"
            )
    finally:
        admin.dispose()
    plan = replace(plan, model_projection_service_role_bindings=profile)
    assert len(plan.service_role_graph.bindings) == 19
    source = {}
    for prefix, binding in (
        ("OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS", plan.service_role_bindings),
        (
            "OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS",
            plan.platform_model_service_role_bindings,
        ),
        (
            "OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS",
            plan.platform_admin_service_role_bindings,
        ),
        ("OMNIGENT_SAAS_MODEL_PROJECTION_SERVICE_ROLE_BINDINGS", profile),
    ):
        assert binding is not None
        source[prefix + "_FILE"] = str(binding.path)
        source[prefix + "_SHA256"] = binding.sha256
    document = {
        "source_root": str(root),
        "source_revision": revision,
        "bindings": source,
        "urls": {
            authority.kind + "_url": authority.url.render_as_string(hide_password=False)
            for authority in plan.authorities()
        },
    }
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR") if key in os.environ}
    environment["PYTHONPATH"] = str(root)
    environment["OMNIGENT_SKIP_WEB_UI"] = "true"
    produced = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--produce"],
        cwd=root,
        env=environment,
        input=json.dumps(document),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert produced.returncode == 0, produced.stderr[-2000:]
    receipt_document = json.loads(produced.stdout)
    producer_receipt = migration.PostgreSqlMigrationReceipt(
        schema_version=receipt_document["schema_version"],
        status=receipt_document["status"],
        product_revision=receipt_document["product_revision"],
        official_head=receipt_document["official_head"],
        saas_head=receipt_document["saas_head"],
        database_identity_sha256=receipt_document["database_identity_sha256"],
        runtime_rls_table_count=receipt_document["runtime_rls_table_count"],
        authorities=tuple((row["kind"], row["login"]) for row in receipt_document["authorities"]),
        phases=tuple(receipt_document["phases"]),
        catalog_sha256=receipt_document["catalog_sha256"],
        service_role_bindings_sha256=receipt_document["service_role_bindings_sha256"],
        service_role_graph_sha256=receipt_document["service_role_graph_sha256"],
        completed_at=receipt_document["completed_at"],
        verify_only=receipt_document["verify_only"],
    )
    assert producer_receipt.saas_head == _R
    assert producer_receipt.product_revision == revision != plan.product_revision
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    config, engines = _startup_config(plan, producer_receipt, foreign)
    try:
        with pytest.raises(migration.PostgreSqlMigrationError) as rejected:
            migration.verify_production_postgresql_state(engines=engines, config=config)
        assert rejected.value.code == "migration_receipt_binding_mismatch"
    finally:
        for engine in engines.values():
            engine.dispose()
    with pytest.raises(migration.PostgreSqlMigrationError):
        migration.run_production_postgresql_migration(plan, verify_only=True)
    refreshed = migration.run_production_postgresql_migration(
        replace(plan, verification_saas_head=_R), verify_only=True
    )
    assert refreshed.product_revision == plan.product_revision and refreshed.verify_only is True
    assert refreshed.catalog_sha256 == producer_receipt.catalog_sha256
    assert refreshed.saas_head == _R
    own = tmp_path / "own"
    own.mkdir()
    config, engines = _startup_config(plan, refreshed, own)
    try:
        migration.verify_production_postgresql_state(engines=engines, config=config)
    finally:
        for engine in engines.values():
            engine.dispose()
    owner = sa.create_engine(plan.saas_owner.url)
    try:
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == _R
            )
    finally:
        owner.dispose()


if __name__ == "__main__":
    if sys.argv[1:] == ["--produce"]:
        _produce_schema()
    else:
        assert sys.argv[1:] == ["--produce-runner"]
        _produce_runner_schema()
