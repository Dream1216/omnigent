"""Run with a fresh dedicated PG16/18 cluster, separate from shared SaaS fixtures."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command

from saas.production import postgresql_migration as migration
from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    render_production_service_role_bindings,
)


@pytest.fixture
def production_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[migration.ProductionPostgreSqlPlan]:
    configured = os.environ.get("OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL")
    if not configured:
        pytest.skip("requires a dedicated clean production-migration replay cluster")
    url = sa.make_url(configured)
    assert url.host in ("127.0.0.1", "localhost") and url.username == "postgres"
    bindings = tuple(
        ProductionServiceRoleBinding(service=service, login=f"replay_{service}", base_role=role)
        for service, role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
    )
    document = render_production_service_role_bindings(bindings)
    manifest_path = tmp_path / "bindings.json"
    manifest_path.write_text(document)
    manifest_path.chmod(0o400)
    manifest = ProductionServiceRoleBindings(
        manifest_path, hashlib.sha256(document.encode()).hexdigest(), bindings
    )
    roles = {
        "principal_operator": "replay_principal",
        "database_owner": "replay_database",
        "official_owner": "replay_official",
        "saas_owner": "replay_saas",
    }
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        existing = (
            connection.execute(
                sa.text("SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg_%' ORDER BY 1")
            )
            .scalars()
            .all()
        )
        assert existing == ["postgres"], "dedicated fresh cluster required"
        for kind, role in roles.items():
            flags = "CREATEROLE" if kind == "principal_operator" else "NOCREATEROLE"
            connection.exec_driver_sql(
                f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB INHERIT "
                f"NOREPLICATION NOBYPASSRLS {flags} PASSWORD 'production-replay-test'"
            )
        for binding in bindings:
            connection.exec_driver_sql(
                f"CREATE ROLE {binding.login} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'production-replay-test'"
            )
        connection.exec_driver_sql(
            "ALTER ROLE replay_runtime_provider_journal SET search_path=public"
        )
        connection.exec_driver_sql("CREATE DATABASE admission_replay OWNER replay_database")
    admin.dispose()
    revision = "d" * 40
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: revision)

    def authority_url(kind: str) -> str:
        return url.set(
            username=roles[kind], password="production-replay-test", database="admission_replay"
        ).render_as_string(hide_password=False)

    plan = migration.ProductionPostgreSqlPlan.from_urls(
        product_revision=revision,
        principal_operator_url=authority_url("principal_operator"),
        database_owner_url=authority_url("database_owner"),
        official_owner_url=authority_url("official_owner"),
        saas_owner_url=authority_url("saas_owner"),
        service_role_bindings=manifest,
        require_tls=False,
    )
    yield plan


def test_real_clean_replay_upgrade_and_catalog_rejections(
    production_replay: migration.ProductionPostgreSqlPlan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = production_replay
    target = migration._expected_head("official")
    first = migration.run_production_postgresql_migration(plan)
    assert first.status == "pass" and first.official_head == target
    verified = migration.run_production_postgresql_migration(plan, verify_only=True)
    assert verified.catalog_sha256 == first.catalog_sha256
    repeated = migration.run_production_postgresql_migration(plan)
    assert repeated.catalog_sha256 == first.catalog_sha256

    owner = sa.create_engine(plan.official_owner.url)
    try:
        # Reproduce a deployed predecessor that already has the valid extension.
        config = migration._migration_config("official")
        with owner.connect() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "ga1b2c3d4e5f")
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                == "ga1b2c3d4e5f"
            )
        with monkeypatch.context() as context:
            context.setattr(migration, "_SOURCE_SECURITY_CATALOG_SHA256", {})
            with pytest.raises(migration.PostgreSqlMigrationError) as absent:
                migration.run_production_postgresql_migration(plan)
            assert absent.value.code == "source_catalog_baseline_missing"
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                == "ga1b2c3d4e5f"
            )
        upgraded = migration.run_production_postgresql_migration(plan)
        assert upgraded.official_head == target
        assert upgraded.catalog_sha256 == first.catalog_sha256

        with owner.begin() as connection:
            connection.exec_driver_sql("UPDATE alembic_version SET version_num='unknown'")
        with pytest.raises(migration.PostgreSqlMigrationError) as unknown:
            migration.run_production_postgresql_migration(plan)
        assert unknown.value.code == "pg_trgm_preexisting_before_head"
        with owner.begin() as connection:
            connection.execute(
                sa.text("UPDATE alembic_version SET version_num=:head"), {"head": target}
            )
            connection.exec_driver_sql(
                "ALTER TABLE hosts ADD CONSTRAINT replay_unreviewed_guard CHECK (true)"
            )
        with pytest.raises(migration.PostgreSqlMigrationError) as drift:
            migration.run_production_postgresql_migration(plan, verify_only=True)
        assert drift.value.code == "public_schema_inventory_drifted"
        with owner.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE hosts DROP CONSTRAINT replay_unreviewed_guard")
        final = migration.run_production_postgresql_migration(plan, verify_only=True)
        assert final.catalog_sha256 == first.catalog_sha256
    finally:
        owner.dispose()
