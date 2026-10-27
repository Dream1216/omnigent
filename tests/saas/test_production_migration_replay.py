"""Run with a fresh dedicated PG16/18 cluster, separate from shared SaaS fixtures."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from saas.production import postgresql_migration as migration
from saas.production.server import create_role_session_factories
from saas.production.server_config import ProductionMigrationReceipt
from saas.production.service_bindings import (
    EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES,
    EXPECTED_PLATFORM_MODEL_SERVICE_ROLES,
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    render_production_service_role_bindings,
)


def _enable_replay_tls(connection: sa.Connection, tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # COPY writes only these two fixture files, owned by the fresh cluster's OS user.
    for name, pem in (("crt", certificate_pem), ("key", key_pem)):
        lines = ",".join("'" + line + "'" for line in pem.decode().splitlines())
        connection.exec_driver_sql(
            f"COPY (SELECT unnest(ARRAY[{lines}])) TO '/tmp/omnigent-production-replay.{name}'"
        )
        setting = "ssl_cert_file" if name == "crt" else "ssl_key_file"
        connection.exec_driver_sql(
            f"ALTER SYSTEM SET {setting} = '/tmp/omnigent-production-replay.{name}'"
        )
    connection.exec_driver_sql(
        "COPY (SELECT '') TO PROGRAM "
        "'chmod 0600 /tmp/omnigent-production-replay.key && cat >/dev/null'"
    )
    connection.exec_driver_sql("ALTER SYSTEM SET ssl = 'on'")
    assert connection.exec_driver_sql("SELECT pg_reload_conf()").scalar_one()
    ca_path = tmp_path / "replay-ca.crt"
    ca_path.write_bytes(certificate_pem)
    return ca_path


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
        ProductionServiceRoleBinding(
            service=service,
            login=f"replay_{'preview_manager' if service == 'preview_owner' else service}",
            base_role=role,
        )
        for service, role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
    )
    document = render_production_service_role_bindings(bindings)
    manifest_path = tmp_path / "bindings.json"
    manifest_path.write_text(document)
    manifest_path.chmod(0o400)
    manifest = ProductionServiceRoleBindings(
        manifest_path, hashlib.sha256(document.encode()).hexdigest(), bindings
    )
    core_by_service = manifest.by_service
    platform_bindings = tuple(
        core_by_service[service]
        if service in core_by_service
        else ProductionServiceRoleBinding(
            service=service,
            login=f"replay_platform_model_{service}",
            base_role=role,
        )
        for service, role in sorted(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES.items())
    )
    platform_document = render_production_service_role_bindings(platform_bindings)
    platform_path = tmp_path / "platform-model-bindings.json"
    platform_path.write_text(platform_document)
    platform_path.chmod(0o400)
    platform_manifest = ProductionServiceRoleBindings(
        platform_path,
        hashlib.sha256(platform_document.encode()).hexdigest(),
        platform_bindings,
    )
    platform_graph = {**core_by_service, **platform_manifest.by_service}
    platform_admin_bindings = tuple(
        platform_graph[service]
        if service in platform_graph
        else ProductionServiceRoleBinding(
            service=service,
            login=f"replay_platform_staff_{service}",
            base_role=role,
        )
        for service, role in sorted(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES.items())
    )
    platform_admin_document = render_production_service_role_bindings(platform_admin_bindings)
    platform_admin_path = tmp_path / "platform-admin-bindings.json"
    platform_admin_path.write_text(platform_admin_document)
    platform_admin_path.chmod(0o400)
    platform_admin_manifest = ProductionServiceRoleBindings(
        platform_admin_path,
        hashlib.sha256(platform_admin_document.encode()).hexdigest(),
        platform_admin_bindings,
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
        ca_path = _enable_replay_tls(connection, tmp_path)
        for kind, role in roles.items():
            flags = "CREATEROLE" if kind == "principal_operator" else "NOCREATEROLE"
            connection.exec_driver_sql(
                f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB INHERIT "
                f"NOREPLICATION NOBYPASSRLS {flags} PASSWORD 'production-replay-test'"
            )
        all_bindings = {
            binding.login: binding
            for binding in (*bindings, *platform_bindings, *platform_admin_bindings)
        }
        for binding in all_bindings.values():
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
            username=roles[kind],
            password="production-replay-test",
            database="admission_replay",
            query={"sslmode": "verify-full", "sslrootcert": str(ca_path)},
        ).render_as_string(hide_password=False)

    plan = migration.ProductionPostgreSqlPlan.from_urls(
        product_revision=revision,
        principal_operator_url=authority_url("principal_operator"),
        database_owner_url=authority_url("database_owner"),
        official_owner_url=authority_url("official_owner"),
        saas_owner_url=authority_url("saas_owner"),
        service_role_bindings=manifest,
        platform_model_service_role_bindings=platform_manifest,
        platform_admin_service_role_bindings=platform_admin_manifest,
        require_tls=True,
    )
    yield plan


def test_real_clean_replay_upgrade_and_catalog_rejections(
    production_replay: migration.ProductionPostgreSqlPlan,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = production_replay
    target = migration._expected_head("official")
    first = migration.run_production_postgresql_migration(plan)
    assert first.status == "pass" and first.official_head == target
    assert first.service_role_graph_sha256 == plan.service_role_graph.sha256
    assert len(plan.service_role_graph.bindings) == 18
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
            context.setattr(
                migration,
                "_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256",
                {},
            )
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
    if final.saas_head in {"lm2t00000001", "dp1a00000001"}:
        from tests.saas.test_model_budget_owner_settlement_postgresql import (
            verify_non_bypass_budget_owner_settlement,
        )

        verify_non_bypass_budget_owner_settlement(plan)
    _verify_preview_deployment_and_startup(plan, final, tmp_path)


def _startup_config(
    plan: migration.ProductionPostgreSqlPlan,
    receipt: migration.PostgreSqlMigrationReceipt,
    tmp_path: Path,
) -> tuple[SimpleNamespace, dict[str, sa.Engine]]:
    path = tmp_path / f"runtime-migration-receipt-{receipt.catalog_sha256}.json"
    path.write_text(json.dumps(receipt.to_dict()))
    path.chmod(0o400)
    urls = {
        service: sa.make_url(plan.saas_owner.url)
        .set(username=plan.service_role_graph.login_for(service))
        .render_as_string(hide_password=False)
        for service in (*migration._SERVER_SERVICE_ROLES, "billing")
    }
    config = SimpleNamespace(
        product_revision=plan.product_revision,
        official_schema_revision=receipt.official_head,
        control_plane_schema_revision=receipt.saas_head,
        service_role_bindings=plan.service_role_bindings,
        service_role_graph=plan.service_role_graph,
        capabilities=frozenset({"billing"}),
        secrets=SimpleNamespace(database_urls=SimpleNamespace(as_mapping=lambda: urls)),
        migration_receipt=ProductionMigrationReceipt(
            path=path,
            product_revision=plan.product_revision,
            official_head=receipt.official_head,
            saas_head=receipt.saas_head,
            database_identity_sha256=receipt.database_identity_sha256,
            catalog_sha256=receipt.catalog_sha256,
            service_role_bindings_sha256=receipt.service_role_bindings_sha256,
            service_role_graph_sha256=receipt.service_role_graph_sha256,
            runtime_rls_table_count=receipt.runtime_rls_table_count,
        ),
    )
    return config, {service: sa.create_engine(url) for service, url in urls.items()}


def _preview_catalog(plan: migration.ProductionPostgreSqlPlan) -> tuple[tuple[int, str, str], str]:
    engine = sa.create_engine(plan.official_owner.url)
    try:
        with engine.connect() as connection:
            major = (
                int(connection.exec_driver_sql("SHOW server_version_num").scalar_one()) // 10000
            )
            inventory = migration._public_schema_inventory(
                connection,
                official_owner=plan.official_owner.login,
                saas_owner=plan.saas_owner.login,
            )
            key = (major, migration._expected_head("official"), migration._expected_head("saas"))
            inventory_digest = hashlib.sha256(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            print(f"CLEAN_REPLAY_PREVIEW_INVENTORY_PG{major}={inventory_digest}")
            assert (
                inventory_digest
                == migration._PREVIEW_AUTHORITY_PUBLIC_SCHEMA_INVENTORY_SHA256.get(key)
            )
            catalog = {
                "official_head": key[1],
                "saas_head": key[2],
                "ownership": migration._verify_object_ownership(
                    connection,
                    connection,
                    official_owner=plan.official_owner.login,
                    saas_owner=plan.saas_owner.login,
                ),
                "runtime_acls": migration._verify_runtime_acl(connection),
                "runtime_rls_tables": [
                    contract.table_name for contract in migration.load_runtime_rls_contract()
                ],
                "official_security": migration._official_security_catalog(
                    connection, official_owner=plan.official_owner.login
                ),
                "control_plane_security": migration._control_plane_security_catalog(
                    connection, saas_owner=plan.saas_owner.login
                ),
            }
            aliases = migration._source_catalog_role_aliases(
                principal_operator=plan.principal_operator.login,
                database_owner=plan.database_owner.login,
                official_owner=plan.official_owner.login,
                saas_owner=plan.saas_owner.login,
                bootstrap_name="postgres",
                bindings=plan.service_role_graph,
            )
            normalized = migration._sort_normalized_source_catalog_rows(
                migration._normalize_source_catalog(catalog, role_aliases=aliases)
            )
            digest = hashlib.sha256(
                json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            print(f"CLEAN_REPLAY_PREVIEW_SECURITY_PG{major}={digest}")
            assert (
                digest
                == migration._PREVIEW_AUTHORITY_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256.get(
                    key
                )
            )
            return key, digest
    finally:
        engine.dispose()


def _verify_preview_deployment_and_startup(
    plan: migration.ProductionPostgreSqlPlan,
    clean_receipt: migration.PostgreSqlMigrationReceipt,
    tmp_path: Path,
) -> None:
    config, engines = _startup_config(plan, clean_receipt, tmp_path)
    admin = sa.create_engine(
        sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
            database="admission_replay", query=sa.make_url(plan.saas_owner.url).query
        )
    )
    try:
        migration.verify_production_postgresql_state(engines=engines, config=config)
        with admin.begin() as connection:
            connection.exec_driver_sql(
                (
                    Path(__file__).parent / "fixtures" / "production_preview_authority.sql"
                ).read_text()
            )
        key, _digest = _preview_catalog(plan)
        with pytest.raises(migration.PostgreSqlMigrationError) as stale:
            migration.verify_production_postgresql_state(engines=engines, config=config)
        assert stale.value.code == "service_catalog_receipt_mismatch"
        preview_receipt = migration.run_production_postgresql_migration(plan, verify_only=True)
        assert preview_receipt.catalog_sha256 != clean_receipt.catalog_sha256
        reapplied = migration.run_production_postgresql_migration(plan)
        assert reapplied.catalog_sha256 == preview_receipt.catalog_sha256
        config, refreshed = _startup_config(plan, preview_receipt, tmp_path)
        try:
            migration.verify_production_postgresql_state(engines=refreshed, config=config)
            sessions = create_role_session_factories(
                config,  # type: ignore[arg-type]
                verify_state=lambda service_engines, service_config: (
                    migration.verify_production_postgresql_state(
                        engines=service_engines, config=service_config
                    )
                ),
            )
            sessions.close()
            _verify_runner_deployment_and_startup(plan, preview_receipt, config, refreshed, admin)
            with admin.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER POLICY rls_preview_gateway_instances_preview_edge "
                    "ON public.saas_preview_gateway_instances USING (true)"
                )
            with pytest.raises(migration.PostgreSqlMigrationError) as widened:
                migration.verify_production_postgresql_state(engines=refreshed, config=config)
            assert widened.value.code == "source_security_catalog_drifted"
            print(
                f"PREVIEW_PRODUCTION_STARTUP_PG{key[0]}=pass; "
                "stale_receipt=rejected; widened_policy=rejected; reapply=unchanged"
            )
        finally:
            for engine in refreshed.values():
                engine.dispose()
    finally:
        admin.dispose()
        for engine in engines.values():
            engine.dispose()


def _verify_runner_deployment_and_startup(
    plan: migration.ProductionPostgreSqlPlan,
    staging_receipt: migration.PostgreSqlMigrationReceipt,
    config: SimpleNamespace,
    engines: dict[str, sa.Engine],
    admin: sa.Engine,
) -> None:
    login = "runner_23dbe8e9d95a442abc841c356800ecfc_g13"
    with admin.begin() as connection:
        connection.exec_driver_sql(
            f"CREATE ROLE {login} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8"
        )
        connection.exec_driver_sql(
            f"GRANT saas_runner_agent TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
        )
    migration.verify_production_postgresql_state(engines=engines, config=config)
    with admin.begin() as connection:
        connection.exec_driver_sql(
            f"REVOKE saas_runner_agent FROM {plan.principal_operator.login} "
            "GRANTED BY CURRENT_USER RESTRICT"
        )
    migration.verify_production_postgresql_state(engines=engines, config=config)
    verified = migration.run_production_postgresql_migration(plan, verify_only=True)
    assert verified.catalog_sha256 == staging_receipt.catalog_sha256
    sessions = create_role_session_factories(
        config,  # type: ignore[arg-type]
        verify_state=lambda service_engines, service_config: (
            migration.verify_production_postgresql_state(
                engines=service_engines, config=service_config
            )
        ),
    )
    sessions.close()
    with admin.connect() as connection:
        assert (
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_auth_members m "
                    "JOIN pg_roles granted ON granted.oid=m.roleid "
                    "JOIN pg_roles member ON member.oid=m.member "
                    "WHERE granted.rolname='saas_runner_agent' AND member.rolname=:principal"
                ),
                {"principal": plan.principal_operator.login},
            )
            == 0
        )
    for unsafe in ("ADMIN TRUE", "INHERIT FALSE", "SET TRUE"):
        with admin.begin() as connection:
            connection.exec_driver_sql(f"GRANT saas_runner_agent TO {login} WITH {unsafe}")
        with pytest.raises(migration.PostgreSqlMigrationError) as widened:
            migration.verify_production_postgresql_state(engines=engines, config=config)
        assert widened.value.code == "service_role_graph_drifted"
        with admin.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT saas_runner_agent TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
    migration.verify_production_postgresql_state(engines=engines, config=config)
    print(
        "RUNNER_REVOKED_MANAGEMENT_STARTUP=pass; original_receipt=unchanged; unsafe_edges=rejected"
    )
