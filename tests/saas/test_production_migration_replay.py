"""Run with a fresh dedicated PG16/18 cluster, separate from shared SaaS fixtures."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from saas.production import postgresql_migration as migration
from saas.production import service_bindings
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
    # Each fixture owns its certificate files across repeated cluster replays.
    prefix = f"/tmp/omnigent-production-replay-{uuid4().hex}"
    for name, pem in (("crt", certificate_pem), ("key", key_pem)):
        lines = ",".join("'" + line + "'" for line in pem.decode().splitlines())
        connection.exec_driver_sql(f"COPY (SELECT unnest(ARRAY[{lines}])) TO '{prefix}.{name}'")
        setting = "ssl_cert_file" if name == "crt" else "ssl_key_file"
        connection.exec_driver_sql(f"ALTER SYSTEM SET {setting} = '{prefix}.{name}'")
    connection.exec_driver_sql(
        f"COPY (SELECT '') TO PROGRAM 'chmod 0600 {prefix}.key && cat >/dev/null'"
    )
    connection.exec_driver_sql("ALTER SYSTEM SET ssl = 'on'")
    assert connection.exec_driver_sql("SELECT pg_reload_conf()").scalar_one()
    ca_path = tmp_path / "replay-ca.crt"
    ca_path.write_bytes(certificate_pem)
    return ca_path


@pytest.fixture(params=["core", "model", "admin", "projection"])
def production_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
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
    projection_bindings = tuple(
        ProductionServiceRoleBinding(service=service, login=f"replay_{service}", base_role=role)
        for service, role in sorted(
            service_bindings.EXPECTED_MODEL_PROJECTION_SERVICE_ROLES.items()
        )
    )
    projection_document = render_production_service_role_bindings(projection_bindings)
    projection_path = tmp_path / "model-projection-bindings.json"
    projection_path.write_text(projection_document)
    projection_path.chmod(0o400)
    projection_manifest = ProductionServiceRoleBindings(
        projection_path,
        hashlib.sha256(projection_document.encode()).hexdigest(),
        projection_bindings,
    )
    delivery_manifest = None
    delivery_bindings: tuple[ProductionServiceRoleBinding, ...] = ()
    if migration._expected_head("saas") in {"p0s000000017", "p0s000000018"}:
        delivery_bindings = tuple(
            ProductionServiceRoleBinding(
                service=service,
                login=f"replay_{service}",
                base_role=role,
            )
            for service, role in sorted(
                service_bindings.EXPECTED_BUSINESS_DELIVERY_SERVICE_ROLES.items()
            )
        )
        delivery_document = render_production_service_role_bindings(delivery_bindings)
        delivery_path = tmp_path / "business-delivery-bindings.json"
        delivery_path.write_text(delivery_document)
        delivery_path.chmod(0o400)
        delivery_manifest = ProductionServiceRoleBindings(
            delivery_path,
            hashlib.sha256(delivery_document.encode()).hexdigest(),
            delivery_bindings,
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
            for binding in (
                *bindings,
                *platform_bindings,
                *platform_admin_bindings,
                *projection_bindings,
                *delivery_bindings,
            )
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
        platform_model_service_role_bindings=(
            platform_manifest if request.param != "core" else None
        ),
        platform_admin_service_role_bindings=(
            platform_admin_manifest if request.param in {"admin", "projection"} else None
        ),
        model_projection_service_role_bindings=(
            projection_manifest if request.param == "projection" else None
        ),
        **(
            {"business_delivery_service_role_bindings": delivery_manifest}
            if delivery_manifest is not None
            else {}
        ),
        require_tls=True,
    )
    try:
        yield plan
    finally:
        cleanup = sa.create_engine(url, isolation_level="AUTOCOMMIT")
        try:
            with cleanup.connect() as connection:
                connection.exec_driver_sql("DROP DATABASE IF EXISTS admission_replay WITH (FORCE)")
                roles = (
                    connection.execute(
                        sa.text(
                            "SELECT rolname FROM pg_roles "
                            "WHERE rolname <> 'postgres' AND rolname NOT LIKE 'pg_%'"
                        )
                    )
                    .scalars()
                    .all()
                )
                if roles:
                    quote = connection.dialect.identifier_preparer.quote
                    connection.exec_driver_sql(
                        "DROP ROLE " + ", ".join(quote(role) for role in roles)
                    )
        finally:
            cleanup.dispose()


def _run_original_migration_cli(
    plan: migration.ProductionPostgreSqlPlan,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
) -> dict[str, object]:
    import omnigent
    from saas.scripts import run_postgresql_migration as cli

    output = tmp_path / f"native-cli-{label}.json"
    with monkeypatch.context() as context:
        # Keep the original installed-build guard active with the fixture's own revision.
        context.setattr(
            omnigent,
            "_build_info",
            SimpleNamespace(COMMIT_SHA=plan.product_revision),
            raising=False,
        )
        for field, name in cli._URL_ENVIRONMENTS.items():
            authority = getattr(plan, field.removesuffix("_url"))
            path = tmp_path / f"native-cli-{label}-{field}"
            path.write_text(authority.url.render_as_string(hide_password=False))
            path.chmod(0o400)
            context.setenv(name, str(path))
        for name in cli._DIRECT_URL_ENVIRONMENTS:
            context.delenv(name, raising=False)
        for name in ("OMNIGENT_SAAS_SOURCE_SHA", "OMNIGENT_SAAS_PRODUCT_REVISION"):
            context.setenv(name, plan.product_revision)
        for name, profile in (
            ("SERVICE_ROLE_BINDINGS", plan.service_role_bindings),
            ("PLATFORM_MODEL_SERVICE_ROLE_BINDINGS", plan.platform_model_service_role_bindings),
            ("PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS", plan.platform_admin_service_role_bindings),
            (
                "MODEL_PROJECTION_SERVICE_ROLE_BINDINGS",
                plan.model_projection_service_role_bindings,
            ),
            (
                "BUSINESS_DELIVERY_SERVICE_ROLE_BINDINGS",
                plan.business_delivery_service_role_bindings,
            ),
        ):
            prefix = "OMNIGENT_SAAS_" + name
            for suffix in ("_FILE", "_SHA256"):
                context.delenv(prefix + suffix, raising=False)
            if profile is not None:
                context.setenv(prefix + "_FILE", str(profile.path))
                context.setenv(prefix + "_SHA256", profile.sha256)
        context.setattr(
            "sys.argv",
            [
                "run_postgresql_migration",
                "--product-revision",
                plan.product_revision,
                "--output",
                str(output),
            ],
        )
        assert cli.main() == 0
    return json.loads(output.read_text())


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
    profile = (
        "projection"
        if plan.model_projection_service_role_bindings is not None
        else "core"
        if plan.platform_model_service_role_bindings is None
        else "model"
        if plan.platform_admin_service_role_bindings is None
        else "admin"
    )
    delivery_manifest = getattr(plan, "business_delivery_service_role_bindings", None)
    assert len(plan.service_role_graph.bindings) == (
        {"core": 15, "model": 17, "admin": 18, "projection": 19}[profile]
        + (3 if delivery_manifest is not None else 0)
    )
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
            if delivery_manifest is not None:
                context.setitem(migration._BUSINESS_DELIVERY_SOURCE_SECURITY_CATALOGS, profile, {})
            else:
                context.setattr(
                    migration,
                    {
                        "core": "_SOURCE_SECURITY_CATALOG_SHA256",
                        "model": "_PLATFORM_MODEL_SOURCE_SECURITY_CATALOG_SHA256",
                        "admin": "_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256",
                        "projection": "_MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256",
                    }[profile],
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

        historical_users = [(1_234_567, f"trgm-a-{uuid4()}"), (1_234_568, f"trgm-b-{uuid4()}")]
        with owner.begin() as connection:
            for workspace, user in historical_users:
                connection.execute(
                    sa.text("SELECT set_config('app.runtime_workspace_id', :workspace, true)"),
                    {"workspace": str(workspace)},
                )
                connection.execute(
                    sa.text("INSERT INTO users (workspace_id,id) VALUES (:workspace,:user)"),
                    {"workspace": workspace, "user": user},
                )
        operator = sa.create_engine(
            sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
                database=plan.official_owner.url.database
            )
        )
        try:
            for predecessor in ("hh1b2c3d4e5f", "mm1a2b3c4d5e"):
                with owner.connect() as connection:
                    config.attributes["connection"] = connection
                    command.downgrade(config, predecessor)
                with owner.connect() as connection:
                    assert (
                        connection.exec_driver_sql(
                            "SELECT version_num FROM alembic_version"
                        ).scalar_one()
                        == predecessor
                    )
                    assert connection.exec_driver_sql(
                        "SELECT indexname FROM pg_indexes WHERE schemaname='public' "
                        "AND indexname IN ('ix_conversations_title_trgm', "
                        "'ix_conversation_items_search_text_trgm') ORDER BY indexname"
                    ).scalars().all() == ["ix_conversations_title_trgm"]
                with owner.begin() as connection:
                    connection.exec_driver_sql(
                        "CREATE INDEX replay_unreviewed_title_trgm ON public.conversations "
                        "USING gin (lower(title) gin_trgm_ops)"
                    )
                try:
                    with pytest.raises(migration.PostgreSqlMigrationError) as extra:
                        migration.run_production_postgresql_migration(plan)
                    assert extra.value.code == "pg_trgm_index_contract_drifted"
                finally:
                    with owner.begin() as connection:
                        connection.exec_driver_sql("DROP INDEX replay_unreviewed_title_trgm")
                with owner.begin() as connection:
                    connection.exec_driver_sql("DROP INDEX ix_conversations_title_trgm")
                    connection.exec_driver_sql(
                        "CREATE INDEX ix_conversations_title_trgm ON public.conversations "
                        "USING gin ((lower(title) || 'drift') gin_trgm_ops)"
                    )
                try:
                    with pytest.raises(migration.PostgreSqlMigrationError) as expression:
                        migration.run_production_postgresql_migration(plan)
                    assert expression.value.code == "pg_trgm_index_contract_drifted"
                finally:
                    with owner.begin() as connection:
                        connection.exec_driver_sql("DROP INDEX ix_conversations_title_trgm")
                        connection.exec_driver_sql(
                            "CREATE INDEX ix_conversations_title_trgm ON public.conversations "
                            "USING gin (lower(title) gin_trgm_ops)"
                        )
                with operator.begin() as connection:
                    quote = connection.dialect.identifier_preparer.quote
                    connection.exec_driver_sql(
                        "ALTER TABLE public.conversations OWNER TO "
                        + quote(plan.database_owner.login)
                    )
                try:
                    with pytest.raises(migration.PostgreSqlMigrationError) as ownership:
                        migration.run_production_postgresql_migration(plan)
                    assert ownership.value.code == "pg_trgm_index_contract_drifted"
                finally:
                    with operator.begin() as connection:
                        quote = connection.dialect.identifier_preparer.quote
                        connection.exec_driver_sql(
                            "ALTER TABLE public.conversations OWNER TO "
                            + quote(plan.official_owner.login)
                        )
                receipt = _run_original_migration_cli(plan, tmp_path, monkeypatch, predecessor)
                assert receipt["status"] == "pass" and receipt["official_head"] == target
                assert receipt["catalog_sha256"] == first.catalog_sha256
                assert receipt["service_role_graph_sha256"] == plan.service_role_graph.sha256
                with owner.begin() as connection:
                    for workspace, user in historical_users:
                        connection.execute(
                            sa.text(
                                "SELECT set_config('app.runtime_workspace_id', :workspace, true)"
                            ),
                            {"workspace": str(workspace)},
                        )
                        assert connection.execute(
                            sa.text("SELECT workspace_id,id FROM users WHERE id=:user"),
                            {"user": user},
                        ).all() == [(workspace, user)]
        finally:
            operator.dispose()

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
    if final.saas_head in {"lm2t00000001", "p0s000000016", "p0s000000017", "p0s000000018"}:
        from tests.saas.test_model_budget_owner_settlement_postgresql import (
            verify_non_bypass_budget_owner_settlement,
        )

        if profile == "core":
            assert "billing" not in plan.service_role_graph.by_service
        else:
            verify_non_bypass_budget_owner_settlement(plan)
    if profile in {"admin", "projection"}:
        _verify_preview_deployment_and_startup(plan, final, tmp_path)
    else:
        config, engines = _startup_config(plan, final, tmp_path)
        try:
            migration.verify_production_postgresql_state(engines=engines, config=config)
            sessions = create_role_session_factories(
                config,  # type: ignore[arg-type]
                verify_state=lambda service_engines, service_config: (
                    migration.verify_production_postgresql_state(
                        engines=service_engines, config=service_config
                    )
                ),
            )
            sessions.close()
        finally:
            for engine in engines.values():
                engine.dispose()


def _startup_config(
    plan: migration.ProductionPostgreSqlPlan,
    receipt: migration.PostgreSqlMigrationReceipt,
    tmp_path: Path,
) -> tuple[SimpleNamespace, dict[str, sa.Engine]]:
    path = tmp_path / f"runtime-migration-receipt-{receipt.catalog_sha256}.json"
    path.write_text(json.dumps(receipt.to_dict()))
    path.chmod(0o400)
    delivery_manifest = getattr(plan, "business_delivery_service_role_bindings", None)
    urls = {
        service: sa.make_url(plan.saas_owner.url)
        .set(username=plan.service_role_graph.login_for(service))
        .update_query_dict(
            {"application_name": "saas-revocation-worker"}
            if service == "revocation_consumer"
            else {}
        )
        .render_as_string(hide_password=False)
        for service in (
            *migration._SERVER_SERVICE_ROLES,
            *(("billing",) if "billing" in plan.service_role_graph.by_service else ()),
            *(("revocation_consumer",) if delivery_manifest is not None else ()),
        )
    }
    config = SimpleNamespace(
        product_revision=plan.product_revision,
        official_schema_revision=receipt.official_head,
        control_plane_schema_revision=receipt.saas_head,
        service_role_bindings=plan.service_role_bindings,
        service_role_graph=plan.service_role_graph,
        business_delivery_service_role_bindings=delivery_manifest,
        capabilities=(
            frozenset({"billing"})
            if "billing" in plan.service_role_graph.by_service
            else frozenset()
        ),
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
        preview_plan = replace(plan, install_preview_authority=True)
        preview_receipt = migration.run_production_postgresql_migration(preview_plan)
        assert "preview_authority:applied" in preview_receipt.phases
        assert not any("alembic:applied" in phase for phase in preview_receipt.phases)
        with admin.connect() as connection:
            key = (
                int(connection.exec_driver_sql("SHOW server_version_num").scalar_one()) // 10000,
                preview_receipt.official_head,
                preview_receipt.saas_head,
            )
        with pytest.raises(migration.PostgreSqlMigrationError) as stale:
            migration.verify_production_postgresql_state(engines=engines, config=config)
        assert stale.value.code == "service_catalog_receipt_mismatch"
        assert preview_receipt.catalog_sha256 != clean_receipt.catalog_sha256
        reapplied = migration.run_production_postgresql_migration(preview_plan)
        assert reapplied.catalog_sha256 == preview_receipt.catalog_sha256
        assert (
            migration.run_production_postgresql_migration(
                preview_plan, verify_only=True
            ).catalog_sha256
            == preview_receipt.catalog_sha256
        )
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
            saas_engine = sa.create_engine(plan.saas_owner.url)
            try:
                with saas_engine.begin() as connection:
                    original_guard = connection.scalar(
                        sa.text(
                            "SELECT pg_get_functiondef("
                            "'public.saas_preview_owner_scope_is_current_v1()'::regprocedure)"
                        )
                    )
                    connection.exec_driver_sql(
                        "CREATE OR REPLACE FUNCTION "
                        "public.saas_preview_owner_scope_is_current_v1() "
                        "RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER "
                        "SET search_path=pg_catalog,pg_temp AS 'SELECT true'"
                    )
                with pytest.raises(migration.PostgreSqlMigrationError) as body_drift:
                    migration.run_production_postgresql_migration(preview_plan)
                assert body_drift.value.code == "source_security_catalog_drifted"
                with saas_engine.begin() as connection:
                    assert (
                        connection.scalar(
                            sa.text(
                                "SELECT prosrc FROM pg_proc WHERE "
                                "oid='public.saas_preview_owner_scope_is_current_v1()'::regprocedure"
                            )
                        )
                        == "SELECT true"
                    )
                    connection.exec_driver_sql(original_guard)
            finally:
                saas_engine.dispose()
            _verify_native_preview_owner(plan, admin, tmp_path)
            _verify_runner_deployment_and_startup(plan, preview_receipt, config, refreshed, admin)
            with admin.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER POLICY rls_preview_gateway_instances_preview_edge "
                    "ON public.saas_preview_gateway_instances USING (true)"
                )
            with pytest.raises(migration.PostgreSqlMigrationError) as widened:
                migration.verify_production_postgresql_state(engines=refreshed, config=config)
            assert widened.value.code == "source_security_catalog_drifted"
            with pytest.raises(migration.PostgreSqlMigrationError) as repair:
                migration.run_production_postgresql_migration(preview_plan)
            assert repair.value.code == "source_security_catalog_drifted"
            with admin.connect() as connection:
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT pg_get_expr(polqual,polrelid) FROM pg_policy WHERE "
                            "polname='rls_preview_gateway_instances_preview_edge'"
                        )
                    )
                    == "true"
                )
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


def _verify_native_preview_owner(
    plan: migration.ProductionPostgreSqlPlan, admin: sa.Engine, tmp_path: Path
) -> None:
    from sqlalchemy.orm import sessionmaker

    from omnigent.runner.identity import token_bound_runner_id
    from saas.control_plane import PreviewGatewayCertificateAuthority, PreviewGatewayLifecycleError
    from saas.control_plane.preview_tunnel_registration import (
        PreviewTunnelOwnerAuthority,
        PreviewTunnelRegistrationError,
    )
    from saas.production.preview_relay import (
        ProductionPreviewRelayError,
        ProductionPreviewRelayOwner,
        build_production_preview_relay_owner,
    )
    from tests.saas.test_preview_gateway_authority import _gateway_certificate
    from tests.saas.test_preview_p0s9_postgresql import _seed_ready_preview
    from tests.saas.test_production_preview_relay import _owner_config

    relay_config = _owner_config(tmp_path, include_loopback_ip=False)
    raw_gateway_token = "native-owner-registration-" + "g" * 32
    raw_registration = "native-runner-registration-" + "r" * 32
    official_runner = token_bound_runner_id(raw_registration)
    gateway = relay_config.gateway_instance_id
    owner_url = plan.saas_owner.url.set(
        username=plan.service_role_graph.login_for("preview_owner")
    )
    relay_config = replace(
        relay_config,
        source_revision=plan.product_revision,
        product_revision=plan.product_revision,
        expected_preview_login=owner_url.username,
        preview_database_url=owner_url.render_as_string(hide_password=False),
    )
    with admin.begin() as connection:
        facts = _seed_ready_preview(
            connection,
            gateway_id=gateway,
            gateway_token_hash=hashlib.sha256(raw_gateway_token.encode()).hexdigest(),
            gateway_host="127.0.0.1",
            gateway_server_name="localhost",
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role=replica")
        connection.execute(
            sa.text(
                "INSERT INTO saas_runner_certificates (id,runner_id,runner_connection_generation,"
                "purpose,fingerprint_sha256,spki_sha256,serial_hex,spiffe_id,trust_bundle_version,"
                "rotation_generation,certificate_not_before,certificate_not_after,status,activated_at,"
                "created_at,updated_at) VALUES (:id,:runner_id,4,'runner_control',"
                ":fingerprint,:spki,"
                "'01',:spiffe,'test-bundle',1,:now,:expires_at,'active',:now,:now,:now)"
            ),
            {
                **facts,
                "id": uuid4(),
                "fingerprint": "a" * 64,
                "spki": "b" * 64,
                "spiffe": f"spiffe://omnigent/runner/{facts['runner_id']}",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_preview_tunnel_registrations (id,runner_id,placement_id,"
                "connection_generation,gateway_instance_id,certificate_fingerprint_sha256,audience,"
                "jti_hash,token_hash,official_runner_id,status,expires_at,created_at,updated_at) "
                "VALUES (:id,:runner_id,:placement_id,4,:gateway_id,:fingerprint,'localhost',:jti,"
                ":token,:official_runner,'issued',:expires_at,:now,:now)"
            ),
            {
                **facts,
                "id": uuid4(),
                "fingerprint": "a" * 64,
                "jti": "c" * 64,
                "token": hashlib.sha256(raw_registration.encode()).hexdigest(),
                "official_runner": official_runner,
            },
        )
        connection.exec_driver_sql("SET LOCAL session_replication_role=origin")
        connection.execute(
            sa.text(
                "INSERT INTO saas_preview_gateway_instances (id,connect_host,connect_port,"
                "server_name,failure_domain,source_revision,adapter_contract_version,"
                "registration_token_hash,status,registered_at,activated_at,last_heartbeat_at,"
                "lease_expires_at,released_at,release_reason,created_at,updated_at) "
                "SELECT 'gateway-owner-peer',connect_host,"
                "connect_port,server_name,failure_domain,source_revision,adapter_contract_version,"
                "repeat('e',64),status,registered_at,activated_at,last_heartbeat_at,"
                "lease_expires_at,released_at,release_reason,created_at,updated_at "
                "FROM saas_preview_gateway_instances WHERE id=:gateway"
            ),
            {"gateway": gateway},
        )
    admin_certificates = PreviewGatewayCertificateAuthority(
        sessionmaker(admin), accepted_trust_bundle_versions=("test-bundle",)
    )
    for purpose, path in (
        ("preview_relay_client", relay_config.relay_client_certificate_path),
        ("preview_relay_server", relay_config.relay_server_certificate_path),
    ):
        der = x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
        admin_certificates.activate_certificate(
            gateway_instance_id=gateway,
            purpose=purpose,
            certificate_der=der,
            trust_bundle_version="test-bundle",
        )
    peer_der = _gateway_certificate(
        "gateway-owner-peer", purpose="preview_relay_server", now=datetime.now(UTC)
    )
    peer_certificate = admin_certificates.activate_certificate(
        gateway_instance_id="gateway-owner-peer",
        purpose="preview_relay_server",
        certificate_der=peer_der,
        trust_bundle_version="test-bundle",
    )
    token_path = tmp_path / "native-owner-registration-token"
    token_path.write_text(raw_gateway_token + "\n")
    token_path.chmod(0o400)
    relay_config = replace(relay_config, gateway_registration_token_path=token_path)
    from saas.production.preview_edge import ProductionPreviewEdgeError

    edge_url = owner_url.set(username=plan.service_role_graph.login_for("preview_edge"))
    with pytest.raises(ProductionPreviewEdgeError):
        build_production_preview_relay_owner(
            config=replace(
                relay_config,
                preview_database_url=edge_url.render_as_string(hide_password=False),
                expected_preview_login=edge_url.username,
            )
        )
    owner = build_production_preview_relay_owner(config=relay_config)
    wrong = ProductionPreviewRelayOwner(
        relay_config,
        sa.create_engine(owner_url, hide_parameters=True),
        gateway_registration_token="wrong-" + "x" * 48,
    )
    authority = PreviewTunnelOwnerAuthority(
        owner._sessions, gateway_instance_id=gateway, gateway_registration_token=raw_gateway_token
    )
    try:

        async def start_and_stop() -> None:
            await owner.start()
            owner.assert_production_ready()
            await owner.aclose()

        asyncio.run(start_and_stop())
        assert owner._directory.resolve(SimpleNamespace(gateway_instance_id="gateway-owner-peer"))
        assert owner._certificates.is_preview_gateway_certificate_authorized(
            gateway_instance_id="gateway-owner-peer",
            certificate_der=peer_der,
            purpose="preview_relay_server",
        )
        assert not owner._certificates.is_preview_gateway_certificate_authorized(
            gateway_instance_id=gateway, certificate_der=peer_der, purpose="preview_relay_server"
        )
        assert not owner._certificates.is_preview_gateway_certificate_authorized(
            gateway_instance_id="gateway-owner-peer",
            certificate_der=peer_der,
            purpose="preview_relay_client",
        )
        with pytest.raises(ProductionPreviewRelayError):
            wrong.assert_production_ready()
        with wrong._sessions.begin() as db:
            assert db.scalar(sa.text("SELECT count(*) FROM saas_runner_tunnel_placements")) == 0
        with owner._sessions.begin() as db:
            assert db.scalar(sa.text("SELECT count(*) FROM saas_runner_tunnel_placements")) == 1
            db.execute(
                sa.text("SELECT set_config('app.preview_gateway_instance_id', :peer, true)"),
                {"peer": "gateway-owner-peer"},
            )
            assert db.scalar(sa.text("SELECT count(*) FROM saas_runner_tunnel_placements")) == 0
        with owner._sessions.begin() as db:
            assert db.scalar(sa.text("SELECT count(*) FROM saas_runner_tunnel_placements")) == 1
        for statement in (
            "UPDATE saas_preview_gateway_instances SET status='released'",
            "SELECT registration_token_hash FROM saas_preview_gateway_instances",
            "DELETE FROM saas_preview_tunnel_registrations",
        ):
            with pytest.raises(sa.exc.ProgrammingError), owner._sessions.begin() as db:
                db.execute(sa.text(statement))
        assert authority.heartbeat_gateway()
        assert (
            authority.preauthorize(
                official_runner_id=official_runner, registration_token=raw_registration
            )
            is not None
        )
        grant = authority.redeem(
            official_runner_id=official_runner, registration_token=raw_registration
        )
        assert grant.runner_id == facts["runner_id"]
        with pytest.raises(PreviewTunnelRegistrationError):
            authority.redeem(
                official_runner_id=official_runner, registration_token=raw_registration
            )
        assert authority.heartbeat(
            official_runner_id=official_runner, registration_token=raw_registration
        )
        assert authority.disconnect(
            official_runner_id=official_runner, registration_token=raw_registration
        )
        assert admin_certificates.revoke_certificate(
            fingerprint_sha256=peer_certificate.fingerprint_sha256, reason="native-test"
        )
        assert not owner._certificates.is_preview_gateway_certificate_authorized(
            gateway_instance_id="gateway-owner-peer",
            certificate_der=peer_der,
            purpose="preview_relay_server",
        )
        with admin.begin() as connection:
            connection.exec_driver_sql("SET LOCAL session_replication_role=replica")
            connection.execute(
                sa.text(
                    "UPDATE saas_preview_gateway_instances "
                    "SET registered_at=CURRENT_TIMESTAMP-INTERVAL '2 minutes', "
                    "activated_at=CURRENT_TIMESTAMP-INTERVAL '2 minutes', "
                    "lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=:gateway"
                ),
                {"gateway": gateway},
            )
        assert not authority.heartbeat_gateway()
        with pytest.raises(ProductionPreviewRelayError):
            owner._assert_authority_ready()
        with pytest.raises(PreviewGatewayLifecycleError):
            owner._directory.resolve(SimpleNamespace(gateway_instance_id="gateway-owner-peer"))
        assert authority.release_gateway()
        assert not authority.release_gateway()
    finally:
        wrong.close()
        owner.close()


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


@pytest.mark.parametrize("production_replay", ["admin"], indirect=True)
def test_real_fenced_t_runtime_rebinding_commit_and_complete_facts(production_replay):
    """Run the native maintenance scenario in the existing two-major replay lane."""
    from tests.saas.test_runtime_maintenance_postgresql import (
        assert_fenced_t_rebinding_preserves_same_projects_all_other_facts_and_commit_outcome,
    )

    assert_fenced_t_rebinding_preserves_same_projects_all_other_facts_and_commit_outcome(
        production_replay
    )


@pytest.mark.parametrize("production_replay", ["admin"], indirect=True)
def test_real_fenced_t_new_schema_inverse_refuses_before_mutation(production_replay, tmp_path):
    """New official columns cannot enter the original destructive T downgrade."""
    from tests.saas.test_runtime_maintenance_postgresql import (
        assert_fenced_t_complete_inverse_and_reattach_derives_independent_target_gold,
    )

    assert_fenced_t_complete_inverse_and_reattach_derives_independent_target_gold(
        production_replay,
        tmp_path,
        expected_inverse_refusal=r"^official_schema_inverse_not_source_qualified$",
    )


@pytest.mark.parametrize("production_replay", ["admin"], indirect=True)
def test_real_d0_retaining_t_inverse_and_reattach_preserves_complete_facts(
    production_replay, tmp_path
):
    """Real SQL proof; image/provider/physical-restore qualification is separate."""
    from tests.saas.test_runtime_maintenance_postgresql import (
        assert_fenced_t_complete_inverse_and_reattach_derives_independent_target_gold,
    )

    assert_fenced_t_complete_inverse_and_reattach_derives_independent_target_gold(
        production_replay, tmp_path, retain_d0=True
    )
