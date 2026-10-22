from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane.migrations.versions import (
    lm2q00000001_bounded_model_documents as migration,
)
from saas.control_plane.model_gateway_audit import verify_gateway_audit_function
from tests.saas.test_model_document_storage_migration import _raw_documents
from tests.saas.test_model_secret_storage_migration import _config
from tests.saas.test_model_verification_postgresql import (
    test_real_postgresql_model_test_requires_staff_projection_and_billing_identities as _staff_chain,  # noqa: E501
)
from tests.saas.test_platform_model_gateway_attempts_postgresql import (
    test_real_postgresql_gateway_uses_billing_login_for_one_sent_attempt as _gateway_chain,
)


def _roundtrip(engine, expected_tables):
    roles = (
        Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
    ).read_text()
    before = _raw_documents(engine)
    assert {table for table, rows in before.items() if rows} == expected_tables
    assert all(
        isinstance(value, bytes) and value.startswith(b"OGMD\x01\x00\x00")
        for rows in before.values()
        for row in rows
        for value in row[1:]
    )
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")) == (
            "lm2q00000001"
        )
        assert verify_gateway_audit_function(connection) is not None
        authority = _authority(connection)
    assert (
        sum(len(sa.inspect(engine).get_foreign_keys(table)) for table in migration._RELATION_ORDER)
        == 0
    )
    with engine.begin() as connection:
        command.downgrade(_config(connection), "lm2p00000001")
        connection.exec_driver_sql(roles)
    assert (
        sum(len(sa.inspect(engine).get_foreign_keys(table)) for table in migration._RELATION_ORDER)
        == 37
    )
    legacy = _raw_documents(engine)
    assert {
        table: [(row[0], *(value.encode() for value in row[1:])) for row in rows]
        for table, rows in legacy.items()
    } == {
        table: [(row[0], *(value[7:] for value in row[1:])) for row in rows]
        for table, rows in before.items()
    }
    with engine.begin() as connection:
        command.upgrade(_config(connection), "lm2q00000001")
        connection.exec_driver_sql(roles)
    assert _raw_documents(engine) == before
    with engine.connect() as connection:
        assert verify_gateway_audit_function(connection) is not None
        assert _authority(connection) == authority


def _authority(connection):
    relations = connection.exec_driver_sql(
        "SELECT relname,relowner,relrowsecurity,relforcerowsecurity "
        "FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY 1"
    ).all()
    grants = connection.exec_driver_sql(
        "SELECT relation.relname,acl.grantee,acl.grantor,acl.privilege_type,acl.is_grantable "
        "FROM pg_class relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,"
        "acldefault('r',relation.relowner))) acl "
        "WHERE relation.relnamespace='public'::regnamespace AND relation.relkind='r' "
        "ORDER BY 1,2,3,4,5"
    ).all()
    return relations, grants


def test_real_postgresql_staff_financial_chain_survives_document_and_relationship_roundtrip(
    isolated_postgres_url, monkeypatch
):
    # Start at the document migration's real historical schema, not by removing
    # the newer retained-budget policy from a populated current schema.
    _staff_chain(isolated_postgres_url, monkeypatch, schema_revision="lm2q00000001")
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _roundtrip(
            engine,
            {
                table
                for table, _pk, _columns in migration._COLUMNS
                if table != "saas_model_gateway_evidence"
            },
        )
    finally:
        engine.dispose()


def test_real_postgresql_billing_attempt_survives_gateway_document_roundtrip(
    tmp_path, isolated_postgres_url
):
    _gateway_chain(
        tmp_path,
        isolated_postgres_url,
        responses=False,
        zero=False,
        schema_revision="lm2q00000001",
    )
    engine = sa.create_engine(isolated_postgres_url)
    try:
        _roundtrip(engine, {"saas_model_gateway_evidence"})
    finally:
        engine.dispose()


def test_role_projection_accepts_exact_pg_dump_publication_check_form(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    roles = (
        Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
    ).read_text()
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), "lm2q00000001")
            connection.exec_driver_sql(
                "ALTER TABLE saas_model_publication_versions "
                "DROP CONSTRAINT ck_model_publication_documents"
            )
            connection.exec_driver_sql(
                "ALTER TABLE saas_model_publication_versions "
                "ADD CONSTRAINT ck_model_publication_documents CHECK ("
                "length(canonical_snapshot)>=8 AND length(canonical_snapshot)<=16383 AND "
                "(length(canonical_readiness)>=8 AND length(canonical_readiness)<=16383))"
            )
            connection.exec_driver_sql(roles)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "drift",
    (
        "spoofed_head",
        "weakened_bound",
        "weakened_snapshot",
        "weakened_readiness",
        "new_foreign_key",
    ),
)
def test_role_projection_requires_the_exact_document_and_relationship_contract(
    isolated_postgres_url, drift
):
    engine = sa.create_engine(isolated_postgres_url)
    roles = (
        Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_roles.sql"
    ).read_text()
    head = "lm2p00000001" if drift == "spoofed_head" else "lm2q00000001"
    try:
        with engine.begin() as connection:
            command.upgrade(_config(connection), head)
        reason = (
            "model relationship object contract rejected"
            if drift == "new_foreign_key"
            else "model document storage object contract rejected"
        )
        with pytest.raises(sa.exc.DBAPIError, match=reason):
            with engine.begin() as connection:
                if drift == "spoofed_head":
                    connection.exec_driver_sql(
                        "UPDATE saas_alembic_version SET version_num='lm2q00000001'"
                    )
                elif drift == "weakened_bound":
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_deployment_versions "
                        "DROP CONSTRAINT ck_model_deployment_configuration"
                    )
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_deployment_versions "
                        "ADD CONSTRAINT ck_model_deployment_configuration "
                        "CHECK (length(canonical_configuration) BETWEEN 8 AND 16384)"
                    )
                elif drift in {"weakened_snapshot", "weakened_readiness"}:
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_publication_versions "
                        "DROP CONSTRAINT ck_model_publication_documents"
                    )
                    snapshot_limit = 16384 if drift == "weakened_snapshot" else 16383
                    readiness_limit = 16384 if drift == "weakened_readiness" else 16383
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_publication_versions "
                        "ADD CONSTRAINT ck_model_publication_documents CHECK ("
                        "length(canonical_snapshot)>=8 AND "
                        f"length(canonical_snapshot)<={snapshot_limit} AND "
                        "(length(canonical_readiness)>=8 AND "
                        f"length(canonical_readiness)<={readiness_limit}))"
                    )
                else:
                    connection.exec_driver_sql(
                        "ALTER TABLE saas_model_connections "
                        "ADD CONSTRAINT forged_model_relationship "
                        "FOREIGN KEY (updated_by_principal_id) "
                        "REFERENCES saas_platform_staff_principals(id)"
                    )
                connection.exec_driver_sql(roles)
        with engine.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == head
            )
        assert sum(
            len(sa.inspect(engine).get_foreign_keys(table)) for table in migration._RELATION_ORDER
        ) == (37 if head == "lm2p00000001" else 0)
    finally:
        engine.dispose()
