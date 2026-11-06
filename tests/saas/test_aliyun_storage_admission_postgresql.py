from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import sqlalchemy as sa

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import (
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.rls import RlsContext, apply_rls_context
from tests.saas.test_execution_control_plane import _execution_fixture
from tests.saas.test_postgresql_rls import _migrate


def test_real_app_login_sees_project_binding_inventory_only_in_its_space(
    isolated_postgres_url,
):
    admin = sa.create_engine(isolated_postgres_url, hide_parameters=True)
    role = f"aliyun_storage_{uuid4().hex[:16]}"
    password = uuid4().hex
    quote = admin.dialect.identifier_preparer.quote
    app = None
    try:
        root = Path(__file__).resolve().parents[2]
        with admin.begin() as db:
            _migrate(db, root)
            db.exec_driver_sql((root / "saas/control_plane/postgresql_roles.sql").read_text())
        first = _execution_fixture(admin, create_schema=False)[2]
        other = _execution_fixture(admin, create_schema=False)[2]
        expected = []
        with admin.begin() as db:
            for scope in (first, other):
                placement, partition = uuid4(), uuid4()
                db.execute(
                    sa.insert(RuntimePlacementRecord).values(
                        id=placement,
                        runtime_type="omnigent",
                        data_region="cn-east-1",
                        failure_domain="test",
                        database_cluster_ref="test-db",
                        object_store_ref="test-store",
                        kms_key_ref="test-kms",
                        official_schema_revision="test-schema",
                        capacity_class="test",
                        status="active",
                    )
                )
                db.execute(
                    sa.insert(RuntimePartitionRecord).values(
                        id=partition,
                        tenant_id=scope.tenant_id,
                        space_id=scope.space_id,
                        placement_id=placement,
                        runtime_type="omnigent",
                        runtime_version="test",
                        physical_partition_key=str(len(expected) + 41),
                        placement_generation=1,
                        source_revision="test",
                        adapter_contract_version="0.2.0",
                        status="active",
                    )
                )
                identifiers = [uuid4(), uuid4()]
                db.execute(
                    sa.insert(RuntimeResourceBindingRecord),
                    [
                        {
                            "id": identifier,
                            "runtime_partition_id": partition,
                            "tenant_id": scope.tenant_id,
                            "space_id": scope.space_id,
                            "project_id": scope.project_id if index == 0 else None,
                            "resource_type": "session",
                            "runtime_resource_id": uuid4().hex,
                            "saas_resource_id": uuid4(),
                            "partition_generation": 1,
                            "binding_generation": 1,
                            "status": "active",
                        }
                        for index, identifier in enumerate(identifiers)
                    ],
                )
                expected.append(set(identifiers))
            db.exec_driver_sql(
                f"CREATE ROLE {quote(role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
            )
            db.exec_driver_sql(f"GRANT saas_app TO {quote(role)}")
            database = db.exec_driver_sql("SELECT current_database()").scalar_one()
            db.exec_driver_sql(f"GRANT CONNECT ON DATABASE {quote(database)} TO {quote(role)}")
        app = sa.create_engine(
            sa.engine.make_url(isolated_postgres_url).set(username=role, password=password),
            hide_parameters=True,
        )
        sessions = make_named_managed_session_maker(app, query_name_prefix="test.aliyun_storage")
        with sessions("verify_actual_login") as db:
            identity = db.execute(
                sa.text(
                    "SELECT current_user,rolsuper,rolbypassrls "
                    "FROM pg_roles WHERE rolname=current_user"
                )
            ).one()
            assert identity == (role, False, False)
            assert list(db.scalars(sa.select(RuntimeResourceBindingRecord.id))) == []
        for scope, visible in ((first, expected[0]), (other, expected[1])):
            with sessions("inspect_space_binding_inventory") as db:
                apply_rls_context(
                    db,
                    RlsContext(
                        actor_id=scope.owner_id, tenant_id=scope.tenant_id, space_id=scope.space_id
                    ),
                )
                rows = list(db.scalars(sa.select(RuntimeResourceBindingRecord)))
                assert {row.id for row in rows} == visible
                assert {row.project_id for row in rows} == {None, scope.project_id}
        with sessions("verify_context_does_not_leak_between_transactions") as db:
            assert list(db.scalars(sa.select(RuntimeResourceBindingRecord.id))) == []
    finally:
        if app is not None:
            app.dispose()
        with admin.begin() as db:
            exists = db.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:role"), {"role": role}
            )
            if exists:
                db.exec_driver_sql(f"DROP OWNED BY {quote(role)}")
                db.exec_driver_sql(f"DROP ROLE {quote(role)}")
        admin.dispose()
