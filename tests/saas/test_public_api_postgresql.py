from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credentials import ValidatedApiCredential
from saas.control_plane.api_http import create_public_api_router
from saas.control_plane.http_auth import SaasMachinePrincipal
from saas.control_plane.public_api import PublicApiError, PublicApiExecutionService
from saas.public_api_contract import PUBLIC_API_PREFIX, FilterBoundCursorCodec


def _migration_config(connection: sa.Connection, root: Path) -> Config:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


def _public_service(factory: sessionmaker[Session]) -> PublicApiExecutionService:
    return PublicApiExecutionService(
        factory,
        cursor_codec=FilterBoundCursorCodec(
            keys={"2026-08": b"public-api-cursor-acceptance-key-v1"},
            active_key_id="2026-08",
        ),
        idempotency_keys={"2026-08": b"public-api-idempotency-accept-key-v1"},
        active_idempotency_key_id="2026-08",
        product_revision="product-acceptance",
        upstream_revision="upstream-acceptance",
        schema_revision="pc5a00000005",
        adapter_contract_version="v1",
        rate_limits={
            "projects.read": (3, timedelta(minutes=1)),
            "runs.read": (10, timedelta(minutes=1)),
            "runs.write": (10, timedelta(minutes=1)),
            "events.read": (10, timedelta(minutes=1)),
        },
    )


def _set_public_context(
    connection: sa.Connection,
    *,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    service_account_id: UUID,
    credential_id: UUID,
) -> None:
    connection.execute(
        sa.text(
            "SELECT set_config('app.tenant_id', :tenant, true), "
            "set_config('app.space_id', :space, true), "
            "set_config('app.project_id', :project, true), "
            "set_config('app.actor_id', :actor, true), "
            "set_config('app.api_credential_id', :credential, true)"
        ),
        {
            "tenant": str(tenant_id),
            "space": str(space_id),
            "project": str(project_id),
            "actor": str(service_account_id),
            "credential": str(credential_id),
        },
    )


def test_public_api_real_role_rls_provenance_rate_and_idempotency(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    owner_id, steward_id = uuid4(), uuid4()
    tenant_id, space_id, project_id = uuid4(), uuid4(), uuid4()
    service_account_id, credential_id = uuid4(), uuid4()
    quota_id = uuid4()
    now = datetime.now(timezone.utc)
    scopes = (
        "project.read_metadata",
        "run.create",
        "run.read_metadata",
        "run.read_content",
        "run.cancel",
        "run.retry",
    )

    with engine.begin() as connection:
        migration = _migration_config(connection, root)
        command.upgrade(migration, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        command.downgrade(migration, "pc5c00000002")
        assert (
            connection.execute(
                sa.text("SELECT to_regclass('saas_public_api_mutation_receipts')")
            ).scalar_one_or_none()
            is None
        )
        assert (
            connection.execute(
                sa.text(
                    "SELECT has_column_privilege("
                    "'saas_public_api', 'saas_tenant_memberships', 'tenant_id', 'SELECT')"
                )
            ).scalar_one()
            is False
        )
        command.upgrade(migration, "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        assert (
            connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            == "p0s000000011"
        )
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) VALUES "
                "(:owner, 'active', 1), (:steward, 'active', 1)"
            ),
            {"owner": owner_id, "steward": steward_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region) VALUES "
                "(:tenant, :slug, 'Public API', 'active', 'team', 'cn-east-1')"
            ),
            {"tenant": tenant_id, "slug": f"public-api-{tenant_id.hex}"},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_memberships "
                "(tenant_id, user_id, role, status, version) VALUES "
                "(:tenant, :owner, 'owner', 'active', 1), "
                "(:tenant, :steward, 'member', 'active', 1)"
            ),
            {"tenant": tenant_id, "owner": owner_id, "steward": steward_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
                "(:space, :tenant, 'api', 'API', 'active')"
            ),
            {"space": space_id, "tenant": tenant_id},
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_space_memberships "
                "(tenant_id, space_id, user_id, role, status, version) VALUES "
                "(:tenant, :space, :owner, 'owner', 'active', 1), "
                "(:tenant, :space, :steward, 'member', 'active', 1)"
            ),
            {
                "tenant": tenant_id,
                "space": space_id,
                "owner": owner_id,
                "steward": steward_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_projects "
                "(id, tenant_id, space_id, name, visibility, created_by, status, "
                "authorization_version) VALUES "
                "(:project, :tenant, :space, 'API Project', 'private', :owner, 'active', 1)"
            ),
            {
                "project": project_id,
                "tenant": tenant_id,
                "space": space_id,
                "owner": owner_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_service_accounts "
                "(id, tenant_id, space_id, project_id, name, steward_user_id, created_by, "
                "status, security_version) VALUES "
                "(:account, :tenant, :space, :project, 'public-bot', :steward, :owner, "
                "'active', 1)"
            ),
            {
                "account": service_account_id,
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
                "steward": steward_id,
                "owner": owner_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_api_credentials "
                "(id, tenant_id, service_account_id, name, token_hash, display_prefix, "
                "permission_scopes, allowed_networks, account_security_version, status, "
                "expires_at, created_by) VALUES "
                "(:credential, :tenant, :account, 'key', :token_hash, :prefix, "
                "CAST(:scopes AS json), CAST('[]' AS json), 1, 'active', :expires, :owner)"
            ),
            {
                "credential": credential_id,
                "tenant": tenant_id,
                "account": service_account_id,
                "token_hash": uuid4().hex + uuid4().hex,
                "prefix": f"omni_{credential_id.hex[:16]}",
                "scopes": json.dumps(scopes),
                "expires": now + timedelta(days=1),
                "owner": owner_id,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_admission_quotas "
                "(id, tenant_id, space_id, project_id, resource, limit_units, "
                "reserved_units, consumed_units, version) VALUES "
                "(:quota, :tenant, :space, :project, 'run', 100, 0, 0, 1)"
            ),
            {
                "quota": quota_id,
                "tenant": tenant_id,
                "space": space_id,
                "project": project_id,
            },
        )

    public_sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(public_sessions, "after_begin")
    def _use_public_role(
        _session: Session, _transaction: object, connection: sa.Connection
    ) -> None:
        connection.exec_driver_sql("SET LOCAL ROLE saas_public_api")

    principal = ValidatedApiCredential(
        credential_id=credential_id,
        service_account_id=service_account_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        security_version=1,
        permission_scopes=frozenset(scopes),
        authenticated_at=now,
        expires_at=now + timedelta(days=1),
    )
    service = _public_service(public_sessions)

    class _AuthenticatedMachine:
        @staticmethod
        def get_machine_principal(_request: object) -> SaasMachinePrincipal:
            return SaasMachinePrincipal(credential=principal)

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(
        create_public_api_router(
            auth_provider=_AuthenticatedMachine(),  # type: ignore[arg-type]
            public_execution=service,
        ),
        prefix=PUBLIC_API_PREFIX,
    )
    http_project = TestClient(app).get(
        f"/api/v1/projects/{project_id}",
        headers={"X-Request-Id": "public-postgres-http"},
    )
    assert http_project.status_code == 200
    assert http_project.headers["ETag"] == 'W/"1"'
    assert http_project.json()["id"] == str(project_id)
    assert service.get_project(principal, project_id=project_id).id == project_id
    first_limit = service.consume_rate_limit(
        principal,
        project_id=project_id,
        permission="project.read_metadata",
        route_class="projects.read",
        now=now,
    )
    second_limit = service.consume_rate_limit(
        principal,
        project_id=project_id,
        permission="project.read_metadata",
        route_class="projects.read",
        now=now,
    )
    assert (first_limit.remaining, second_limit.remaining) == (1, 0)
    with pytest.raises(PublicApiError, match="Shared API rate limit exceeded") as limited:
        service.consume_rate_limit(
            principal,
            project_id=project_id,
            permission="project.read_metadata",
            route_class="projects.read",
            now=now,
        )
    assert limited.value.code == "rate_limit_exceeded"

    created = service.create_run(
        principal,
        project_id=project_id,
        title="Public run",
        input_payload={"prompt": "hello"},
        session_id=None,
        metadata={"caller": "acceptance"},
        idempotency_key="create-once",
        trace_id="public-api-acceptance",
    )
    replayed = service.create_run(
        principal,
        project_id=project_id,
        title="Public run",
        input_payload={"prompt": "hello"},
        session_id=None,
        metadata={"caller": "acceptance"},
        idempotency_key="create-once",
        trace_id="public-api-acceptance",
    )
    assert replayed.id == created.id
    assert replayed.replayed is True
    with pytest.raises(PublicApiError) as conflict:
        service.create_run(
            principal,
            project_id=project_id,
            title="Changed request",
            input_payload={"prompt": "different"},
            session_id=None,
            metadata={},
            idempotency_key="create-once",
            trace_id="public-api-acceptance",
        )
    assert conflict.value.code == "idempotency_conflict"

    def _parallel_create() -> tuple[UUID, bool]:
        view = service.create_run(
            principal,
            project_id=project_id,
            title="Parallel",
            input_payload={"parallel": True},
            session_id=None,
            metadata={},
            idempotency_key="parallel-create",
            trace_id="public-api-parallel",
        )
        return view.id, view.replayed

    with ThreadPoolExecutor(max_workers=2) as pool:
        parallel = tuple(pool.map(lambda _index: _parallel_create(), range(2)))
    assert len({run_id for run_id, _replayed in parallel}) == 1
    assert sorted(replayed for _run_id, replayed in parallel) == [False, True]

    content = service.get_run_content(principal, project_id=project_id, run_id=created.id)
    assert content.input == {"prompt": "hello"}
    events = service.list_run_events(
        principal,
        project_id=project_id,
        run_id=created.id,
        cursor=None,
        limit=100,
    )
    assert [event.event_type for event in events.items] == ["run.created", "run.queued"]

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_public_api")
        _set_public_context(
            connection,
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            service_account_id=service_account_id,
            credential_id=credential_id,
        )
        assert (
            connection.execute(
                sa.text("SELECT count(*) FROM saas_tenant_memberships")
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(sa.text("SELECT count(*) FROM saas_space_memberships")).scalar_one()
            == 0
        )
        with pytest.raises(DBAPIError) as forged:
            connection.execute(
                sa.text(
                    "UPDATE saas_runs SET created_by_service_account_id = NULL WHERE id = :id"
                ),
                {"id": created.id},
            )
        assert getattr(forged.value.orig, "sqlstate", None) in {"23514", "42501", "P0001"}

    with engine.begin() as connection:
        connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
        connection.execute(
            sa.text(
                "UPDATE saas_api_credentials SET status = 'revoked', revoked_at = :now "
                "WHERE id = :credential"
            ),
            {"now": now, "credential": credential_id},
        )
    with pytest.raises(PublicApiError) as revoked:
        service.get_project(principal, project_id=project_id)
    assert revoked.value.code == "invalid_api_credential"

    engine.dispose()
