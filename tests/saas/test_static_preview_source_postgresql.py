"""Read frozen source metadata with the production non-bypass application role."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import sqlalchemy as sa

from saas.control_plane.preview_execution import PreviewExecutionControlPlane
from saas.control_plane.preview_models import PreviewExecutionRecord
from saas.control_plane.rls import RlsContext, apply_rls_context
from tests.saas.test_worktree_postgresql import _migrate, _role_factory, _seed_scope


def test_frozen_preview_source_is_readable_only_in_its_postgresql_scope(isolated_postgres_url):
    engine = sa.create_engine(isolated_postgres_url)
    scope = {key: uuid4() for key in ("actor", "tenant", "space", "project", "run")}
    try:
        with engine.begin() as connection:
            root = Path(__file__).resolve().parents[2]
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            _seed_scope(
                connection,
                actor_id=scope["actor"],
                tenant_id=scope["tenant"],
                space_id=scope["space"],
                project_id=scope["project"],
                run_id=scope["run"],
                task_id=uuid4(),
                execution_profile_id=uuid4(),
                execution_profile_hash="a" * 64,
                repository_id=uuid4(),
                group_id=uuid4(),
                change_set_id=uuid4(),
                quota_id=uuid4(),
                suffix="a-static-source",
            )
            connection.execute(
                sa.text("UPDATE saas_runs SET input=CAST(:payload AS jsonb) WHERE id=:id"),
                {
                    "id": scope["run"],
                    "payload": '{"execution":{"checkpoint_revision":"' + "a" * 40 + '"}}',
                },
            )
        state = PreviewExecutionRecord(
            id=uuid4(),
            tenant_id=scope["tenant"],
            space_id=scope["space"],
            project_id=scope["project"],
            source_run_id=uuid4(),
            child_run_id=scope["run"],
            status="failed",
            preview_host="fixture.preview.test",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            failure_code="preview_entry_unavailable",
        )
        factory = _role_factory(engine, "saas_app")
        with factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=scope["actor"],
                    tenant_id=scope["tenant"],
                    space_id=scope["space"],
                    project_id=scope["project"],
                ),
            )
            assert db.scalar(sa.text("SELECT current_user")) == "saas_app"
            assert not db.scalar(
                sa.text("SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user")
            )
            result = PreviewExecutionControlPlane._state(db, state, replayed=True)
            assert result.source_sha == "a" * 40
            assert result.failure_code == "preview_entry_unavailable"
        with factory.begin() as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=scope["actor"],
                    tenant_id=uuid4(),
                    space_id=uuid4(),
                    project_id=uuid4(),
                ),
            )
            assert PreviewExecutionControlPlane._state(db, state, replayed=True).source_sha is None
    finally:
        engine.dispose()
