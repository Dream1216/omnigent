from __future__ import annotations

from hashlib import sha256

import pytest
import sqlalchemy as sa
from alembic import command

from saas.control_plane.execution_models import RunEventRecord, RunRecord
from saas.control_plane.migrations.versions.lm2k00000001_interactive_physical_recovery import (
    _BODY as _ORPHAN_BODY,
)
from saas.control_plane.migrations.versions.lm2o00000001_terminal_physical_recovery import _BODY
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling import SchedulingControlPlane, SchedulingError
from saas.control_plane.scheduling_models import CapabilityTokenRecord, RunDispatchRecord
from tests.saas.test_control_plane_migration import _migration_config
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_credentials_postgresql import _claim
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@pytest.mark.parametrize("terminal", ("cancelled", "succeeded", "failed", "timed_out", "orphaned"))
def test_real_executor_confirms_released_terminal_without_reopening_execution(
    interactive_postgresql, terminal
):
    f = interactive_postgresql.base
    with _worker_logins(f) as workers:
        _, _, lease, control, machine = _claim(
            interactive_postgresql, workers, include_controller=True
        )
        scheduling = SchedulingControlPlane(workers["executor"])
        values = {
            **machine,
            "run_id": lease.run_id,
            "fence_token": lease.fence_token,
            "capability_token": lease.capability_token,
            "proof_sha256": "b" * 64,
            "certificate_fingerprint_sha256": "a" * 64,
            "expected_product_revision": "c" * 40,
            "product_image_digest": "sha256:" + "a" * 64,
        }

        def write(factory, fence):
            with factory.begin() as db:
                apply_rls_context(
                    db,
                    RlsContext(
                        actor_id=f.scope.owner_id,
                        tenant_id=f.scope.tenant_id,
                        space_id=f.scope.space_id,
                        project_id=f.scope.project_id,
                    ),
                )
                db.execute(
                    sa.update(RunDispatchRecord)
                    .where(RunDispatchRecord.run_id == lease.run_id)
                    .values(physical_recovery_fence=fence)
                )

        with pytest.raises(sa.exc.IntegrityError) as active:
            write(workers["executor"], lease.fence_token)
        assert active.value.orig.sqlstate == "23514"
        for status in (*(("cancelling",) if terminal == "cancelled" else ()), terminal):
            control.transition_run(
                **machine,
                run_id=lease.run_id,
                lease_token=lease.lease_token,
                fence_token=lease.fence_token,
                capability_token=lease.capability_token,
                target_status=status,
            )
        with pytest.raises(SchedulingError, match="pending"):
            scheduling.confirm_interactive_recovery(**values)
        control.release_run(**machine, run_id=lease.run_id, fence_token=lease.fence_token)
        with pytest.raises(sa.exc.IntegrityError) as wrong_fence:
            write(workers["executor"], lease.fence_token + 1)
        assert wrong_fence.value.orig.sqlstate == "23514"
        with pytest.raises(sa.exc.DBAPIError) as customer:
            write(f.app_factory, lease.fence_token)
        assert customer.value.orig.sqlstate == "42501"
        assert scheduling.confirm_interactive_recovery(**values) is False
        assert scheduling.confirm_interactive_recovery(**values) is True
        with f.factory() as db:
            assert db.get(RunRecord, lease.run_id).status == terminal
            assert (
                db.get(RunDispatchRecord, lease.run_id).physical_recovery_fence
                == lease.fence_token
            )
            assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is not None
            events = db.scalars(
                sa.select(RunEventRecord).where(
                    RunEventRecord.run_id == lease.run_id,
                    RunEventRecord.event_type == "run.interactive_physical_recovered",
                )
            ).all()
            assert len(events) == 1 and events[0].payload["proof_sha256"] == "b" * 64
        with pytest.raises(sa.exc.IntegrityError) as immutable:
            write(workers["executor"], None)
        assert immutable.value.orig.sqlstate == "23514"

        if terminal == "cancelled":
            with f.engine.begin() as db:
                config = _migration_config(db)
                signature = "public.saas_interactive_physical_recovery_guard_v1()"
                original = db.execute(
                    sa.text(
                        "SELECT proowner,proacl::text FROM pg_proc WHERE oid=to_regprocedure(:s)"
                    ),
                    {"s": signature},
                ).one()
                db.exec_driver_sql(f"GRANT CREATE ON SCHEMA public TO {f.table_owner}")
                db.exec_driver_sql(f"SET LOCAL ROLE {f.table_owner}")
                for target, body in (("lm2n00000001", _ORPHAN_BODY), ("head", _BODY)):
                    if target == "head":
                        command.upgrade(config, target)
                    else:
                        command.downgrade(config, target)
                    observed = db.execute(
                        sa.text(
                            "SELECT proowner,proacl::text,prosrc FROM pg_proc "
                            "WHERE oid=to_regprocedure(:s)"
                        ),
                        {"s": signature},
                    ).one()
                    assert tuple(observed[:2]) == tuple(original)
                    assert (
                        sha256(observed.prosrc.encode()).digest() == sha256(body.encode()).digest()
                    )
                db.exec_driver_sql("RESET ROLE")
                db.exec_driver_sql(f"REVOKE CREATE ON SCHEMA public FROM {f.table_owner}")
                assert (
                    db.scalar(
                        sa.select(RunDispatchRecord.physical_recovery_fence).where(
                            RunDispatchRecord.run_id == lease.run_id
                        )
                    )
                    == lease.fence_token
                )
