from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.entities import Conversation
from omnigent.server.schemas import SessionEventInput
from saas.compatibility import bind_runtime_context
from saas.control_plane import (
    AdmissionQuotaRecord,
    ExecutionRevisionSet,
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord, TaskRecord
from saas.control_plane.interactive_execution import RuntimeSessionRunAdmission
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord
from tests.saas.test_interactive_execution_http import _launch, _message
from tests.saas.test_run_customer_pricing import _plan
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution
from tests.saas.test_tenant_model_catalog_postgresql import _published


@pytest.fixture
def interactive_postgresql(priced_execution, monkeypatch):
    f = priced_execution
    _catalog, runtime = _published(f, monkeypatch)
    placement_id, partition_id, runtime_project_id = uuid4(), uuid4(), uuid4().hex
    runtime = replace(runtime, placement_id=placement_id, runtime_partition_id=partition_id)
    _plan(f.factory, f.scope)
    with f.factory.begin() as db:
        publication = db.scalars(sa.select(ModelPublicationVersionRecord)).one()
        marker = {
            "schema_version": 1,
            "public_model_id": publication.public_model_id,
            "wire_api": publication.wire_api,
            "generation": publication.generation,
            "snapshot_sha256": publication.snapshot_sha256,
        }
        db.add(
            RuntimePlacementRecord(
                id=placement_id,
                runtime_type=runtime.runtime_type,
                data_region=runtime.data_region,
                failure_domain="isolated",
                database_cluster_ref="isolated",
                object_store_ref="isolated",
                kms_key_ref="isolated",
                official_schema_revision="test-schema",
                capacity_class="isolated",
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimePartitionRecord(
                id=partition_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                placement_id=placement_id,
                runtime_type=runtime.runtime_type,
                runtime_version="0.9.0.dev0",
                physical_partition_key=str(runtime.physical_workspace_id),
                placement_generation=runtime.placement_generation,
                source_revision=runtime.source_revision,
                adapter_contract_version=runtime.adapter_contract_version,
                status="active",
            )
        )
        db.flush()
        db.add(
            RuntimeIdentityAliasRecord(
                runtime_partition_id=partition_id,
                user_id=runtime.actor_id,
                runtime_user_key=runtime.runtime_user_key,
                status="active",
            )
        )
        db.add(
            RuntimeResourceBindingRecord(
                runtime_partition_id=partition_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=runtime.project_id,
                resource_type="project",
                runtime_resource_id=runtime_project_id,
                saas_resource_id=runtime.project_id,
                partition_generation=runtime.placement_generation,
                binding_generation=1,
                status="active",
            )
        )
        db.add(
            AdmissionQuotaRecord(
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=runtime.project_id,
                resource="run",
                limit_units=2,
                reserved_units=0,
                consumed_units=0,
                version=1,
            )
        )
    runtime_session_id = uuid4().hex
    conversation = Conversation(
        id=runtime_session_id,
        root_conversation_id=runtime_session_id,
        created_at=1,
        updated_at=1,
        project_id=runtime_project_id,
        agent_id="b" * 32,
        host_id="c" * 32,
        workspace="/workspace",
        model_override=marker["public_model_id"],
        inference_snapshot={"managed_execution": marker, "managed_launch": _launch()},
    )
    service = RuntimeSessionRunAdmission(
        f.app_factory,
        revisions=ExecutionRevisionSet("c" * 40, runtime.source_revision, "test-schema", "0.2.0"),
    )
    return SimpleNamespace(base=f, runtime=runtime, conversation=conversation, service=service)


def test_actual_app_login_binds_one_session_and_admits_one_run_under_duplicate_race(
    interactive_postgresql,
):
    fixture = interactive_postgresql
    f, runtime = fixture.base, fixture.runtime
    service, conversation = fixture.service, fixture.conversation
    barrier = Barrier(4)

    def admit(_index):
        with bind_runtime_context(runtime):
            barrier.wait(timeout=15)
            return service.dispatch(
                runtime,
                conversation,
                SessionEventInput.model_validate(_message()),
                created_by=runtime.runtime_user_key,
            )

    with ThreadPoolExecutor(max_workers=4) as pool:
        admitted = list(pool.map(admit, range(4)))
    assert len({result["run_id"] for result in admitted}) == 1
    with f.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
        session = db.scalars(sa.select(ExecutionSessionRecord)).one()
        assert session.customer_pricing_frozen and session.customer_pricing_snapshot_id
        assert str(session.id).replace("-", "") != conversation.id
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 1
    with f.app.connect() as connection:
        assert connection.exec_driver_sql("SELECT current_user=session_user").scalar_one()
        assert not connection.exec_driver_sql(
            "SELECT has_table_privilege(current_user,'saas_runtime_resource_bindings','INSERT')"
        ).scalar_one()
        assert connection.exec_driver_sql("SELECT count(*) FROM saas_runs").scalar_one() == 0
