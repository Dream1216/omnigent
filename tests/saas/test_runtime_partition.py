from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from omnigent.db.db_models import DEFAULT_WORKSPACE_ID, current_workspace_id
from saas.compatibility import (
    BindingStatus,
    PartitionStatus,
    RequestContext,
    RuntimeIdentityAlias,
    RuntimePartition,
    RuntimeResolutionError,
    RuntimeResourceBinding,
    bind_runtime_context,
    current_runtime_context,
    resolve_runtime_context,
)


def _records():
    tenant_id = uuid4()
    space_id = uuid4()
    project_id = uuid4()
    actor_id = uuid4()
    partition_id = uuid4()
    request = RequestContext(
        actor_id=actor_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        user_security_version=2,
        tenant_membership_version=3,
        space_membership_version=7,
        trace_id="trace-runtime-p0",
    )
    partition = RuntimePartition(
        id=partition_id,
        tenant_id=tenant_id,
        space_id=space_id,
        placement_id=uuid4(),
        placement_generation=4,
        physical_workspace_id=41,
        runtime_type="omnigent",
        data_region="cn-east-1",
        source_revision="2ce9c60bf57e168bdd4d7e6236e68e18ebb4bb9f",
        adapter_contract_version="0.2.0",
        status=PartitionStatus.ACTIVE,
    )
    alias = RuntimeIdentityAlias(
        runtime_partition_id=partition_id,
        user_id=actor_id,
        runtime_user_key="user_7f7b",
        status=BindingStatus.ACTIVE,
    )
    binding = RuntimeResourceBinding(
        id=uuid4(),
        runtime_partition_id=partition_id,
        tenant_id=tenant_id,
        space_id=space_id,
        project_id=project_id,
        resource_type="conversation",
        runtime_resource_id="conv_123",
        saas_resource_id=uuid4(),
        partition_generation=4,
        binding_generation=2,
        status=BindingStatus.ACTIVE,
    )
    return request, partition, alias, binding


def test_resolves_and_binds_official_workspace_scope() -> None:
    request, partition, alias, binding = _records()
    runtime = resolve_runtime_context(request, partition, alias, binding)

    assert current_workspace_id() == DEFAULT_WORKSPACE_ID
    with bind_runtime_context(runtime):
        assert current_workspace_id() == 41
        assert current_runtime_context() == runtime
        assert current_runtime_context().placement_generation == 4
    assert current_workspace_id() == DEFAULT_WORKSPACE_ID


def test_nested_scope_restores_previous_runtime_context() -> None:
    records = _records()
    outer = resolve_runtime_context(*records)
    request, partition, alias, binding = _records()
    inner = resolve_runtime_context(
        request, replace(partition, physical_workspace_id=52), alias, binding
    )

    with bind_runtime_context(outer):
        with bind_runtime_context(inner):
            assert current_workspace_id() == 52
            assert current_runtime_context() == inner
        assert current_workspace_id() == outer.physical_workspace_id
        assert current_runtime_context() == outer


@pytest.mark.parametrize(
    ("partition_update", "error_code"),
    [
        ({"status": PartitionStatus.DRAINING}, "partition_not_active"),
        ({"physical_workspace_id": 0}, "default_workspace_forbidden"),
        ({"tenant_id": uuid4()}, "tenant_scope_mismatch"),
        ({"space_id": uuid4()}, "space_scope_mismatch"),
    ],
)
def test_partition_mismatch_fails_closed(partition_update, error_code: str) -> None:
    request, partition, alias, binding = _records()

    with pytest.raises(RuntimeResolutionError) as exc_info:
        resolve_runtime_context(request, replace(partition, **partition_update), alias, binding)

    assert exc_info.value.code == error_code
    assert current_workspace_id() == DEFAULT_WORKSPACE_ID


def test_stale_resource_binding_generation_is_rejected() -> None:
    request, partition, alias, binding = _records()

    with pytest.raises(RuntimeResolutionError) as exc_info:
        resolve_runtime_context(
            request,
            replace(partition, placement_generation=5),
            alias,
            binding,
        )

    assert exc_info.value.code == "binding_generation_stale"


def test_cross_project_resource_binding_is_rejected() -> None:
    request, partition, alias, binding = _records()

    with pytest.raises(RuntimeResolutionError) as exc_info:
        resolve_runtime_context(request, partition, alias, replace(binding, project_id=uuid4()))

    assert exc_info.value.code == "binding_project_mismatch"


def test_suspended_identity_alias_is_rejected() -> None:
    request, partition, alias, binding = _records()

    with pytest.raises(RuntimeResolutionError) as exc_info:
        resolve_runtime_context(
            request,
            partition,
            replace(alias, status=BindingStatus.SUSPENDED),
            binding,
        )

    assert exc_info.value.code == "identity_alias_not_active"


def test_current_runtime_context_fails_when_unbound() -> None:
    with pytest.raises(RuntimeError, match="not bound"):
        current_runtime_context()
