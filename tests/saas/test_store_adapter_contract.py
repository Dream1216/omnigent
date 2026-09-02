from __future__ import annotations

from dataclasses import dataclass, replace
from uuid import uuid4

import pytest
import sqlalchemy as sa

from omnigent.db.db_models import current_workspace_id
from omnigent.db.utils import (
    bind_managed_session_initializer,
    make_managed_session_maker,
    shared_read_scope,
)
from saas.compatibility import (
    OmnigentStoreAdapter,
    RuntimeContext,
    StoreAdapterContractError,
    current_runtime_context,
)


def _runtime() -> RuntimeContext:
    return RuntimeContext(
        actor_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        runtime_partition_id=uuid4(),
        placement_id=uuid4(),
        placement_generation=2,
        binding_generation=3,
        data_region="cn-east-1",
        physical_workspace_id=91,
        runtime_user_key="runtime-user",
        runtime_type="omnigent",
        source_revision="reviewed-revision",
        adapter_contract_version="0.2.0",
        trace_id="store-contract",
    )


def test_store_adapter_binds_and_restores_both_runtime_contexts() -> None:
    runtime = _runtime()
    adapter = OmnigentStoreAdapter("0.2.0")
    observed = adapter.invoke(
        runtime,
        lambda: (
            current_workspace_id(),
            current_runtime_context().runtime_partition_id,
        ),
    )

    assert observed == (91, runtime.runtime_partition_id)
    assert current_workspace_id() == 0
    with pytest.raises(RuntimeError, match="runtime context is not bound"):
        current_runtime_context()


def test_store_adapter_bind_initializes_every_real_managed_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sa.create_engine("sqlite://")
    managed_session = make_managed_session_maker(engine)
    initialized: list[sa.orm.Session] = []

    monkeypatch.setattr(
        OmnigentStoreAdapter,
        "_initialize_official_session",
        staticmethod(initialized.append),
    )
    adapter = OmnigentStoreAdapter("0.2.0")
    runtime = _runtime()
    try:
        with adapter.bind(runtime):
            with managed_session() as database:
                assert database.scalar(sa.select(sa.literal(1))) == 1
                assert current_workspace_id() == runtime.physical_workspace_id
                assert current_runtime_context() is runtime

        assert initialized == [database]
        assert current_workspace_id() == 0
        with pytest.raises(RuntimeError, match="runtime context is not bound"):
            current_runtime_context()
    finally:
        engine.dispose()


def test_store_adapter_rejects_unreviewed_contract_before_invocation() -> None:
    called = False

    def _operation() -> None:
        nonlocal called
        called = True

    with pytest.raises(StoreAdapterContractError) as exc_info:
        OmnigentStoreAdapter("0.3.0").invoke(_runtime(), _operation)
    assert exc_info.value.code == "adapter_contract_mismatch"
    assert called is False


@dataclass(frozen=True, slots=True)
class _Record:
    workspace_id: int


def test_store_adapter_rejects_cross_partition_record() -> None:
    runtime = _runtime()
    adapter = OmnigentStoreAdapter("0.2.0")

    adapter.require_owned_record(runtime, _Record(workspace_id=91))
    with pytest.raises(StoreAdapterContractError) as exc_info:
        adapter.require_owned_record(runtime, _Record(workspace_id=92))
    assert exc_info.value.code == "store_workspace_mismatch"


def test_store_adapter_rejects_invalid_generation() -> None:
    adapter = OmnigentStoreAdapter("0.2.0")
    with pytest.raises(StoreAdapterContractError) as exc_info:
        adapter.invoke(replace(_runtime(), binding_generation=0), lambda: None)
    assert exc_info.value.code == "runtime_generation_invalid"


def test_managed_initializer_bypasses_shared_read_session() -> None:
    engine = sa.create_engine("sqlite://")
    managed_session = make_managed_session_maker(engine)
    initialized: list[sa.orm.Session] = []

    with bind_managed_session_initializer(initialized.append), shared_read_scope():
        with managed_session() as first:
            first.execute(sa.text("SELECT 1"))
        with managed_session() as second:
            second.execute(sa.text("SELECT 1"))

    assert initialized == [first, second]
    assert first is not second
    engine.dispose()
