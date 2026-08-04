"""Trusted adapter boundary for invoking official workspace-scoped stores."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.utils import bind_managed_session_initializer
from saas.compatibility.runtime_partition import RuntimeContext, bind_runtime_context

T = TypeVar("T")


class WorkspaceOwnedRecord(Protocol):
    @property
    def workspace_id(self) -> int: ...


class StoreAdapterContractError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class OmnigentStoreAdapter:
    """Bind a reviewed RuntimeContext before any official Store invocation."""

    adapter_contract_version: str

    def __post_init__(self) -> None:
        if not self.adapter_contract_version.strip():
            raise ValueError("adapter contract version must not be empty")

    def invoke(self, runtime: RuntimeContext, operation: Callable[[], T]) -> T:
        """Run an official Store call under the server-derived physical workspace."""

        self._validate_runtime(runtime)
        with (
            bind_runtime_context(runtime),
            bind_managed_session_initializer(self._initialize_official_session),
        ):
            return operation()

    def require_owned_record(self, runtime: RuntimeContext, record: WorkspaceOwnedRecord) -> None:
        """Reject naked-ID results from another physical Runtime Partition."""

        self._validate_runtime(runtime)
        if record.workspace_id != runtime.physical_workspace_id:
            raise StoreAdapterContractError(
                "store_workspace_mismatch",
                "official Store returned a record from another Runtime Partition",
            )

    def _validate_runtime(self, runtime: RuntimeContext) -> None:
        if runtime.adapter_contract_version != self.adapter_contract_version:
            raise StoreAdapterContractError(
                "adapter_contract_mismatch",
                "RuntimeContext adapter contract is not supported by this Store Adapter",
            )
        if runtime.physical_workspace_id <= 0:
            raise StoreAdapterContractError(
                "default_workspace_forbidden", "SaaS Store Adapter cannot enter workspace 0"
            )
        if runtime.binding_generation < 1 or runtime.placement_generation < 1:
            raise StoreAdapterContractError(
                "runtime_generation_invalid", "RuntimeContext generations must be positive"
            )

    @staticmethod
    def _initialize_official_session(session: Session) -> None:
        if session.get_bind().dialect.name != "postgresql":
            return
        from saas.compatibility.runtime_partition import current_runtime_context

        runtime = current_runtime_context()
        session.execute(
            sa.text("SELECT set_config('app.runtime_workspace_id', :value, true)"),
            {"value": str(runtime.physical_workspace_id)},
        )
