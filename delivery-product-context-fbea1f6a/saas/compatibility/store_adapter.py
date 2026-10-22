"""Trusted adapter boundary for invoking official workspace-scoped stores."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, TypeVar

import sqlalchemy as sa
from sqlalchemy.orm import Session

from omnigent.db.db_models import workspace_scope
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

    @contextmanager
    def bind(self, runtime: RuntimeContext) -> Iterator[RuntimeContext]:
        """Bind both workspace contexts for every Store transaction in one operation."""

        self._validate_runtime(runtime)
        with (
            bind_runtime_context(runtime),
            bind_managed_session_initializer(self._initialize_official_session),
        ):
            yield runtime

    def invoke(self, runtime: RuntimeContext, operation: Callable[[], T]) -> T:
        """Run an official Store call under the server-derived physical workspace."""

        with self.bind(runtime):
            return operation()

    @contextmanager
    def bind_host_credential_workspace(self, workspace_id: int) -> Iterator[int]:
        """Bind an untrusted Host credential routing hint for token validation.

        The selector is not authorization.  This narrow context manager is
        used only for ``/v1/hosts/{id}/tunnel`` while the official Host route
        validates the path-bound machine token inside the selected workspace.
        No other runtime route may derive authority from this binding.
        """

        with self.bind_machine_credential_workspace(
            workspace_id,
            credential_kind="host",
        ):
            yield workspace_id

    @contextmanager
    def bind_machine_credential_workspace(
        self,
        workspace_id: int,
        *,
        credential_kind: str,
    ) -> Iterator[int]:
        """Bind a routing-only workspace for an exact machine credential route."""

        if credential_kind not in {"host", "runner"}:
            raise ValueError("machine credential kind is not supported")
        if workspace_id <= 0:
            raise StoreAdapterContractError(
                f"{credential_kind}_machine_workspace_invalid",
                f"{credential_kind.title()} machine credential workspace must be positive",
            )

        def initialize(session: Session) -> None:
            self._initialize_workspace_session(session, workspace_id)

        with workspace_scope(workspace_id), bind_managed_session_initializer(initialize):
            yield workspace_id

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
        OmnigentStoreAdapter._initialize_workspace_session(session, runtime.physical_workspace_id)

    @staticmethod
    def _initialize_workspace_session(session: Session, workspace_id: int) -> None:
        if session.get_bind().dialect.name != "postgresql":
            return
        session.execute(
            sa.text("SELECT set_config('app.runtime_workspace_id', :value, true)"),
            {"value": str(workspace_id)},
        )
