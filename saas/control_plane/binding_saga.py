"""Durable Saga for official-runtime resource creation and control-plane Binding."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.bindings import RuntimeBindingService
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    RuntimeBindingSagaRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.rls import RlsContext, apply_rls_context


class RuntimeProvisioningError(RuntimeError):
    """Stable failure reported by a Placement-specific official-runtime adapter."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ProvisioningTarget:
    """Server-loaded Placement/Partition facts passed to a trusted provisioner."""

    runtime_partition_id: UUID
    placement_id: UUID
    tenant_id: UUID
    space_id: UUID
    runtime_type: str
    physical_partition_key: str
    partition_generation: int
    data_region: str


class RuntimeResourceProvisioner(Protocol):
    """Idempotent adapter for the official runtime database or service."""

    def provision(
        self,
        *,
        target: ProvisioningTarget,
        resource_type: str,
        saas_resource_id: UUID,
        idempotency_key: str,
    ) -> str: ...

    def compensate(
        self,
        *,
        target: ProvisioningTarget,
        resource_type: str,
        runtime_resource_id: str,
        idempotency_key: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RuntimeBindingSagaResult:
    saga_id: UUID
    status: str
    runtime_resource_id: str | None
    binding_id: UUID | None
    attempt_count: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class _SagaSnapshot:
    id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    runtime_partition_id: UUID
    resource_type: str
    saas_resource_id: UUID
    runtime_resource_id: str | None
    binding_id: UUID | None
    partition_generation: int
    status: str
    attempt_count: int


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _clean_error(error: Exception) -> str:
    return str(error).strip()[:2048] or error.__class__.__name__


class RuntimeBindingSagaService:
    """Advance cross-database work one durable transition at a time."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        binding_service: RuntimeBindingService,
        authorizer: ProjectAuthorizer,
    ) -> None:
        self._session_factory = session_factory
        self._bindings = binding_service
        self._authorizer = authorizer

    def start(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        runtime_partition_id: UUID,
        resource_type: str,
        saas_resource_id: UUID,
        idempotency_key: str,
    ) -> RuntimeBindingSagaResult:
        """Persist intent before making any call to the official runtime."""

        if not idempotency_key or len(idempotency_key) > 128:
            raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")
        cleaned_type = resource_type.strip()
        if not cleaned_type or len(cleaned_type) > 64:
            raise LifecycleError("resource_type_invalid", "resource type is invalid")
        self._authorizer.require(
            request,
            action="runtime.binding.manage",
            project_id=project_id,
            resource_type=cleaned_type,
            resource_id=saas_resource_id,
        )
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "project_id": str(project_id),
            "runtime_partition_id": str(runtime_partition_id),
            "resource_type": cleaned_type,
            "saas_resource_id": str(saas_resource_id),
        }
        request_hash = _digest(payload)
        receipt_key = scoped_idempotency_key("tenant", request.tenant_id, idempotency_key)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            existing = db.execute(
                sa.select(RuntimeBindingSagaRecord).where(
                    RuntimeBindingSagaRecord.idempotency_key == receipt_key
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise LifecycleError(
                        "idempotency_conflict", "idempotency key was already used"
                    )
                return self._result(existing, replayed=True)
            target = self._load_target(
                db,
                request,
                runtime_partition_id=runtime_partition_id,
                expected_generation=None,
            )
            saga_id = uuid4()
            saga = RuntimeBindingSagaRecord(
                id=saga_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                runtime_partition_id=runtime_partition_id,
                resource_type=cleaned_type,
                saas_resource_id=saas_resource_id,
                runtime_resource_id=None,
                binding_id=None,
                partition_generation=target.partition_generation,
                status="pending",
                idempotency_key=receipt_key,
                request_hash=request_hash,
                attempt_count=0,
            )
            db.add(saga)
            self._event(
                db,
                request,
                saga_id=saga_id,
                event_type="runtime.binding_saga.started",
                suffix="started",
                payload={**payload, "saga_id": str(saga_id), "status": "pending"},
            )
            return self._result(saga, replayed=False)

    def advance(
        self,
        request: RequestContext,
        *,
        saga_id: UUID,
        provisioner: RuntimeResourceProvisioner,
    ) -> RuntimeBindingSagaResult:
        """Perform at most one resumable external transition."""

        snapshot, target = self._authorized_snapshot(request, saga_id)
        if snapshot.status in {"bound", "compensated"}:
            return self._snapshot_result(snapshot, replayed=True)
        if snapshot.status == "failed":
            raise LifecycleError("binding_saga_failed", "Binding Saga requires operator review")
        if snapshot.status == "pending":
            return self._provision(request, snapshot, target, provisioner)
        if snapshot.status == "runtime_created":
            return self._bind_or_compensate(request, snapshot, target, provisioner)
        if snapshot.status == "compensating":
            return self._compensate(request, snapshot, target, provisioner)
        raise LifecycleError("binding_saga_state_invalid", "Binding Saga state is invalid")

    def run_to_terminal(
        self,
        request: RequestContext,
        *,
        saga_id: UUID,
        provisioner: RuntimeResourceProvisioner,
    ) -> RuntimeBindingSagaResult:
        """Advance until bound/compensated, retaining durable boundaries between calls."""

        for _ in range(4):
            result = self.advance(request, saga_id=saga_id, provisioner=provisioner)
            if result.status in {"bound", "compensated"}:
                return result
        raise LifecycleError("binding_saga_did_not_converge", "Binding Saga did not converge")

    def _provision(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        target: ProvisioningTarget,
        provisioner: RuntimeResourceProvisioner,
    ) -> RuntimeBindingSagaResult:
        try:
            runtime_resource_id = provisioner.provision(
                target=target,
                resource_type=snapshot.resource_type,
                saas_resource_id=snapshot.saas_resource_id,
                idempotency_key=f"binding-saga:{snapshot.id}:provision",
            ).strip()
            if not runtime_resource_id or len(runtime_resource_id) > 256:
                raise RuntimeProvisioningError(
                    "runtime_resource_invalid", "provisioner returned an invalid resource id"
                )
        except RuntimeProvisioningError as error:
            self._record_pending_error(request, snapshot, error)
            raise
        return self._mark_runtime_created(
            request, snapshot, runtime_resource_id=runtime_resource_id
        )

    def _bind_or_compensate(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        target: ProvisioningTarget,
        provisioner: RuntimeResourceProvisioner,
    ) -> RuntimeBindingSagaResult:
        if snapshot.runtime_resource_id is None:
            raise LifecycleError("binding_saga_state_invalid", "runtime resource is missing")
        try:
            binding = self._bindings.bind_resource(
                request,
                project_id=snapshot.project_id,
                runtime_partition_id=snapshot.runtime_partition_id,
                resource_type=snapshot.resource_type,
                runtime_resource_id=snapshot.runtime_resource_id,
                saas_resource_id=snapshot.saas_resource_id,
                expected_partition_generation=snapshot.partition_generation,
                idempotency_key=f"binding-saga:{snapshot.id}:bind",
            )
        except LifecycleError as binding_error:
            compensating = self._mark_compensating(request, snapshot, binding_error)
            try:
                self._compensate(
                    request,
                    replace(
                        snapshot,
                        status="compensating",
                        attempt_count=compensating.attempt_count,
                    ),
                    target,
                    provisioner,
                )
            except RuntimeProvisioningError as compensation_error:
                raise LifecycleError(
                    "binding_saga_compensation_failed",
                    "Binding failed and runtime compensation requires operator review",
                ) from compensation_error
            raise LifecycleError(
                "binding_saga_compensated",
                "Binding failed and the official runtime resource was compensated",
            ) from binding_error
        return self._mark_bound(request, snapshot, binding.binding_id)

    def _compensate(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        target: ProvisioningTarget,
        provisioner: RuntimeResourceProvisioner,
    ) -> RuntimeBindingSagaResult:
        if snapshot.runtime_resource_id is None:
            raise LifecycleError("binding_saga_state_invalid", "runtime resource is missing")
        try:
            provisioner.compensate(
                target=target,
                resource_type=snapshot.resource_type,
                runtime_resource_id=snapshot.runtime_resource_id,
                idempotency_key=f"binding-saga:{snapshot.id}:compensate",
            )
        except RuntimeProvisioningError as error:
            self._mark_failed(request, snapshot, error)
            raise
        return self._mark_compensated(request, snapshot)

    def _authorized_snapshot(
        self, request: RequestContext, saga_id: UUID
    ) -> tuple[_SagaSnapshot, ProvisioningTarget]:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = db.execute(
                sa.select(RuntimeBindingSagaRecord).where(
                    RuntimeBindingSagaRecord.id == saga_id,
                    RuntimeBindingSagaRecord.tenant_id == request.tenant_id,
                    RuntimeBindingSagaRecord.space_id == request.space_id,
                )
            ).scalar_one_or_none()
            if saga is None:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            snapshot = self._to_snapshot(saga)
            target = self._load_target(
                db,
                request,
                runtime_partition_id=saga.runtime_partition_id,
                expected_generation=saga.partition_generation,
            )
        self._authorizer.require(
            request,
            action="runtime.binding.manage",
            project_id=snapshot.project_id,
            resource_type=snapshot.resource_type,
            resource_id=snapshot.saas_resource_id,
        )
        return snapshot, target

    def _mark_runtime_created(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        *,
        runtime_resource_id: str,
    ) -> RuntimeBindingSagaResult:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="pending")
            saga.runtime_resource_id = runtime_resource_id
            saga.status = "runtime_created"
            saga.attempt_count += 1
            saga.last_error = None
            self._event(
                db,
                request,
                saga_id=saga.id,
                event_type="runtime.binding_saga.runtime_created",
                suffix="runtime-created",
                payload={
                    "saga_id": str(saga.id),
                    "runtime_resource_id": runtime_resource_id,
                    "status": saga.status,
                },
            )
            return self._result(saga, replayed=False)

    def _mark_bound(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        binding_id: UUID,
    ) -> RuntimeBindingSagaResult:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="runtime_created")
            saga.binding_id = binding_id
            saga.status = "bound"
            saga.attempt_count += 1
            saga.last_error = None
            self._event(
                db,
                request,
                saga_id=saga.id,
                event_type="runtime.binding_saga.bound",
                suffix="bound",
                payload={
                    "saga_id": str(saga.id),
                    "binding_id": str(binding_id),
                    "status": saga.status,
                },
            )
            return self._result(saga, replayed=False)

    def _mark_compensating(
        self,
        request: RequestContext,
        snapshot: _SagaSnapshot,
        error: Exception,
    ) -> RuntimeBindingSagaResult:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="runtime_created")
            saga.status = "compensating"
            saga.attempt_count += 1
            saga.last_error = _clean_error(error)
            self._event(
                db,
                request,
                saga_id=saga.id,
                event_type="runtime.binding_saga.compensating",
                suffix="compensating",
                payload={"saga_id": str(saga.id), "status": saga.status},
            )
            return self._result(saga, replayed=False)

    def _mark_compensated(
        self, request: RequestContext, snapshot: _SagaSnapshot
    ) -> RuntimeBindingSagaResult:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="compensating")
            saga.status = "compensated"
            saga.attempt_count += 1
            self._event(
                db,
                request,
                saga_id=saga.id,
                event_type="runtime.binding_saga.compensated",
                suffix="compensated",
                payload={"saga_id": str(saga.id), "status": saga.status},
            )
            return self._result(saga, replayed=False)

    def _mark_failed(
        self, request: RequestContext, snapshot: _SagaSnapshot, error: Exception
    ) -> RuntimeBindingSagaResult:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="compensating")
            saga.status = "failed"
            saga.attempt_count += 1
            saga.last_error = _clean_error(error)
            self._event(
                db,
                request,
                saga_id=saga.id,
                event_type="runtime.binding_saga.failed",
                suffix="failed",
                payload={"saga_id": str(saga.id), "status": saga.status},
            )
            return self._result(saga, replayed=False)

    def _record_pending_error(
        self, request: RequestContext, snapshot: _SagaSnapshot, error: Exception
    ) -> None:
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            saga = self._locked(db, request, snapshot.id, expected_status="pending")
            saga.attempt_count += 1
            saga.last_error = _clean_error(error)

    def _load_target(
        self,
        db: Session,
        request: RequestContext,
        *,
        runtime_partition_id: UUID,
        expected_generation: int | None,
    ) -> ProvisioningTarget:
        row = db.execute(
            sa.select(RuntimePartitionRecord, RuntimePlacementRecord)
            .join(
                RuntimePlacementRecord,
                RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
            )
            .where(
                RuntimePartitionRecord.id == runtime_partition_id,
                RuntimePartitionRecord.tenant_id == request.tenant_id,
                RuntimePartitionRecord.space_id == request.space_id,
            )
        ).one_or_none()
        if row is None:
            raise LifecycleError("resource_not_accessible", "resource is not accessible")
        partition, placement = row
        if partition.status != "active" or placement.status != "active":
            raise LifecycleError("partition_not_active", "runtime Partition is not active")
        self._bindings.validate_target_records(partition, placement)
        if (
            expected_generation is not None
            and partition.placement_generation != expected_generation
        ):
            raise LifecycleError("partition_generation_stale", "runtime generation changed")
        return ProvisioningTarget(
            runtime_partition_id=partition.id,
            placement_id=partition.placement_id,
            tenant_id=partition.tenant_id,
            space_id=partition.space_id,
            runtime_type=partition.runtime_type,
            physical_partition_key=partition.physical_partition_key,
            partition_generation=partition.placement_generation,
            data_region=placement.data_region,
        )

    @staticmethod
    def _locked(
        db: Session,
        request: RequestContext,
        saga_id: UUID,
        *,
        expected_status: str,
    ) -> RuntimeBindingSagaRecord:
        saga = db.execute(
            sa.select(RuntimeBindingSagaRecord)
            .where(
                RuntimeBindingSagaRecord.id == saga_id,
                RuntimeBindingSagaRecord.tenant_id == request.tenant_id,
                RuntimeBindingSagaRecord.space_id == request.space_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if saga is None:
            raise LifecycleError("resource_not_accessible", "resource is not accessible")
        if saga.status != expected_status:
            raise LifecycleError(
                "binding_saga_state_conflict", "Binding Saga changed concurrently"
            )
        return saga

    @staticmethod
    def _event(
        db: Session,
        request: RequestContext,
        *,
        saga_id: UUID,
        event_type: str,
        suffix: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=request.tenant_id,
                aggregate_type="runtime_binding_saga",
                aggregate_key=str(saga_id),
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key(
                    "tenant", request.tenant_id, f"binding-saga:{saga_id}:{suffix}"
                ),
                request_hash=_digest(payload),
                attempt_count=0,
            )
        )

    @staticmethod
    def _apply_context(db: Session, request: RequestContext) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
            ),
        )

    @staticmethod
    def _to_snapshot(saga: RuntimeBindingSagaRecord) -> _SagaSnapshot:
        return _SagaSnapshot(
            id=saga.id,
            tenant_id=saga.tenant_id,
            space_id=saga.space_id,
            project_id=saga.project_id,
            runtime_partition_id=saga.runtime_partition_id,
            resource_type=saga.resource_type,
            saas_resource_id=saga.saas_resource_id,
            runtime_resource_id=saga.runtime_resource_id,
            binding_id=saga.binding_id,
            partition_generation=saga.partition_generation,
            status=saga.status,
            attempt_count=saga.attempt_count,
        )

    @staticmethod
    def _result(saga: RuntimeBindingSagaRecord, *, replayed: bool) -> RuntimeBindingSagaResult:
        return RuntimeBindingSagaResult(
            saga_id=saga.id,
            status=saga.status,
            runtime_resource_id=saga.runtime_resource_id,
            binding_id=saga.binding_id,
            attempt_count=saga.attempt_count,
            replayed=replayed,
        )

    @staticmethod
    def _snapshot_result(saga: _SagaSnapshot, *, replayed: bool) -> RuntimeBindingSagaResult:
        return RuntimeBindingSagaResult(
            saga_id=saga.id,
            status=saga.status,
            runtime_resource_id=saga.runtime_resource_id,
            binding_id=saga.binding_id,
            attempt_count=saga.attempt_count,
            replayed=replayed,
        )
