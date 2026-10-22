"""Recoverable Runtime Resource Binding lifecycle with database-enforced uniqueness."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    ProjectRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
    RuntimeResourceBindingRecord,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.resolver import RuntimeCompatibilityPolicy
from saas.control_plane.rls import RlsContext, apply_rls_context


@dataclass(frozen=True, slots=True)
class RuntimeBindingChanged:
    binding_id: UUID
    binding_generation: int
    status: str
    replayed: bool


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _validate_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise LifecycleError("invalid_idempotency_key", "idempotency key is invalid")


class RuntimeBindingService:
    """Create and retire bindings without accepting Placement or physical workspace input."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        authorizer: ProjectAuthorizer,
        compatibility_policy: RuntimeCompatibilityPolicy,
    ) -> None:
        self._session_factory = session_factory
        self._authorizer = authorizer
        self._compatibility_policy = compatibility_policy

    def bind_resource(
        self,
        request: RequestContext,
        *,
        project_id: UUID,
        runtime_partition_id: UUID,
        resource_type: str,
        runtime_resource_id: str,
        saas_resource_id: UUID,
        expected_partition_generation: int,
        idempotency_key: str,
    ) -> RuntimeBindingChanged:
        """Create one active Project binding after locking trusted Partition facts."""

        _validate_idempotency_key(idempotency_key)
        cleaned_type = resource_type.strip()
        cleaned_runtime_id = runtime_resource_id.strip()
        if not cleaned_type or len(cleaned_type) > 64:
            raise LifecycleError("resource_type_invalid", "resource type is invalid")
        if not cleaned_runtime_id or len(cleaned_runtime_id) > 256:
            raise LifecycleError("runtime_resource_invalid", "runtime resource id is invalid")
        if expected_partition_generation < 1:
            raise LifecycleError("partition_generation_invalid", "generation is invalid")
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
            "runtime_resource_id": cleaned_runtime_id,
            "saas_resource_id": str(saas_resource_id),
            "expected_partition_generation": expected_partition_generation,
        }
        request_hash = _digest(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(
                db,
                request,
                idempotency_key,
                "runtime.binding.created",
                request_hash,
            )
            if receipt is not None:
                return self._result(receipt.payload, replayed=True)
            project = db.execute(
                sa.select(ProjectRecord)
                .where(
                    ProjectRecord.id == project_id,
                    ProjectRecord.tenant_id == request.tenant_id,
                    ProjectRecord.space_id == request.space_id,
                    ProjectRecord.status == "active",
                )
                .with_for_update()
            ).scalar_one_or_none()
            if project is None:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            target = db.execute(
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
                .with_for_update()
            ).one_or_none()
            if target is None:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            partition, placement = target
            if partition.status != "active" or placement.status != "active":
                raise LifecycleError("partition_not_active", "runtime Partition is not active")
            self.validate_target_records(partition, placement)
            if partition.placement_generation != expected_partition_generation:
                raise LifecycleError(
                    "partition_generation_stale", "runtime Partition generation changed"
                )
            existing = db.execute(
                sa.select(RuntimeResourceBindingRecord).where(
                    RuntimeResourceBindingRecord.tenant_id == request.tenant_id,
                    RuntimeResourceBindingRecord.space_id == request.space_id,
                    RuntimeResourceBindingRecord.resource_type == cleaned_type,
                    RuntimeResourceBindingRecord.saas_resource_id == saas_resource_id,
                    RuntimeResourceBindingRecord.status == "active",
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise LifecycleError(
                    "active_binding_exists", "resource already has an active binding"
                )
            generation = (
                db.execute(
                    sa.select(
                        sa.func.coalesce(
                            sa.func.max(RuntimeResourceBindingRecord.binding_generation), 0
                        )
                    ).where(
                        RuntimeResourceBindingRecord.tenant_id == request.tenant_id,
                        RuntimeResourceBindingRecord.space_id == request.space_id,
                        RuntimeResourceBindingRecord.resource_type == cleaned_type,
                        RuntimeResourceBindingRecord.saas_resource_id == saas_resource_id,
                    )
                ).scalar_one()
                + 1
            )
            binding_id = uuid4()
            binding = RuntimeResourceBindingRecord(
                id=binding_id,
                runtime_partition_id=runtime_partition_id,
                tenant_id=request.tenant_id,
                space_id=request.space_id,
                project_id=project_id,
                resource_type=cleaned_type,
                runtime_resource_id=cleaned_runtime_id,
                saas_resource_id=saas_resource_id,
                partition_generation=partition.placement_generation,
                binding_generation=generation,
                status="active",
            )
            try:
                db.add(binding)
                db.flush()
            except IntegrityError as error:
                raise LifecycleError(
                    "binding_conflict", "binding uniqueness or scope validation failed"
                ) from error
            event_payload = {
                **payload,
                "binding_id": str(binding_id),
                "binding_generation": generation,
                "status": "active",
            }
            self._event(
                db,
                request,
                aggregate_key=str(binding_id),
                event_type="runtime.binding.created",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=event_payload,
            )
            return RuntimeBindingChanged(binding_id, generation, "active", False)

    def retire_binding(
        self,
        request: RequestContext,
        *,
        binding_id: UUID,
        expected_binding_generation: int,
        idempotency_key: str,
    ) -> RuntimeBindingChanged:
        """Retire an active binding under optimistic generation control."""

        _validate_idempotency_key(idempotency_key)
        if expected_binding_generation < 1:
            raise LifecycleError("binding_generation_invalid", "generation is invalid")
        payload: dict[str, object] = {
            "actor_id": str(request.actor_id),
            "tenant_id": str(request.tenant_id),
            "space_id": str(request.space_id),
            "binding_id": str(binding_id),
            "expected_binding_generation": expected_binding_generation,
        }
        request_hash = _digest(payload)
        with self._session_factory.begin() as db:
            self._apply_context(db, request)
            receipt = self._receipt(
                db,
                request,
                idempotency_key,
                "runtime.binding.retired",
                request_hash,
            )
            if receipt is not None:
                return self._result(receipt.payload, replayed=True)
            binding = db.execute(
                sa.select(RuntimeResourceBindingRecord)
                .where(
                    RuntimeResourceBindingRecord.id == binding_id,
                    RuntimeResourceBindingRecord.tenant_id == request.tenant_id,
                    RuntimeResourceBindingRecord.space_id == request.space_id,
                    RuntimeResourceBindingRecord.status == "active",
                )
                .with_for_update()
            ).scalar_one_or_none()
            if binding is None or binding.project_id is None:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            if request.project_id is not None and request.project_id != binding.project_id:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            if binding.binding_generation != expected_binding_generation:
                raise LifecycleError("binding_generation_stale", "binding generation changed")
            decision = self._authorizer.evaluate_in_session(
                db,
                request,
                action="runtime.binding.manage",
                project_id=binding.project_id,
                resource_type=binding.resource_type,
                resource_id=binding.saas_resource_id,
                mode="enforce",
            )
            if not decision.allowed:
                raise LifecycleError("resource_not_accessible", "resource is not accessible")
            binding.status = "retired"
            event_payload = {
                **payload,
                "project_id": str(binding.project_id),
                "binding_generation": binding.binding_generation,
                "status": "retired",
            }
            self._event(
                db,
                request,
                aggregate_key=str(binding_id),
                event_type="runtime.binding.retired",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                payload=event_payload,
            )
            return RuntimeBindingChanged(binding_id, binding.binding_generation, "retired", False)

    def validate_target_records(
        self,
        partition: RuntimePartitionRecord,
        placement: RuntimePlacementRecord,
    ) -> int:
        """Validate reviewed lineage and return the canonical physical workspace."""

        policy = self._compatibility_policy
        if (
            partition.placement_id != placement.id
            or partition.runtime_type != placement.runtime_type
        ):
            raise LifecycleError(
                "runtime_placement_mismatch", "runtime Partition and Placement are incompatible"
            )
        if partition.runtime_type != policy.runtime_type:
            raise LifecycleError("runtime_type_not_allowed", "runtime type is not reviewed")
        if partition.runtime_version not in policy.allowed_runtime_versions:
            raise LifecycleError("runtime_version_not_allowed", "runtime version is not reviewed")
        if partition.source_revision not in policy.allowed_source_revisions:
            raise LifecycleError("source_revision_not_allowed", "source revision is not reviewed")
        if placement.official_schema_revision not in policy.allowed_schema_revisions:
            raise LifecycleError("schema_revision_not_allowed", "schema revision is not reviewed")
        if partition.adapter_contract_version != policy.adapter_contract_version:
            raise LifecycleError(
                "adapter_contract_mismatch", "runtime Adapter contract is not reviewed"
            )
        try:
            workspace_id = int(partition.physical_partition_key)
        except ValueError as error:
            raise LifecycleError(
                "physical_partition_invalid", "physical Runtime Partition key is invalid"
            ) from error
        if workspace_id <= 0 or str(workspace_id) != partition.physical_partition_key:
            raise LifecycleError(
                "physical_partition_invalid", "physical Runtime Partition key is invalid"
            )
        return workspace_id

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
    def _receipt(
        db: Session,
        request: RequestContext,
        idempotency_key: str,
        event_type: str,
        request_hash: str,
    ) -> ControlPlaneOutboxEvent | None:
        receipt_key = scoped_idempotency_key("tenant", request.tenant_id, idempotency_key)
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key == receipt_key
            )
        ).scalar_one_or_none()
        if receipt is not None and (
            receipt.event_type != event_type or receipt.request_hash != request_hash
        ):
            raise LifecycleError("idempotency_conflict", "idempotency key was already used")
        return receipt

    @staticmethod
    def _event(
        db: Session,
        request: RequestContext,
        *,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=request.tenant_id,
                aggregate_type="runtime_binding",
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key(
                    "tenant", request.tenant_id, idempotency_key
                ),
                request_hash=request_hash,
                attempt_count=0,
            )
        )

    @staticmethod
    def _result(payload: dict[str, object], *, replayed: bool) -> RuntimeBindingChanged:
        return RuntimeBindingChanged(
            binding_id=UUID(cast(str, payload["binding_id"])),
            binding_generation=cast(int, payload["binding_generation"]),
            status=cast(str, payload["status"]),
            replayed=replayed,
        )
