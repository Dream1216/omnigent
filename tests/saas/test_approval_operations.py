from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.approval_operations import (
    ApprovalActor,
    ApprovalOperationsError,
    ApprovalOperationsService,
    ApprovalProjectionCommand,
    ApprovalProjectionService,
    ApprovalSecretDigester,
    ApprovalTerminalCommand,
    ApprovalWorkItemView,
    AuthorityDecisionCommand,
    BatchDecisionCommand,
)
from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant
from saas.control_plane.notification_models import (
    ApprovalWorkItemRecord,
    OperationBatchRecord,
)

NOW = datetime(2026, 8, 10, 10, 0, tzinfo=timezone.utc)
OLD = ApprovalSecretDigester("approval-old", b"o" * 32)
NEW = ApprovalSecretDigester("approval-new", b"n" * 32)


class RecordingBatchNotifier:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, str, UUID]] = []

    def enqueue_batch_completed_in_transaction(
        self,
        db: Session,
        *,
        realm: Literal["tenant", "staff"],
        tenant_id: UUID | None,
        requester_id: UUID,
        batch_id: UUID,
        status: str,
        now: datetime,
    ) -> None:
        del realm, tenant_id, now
        row = db.get(OperationBatchRecord, batch_id)
        assert row is not None and row.status == status
        self.calls.append((batch_id, status, requester_id))


class FakeEnterpriseAuthority:
    def __init__(self, factory: sessionmaker[Session], allowed: set[UUID]) -> None:
        self.factory = factory
        self.allowed = allowed
        self.failed_operations: set[UUID] = set()

    def authorize(
        self,
        actor: ApprovalActor,
        *,
        permission: str,
        tenant_id: UUID | None,
        now: datetime,
    ) -> None:
        del permission, tenant_id, now
        if actor.actor_id not in self.allowed:
            raise ApprovalOperationsError("approval_permission_forbidden")

    def authorize_work_item(
        self,
        actor: ApprovalActor,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
    ) -> None:
        del work_item, now
        if actor.actor_id not in self.allowed:
            raise ApprovalOperationsError("approval_permission_forbidden")

    def authorize_identity(
        self,
        *,
        realm: str,
        actor_id: UUID,
        permission: str,
        tenant_id: UUID | None,
        operation_id: UUID,
        now: datetime,
    ) -> None:
        del realm, permission, tenant_id, operation_id, now
        if actor_id not in self.allowed:
            raise ApprovalOperationsError("approval_delegate_permission_forbidden")

    def eligible_actor_ids(
        self,
        work_item: ApprovalWorkItemView,
        *,
        now: datetime,
        limit: int,
    ) -> tuple[UUID, ...]:
        del work_item, now
        return tuple(self.allowed)[:limit]

    def decide(
        self,
        actor: ApprovalActor,
        command: AuthorityDecisionCommand,
        *,
        projection: ApprovalProjectionService,
        now: datetime,
    ) -> None:
        if command.operation_id in self.failed_operations:
            raise ApprovalOperationsError("enterprise_source_conflict")
        with self.factory.begin() as db:
            work = db.execute(
                sa.select(ApprovalWorkItemRecord).where(
                    ApprovalWorkItemRecord.operation_id == command.operation_id
                )
            ).scalar_one()
            projection.sync_terminal_in_transaction(
                db,
                ApprovalTerminalCommand(
                    work_item_id=work.id,
                    source_authority="enterprise",
                    source_subject_id=None,
                    realm="tenant",
                    tenant_id=work.tenant_id,
                    operation_kind="enterprise",
                    operation_id=work.operation_id,
                    required_permission=work.required_permission,
                    expected_snapshot_hash=command.expected_snapshot_hash,
                    expected_projection_version=command.expected_projection_version,
                    status=("approved" if command.decision == "approve" else "rejected"),
                    decision_code=command.decision_code,
                    decided_by_id=actor.actor_id,
                    decided_at=now,
                ),
            )


@dataclass(frozen=True, slots=True)
class ApprovalHarness:
    factory: sessionmaker[Session]
    projection: ApprovalProjectionService
    authority: FakeEnterpriseAuthority
    service: ApprovalOperationsService
    tenant_id: UUID
    requester_id: UUID
    assignee_id: UUID
    delegate_id: UUID
    outsider_id: UUID

    def actor(self, actor_id: UUID) -> ApprovalActor:
        return ApprovalActor(
            realm="tenant",
            actor_id=actor_id,
            tenant_id=self.tenant_id,
            security_version=1,
            authenticated_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(hours=1),
        )

    def project(
        self,
        *,
        assignee_id: UUID | None = None,
        operation_id: UUID | None = None,
        work_item_id: UUID | None = None,
    ) -> tuple[ApprovalWorkItemView, ApprovalProjectionCommand]:
        operation = operation_id or uuid4()
        command = ApprovalProjectionCommand(
            work_item_id=work_item_id or uuid4(),
            source_authority="enterprise",
            source_subject_id=None,
            realm="tenant",
            tenant_id=self.tenant_id,
            hmac_key_id=OLD.key_id,
            requester_realm="tenant",
            requester_id=self.requester_id,
            assignee_id=assignee_id,
            operation_kind="enterprise",
            operation_id=operation,
            action="custom_role_retire",
            target_type="custom_role",
            target_locator_hmac=operation.hex * 2,
            required_permission="tenant.enterprise.role.manage",
            risk_level="high",
            snapshot_hash="2" * 64,
            priority="high",
            due_at=NOW + timedelta(hours=1),
            escalation_at=NOW + timedelta(minutes=15),
        )
        with self.factory.begin() as db:
            view = self.projection.project_in_transaction(db, command, now=NOW)
        return view, command


@pytest.fixture
def approvals() -> ApprovalHarness:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, requester_id, assignee_id, delegate_id, outsider_id = (uuid4() for _ in range(5))
    with factory.begin() as db:
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"approval-{tenant_id.hex}",
                name="Approval tenant",
                status="active",
                plan="enterprise",
                home_region="cn-east-1",
                lifecycle_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add_all(
            GlobalUser(
                id=value,
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
            for value in (requester_id, assignee_id, delegate_id, outsider_id)
        )
    projection = ApprovalProjectionService()
    authority = FakeEnterpriseAuthority(factory, {assignee_id, delegate_id, outsider_id})
    service = ApprovalOperationsService(
        factory,
        projection=projection,
        adapters={"enterprise": authority},
        digester=OLD,
        clock=lambda: NOW,
    )
    return ApprovalHarness(
        factory,
        projection,
        authority,
        service,
        tenant_id,
        requester_id,
        assignee_id,
        delegate_id,
        outsider_id,
    )


def test_projection_rejects_terminal_and_pending_source_rebinding(
    approvals: ApprovalHarness,
) -> None:
    work, command = approvals.project(assignee_id=approvals.assignee_id)
    with approvals.factory.begin() as db:
        with pytest.raises(ApprovalOperationsError) as raised:
            approvals.projection.project_in_transaction(
                db, replace(command, operation_id=uuid4()), now=NOW
            )
    assert raised.value.code == "approval_projection_source_binding_conflict"

    decided = approvals.service.decide(
        approvals.actor(approvals.assignee_id),
        work_item_id=work.id,
        expected_version=work.version,
        decision="approve",
        decision_code="enterprise-approved",
        decision_reason="verified exact source state",
        idempotency_key="decision-one",
        now=NOW,
    )
    assert decided.status == "approved"
    with approvals.factory.begin() as db:
        with pytest.raises(ApprovalOperationsError) as raised:
            approvals.projection.project_in_transaction(
                db,
                replace(command, required_permission="tenant.owner.transfer"),
                now=NOW,
            )
    assert raised.value.code == "approval_projection_source_binding_conflict"

    with approvals.factory.begin() as db:
        with pytest.raises(ApprovalOperationsError) as raised:
            approvals.projection.sync_terminal_in_transaction(
                db,
                ApprovalTerminalCommand(
                    work_item_id=work.id,
                    source_authority="enterprise",
                    source_subject_id=None,
                    realm="tenant",
                    tenant_id=approvals.tenant_id,
                    operation_kind="enterprise",
                    operation_id=uuid4(),
                    required_permission=command.required_permission,
                    expected_snapshot_hash=command.snapshot_hash,
                    expected_projection_version=decided.version,
                    status="cancelled",
                    decision_code="source-cancelled",
                    decided_by_id=None,
                    decided_at=NOW,
                ),
            )
    assert raised.value.code == "approval_projection_source_binding_conflict"


def test_one_hop_delegation_controls_list_and_decision(
    approvals: ApprovalHarness,
) -> None:
    work, _ = approvals.project(assignee_id=approvals.assignee_id)
    outsider = approvals.actor(approvals.outsider_id)
    assert not approvals.service.list_work_items(outsider, now=NOW).items
    with pytest.raises(ApprovalOperationsError) as raised:
        approvals.service.decide(
            outsider,
            work_item_id=work.id,
            expected_version=work.version,
            decision="approve",
            decision_code="forbidden",
            decision_reason="must not bypass routing",
            idempotency_key="outsider",
            now=NOW,
        )
    assert raised.value.code == "approval_work_item_not_found"

    assignee = approvals.actor(approvals.assignee_id)
    delegation = approvals.service.create_delegation(
        assignee,
        work_item_id=work.id,
        expected_version=work.version,
        delegate_id=approvals.delegate_id,
        starts_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        reason="on-call coverage",
        idempotency_key="delegate-one",
        now=NOW,
    )
    delegate = approvals.actor(approvals.delegate_id)
    assert [value.id for value in approvals.service.list_work_items(delegate, now=NOW).items] == [
        work.id
    ]
    with pytest.raises(ApprovalOperationsError) as raised:
        approvals.service.create_delegation(
            delegate,
            work_item_id=work.id,
            expected_version=work.version,
            delegate_id=approvals.outsider_id,
            starts_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            reason="forbidden second hop",
            idempotency_key="delegate-chain",
            now=NOW,
        )
    assert raised.value.code == "approval_delegation_chain_forbidden"

    approvals.service.revoke_delegation(
        assignee,
        delegation_id=delegation.id,
        expected_version=delegation.version,
        idempotency_key="revoke-one",
        now=NOW,
    )
    assert not approvals.service.list_work_items(delegate, now=NOW).items
    with pytest.raises(ApprovalOperationsError):
        approvals.service.decide(
            delegate,
            work_item_id=work.id,
            expected_version=work.version,
            decision="approve",
            decision_code="revoked",
            decision_reason="delegation was revoked",
            idempotency_key="revoked-decision",
            now=NOW,
        )


def test_batch_previous_key_replay_and_partial_completion(
    approvals: ApprovalHarness,
) -> None:
    first, _ = approvals.project(assignee_id=approvals.assignee_id)
    second, _ = approvals.project(assignee_id=approvals.assignee_id)
    commands = (
        BatchDecisionCommand(first.id, first.version),
        BatchDecisionCommand(second.id, second.version),
    )
    actor = approvals.actor(approvals.assignee_id)
    preview = approvals.service.preview_batch(
        actor,
        commands=commands,
        decision="approve",
        decision_code="enterprise-approved",
        decision_reason="same reviewed evidence",
        idempotency_key="batch-one",
        now=NOW,
    )
    notifier = RecordingBatchNotifier()
    rotated = ApprovalOperationsService(
        approvals.factory,
        projection=approvals.projection,
        adapters={"enterprise": approvals.authority},
        digester=NEW,
        previous_digesters=(OLD,),
        clock=lambda: NOW,
        notifier=notifier,
    )
    replay = rotated.preview_batch(
        actor,
        commands=commands,
        decision="approve",
        decision_code="enterprise-approved",
        decision_reason="same reviewed evidence",
        idempotency_key="batch-one",
        now=NOW,
    )
    assert replay.replayed and replay.id == preview.id
    approvals.authority.failed_operations.add(second.operation_id)
    completed = rotated.execute_batch(
        actor,
        batch_id=preview.id,
        expected_version=preview.version,
        decision_reason="same reviewed evidence",
        now=NOW,
    )
    assert completed.status == "partial"
    assert (completed.success_count, completed.failure_count) == (1, 1)
    assert notifier.calls == [(preview.id, "partial", actor.actor_id)]
    with approvals.factory.begin() as db:
        row = db.get(OperationBatchRecord, preview.id)
        assert row is not None
        assert row.hmac_key_id == OLD.key_id
        assert "same reviewed evidence" not in repr(row.__dict__)


def test_approval_secret_repr_is_content_blind() -> None:
    assert (b"o" * 32).decode() not in repr(OLD)
