from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    SaasBase,
    Tenant,
)
from saas.control_plane.permissions import PLATFORM_ROLE_PERMISSIONS
from saas.control_plane.platform_governed_models import (
    PlatformAdminOperationRecord,
    PlatformAuditEventRecord,
)
from saas.control_plane.platform_lifecycle import PlatformLifecycleService
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from saas.control_plane.privacy_attestation import (
    canonical_json,
    privacy_verifier_receipt_sha256,
)
from saas.control_plane.privacy_lifecycle import DeletionEvidenceKey, PrivacyLifecycleService
from saas.control_plane.privacy_models import (
    PrivacyApprovalBindingRecord,
    PrivacyBackupRetentionItemRecord,
    PrivacyDeletionManifestRecord,
    PrivacyDeletionWorkItemRecord,
    PrivacyEvidenceAttestationRecord,
    PrivacyIdentityTombstoneRecord,
    PrivacyLegalHoldRecord,
)
from saas.control_plane.privacy_operations import (
    PrivacyLocatorKey,
    PrivacyOperationService,
)

NOW = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)


def _digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode()
    ).hexdigest()


def _actor(principal_id: UUID, *roles: str) -> ValidatedPlatformPrincipal:
    return ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=principal_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        roles=frozenset(roles),
        permissions=frozenset(
            permission for role in roles for permission in PLATFORM_ROLE_PERMISSIONS[role]
        ),
    )


@pytest.fixture
def privacy_operations() -> tuple[
    sessionmaker[Session],
    PrivacyLifecycleService,
    PrivacyOperationService,
    ValidatedPlatformPrincipal,
    ValidatedPlatformPrincipal,
    ValidatedPlatformPrincipal,
    UUID,
]:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    requester_id, approver_id, finalizer_id, assigner_id, target_id = (uuid4() for _ in range(5))
    principals = (
        (requester_id, "requester"),
        (approver_id, "approver"),
        (finalizer_id, "finalizer"),
        (assigner_id, "assigner"),
    )
    with factory.begin() as db:
        db.add_all(
            PlatformStaffPrincipalRecord(
                id=principal_id,
                identity_connection_ref=f"staff:{subject}",
                issuer="https://staff-idp.example.test",
                subject=subject,
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
            for principal_id, subject in principals
        )
        db.flush()
        db.add_all(
            [
                PlatformRoleAssignmentRecord(
                    principal_id=requester_id,
                    role=role,
                    status="active",
                    version=1,
                    assigned_by_principal_id=assigner_id,
                    approval_ref=f"bootstrap:{role}",
                    reason="Privacy operation acceptance",
                    created_at=NOW,
                    updated_at=NOW,
                )
                for role in ("compliance_operator", "platform_operator")
            ]
            + [
                PlatformRoleAssignmentRecord(
                    principal_id=principal_id,
                    role="platform_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=assigner_id,
                    approval_ref=f"bootstrap:{subject}",
                    reason="Privacy operation acceptance",
                    created_at=NOW,
                    updated_at=NOW,
                )
                for principal_id, subject in (
                    (approver_id, "approver"),
                    (finalizer_id, "finalizer"),
                )
            ]
        )
        db.add(
            GlobalUser(
                id=target_id,
                status="active",
                display_name="Privacy Subject",
                primary_email_normalized="subject@example.test",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    lifecycle = PrivacyLifecycleService(
        factory,
        evidence_verifier=DeletionEvidenceKey("test-key", b"e" * 32),
    )
    service = PrivacyOperationService(
        factory,
        lifecycle=lifecycle,
        locator_key=PrivacyLocatorKey("locator-v1", b"l" * 32),
    )
    return (
        factory,
        lifecycle,
        service,
        _actor(requester_id, "compliance_operator", "platform_operator"),
        _actor(approver_id, "platform_operator"),
        _actor(finalizer_id, "platform_operator"),
        target_id,
    )


def _request_start(
    lifecycle: PrivacyLifecycleService,
    service: PrivacyOperationService,
    requester: ValidatedPlatformPrincipal,
    target_id: UUID,
    *,
    now: datetime = NOW + timedelta(seconds=1),
):
    preview = lifecycle.preview_deletion(
        requester,
        target_type="global_user",
        target_id=target_id,
        now=now,
    )
    return service.request_deletion_start(
        requester,
        target_type="global_user",
        target_id=target_id,
        expected_target_version=preview.target_version,
        preview_hash=preview.preview_hash,
        reason_code="data_subject_request",
        case_reference="privacy-case-001",
        expires_at=now + timedelta(minutes=15),
        idempotency_key="privacy-start-001",
        now=now,
    )


def _surface_attestation(
    manifest: PrivacyDeletionManifestRecord,
    item: PrivacyDeletionWorkItemRecord,
    *,
    envelope_suffix: str = "primary",
) -> PrivacyEvidenceAttestationRecord:
    assert item.outcome_content_sha256 is not None
    attestation_id = uuid4()
    execution_attempt_id = uuid4()
    envelope = {
        "payloadType": "application/vnd.omnigent.privacy-evidence.v1+json",
        "payload": f"dGVzdC1vbmx5{item.id.hex}{envelope_suffix}",
        "signatures": [{"keyid": "privacy-prod-2026-08", "sig": "dGVzdC1vbmx5"}],
    }
    envelope_hash = sha256(canonical_json(envelope)).hexdigest()
    value = PrivacyEvidenceAttestationRecord(
        id=attestation_id,
        manifest_id=manifest.id,
        target_type=manifest.target_type,
        target_id=manifest.target_id,
        tenant_id=manifest.tenant_id,
        subject_kind="surface",
        subject_id=item.id,
        execution_attempt_id=execution_attempt_id,
        attempt_number=item.attempt_count,
        lease_generation=item.lease_generation,
        replay_generation=item.replay_generation,
        surface=item.surface,
        payload_type="application/vnd.omnigent.privacy-evidence.v1+json",
        payload_sha256=item.outcome_content_sha256,
        envelope_sha256=envelope_hash,
        envelope=envelope,
        envelope_uri=f"https://evidence.example.test/{item.id}/{envelope_suffix}.json",
        immutability_receipt_sha256=_digest(["immutability", item.id, envelope_suffix]),
        kms_audit_receipt_sha256=_digest(["kms", item.id, envelope_suffix]),
        signature_algorithm="ed25519",
        signer_key_id="privacy-prod-2026-08",
        workflow_identity="spiffe://prod/privacy-dispatcher",
        attestor_role=None,
        actor_identity_hmac=None,
        record_sha256=None,
        product_revision="a" * 40,
        upstream_revision="b" * 40,
        schema_revision="pc5b00000003",
        adapter_contract_version="privacy-adapter.v1",
        verifier_policy_version="2026-08-10.p1-privacy-execution",
        verifier_receipt_sha256="0" * 64,
        observed_at=NOW + timedelta(seconds=3),
        signed_at=NOW + timedelta(seconds=3),
        verified_at=NOW + timedelta(seconds=3),
        created_at=NOW + timedelta(seconds=3),
    )
    value.verifier_receipt_sha256 = privacy_verifier_receipt_sha256(
        {
            "schema_version": 1,
            "attestation_id": str(value.id),
            "manifest_id": str(value.manifest_id),
            "target_type": value.target_type,
            "target_id": str(value.target_id),
            "subject_kind": value.subject_kind,
            "subject_id": str(value.subject_id),
            "execution_attempt_id": str(value.execution_attempt_id),
            "attempt_number": value.attempt_number,
            "lease_generation": value.lease_generation,
            "replay_generation": value.replay_generation,
            "surface": value.surface,
            "payload_sha256": value.payload_sha256,
            "envelope_sha256": value.envelope_sha256,
            "artifact_uri": value.envelope_uri,
            "immutability_receipt_sha256": value.immutability_receipt_sha256,
            "kms_audit_receipt_sha256": value.kms_audit_receipt_sha256,
            "signer_key_id": value.signer_key_id,
            "workflow_identity": value.workflow_identity,
            "observed_at": value.observed_at.isoformat(),
            "signed_at": value.signed_at.isoformat(),
            "verified_at": value.verified_at.isoformat(),
            "verifier_policy_version": value.verifier_policy_version,
        }
    )
    return value


def _prepare_finalizable_manifest(privacy_operations) -> UUID:
    factory, lifecycle, service, requester, start_approver, _finalizer, target_id = (
        privacy_operations
    )
    start = _request_start(lifecycle, service, requester, target_id)
    service.decide(
        start_approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=start.operation_id,
        expected_version=start.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=2),
    )
    with factory.begin() as db:
        manifest = db.scalar(sa.select(PrivacyDeletionManifestRecord))
        assert manifest is not None
        work_items = tuple(
            db.scalars(
                sa.select(PrivacyDeletionWorkItemRecord)
                .where(PrivacyDeletionWorkItemRecord.manifest_id == manifest.id)
                .order_by(PrivacyDeletionWorkItemRecord.surface)
            )
        )
        assert len(work_items) == 15
        outcomes = dict(manifest.surface_outcomes)
        for item in work_items:
            item.status = "succeeded"
            item.attempt_count = 1
            item.lease_generation = 1
            item.outcome_content_sha256 = _digest(["surface", item.id, item.surface])
            item.updated_at = NOW + timedelta(seconds=3)
            projected = dict(cast(dict[str, object], outcomes[item.surface]))
            projected["status"] = (
                "pending_retention"
                if item.surface == "backups_and_snapshots"
                else "retained"
                if item.disposition in {"anonymize_and_retain", "redact_and_retain"}
                else "erased"
            )
            projected["content_hash"] = item.outcome_content_sha256
            outcomes[item.surface] = projected
            attestation = _surface_attestation(manifest, item)
            item.evidence_attestation_id = attestation.id
            db.add(attestation)
        manifest.surface_outcomes = outcomes
        manifest.status = "ready_to_finalize"
        manifest.retention_status = "pending"
        manifest.retention_completed_at = None
        manifest.version += 1
        manifest.updated_at = NOW + timedelta(seconds=3)
        db.add(
            PrivacyBackupRetentionItemRecord(
                id=uuid4(),
                manifest_id=manifest.id,
                target_type=manifest.target_type,
                target_id=manifest.target_id,
                tenant_id=manifest.tenant_id,
                runtime_partition_id=None,
                provider="test-backup-provider",
                backup_data_class="database_snapshot",
                backup_locator_hmac=_digest(["backup-locator", manifest.id]),
                resource_handle_ref="backup://opaque/finalize-test",
                catalog_snapshot_sha256=_digest(["backup-catalog", manifest.id]),
                tombstone_sha256=_digest(["backup-tombstone", manifest.id]),
                object_lock_until=NOW + timedelta(days=30),
                purge_due_at=NOW + timedelta(days=35),
                status="retention_wait",
                attempt_count=0,
                max_attempts=8,
                available_at=NOW + timedelta(seconds=3),
                lease_generation=0,
                replay_generation=0,
                version=1,
                created_at=NOW + timedelta(seconds=3),
                updated_at=NOW + timedelta(seconds=3),
            )
        )
        return manifest.id


def _request_finalize(privacy_operations, manifest_id: UUID):
    factory, _lifecycle, service, requester, _approver, _finalizer, target_id = privacy_operations
    with factory() as db:
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        assert manifest is not None
        expected_version = manifest.version
    return service.request_deletion_finalize(
        requester,
        target_type="global_user",
        target_id=target_id,
        manifest_id=manifest_id,
        expected_manifest_version=expected_version,
        reason_code="data_subject_request",
        case_reference="privacy-case-finalize-001",
        expires_at=NOW + timedelta(minutes=15),
        idempotency_key="privacy-finalize-001",
        now=NOW + timedelta(seconds=4),
    )


def test_request_is_side_effect_free_and_requires_distinct_approver(
    privacy_operations,
) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    requested = _request_start(lifecycle, service, requester, target_id)

    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "active"
        manifest_count = db.scalar(
            sa.select(sa.func.count()).select_from(PrivacyDeletionManifestRecord)
        )
        assert manifest_count == 0
        binding = db.get(PrivacyApprovalBindingRecord, requested.operation_id)
        assert binding is not None
        assert binding.impact_snapshot["case_reference_hmac"] != "privacy-case-001"

    with pytest.raises(PlatformSecurityError) as self_approval:
        service.decide(
            requester,
            target_type="global_user",
            target_id=target_id,
            operation_id=requested.operation_id,
            expected_version=requested.version,
            decision="approve",
            decision_code="policy_confirmed",
            idempotency_key="privacy-decision-test",
            now=NOW + timedelta(seconds=2),
        )
    assert self_approval.value.code == "platform_separation_of_duties"

    completed = service.decide(
        approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=2),
    )
    assert completed.status == "succeeded"
    assert completed.approved_by_principal_id == approver.principal_id

    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "suspended"
        manifest = db.scalar(sa.select(PrivacyDeletionManifestRecord))
        assert manifest is not None
        assert manifest.approval_provenance == "governed_operation"
        assert manifest.start_operation_id == requested.operation_id
        assert manifest.approval_ref == f"operation:{requested.operation_id}"
        work_items = tuple(
            db.scalars(
                sa.select(PrivacyDeletionWorkItemRecord).where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest.id
                )
            )
        )
        assert len(work_items) == 15
        assert {item.status for item in work_items} == {"pending"}


def test_approval_expires_without_mutating_the_target(privacy_operations) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    requested = _request_start(lifecycle, service, requester, target_id)

    freshly_authenticated_approver = replace(
        approver,
        authenticated_at=NOW + timedelta(minutes=16),
        expires_at=NOW + timedelta(hours=1, minutes=16),
    )
    result = service.decide(
        freshly_authenticated_approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(minutes=16),
    )
    assert result.status == "failed"
    assert result.error_code == "approval_expired"
    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "active"
        manifest_count = db.scalar(
            sa.select(sa.func.count()).select_from(PrivacyDeletionManifestRecord)
        )
        assert manifest_count == 0


def test_stale_snapshot_is_recorded_and_idempotency_is_exact(privacy_operations) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    requested = _request_start(lifecycle, service, requester, target_id)
    replayed = _request_start(lifecycle, service, requester, target_id)
    assert replayed.operation_id == requested.operation_id
    assert replayed.replayed is True

    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None
        target.security_version += 1
        target.updated_at = NOW + timedelta(seconds=2)

    result = service.decide(
        approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=3),
    )
    assert result.status == "failed"
    assert result.error_code == "approval_stale"
    with factory.begin() as db:
        operation = db.get(PlatformAdminOperationRecord, requested.operation_id)
        assert operation is not None and operation.status == "failed"
        manifest_count = db.scalar(
            sa.select(sa.func.count()).select_from(PrivacyDeletionManifestRecord)
        )
        assert manifest_count == 0


def test_requester_permission_revocation_invalidates_pending_approval(
    privacy_operations,
) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    requested = _request_start(lifecycle, service, requester, target_id)
    with factory.begin() as db:
        assignment = db.scalar(
            sa.select(PlatformRoleAssignmentRecord).where(
                PlatformRoleAssignmentRecord.principal_id == requester.principal_id,
                PlatformRoleAssignmentRecord.role == "compliance_operator",
            )
        )
        assert assignment is not None
        assignment.status = "revoked"
        assignment.revoked_at = NOW + timedelta(seconds=2)
        assignment.revoked_by_principal_id = approver.principal_id
        assignment.updated_at = NOW + timedelta(seconds=2)

    result = service.decide(
        approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=3),
    )
    assert result.status == "failed"
    assert result.error_code == "requester_authority_revoked"
    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "active"


def test_finalize_succeeds_with_15_unique_dsse_and_pending_backup_retention(
    privacy_operations,
) -> None:
    factory, _lifecycle, service, _requester, start_approver, finalizer, target_id = (
        privacy_operations
    )
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    requested = _request_finalize(privacy_operations, manifest_id)
    completed = service.decide(
        finalizer,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=5),
    )
    assert completed.status == "succeeded"
    assert completed.approved_by_principal_id == finalizer.principal_id
    assert finalizer.principal_id != start_approver.principal_id

    with factory() as db:
        target = db.get(GlobalUser, target_id)
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        operation = db.get(PlatformAdminOperationRecord, requested.operation_id)
        binding = db.get(PrivacyApprovalBindingRecord, requested.operation_id)
        work_items = tuple(
            db.scalars(
                sa.select(PrivacyDeletionWorkItemRecord).where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest_id
                )
            )
        )
        attestations = tuple(
            db.scalars(
                sa.select(PrivacyEvidenceAttestationRecord).where(
                    PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                    PrivacyEvidenceAttestationRecord.subject_kind == "surface",
                )
            )
        )
        backups = tuple(
            db.scalars(
                sa.select(PrivacyBackupRetentionItemRecord).where(
                    PrivacyBackupRetentionItemRecord.manifest_id == manifest_id
                )
            )
        )
        audit = tuple(
            db.scalars(
                sa.select(PlatformAuditEventRecord)
                .where(PlatformAuditEventRecord.operation_id == requested.operation_id)
                .order_by(PlatformAuditEventRecord.sequence_no)
            )
        )
        completion_events = tuple(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == "privacy.deletion.governed_completed"
                )
            )
        )
        assert target is not None and target.status == "deleted"
        assert manifest is not None and manifest.status == "completed"
        assert manifest.approval_provenance == "governed_operation"
        assert manifest.completion_operation_id == requested.operation_id
        assert manifest.completion_approval_ref == f"operation:{requested.operation_id}"
        assert manifest.manifest_hash is not None
        assert manifest.retention_status == "pending"
        assert len(backups) == 1 and backups[0].status == "retention_wait"
        assert operation is not None and operation.status == "succeeded"
        assert operation.approved_by_principal_id == finalizer.principal_id
        assert binding is not None and binding.phase == "deletion_finalize"
        assert binding.snapshot_hash == operation.request_hash
        assert binding.impact_snapshot["manifest_record_sha256"]
        assert len(work_items) == 15
        assert len({item.surface for item in work_items}) == 15
        assert {item.status for item in work_items} == {"succeeded"}
        assert len(attestations) == 15
        assert {value.subject_id for value in attestations} == {item.id for item in work_items}
        assert len(completion_events) == 1
        assert completion_events[0].aggregate_key != str(target_id)
        assert len(completion_events[0].aggregate_key) == 64
        assert "target_id" not in completion_events[0].payload
        assert all(
            value.payload_sha256
            == next(
                item.outcome_content_sha256 for item in work_items if item.id == value.subject_id
            )
            for value in attestations
        )
        assert [value.event_type for value in audit] == [
            "platform.privacy_operation.requested",
            "platform.privacy_operation.executed",
        ]
        assert audit[1].previous_hash == audit[0].event_hash
        assert audit[0].payload["snapshot_hash"] == binding.snapshot_hash
        assert len(completion_events) == 1
        assert completion_events[0].payload["operation_id"] == str(requested.operation_id)
        assert completion_events[0].payload["manifest_hash"] == manifest.manifest_hash
        assert completion_events[0].request_hash == manifest.manifest_hash


@pytest.mark.parametrize(
    "mutation",
    ["missing_attestation", "unfinished_work", "surface_drift", "dsse_tamper"],
)
def test_finalize_rejects_incomplete_or_tampered_surface_authority(
    privacy_operations,
    mutation: str,
) -> None:
    factory, _lifecycle, _service, _requester, _approver, _finalizer, target_id = (
        privacy_operations
    )
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    with factory.begin() as db:
        if mutation == "missing_attestation":
            receipt = db.scalar(
                sa.select(PrivacyEvidenceAttestationRecord).where(
                    PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                    PrivacyEvidenceAttestationRecord.subject_kind == "surface",
                )
            )
            assert receipt is not None
            db.delete(receipt)
        elif mutation == "unfinished_work":
            item = db.scalar(
                sa.select(PrivacyDeletionWorkItemRecord).where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest_id
                )
            )
            assert item is not None
            item.status = "retry"
            item.outcome_content_sha256 = None
            item.evidence_attestation_id = None
        elif mutation == "surface_drift":
            item = db.scalar(
                sa.select(PrivacyDeletionWorkItemRecord).where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest_id
                )
            )
            assert item is not None
            item.surface = "unexpected_surface"
        else:
            receipt = db.scalar(
                sa.select(PrivacyEvidenceAttestationRecord).where(
                    PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                    PrivacyEvidenceAttestationRecord.subject_kind == "surface",
                )
            )
            assert receipt is not None
            receipt.payload_sha256 = _digest(["tampered-dsse", receipt.id])

    with pytest.raises(PlatformSecurityError) as blocked:
        _request_finalize(privacy_operations, manifest_id)
    assert blocked.value.code == "platform_privacy_manifest_blocked"
    with factory() as db:
        target = db.get(GlobalUser, target_id)
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        finalize_count = db.scalar(
            sa.select(sa.func.count())
            .select_from(PlatformAdminOperationRecord)
            .where(PlatformAdminOperationRecord.action == "privacy_deletion_finalize")
        )
        assert target is not None and target.status == "suspended"
        assert manifest is not None and manifest.completion_operation_id is None
        assert finalize_count == 0


def test_duplicate_execution_attempt_attestation_is_rejected_by_storage_authority(
    privacy_operations,
) -> None:
    factory, _lifecycle, _service, _requester, _approver, _finalizer, _target_id = (
        privacy_operations
    )
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    with pytest.raises(IntegrityError):
        with factory.begin() as db:
            manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
            item = db.scalar(
                sa.select(PrivacyDeletionWorkItemRecord).where(
                    PrivacyDeletionWorkItemRecord.manifest_id == manifest_id
                )
            )
            assert manifest is not None and item is not None
            existing = db.scalar(
                sa.select(PrivacyEvidenceAttestationRecord).where(
                    PrivacyEvidenceAttestationRecord.subject_id == item.id,
                    PrivacyEvidenceAttestationRecord.subject_kind == "surface",
                )
            )
            assert existing is not None
            duplicate = _surface_attestation(manifest, item, envelope_suffix="duplicate")
            duplicate.execution_attempt_id = existing.execution_attempt_id
            db.add(duplicate)
    with factory() as db:
        count = db.scalar(
            sa.select(sa.func.count())
            .select_from(PrivacyEvidenceAttestationRecord)
            .where(
                PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                PrivacyEvidenceAttestationRecord.subject_kind == "surface",
            )
        )
        assert count == 15


def test_finalize_approver_must_differ_from_start_approver(privacy_operations) -> None:
    factory, _lifecycle, service, _requester, start_approver, _finalizer, target_id = (
        privacy_operations
    )
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    requested = _request_finalize(privacy_operations, manifest_id)
    with pytest.raises(PlatformSecurityError) as same_approver:
        service.decide(
            start_approver,
            target_type="global_user",
            target_id=target_id,
            operation_id=requested.operation_id,
            expected_version=requested.version,
            decision="approve",
            decision_code="policy_confirmed",
            idempotency_key="privacy-decision-test",
            now=NOW + timedelta(seconds=5),
        )
    assert same_approver.value.code == "platform_separation_of_duties"
    with factory() as db:
        operation = db.get(PlatformAdminOperationRecord, requested.operation_id)
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        assert operation is not None and operation.status == "pending_staff_approval"
        assert manifest is not None and manifest.completion_operation_id is None


def test_active_hold_blocks_finalize_without_creating_approval(privacy_operations) -> None:
    factory, _lifecycle, _service, requester, _approver, _finalizer, target_id = privacy_operations
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    with factory.begin() as db:
        db.add(
            PrivacyLegalHoldRecord(
                id=uuid4(),
                target_type="global_user",
                target_id=target_id,
                tenant_id=None,
                status="active",
                scope=["all"],
                authority_ref="case:active-hold",
                reason="Preserve data during legal review",
                review_due_at=NOW + timedelta(days=30),
                placed_by_principal_id=requester.principal_id,
                version=1,
                created_at=NOW + timedelta(seconds=3),
                updated_at=NOW + timedelta(seconds=3),
            )
        )
    with pytest.raises(PlatformSecurityError) as blocked:
        _request_finalize(privacy_operations, manifest_id)
    assert blocked.value.code == "platform_privacy_deletion_blocked"
    with factory() as db:
        finalize_count = db.scalar(
            sa.select(sa.func.count())
            .select_from(PlatformAdminOperationRecord)
            .where(PlatformAdminOperationRecord.action == "privacy_deletion_finalize")
        )
        assert finalize_count == 0


def test_dsse_tamper_after_finalize_request_invalidates_immutable_approval(
    privacy_operations,
) -> None:
    factory, _lifecycle, service, _requester, _approver, finalizer, target_id = privacy_operations
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    requested = _request_finalize(privacy_operations, manifest_id)
    with factory.begin() as db:
        receipt = db.scalar(
            sa.select(PrivacyEvidenceAttestationRecord).where(
                PrivacyEvidenceAttestationRecord.manifest_id == manifest_id,
                PrivacyEvidenceAttestationRecord.subject_kind == "surface",
            )
        )
        assert receipt is not None
        receipt.envelope_sha256 = _digest(["tampered-envelope", receipt.id])
    result = service.decide(
        finalizer,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=5),
    )
    assert result.status == "failed"
    assert result.error_code == "approval_stale"
    with factory() as db:
        target = db.get(GlobalUser, target_id)
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        operation = db.get(PlatformAdminOperationRecord, requested.operation_id)
        failed_audit = db.scalar(
            sa.select(PlatformAuditEventRecord).where(
                PlatformAuditEventRecord.operation_id == requested.operation_id,
                PlatformAuditEventRecord.event_type == "platform.privacy_operation.failed",
            )
        )
        completion_count = db.scalar(
            sa.select(sa.func.count())
            .select_from(ControlPlaneOutboxEvent)
            .where(ControlPlaneOutboxEvent.event_type == "privacy.deletion.governed_completed")
        )
        assert target is not None and target.status == "suspended"
        assert manifest is not None and manifest.completion_operation_id is None
        assert operation is not None and operation.status == "failed"
        assert failed_audit is not None
        assert completion_count == 0


def test_pending_governed_start_blocks_ordinary_user_restore(privacy_operations) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    platform_lifecycle = PlatformLifecycleService(factory)
    suspended = platform_lifecycle.suspend_user(
        requester,
        user_id=target_id,
        expected_security_version=1,
        approval_ref="approval:pre-deletion-suspend",
        reason="Prepare a governed deletion request",
        idempotency_key="pre-deletion-suspend",
        now=NOW + timedelta(milliseconds=500),
    )
    assert suspended.result["security_version"] == 2
    requested = _request_start(
        lifecycle,
        service,
        requester,
        target_id,
        now=NOW + timedelta(seconds=1),
    )
    assert requested.status == "pending_staff_approval"

    with pytest.raises(PlatformSecurityError) as blocked:
        platform_lifecycle.restore_user(
            approver,
            user_id=target_id,
            expected_security_version=2,
            approval_ref="approval:ordinary-restore",
            reason="Ordinary restore cannot cancel deletion governance",
            idempotency_key="restore-during-pending-deletion",
            now=NOW + timedelta(seconds=2),
        )
    assert blocked.value.code == "platform_privacy_restore_governance_required"
    with factory() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "suspended"
        manifest_count = db.scalar(
            sa.select(sa.func.count()).select_from(PrivacyDeletionManifestRecord)
        )
        assert manifest_count == 0


def test_governed_start_binds_user_state_and_tombstone_blocks_restore(
    privacy_operations,
) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    with factory.begin() as db:
        db.add(
            IdentityConnection(
                id=uuid4(),
                user_id=target_id,
                provider="oidc",
                issuer="https://customer-idp.example.test",
                subject="privacy-subject",
                email_normalized="subject@example.test",
                email_verified=True,
                status="active",
                created_at=NOW,
                updated_at=NOW,
            )
        )
    requested = _request_start(lifecycle, service, requester, target_id)
    completed = service.decide(
        approver,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=2),
    )
    assert completed.status == "succeeded"
    with factory() as db:
        target = db.get(GlobalUser, target_id)
        manifest = db.scalar(
            sa.select(PrivacyDeletionManifestRecord).where(
                PrivacyDeletionManifestRecord.target_type == "global_user",
                PrivacyDeletionManifestRecord.target_id == target_id,
            )
        )
        assert target is not None and target.status == "suspended"
        assert target.security_version == 2
        assert manifest is not None and manifest.expected_target_version == 2
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PrivacyIdentityTombstoneRecord)) == 1
        )

    with pytest.raises(PlatformSecurityError) as blocked:
        PlatformLifecycleService(factory).restore_user(
            approver,
            user_id=target_id,
            expected_security_version=2,
            approval_ref="approval:ordinary-restore",
            reason="A Tombstone requires governed deletion cancellation",
            idempotency_key="restore-after-deletion-start",
            now=NOW + timedelta(seconds=3),
        )
    assert blocked.value.code == "platform_privacy_restore_governance_required"


def test_governed_start_binds_tenant_state_and_blocks_ordinary_restore(
    privacy_operations,
) -> None:
    factory, lifecycle, service, requester, approver, _finalizer, _target_id = privacy_operations
    tenant_id = uuid4()
    with factory.begin() as db:
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"privacy-{tenant_id.hex[:12]}",
                name="Privacy Tenant",
                status="suspended",
                plan="enterprise",
                home_region="cn-east-1",
                lifecycle_version=7,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    preview = lifecycle.preview_deletion(
        requester,
        target_type="tenant",
        target_id=tenant_id,
        now=NOW + timedelta(seconds=1),
    )
    requested = service.request_deletion_start(
        requester,
        target_type="tenant",
        target_id=tenant_id,
        expected_target_version=preview.target_version,
        preview_hash=preview.preview_hash,
        reason_code="tenant_termination",
        case_reference="privacy-tenant-case-001",
        expires_at=NOW + timedelta(minutes=15),
        idempotency_key="privacy-tenant-start-001",
        now=NOW + timedelta(seconds=1),
    )
    completed = service.decide(
        approver,
        target_type="tenant",
        target_id=tenant_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=2),
    )
    assert completed.status == "succeeded"
    with factory() as db:
        tenant = db.get(Tenant, tenant_id)
        manifest = db.scalar(
            sa.select(PrivacyDeletionManifestRecord).where(
                PrivacyDeletionManifestRecord.target_type == "tenant",
                PrivacyDeletionManifestRecord.target_id == tenant_id,
            )
        )
        assert tenant is not None and tenant.status == "pending_deletion"
        assert tenant.lifecycle_version == 8
        assert manifest is not None and manifest.expected_target_version == 8

    with pytest.raises(PlatformSecurityError) as blocked:
        PlatformLifecycleService(factory).restore_tenant(
            approver,
            tenant_id=tenant_id,
            expected_lifecycle_version=8,
            approval_ref="approval:ordinary-tenant-restore",
            reason="Tenant deletion needs an explicit governed cancellation",
            idempotency_key="restore-tenant-after-deletion-start",
            now=NOW + timedelta(seconds=3),
        )
    assert blocked.value.code == "platform_privacy_restore_governance_required"


def test_finalize_request_rejects_manifest_target_version_drift(privacy_operations) -> None:
    factory, _lifecycle, service, requester, approver, _finalizer, target_id = privacy_operations
    start_operation_id = uuid4()
    manifest_id = uuid4()
    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None
        target.status = "suspended"
        target.security_version = 3
        target.updated_at = NOW + timedelta(seconds=3)
        db.add(
            PlatformAdminOperationRecord(
                id=start_operation_id,
                action="privacy_deletion_start",
                risk_level="critical",
                tenant_id=None,
                target_type="privacy_global_user",
                target_id=target_id,
                requested_by_principal_id=requester.principal_id,
                approved_by_principal_id=approver.principal_id,
                idempotency_key="seeded-governed-start",
                request_hash="a" * 64,
                reason="data_subject_request",
                status="succeeded",
                version=2,
                result={"decision": "approved"},
                approved_at=NOW + timedelta(seconds=2),
                completed_at=NOW + timedelta(seconds=2),
                created_at=NOW + timedelta(seconds=1),
                updated_at=NOW + timedelta(seconds=2),
            )
        )
        db.add(
            PrivacyDeletionManifestRecord(
                id=manifest_id,
                target_type="global_user",
                target_id=target_id,
                tenant_id=None,
                requested_by_principal_id=requester.principal_id,
                start_operation_id=start_operation_id,
                approval_provenance="governed_operation",
                idempotency_key="seeded-governed-manifest",
                request_hash="b" * 64,
                approval_ref=f"operation:{start_operation_id}",
                reason="data_subject_request",
                expected_target_version=2,
                preview_hash="c" * 64,
                status="ready_to_finalize",
                blockers=[],
                surface_outcomes={},
                version=1,
                started_at=NOW + timedelta(seconds=2),
                retention_status="pending",
                updated_at=NOW + timedelta(seconds=2),
            )
        )

    with pytest.raises(PlatformSecurityError) as stale:
        service.request_deletion_finalize(
            requester,
            target_type="global_user",
            target_id=target_id,
            manifest_id=manifest_id,
            expected_manifest_version=1,
            reason_code="data_subject_request",
            case_reference="privacy-stale-finalize-001",
            expires_at=NOW + timedelta(minutes=15),
            idempotency_key="privacy-stale-finalize-001",
            now=NOW + timedelta(seconds=4),
        )
    assert stale.value.code == "platform_privacy_manifest_conflict"


def test_finalize_approval_fails_closed_on_target_version_drift(privacy_operations) -> None:
    factory, _lifecycle, service, _requester, _approver, finalizer, target_id = privacy_operations
    manifest_id = _prepare_finalizable_manifest(privacy_operations)
    requested = _request_finalize(privacy_operations, manifest_id)
    with factory.begin() as db:
        target = db.get(GlobalUser, target_id)
        assert target is not None and target.status == "suspended"
        target.security_version += 1
        target.updated_at = NOW + timedelta(seconds=5)

    result = service.decide(
        finalizer,
        target_type="global_user",
        target_id=target_id,
        operation_id=requested.operation_id,
        expected_version=requested.version,
        decision="approve",
        decision_code="policy_confirmed",
        idempotency_key="privacy-decision-test",
        now=NOW + timedelta(seconds=6),
    )
    assert result.status == "failed"
    assert result.error_code == "approval_stale"
    with factory() as db:
        target = db.get(GlobalUser, target_id)
        manifest = db.get(PrivacyDeletionManifestRecord, manifest_id)
        assert target is not None and target.status == "suspended"
        assert manifest is not None and manifest.status == "ready_to_finalize"
        assert manifest.completion_operation_id is None
