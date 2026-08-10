from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import ControlPlaneOutboxEvent, GlobalUser, SaasBase
from saas.control_plane.platform_models import PlatformStaffPrincipalRecord
from saas.control_plane.platform_security import PlatformSecurityError, ValidatedPlatformPrincipal
from saas.control_plane.privacy_attestation import (
    PRIVACY_DSSE_KEY_PURPOSE,
    PRIVACY_DSSE_PAYLOAD_TYPE,
    PrivacyAttestationTrustKey,
    PrivacyAttestationVerifier,
    PrivacyDsseEnvelope,
    canonical_json,
    dsse_pae,
)
from saas.control_plane.privacy_execution import (
    ClaimedPrivacyBackupItem,
    ClaimedPrivacyWorkItem,
    PrivacyBackupCatalogEntry,
    PrivacyEvidenceOutcome,
    PrivacyExecutionPolicy,
    PrivacyExecutionService,
    WorkloadIdentity,
    privacy_adapter_error_hmac,
    privacy_backup_catalog_digest,
    privacy_backup_locator_hmac,
    privacy_target_locator_hmac,
)
from saas.control_plane.privacy_models import (
    PrivacyBackupRetentionItemRecord,
    PrivacyDeletionAttemptRecord,
    PrivacyDeletionManifestRecord,
    PrivacyDeletionWorkItemRecord,
    PrivacyEvidenceAttestationRecord,
    PrivacyLegalHoldRecord,
)

NOW = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
LOCATOR_KEY = b"l" * 32
POLICY = PrivacyExecutionPolicy(
    audience="omnigent:privacy-execution",
    trusted_issuers=frozenset({"https://workload-id.example.test"}),
    product_revision="a" * 40,
    upstream_revision="b" * 40,
    schema_revision="pc5b00000003",
    adapter_contract_version="privacy-adapter.v1",
    verifier_policy_version="2026-08-10.p1-privacy-execution",
    lease_duration=timedelta(minutes=2),
    base_backoff=timedelta(seconds=4),
    max_backoff=timedelta(minutes=2),
)


@dataclass(frozen=True, slots=True)
class ExecutionHarness:
    factory: sessionmaker[Session]
    service: PrivacyExecutionService
    private_key: Ed25519PrivateKey
    identity: WorkloadIdentity
    staff_id: UUID
    target_id: UUID
    manifest_id: UUID
    work_item_id: UUID
    backup_item_id: UUID


@pytest.fixture
def execution() -> ExecutionHarness:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    identity = WorkloadIdentity(
        issuer="https://workload-id.example.test",
        subject="spiffe://prod/privacy-dispatcher",
        audience=POLICY.audience,
        authenticated_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=3),
    )
    verifier = PrivacyAttestationVerifier(
        (
            PrivacyAttestationTrustKey(
                key_id="privacy-prod-2026-08",
                public_key_pem=public_pem,
                workflow_identity=identity.subject,
                purpose=PRIVACY_DSSE_KEY_PURPOSE,
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=30),
                revocation_checked_at=NOW,
            ),
        )
    )
    staff_id, target_id, manifest_id, work_item_id, backup_item_id = (uuid4() for _ in range(5))
    with factory.begin() as db:
        db.add(
            PlatformStaffPrincipalRecord(
                id=staff_id,
                identity_connection_ref="staff:privacy-bootstrap",
                issuer="https://staff-idp.example.test",
                subject="privacy-bootstrap",
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add(
            GlobalUser(
                id=target_id,
                status="suspended",
                display_name="Privacy Subject",
                primary_email_normalized="subject@example.test",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.flush()
        db.add(
            PrivacyDeletionManifestRecord(
                id=manifest_id,
                target_type="global_user",
                target_id=target_id,
                tenant_id=None,
                requested_by_principal_id=staff_id,
                approval_provenance="legacy_unverified",
                idempotency_key=f"privacy:{manifest_id}",
                request_hash="1" * 64,
                approval_ref="test-approval",
                reason="Privacy execution contract test",
                expected_target_version=1,
                preview_hash="2" * 64,
                status="executing",
                blockers=[],
                surface_outcomes={
                    "object_and_artifact_store": {
                        "disposition": "erase",
                        "status": "pending",
                    }
                },
                version=1,
                started_at=NOW,
                retention_status="pending",
                updated_at=NOW,
            )
        )
        db.flush()
        db.add_all(
            (
                PrivacyDeletionWorkItemRecord(
                    id=work_item_id,
                    manifest_id=manifest_id,
                    target_type="global_user",
                    target_id=target_id,
                    tenant_id=None,
                    runtime_partition_id=None,
                    surface="object_and_artifact_store",
                    disposition="erase",
                    resource_scope_hmac="3" * 64,
                    adapter_type="object_store_adapter",
                    status="pending",
                    attempt_count=0,
                    max_attempts=2,
                    available_at=NOW,
                    lease_generation=0,
                    replay_generation=0,
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                PrivacyBackupRetentionItemRecord(
                    id=backup_item_id,
                    manifest_id=manifest_id,
                    target_type="global_user",
                    target_id=target_id,
                    tenant_id=None,
                    runtime_partition_id=None,
                    provider="test-backup-provider",
                    backup_data_class="database_snapshot",
                    backup_locator_hmac=privacy_backup_locator_hmac(
                        LOCATOR_KEY,
                        "test-backup-provider",
                        "backup://opaque-handle/1",
                    ),
                    resource_handle_ref="backup://opaque-handle/1",
                    catalog_snapshot_sha256="5" * 64,
                    tombstone_sha256="6" * 64,
                    object_lock_until=NOW,
                    purge_due_at=NOW,
                    status="retention_wait",
                    attempt_count=0,
                    max_attempts=2,
                    available_at=NOW,
                    lease_generation=0,
                    replay_generation=0,
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            )
        )
    return ExecutionHarness(
        factory=factory,
        service=PrivacyExecutionService(
            factory,
            verifier_session_factory=factory,
            verifier=verifier,
            policy=POLICY,
            locator_hmac_key=LOCATOR_KEY,
        ),
        private_key=private_key,
        identity=identity,
        staff_id=staff_id,
        target_id=target_id,
        manifest_id=manifest_id,
        work_item_id=work_item_id,
        backup_item_id=backup_item_id,
    )


def _claim_work(execution: ExecutionHarness, *, now: datetime = NOW) -> ClaimedPrivacyWorkItem:
    claim = execution.service.claim_work_item(
        execution.identity,
        target_type="global_user",
        target_id=execution.target_id,
        manifest_id=execution.manifest_id,
        now=now,
    )
    assert claim is not None
    return claim


def _claim_backup(execution: ExecutionHarness, *, now: datetime = NOW) -> ClaimedPrivacyBackupItem:
    claim = execution.service.claim_backup_item(
        execution.identity,
        target_type="global_user",
        target_id=execution.target_id,
        manifest_id=execution.manifest_id,
        now=now,
    )
    assert claim is not None
    return claim


def _prepare_backup_catalog_work(execution: ExecutionHarness) -> None:
    with execution.factory.begin() as db:
        db.execute(
            sa.delete(PrivacyBackupRetentionItemRecord).where(
                PrivacyBackupRetentionItemRecord.manifest_id == execution.manifest_id
            )
        )
        item = db.get(PrivacyDeletionWorkItemRecord, execution.work_item_id)
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        assert item is not None and manifest is not None
        item.surface = "backups_and_snapshots"
        item.disposition = "tombstone_then_expire"
        item.adapter_type = "backup_catalog_adapter"
        manifest.surface_outcomes = {
            "backups_and_snapshots": {
                "disposition": "tombstone_then_expire",
                "status": "pending",
            }
        }


def _payload(
    claim: ClaimedPrivacyWorkItem | ClaimedPrivacyBackupItem,
    *,
    evidence_sha256: str,
    issued_at: datetime,
    outcome: PrivacyEvidenceOutcome | None = None,
) -> dict[str, object]:
    backup = isinstance(claim, ClaimedPrivacyBackupItem)
    observed = outcome or PrivacyEvidenceOutcome(
        evidence_sha256=evidence_sha256,
        tombstone_sha256=claim.tombstone_sha256 if backup else None,
    )
    return {
        "schema_version": 1,
        "subject_kind": "backup_purge" if backup else "surface_attempt",
        "manifest_id": str(claim.manifest_id),
        "work_item_id": str(claim.item_id),
        "attempt_id": str(claim.attempt_id),
        "surface": "backups_and_snapshots" if backup else claim.surface,
        "phase": "retention_purge" if backup else "primary_erasure",
        "target_locator_hmac": (
            claim.backup_locator_hmac if backup else claim.resource_scope_hmac
        ),
        "disposition": "tombstone_then_expire" if backup else claim.disposition,
        "outcome": "succeeded",
        "evidence_sha256": observed.evidence_sha256,
        "remaining_item_count": observed.remaining_item_count,
        "runtime_accessible": observed.runtime_accessible,
        "direct_identifiers_remaining": observed.direct_identifiers_remaining,
        "retention_until": (
            observed.retention_until.isoformat() if observed.retention_until is not None else None
        ),
        "retention_basis": observed.retention_basis,
        "tombstone_sha256": observed.tombstone_sha256,
        "product_revision": POLICY.product_revision,
        "upstream_revision": POLICY.upstream_revision,
        "schema_revision": POLICY.schema_revision,
        "adapter_contract_version": POLICY.adapter_contract_version,
        "policy_version": POLICY.verifier_policy_version,
        "workflow_identity": "spiffe://prod/privacy-dispatcher",
        "artifact_uri": f"https://evidence.example.test/privacy/{claim.attempt_id}.json",
        "immutability_receipt_sha256": "7" * 64,
        "kms_audit_receipt_sha256": "8" * 64,
        "observed_at": issued_at.isoformat(),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(minutes=15)).isoformat(),
    }


def _envelope(execution: ExecutionHarness, payload: dict[str, object]) -> PrivacyDsseEnvelope:
    encoded = canonical_json(payload)
    signature = execution.private_key.sign(dsse_pae(PRIVACY_DSSE_PAYLOAD_TYPE, encoded))
    return PrivacyDsseEnvelope(
        envelope={
            "payloadType": PRIVACY_DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(encoded).decode("ascii"),
            "signatures": [
                {
                    "keyid": "privacy-prod-2026-08",
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
        artifact_uri=f"https://evidence.example.test/privacy/{payload['attempt_id']}.json",
        immutability_receipt_sha256="7" * 64,
        kms_audit_receipt_sha256="8" * 64,
    )


def test_claim_hashes_lease_and_executor_and_rejects_staff_identity(
    execution: ExecutionHarness,
) -> None:
    claim = _claim_work(execution)
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, claim.item_id)
        assert item is not None
        assert claim.lease_token not in repr(claim)
        assert item.lease_token_hash == sha256(claim.lease_token.encode()).hexdigest()
        assert item.lease_token_hash != claim.lease_token
        assert (
            item.executor_identity_sha256
            == sha256(
                canonical_json(
                    {
                        "audience": execution.identity.audience,
                        "issuer": execution.identity.issuer,
                        "subject": execution.identity.subject,
                    }
                )
            ).hexdigest()
        )
        executor_identity_sha256 = item.executor_identity_sha256
        assert executor_identity_sha256 is not None
        assert execution.identity.subject not in executor_identity_sha256

    staff = ValidatedPlatformPrincipal(
        session_id=uuid4(),
        principal_id=execution.staff_id,
        security_version=1,
        authn_method="passkey",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        roles=frozenset(),
        permissions=frozenset(),
    )
    with pytest.raises(PlatformSecurityError) as rejected:
        execution.service.claim_work_item(
            cast(WorkloadIdentity, staff),
            target_type="global_user",
            target_id=execution.target_id,
            manifest_id=execution.manifest_id,
            now=NOW,
        )
    assert rejected.value.code == "platform_privacy_workload_identity_invalid"

    with pytest.raises(PlatformSecurityError) as wrong_issuer:
        execution.service.claim_work_item(
            replace(execution.identity, issuer="https://attacker-idp.example.test"),
            target_type="global_user",
            target_id=execution.target_id,
            manifest_id=execution.manifest_id,
            now=NOW,
        )
    assert wrong_issuer.value.code == "platform_privacy_workload_identity_invalid"


def test_hold_first_blocks_surface_claim_without_creating_destructive_lease(
    execution: ExecutionHarness,
) -> None:
    with execution.factory.begin() as db:
        db.add(
            PrivacyLegalHoldRecord(
                id=uuid4(),
                target_type="global_user",
                target_id=execution.target_id,
                tenant_id=None,
                status="active",
                scope=["object_and_artifact_store"],
                authority_ref="case:hold-first",
                reason="Preserve the surface before destructive execution",
                review_due_at=NOW + timedelta(days=30),
                placed_by_principal_id=execution.staff_id,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )

    claim = execution.service.claim_work_item(
        execution.identity,
        target_type="global_user",
        target_id=execution.target_id,
        manifest_id=execution.manifest_id,
        now=NOW + timedelta(seconds=1),
    )

    assert claim is None
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, execution.work_item_id)
        assert item is not None and item.status == "pending"
        assert item.lease_token_hash is None


def test_claim_first_authorization_is_exact_and_hold_recheck_fails_closed(
    execution: ExecutionHarness,
) -> None:
    claim = _claim_work(execution)
    authorization = execution.service.authorize_destructive_execution(
        execution.identity,
        claim,
        now=NOW + timedelta(seconds=1),
    )
    assert authorization.item_id == claim.item_id
    assert authorization.attempt_id == claim.attempt_id
    assert authorization.lease_generation == claim.lease_generation
    assert authorization.expires_at == claim.lease_expires_at
    assert len(authorization.authorization_sha256) == 64
    assert claim.lease_token not in repr(authorization)

    # Bypass the public Hold service to prove every pre-I/O and commit path
    # independently fails closed against legacy or out-of-band Hold insertion.
    with execution.factory.begin() as db:
        db.add(
            PrivacyLegalHoldRecord(
                id=uuid4(),
                target_type="global_user",
                target_id=execution.target_id,
                tenant_id=None,
                status="active",
                scope=["object_and_artifact_store"],
                authority_ref="case:out-of-band-hold",
                reason="Exercise the independent destructive execution fence",
                review_due_at=NOW + timedelta(days=30),
                placed_by_principal_id=execution.staff_id,
                version=1,
                created_at=NOW + timedelta(seconds=2),
                updated_at=NOW + timedelta(seconds=2),
            )
        )

    with pytest.raises(PlatformSecurityError) as preflight:
        execution.service.authorize_destructive_execution(
            execution.identity,
            claim,
            now=NOW + timedelta(seconds=3),
        )
    assert preflight.value.code == "platform_privacy_execution_blocked"

    evidence = "9" * 64
    with pytest.raises(PlatformSecurityError) as completion:
        execution.service.complete_work_item(
            execution.identity,
            claim,
            outcome=PrivacyEvidenceOutcome(evidence_sha256=evidence),
            envelope=_envelope(
                execution,
                _payload(
                    claim,
                    evidence_sha256=evidence,
                    issued_at=NOW + timedelta(seconds=3),
                ),
            ),
            now=NOW + timedelta(seconds=3),
        )
    assert completion.value.code == "platform_privacy_execution_blocked"


def test_destructive_authorization_rejects_expired_surface_and_backup_leases(
    execution: ExecutionHarness,
) -> None:
    surface_claim = _claim_work(execution)
    with pytest.raises(PlatformSecurityError) as surface_expired:
        execution.service.authorize_destructive_execution(
            execution.identity,
            surface_claim,
            now=surface_claim.lease_expires_at + timedelta(microseconds=1),
        )
    assert surface_expired.value.code == "platform_privacy_execution_lease_lost"

    backup_claim = _claim_backup(execution)
    with pytest.raises(PlatformSecurityError) as backup_expired:
        execution.service.authorize_destructive_execution(
            execution.identity,
            backup_claim,
            now=backup_claim.lease_expires_at + timedelta(microseconds=1),
        )
    assert backup_expired.value.code == "platform_privacy_execution_lease_lost"


def test_expired_lease_is_reclaimed_with_generation_fence(execution: ExecutionHarness) -> None:
    first = _claim_work(execution)
    reclaimed_at = first.lease_expires_at + timedelta(seconds=1)
    second = _claim_work(execution, now=reclaimed_at)
    assert second.attempt_number == 2
    assert second.lease_generation == first.lease_generation + 1
    assert second.lease_token != first.lease_token

    evidence = "9" * 64
    with pytest.raises(PlatformSecurityError) as stale:
        execution.service.complete_work_item(
            execution.identity,
            first,
            outcome=PrivacyEvidenceOutcome(evidence_sha256=evidence),
            envelope=_envelope(
                execution, _payload(first, evidence_sha256=evidence, issued_at=reclaimed_at)
            ),
            now=reclaimed_at,
        )
    assert stale.value.code == "platform_privacy_execution_lease_lost"
    with execution.factory() as db:
        attempts = tuple(db.scalars(sa.select(PrivacyDeletionAttemptRecord)))
        assert len(attempts) == 1
        assert attempts[0].outcome == "lease_lost"
        assert attempts[0].attempt_number == 1


def test_retry_uses_deterministic_backoff_then_dead_letters_without_raw_error(
    execution: ExecutionHarness,
) -> None:
    first = _claim_work(execution)
    raw_first = "provider timeout with customer@example.test"
    retried = execution.service.fail_work_item(
        execution.identity,
        first,
        error_code="privacy_provider_timeout",
        raw_error=raw_first,
        now=NOW + timedelta(seconds=1),
    )
    assert retried.status == "retry"
    assert retried.available_at > NOW + timedelta(seconds=1)

    second = _claim_work(execution, now=retried.available_at)
    raw_second = "provider timeout leaked /tenant/private/path"
    dead = execution.service.fail_work_item(
        execution.identity,
        second,
        error_code="privacy_provider_timeout",
        raw_error=raw_second,
        now=retried.available_at + timedelta(seconds=1),
    )
    assert dead.status == "dead_letter"
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, execution.work_item_id)
        attempts = tuple(
            db.scalars(
                sa.select(PrivacyDeletionAttemptRecord).order_by(
                    PrivacyDeletionAttemptRecord.attempt_number
                )
            )
        )
        events = tuple(
            db.scalars(
                sa.select(ControlPlaneOutboxEvent).order_by(ControlPlaneOutboxEvent.created_at)
            )
        )
        assert item is not None
        assert item.status == "dead_letter"
        assert item.last_error_sha256 == privacy_adapter_error_hmac(
            LOCATOR_KEY,
            execution.work_item_id,
            "privacy_provider_timeout",
            raw_second,
        )
        assert [attempt.outcome for attempt in attempts] == ["retry", "dead_letter"]
        assert attempts[0].error_sha256 == privacy_adapter_error_hmac(
            LOCATOR_KEY,
            execution.work_item_id,
            "privacy_provider_timeout",
            raw_first,
        )
        assert attempts[0].error_sha256 != sha256(raw_first.encode()).hexdigest()
        assert raw_first not in repr(attempts)
        assert raw_second not in repr(item.__dict__)
        assert [event.event_type for event in events] == [
            "privacy.execution.work_retry_scheduled",
            "privacy.execution.work_dead_lettered",
        ]
        required = {
            "schema_version",
            "manifest_id",
            "target_type",
            "target_locator_hmac",
            "item_id",
            "attempt_id",
            "status",
            "content_sha256",
            "surface",
            "replay_generation",
            "attempt_number",
            "error_code",
            "available_at",
        }
        assert all(required == event.payload.keys() for event in events)
        assert raw_first not in repr(events)
        assert raw_second not in repr(events)


def test_backup_retry_dead_letter_and_retention_attention_emit_content_blind_events(
    execution: ExecutionHarness,
) -> None:
    first = _claim_backup(execution)
    raw_first = "backup timeout for secret provider handle"
    retried = execution.service.fail_backup_item(
        execution.identity,
        first,
        error_code="privacy_provider_timeout",
        raw_error=raw_first,
        now=NOW + timedelta(seconds=1),
    )
    second = _claim_backup(execution, now=retried.available_at)
    raw_second = "backup timeout for customer@example.test"
    dead = execution.service.fail_backup_item(
        execution.identity,
        second,
        error_code="privacy_provider_timeout",
        raw_error=raw_second,
        now=retried.available_at + timedelta(seconds=1),
    )
    assert dead.status == "dead_letter"
    with execution.factory() as db:
        backup = db.get(PrivacyBackupRetentionItemRecord, execution.backup_item_id)
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        events = tuple(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        event_types = {event.event_type for event in events}
        assert backup is not None and backup.status == "dead_letter"
        assert manifest is not None and manifest.retention_status == "attention_required"
        assert event_types == {
            "privacy.execution.backup_retry_scheduled",
            "privacy.execution.backup_dead_lettered",
            "privacy.execution.retention_attention_required",
        }
        assert all(event.payload["manifest_id"] == str(execution.manifest_id) for event in events)
        assert all(
            event.payload["target_locator_hmac"]
            == privacy_target_locator_hmac(LOCATOR_KEY, "global_user", execution.target_id)
            for event in events
        )
        assert all(event.payload["item_id"] == str(execution.backup_item_id) for event in events)
        assert raw_first not in repr(events)
        assert raw_second not in repr(events)


def test_work_success_appends_dsse_receipts_and_projects_manifest(
    execution: ExecutionHarness,
) -> None:
    claim = _claim_work(execution)
    completed_at = NOW + timedelta(seconds=1)
    evidence = "9" * 64
    result = execution.service.complete_work_item(
        execution.identity,
        claim,
        outcome=PrivacyEvidenceOutcome(evidence_sha256=evidence),
        envelope=_envelope(
            execution,
            _payload(claim, evidence_sha256=evidence, issued_at=completed_at),
        ),
        now=completed_at,
    )
    assert result.status == "succeeded"
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, claim.item_id)
        attempt = db.get(PrivacyDeletionAttemptRecord, result.attempt_id)
        attestation = db.get(PrivacyEvidenceAttestationRecord, result.attestation_id)
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        assert item is not None and item.status == "succeeded"
        assert attempt is not None and attempt.work_item_id == item.id
        assert attestation is not None and attestation.subject_id == item.id
        assert attestation.subject_kind == "surface"
        assert manifest is not None and manifest.status == "ready_to_finalize"
        surface_outcome = cast(dict[str, object], manifest.surface_outcomes[item.surface])
        assert surface_outcome["status"] == "erased"


def test_non_backup_surface_rejects_catalog_without_mutation(
    execution: ExecutionHarness,
) -> None:
    claim = _claim_work(execution)
    completed_at = NOW + timedelta(seconds=1)
    outcome = PrivacyEvidenceOutcome(evidence_sha256="9" * 64)
    catalog = (
        PrivacyBackupCatalogEntry(
            provider="object-store-a",
            backup_data_class="database_snapshot",
            backup_locator_hmac=privacy_backup_locator_hmac(
                LOCATOR_KEY, "object-store-a", "backup://internal/opaque-a"
            ),
            resource_handle_ref="backup://internal/opaque-a",
            catalog_snapshot_sha256="b" * 64,
            tombstone_sha256="c" * 64,
            purge_due_at=NOW + timedelta(days=30),
        ),
    )
    with pytest.raises(PlatformSecurityError) as rejected:
        execution.service.complete_work_item(
            execution.identity,
            claim,
            outcome=outcome,
            envelope=_envelope(
                execution,
                _payload(
                    claim,
                    evidence_sha256=outcome.evidence_sha256,
                    issued_at=completed_at,
                    outcome=outcome,
                ),
            ),
            backup_catalog=catalog,
            now=completed_at,
        )
    assert rejected.value.code == "platform_privacy_backup_catalog_invalid"
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, claim.item_id)
        assert item is not None and item.status == "leased"
        assert db.scalar(sa.select(sa.func.count()).select_from(PrivacyDeletionAttemptRecord)) == 0


def test_backup_catalog_is_dsse_bound_and_materialized_atomically(
    execution: ExecutionHarness,
) -> None:
    _prepare_backup_catalog_work(execution)
    claim = _claim_work(execution)
    completed_at = NOW + timedelta(seconds=1)
    entries = (
        PrivacyBackupCatalogEntry(
            provider="object-store-a",
            backup_data_class="database_snapshot",
            backup_locator_hmac=privacy_backup_locator_hmac(
                LOCATOR_KEY, "object-store-a", "backup://internal/opaque-a"
            ),
            resource_handle_ref="backup://internal/opaque-a",
            catalog_snapshot_sha256="b" * 64,
            tombstone_sha256="c" * 64,
            object_lock_until=NOW + timedelta(days=10),
            purge_due_at=NOW + timedelta(days=30),
        ),
        PrivacyBackupCatalogEntry(
            provider="object-store-b",
            backup_data_class="artifact_snapshot",
            backup_locator_hmac=privacy_backup_locator_hmac(
                LOCATOR_KEY, "object-store-b", "backup://internal/opaque-b"
            ),
            resource_handle_ref="backup://internal/opaque-b",
            catalog_snapshot_sha256="e" * 64,
            tombstone_sha256="f" * 64,
            object_lock_until=None,
            purge_due_at=NOW + timedelta(days=35),
        ),
    )
    aggregate_tombstone = privacy_backup_catalog_digest(entries)
    changed_handles = tuple(
        replace(entry, resource_handle_ref=f"backup://different/{index}")
        for index, entry in enumerate(entries)
    )
    assert privacy_backup_catalog_digest(changed_handles) == aggregate_tombstone
    assert "backup://internal/opaque-a" not in repr(entries[0])
    assert (
        privacy_backup_catalog_digest((replace(entries[0], provider="provider-drift"), entries[1]))
        != aggregate_tombstone
    )
    outcome = PrivacyEvidenceOutcome(
        evidence_sha256="9" * 64,
        remaining_item_count=2,
        retention_until=NOW + timedelta(days=35),
        retention_basis="backup-retention-policy-v1",
        tombstone_sha256=aggregate_tombstone,
    )
    payload = _payload(
        claim,
        evidence_sha256=outcome.evidence_sha256,
        issued_at=completed_at,
        outcome=outcome,
    )
    envelope = _envelope(execution, payload)
    encoded_payload = cast(str, envelope.envelope["payload"])
    decoded_payload = base64.b64decode(encoded_payload).decode()
    assert "backup://internal/opaque-a" not in decoded_payload
    assert "backup://internal/opaque-b" not in decoded_payload

    with pytest.raises(PlatformSecurityError, match="opaque handle"):
        execution.service.complete_work_item(
            execution.identity,
            claim,
            outcome=outcome,
            envelope=envelope,
            backup_catalog=changed_handles,
            now=completed_at,
        )

    invalid_outcome = replace(outcome, tombstone_sha256="0" * 64)
    with pytest.raises(PlatformSecurityError) as invalid_catalog:
        execution.service.complete_work_item(
            execution.identity,
            claim,
            outcome=invalid_outcome,
            envelope=_envelope(
                execution,
                _payload(
                    claim,
                    evidence_sha256=invalid_outcome.evidence_sha256,
                    issued_at=completed_at,
                    outcome=invalid_outcome,
                ),
            ),
            backup_catalog=entries,
            now=completed_at,
        )
    assert invalid_catalog.value.code == "platform_privacy_backup_catalog_invalid"
    with execution.factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PrivacyBackupRetentionItemRecord))
            == 0
        )

    execution.service.complete_work_item(
        execution.identity,
        claim,
        outcome=outcome,
        envelope=envelope,
        backup_catalog=entries,
        now=completed_at,
    )
    with execution.factory() as db:
        catalog = tuple(
            db.scalars(
                sa.select(PrivacyBackupRetentionItemRecord).order_by(
                    PrivacyBackupRetentionItemRecord.backup_locator_hmac
                )
            )
        )
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        assert len(catalog) == 2
        assert {item.resource_handle_ref for item in catalog} == {
            "backup://internal/opaque-a",
            "backup://internal/opaque-b",
        }
        assert manifest is not None and manifest.retention_status == "pending"
        assert manifest.retention_completed_at is None


def test_empty_backup_catalog_marks_retention_not_applicable(
    execution: ExecutionHarness,
) -> None:
    _prepare_backup_catalog_work(execution)
    claim = _claim_work(execution)
    completed_at = NOW + timedelta(seconds=1)
    outcome = PrivacyEvidenceOutcome(evidence_sha256="9" * 64)
    execution.service.complete_work_item(
        execution.identity,
        claim,
        outcome=outcome,
        envelope=_envelope(
            execution,
            _payload(
                claim,
                evidence_sha256=outcome.evidence_sha256,
                issued_at=completed_at,
                outcome=outcome,
            ),
        ),
        backup_catalog=(),
        now=completed_at,
    )
    with execution.factory() as db:
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        events = tuple(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert manifest is not None and manifest.retention_status == "not_applicable"
        assert manifest.retention_completed_at is not None
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PrivacyBackupRetentionItemRecord))
            == 0
        )
        assert {event.event_type for event in events} == {
            "privacy.execution.retention_completed",
            "privacy.execution.work_succeeded",
        }


def test_dsse_tamper_rolls_back_attempt_attestation_and_projection(
    execution: ExecutionHarness,
) -> None:
    claim = _claim_work(execution)
    completed_at = NOW + timedelta(seconds=1)
    evidence = "9" * 64
    payload = _payload(claim, evidence_sha256=evidence, issued_at=completed_at)
    value = _envelope(execution, payload)
    tampered_envelope = dict(value.envelope)
    tampered_envelope["payload"] = base64.b64encode(
        canonical_json({**payload, "remaining_item_count": 1})
    ).decode("ascii")
    with pytest.raises(PlatformSecurityError) as tampered:
        execution.service.complete_work_item(
            execution.identity,
            claim,
            outcome=PrivacyEvidenceOutcome(evidence_sha256=evidence),
            envelope=PrivacyDsseEnvelope(
                envelope=tampered_envelope,
                artifact_uri=value.artifact_uri,
                immutability_receipt_sha256=value.immutability_receipt_sha256,
                kms_audit_receipt_sha256=value.kms_audit_receipt_sha256,
            ),
            now=completed_at,
        )
    assert tampered.value.code == "platform_privacy_attestation_invalid"
    with execution.factory() as db:
        item = db.get(PrivacyDeletionWorkItemRecord, claim.item_id)
        assert item is not None and item.status == "leased"
        assert db.scalar(sa.select(sa.func.count()).select_from(PrivacyDeletionAttemptRecord)) == 0
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PrivacyEvidenceAttestationRecord))
            == 0
        )


def test_backup_purge_waits_for_lock_and_hold_then_completes_retention(
    execution: ExecutionHarness,
) -> None:
    due_at = NOW + timedelta(minutes=10)
    hold_id = uuid4()
    with execution.factory.begin() as db:
        backup = db.get(PrivacyBackupRetentionItemRecord, execution.backup_item_id)
        assert backup is not None
        backup.object_lock_until = due_at
        backup.purge_due_at = due_at
        db.add(
            PrivacyLegalHoldRecord(
                id=hold_id,
                target_type="global_user",
                target_id=execution.target_id,
                tenant_id=None,
                status="active",
                scope=["backups_and_snapshots"],
                authority_ref="case:test-hold",
                reason="Preserve backup during investigation",
                review_due_at=NOW + timedelta(days=30),
                placed_by_principal_id=execution.staff_id,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )

    assert (
        execution.service.claim_backup_item(
            execution.identity,
            target_type="global_user",
            target_id=execution.target_id,
            manifest_id=execution.manifest_id,
            now=NOW + timedelta(minutes=5),
        )
        is None
    )
    assert (
        execution.service.claim_backup_item(
            execution.identity,
            target_type="global_user",
            target_id=execution.target_id,
            manifest_id=execution.manifest_id,
            now=due_at + timedelta(seconds=1),
        )
        is None
    )
    with execution.factory.begin() as db:
        backup = db.get(PrivacyBackupRetentionItemRecord, execution.backup_item_id)
        hold = db.get(PrivacyLegalHoldRecord, hold_id)
        assert backup is not None and backup.status == "held"
        assert hold is not None
        hold.status = "released"
        hold.released_by_principal_id = execution.staff_id
        hold.release_reason = "Investigation completed"
        hold.released_at = due_at + timedelta(seconds=2)
        hold.updated_at = due_at + timedelta(seconds=2)
        hold.version += 1

    claim = _claim_backup(execution, now=due_at + timedelta(seconds=3))
    completed_at = due_at + timedelta(seconds=4)
    authorization = execution.service.authorize_destructive_execution(
        execution.identity,
        claim,
        now=due_at + timedelta(seconds=3),
    )
    assert authorization.item_id == claim.item_id
    assert authorization.expires_at == claim.lease_expires_at
    evidence = "9" * 64
    result = execution.service.complete_backup_item(
        execution.identity,
        claim,
        evidence_sha256=evidence,
        envelope=_envelope(
            execution,
            _payload(claim, evidence_sha256=evidence, issued_at=completed_at),
        ),
        now=completed_at,
    )
    assert result.status == "purged"
    with execution.factory() as db:
        backup = db.get(PrivacyBackupRetentionItemRecord, execution.backup_item_id)
        attempt = db.get(PrivacyDeletionAttemptRecord, result.attempt_id)
        attestation = db.get(PrivacyEvidenceAttestationRecord, result.attestation_id)
        manifest = db.get(PrivacyDeletionManifestRecord, execution.manifest_id)
        events = tuple(db.scalars(sa.select(ControlPlaneOutboxEvent)))
        assert backup is not None and backup.status == "purged"
        assert attempt is not None and attempt.backup_retention_item_id == backup.id
        assert attempt.work_item_id is None
        assert attestation is not None and attestation.subject_id == backup.id
        assert attestation.subject_kind == "backup"
        assert manifest is not None and manifest.retention_status == "completed"
        assert manifest.retention_completed_at is not None
        assert {event.event_type for event in events} == {
            "privacy.execution.backup_purged",
            "privacy.execution.retention_completed",
        }
