from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_models import PlatformRoleAssignmentRecord
from saas.control_plane.platform_security import (
    IssuedPlatformSession,
    PlatformAuthorizationService,
    PlatformProjectionService,
    PlatformSessionService,
    StaffIdentityAssertion,
)
from saas.control_plane.privacy_attestation import (
    canonical_json,
    privacy_verifier_receipt_sha256,
)
from saas.control_plane.privacy_lifecycle import DeletionEvidenceKey, PrivacyLifecycleService
from saas.control_plane.privacy_models import (
    PrivacyBackupRetentionItemRecord,
    PrivacyDeletionAttemptRecord,
    PrivacyDeletionManifestRecord,
    PrivacyDeletionWorkItemRecord,
    PrivacyEvidenceAttestationRecord,
)
from saas.control_plane.privacy_operations import PrivacyLocatorKey, PrivacyOperationService

ORIGIN = "https://platform-admin.example.test"
AUDIENCE = "omnigent-platform-admin"


def _hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _attestation(
    *,
    manifest_id: UUID,
    target_id: UUID,
    subject_kind: str,
    subject_id: UUID,
    surface: str | None,
    payload_sha256: str,
    label: str,
    signer_key_id: str,
    workflow_identity: str,
    now: datetime,
    execution_attempt_id: UUID | None = None,
    attempt_number: int | None = None,
    lease_generation: int | None = None,
    replay_generation: int | None = None,
    attestor_role: str | None = None,
    actor_identity_hmac: str | None = None,
    record_sha256: str | None = None,
) -> PrivacyEvidenceAttestationRecord:
    envelope = {"test_fixture": label}
    value = PrivacyEvidenceAttestationRecord(
        id=uuid4(),
        manifest_id=manifest_id,
        target_type="global_user",
        target_id=target_id,
        tenant_id=None,
        subject_kind=subject_kind,
        subject_id=subject_id,
        execution_attempt_id=execution_attempt_id,
        attempt_number=attempt_number,
        lease_generation=lease_generation,
        replay_generation=replay_generation,
        surface=surface,
        payload_type=f"application/vnd.omnigent.privacy-{subject_kind}+json",
        payload_sha256=payload_sha256,
        envelope_sha256=sha256(canonical_json(envelope)).hexdigest(),
        envelope=envelope,
        envelope_uri=f"s3://private-evidence/{label}.dsse.json",
        immutability_receipt_sha256=_hash(f"immutable:{label}"),
        kms_audit_receipt_sha256=_hash(f"kms:{label}"),
        signature_algorithm="ed25519",
        signer_key_id=signer_key_id,
        workflow_identity=workflow_identity,
        attestor_role=attestor_role,
        actor_identity_hmac=actor_identity_hmac,
        record_sha256=record_sha256,
        product_revision="a" * 40,
        upstream_revision="b" * 40,
        schema_revision="pc5b00000003",
        adapter_contract_version="0.2.0",
        verifier_policy_version="privacy-http-v1",
        verifier_receipt_sha256="0" * 64,
        observed_at=now,
        signed_at=now,
        verified_at=now,
        created_at=now,
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
            "execution_attempt_id": (
                str(value.execution_attempt_id) if value.execution_attempt_id is not None else None
            ),
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


def _assert_content_blind(payload: dict[str, object], *secrets: str) -> None:
    serialized = str(payload)
    for field in (
        "reason",
        "reason_code",
        "case_reference",
        "signature",
        "raw_error",
        "requested_by_principal_id",
        "approved_by_principal_id",
    ):
        assert field not in payload
    for secret in secrets:
        assert secret not in serialized
    assert payload["content_access"] == "none"


def _build_http_authority() -> tuple[
    TestClient,
    PlatformHttpConfig,
    sessionmaker[Session],
    UUID,
    IssuedPlatformSession,
    IssuedPlatformSession,
]:
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=ORIGIN, audience=AUDIENCE)
    requester_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:privacy-http-requester",
        issuer="https://staff-idp.example.test",
        subject="privacy-http-requester",
        now=now,
    )
    approver_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:privacy-http-approver",
        issuer="https://staff-idp.example.test",
        subject="privacy-http-approver",
        now=now,
    )
    assigner_id = authorization.provision_staff_principal(
        identity_connection_ref="staff-idp:privacy-http-assigner",
        issuer="https://staff-idp.example.test",
        subject="privacy-http-assigner",
        now=now,
    )
    target_id = uuid4()
    with factory.begin() as db:
        db.add_all(
            [
                PlatformRoleAssignmentRecord(
                    principal_id=requester_id,
                    role="compliance_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=assigner_id,
                    approval_ref="bootstrap:privacy-http-requester",
                    reason="Privacy HTTP acceptance",
                    created_at=now,
                    updated_at=now,
                ),
                PlatformRoleAssignmentRecord(
                    principal_id=approver_id,
                    role="platform_operator",
                    status="active",
                    version=1,
                    assigned_by_principal_id=assigner_id,
                    approval_ref="bootstrap:privacy-http-approver",
                    reason="Privacy HTTP acceptance",
                    created_at=now,
                    updated_at=now,
                ),
                GlobalUser(
                    id=target_id,
                    status="active",
                    display_name="Privacy HTTP Subject",
                    primary_email_normalized="privacy-http-subject@example.test",
                    security_version=1,
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )
    requester = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="privacy-http-requester",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    approver = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.example.test",
            subject="privacy-http-approver",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    lifecycle = PrivacyLifecycleService(
        factory,
        evidence_verifier=DeletionEvidenceKey("privacy-http-key", b"e" * 32),
    )
    operations = PrivacyOperationService(
        factory,
        lifecycle=lifecycle,
        locator_key=PrivacyLocatorKey("privacy-http-locator", b"l" * 32),
    )
    config = PlatformHttpConfig(enabled=True, origin=ORIGIN, audience=AUDIENCE)
    client = TestClient(
        create_platform_admin_app(
            config=config,
            sessions=sessions,
            authorization=authorization,
            projections=PlatformProjectionService(factory),
            privacy=lifecycle,
            privacy_operations=operations,
        ),
        base_url=ORIGIN,
    )
    return client, config, factory, target_id, requester, approver


def _prepare_finalization_and_replay(
    factory: sessionmaker[Session],
    target_id: UUID,
) -> tuple[UUID, int, UUID, int, UUID, int]:
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        manifest = db.scalar(sa.select(PrivacyDeletionManifestRecord))
        assert manifest is not None
        work_items = tuple(
            db.scalars(
                sa.select(PrivacyDeletionWorkItemRecord)
                .where(PrivacyDeletionWorkItemRecord.manifest_id == manifest.id)
                .order_by(PrivacyDeletionWorkItemRecord.id)
            )
        )
        assert len(work_items) == 15
        for item in work_items:
            payload_sha256 = _hash(f"surface:{item.id}")
            attestation = _attestation(
                manifest_id=manifest.id,
                target_id=target_id,
                subject_kind="surface",
                subject_id=item.id,
                surface=item.surface,
                payload_sha256=payload_sha256,
                label=f"surface-{item.id}",
                signer_key_id="privacy-production-key",
                workflow_identity="spiffe://omnigent/privacy-deletion-worker",
                now=now,
                execution_attempt_id=uuid4(),
                attempt_number=1,
                lease_generation=1,
                replay_generation=0,
            )
            item.status = "succeeded"
            item.attempt_count = 1
            item.lease_generation = 1
            item.outcome_content_sha256 = payload_sha256
            item.evidence_attestation_id = attestation.id
            item.version += 1
            item.updated_at = now
            db.add(attestation)
        manifest.status = "ready_to_finalize"
        manifest.version += 1
        manifest.updated_at = now
        replay_item = work_items[0]
        backup_id = uuid4()
        db.add(
            PrivacyBackupRetentionItemRecord(
                id=backup_id,
                manifest_id=manifest.id,
                target_type="global_user",
                target_id=target_id,
                tenant_id=None,
                runtime_partition_id=None,
                provider="test-provider",
                backup_data_class="database",
                backup_locator_hmac=_hash("backup-locator"),
                resource_handle_ref="opaque:test-backup-handle",
                catalog_snapshot_sha256=_hash("backup-catalog"),
                tombstone_sha256=_hash("backup-tombstone"),
                object_lock_until=None,
                purge_due_at=now + timedelta(days=30),
                status="retention_wait",
                attempt_count=0,
                max_attempts=8,
                available_at=now,
                leased_at=None,
                lease_expires_at=None,
                lease_token_hash=None,
                executor_identity_sha256=None,
                lease_generation=1,
                replay_generation=0,
                last_error_code=None,
                last_error_sha256=None,
                purge_evidence_sha256=None,
                purged_at=None,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        db.add_all(
            [
                PrivacyDeletionAttemptRecord(
                    id=uuid4(),
                    work_item_id=work_items[0].id,
                    backup_retention_item_id=None,
                    manifest_id=manifest.id,
                    target_type="global_user",
                    target_id=target_id,
                    tenant_id=None,
                    surface=work_items[0].surface,
                    attempt_number=1,
                    lease_generation=1,
                    replay_generation=0,
                    provider_idempotency_sha256=_hash("provider-attempt-success"),
                    executor_identity_sha256=_hash("private-executor-identity"),
                    outcome="succeeded",
                    error_code=None,
                    error_sha256=None,
                    evidence_payload_sha256=_hash("attempt-evidence"),
                    started_at=now - timedelta(seconds=2),
                    completed_at=now - timedelta(seconds=1),
                ),
                PrivacyDeletionAttemptRecord(
                    id=uuid4(),
                    work_item_id=work_items[1].id,
                    backup_retention_item_id=None,
                    manifest_id=manifest.id,
                    target_type="global_user",
                    target_id=target_id,
                    tenant_id=None,
                    surface=work_items[1].surface,
                    attempt_number=1,
                    lease_generation=1,
                    replay_generation=0,
                    provider_idempotency_sha256=_hash("provider-attempt-failed"),
                    executor_identity_sha256=_hash("private-executor-identity-two"),
                    outcome="dead_letter",
                    error_code="provider_timeout",
                    error_sha256=_hash("private-attempt-error"),
                    evidence_payload_sha256=None,
                    started_at=now - timedelta(seconds=1),
                    completed_at=now,
                ),
                PrivacyDeletionAttemptRecord(
                    id=uuid4(),
                    work_item_id=None,
                    backup_retention_item_id=backup_id,
                    manifest_id=manifest.id,
                    target_type="global_user",
                    target_id=target_id,
                    tenant_id=None,
                    surface="backups_and_snapshots",
                    attempt_number=1,
                    lease_generation=1,
                    replay_generation=0,
                    provider_idempotency_sha256=_hash("provider-backup-attempt"),
                    executor_identity_sha256=_hash("private-backup-executor"),
                    outcome="dead_letter",
                    error_code="provider_timeout",
                    error_sha256=_hash("private-backup-attempt-error"),
                    evidence_payload_sha256=None,
                    started_at=now - timedelta(seconds=1),
                    completed_at=now,
                ),
                _attestation(
                    manifest_id=manifest.id,
                    target_id=target_id,
                    subject_kind="manifest",
                    subject_id=manifest.id,
                    surface=None,
                    payload_sha256=_hash("manifest-payload"),
                    label="manifest",
                    signer_key_id="private-manifest-signer",
                    workflow_identity="spiffe://private/manifest-workflow",
                    now=now,
                    attestor_role="privacy",
                    actor_identity_hmac=_hash("private-attestor-identity"),
                    record_sha256=_hash("manifest-record"),
                ),
                _attestation(
                    manifest_id=manifest.id,
                    target_id=target_id,
                    subject_kind="backup",
                    subject_id=backup_id,
                    surface="backups_and_snapshots",
                    payload_sha256=_hash("backup-payload"),
                    label="backup",
                    signer_key_id="private-backup-signer",
                    workflow_identity="spiffe://private/backup-workflow",
                    now=now,
                    execution_attempt_id=uuid4(),
                    attempt_number=1,
                    lease_generation=1,
                    replay_generation=0,
                ),
            ]
        )
        return manifest.id, manifest.version, replay_item.id, replay_item.version, backup_id, 1


def test_governed_privacy_http_is_exact_strict_content_blind_and_idempotent() -> None:
    client, config, factory, target_id, requester, approver = _build_http_authority()
    target_path = f"/v2/platform-admin/privacy/global_user/{target_id}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    client.cookies.set(config.cookie_name, requester.token)
    preview = client.get(f"{target_path}/deletion-preview")
    assert preview.status_code == 200
    case_reference = "privacy-case-secret-001"
    command = {
        "expected_target_version": preview.json()["target_version"],
        "preview_hash": preview.json()["preview_hash"],
        "reason_code": "data_subject_request",
        "case_reference": case_reference,
        "expires_at": expires_at,
    }
    client.cookies.clear()
    unauthenticated = client.post(
        f"{target_path}/deletion-requests",
        headers={"Origin": ORIGIN, "X-CSRF-Token": "invalid"},
        json=command,
    )
    assert unauthenticated.status_code == 401

    client.cookies.set(config.cookie_name, requester.token)
    missing_csrf = client.post(
        f"{target_path}/deletion-requests",
        headers={"Origin": ORIGIN},
        json=command,
    )
    assert missing_csrf.status_code == 403
    requester_headers = {
        "Origin": ORIGIN,
        "X-CSRF-Token": requester.csrf_token,
    }
    invalid = client.post(
        f"{target_path}/deletion-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-invalid"},
        json={**command, "expected_target_version": "1", "raw_error": "do-not-echo"},
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "platform_privacy_invalid"
    assert "do-not-echo" not in invalid.text
    assert case_reference not in invalid.text

    missing_idempotency = client.post(
        f"{target_path}/deletion-requests",
        headers=requester_headers,
        json=command,
    )
    assert missing_idempotency.status_code == 400

    requested = client.post(
        f"{target_path}/deletion-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-start-001"},
        json=command,
    )
    assert requested.status_code == 202
    requested_payload = requested.json()
    assert requested_payload["phase"] == "deletion_start"
    assert requested_payload["status"] == "pending_staff_approval"
    _assert_content_blind(requested_payload, case_reference)

    replayed = client.post(
        f"{target_path}/deletion-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-start-001"},
        json=command,
    )
    assert replayed.status_code == 202
    assert replayed.json()["operation_id"] == requested_payload["operation_id"]
    assert replayed.json()["replayed"] is True

    client.cookies.clear()
    client.cookies.set(config.cookie_name, approver.token)
    approver_headers = {"Origin": ORIGIN, "X-CSRF-Token": approver.csrf_token}
    missing_decision_idempotency = client.post(
        f"{target_path}/operations/{requested_payload['operation_id']}/decision",
        headers=approver_headers,
        json={
            "expected_version": requested_payload["version"],
            "decision": "approve",
            "decision_code": "policy_confirmed",
        },
    )
    assert missing_decision_idempotency.status_code == 400
    invalid_decision_code = client.post(
        f"{target_path}/operations/{requested_payload['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-invalid"},
        json={
            "expected_version": requested_payload["version"],
            "decision": "approve",
            "decision_code": "verified_replay",
        },
    )
    assert invalid_decision_code.status_code == 400
    approved = client.post(
        f"{target_path}/operations/{requested_payload['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-001"},
        json={
            "expected_version": requested_payload["version"],
            "decision": "approve",
            "decision_code": "policy_confirmed",
        },
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "succeeded"
    _assert_content_blind(approved.json(), case_reference)
    replayed_decision = client.post(
        f"{target_path}/operations/{requested_payload['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-001"},
        json={
            "expected_version": requested_payload["version"],
            "decision": "approve",
            "decision_code": "policy_confirmed",
        },
    )
    assert replayed_decision.status_code == 200
    assert replayed_decision.json()["replayed"] is True
    conflicting_decision_replay = client.post(
        f"{target_path}/operations/{requested_payload['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-other"},
        json={
            "expected_version": requested_payload["version"],
            "decision": "approve",
            "decision_code": "policy_confirmed",
        },
    )
    assert conflicting_decision_replay.status_code == 409

    wrong_target = client.post(
        f"/v2/platform-admin/privacy/global_user/{uuid4()}/operations/"
        f"{requested_payload['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-wrong"},
        json={
            "expected_version": approved.json()["version"],
            "decision": "reject",
            "decision_code": "stale_request",
        },
    )
    assert wrong_target.status_code == 404

    with factory.begin() as db:
        manifest = db.scalar(sa.select(PrivacyDeletionManifestRecord))
        assert manifest is not None
        assert manifest.start_operation_id == UUID(requested_payload["operation_id"])


def test_finalize_work_item_backup_replay_and_operation_list_http_contracts() -> None:
    client, config, factory, target_id, requester, approver = _build_http_authority()
    target_path = f"/v2/platform-admin/privacy/global_user/{target_id}"
    client.cookies.set(config.cookie_name, requester.token)
    requester_headers = {"Origin": ORIGIN, "X-CSRF-Token": requester.csrf_token}
    preview = client.get(f"{target_path}/deletion-preview").json()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    started = client.post(
        f"{target_path}/deletion-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-start-002"},
        json={
            "expected_target_version": preview["target_version"],
            "preview_hash": preview["preview_hash"],
            "reason_code": "data_subject_request",
            "case_reference": "privacy-start-case-secret",
            "expires_at": expires_at,
        },
    ).json()
    client.cookies.clear()
    client.cookies.set(config.cookie_name, approver.token)
    approver_headers = {"Origin": ORIGIN, "X-CSRF-Token": approver.csrf_token}
    approved = client.post(
        f"{target_path}/operations/{started['operation_id']}/decision",
        headers={**approver_headers, "Idempotency-Key": "privacy-http-decision-002"},
        json={
            "expected_version": started["version"],
            "decision": "approve",
            "decision_code": "policy_confirmed",
        },
    )
    assert approved.status_code == 200

    manifest_id, manifest_version, work_id, work_version, backup_id, backup_version = (
        _prepare_finalization_and_replay(factory, target_id)
    )
    client.cookies.clear()
    client.cookies.set(config.cookie_name, requester.token)
    finalize_case = "privacy-finalize-case-secret"
    finalized = client.post(
        f"{target_path}/deletions/{manifest_id}/finalization-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-finalize-001"},
        json={
            "expected_manifest_version": manifest_version,
            "reason_code": "data_subject_request",
            "case_reference": finalize_case,
            "expires_at": expires_at,
        },
    )
    assert finalized.status_code == 202
    assert finalized.json()["phase"] == "deletion_finalize"
    assert finalized.json()["manifest_id"] == str(manifest_id)
    _assert_content_blind(finalized.json(), finalize_case)

    with factory.begin() as db:
        work_item = db.get(PrivacyDeletionWorkItemRecord, work_id)
        assert work_item is not None
        work_item.status = "dead_letter"
        work_item.attempt_count = work_item.max_attempts
        work_item.last_error_code = "provider_timeout"
        work_item.last_error_sha256 = _hash("surface-raw-error")
        work_item.outcome_content_sha256 = None
        work_item.evidence_attestation_id = None
        work_item.version += 1
        work_item.updated_at = datetime.now(timezone.utc)
        work_version = work_item.version
        backup_item = db.get(PrivacyBackupRetentionItemRecord, backup_id)
        assert backup_item is not None
        backup_item.status = "dead_letter"
        backup_item.attempt_count = backup_item.max_attempts
        backup_item.last_error_code = "provider_timeout"
        backup_item.last_error_sha256 = _hash("backup-error-details")
        backup_item.version += 1
        backup_item.updated_at = datetime.now(timezone.utc)
        backup_version = backup_item.version

    replay_case = "privacy-replay-case-secret"
    replay_body = {
        "reason_code": "verified_operational_replay",
        "case_reference": replay_case,
        "expires_at": expires_at,
    }
    work_replay = client.post(
        f"{target_path}/deletions/{manifest_id}/work-items/{work_id}/replay-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-work-replay-001"},
        json={**replay_body, "expected_version": work_version},
    )
    assert work_replay.status_code == 202
    assert work_replay.json()["phase"] == "surface_replay"
    assert work_replay.json()["subject_id"] == str(work_id)
    _assert_content_blind(work_replay.json(), replay_case, "surface-raw-error")

    backup_replay = client.post(
        f"{target_path}/deletions/{manifest_id}/backups/{backup_id}/replay-requests",
        headers={**requester_headers, "Idempotency-Key": "privacy-http-backup-replay-001"},
        json={**replay_body, "expected_version": backup_version},
    )
    assert backup_replay.status_code == 202
    assert backup_replay.json()["phase"] == "backup_purge_replay"
    assert backup_replay.json()["subject_id"] == str(backup_id)
    _assert_content_blind(backup_replay.json(), replay_case, "backup-error-details")

    operations = client.get(f"{target_path}/operations?limit=10")
    assert operations.status_code == 200
    payload = operations.json()
    assert payload["content_access"] == "none"
    assert {item["phase"] for item in payload["items"]} == {
        "deletion_start",
        "deletion_finalize",
        "surface_replay",
        "backup_purge_replay",
    }
    for item in payload["items"]:
        _assert_content_blind(
            item,
            "privacy-start-case-secret",
            finalize_case,
            replay_case,
            "surface-raw-error",
            "backup-error-details",
        )

    work_items = client.get(f"{target_path}/deletions/{manifest_id}/work-items?limit=2")
    assert work_items.status_code == 200
    work_payload = work_items.json()
    assert len(work_payload["items"]) == 2
    assert work_payload["next_cursor"] is not None
    next_work_items = client.get(
        f"{target_path}/deletions/{manifest_id}/work-items",
        params={"limit": 2, "cursor": work_payload["next_cursor"]},
    )
    assert next_work_items.status_code == 200
    assert {value["work_item_id"] for value in work_payload["items"]}.isdisjoint(
        value["work_item_id"] for value in next_work_items.json()["items"]
    )

    attempts = client.get(f"{target_path}/deletions/{manifest_id}/attempts?limit=10")
    assert attempts.status_code == 200
    attempt_payload = attempts.json()
    assert len(attempt_payload["items"]) == 3
    selected_surface = attempt_payload["items"][0]["surface"]
    filtered_attempts = client.get(
        f"{target_path}/deletions/{manifest_id}/attempts",
        params={"surface": selected_surface, "limit": 10},
    )
    assert filtered_attempts.status_code == 200
    assert filtered_attempts.json()["items"]
    assert {value["surface"] for value in filtered_attempts.json()["items"]} == {selected_surface}

    attestations = client.get(f"{target_path}/deletions/{manifest_id}/attestations?limit=5")
    assert attestations.status_code == 200
    attestation_payload = attestations.json()
    assert len(attestation_payload["items"]) == 5
    assert attestation_payload["next_cursor"] is not None

    backups = client.get(f"{target_path}/deletions/{manifest_id}/backups?limit=10")
    assert backups.status_code == 200
    backup_payload = backups.json()
    assert len(backup_payload["items"]) == 1
    assert backup_payload["items"][0]["backup_item_id"] == str(backup_id)

    forbidden_fields = {
        "resource_handle_ref",
        "resource_scope_hmac",
        "backup_locator_hmac",
        "envelope_uri",
        "signer_key_id",
        "workflow_identity",
        "attestor_role",
        "actor_identity_hmac",
        "lease_token_hash",
        "executor_identity_sha256",
    }
    for resource_payload in (
        work_payload,
        attempt_payload,
        attestation_payload,
        backup_payload,
    ):
        assert resource_payload["content_access"] == "none"
        assert all(forbidden_fields.isdisjoint(item) for item in resource_payload["items"])
        serialized = str(resource_payload)
        for secret in (
            "opaque:test-backup-handle",
            "s3://private-evidence/manifest.dsse.json",
            "private-manifest-signer",
            "spiffe://private/manifest-workflow",
            _hash("private-attestor-identity"),
            _hash("private-executor-identity"),
            _hash("private-backup-executor"),
        ):
            assert secret not in serialized

    wrong_target_items = client.get(
        f"/v2/platform-admin/privacy/global_user/{uuid4()}/deletions/{manifest_id}/work-items"
    )
    assert wrong_target_items.status_code == 404
