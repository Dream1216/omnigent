from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.outbox import OutboxPublishError
from saas.control_plane.outbox_delivery import PlatformAuditJournalConsumer, canonical
from saas.control_plane.outbox_delivery_models import PlatformAuditJournalDeliveryRecord
from saas.control_plane.platform_governed_models import PlatformAuditExportRecord
from tests.saas.test_platform_governed_access import governed as governed
from tests.saas.test_slo_observability import _Store


class _Cipher:
    """Actual authenticated crypto in tests; not a production KMS qualification."""

    def __init__(self):
        self.aead = AESGCM(AESGCM.generate_key(bit_length=256))

    def encrypt(self, plaintext, *, context):
        nonce = __import__("os").urandom(12)
        return base64.b64encode(
            nonce + self.aead.encrypt(nonce, plaintext.encode(), canonical(context))
        ).decode()

    def decrypt(self, ciphertext, *, context):
        value = base64.b64decode(ciphertext, validate=True)
        return self.aead.decrypt(value[:12], value[12:], canonical(context)).decode()


class _Signer:
    """Actual local Ed25519 test boundary, never represented as nonexportable KMS."""

    key_id = "isolated-unit-audit-purpose-only/v1"
    algorithm = "ed25519"

    def __init__(self):
        self.private = Ed25519PrivateKey.generate()
        self.calls = 0

    def sign(self, content_hash):
        self.calls += 1
        return base64.b64encode(self.private.sign(content_hash.encode())).decode()

    def verify(self, content_hash, signature):
        try:
            self.private.public_key().verify(
                base64.b64decode(signature, validate=True), content_hash.encode()
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


def _audit_event(fixture):
    factory, service, _, tenant, customer = fixture
    with factory.begin() as db:
        source = service._append_audit(
            db,
            tenant_id=tenant,
            actor_type="customer",
            actor_id=customer,
            event_type="audit.delivery.acceptance",
            target_type="tenant",
            target_id=tenant,
            operation_id=None,
            payload={"purpose": "unit-audit-delivery", "secret-canary": "must-remain-encrypted"},
            occurred_at=datetime(2026, 8, 8, tzinfo=UTC),
        )
        db.flush()
        row = ControlPlaneOutboxEvent(
            tenant_id=tenant,
            aggregate_type="platform_audit",
            aggregate_key=str(source.id),
            event_type="platform.audit.persisted",
            idempotency_key=f"audit:{source.id}",
            request_hash=source.event_hash,
            payload={
                "audit_event_id": str(source.id),
                "sequence_no": source.sequence_no,
                "event_hash": source.event_hash,
            },
        )
        db.add(row)
        db.flush()
        return {
            "event_id": row.id,
            "aggregate_type": row.aggregate_type,
            "aggregate_key": row.aggregate_key,
            "event_type": row.event_type,
            "payload": row.payload,
        }


def _consumer(fixture):
    store, signer = _Store(), _Signer()
    return (
        PlatformAuditJournalConsumer(
            fixture[0], store, _Cipher(), signer, product_revision="a" * 40
        ),
        store,
        signer,
    )


def test_actual_audit_chain_has_retained_encrypted_signed_delivery_and_no_export_approval(
    governed,
):
    consumer, store, signer = _consumer(governed)
    first, second = _audit_event(governed), _audit_event(governed)
    with pytest.raises(OutboxPublishError) as pending:
        consumer.publish(**second)
    assert pending.value.code == "audit_predecessor_pending" and signer.calls == 0
    consumer.publish(**first)
    consumer.publish(**second)
    consumer.publish(**first)
    assert signer.calls == 2 and len(store.objects) == 2
    assert b"must-remain-encrypted" not in b"".join(row.body for row in store.objects.values())
    with governed[0]() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditJournalDeliveryRecord))
            == 2
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditExportRecord)) == 0
        for receipt in db.scalars(sa.select(PlatformAuditJournalDeliveryRecord)):
            assert receipt.storage_version == store.read(receipt.storage_key).version


def test_crash_after_destination_commit_recovers_same_version_without_resigning(governed):
    consumer, store, signer = _consumer(governed)
    event = _audit_event(governed)
    failed = [False]

    @sa.event.listens_for(governed[0], "before_flush")
    def fail_first_receiver_commit(db, _context, _instances):
        if not failed[0] and any(
            isinstance(row, PlatformAuditJournalDeliveryRecord) for row in db.new
        ):
            failed[0] = True
            raise RuntimeError("injected receiver crash after independent destination commit")

    with pytest.raises(RuntimeError, match="receiver crash"):
        consumer.publish(**event)
    with governed[0]() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditJournalDeliveryRecord))
            == 0
        )
    previous = next(iter(store.objects.values()))
    consumer.publish(**event)
    assert signer.calls == 1 and len(store.objects) == 1
    assert next(iter(store.objects.values())) is previous


def test_tampered_journal_or_missing_retained_predecessor_cannot_be_acked(governed):
    consumer, store, _ = _consumer(governed)
    first, second = _audit_event(governed), _audit_event(governed)
    consumer.publish(**first)
    original = next(iter(store.objects.values()))
    key = next(iter(store.objects))
    del store.objects[key]
    with pytest.raises(OutboxPublishError) as missing:
        consumer.publish(**second)
    assert missing.value.code == "audit_predecessor_readback_failed"
    from saas.production.slo_witness import StoredObject

    store.objects[key] = StoredObject(
        original.body.replace(b'"ed25519"', b'"hmac-sha256"'), original.etag, original.version
    )
    with pytest.raises(OutboxPublishError) as invalid:
        consumer.publish(**first)
    assert invalid.value.code == "audit_destination_invalid"
    with governed[0]() as db:
        assert db.get(ControlPlaneOutboxEvent, second["event_id"]).published_at is None
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(PlatformAuditJournalDeliveryRecord))
            == 1
        )
