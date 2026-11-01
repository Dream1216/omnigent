from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from saas.control_plane.credential_migration_models import CredentialMigrationRecord
from saas.control_plane.customer_auth_restore import (
    CustomerAuthRestoreService,
    restore_review_sha256,
)
from saas.control_plane.db_models import GlobalUser
from tests.saas.test_credential_migration import NOW
from tests.saas.test_credential_migration import source as source


def test_restore_invalidates_migration_lease_without_changing_password_authority(source):
    record = source.prepare()
    claim = source.service.claim(record.id, now=NOW)
    assert hasattr(claim, "claim_token")
    service = CustomerAuthRestoreService(source.sessions, product_revision="9" * 40)
    review = service.review(restore_id=uuid4(), backup_set_sha256="b" * 64, now=NOW)
    service.apply(
        review,
        expected_sha256=restore_review_sha256(review),
        review_reference="owned/RESTORE-123",
        now=NOW,
    )
    with source.sessions() as db:
        assert db.get(CredentialMigrationRecord, record.id).claim_token is None
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"
    assert source.service.claim(record.id, now=NOW + timedelta(seconds=1)).status == "conflict"
