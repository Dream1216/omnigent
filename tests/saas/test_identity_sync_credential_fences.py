from __future__ import annotations

from uuid import UUID

import pytest

from saas.control_plane import GlobalUser
from saas.control_plane.credential_migration import CredentialMigrationError
from saas.control_plane.db_models import IdentityConnection
from saas.control_plane.identity_event_models import IdentityProviderStateRecord
from saas.control_plane.identity_inbox import identity_locator
from tests.saas.test_credential_migration import NOW
from tests.saas.test_credential_migration import source as source
from tests.saas.test_credential_reconnection import recovered, sign
from tests.saas.test_existing_identity_cutover import linked, prepare


def cache(source, connection_id, status):
    with source.sessions.begin() as db:
        connection = db.get(IdentityConnection, connection_id)
        db.add(
            IdentityProviderStateRecord(
                connection_id=connection_id,
                subject_locator_sha256=identity_locator(
                    connection.issuer, "customers", "subject", connection.subject
                ),
                status=status,
            )
        )


@pytest.mark.parametrize("status", ["disabled", "deleted"])
def test_known_unusable_provider_identity_cannot_prepare_existing_link_cutover(source, status):
    service, provider, connection = linked(source)
    cache(source, connection, status)
    with pytest.raises(CredentialMigrationError, match="existing_link_required"):
        prepare(service, source, connection)
    assert provider.reads == []


def test_provider_state_changed_after_migration_claim_cannot_cut_over(source):
    service, provider, connection = linked(source)
    receipt = prepare(service, source, connection)
    claim = service.claim(receipt.id, now=NOW)
    cache(source, connection, "disabled")
    proof = provider.read_linked_identity(claim.subject)
    result = service.finish(claim, proof, cutover=True, now=NOW)
    assert (
        result.status == "conflict"
        and result.last_error_code == "migration_existing_link_required"
    )
    with source.sessions() as db:
        assert db.get(GlobalUser, source.user_id).credential_owner == "legacy"


def test_fresh_signed_return_can_resolve_disabled_cache_and_cancels_pending_state_claim(source):
    service, _provider, key, request = recovered(source)
    connection_id = UUID(request["connection_id"])
    cache(source, connection_id, "disabled")
    assert service.reconnect(signed_grant=sign(key, request), now=NOW) == connection_id
    with source.sessions() as db:
        row = db.get(IdentityProviderStateRecord, connection_id)
        assert row.status == "active" and row.checked_at is None
        assert row.claim_token is row.claim_sha256 is row.lease_expires_at is None


def test_signed_return_never_reactivates_provider_deleted_cache(source):
    service, _provider, key, request = recovered(source)
    connection_id = UUID(request["connection_id"])
    cache(source, connection_id, "deleted")
    with pytest.raises(CredentialMigrationError, match="reconnection_state_conflict"):
        service.reconnect(signed_grant=sign(key, request), now=NOW)
    with source.sessions() as db:
        assert db.get(IdentityProviderStateRecord, connection_id).status == "deleted"
        assert db.get(IdentityConnection, connection_id).status == "revoked"
