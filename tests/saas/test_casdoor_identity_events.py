from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime, timezone

import httpx
import pytest

from saas.control_plane.identity_events import (
    IdentityNotificationIgnored,
    IdentitySyncError,
    parse_casdoor_notification,
)
from saas.production.casdoor_identity_sync import CasdoorIdentityStateProvider
from tests.saas.test_casdoor_credential_import import config as config

NOW = datetime(2026, 10, 13, 8, 0, tzinfo=timezone.utc)
SUBJECT = "stable-customer-uuid"


def notification(**changes):
    return json.dumps(
        {
            "id": 0,
            "name": "durable-record-name",
            "organization": "built-in",
            "user": "administrator",
            "createdTime": NOW.isoformat(),
            "action": "update-user",
            "object": json.dumps(
                {
                    "owner": "customers",
                    "name": "target-user",
                    "id": SUBJECT,
                    "password": "never-store-the-audit-password",
                    "accessToken": "never-store-the-audit-token",
                }
            ),
            "response": '{status:"ok", msg:""}',
            **changes,
        }
    ).encode()


def test_notification_routes_target_identity_and_stable_name_never_actor_or_zero_audit_id():
    event = parse_casdoor_notification(notification(), organization="customers", now=NOW)
    assert (event.event_id, event.subject, event.username) == (
        "durable-record-name",
        SUBJECT,
        "target-user",
    )
    assert event.event_id != "0" and event.subject != "administrator"
    serialized = json.dumps(asdict(event), default=str)
    assert "never-store" not in serialized and "administrator" not in serialized
    assert len(event.digest()) == 64
    repeated = parse_casdoor_notification(
        notification(id=50, clientIp="changed"), organization="customers", now=NOW
    )
    assert repeated.digest() == event.digest()
    retargeted = parse_casdoor_notification(
        notification(
            object=json.dumps(
                {"owner": "customers", "name": "another-user", "id": "another-subject"}
            )
        ),
        organization="customers",
        now=NOW,
    )
    assert retargeted.digest() != event.digest()


def test_password_form_is_read_only_routing_metadata_and_never_a_secret_payload():
    raw = notification(
        action="set-password",
        object="userOwner=customers&userName=target-user&oldPassword=never-store-old&newPassword=never-store-new",
    )
    event = parse_casdoor_notification(raw, organization="customers", now=NOW)
    assert event.subject is None and event.username == "target-user"
    assert "never-store" not in repr(event) and "password" not in json.dumps(
        asdict(event), default=str
    ).replace("set-password", "")


@pytest.mark.parametrize(
    "changes",
    [
        {"action": "login"},
        {"response": '{status:"error", msg:"password mismatch"}'},
        {"object": json.dumps({"owner": "foreign", "name": "target", "id": SUBJECT})},
    ],
)
def test_unsupported_failed_and_foreign_operations_are_ignored(changes):
    with pytest.raises(IdentityNotificationIgnored):
        parse_casdoor_notification(notification(**changes), organization="customers", now=NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"name": ""},
        {"name": "bad/event"},
        {"response": 'prefix {status:"ok", msg:""}'},
        {"createdTime": "2026-10-13T08:02:00Z"},
        {"createdTime": "2026-10-13T08:00:00"},
        {"object": '{"owner":"customers","owner":"foreign","name":"target"}'},
        {"object": json.dumps({"owner": "customers", "name": "target", "id": []})},
        {"object": "userOwner=customers&userName=target", "action": "update-user"},
        {"object": "userOwner=customers&userName=one&userName=two", "action": "set-password"},
    ],
)
def test_malformed_notification_is_bounded_and_content_free(changes):
    with pytest.raises(IdentitySyncError, match=r"^identity_notification_invalid$"):
        parse_casdoor_notification(notification(**changes), organization="customers", now=NOW)


class Remote:
    def __init__(self):
        self.organization = {"name": "customers", "passwordType": "argon2id", "passwordSalt": ""}
        self.application = {
            "owner": "admin",
            "name": "private-state-reader",
            "organization": "customers",
            "clientId": "private-migration-app",
            "clientSecret": "dedicated-service-secret-material",
            "isShared": False,
            "enableSignUp": False,
            "disableSelfSignup": True,
            "disableSignin": True,
            "enablePassword": False,
            "enableGuestSignin": False,
            "enableAutoSignin": False,
            "enableCodeSignin": False,
            "enableSigninSession": False,
            "enableWebAuthn": False,
            "grantTypes": ["client_credentials"],
            "redirectUris": [],
            "backchannelLogoutUri": "",
            "providers": [],
            "signinMethods": [{"name": "Face ID", "rule": "None"}],
            "tags": [],
        }
        self.user = {
            "owner": "customers",
            "id": SUBJECT,
            "name": "target-user",
            "type": "normal-user",
            "email": "verified@example.test",
            "emailVerified": True,
            "phoneVerified": False,
            "phoneE164": "",
            "isForbidden": False,
            "isDeleted": False,
            "isAdmin": False,
            "isGlobalAdmin": False,
            "password": "***",
            "passwordType": "argon2id",
            "passwordSalt": "fresh-private-random-salt",
            "lastChangePasswordTime": NOW.isoformat(),
        }
        self.requests = []
        self.status = 200
        self.response_status = "ok"

    def __call__(self, request):
        self.requests.append(request)
        assert request.method == "GET" and request.url.host == "auth.example.test"
        assert "Basic " in request.headers["authorization"] and "clientSecret" not in str(
            request.url
        )
        if request.url.path == "/api/get-organization":
            assert dict(request.url.params) == {"id": "admin/customers"}
            return httpx.Response(200, json={"status": "ok", "data": self.organization})
        if request.url.path == "/api/get-application":
            assert dict(request.url.params) == {"id": "admin/private-state-reader"}
            return httpx.Response(200, json={"status": "ok", "data": self.application})
        assert request.url.path == "/api/get-user"
        assert dict(request.url.params) == {"owner": "customers", "userId": SUBJECT}
        return httpx.Response(
            self.status, json={"status": self.response_status, "data": self.user}
        )


def reader(config):
    remote = Remote()
    provider = CasdoorIdentityStateProvider(
        replace(config, marker_keyring=None),
        application="private-state-reader",
        transport=httpx.MockTransport(remote),
    )
    provider.verify_organization()
    return provider, remote


def test_reader_uses_canonical_phone_ownership_fact_without_exporting_it_in_repr(config):
    provider, remote = reader(config)
    remote.user.update(
        phone="2025550100", countryCode="US", phoneVerified=True, phoneE164="+12025550100"
    )
    proof = provider.read_identity(SUBJECT)
    assert proof.phone_e164 == "+12025550100" and proof.phone_verified is True
    assert "+12025550100" not in repr(proof)
    before = proof.snapshot_sha256()
    remote.user.update(phoneVerified=False)
    unverified = provider.read_identity(SUBJECT)
    assert unverified.phone_e164 is None and not unverified.phone_verified
    assert unverified.snapshot_sha256() != before


@pytest.mark.parametrize(
    "changes",
    [
        {"phoneVerified": 1},
        {"phoneVerified": True},
        {"phoneVerified": True, "phoneE164": "2025550100"},
        {"phoneVerified": True, "phoneE164": "+01234"},
        {"phoneVerified": True, "phoneE164": 123},
    ],
)
def test_reader_rejects_unqualified_phone_proof_even_if_number_is_present(config, changes):
    provider, remote = reader(config)
    remote.user.update(phone="2025550100", countryCode="US", **changes)
    with pytest.raises(IdentitySyncError, match="response_invalid"):
        provider.read_identity(SUBJECT)


def test_provider_only_reads_stable_subject_and_hashes_salt_without_exporting_password(config):
    provider, remote = reader(config)
    state = provider.read_identity(SUBJECT)
    assert state.usable and state.password_configured and state.email_verified
    assert state.phone_e164 is None and state.phone_verified is False
    assert len(state.password_revision_sha256) == len(state.snapshot_sha256()) == 64
    assert remote.user["passwordSalt"] not in repr(state) and "***" not in repr(state)
    assert not hasattr(state, "password_hash") and not hasattr(state, "password_salt")
    before = state.password_revision_sha256
    remote.user["passwordSalt"] = "second-private-random-salt"
    changed = provider.read_identity(SUBJECT)
    assert changed.password_changed_at == state.password_changed_at
    assert changed.password_revision_sha256 != before
    remote.user.update(updatedTime="different-nonsecurity-time", lastSigninTime="another-login")
    assert provider.read_identity(SUBJECT).snapshot_sha256() == changed.snapshot_sha256()


@pytest.mark.parametrize("mutation", [{"passwordType": "plain"}, {"passwordSalt": "fixed-salt"}])
def test_reconciliation_refuses_unqualified_organization_password_revisions(config, mutation):
    provider, remote = reader(config)
    remote.organization.update(mutation)
    with pytest.raises(IdentitySyncError, match="password_policy_unqualified"):
        provider.verify_organization()
    with pytest.raises(IdentitySyncError, match="password_policy_unqualified"):
        provider.read_identity(SUBJECT)


@pytest.mark.parametrize(
    "mutation",
    [
        {"isForbidden": True},
        {"isDeleted": True},
        {"isAdmin": True},
        {"isGlobalAdmin": True},
        {"type": "virtual-user"},
    ],
)
def test_provider_reports_unusable_identity_without_changing_product_authority(config, mutation):
    provider, remote = reader(config)
    remote.user.update(mutation)
    assert not provider.read_identity(SUBJECT).usable


def test_successful_null_lookup_differs_from_unavailability_and_provider_errors(config):
    provider, remote = reader(config)
    remote.user = None
    assert not provider.read_identity(SUBJECT).exists
    remote.status = 503
    with pytest.raises(IdentitySyncError) as failed:
        provider.read_identity(SUBJECT)
    assert failed.value.retryable
    remote.status = 200
    remote.response_status = "error"
    with pytest.raises(IdentitySyncError):
        provider.read_identity(SUBJECT)


@pytest.mark.parametrize(
    "mutation",
    [
        {"id": "another-subject"},
        {"owner": "foreign"},
        {"password": "raw-password-or-phc"},
        {"emailVerified": 1},
        {"lastChangePasswordTime": "unparseable"},
        {"passwordSalt": None},
    ],
)
def test_invalid_readback_cannot_be_used_for_identity_sync(config, mutation):
    provider, remote = reader(config)
    remote.user.update(mutation)
    with pytest.raises(IdentitySyncError, match="identity_provider_response_invalid"):
        provider.read_identity(SUBJECT)


@pytest.mark.parametrize(
    "mutation",
    [
        {"owner": "foreign"},
        {"name": "another-app"},
        {"organization": "built-in"},
        {"clientId": "another-client"},
        {"clientSecret": "***"},
        {"clientSecret": "wrong"},
        {"isShared": True},
        {"enableSignUp": True},
        {"disableSelfSignup": False},
        {"disableSignin": False},
        {"enablePassword": True},
        {"enableGuestSignin": True},
        {"enableAutoSignin": True},
        {"enableCodeSignin": True},
        {"enableSigninSession": True},
        {"enableWebAuthn": True},
        {"grantTypes": ["authorization_code"]},
        {"redirectUris": ["https://attacker.test/callback"]},
        {"backchannelLogoutUri": "https://attacker.test"},
        {"providers": [{"name": "public-login"}]},
        {"signinMethods": [{"rule": "All"}]},
        {"tags": ["dcr"]},
        {"tags": ["cimd"]},
        {"isShared": 0},
    ],
)
def test_reader_rejects_unqualified_or_publicly_masked_application_and_clears_old_policy(
    config, mutation
):
    provider, remote = reader(config)
    remote.application.update(mutation)
    remote.user = None
    with pytest.raises(IdentitySyncError, match="application_unqualified"):
        provider.verify_organization()
    with pytest.raises(IdentitySyncError, match="password_policy_unqualified"):
        provider.read_identity(SUBJECT)


def test_invalid_basic_secret_cannot_turn_a_public_null_user_lookup_into_deletion(config):
    remote = Remote()
    remote.user = None
    provider = CasdoorIdentityStateProvider(
        replace(config, marker_keyring=None, migration_client_secret="incorrect-but-long-enough"),
        application="private-state-reader",
        transport=httpx.MockTransport(remote),
    )
    with pytest.raises(IdentitySyncError, match="application_unqualified"):
        provider.verify_organization()
    assert [request.url.path for request in remote.requests] == ["/api/get-application"]
