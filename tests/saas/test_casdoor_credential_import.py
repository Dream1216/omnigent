from __future__ import annotations

import base64
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from saas.control_plane.credential_migration import (
    CredentialImportClaim,
    CredentialMigrationError,
)
from saas.control_plane.oidc import OidcProviderConfig
from saas.production.credential_migration import (
    CasdoorCredentialImportConfig,
    CasdoorCredentialImportProvider,
    CredentialImportKeyring,
    load_casdoor_credential_import_config,
)
from saas.production.server_config import ProductionIdentityConfig, ProductionServerConfigError


@pytest.fixture
def config():
    return CasdoorCredentialImportConfig(
        issuer="https://auth.example.test",
        organization="customers",
        customer_application="customer-web",
        migration_client_id="private-migration-app",
        migration_client_secret="dedicated-service-secret-material",
        source_lock_sha256=sha256(
            (
                Path(__file__).resolve().parents[2] / "saas/production/casdoor/source-lock.json"
            ).read_bytes()
        ).hexdigest(),
        policy_revision="p3-v1",
        marker_keyring=CredentialImportKeyring("first", {"first": b"k" * 32}),
    )


@pytest.fixture
def claim(config):
    user_id = uuid4()
    password_hash = "$argon2id$synthetic-test-only"
    email = "legacy@example.test"
    return CredentialImportClaim(
        receipt_id=uuid4(),
        user_id=user_id,
        issuer=config.issuer,
        organization=config.organization,
        subject=str(user_id),
        username="omnigent-" + user_id.hex,
        policy_sha256=config.policy().policy_sha256,
        source_password_sha256=sha256(password_hash.encode()).hexdigest(),
        source_email_sha256=sha256(email.encode()).hexdigest(),
        claim_token=uuid4(),
        password_hash=password_hash,
        email=email,
    )


class Remote:
    def __init__(self):
        self.data = None
        self.requests = []
        self.create_count = 0
        self.lose_create_response = False
        self.create_error = False

    def __call__(self, request):
        self.requests.append(request)
        assert request.url.host == "auth.example.test"
        assert "clientSecret" not in request.url.query.decode()
        assert (
            request.headers["authorization"]
            == "Basic "
            + base64.b64encode(b"private-migration-app:dedicated-service-secret-material").decode()
        )
        if request.url.path == "/api/get-user":
            assert request.method == "GET"
            return httpx.Response(200, json={"status": "ok", "data": self.data})
        assert request.url.path == "/api/add-user" and request.method == "POST"
        self.create_count += 1
        self.data = {
            **json.loads(request.content),
            "password": "***",
            "isAdmin": False,
            "isForbidden": False,
            "isDeleted": False,
        }
        if self.lose_create_response:
            self.lose_create_response = False
            raise httpx.ReadTimeout("private upstream response", request=request)
        return httpx.Response(200, json={"status": "error" if self.create_error else "ok"})


def test_import_readback_and_replay_do_not_overwrite_provider_password(config, claim):
    remote = Remote()
    provider = CasdoorCredentialImportProvider(config, transport=httpx.MockTransport(remote))
    identity = provider.ensure_import(claim)
    assert identity.subject == str(claim.user_id)
    assert identity.marker_verified and identity.email_verified and identity.active
    assert not identity.is_admin and not identity.is_global_admin
    body = json.loads(remote.requests[1].content)
    assert body["password"] == claim.password_hash and body["passwordType"] == "argon2id"
    assert body["passwordSalt"] == "" and body["signupApplication"] == "customer-web"
    assert "isAdmin" not in body and "roles" not in body
    # The provider may have changed its password after the import. A retry may
    # verify the original receipt but must never put the retained hash back.
    remote.data["passwordType"] = "salt"
    remote.data["password"] = "changed-and-redacted"
    assert provider.ensure_import(replace(claim, claim_token=uuid4())) == identity
    assert remote.create_count == 1
    assert claim.password_hash not in repr(claim) and claim.email not in repr(claim)
    assert config.migration_client_secret not in repr(config)


@pytest.mark.parametrize("failure", ["lost-response", "create-race"])
def test_remote_create_survives_lost_response_or_race(config, claim, failure):
    remote = Remote()
    remote.lose_create_response = failure == "lost-response"
    remote.create_error = failure == "create-race"
    provider = CasdoorCredentialImportProvider(config, transport=httpx.MockTransport(remote))
    if failure == "lost-response":
        with pytest.raises(CredentialMigrationError) as caught:
            provider.ensure_import(claim)
        assert caught.value.code == "provider_import_unavailable" and caught.value.retryable
        assert "private upstream response" not in str(caught.value)
    assert provider.ensure_import(claim).marker_verified
    assert remote.create_count == 1


def test_marker_rotation_accepts_retained_key_but_refuses_foreign_receipt(config, claim):
    remote = Remote()
    CasdoorCredentialImportProvider(config, transport=httpx.MockTransport(remote)).ensure_import(
        claim
    )
    rotated = replace(
        config,
        marker_keyring=CredentialImportKeyring(
            "second", {"first": b"k" * 32, "second": b"n" * 32}
        ),
    )
    assert rotated.policy() == config.policy()
    provider = CasdoorCredentialImportProvider(rotated, transport=httpx.MockTransport(remote))
    assert provider.ensure_import(claim).marker_verified
    with pytest.raises(CredentialMigrationError, match="provider_mapping_conflict"):
        provider.ensure_import(replace(claim, receipt_id=uuid4()))
    unavailable = replace(
        rotated, marker_keyring=CredentialImportKeyring("second", {"second": b"n" * 32})
    )
    with pytest.raises(CredentialMigrationError) as caught:
        CasdoorCredentialImportProvider(
            unavailable, transport=httpx.MockTransport(remote)
        ).ensure_import(claim)
    assert caught.value.code == "provider_marker_key_unavailable" and caught.value.retryable
    assert remote.create_count == 1


@pytest.mark.parametrize(
    "mutation",
    [
        {"owner": "built-in"},
        {"id": "other-user"},
        {"type": "admin"},
        {"properties": {}},
        {"properties": {"omnigentCredentialMigration": "v1.first." + "0" * 64}},
        {"isAdmin": "false"},
        {"isDeleted": None},
        {"email": None},
    ],
)
def test_untrusted_existing_identity_is_never_modified(config, claim, mutation):
    remote = Remote()
    provider = CasdoorCredentialImportProvider(config, transport=httpx.MockTransport(remote))
    provider.ensure_import(claim)
    remote.data.update(mutation)
    with pytest.raises(CredentialMigrationError):
        provider.ensure_import(claim)
    assert remote.create_count == 1


@pytest.mark.parametrize("status", [301, 400, 401, 403, 429, 500])
def test_errors_are_content_blind_and_redirects_are_rejected(config, claim, status):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(
            status,
            headers={"Location": "https://attacker.example.test/leak"},
            text="secret upstream details",
        )

    with pytest.raises(CredentialMigrationError) as caught:
        CasdoorCredentialImportProvider(
            config, transport=httpx.MockTransport(handle)
        ).ensure_import(claim)
    assert caught.value.retryable == (status in {401, 403, 429, 500})
    assert "secret upstream" not in str(caught.value)
    assert len(requests) == 1


def test_claim_mismatch_rejected_without_network(config, claim):
    requests = []
    provider = CasdoorCredentialImportProvider(
        config, transport=httpx.MockTransport(lambda request: requests.append(request))
    )
    with pytest.raises(CredentialMigrationError, match="provider_import_claim_invalid"):
        provider.ensure_import(replace(claim, password_hash="different"))
    assert requests == []


@pytest.mark.parametrize("configured", [False, True])
def test_linked_identity_lookup_uses_only_pinned_owner_and_stable_subject(
    config, claim, configured
):
    requests = []

    def read(request):
        requests.append(request)
        assert request.method == "GET" and request.url.path == "/api/get-user"
        assert dict(request.url.params) == {"owner": "customers", "userId": claim.subject}
        assert not request.content
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "id": claim.subject,
                    "owner": "customers",
                    "name": "previously-connected-account",
                    "type": "normal-user",
                    "email": "linked@example.test",
                    "emailVerified": True,
                    "isAdmin": False,
                    "isForbidden": False,
                    "isDeleted": False,
                    "password": "***" if configured else "",
                    "passwordType": "argon2id" if configured else "",
                },
            },
        )

    snapshot = CasdoorCredentialImportProvider(
        config, transport=httpx.MockTransport(read)
    ).read_linked_identity(claim.subject)
    assert snapshot.password_configured is configured
    assert snapshot.identity.subject == claim.subject
    assert snapshot.identity.username == "previously-connected-account"
    assert snapshot.identity.email_verified and snapshot.identity.active
    assert not snapshot.identity.marker_verified
    assert len(snapshot.snapshot_sha256()) == 64 and len(requests) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        {"owner": "built-in"},
        {"id": "foreign-subject"},
        {"password": "unmasked-private-material"},
        {"password": {}},
        {"passwordType": True},
        {"isForbidden": "false"},
    ],
)
def test_linked_identity_lookup_refuses_foreign_or_unmasked_response(config, claim, mutation):
    def read(_request):
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "id": claim.subject,
                    "owner": "customers",
                    "name": "connected-account",
                    "type": "normal-user",
                    "email": "linked@example.test",
                    "emailVerified": True,
                    "isAdmin": False,
                    "isForbidden": False,
                    "isDeleted": False,
                    "password": "***",
                    "passwordType": "salt",
                    **mutation,
                },
            },
        )

    provider = CasdoorCredentialImportProvider(config, transport=httpx.MockTransport(read))
    with pytest.raises(CredentialMigrationError) as rejected:
        provider.read_linked_identity(claim.subject)
    assert "private-material" not in str(rejected.value)


def test_production_loader_pins_identity_and_requires_private_secret_files(tmp_path, config):
    provider = OidcProviderConfig(
        provider="casdoor",
        issuer=config.issuer,
        authorization_endpoint=config.issuer + "/login/oauth/authorize",
        token_endpoint=config.issuer + "/api/login/oauth/access_token",
        jwks_uri=config.issuer + "/.well-known/customer-web/jwks",
        client_id="customer-oidc-app",
        client_secret="customer-oidc-secret",
        redirect_uri="https://product.example.test/saas/auth/oidc/casdoor/callback",
        allowed_identity_owners=("customers",),
    )
    identity = ProductionIdentityConfig(mode="dual", provider=provider)
    document = {
        key: getattr(config, key)
        for key in (
            "issuer",
            "organization",
            "customer_application",
            "migration_client_id",
            "source_lock_sha256",
            "policy_revision",
        )
    }
    files = {
        "CONFIG": json.dumps(document),
        "CLIENT_SECRET": config.migration_client_secret,
        "MARKER_KEYRING": json.dumps(
            {
                "schema_version": 1,
                "active_key_id": "first",
                "keys": {"first": base64.b64encode(b"k" * 32).decode()},
            }
        ),
    }
    environ = {}
    for name, content in files.items():
        path = tmp_path / name
        path.write_text(content)
        path.chmod(0o600)
        environ["OMNIGENT_SAAS_CREDENTIAL_IMPORT_" + name + "_FILE"] = str(path)
    loaded = load_casdoor_credential_import_config(environ, identity=identity)
    assert loaded.policy() == config.policy()
    with pytest.raises(ProductionServerConfigError):
        load_casdoor_credential_import_config(
            environ,
            identity=replace(
                identity, provider=replace(provider, client_id=config.migration_client_id)
            ),
        )
    (tmp_path / "CLIENT_SECRET").chmod(0o644)
    with pytest.raises(ProductionServerConfigError):
        load_casdoor_credential_import_config(environ, identity=identity)


@pytest.mark.parametrize(
    "mutation",
    [
        {"issuer": "http://auth.example.test"},
        {"issuer": "https://auth.example.test/path"},
        {"issuer": "https://user:password@auth.example.test"},
        {"organization": "built-in"},
        {"customer_application": "app-built-in"},
    ],
)
def test_unsafe_provider_configuration_is_rejected(config, mutation):
    with pytest.raises(ValueError):
        replace(config, **mutation)


def test_committed_hash_import_marker_and_snapshot_remain_compatible():
    from uuid import UUID

    from saas.control_plane.credential_migration import VerifiedMigrationIdentity

    # Fixed synthetic vector from committed 9e3c9239b; existing remote markers
    # must still verify when existing-link support is deployed.
    user_id = UUID(int=2)
    claim = CredentialImportClaim(
        receipt_id=UUID(int=1),
        user_id=user_id,
        issuer="https://auth.example.test",
        organization="customers",
        subject=str(user_id),
        username="omnigent-" + user_id.hex,
        policy_sha256="a" * 64,
        source_password_sha256="b" * 64,
        source_email_sha256="c" * 64,
        claim_token=UUID(int=3),
        password_hash="synthetic-unused",
        email="legacy@example.test",
    )
    marker = "v1.first.70f49b3efa057a18fe5650d17e56372a143aa92cbc38f12ba134211b0d112a78"
    keys = CredentialImportKeyring("first", {"first": b"k" * 32})
    assert keys.sign(claim) == marker
    keys.verify(marker, claim)
    identity = VerifiedMigrationIdentity(
        claim.issuer,
        claim.organization,
        claim.subject,
        claim.username,
        claim.email,
        True,
        True,
        False,
        False,
        True,
    )
    assert identity.snapshot_sha256() == (
        "43f8874bb53de6bf2209a6350232b9973cd9b82ceb236b00018317c02d22c449"
    )
