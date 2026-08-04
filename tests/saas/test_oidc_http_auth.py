from __future__ import annotations

import base64
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import jwt
import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    IdentityManagementService,
    MembershipLifecycleService,
    OidcAuthorizationService,
    OidcProviderConfig,
    PasswordCredentialService,
    RuntimeCompatibilityPolicy,
    SaasBase,
    SaasCookieConfig,
    SqlAlchemyContextResolver,
    VerifiedIdentityAssertion,
    create_saas_http_integration,
)

_ISSUER = "https://idp.example.test"
_CLIENT_ID = "omnigent-test-client"
_CLIENT_SECRET = "test-client-secret"
_REDIRECT_URI = "https://testserver/saas/auth/oidc/test/callback"


def _b64url_int(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


@dataclass(slots=True)
class _AuthorizationCode:
    nonce: str
    code_challenge: str
    subject: str
    email: str
    claim_overrides: dict[str, object]
    algorithm: str


class _FakeOidcProvider:
    def __init__(self) -> None:
        self._keys = [
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ]
        self._key_index = 0
        self._codes: dict[str, _AuthorizationCode] = {}
        self.token_exchange_count = 0
        self.jwks_request_count = 0

    @property
    def key_id(self) -> str:
        return f"test-key-{self._key_index}"

    def rotate_signing_key(self) -> None:
        self._key_index = 1

    def authorize(
        self,
        authorization_url: str,
        *,
        subject: str,
        email: str,
        claim_overrides: dict[str, object] | None = None,
        algorithm: str = "RS256",
    ) -> dict[str, str]:
        query = parse_qs(urlsplit(authorization_url).query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == [_CLIENT_ID]
        assert query["redirect_uri"] == [_REDIRECT_URI]
        assert query["code_challenge_method"] == ["S256"]
        assert "openid" in query["scope"][0].split()
        code = secrets.token_urlsafe(24)
        self._codes[code] = _AuthorizationCode(
            nonce=query["nonce"][0],
            code_challenge=query["code_challenge"][0],
            subject=subject,
            email=email,
            claim_overrides=claim_overrides or {},
            algorithm=algorithm,
        )
        return {"code": code, "state": query["state"][0]}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/jwks":
            self.jwks_request_count += 1
            public = self._keys[self._key_index].public_key().public_numbers()
            return httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "kid": self.key_id,
                            "n": _b64url_int(public.n),
                            "e": _b64url_int(public.e),
                        }
                    ]
                },
            )
        if request.url.path != "/token":
            return httpx.Response(404)

        expected_basic = (
            "Basic " + base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
        )
        if request.headers.get("authorization") != expected_basic:
            return httpx.Response(401)
        form = parse_qs(request.content.decode())
        code = form.get("code", [""])[0]
        pending = self._codes.pop(code, None)
        if pending is None:
            return httpx.Response(400)
        verifier = form.get("code_verifier", [""])[0]
        actual_challenge = (
            base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        )
        if (
            actual_challenge != pending.code_challenge
            or form.get("grant_type") != ["authorization_code"]
            or form.get("client_id") != [_CLIENT_ID]
            or form.get("redirect_uri") != [_REDIRECT_URI]
        ):
            return httpx.Response(400)

        now = datetime.now(timezone.utc)
        claims: dict[str, object] = {
            "iss": _ISSUER,
            "sub": pending.subject,
            "aud": _CLIENT_ID,
            "iat": int(now.timestamp()),
            "nbf": int((now - timedelta(seconds=1)).timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "nonce": pending.nonce,
            "email": pending.email,
            "email_verified": True,
            "name": pending.subject,
        }
        claims.update(pending.claim_overrides)
        if pending.algorithm == "RS256":
            token = jwt.encode(
                claims,
                self._keys[self._key_index],
                algorithm="RS256",
                headers={"kid": self.key_id},
            )
        else:
            token = jwt.encode(
                claims,
                "untrusted-symmetric-secret-long-enough",
                algorithm="HS256",
                headers={"kid": self.key_id},
            )
        self.token_exchange_count += 1
        return httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})


@dataclass(slots=True)
class _Harness:
    client: TestClient
    provider: _FakeOidcProvider
    sessions: sessionmaker[Session]
    identities: IdentityManagementService
    passwords: PasswordCredentialService
    engine: Engine


@pytest.fixture
def oidc_harness() -> Iterator[_Harness]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    identities = IdentityManagementService(sessions)
    lifecycle = MembershipLifecycleService(sessions)
    passwords = PasswordCredentialService(sessions)
    provider = _FakeOidcProvider()
    config = OidcProviderConfig(
        provider="test",
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        token_endpoint=f"{_ISSUER}/token",
        jwks_uri=f"{_ISSUER}/jwks",
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
        redirect_uri=_REDIRECT_URI,
    )
    oidc = OidcAuthorizationService(
        sessions,
        identities,
        {"test": config},
        transaction_encryption_key=b"o" * 32,
        http_transport=cast(httpx.AsyncBaseTransport, httpx.MockTransport(provider.handle)),
    )
    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
        allowed_source_revisions=frozenset({"15dd7bec"}),
        allowed_schema_revisions=frozenset({"schema"}),
        adapter_contract_version="0.2.0",
    )
    resolver = SqlAlchemyContextResolver(sessions, policy)
    cookie = SaasCookieConfig(trusted_origins=frozenset({"https://testserver"}))
    integration = create_saas_http_integration(
        lifecycle=lifecycle,
        identities=identities,
        passwords=passwords,
        context_resolver=resolver,
        cookie_config=cookie,
        oidc=oidc,
    )
    app = FastAPI()
    router, prefix, tags = integration.extra_router
    app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    with TestClient(app, base_url="https://testserver") as client:
        yield _Harness(client, provider, sessions, identities, passwords, engine)
    SaasBase.metadata.drop_all(engine)
    engine.dispose()


def _start(
    harness: _Harness,
    *,
    subject: str,
    email: str,
    claim_overrides: dict[str, object] | None = None,
    algorithm: str = "RS256",
) -> tuple[dict[str, str], str]:
    response = harness.client.get("/saas/auth/oidc/test/start", follow_redirects=False)
    assert response.status_code == 302
    set_cookie = response.headers["set-cookie"]
    assert "__Host-omnigent_saas_session_oidc=" in set_cookie
    assert "HttpOnly" in set_cookie and "Secure" in set_cookie and "SameSite=lax" in set_cookie
    location = response.headers["location"]
    return (
        harness.provider.authorize(
            location,
            subject=subject,
            email=email,
            claim_overrides=claim_overrides,
            algorithm=algorithm,
        ),
        cast(str, harness.client.cookies.get("__Host-omnigent_saas_session_oidc")),
    )


def test_oidc_http_cookie_login_is_one_time_pkce_bound_and_jwks_rotates(
    oidc_harness: _Harness,
) -> None:
    callback, browser_binding = _start(oidc_harness, subject="oidc-user-a", email="a@example.com")
    completed = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert completed.status_code == 200
    assert completed.json()["purpose"] == "login"
    assert completed.json()["csrf_token"]
    assert oidc_harness.client.cookies.get("__Host-omnigent_saas_session")
    assert oidc_harness.client.cookies.get("__Host-omnigent_saas_session_oidc") is None

    oidc_harness.client.cookies.set(
        "__Host-omnigent_saas_session_oidc", browser_binding, domain="testserver.local", path="/"
    )
    replay = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert replay.status_code == 400
    assert replay.json()["error"]["code"] == "oidc_transaction_invalid"
    assert oidc_harness.provider.token_exchange_count == 1

    next_callback, _ = _start(oidc_harness, subject="oidc-user-b", email="b@example.com")
    oidc_harness.provider.rotate_signing_key()
    rotated = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=next_callback)
    assert rotated.status_code == 200
    assert oidc_harness.provider.jwks_request_count >= 2


def test_oidc_callback_rejects_wrong_browser_binding_without_exchanging_code(
    oidc_harness: _Harness,
) -> None:
    callback, browser_binding = _start(
        oidc_harness, subject="binding-user", email="binding@example.com"
    )
    oidc_harness.client.cookies.set(
        "__Host-omnigent_saas_session_oidc",
        "wrong-browser-binding",
        domain="testserver.local",
        path="/",
    )
    rejected = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "oidc_transaction_invalid"
    assert oidc_harness.provider.token_exchange_count == 0

    oidc_harness.client.cookies.set(
        "__Host-omnigent_saas_session_oidc",
        browser_binding,
        domain="testserver.local",
        path="/",
    )
    completed = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert completed.status_code == 200


@pytest.mark.parametrize(
    ("claim_overrides", "algorithm"),
    [
        ({"iss": "https://attacker.example.test"}, "RS256"),
        ({"aud": "another-client"}, "RS256"),
        ({"aud": [_CLIENT_ID, "another-client"]}, "RS256"),
        ({"nonce": "wrong-nonce"}, "RS256"),
        ({}, "HS256"),
    ],
)
def test_oidc_callback_rejects_untrusted_claims_and_algorithm_downgrade(
    oidc_harness: _Harness,
    claim_overrides: dict[str, object],
    algorithm: str,
) -> None:
    callback, _ = _start(
        oidc_harness,
        subject="negative-user",
        email="negative@example.com",
        claim_overrides=claim_overrides,
        algorithm=algorithm,
    )
    rejected = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] in {
        "oidc_id_token_invalid",
        "oidc_nonce_invalid",
    }
    assert oidc_harness.client.cookies.get("__Host-omnigent_saas_session") is None


def test_same_email_oidc_subject_requires_recent_explicit_confirmation(
    oidc_harness: _Harness,
) -> None:
    existing_user = oidc_harness.identities.provision_identity(
        VerifiedIdentityAssertion(
            provider="existing",
            issuer="https://existing.example.test",
            subject="existing-subject",
            email="same@example.com",
            email_verified=True,
        )
    )
    oidc_harness.passwords.set_password(
        user_id=existing_user,
        new_password="existing-password-value",
        expected_version=None,
        idempotency_key="set-existing-password",
    )
    logged_in = oidc_harness.client.post(
        "/saas/auth/login",
        json={"email": "same@example.com", "password": "existing-password-value"},
    )
    assert logged_in.status_code == 200

    callback, _ = _start(
        oidc_harness,
        subject="new-subject-same-email",
        email="same@example.com",
    )
    conflict = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "identity_confirmation_required"
    conflict_id = conflict.json()["identity_conflict_id"]
    assert len(oidc_harness.identities.list_identities(existing_user)) == 1

    resolved = oidc_harness.client.post(
        f"/saas/auth/identity-conflicts/{conflict_id}",
        json={"decision": "approve", "reason": "confirmed after password login"},
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": logged_in.json()["csrf_token"],
            "Idempotency-Key": "approve-explicit-identity",
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["decision"] == "approve"
    assert resolved.json()["identity_connection_id"]
    assert len(oidc_harness.identities.list_identities(existing_user)) == 2

    exact_callback, _ = _start(
        oidc_harness,
        subject="new-subject-same-email",
        email="same@example.com",
    )
    exact_login = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=exact_callback)
    assert exact_login.status_code == 200
    assert exact_login.json()["user_id"] == str(existing_user)


def test_authenticated_oidc_link_flow_binds_target_security_version(
    oidc_harness: _Harness,
) -> None:
    first_callback, _ = _start(oidc_harness, subject="link-primary", email="link@example.com")
    logged_in = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=first_callback)
    assert logged_in.status_code == 200
    user_id = logged_in.json()["user_id"]

    started = oidc_harness.client.post(
        "/saas/auth/oidc/test/link/start",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": logged_in.json()["csrf_token"],
        },
        follow_redirects=False,
    )
    assert started.status_code == 303
    callback = oidc_harness.provider.authorize(
        started.headers["location"],
        subject="link-secondary",
        email="secondary@example.com",
    )
    linked = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert linked.status_code == 200
    assert linked.json()["purpose"] == "link"
    assert len(oidc_harness.identities.list_identities(UUID(user_id))) == 2
