"""Pinned OIDC Authorization Code + PKCE flow with replica-safe transactions."""

from __future__ import annotations

import asyncio
import base64
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, cast
from urllib.parse import urlencode, urlsplit
from uuid import UUID, uuid4

import httpx
import jwt
import sqlalchemy as sa
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwt import InvalidTokenError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import GlobalUser, OidcLoginTransaction
from saas.control_plane.identity import (
    IdentityLoginResolution,
    IdentityManagementService,
    VerifiedIdentityAssertion,
)
from saas.control_plane.lifecycle import LifecycleError, ValidatedAuthSession

_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MAX_TOKEN_RESPONSE_BYTES = 1_048_576


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _comparable_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _validate_endpoint(url: str, *, allow_insecure_loopback: bool, name: str) -> None:
    parsed = urlsplit(url)
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"OIDC {name} URL is invalid")
    if parsed.scheme == "https":
        return
    if (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        return
    raise ValueError(f"OIDC {name} URL must use HTTPS")


@dataclass(frozen=True, slots=True)
class OidcProviderConfig:
    """Pinned provider metadata; discovery URLs are never accepted from a request."""

    provider: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    client_id: str
    client_secret: str
    redirect_uri: str
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    transaction_ttl: timedelta = timedelta(minutes=5)
    jwks_ttl: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        if not _PROVIDER_NAME.fullmatch(self.provider):
            raise ValueError("OIDC provider name is invalid")
        for name, url in (
            ("issuer", self.issuer),
            ("authorization endpoint", self.authorization_endpoint),
            ("token endpoint", self.token_endpoint),
            ("JWKS", self.jwks_uri),
            ("redirect", self.redirect_uri),
        ):
            _validate_endpoint(
                url,
                allow_insecure_loopback=self.allow_insecure_loopback,
                name=name,
            )
        if self.issuer.endswith("/"):
            raise ValueError(
                "OIDC issuer must be stored in canonical form without a trailing slash"
            )
        if not self.client_id or not self.client_secret:
            raise ValueError("OIDC client credentials must be configured")
        if not self.allowed_algorithms or any(
            algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
            for algorithm in self.allowed_algorithms
        ):
            raise ValueError("OIDC signing algorithm allowlist is invalid")
        if "openid" not in self.scopes:
            raise ValueError("OIDC scope must include openid")
        if not timedelta(seconds=30) <= self.transaction_ttl <= timedelta(minutes=10):
            raise ValueError("OIDC transaction TTL must be between 30 seconds and 10 minutes")
        if not timedelta(seconds=1) <= self.jwks_ttl <= timedelta(hours=1):
            raise ValueError("OIDC JWKS TTL must be between 1 second and 1 hour")
        if not timedelta(0) <= self.clock_skew <= timedelta(minutes=2):
            raise ValueError("OIDC clock skew must be between 0 and 2 minutes")


@dataclass(frozen=True, slots=True)
class OidcAuthorizationStarted:
    """Authorization redirect and one browser-binding secret returned once."""

    transaction_id: UUID
    authorization_url: str
    browser_binding: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class OidcAuthorizationCompleted:
    """Verified callback result; conflicts never receive an Auth Session."""

    transaction_id: UUID
    user_id: UUID | None
    conflict_id: UUID | None
    purpose: Literal["login", "link"]


@dataclass(frozen=True, slots=True)
class _ConsumedTransaction:
    id: UUID
    provider: str
    nonce_hash: str
    code_verifier: str
    purpose: Literal["login", "link"]
    target_user_id: UUID | None
    target_security_version: int | None


class OidcAuthorizationService:
    """Execute strict OIDC callbacks without process-local transaction authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        identities: IdentityManagementService,
        providers: Mapping[str, OidcProviderConfig],
        *,
        transaction_encryption_key: bytes,
        http_transport: httpx.AsyncBaseTransport | None = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if len(transaction_encryption_key) != 32:
            raise ValueError("OIDC transaction encryption key must contain exactly 32 bytes")
        if not providers:
            raise ValueError("at least one pinned OIDC provider is required")
        if set(providers) != {config.provider for config in providers.values()}:
            raise ValueError("OIDC provider map keys must match provider names")
        self._session_factory = session_factory
        self._identities = identities
        self._providers = dict(providers)
        self._cipher = AESGCM(transaction_encryption_key)
        self._http_transport = http_transport
        self._now = now
        self._jwks_cache: dict[str, tuple[datetime, list[dict[str, object]]]] = {}
        self._jwks_lock = asyncio.Lock()

    def begin(
        self,
        provider: str,
        *,
        purpose: Literal["login", "link"] = "login",
        target_session: ValidatedAuthSession | None = None,
    ) -> OidcAuthorizationStarted:
        """Persist state, nonce, encrypted verifier, and browser binding before redirect."""

        config = self._provider(provider)
        issued_at = self._now()
        if purpose == "link":
            if target_session is None:
                raise LifecycleError(
                    "authentication_required", "authenticated account is required for linking"
                )
            if issued_at - _comparable_time(target_session.authenticated_at) > timedelta(
                minutes=5
            ):
                raise LifecycleError(
                    "recent_authentication_required", "recent authentication is required"
                )
        elif purpose != "login":
            raise LifecycleError("oidc_purpose_invalid", "OIDC purpose is invalid")

        transaction_id = uuid4()
        raw_state = secrets.token_urlsafe(32)
        raw_nonce = secrets.token_urlsafe(32)
        browser_binding = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        state_hash = _digest(raw_state)
        verifier_nonce = secrets.token_bytes(12)
        verifier_ciphertext = self._cipher.encrypt(
            verifier_nonce,
            code_verifier.encode("ascii"),
            state_hash.encode("ascii"),
        )
        encrypted_verifier = _b64url(verifier_nonce + verifier_ciphertext)
        expires_at = issued_at + config.transaction_ttl
        with self._session_factory.begin() as db:
            if target_session is not None:
                user = db.get(GlobalUser, target_session.user_id)
                if (
                    user is None
                    or user.status != "active"
                    or user.security_version != target_session.security_version
                ):
                    raise LifecycleError("invalid_session", "authentication session is invalid")
            db.add(
                OidcLoginTransaction(
                    id=transaction_id,
                    provider=provider,
                    state_hash=state_hash,
                    browser_binding_hash=_digest(browser_binding),
                    nonce_hash=_digest(raw_nonce),
                    code_verifier_ciphertext=encrypted_verifier,
                    purpose=purpose,
                    target_user_id=target_session.user_id if target_session else None,
                    target_security_version=(
                        target_session.security_version if target_session else None
                    ),
                    status="pending",
                    expires_at=expires_at,
                )
            )

        code_challenge = _b64url(sha256(code_verifier.encode("ascii")).digest())
        query = urlencode(
            {
                "response_type": "code",
                "client_id": config.client_id,
                "redirect_uri": config.redirect_uri,
                "scope": " ".join(config.scopes),
                "state": raw_state,
                "nonce": raw_nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return OidcAuthorizationStarted(
            transaction_id=transaction_id,
            authorization_url=f"{config.authorization_endpoint}?{query}",
            browser_binding=browser_binding,
            expires_at=expires_at,
        )

    async def complete(
        self,
        provider: str,
        *,
        code: str,
        state: str,
        browser_binding: str,
    ) -> OidcAuthorizationCompleted:
        """Consume a one-time transaction, exchange code, and verify the ID Token."""

        if not code or len(code) > 4096:
            raise LifecycleError("oidc_code_invalid", "authorization code is invalid")
        transaction = self._consume_transaction(provider, state, browser_binding)
        config = self._provider(provider)
        try:
            id_token = await self._exchange_code(config, code, transaction.code_verifier)
            claims = await self._verify_id_token(config, id_token)
            nonce = claims.get("nonce")
            if not isinstance(nonce, str) or not hmac.compare_digest(
                _digest(nonce), transaction.nonce_hash
            ):
                raise LifecycleError("oidc_nonce_invalid", "OIDC nonce verification failed")
            assertion = VerifiedIdentityAssertion(
                provider=config.provider,
                issuer=cast(str, claims["iss"]),
                subject=cast(str, claims["sub"]),
                email=claims.get("email") if isinstance(claims.get("email"), str) else None,
                email_verified=claims.get("email_verified") is True,
                display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
            )
            if transaction.purpose == "link":
                self._require_link_target_current(transaction)
                user_id = cast(UUID, transaction.target_user_id)
                self._identities.link_identity(
                    user_id=user_id,
                    assertion=assertion,
                    idempotency_key=f"oidc-link:{transaction.id}",
                    expected_security_version=transaction.target_security_version,
                )
                resolution = IdentityLoginResolution(user_id=user_id, conflict_id=None)
            else:
                resolution = self._identities.resolve_verified_login(assertion)
        except Exception:
            self._mark_failed(transaction.id)
            raise

        return OidcAuthorizationCompleted(
            transaction_id=transaction.id,
            user_id=resolution.user_id,
            conflict_id=resolution.conflict_id,
            purpose=transaction.purpose,
        )

    def abort(
        self,
        provider: str,
        *,
        state: str,
        browser_binding: str,
    ) -> None:
        """Consume a provider-declined callback without trusting its error description."""

        transaction = self._consume_transaction(provider, state, browser_binding)
        self._mark_failed(transaction.id)

    def _consume_transaction(
        self, provider: str, state: str, browser_binding: str
    ) -> _ConsumedTransaction:
        config = self._provider(provider)
        consumed_at = self._now()
        if not state or len(state) > 1024 or not browser_binding or len(browser_binding) > 1024:
            raise LifecycleError("oidc_transaction_invalid", "OIDC transaction is invalid")
        state_hash = _digest(state)
        with self._session_factory.begin() as db:
            transaction = db.execute(
                sa.select(OidcLoginTransaction)
                .where(OidcLoginTransaction.state_hash == state_hash)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                transaction is None
                or transaction.provider != config.provider
                or transaction.status != "pending"
                or _comparable_time(transaction.expires_at) <= consumed_at
                or not hmac.compare_digest(
                    transaction.browser_binding_hash, _digest(browser_binding)
                )
            ):
                raise LifecycleError("oidc_transaction_invalid", "OIDC transaction is invalid")
            transaction.status = "consumed"
            transaction.consumed_at = consumed_at
            code_verifier = self._decrypt_verifier(
                transaction.code_verifier_ciphertext, state_hash
            )
            return _ConsumedTransaction(
                id=transaction.id,
                provider=transaction.provider,
                nonce_hash=transaction.nonce_hash,
                code_verifier=code_verifier,
                purpose=cast(Literal["login", "link"], transaction.purpose),
                target_user_id=transaction.target_user_id,
                target_security_version=transaction.target_security_version,
            )

    def _decrypt_verifier(self, encoded: str, state_hash: str) -> str:
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = base64.urlsafe_b64decode(padded.encode("ascii"))
            if len(payload) < 29:
                raise ValueError
            plaintext = self._cipher.decrypt(
                payload[:12], payload[12:], state_hash.encode("ascii")
            )
            verifier = plaintext.decode("ascii")
        except (InvalidTag, ValueError, UnicodeDecodeError) as error:
            raise LifecycleError(
                "oidc_transaction_invalid", "OIDC transaction verifier is invalid"
            ) from error
        if not 43 <= len(verifier) <= 128:
            raise LifecycleError(
                "oidc_transaction_invalid", "OIDC transaction verifier is invalid"
            )
        return verifier

    async def _exchange_code(
        self, config: OidcProviderConfig, code: str, code_verifier: str
    ) -> str:
        try:
            async with httpx.AsyncClient(
                transport=self._http_transport,
                timeout=httpx.Timeout(10.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    config.token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": config.redirect_uri,
                        "client_id": config.client_id,
                        "code_verifier": code_verifier,
                    },
                    auth=httpx.BasicAuth(config.client_id, config.client_secret),
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as error:
            raise LifecycleError(
                "oidc_dependency_unavailable", "OIDC token endpoint is unavailable"
            ) from error
        if response.status_code != 200 or len(response.content) > _MAX_TOKEN_RESPONSE_BYTES:
            raise LifecycleError("oidc_token_exchange_failed", "OIDC token exchange failed")
        try:
            payload = response.json()
        except ValueError as error:
            raise LifecycleError(
                "oidc_token_exchange_failed", "OIDC token response is invalid"
            ) from error
        id_token = payload.get("id_token") if isinstance(payload, dict) else None
        if not isinstance(id_token, str) or not id_token or len(id_token) > 64_000:
            raise LifecycleError("oidc_token_exchange_failed", "OIDC ID Token is invalid")
        return id_token

    async def _verify_id_token(
        self, config: OidcProviderConfig, id_token: str
    ) -> dict[str, object]:
        last_error: Exception | None = None
        for force_refresh in (False, True):
            try:
                keys = await self._jwks(config, force_refresh=force_refresh)
                return self._decode_id_token(config, id_token, keys)
            except (InvalidTokenError, LifecycleError, ValueError) as error:
                last_error = error
        raise LifecycleError(
            "oidc_id_token_invalid", "OIDC ID Token verification failed"
        ) from last_error

    async def _jwks(
        self, config: OidcProviderConfig, *, force_refresh: bool
    ) -> list[dict[str, object]]:
        now = self._now()
        cached = self._jwks_cache.get(config.provider)
        if not force_refresh and cached is not None and cached[0] > now:
            return cached[1]
        async with self._jwks_lock:
            cached = self._jwks_cache.get(config.provider)
            if not force_refresh and cached is not None and cached[0] > now:
                return cached[1]
            try:
                async with httpx.AsyncClient(
                    transport=self._http_transport,
                    timeout=httpx.Timeout(10.0),
                    follow_redirects=False,
                ) as client:
                    response = await client.get(
                        config.jwks_uri, headers={"Accept": "application/json"}
                    )
            except httpx.HTTPError as error:
                raise LifecycleError(
                    "oidc_dependency_unavailable", "OIDC JWKS endpoint is unavailable"
                ) from error
            if response.status_code != 200 or len(response.content) > _MAX_TOKEN_RESPONSE_BYTES:
                raise LifecycleError("oidc_jwks_invalid", "OIDC JWKS response is invalid")
            try:
                payload = response.json()
            except ValueError as error:
                raise LifecycleError(
                    "oidc_jwks_invalid", "OIDC JWKS response is invalid"
                ) from error
            raw_keys = payload.get("keys") if isinstance(payload, dict) else None
            if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > 100:
                raise LifecycleError("oidc_jwks_invalid", "OIDC JWKS response is invalid")
            keys = [key for key in raw_keys if isinstance(key, dict)]
            if len(keys) != len(raw_keys):
                raise LifecycleError("oidc_jwks_invalid", "OIDC JWKS response is invalid")
            self._jwks_cache[config.provider] = (now + config.jwks_ttl, keys)
            return keys

    @staticmethod
    def _decode_id_token(
        config: OidcProviderConfig,
        id_token: str,
        keys: list[dict[str, object]],
    ) -> dict[str, object]:
        header = jwt.get_unverified_header(id_token)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in config.allowed_algorithms or not isinstance(key_id, str) or not key_id:
            raise LifecycleError("oidc_id_token_invalid", "OIDC signing header is invalid")
        candidates = [
            key
            for key in keys
            if key.get("kid") == key_id
            and key.get("use", "sig") == "sig"
            and key.get("alg", algorithm) == algorithm
        ]
        if len(candidates) != 1:
            raise LifecycleError("oidc_id_token_invalid", "OIDC signing key is ambiguous")
        signing_key = jwt.PyJWK.from_dict(candidates[0], algorithm=cast(str, algorithm)).key
        claims = jwt.decode(
            id_token,
            key=signing_key,
            algorithms=[cast(str, algorithm)],
            audience=config.client_id,
            issuer=config.issuer,
            leeway=config.clock_skew.total_seconds(),
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "nbf", "nonce"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        if not isinstance(claims, dict):
            raise LifecycleError("oidc_id_token_invalid", "OIDC claims are invalid")
        audience = claims.get("aud")
        authorized_party = claims.get("azp")
        if (
            isinstance(audience, list)
            and len(audience) > 1
            and authorized_party != config.client_id
        ) or (authorized_party is not None and authorized_party != config.client_id):
            raise LifecycleError("oidc_id_token_invalid", "OIDC authorized party is invalid")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 512:
            raise LifecycleError("oidc_id_token_invalid", "OIDC subject is invalid")
        return cast(dict[str, object], claims)

    def _require_link_target_current(self, transaction: _ConsumedTransaction) -> None:
        if transaction.target_user_id is None or transaction.target_security_version is None:
            raise LifecycleError("oidc_transaction_invalid", "OIDC link target is invalid")
        with self._session_factory() as db:
            user = db.get(GlobalUser, transaction.target_user_id)
            if (
                user is None
                or user.status != "active"
                or user.security_version != transaction.target_security_version
            ):
                raise LifecycleError("authorization_snapshot_stale", "account changed during link")

    def _mark_failed(self, transaction_id: UUID) -> None:
        with self._session_factory.begin() as db:
            db.execute(
                sa.update(OidcLoginTransaction)
                .where(
                    OidcLoginTransaction.id == transaction_id,
                    OidcLoginTransaction.status == "consumed",
                )
                .values(status="failed")
            )

    def _provider(self, provider: str) -> OidcProviderConfig:
        config = self._providers.get(provider)
        if config is None:
            raise LifecycleError("oidc_provider_unknown", "OIDC provider is not configured")
        return config
