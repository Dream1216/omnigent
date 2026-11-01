"""Pinned OIDC Authorization Code + PKCE flow with replica-safe transactions."""

from __future__ import annotations

import asyncio
import base64
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Literal, cast
from urllib.parse import unquote, urlencode, urlsplit
from uuid import UUID, uuid4

import httpx
import jwt
import sqlalchemy as sa
from jwt import InvalidTokenError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import AuthSessionRecord, GlobalUser, OidcLoginTransaction
from saas.control_plane.federated_sessions import (
    ExternalSessionIdentity,
    FederatedSessionService,
    VerifiedLogoutEvent,
)
from saas.control_plane.identity import (
    IdentityLoginResolution,
    IdentityManagementService,
    VerifiedIdentityAssertion,
)
from saas.control_plane.lifecycle import LifecycleError, ValidatedAuthSession
from saas.control_plane.oidc_keyring import OidcTransactionKeyring

_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MAX_TOKEN_RESPONSE_BYTES = 1_048_576


class OidcFlowError(LifecycleError):
    def __init__(self, error: LifecycleError, ui_locale: str) -> None:
        super().__init__(error.code, str(error))
        self.ui_locale = ui_locale


def validate_oidc_return_to(value: str) -> str:
    """Accept only an unambiguous local navigation target, never an auth loop."""

    if not value or len(value) > 2048:
        raise LifecycleError("oidc_return_to_invalid", "return target is invalid")
    decoded = value
    for _ in range(4):
        if (
            not decoded.startswith("/")
            or decoded.startswith("//")
            or "\\" in decoded
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        ):
            raise LifecycleError("oidc_return_to_invalid", "return target is invalid")
        parsed = urlsplit(decoded)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.path.rstrip("/") in {"/login", "/signup", "/saas/login", "/saas/auth"}
            or any(part in {".", ".."} for part in parsed.path.split("/"))
            or parsed.path.startswith("/saas/auth/")
        ):
            raise LifecycleError("oidc_return_to_invalid", "return target is invalid")
        next_value = unquote(decoded)
        if next_value == decoded:
            return value
        decoded = next_value
    raise LifecycleError("oidc_return_to_invalid", "return target is invalid")


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
    client_secret: str = field(repr=False)
    redirect_uri: str
    allowed_algorithms: tuple[str, ...] = ("RS256",)
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    transaction_ttl: timedelta = timedelta(minutes=5)
    jwks_ttl: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    allow_insecure_loopback: bool = False
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = (
        "client_secret_basic"
    )
    signup_endpoint: str | None = None
    allowed_identity_owners: tuple[str, ...] = ()
    ui_locale_parameter: Literal["ui_locales", "language"] = "ui_locales"
    end_session_endpoint: str | None = None
    post_logout_redirect_uri: str | None = None

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
        if self.token_endpoint_auth_method not in {"client_secret_basic", "client_secret_post"}:
            raise ValueError("OIDC token endpoint authentication method is invalid")
        if self.signup_endpoint is not None:
            _validate_endpoint(
                self.signup_endpoint,
                allow_insecure_loopback=self.allow_insecure_loopback,
                name="signup",
            )
            if (
                urlsplit(self.signup_endpoint).netloc
                != urlsplit(self.authorization_endpoint).netloc
            ):
                raise ValueError("OIDC signup and authorization endpoints must share an origin")
        if any(not owner or owner == "built-in" for owner in self.allowed_identity_owners):
            raise ValueError("OIDC customer identity owner allowlist is invalid")
        if self.ui_locale_parameter not in {"ui_locales", "language"}:
            raise ValueError("OIDC language parameter is invalid")
        if (self.end_session_endpoint is None) != (self.post_logout_redirect_uri is None):
            raise ValueError("OIDC logout endpoint and return URI must be configured together")
        if self.end_session_endpoint is not None:
            for name, url in (
                ("logout", self.end_session_endpoint),
                ("post logout", self.post_logout_redirect_uri),
            ):
                _validate_endpoint(
                    cast(str, url), allow_insecure_loopback=self.allow_insecure_loopback, name=name
                )
            if urlsplit(self.end_session_endpoint).netloc != urlsplit(self.issuer).netloc:
                raise ValueError("OIDC logout endpoint must belong to the pinned issuer")
            if (
                urlsplit(cast(str, self.post_logout_redirect_uri)).netloc
                != urlsplit(self.redirect_uri).netloc
            ):
                raise ValueError("OIDC logout return URI must belong to the relying party")
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
    state: str


@dataclass(frozen=True, slots=True)
class OidcAuthorizationCompleted:
    """Verified callback result; conflicts never receive an Auth Session."""

    transaction_id: UUID
    user_id: UUID | None
    conflict_id: UUID | None
    purpose: Literal["login", "signup", "link", "reauth"]
    return_to: str
    ui_locale: str
    external_identity: ExternalSessionIdentity
    parent_session_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class _ConsumedTransaction:
    id: UUID
    provider: str
    nonce_hash: str
    code_verifier: str
    purpose: Literal["login", "signup", "link", "reauth"]
    target_user_id: UUID | None
    target_security_version: int | None
    target_session_id: UUID | None
    return_to: str
    ui_locale: str
    created_at: datetime


class OidcAuthorizationService:
    """Execute strict OIDC callbacks without process-local transaction authority."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        identities: IdentityManagementService,
        providers: Mapping[str, OidcProviderConfig],
        *,
        transaction_encryption_key: bytes | None = None,
        transaction_keyring: OidcTransactionKeyring | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        if (transaction_encryption_key is None) == (transaction_keyring is None):
            raise ValueError("configure exactly one OIDC transaction key authority")
        if transaction_keyring is None:
            transaction_keyring = OidcTransactionKeyring(
                "legacy", {"legacy": cast(bytes, transaction_encryption_key)}
            )
        if not providers:
            raise ValueError("at least one pinned OIDC provider is required")
        if set(providers) != {config.provider for config in providers.values()}:
            raise ValueError("OIDC provider map keys must match provider names")
        self._session_factory = session_factory
        self._identities = identities
        self._providers = dict(providers)
        self._keyring = transaction_keyring
        self._http_transport = http_transport
        self._now = now
        self._jwks_cache: dict[str, tuple[datetime, list[dict[str, object]]]] = {}
        self._jwks_lock = asyncio.Lock()
        self._jwks_last_forced_refresh: dict[str, datetime] = {}
        with self._session_factory() as db:
            pending = db.scalars(
                sa.select(OidcLoginTransaction.code_verifier_ciphertext).where(
                    OidcLoginTransaction.provider.in_(self._providers),
                    OidcLoginTransaction.status == "pending",
                    OidcLoginTransaction.expires_at > self._now(),
                )
            )
            if any(self._keyring.key_id(value) not in self._keyring.keys for value in pending):
                raise ValueError("OIDC transaction rotation must retain keys for pending logins")

    def browser_providers(self) -> list[dict[str, str | None]]:
        return [
            {
                "name": name,
                "authorization_origin": urlsplit(config.authorization_endpoint)
                ._replace(path="", query="", fragment="")
                .geturl(),
                "start_path": f"/saas/auth/oidc/{name}/start",
                "link_path": f"/saas/auth/oidc/{name}/link/start",
                "signup_path": f"/saas/auth/oidc/{name}/start?intent=signup"
                if config.signup_endpoint is not None
                else None,
            }
            for name, config in self._providers.items()
        ]

    def begin(
        self,
        provider: str,
        *,
        purpose: Literal["login", "signup", "link", "reauth"] = "login",
        target_session: ValidatedAuthSession | None = None,
        return_to: str = "/",
        ui_locale: str = "zh-CN",
    ) -> OidcAuthorizationStarted:
        """Persist state, nonce, encrypted verifier, and browser binding before redirect."""

        config = self._provider(provider)
        return_to = validate_oidc_return_to(return_to)
        if ui_locale not in {"zh-CN", "en-US"}:
            raise LifecycleError("oidc_locale_invalid", "OIDC language is unsupported")
        if purpose == "signup" and config.signup_endpoint is None:
            raise LifecycleError("oidc_signup_unavailable", "OIDC signup is not configured")
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
        elif purpose not in {"login", "signup", "reauth"}:
            raise LifecycleError("oidc_purpose_invalid", "OIDC purpose is invalid")

        transaction_id = uuid4()
        raw_state = secrets.token_urlsafe(32)
        raw_nonce = secrets.token_urlsafe(32)
        browser_binding = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        state_hash = _digest(raw_state)
        verifier_nonce = secrets.token_bytes(12)
        encrypted_verifier = self._keyring.encrypt(
            code_verifier.encode("ascii"),
            state_hash=state_hash,
            nonce=verifier_nonce,
        )
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
                    return_to=return_to,
                    ui_locale=ui_locale,
                    created_at=issued_at,
                    target_user_id=target_session.user_id if target_session else None,
                    target_session_id=target_session.session_id if target_session else None,
                    target_security_version=(
                        target_session.security_version if target_session else None
                    ),
                    status="pending",
                    expires_at=expires_at,
                )
            )

        code_challenge = _b64url(sha256(code_verifier.encode("ascii")).digest())
        parameters = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": raw_state,
            "nonce": raw_nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            config.ui_locale_parameter: (
                {"zh-CN": "zh", "en-US": "en"}[ui_locale]
                if config.ui_locale_parameter == "language"
                else ui_locale
            ),
        }
        if purpose in {"link", "reauth"}:
            parameters.update({"prompt": "login", "max_age": "0"})
        query = urlencode(parameters)
        endpoint = config.signup_endpoint if purpose == "signup" else config.authorization_endpoint
        return OidcAuthorizationStarted(
            transaction_id=transaction_id,
            authorization_url=f"{endpoint}?{query}",
            browser_binding=browser_binding,
            expires_at=expires_at,
            state=raw_state,
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
            sid = claims.get("sid")
            if sid is not None and (not isinstance(sid, str) or not sid or len(sid) > 512):
                raise LifecycleError("oidc_id_token_invalid", "OIDC session identifier is invalid")
            external = ExternalSessionIdentity(
                provider=config.provider,
                issuer=config.issuer,
                subject=cast(str, claims["sub"]),
                sid=cast(str | None, sid),
                issued_at=datetime.fromtimestamp(cast(int, claims["iat"]), timezone.utc),
            )
            assertion = VerifiedIdentityAssertion(
                provider=config.provider,
                issuer=cast(str, claims["iss"]),
                subject=cast(str, claims["sub"]),
                email=claims.get("email") if isinstance(claims.get("email"), str) else None,
                email_verified=claims.get("email_verified") is True,
                display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
                phone_number=cast(str | None, claims.get("phone_number"))
                if "phone" in config.scopes
                else None,
                phone_number_verified=cast(bool, claims.get("phone_number_verified", False))
                if "phone" in config.scopes
                else False,
            )
            if transaction.purpose in {"link", "reauth"}:
                auth_time = claims.get("auth_time")
                if (
                    isinstance(auth_time, bool)
                    or not isinstance(auth_time, int)
                    or auth_time
                    < transaction.created_at.timestamp() - config.clock_skew.total_seconds()
                    or auth_time > self._now().timestamp() + config.clock_skew.total_seconds()
                ):
                    raise LifecycleError(
                        "oidc_recent_authentication_required",
                        "recent identity authentication is required",
                    )
            if transaction.purpose == "link":
                self._require_link_target_current(transaction)
                user_id = cast(UUID, transaction.target_user_id)
                self._identities.link_identity(
                    user_id=user_id,
                    assertion=assertion,
                    idempotency_key=f"oidc-link:{transaction.id}",
                    expected_security_version=transaction.target_security_version,
                    required_session_id=transaction.target_session_id,
                    require_local_session=True,
                )
                resolution = IdentityLoginResolution(user_id=user_id, conflict_id=None)
            elif transaction.purpose == "reauth" and transaction.target_user_id is not None:
                self._require_link_target_current(transaction, recent=False)
                user_id = self._identities.require_reauthentication_identity(
                    user_id=transaction.target_user_id, assertion=assertion
                )
                resolution = IdentityLoginResolution(user_id=user_id, conflict_id=None)
            else:
                resolution = self._identities.resolve_verified_login(assertion)
        except LifecycleError as error:
            self._mark_failed(transaction.id)
            raise OidcFlowError(error, transaction.ui_locale) from error
        except Exception:
            self._mark_failed(transaction.id)
            raise

        return OidcAuthorizationCompleted(
            transaction_id=transaction.id,
            user_id=resolution.user_id,
            conflict_id=resolution.conflict_id,
            purpose=transaction.purpose,
            return_to=transaction.return_to,
            ui_locale=transaction.ui_locale,
            external_identity=external,
            parent_session_id=transaction.target_session_id,
        )

    def logout_url(self, provider: str) -> str | None:
        config = self._providers.get(provider)
        if config is None or config.end_session_endpoint is None:
            return None
        return f"{config.end_session_endpoint}?" + urlencode(
            {
                "client_id": config.client_id,
                "post_logout_redirect_uri": config.post_logout_redirect_uri,
            }
        )

    async def verify_logout_token(self, provider: str, token: str) -> VerifiedLogoutEvent:
        config = self._provider(provider)
        claims = await self._verify_signed_token(
            config,
            token,
            required=("iss", "aud", "iat", "exp", "jti", "events"),
            error_code="oidc_logout_token_invalid",
        )
        sub, sid, issued_at, expires_at, jti = (
            claims.get("sub"),
            claims.get("sid"),
            claims.get("iat"),
            claims.get("exp"),
            claims.get("jti"),
        )
        events = claims.get("events")
        event_type = "http://schemas.openid.net/event/backchannel-logout"
        now = self._now().timestamp()
        if (
            "nonce" in claims
            or not isinstance(events, dict)
            or not isinstance(events.get(event_type), dict)
            or (sub is None and sid is None)
            or any(
                value is not None and (not isinstance(value, str) or not value or len(value) > 512)
                for value in (sub, sid)
            )
            or not isinstance(jti, str)
            or not jti
            or len(jti) > 512
            or type(issued_at) is not int
            or type(expires_at) is not int
            or issued_at < now - 300 - config.clock_skew.total_seconds()
            or issued_at > now + config.clock_skew.total_seconds()
            or expires_at <= issued_at
        ):
            raise LifecycleError("oidc_logout_token_invalid", "OIDC logout token is invalid")
        return VerifiedLogoutEvent(
            provider=provider,
            issuer=config.issuer,
            subject=cast(str | None, sub),
            sid=cast(str | None, sid),
            jti=jti,
            issued_at=datetime.fromtimestamp(issued_at, timezone.utc),
        )

    async def complete_logout(self, provider: str, token: str) -> None:
        event = await self.verify_logout_token(provider, token)
        FederatedSessionService(self._session_factory).revoke(event, now=self._now())

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
                purpose=cast(Literal["login", "signup", "link", "reauth"], transaction.purpose),
                target_user_id=transaction.target_user_id,
                target_security_version=transaction.target_security_version,
                target_session_id=transaction.target_session_id,
                return_to=transaction.return_to,
                ui_locale=transaction.ui_locale,
                created_at=_comparable_time(transaction.created_at),
            )

    def _decrypt_verifier(self, encoded: str, state_hash: str) -> str:
        try:
            plaintext = self._keyring.decrypt(encoded, state_hash=state_hash)
            verifier = plaintext.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
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
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "code_verifier": code_verifier,
        }
        auth = httpx.USE_CLIENT_DEFAULT
        if config.token_endpoint_auth_method == "client_secret_basic":
            auth = httpx.BasicAuth(config.client_id, config.client_secret)
        else:
            form.update({"client_id": config.client_id, "client_secret": config.client_secret})
        try:
            async with httpx.AsyncClient(
                transport=self._http_transport,
                timeout=httpx.Timeout(10.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    config.token_endpoint,
                    data=form,
                    auth=auth,
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
        claims = await self._verify_signed_token(
            config,
            id_token,
            required=("iss", "sub", "aud", "exp", "iat", "nbf", "nonce"),
            error_code="oidc_id_token_invalid",
        )
        subject = claims.get("sub")
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 512
            or any(type(claims.get(name)) is not int for name in ("iat", "exp", "nbf"))
            or cast(int, claims["iat"]) < 0
        ):
            raise LifecycleError(
                "oidc_id_token_invalid", "OIDC subject or issuance time is invalid"
            )
        if (
            config.allowed_identity_owners
            and claims.get("owner") not in config.allowed_identity_owners
        ):
            raise LifecycleError(
                "oidc_identity_owner_invalid", "OIDC identity organization is forbidden"
            )
        return claims

    async def _verify_signed_token(
        self, config: OidcProviderConfig, token: str, *, required: tuple[str, ...], error_code: str
    ) -> dict[str, object]:
        if not token or len(token) > 64_000:
            raise LifecycleError(error_code, "OIDC signed token is invalid")
        try:
            header = jwt.get_unverified_header(token)
            if (
                header.get("alg") not in config.allowed_algorithms
                or not isinstance(header.get("kid"), str)
                or not header["kid"]
            ):
                raise ValueError
        except (InvalidTokenError, ValueError) as error:
            raise LifecycleError(error_code, "OIDC signing header is invalid") from error
        last_error: Exception | None = None
        for force_refresh in (False, True):
            try:
                keys = await self._jwks(config, force_refresh=force_refresh)
                return self._decode_signed_token(config, token, keys, required=required)
            except (
                InvalidTokenError,
                LifecycleError,
                ValueError,
                TypeError,
                OverflowError,
            ) as error:
                last_error = error
                if (
                    not isinstance(error, LifecycleError)
                    or error.code != "oidc_signing_key_unknown"
                ):
                    break
        if (
            isinstance(last_error, LifecycleError)
            and last_error.code == "oidc_dependency_unavailable"
        ):
            raise last_error
        raise LifecycleError(error_code, "OIDC signed token verification failed") from last_error

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
            if force_refresh:
                last_refresh = self._jwks_last_forced_refresh.get(config.provider)
                if (
                    cached is not None
                    and last_refresh is not None
                    and now - last_refresh < timedelta(seconds=5)
                ):
                    return cached[1]
                self._jwks_last_forced_refresh[config.provider] = now
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
    def _decode_signed_token(
        config: OidcProviderConfig,
        id_token: str,
        keys: list[dict[str, object]],
        *,
        required: tuple[str, ...],
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
        if not candidates:
            raise LifecycleError("oidc_signing_key_unknown", "OIDC signing key is unknown")
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
                "require": list(required),
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
        return cast(dict[str, object], claims)

    def _require_link_target_current(
        self, transaction: _ConsumedTransaction, *, recent: bool = True
    ) -> None:
        if transaction.target_user_id is None or transaction.target_security_version is None:
            raise LifecycleError("oidc_transaction_invalid", "OIDC link target is invalid")
        with self._session_factory() as db:
            user = db.get(GlobalUser, transaction.target_user_id)
            local = (
                db.get(AuthSessionRecord, transaction.target_session_id)
                if transaction.target_session_id
                else None
            )
            if (
                local is None
                or local.revoked_at is not None
                or _comparable_time(local.expires_at) <= self._now()
                or local.user_id != transaction.target_user_id
                or (
                    recent
                    and self._now() - _comparable_time(local.created_at) > timedelta(minutes=5)
                )
                or user is None
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
