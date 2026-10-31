from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import jwt
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import AuthSessionRecord, OidcSessionFence
from saas.control_plane.lifecycle import LifecycleError, MembershipLifecycleService
from tests.saas.test_oidc_http_auth import (
    _CLIENT_ID,
    _ISSUER,
    _Harness,
    _start,
)
from tests.saas.test_oidc_http_auth import (
    oidc_harness as oidc_harness,
)


def _token(
    harness: _Harness,
    *,
    subject: str | None = "logout-user",
    sid: str | None = None,
    overrides: dict[str, object] | None = None,
    algorithm: str = "RS256",
    omitted: tuple[str, ...] = (),
) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid4()),
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }
    if subject is not None:
        claims["sub"] = subject
    if sid is not None:
        claims["sid"] = sid
    claims.update(overrides or {})
    for claim in omitted:
        claims.pop(claim, None)
    key = (
        harness.provider._keys[harness.provider._key_index]
        if algorithm == "RS256"
        else "untrusted-symmetric-secret-long-enough"
    )
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": harness.provider.key_id})


def _login(
    harness: _Harness, *, subject: str = "logout-user", sid: str | None = None
) -> tuple[UUID, str]:
    callback, _ = _start(
        harness,
        subject=subject,
        email=f"{subject}@example.com",
        claim_overrides={} if sid is None else {"sid": sid},
    )
    result = harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert result.status_code == 200
    return UUID(result.json()["user_id"]), str(
        harness.client.cookies.get("__Host-omnigent_saas_session")
    )


def test_verified_logout_revokes_only_external_identity_and_is_durable_idempotent(
    oidc_harness: _Harness,
) -> None:
    user, first = _login(oidc_harness)
    _, second = _login(oidc_harness)
    _, unrelated = _login(oidc_harness, subject="unrelated")
    lifecycle = MembershipLifecycleService(oidc_harness.sessions)
    legacy = lifecycle.issue_auth_session(
        user_id=user,
        authn_method="password",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    token = _token(oidc_harness)
    for _ in range(2):
        response = oidc_harness.client.post(
            "/saas/auth/oidc/test/backchannel-logout", data={"logout_token": token}
        )
        assert response.status_code == 200
        assert response.headers["cache-control"] == "private, no-store"
    for local in (first, second):
        with pytest.raises(LifecycleError, match="session is invalid"):
            lifecycle.validate_auth_session(local)
    lifecycle.validate_auth_session(unrelated)
    lifecycle.validate_auth_session(legacy.token)
    with oidc_harness.sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(OidcSessionFence)
                .where(OidcSessionFence.kind == "event")
            )
            == 1
        )
        row = db.scalar(
            sa.select(AuthSessionRecord)
            .where(
                AuthSessionRecord.user_id == user, AuthSessionRecord.external_provider.is_not(None)
            )
            .limit(1)
        )
        assert row is not None and row.external_issuer == _ISSUER
        assert row.external_subject == "logout-user"


@pytest.mark.parametrize(
    "subject,sid,revoked",
    [
        (None, "sid-a", [True, False, False]),
        ("logout-user", "sid-a", [True, False, True]),
        ("logout-user", None, [True, True, True]),
    ],
)
def test_sid_and_sub_scope_including_provider_tokens_without_sid(
    oidc_harness: _Harness, subject: str | None, sid: str | None, revoked: list[bool]
) -> None:
    sessions = [_login(oidc_harness, sid=value)[1] for value in ("sid-a", "sid-b", None)]
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, subject=subject, sid=sid)},
    )
    assert response.status_code == 200
    lifecycle = MembershipLifecycleService(oidc_harness.sessions)
    for token, should_revoke in zip(sessions, revoked, strict=True):
        if should_revoke:
            with pytest.raises(LifecycleError):
                lifecycle.validate_auth_session(token)
        else:
            lifecycle.validate_auth_session(token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.test"},
        {"aud": "other-client"},
        {"aud": [_CLIENT_ID, "other-client"]},
        {"events": {}},
        {"events": {"http://schemas.openid.net/event/backchannel-logout": "logout"}},
        {"nonce": "id-token-nonce"},
        {"iat": 1},
        {"iat": True},
        {"iat": 4_102_444_800},
        {"exp": 1},
        {"exp": None},
        {"jti": ""},
        {"sub": None},
        {"sid": ""},
    ],
)
def test_invalid_signed_logout_does_not_change_any_session(
    oidc_harness: _Harness, overrides: dict[str, object]
) -> None:
    _, local = _login(oidc_harness)
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, overrides=overrides)},
    )
    assert response.status_code == 400
    MembershipLifecycleService(oidc_harness.sessions).validate_auth_session(local)
    with oidc_harness.sessions() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count())
                .select_from(OidcSessionFence)
                .where(OidcSessionFence.kind == "event")
            )
            == 0
        )


def test_algorithm_downgrade_never_fetches_keys_or_revokes(oidc_harness: _Harness) -> None:
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, algorithm="HS256")},
    )
    assert response.status_code == 400
    assert oidc_harness.provider.jwks_request_count == 0


def test_login_token_is_not_a_logout_token(oidc_harness: _Harness) -> None:
    token = _token(oidc_harness, overrides={"nonce": "login-nonce", "owner": "stbz-users"})
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout", data={"logout_token": token}
    )
    assert response.status_code == 400


def test_form_encoding_and_duplicate_tokens_are_rejected(oidc_harness: _Harness) -> None:
    token = _token(oidc_harness)
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout", json={"logout_token": token}
    )
    assert response.status_code == 400
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        content=f"logout_token={token}&logout_token={token}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400


def test_local_revocation_precedes_the_fixed_idp_logout_handoff(oidc_harness: _Harness) -> None:
    _, local = _login(oidc_harness)
    key_requests = oidc_harness.provider.jwks_request_count
    response = oidc_harness.client.post(
        "/saas/auth/logout?return_to=https://attacker.test",
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 200
    redirect = urlsplit(response.json()["logout_url"])
    assert redirect.scheme == "https" and redirect.netloc == "idp.example.test"
    assert parse_qs(redirect.query) == {
        "client_id": [_CLIENT_ID],
        "post_logout_redirect_uri": ["https://testserver/saas/login"],
    }
    assert oidc_harness.client.cookies.get("__Host-omnigent_saas_session") is None
    assert oidc_harness.provider.jwks_request_count == key_requests
    with pytest.raises(LifecycleError):
        MembershipLifecycleService(oidc_harness.sessions).validate_auth_session(local)
    oidc_harness.client.cookies.set("__Host-omnigent_saas_session", local)
    retry = oidc_harness.client.post("/saas/auth/logout", headers={"Origin": "https://testserver"})
    assert retry.status_code == 204


@pytest.mark.parametrize("browser", [False, True])
def test_logout_fence_rejects_a_late_callback_with_a_retryable_response(
    oidc_harness: _Harness, browser: bool
) -> None:
    epoch = int(datetime.now(timezone.utc).timestamp())
    callback, _ = _start(
        oidc_harness,
        subject="logout-user",
        email="logout-user@example.com",
        claim_overrides={"iat": epoch},
        ui_locale="en-US",
    )
    logout = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, overrides={"iat": epoch})},
    )
    assert logout.status_code == 200
    response = oidc_harness.client.get(
        "/saas/auth/oidc/test/callback",
        params=callback,
        headers={"Accept": "text/html" if browser else "application/json"},
    )
    assert response.status_code == 400
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert oidc_harness.client.cookies.get("__Host-omnigent_saas_session") is None
    assert not any("_oidc_" in cookie.name for cookie in oidc_harness.client.cookies.jar)
    if browser:
        assert response.headers["content-type"].startswith("text/html")
        if "__NEXT_DATA__" in response.text:
            assert '"ui_locale": "en-US"' in response.text
            assert '"error_code": "oidc_session_ended"' in response.text
        else:
            assert '<html lang="en-US">' in response.text
            assert '<a href="/saas/login">Try signing in again</a>' in response.text
    else:
        assert response.json()["error"]["code"] == "oidc_session_ended"

    newer, _ = _start(
        oidc_harness,
        subject="logout-user",
        email="logout-user@example.com",
        claim_overrides={"iat": epoch + 1},
    )
    assert (
        oidc_harness.client.get("/saas/auth/oidc/test/callback", params=newer).status_code == 200
    )


def test_logout_requires_exp_and_rejects_reused_event_with_different_identity(
    oidc_harness: _Harness,
) -> None:
    _, local = _login(oidc_harness, subject="unrelated")
    response = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, omitted=("exp",))},
    )
    assert response.status_code == 400
    event = {"jti": "one-immutable-event"}
    first = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, overrides=event)},
    )
    assert first.status_code == 200
    forged = oidc_harness.client.post(
        "/saas/auth/oidc/test/backchannel-logout",
        data={"logout_token": _token(oidc_harness, subject="unrelated", overrides=event)},
    )
    assert forged.status_code == 400
    MembershipLifecycleService(oidc_harness.sessions).validate_auth_session(local)
