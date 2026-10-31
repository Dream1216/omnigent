from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import AuthSessionRecord, GlobalUser, OidcLoginTransaction
from saas.control_plane.lifecycle import MembershipLifecycleService
from tests.saas.test_oidc_http_auth import _Harness, _start
from tests.saas.test_oidc_http_auth import oidc_harness as oidc_harness


def _login(harness: _Harness) -> tuple[dict[str, str], str]:
    callback, _ = _start(harness, subject="entry-owner", email="owner@example.test")
    response = harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert response.status_code == 200
    return response.json(), str(harness.client.cookies.get("__Host-omnigent_saas_session"))


def _link(harness: _Harness, csrf: str) -> dict[str, str]:
    response = harness.client.post(
        "/saas/auth/oidc/test/link/start?return_to=/saas/account/identities&ui_locale=en-US",
        headers={
            "Origin": "https://testserver",
            "X-CSRF-Token": csrf,
            "Accept": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    return harness.provider.authorize(
        response.json()["authorization_url"],
        subject="entry-secondary",
        email="second@example.test",
    )


def test_public_options_are_local_controlled_paths_without_private_authority(
    oidc_harness: _Harness,
) -> None:
    response = oidc_harness.client.get("/saas/auth/options")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json() == {
        "mode": "dual",
        "password_enabled": True,
        "providers": [
            {
                "name": "test",
                "start_path": "/saas/auth/oidc/test/start",
                "signup_path": "/saas/auth/oidc/test/start?intent=signup",
                "link_path": "/saas/auth/oidc/test/link/start",
                "authorization_origin": "https://idp.example.test",
            }
        ],
    }
    assert "secret" not in response.text and "csrf" not in response.text
    assert oidc_harness.provider.jwks_request_count == 0


@pytest.mark.parametrize("change", ["logout", "old", "retained_legacy"])
def test_link_refuses_a_revoked_old_or_unbound_local_session(
    oidc_harness: _Harness,
    change: str,
) -> None:
    login, token = _login(oidc_harness)
    callback = _link(oidc_harness, login["csrf_token"])
    if change == "logout":
        MembershipLifecycleService(oidc_harness.sessions).revoke_auth_session(token)
    else:
        with oidc_harness.sessions.begin() as db:
            if change == "old":
                db.execute(
                    sa.update(AuthSessionRecord).values(
                        created_at=datetime.now(timezone.utc) - timedelta(minutes=6)
                    )
                )
            else:
                db.execute(
                    sa.update(OidcLoginTransaction)
                    .where(OidcLoginTransaction.purpose == "link")
                    .values(target_session_id=None)
                )
    result = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "authorization_snapshot_stale"
    assert len(oidc_harness.identities.list_identities(UUID(login["user_id"]))) == 1


def test_link_rechecks_local_session_inside_the_mapping_transaction(
    oidc_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login, token = _login(oidc_harness)
    callback = _link(oidc_harness, login["csrf_token"])
    original = oidc_harness.oidc._require_link_target_current

    def revoke_after_check(transaction, **kwargs):
        original(transaction, **kwargs)
        MembershipLifecycleService(oidc_harness.sessions).revoke_auth_session(token)

    monkeypatch.setattr(oidc_harness.oidc, "_require_link_target_current", revoke_after_check)
    result = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "recent_authentication_required"


@pytest.mark.parametrize("purpose", ["link", "reauth"])
def test_callback_cannot_issue_a_session_after_its_parent_logs_out(
    oidc_harness: _Harness, monkeypatch: pytest.MonkeyPatch, purpose: str
) -> None:
    login, token = _login(oidc_harness)
    if purpose == "link":
        callback = _link(oidc_harness, login["csrf_token"])
    else:
        response = oidc_harness.client.get(
            "/saas/auth/oidc/test/start?reauthenticate=true", follow_redirects=False
        )
        assert response.status_code == 302
        callback = oidc_harness.provider.authorize(
            response.headers["location"], subject="entry-owner", email="owner@example.test"
        )
    original = MembershipLifecycleService.issue_auth_session

    def revoke_before_issue(self, **kwargs):
        self.revoke_auth_session(token)
        return original(self, **kwargs)

    monkeypatch.setattr(MembershipLifecycleService, "issue_auth_session", revoke_before_issue)
    response = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "authorization_snapshot_stale"
    with oidc_harness.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(AuthSessionRecord)) == 1


@pytest.mark.parametrize(
    "subject,auth_time,expected",
    [("entry-owner", None, 200), ("other-account", None, 400), ("entry-owner", 1, 400)],
)
def test_reauthentication_proves_freshness_and_the_current_identity(
    oidc_harness: _Harness,
    subject: str,
    auth_time: int | None,
    expected: int,
) -> None:
    _login(oidc_harness)
    with oidc_harness.sessions.begin() as db:
        db.execute(
            sa.update(AuthSessionRecord).values(
                created_at=datetime.now(timezone.utc) - timedelta(minutes=10)
            )
        )
    started = oidc_harness.client.get(
        "/saas/auth/oidc/test/start?reauthenticate=true&return_to=/saas/account/identities&ui_locale=en-US",
        follow_redirects=False,
    )
    assert started.status_code == 302
    query = parse_qs(urlsplit(started.headers["location"]).query)
    assert query["prompt"] == ["login"] and query["max_age"] == ["0"]
    callback = oidc_harness.provider.authorize(
        started.headers["location"],
        subject=subject,
        email="owner@example.test",
        claim_overrides={} if auth_time is None else {"auth_time": auth_time},
    )
    result = oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback)
    assert result.status_code == expected
    if expected == 200:
        assert result.json()["purpose"] == "reauth"
    else:
        assert result.json()["error"]["code"] in {
            "reauthentication_identity_mismatch",
            "oidc_recent_authentication_required",
        }
    with oidc_harness.sessions() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(GlobalUser)) == 1


def test_provider_outage_returns_localized_retry_without_disabling_an_existing_session(
    oidc_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _login(oidc_harness)
    callback, _ = _start(
        oidc_harness, subject="entry-owner", email="owner@example.test", ui_locale="en-US"
    )

    def unavailable(request: httpx.Request):
        raise httpx.ConnectError("isolated provider is offline", request=request)

    monkeypatch.setattr(oidc_harness.oidc, "_http_transport", httpx.MockTransport(unavailable))
    result = oidc_harness.client.get(
        "/saas/auth/oidc/test/callback", params=callback, headers={"Accept": "text/html"}
    )
    assert result.status_code == 503
    assert '"ui_locale": "en-US"' in result.text
    assert result.headers["referrer-policy"] == "no-referrer"
    assert oidc_harness.client.get("/saas/identities").status_code == 200


def test_conflict_list_discloses_only_the_authenticated_candidate(oidc_harness: _Harness) -> None:
    login, _ = _login(oidc_harness)
    callback, _ = _start(oidc_harness, subject="conflicting", email="owner@example.test")
    assert (
        oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback).status_code
        == 409
    )
    owned = oidc_harness.client.get("/saas/auth/identity-conflicts")
    assert owned.status_code == 200 and len(owned.json()) == 1
    assert set(owned.json()[0]) == {"id", "provider", "email", "display_name", "review_status"}
    callback, _ = _start(oidc_harness, subject="another-user", email="another@example.test")
    assert (
        oidc_harness.client.get("/saas/auth/oidc/test/callback", params=callback).status_code
        == 200
    )
    denied = oidc_harness.client.get(
        "/saas/auth/identity-conflicts", params={"user_id": login["user_id"]}
    )
    assert denied.status_code == 200 and denied.json() == []


def test_casdoor_mode_rejects_local_password_before_authentication(
    oidc_harness: _Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from saas.control_plane import (
        RuntimeCompatibilityPolicy,
        SaasCookieConfig,
        SqlAlchemyContextResolver,
        create_saas_http_integration,
    )
    from saas.control_plane.client_network import (
        TrustedClientNetworkConfig,
        TrustedClientNetworkResolver,
    )
    from saas.control_plane.onboarding import SelfServiceOnboardingService
    from saas.control_plane.onboarding_status import OnboardingStatusService

    def unexpected_password(*args, **kwargs):
        raise AssertionError("local password authentication must not run")

    monkeypatch.setattr(oidc_harness.passwords, "authenticate", unexpected_password)
    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"test"}),
        allowed_source_revisions=frozenset({"source"}),
        allowed_schema_revisions=frozenset({"schema"}),
        adapter_contract_version="test",
    )
    onboarding = Mock(spec=SelfServiceOnboardingService)
    integration = create_saas_http_integration(
        lifecycle=MembershipLifecycleService(oidc_harness.sessions),
        identities=oidc_harness.identities,
        passwords=oidc_harness.passwords,
        oidc=oidc_harness.oidc,
        context_resolver=SqlAlchemyContextResolver(oidc_harness.sessions, policy),
        cookie_config=SaasCookieConfig(trusted_origins=frozenset({"https://testserver"})),
        auth_mode="casdoor",
        onboarding=onboarding,
        onboarding_status=Mock(spec=OnboardingStatusService),
        onboarding_client_network=TrustedClientNetworkResolver(TrustedClientNetworkConfig()),
    )
    app = FastAPI()
    router, prefix, tags = integration.extra_router
    app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    with TestClient(app, base_url="https://testserver", client=("198.51.100.77", 50443)) as client:
        assert client.get("/saas/auth/options").json()["password_enabled"] is False
        response = client.post(
            "/saas/auth/login",
            json={"email": "owner@example.test", "password": "a-valid-old-password"},
        )
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "identity_provider_required"
        assert client.cookies.get("__Host-omnigent_saas_session") is None
        registration = client.post(
            "/saas/onboarding/registrations",
            headers={"Origin": "https://testserver", "Idempotency-Key": "disabled-signup"},
            json={
                "email": "owner@example.test",
                "display_name": "Owner",
                "tenant_name": "Legacy organization",
                "tenant_slug": "legacy-organization",
                "default_space_name": "Default",
                "default_space_slug": "default",
                "plan_key": "starter",
                "home_region": "cn-east-1",
            },
        )
        assert registration.status_code == 409
        assert registration.json()["detail"]["code"] == "identity_provider_required"
        onboarding.request_registration.assert_not_called()
