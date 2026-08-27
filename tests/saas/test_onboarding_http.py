from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.client_network import (
    TrustedClientNetworkConfig,
    TrustedClientNetworkResolver,
)
from saas.control_plane.db_models import (
    GlobalUser,
    RuntimePlacementRecord,
    SaasBase,
    Tenant,
    TenantMembership,
)
from saas.control_plane.http_auth import SaasCookieConfig, create_saas_http_integration
from saas.control_plane.identity import IdentityManagementService, PasswordCredentialService
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.onboarding import (
    EmailVerificationMessage,
    OnboardingError,
    OnboardingOutboxPublisher,
    OnboardingPlan,
    OnboardingPolicy,
    RegistrationRateLimitDecision,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_models import (
    SelfServiceRegistrationRecord,
    TenantOnboardingRecord,
)
from saas.control_plane.onboarding_status import OnboardingStatusService
from saas.control_plane.outbox import OutboxDispatcher
from saas.control_plane.resolver import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver

TRUSTED_ORIGIN = "http://testserver"
EVIL_ORIGIN = "https://attacker.example"
PASSWORD = "correct-horse-battery-staple"


class _AllowAllRateLimiter:
    def consume(
        self,
        db: Session,
        *,
        action: str,
        subject_kind: str,
        subject: str,
    ) -> RegistrationRateLimitDecision:
        del db, action, subject_kind, subject
        return RegistrationRateLimitDecision(
            allowed=True,
            retry_after_seconds=0,
            remaining=100,
            policy_revision="onboarding-http-test",
        )

    def require(self, *, action: str, subject_kind: str, subject: str) -> None:
        del action, subject_kind, subject


class _NetworkAwareOnboardingService(SelfServiceOnboardingService):
    network_calls: list[tuple[str, str]]
    network_error: OnboardingError | None

    def require_network_rate_limit(self, action: str, subject: str) -> None:
        self.network_calls.append((action, subject))
        if self.network_error is not None:
            raise self.network_error


class _RecordingEmailSender:
    def __init__(self) -> None:
        self.deliveries: list[tuple[UUID, EmailVerificationMessage]] = []

    def send_verification(self, *, event_id: UUID, message: EmailVerificationMessage) -> None:
        self.deliveries.append((event_id, message))


@dataclass(frozen=True, slots=True)
class _HttpHarness:
    client: TestClient
    sessions: sessionmaker[Session]
    sender: _RecordingEmailSender
    dispatcher: OutboxDispatcher
    onboarding: _NetworkAwareOnboardingService


def _http_harness(
    *,
    client_network: TrustedClientNetworkResolver | None = None,
    omit_client_network: bool = False,
    configure_onboarding: bool = True,
) -> Generator[_HttpHarness, None, None]:
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    lifecycle = MembershipLifecycleService(sessions)
    identities = IdentityManagementService(sessions)
    passwords = PasswordCredentialService(sessions)
    policy = OnboardingPolicy(
        plans=(
            OnboardingPlan(
                key="starter",
                policy_revision="starter-2026-08-10",
                trial_days=14,
            ),
        ),
        home_regions=frozenset({"cn-east-1"}),
        reserved_slugs=frozenset({"admin", "platform"}),
        verification_ttl=timedelta(minutes=30),
    )
    envelopes = VerificationEnvelopeKeyring(
        active_key_id="http-test-v1",
        keys={"http-test-v1": b"onboarding-http-envelope-key-001"},
    )
    onboarding = _NetworkAwareOnboardingService(
        sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
    onboarding.network_calls = []
    onboarding.network_error = None
    coordinator = TenantOnboardingCoordinator(sessions, policy=policy)
    sender = _RecordingEmailSender()
    dispatcher = OutboxDispatcher(
        sessions,
        OnboardingOutboxPublisher(
            registrations=onboarding,
            coordinator=coordinator,
            envelopes=envelopes,
            email_sender=sender,
        ),
    )
    resolver = SqlAlchemyContextResolver(
        sessions,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"onboarding-http-test"}),
            allowed_schema_revisions=frozenset({"onboarding-http-test"}),
            adapter_contract_version="0.2.0",
        ),
    )
    try:
        effective_client_network = client_network or TrustedClientNetworkResolver(
            TrustedClientNetworkConfig()
        )
        integration = create_saas_http_integration(
            lifecycle=lifecycle,
            identities=identities,
            passwords=passwords,
            context_resolver=resolver,
            cookie_config=SaasCookieConfig(
                name="saas_session",
                secure=False,
                trusted_origins=frozenset({TRUSTED_ORIGIN}),
            ),
            onboarding=onboarding if configure_onboarding else None,
            onboarding_status=(
                OnboardingStatusService(sessions) if configure_onboarding else None
            ),
            onboarding_client_network=(None if omit_client_network else effective_client_network),
        )
        app = FastAPI()
        router, prefix, tags = integration.extra_router
        app.include_router(router, prefix=prefix, tags=tags)
        integration.install_middleware(app)
        with TestClient(
            app,
            base_url=TRUSTED_ORIGIN,
            client=("198.51.100.77", 50443),
        ) as client:
            yield _HttpHarness(
                client=client,
                sessions=sessions,
                sender=sender,
                dispatcher=dispatcher,
                onboarding=onboarding,
            )
    finally:
        SaasBase.metadata.drop_all(engine)
        engine.dispose()


def _registration_body(suffix: str) -> dict[str, object]:
    return {
        "email": f"owner-{suffix}@example.com",
        "display_name": "Example Owner",
        "tenant_name": f"Example Tenant {suffix}",
        "tenant_slug": f"example-{suffix}",
        "default_space_name": "Default Space",
        "default_space_slug": "default",
        "plan_key": "starter",
        "home_region": "cn-east-1",
    }


def _post_headers(idempotency_key: str, *, origin: str = TRUSTED_ORIGIN) -> dict[str, str]:
    return {"Idempotency-Key": idempotency_key, "Origin": origin}


def _network_error(
    code: str,
    message: str,
    *,
    retry_after_seconds: object | None = None,
) -> OnboardingError:
    error = OnboardingError(code, message)
    if retry_after_seconds is not None:
        object.__setattr__(error, "retry_after_seconds", retry_after_seconds)
    return error


def _assert_secret_free(response_body: object, *, forbidden_values: tuple[str, ...]) -> None:
    keys: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                keys.append(str(key).casefold())
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(response_body)
    assert not any(
        sensitive in key for key in keys for sensitive in ("email", "token", "password")
    )
    serialized = str(response_body)
    assert all(secret not in serialized for secret in forbidden_values)


def _verify_start_and_login(
    harness: _HttpHarness, *, suffix: str
) -> tuple[UUID, UUID, dict[str, object]]:
    body = _registration_body(suffix)
    requested = harness.client.post(
        "/saas/onboarding/registrations",
        headers=_post_headers(f"status-registration-{suffix}"),
        json=body,
    )
    assert requested.status_code == 202
    registration_id = UUID(requested.json()["registration_id"])
    assert harness.dispatcher.dispatch_once().published == 1
    verification_token = harness.sender.deliveries[-1][1].verification_token
    verified = harness.client.post(
        f"/saas/onboarding/registrations/{registration_id}/verify",
        headers=_post_headers(f"status-verification-{suffix}"),
        json={"verification_token": verification_token, "password": PASSWORD},
    )
    assert verified.status_code == 202
    assert harness.dispatcher.dispatch_once().published == 1
    user_id = UUID(verified.json()["user_id"])
    onboarding_id = UUID(verified.json()["onboarding_id"])
    login = harness.client.post(
        "/saas/auth/login",
        headers={"Origin": TRUSTED_ORIGIN},
        json={"email": body["email"], "password": PASSWORD},
    )
    assert login.status_code == 200
    return user_id, onboarding_id, body


def test_only_the_three_exact_post_paths_are_public_and_origin_guarded() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        registration_id = uuid4()
        exact_requests = (
            (
                "/saas/onboarding/registrations",
                _registration_body("evil-origin"),
            ),
            (
                f"/saas/onboarding/registrations/{registration_id}/resend",
                {"email": "owner-evil-origin@example.com"},
            ),
            (
                f"/saas/onboarding/registrations/{registration_id}/verify",
                {"verification_token": "opaque", "password": PASSWORD},
            ),
        )
        for index, (path, body) in enumerate(exact_requests):
            blocked = harness.client.post(
                path,
                headers=_post_headers(f"evil-origin-{index}", origin=EVIL_ORIGIN),
                json=body,
            )
            assert blocked.status_code == 403
            assert blocked.json()["error"]["code"] == "origin_forbidden"

        exact_paths = (
            "/saas/onboarding/registrations",
            f"/saas/onboarding/registrations/{registration_id}/resend",
            f"/saas/onboarding/registrations/{registration_id}/verify",
        )
        for path in exact_paths:
            not_public_get = harness.client.get(path, headers={"Origin": EVIL_ORIGIN})
            assert not_public_get.status_code == 405

        adjacent_paths = (
            "/saas/onboarding/registration",
            f"/saas/onboarding/registrations/{registration_id}/resends",
            f"/saas/onboarding/registrations/{registration_id}/verify/extra",
        )
        for path in adjacent_paths:
            not_public_post = harness.client.post(
                path,
                headers=_post_headers("adjacent", origin=EVIL_ORIGIN),
                json={},
            )
            assert not_public_post.status_code == 404
        assert harness.onboarding.network_calls == []
    finally:
        harness_iterator.close()


@pytest.mark.parametrize(
    ("path", "action"),
    (
        ("/saas/onboarding/registrations", "registration.request"),
        (
            "/saas/onboarding/registrations/00000000-0000-4000-8000-000000000001/resend",
            "registration.resend",
        ),
        (
            "/saas/onboarding/registrations/00000000-0000-4000-8000-000000000002/verify",
            "registration.verify",
        ),
    ),
)
def test_network_gate_runs_before_json_and_body_validation(path: str, action: str) -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        invalid_json = harness.client.post(
            path,
            headers={
                **_post_headers(f"invalid-json-{action}"),
                "Content-Type": "application/json",
            },
            content=b"{",
        )

        assert invalid_json.status_code == 422
        assert harness.onboarding.network_calls == [
            (action, "client-network:ipv4:198.51.100.0/24")
        ]
    finally:
        harness_iterator.close()


@pytest.mark.parametrize("operation", ("resend", "verify"))
def test_network_gate_runs_before_path_uuid_validation(operation: str) -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        body = (
            {"email": "invalid-path@example.com"}
            if operation == "resend"
            else {"verification_token": "opaque", "password": PASSWORD}
        )
        invalid_uuid = harness.client.post(
            f"/saas/onboarding/registrations/not-a-uuid/{operation}",
            headers=_post_headers(f"invalid-uuid-{operation}"),
            json=body,
        )

        assert invalid_uuid.status_code == 422
        assert harness.onboarding.network_calls == [
            (
                f"registration.{operation}",
                "client-network:ipv4:198.51.100.0/24",
            )
        ]
    finally:
        harness_iterator.close()


def test_untrusted_peer_cannot_spoof_the_network_subject() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        accepted = harness.client.post(
            "/saas/onboarding/registrations",
            headers={
                **_post_headers("spoofed-forwarding-header"),
                "X-Forwarded-For": "203.0.113.99",
            },
            json=_registration_body("spoofed-forwarding-header"),
        )

        assert accepted.status_code == 202
        assert harness.onboarding.network_calls == [
            ("registration.request", "client-network:ipv4:198.51.100.0/24")
        ]
    finally:
        harness_iterator.close()


def test_unresolvable_trusted_proxy_subject_fails_generic_before_body_parsing() -> None:
    client_network = TrustedClientNetworkResolver(
        TrustedClientNetworkConfig(trusted_proxy_cidrs=("198.51.100.0/24",))
    )
    harness_iterator = _http_harness(client_network=client_network)
    harness = next(harness_iterator)
    try:
        raw_forwarding_value = "not-a-public-network-subject"
        unavailable = harness.client.post(
            "/saas/onboarding/registrations",
            headers={
                **_post_headers("resolver-unavailable"),
                "Content-Type": "application/json",
                "X-Forwarded-For": raw_forwarding_value,
            },
            content=b"{",
        )

        assert unavailable.status_code == 503
        assert unavailable.headers["Cache-Control"] == "no-store"
        assert unavailable.json() == {
            "detail": {
                "code": "registration_rate_limit_unavailable",
                "message": "registration abuse protection is unavailable",
            }
        }
        assert raw_forwarding_value not in unavailable.text
        assert harness.onboarding.network_calls == []
    finally:
        harness_iterator.close()


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    ((None, "1"), (0, "1"), (37, "37"), (999_999, "86400"), ("45", "1")),
)
def test_network_rate_limit_is_generic_and_retry_after_is_bounded(
    retry_after: object | None,
    expected: str,
) -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        leaked_message = "registration.request client-network:ipv4:198.51.100.0/24"
        harness.onboarding.network_error = _network_error(
            "registration_rate_limited",
            leaked_message,
            retry_after_seconds=retry_after,
        )
        denied = harness.client.post(
            "/saas/onboarding/registrations",
            headers={
                **_post_headers("network-rate-limited"),
                "Content-Type": "application/json",
            },
            content=b"{",
        )

        assert denied.status_code == 429
        assert denied.headers["Cache-Control"] == "no-store"
        assert denied.headers["Retry-After"] == expected
        assert denied.json() == {
            "detail": {
                "code": "registration_rate_limited",
                "message": "registration request rate limit exceeded",
            }
        }
        assert leaked_message not in denied.text
    finally:
        harness_iterator.close()


def test_onboarding_http_dependencies_are_all_or_none() -> None:
    missing_network = _http_harness(omit_client_network=True)
    with pytest.raises(ValueError, match="trusted client network"):
        next(missing_network)

    resolver_without_onboarding = _http_harness(configure_onboarding=False)
    with pytest.raises(ValueError, match="trusted client network"):
        next(resolver_without_onboarding)


def test_registration_requires_idempotency_and_rejects_extra_fields() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        body = _registration_body("validation")
        missing_key = harness.client.post(
            "/saas/onboarding/registrations",
            headers={"Origin": TRUSTED_ORIGIN},
            json=body,
        )
        assert missing_key.status_code == 422
        assert harness.onboarding.network_calls == [
            ("registration.request", "client-network:ipv4:198.51.100.0/24")
        ]

        extra_field = harness.client.post(
            "/saas/onboarding/registrations",
            headers=_post_headers("registration-extra-field"),
            json={**body, "verification_token": "must-not-be-accepted"},
        )
        assert extra_field.status_code == 422
        assert extra_field.json()["detail"][0]["type"] == "extra_forbidden"
        assert harness.onboarding.network_calls == [
            ("registration.request", "client-network:ipv4:198.51.100.0/24"),
            ("registration.request", "client-network:ipv4:198.51.100.0/24"),
        ]
    finally:
        harness_iterator.close()


def test_registration_and_resend_are_no_store_and_secret_free() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        body = _registration_body("resend")
        requested = harness.client.post(
            "/saas/onboarding/registrations",
            headers=_post_headers("registration-resend-http"),
            json=body,
        )
        assert requested.status_code == 202
        assert requested.headers["Cache-Control"] == "no-store"
        assert set(requested.json()) == {"registration_id", "status"}
        _assert_secret_free(requested.json(), forbidden_values=(str(body["email"]), PASSWORD))
        registration_id = UUID(requested.json()["registration_id"])

        dispatched = harness.dispatcher.dispatch_once()
        assert (dispatched.claimed, dispatched.published, dispatched.failed) == (1, 1, 0)
        assert len(harness.sender.deliveries) == 1
        first_token = harness.sender.deliveries[0][1].verification_token

        resent = harness.client.post(
            f"/saas/onboarding/registrations/{registration_id}/resend",
            headers=_post_headers("resend-http"),
            json={"email": body["email"]},
        )
        assert resent.status_code == 202
        assert resent.headers["Cache-Control"] == "no-store"
        assert set(resent.json()) == {"registration_id", "status"}
        assert resent.json()["registration_id"] == str(registration_id)
        _assert_secret_free(
            resent.json(),
            forbidden_values=(str(body["email"]), first_token, PASSWORD),
        )
    finally:
        harness_iterator.close()


def test_existing_password_email_and_new_email_have_identical_anonymous_responses() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        existing_body = _registration_body("enumeration-existing")
        new_body = _registration_body("enumeration-new")
        existing_email = str(existing_body["email"])
        new_email = str(new_body["email"])
        existing_user_id = uuid4()
        with harness.sessions.begin() as db:
            db.add(
                GlobalUser(
                    id=existing_user_id,
                    status="active",
                    primary_email_normalized=existing_email,
                    security_version=1,
                )
            )
        PasswordCredentialService(harness.sessions).set_password(
            user_id=existing_user_id,
            new_password=PASSWORD,
            idempotency_key="enumeration-existing-password",
        )

        responses = []
        registration_ids: list[str] = []
        for suffix, body in (("existing", existing_body), ("new", new_body)):
            requested = harness.client.post(
                "/saas/onboarding/registrations",
                headers=_post_headers(f"enumeration-registration-{suffix}"),
                json=body,
            )
            cohort_responses = [requested]
            registration_id = requested.json()["registration_id"]
            registration_ids.append(registration_id)
            for _ in range(2):
                cohort_responses.append(
                    harness.client.post(
                        f"/saas/onboarding/registrations/{registration_id}/resend",
                        headers=_post_headers("enumeration-resend-same-key"),
                        json={"email": body["email"]},
                    )
                )
            assert {response.json()["registration_id"] for response in cohort_responses} == {
                registration_id
            }
            responses.extend(cohort_responses)

        assert registration_ids[0] != registration_ids[1]
        with harness.sessions() as db:
            internal_statuses: list[str] = []
            for registration_id in registration_ids:
                registration = db.get(SelfServiceRegistrationRecord, UUID(registration_id))
                assert registration is not None
                internal_statuses.append(registration.status)
        assert internal_statuses == ["suppressed", "pending_verification"]
        response_contracts = {
            (response.status_code, frozenset(response.json()), response.json().get("status"))
            for response in responses
        }
        assert response_contracts == {
            (202, frozenset({"registration_id", "status"}), "verification_pending")
        }
        for response in responses:
            payload = response.json()
            assert response.headers["Cache-Control"] == "no-store"
            assert not {
                "replay",
                "replayed",
                "expires_at",
                "email",
                "email_normalized",
                "email_hash",
                "suppressed",
                "existing_identity",
                "challenge_generation",
                "delivery_status",
                "terminal_at",
            }.intersection(payload)
            _assert_secret_free(
                payload,
                forbidden_values=(existing_email, new_email, PASSWORD),
            )
    finally:
        harness_iterator.close()


def test_verification_returns_tenant_provisioning_and_enables_password_login() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        body = _registration_body("verify")
        requested = harness.client.post(
            "/saas/onboarding/registrations",
            headers=_post_headers("registration-verify-http"),
            json=body,
        )
        assert requested.status_code == 202
        registration_id = UUID(requested.json()["registration_id"])

        login_before_verification = harness.client.post(
            "/saas/auth/login",
            headers={"Origin": TRUSTED_ORIGIN},
            json={"email": body["email"], "password": PASSWORD},
        )
        assert login_before_verification.status_code == 401
        assert login_before_verification.json()["detail"]["code"] == "invalid_credentials"

        dispatched = harness.dispatcher.dispatch_once()
        assert dispatched.published == 1
        assert len(harness.sender.deliveries) == 1
        verification_token = harness.sender.deliveries[0][1].verification_token

        verified = harness.client.post(
            f"/saas/onboarding/registrations/{registration_id}/verify",
            headers=_post_headers("verify-http"),
            json={"verification_token": verification_token, "password": PASSWORD},
        )
        assert verified.status_code == 202
        assert verified.headers["Cache-Control"] == "no-store"
        assert verified.json()["status"] == "tenant_provisioning"
        assert "replayed" not in verified.json()
        assert verified.json()["registration_id"] == str(registration_id)
        _assert_secret_free(
            verified.json(),
            forbidden_values=(str(body["email"]), verification_token, PASSWORD),
        )
        with harness.sessions() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(Tenant)) == 0

        login_after_verification = harness.client.post(
            "/saas/auth/login",
            headers={"Origin": TRUSTED_ORIGIN},
            json={"email": body["email"], "password": PASSWORD},
        )
        assert login_after_verification.status_code == 200
        assert login_after_verification.json()["user_id"] == verified.json()["user_id"]
    finally:
        harness_iterator.close()


def test_onboarding_status_requires_cookie_auth_and_rejects_bearer_session() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        _verify_start_and_login(harness, suffix="status-cookie")
        authenticated = harness.client.get("/saas/onboarding/status")
        assert authenticated.status_code == 200
        session_token = harness.client.cookies.get("saas_session")
        assert session_token

        ambiguous_bearer = harness.client.get(
            "/saas/onboarding/status",
            headers={"Authorization": f"Bearer {session_token}"},
        )
        assert ambiguous_bearer.status_code == 400

        for authorization in (f"bearer {session_token}", "Basic dXNlcjpwYXNz", ""):
            ambiguous = harness.client.get(
                "/saas/onboarding/status",
                headers={"Authorization": authorization},
            )
            assert ambiguous.status_code == 401
            assert ambiguous.json()["detail"]["code"] == "authentication_required"
            assert ambiguous.headers["Cache-Control"] == "private, no-store"

        harness.client.cookies.clear()
        unauthenticated = harness.client.get("/saas/onboarding/status")
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["detail"]["code"] == "authentication_required"
        assert unauthenticated.headers["Cache-Control"] == "private, no-store"

        bearer = harness.client.get(
            "/saas/onboarding/status",
            headers={"Authorization": f"Bearer {session_token}"},
        )
        assert bearer.status_code == 401
        assert bearer.json()["detail"]["code"] == "authentication_required"
        assert bearer.headers["Cache-Control"] == "private, no-store"
    finally:
        harness_iterator.close()


def test_onboarding_status_is_actor_scoped_and_missing_is_uniform() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        _verify_start_and_login(harness, suffix="status-owner")
        other_user_id = uuid4()
        other_email = "other-status-owner@example.com"
        with harness.sessions.begin() as db:
            db.add(
                GlobalUser(
                    id=other_user_id,
                    status="active",
                    primary_email_normalized=other_email,
                    security_version=1,
                )
            )
        PasswordCredentialService(harness.sessions).set_password(
            user_id=other_user_id,
            new_password=PASSWORD,
            idempotency_key="status-other-user-password",
        )
        harness.client.cookies.clear()
        login = harness.client.post(
            "/saas/auth/login",
            headers={"Origin": TRUSTED_ORIGIN},
            json={"email": other_email, "password": PASSWORD},
        )
        assert login.status_code == 200

        unavailable = harness.client.get("/saas/onboarding/status")
        assert unavailable.status_code == 404
        assert unavailable.json() == {
            "detail": {
                "code": "onboarding_status_unavailable",
                "message": "Onboarding status is unavailable",
            }
        }
        assert unavailable.headers["Cache-Control"] == "private, no-store"
    finally:
        harness_iterator.close()


def test_onboarding_status_maps_forward_stages_and_hides_ids_until_activation() -> None:
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        user_id, onboarding_id, _body = _verify_start_and_login(harness, suffix="status-forward")
        expected = (
            ("tenant_created", "provisioning", "billing"),
            ("billing_ready", "provisioning", "runtime"),
            ("runtime_ready", "provisioning", "project"),
            ("project_ready", "provisioning", "activation"),
            ("active", "ready_for_first_run", "first_run"),
        )
        placement_id = uuid4()
        for internal_status, public_state, public_stage in expected:
            if internal_status != "tenant_created":
                with harness.sessions.begin() as db:
                    saga = db.get(TenantOnboardingRecord, onboarding_id)
                    assert saga is not None and saga.user_id == user_id
                    occurred_at = saga.last_transition_at
                    if internal_status == "billing_ready":
                        saga.billing_ready_at = occurred_at
                    elif internal_status == "runtime_ready":
                        db.add(
                            RuntimePlacementRecord(
                                id=placement_id,
                                runtime_type="omnigent",
                                data_region="cn-east-1",
                                failure_domain="status-test-a",
                                database_cluster_ref="status-db",
                                object_store_ref="status-objects",
                                kms_key_ref="status-kms",
                                official_schema_revision="onboarding-http-test",
                                capacity_class="starter",
                                status="active",
                            )
                        )
                        saga.runtime_placement_id = placement_id
                        saga.runtime_target_snapshot = {"placement_id": str(placement_id)}
                        saga.runtime_request_hash = "a" * 64
                        saga.runtime_ready_at = occurred_at
                    elif internal_status == "project_ready":
                        saga.project_ready_at = occurred_at
                    elif internal_status == "active":
                        saga.trial_started_at = occurred_at
                        saga.trial_ends_at = occurred_at + timedelta(days=14)
                        saga.activated_at = occurred_at
                    saga.status = internal_status
                    saga.version += 1

            response = harness.client.get("/saas/onboarding/status")
            assert response.status_code == 200
            assert response.headers["Cache-Control"] == "private, no-store"
            payload = response.json()
            assert (payload["state"], payload["stage"]) == (public_state, public_stage)
            assert payload["can_start_first_run"] is (internal_status == "active")
            assert not {"user_id", "onboarding_id", "registration_id"} & set(payload)
            resource_keys = {"tenant_id", "space_id", "default_project_id"}
            if internal_status == "active":
                assert resource_keys <= set(payload)
                assert "trial_ends_at" in payload
            else:
                assert not resource_keys & set(payload)
                assert "trial_ends_at" not in payload

        with harness.sessions.begin() as db:
            saga = db.get(TenantOnboardingRecord, onboarding_id)
            assert saga is not None
            membership = db.get(TenantMembership, (saga.tenant_id, user_id))
            assert membership is not None
            membership.status = "removed"
            membership.version += 1
        removed = harness.client.get("/saas/onboarding/status")
        assert removed.status_code == 404
        assert removed.json()["detail"]["code"] == "onboarding_status_unavailable"
    finally:
        harness_iterator.close()


def test_onboarding_status_failure_projection_is_secret_free_and_support_reference_is_stable() -> (
    None
):
    harness_iterator = _http_harness()
    harness = next(harness_iterator)
    try:
        _user_id, onboarding_id, body = _verify_start_and_login(harness, suffix="status-support")
        provider_secret = "provider-secret-receipt-must-never-render"
        with harness.sessions.begin() as db:
            saga = db.get(TenantOnboardingRecord, onboarding_id)
            assert saga is not None
            saga.status = "compensating"
            saga.failure_stage = "tenant_created"
            saga.compensation_cursor = "billing"
            saga.last_error_code = "provider_internal_failure"
            saga.last_error_detail = provider_secret
            saga.version += 1

        recovering = harness.client.get("/saas/onboarding/status")
        assert recovering.status_code == 200
        assert recovering.json()["state"] == "recovering"
        assert recovering.json()["stage"] == "compensation"
        assert "support_reference" not in recovering.json()

        with harness.sessions.begin() as db:
            saga = db.get(TenantOnboardingRecord, onboarding_id)
            assert saga is not None
            saga.status = "manual_review"
            saga.version += 1
        manual_review = harness.client.get("/saas/onboarding/status")
        assert manual_review.status_code == 200
        payload = manual_review.json()
        assert payload["state"] == "support_required"
        assert payload["stage"] == "support"
        reference = payload["support_reference"]
        assert reference.startswith("ob-")
        assert str(onboarding_id) not in reference
        assert not {"tenant_id", "space_id", "default_project_id"} & set(payload)
        assert set(payload) == {
            "state",
            "stage",
            "version",
            "updated_at",
            "can_start_first_run",
            "support_reference",
        }
        _assert_secret_free(
            payload,
            forbidden_values=(str(body["email"]), provider_secret, str(onboarding_id)),
        )

        with harness.sessions.begin() as db:
            saga = db.get(TenantOnboardingRecord, onboarding_id)
            assert saga is not None
            saga.status = "compensated"
            saga.compensation_cursor = None
            saga.compensated_at = saga.last_transition_at
            saga.version += 1
        compensated = harness.client.get("/saas/onboarding/status")
        assert compensated.status_code == 200
        assert compensated.json()["state"] == "support_required"
        assert compensated.json()["support_reference"] == reference
        assert provider_secret not in compensated.text
        assert compensated.headers["Cache-Control"] == "private, no-store"
    finally:
        harness_iterator.close()
