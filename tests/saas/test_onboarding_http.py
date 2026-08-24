from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase, Tenant
from saas.control_plane.http_auth import SaasCookieConfig, create_saas_http_integration
from saas.control_plane.identity import IdentityManagementService, PasswordCredentialService
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.onboarding import (
    EmailVerificationMessage,
    OnboardingOutboxPublisher,
    OnboardingPlan,
    OnboardingPolicy,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_models import SelfServiceRegistrationRecord
from saas.control_plane.outbox import OutboxDispatcher
from saas.control_plane.resolver import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver

TRUSTED_ORIGIN = "http://testserver"
EVIL_ORIGIN = "https://attacker.example"
PASSWORD = "correct-horse-battery-staple"


class _AllowAllRateLimiter:
    def require(self, *, action: str, subject_hash: str, now: datetime) -> None:
        del action, subject_hash, now


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


def _http_harness() -> Generator[_HttpHarness, None, None]:
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
    onboarding = SelfServiceOnboardingService(
        sessions,
        policy=policy,
        envelope_keyring=envelopes,
        rate_limiter=_AllowAllRateLimiter(),
    )
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
        onboarding=onboarding,
    )
    app = FastAPI()
    router, prefix, tags = integration.extra_router
    app.include_router(router, prefix=prefix, tags=tags)
    integration.install_middleware(app)
    try:
        with TestClient(app, base_url=TRUSTED_ORIGIN) as client:
            yield _HttpHarness(
                client=client,
                sessions=sessions,
                sender=sender,
                dispatcher=dispatcher,
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
    finally:
        harness_iterator.close()


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

        extra_field = harness.client.post(
            "/saas/onboarding/registrations",
            headers=_post_headers("registration-extra-field"),
            json={**body, "verification_token": "must-not-be-accepted"},
        )
        assert extra_field.status_code == 422
        assert extra_field.json()["detail"][0]["type"] == "extra_forbidden"
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
