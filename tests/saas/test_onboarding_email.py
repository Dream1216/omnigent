from __future__ import annotations

import json
import smtplib
import traceback
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from typing import cast
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx
import pytest

from saas.control_plane.onboarding import (
    EmailVerificationMessage,
    EmailVerificationSender,
    OnboardingOutboxPublisher,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.outbox import OutboxPublishError
from saas.onboarding_email import (
    RESEND_EMAIL_ENDPOINT,
    EmailVerificationDeliveryError,
    ResendEmailVerificationConfig,
    ResendEmailVerificationSender,
    SmtpEmailVerificationConfig,
    SmtpEmailVerificationSender,
)

_NOW = datetime(2026, 9, 2, 0, 0, tzinfo=timezone.utc)
_REGISTRATION_ID = UUID("ff43beb0-fba1-4ab5-9faa-939524369266")
_CHALLENGE_ID = UUID("fdad19c9-11bd-4fb8-84ce-85b03105745a")
_EVENT_ID = UUID("5e5218d2-4fc1-446c-8f03-aa514b3e314e")
_PROVIDER_MESSAGE_ID = UUID("49a3999c-0ce1-4ea6-ab68-afcd6dc2e794")
_RECIPIENT = "owner@example.test"
_TOKEN = "test/token+with?reserved=characters"
_PROVIDER_TOKEN = "test-provider-token"
_SMTP_PASSWORD = "smtp-password value"


class _SmtpConnection:
    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.login_values: tuple[str, str] | None = None
        self.messages: list[tuple[object, str | None, list[str] | None]] = []
        self.quit_called = False
        self.close_called = False

    def ehlo(self) -> tuple[int, bytes]:
        return (250, b"ok")

    def starttls(self, *, context: object) -> tuple[int, bytes]:
        del context
        return (220, b"ready")

    def login(self, user: str, password: str) -> tuple[int, bytes]:
        self.login_values = (user, password)
        if self.failure is not None:
            raise self.failure
        return (235, b"authenticated")

    def send_message(
        self,
        msg: object,
        from_addr: str | None = None,
        to_addrs: list[str] | None = None,
    ) -> dict[str, tuple[int, bytes]]:
        self.messages.append((msg, from_addr, to_addrs))
        return {}

    def quit(self) -> tuple[int, bytes]:
        self.quit_called = True
        return (221, b"bye")

    def close(self) -> None:
        self.close_called = True


@pytest.fixture
def sender_factory() -> Iterator[
    Callable[[Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender]
]:
    senders: list[ResendEmailVerificationSender] = []

    def create(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> ResendEmailVerificationSender:
        sender = ResendEmailVerificationSender(
            ResendEmailVerificationConfig(
                public_origin="https://next.jxhh.com/",
                from_address="verify@jxhh.com",
                provider_token=_PROVIDER_TOKEN,
            ),
            transport=httpx.MockTransport(handler),
        )
        senders.append(sender)
        return sender

    yield create
    for sender in senders:
        sender.close()


def _message(**overrides: object) -> EmailVerificationMessage:
    values: dict[str, object] = {
        "registration_id": _REGISTRATION_ID,
        "challenge_id": _CHALLENGE_ID,
        "email": _RECIPIENT,
        "verification_token": _TOKEN,
        "expires_at": _NOW + timedelta(minutes=30),
    }
    values.update(overrides)
    return EmailVerificationMessage(**values)  # type: ignore[arg-type]


def test_resend_sender_uses_exact_https_contract_and_fragment_token(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    observed: dict[str, object] = {}

    def send(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers["Authorization"]
        observed["idempotency"] = request.headers["Idempotency-Key"]
        observed["user_agent"] = request.headers["User-Agent"]
        observed["payload"] = json.loads(request.content)
        return httpx.Response(200, json={"id": str(_PROVIDER_MESSAGE_ID)})

    sender = sender_factory(send)
    sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert observed["method"] == "POST"
    assert observed["url"] == RESEND_EMAIL_ENDPOINT
    assert observed["authorization"] == f"Bearer {_PROVIDER_TOKEN}"
    assert observed["idempotency"] == str(_EVENT_ID)
    assert observed["user_agent"] == "omnigent-saas-onboarding/1"
    payload = cast(dict[str, object], observed["payload"])
    assert payload["from"] == "verify@jxhh.com"
    assert payload["to"] == [_RECIPIENT]
    assert "html" not in payload

    link = next(
        line for line in cast(str, payload["text"]).splitlines() if line.startswith("https://")
    )
    parsed = urlsplit(link)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://next.jxhh.com/signup/verify"
    )
    assert parse_qs(parsed.query) == {"registration_id": [str(_REGISTRATION_ID)]}
    assert parse_qs(parsed.fragment) == {"token": [_TOKEN]}
    assert _TOKEN not in parsed.query


def test_resend_sender_retries_same_event_with_identical_request_contract(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    requests: list[tuple[str, bytes]] = []

    def send(request: httpx.Request) -> httpx.Response:
        requests.append((request.headers["Idempotency-Key"], request.content))
        return httpx.Response(200, json={"id": str(_PROVIDER_MESSAGE_ID)})

    sender = sender_factory(send)
    message = _message()
    sender.send_verification(event_id=_EVENT_ID, message=message)
    sender.send_verification(event_id=_EVENT_ID, message=message)

    assert requests == [(str(_EVENT_ID), requests[0][1])] * 2


def test_resend_sender_rejects_invalid_event_id_without_network(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    request_count = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json={"id": str(_PROVIDER_MESSAGE_ID)})

    sender = sender_factory(send)

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(
            event_id=cast(UUID, "not-a-uuid"),
            message=_message(),
        )

    assert raised.value.code == "email_verification_message_invalid"
    assert not raised.value.retryable
    assert raised.value.pre_side_effect
    assert request_count == 0


@pytest.mark.parametrize(
    "message",
    (
        _message(email="not-an-address"),
        _message(verification_token="token with whitespace"),
        _message(expires_at=_NOW.replace(tzinfo=None)),
    ),
)
def test_resend_sender_rejects_invalid_message_without_network(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
    message: EmailVerificationMessage,
) -> None:
    request_count = 0

    def send(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json={"id": str(_PROVIDER_MESSAGE_ID)})

    sender = sender_factory(send)

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=message)

    assert raised.value.code == "email_verification_message_invalid"
    assert not raised.value.retryable
    assert raised.value.pre_side_effect
    assert request_count == 0


def test_verification_message_and_sender_reprs_hide_delivery_secrets(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    sender = sender_factory(
        lambda _request: httpx.Response(200, json={"id": str(_PROVIDER_MESSAGE_ID)})
    )
    config = ResendEmailVerificationConfig(
        public_origin="https://next.jxhh.com",
        from_address="verify@jxhh.com",
        provider_token=_PROVIDER_TOKEN,
    )
    serialized = f"{_message()!r} {sender!r} {config!r}"

    assert _RECIPIENT not in serialized
    assert _TOKEN not in serialized
    assert _PROVIDER_TOKEN not in serialized


@pytest.mark.parametrize(
    "origin",
    (
        "http://next.jxhh.com",
        "https://next.jxhh.com:443",
        "https://user:password@next.jxhh.com",
        "https://next.jxhh.com/base",
        "https://next.jxhh.com?redirect=other",
        "https://next.jxhh.com#fragment",
        "https://127.0.0.1",
        "https://localhost",
        " https://next.jxhh.com",
    ),
)
def test_resend_config_rejects_non_origin_public_urls(origin: str) -> None:
    with pytest.raises(ValueError, match="public Origin"):
        ResendEmailVerificationConfig(
            public_origin=origin,
            from_address="verify@jxhh.com",
            provider_token=_PROVIDER_TOKEN,
        )


@pytest.mark.parametrize(
    ("from_address", "provider_token"),
    (
        ("Omnigent <verify@jxhh.com>", _PROVIDER_TOKEN),
        ("verify@localhost", _PROVIDER_TOKEN),
        ("verify@jxhh.com\nBcc:other@example.test", _PROVIDER_TOKEN),
        ("verify@jxhh.com", " token-with-space"),
        ("verify@jxhh.com", ""),
    ),
)
def test_resend_config_rejects_unsafe_sender_or_token(
    from_address: str,
    provider_token: str,
) -> None:
    with pytest.raises(ValueError):
        ResendEmailVerificationConfig(
            public_origin="https://next.jxhh.com",
            from_address=from_address,
            provider_token=provider_token,
        )


@pytest.mark.parametrize("timeout_seconds", (True, 0, -1, 30.1, float("inf"), float("nan")))
def test_resend_config_rejects_unsafe_timeouts(timeout_seconds: float) -> None:
    with pytest.raises(ValueError):
        ResendEmailVerificationConfig(
            public_origin="https://next.jxhh.com",
            from_address="verify@jxhh.com",
            provider_token=_PROVIDER_TOKEN,
            timeout_seconds=timeout_seconds,
        )


@pytest.mark.parametrize(
    ("status", "payload", "code", "retryable", "pre_side_effect"),
    (
        (
            400,
            {"message": "recipient-secret"},
            "email_verification_provider_rejected",
            False,
            True,
        ),
        (
            429,
            {"message": "provider-limit-secret"},
            "email_verification_provider_rate_limited",
            True,
            False,
        ),
        (
            503,
            {"message": "provider-outage-secret"},
            "email_verification_provider_unavailable",
            True,
            False,
        ),
        (
            409,
            {"name": "concurrent_idempotent_requests", "message": "provider-secret"},
            "email_verification_provider_concurrent",
            True,
            False,
        ),
        (
            409,
            {"name": "invalid_idempotent_request", "message": "provider-secret"},
            "email_verification_provider_idempotency_conflict",
            False,
            False,
        ),
        (
            409,
            {"name": "undocumented_conflict", "message": "provider-secret"},
            "email_verification_provider_protocol_invalid",
            True,
            False,
        ),
    ),
)
def test_resend_sender_classifies_provider_failures_without_body_leak(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
    status: int,
    payload: dict[str, str],
    code: str,
    retryable: bool,
    pre_side_effect: bool,
) -> None:
    sender = sender_factory(lambda _request: httpx.Response(status, json=payload))

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert raised.value.code == code
    assert raised.value.retryable is retryable
    assert raised.value.pre_side_effect is pre_side_effect
    serialized = f"{raised.value!s} {raised.value!r} {sender!r}"
    assert _TOKEN not in serialized
    assert _RECIPIENT not in serialized
    assert _PROVIDER_TOKEN not in serialized
    assert all(value not in serialized for value in payload.values())


def test_resend_sender_rejects_redirect_without_following_it(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://other.example.test/capture"})

    sender = sender_factory(redirect)

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert raised.value.code == "email_verification_provider_redirect_rejected"
    assert not raised.value.retryable
    assert raised.value.pre_side_effect
    assert len(requests) == 1
    assert str(requests[0].url) == RESEND_EMAIL_ENDPOINT


def test_resend_sender_makes_transport_failure_content_blind(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(
            f"timeout contained {_RECIPIENT} {_TOKEN} {_PROVIDER_TOKEN}", request=request
        )

    sender = sender_factory(timeout)

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert raised.value.code == "email_verification_provider_unavailable"
    assert raised.value.retryable
    assert not raised.value.pre_side_effect
    assert _RECIPIENT not in repr(raised.value)
    assert _TOKEN not in repr(raised.value)
    assert _PROVIDER_TOKEN not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    rendered_traceback = "".join(
        traceback.format_exception(
            type(raised.value),
            raised.value,
            raised.value.__traceback__,
        )
    )
    assert _RECIPIENT not in rendered_traceback
    assert _TOKEN not in rendered_traceback
    assert _PROVIDER_TOKEN not in rendered_traceback


def test_smtp_sender_uses_authenticated_tls_safe_headers_and_stable_message_id() -> None:
    connection = _SmtpConnection()
    config = SmtpEmailVerificationConfig(
        public_origin="https://next.jxhh.com",
        host="smtp.example.test",
        port=587,
        security="starttls",
        username="smtp-user@example.test",
        password=_SMTP_PASSWORD,
        from_address="verify@example.test",
        reply_to_address="support@example.test",
    )
    sender = SmtpEmailVerificationSender(config, connection_factory=lambda config: connection)

    sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert connection.login_values == ("smtp-user@example.test", _SMTP_PASSWORD)
    assert connection.quit_called
    assert not connection.close_called
    assert len(connection.messages) == 1
    raw_message, from_addr, to_addrs = connection.messages[0]
    message = cast(object, raw_message)
    assert message["From"] == "Omnigent <verify@example.test>"  # type: ignore[index]
    assert message["To"] == _RECIPIENT  # type: ignore[index]
    assert message["Reply-To"] == "support@example.test"  # type: ignore[index]
    assert message["Message-ID"] == f"<{_EVENT_ID}@example.test>"  # type: ignore[index]
    assert "#token=test%2Ftoken%2Bwith%3Freserved%3Dcharacters" in message.get_content()  # type: ignore[attr-defined]
    assert from_addr == "verify@example.test"
    assert to_addrs == [_RECIPIENT]
    assert _SMTP_PASSWORD not in repr(config)
    assert _SMTP_PASSWORD not in repr(sender)


def test_smtp_sender_emits_bounded_configuration_test_without_verification_secret() -> None:
    connection = _SmtpConnection()
    sender = SmtpEmailVerificationSender(
        SmtpEmailVerificationConfig(
            public_origin="https://next.jxhh.com",
            host="smtp.example.test",
            port=465,
            security="tls",
            username="smtp-user",
            password=_SMTP_PASSWORD,
            from_address="verify@example.test",
        ),
        connection_factory=lambda config: connection,
    )

    test_id = UUID("223e4567-e89b-12d3-a456-426614174000")
    sender.send_test(
        recipient="ops@example.test",
        configuration_version=7,
        test_id=test_id,
    )

    raw_message = connection.messages[0][0]
    assert raw_message["Subject"] == "Omnigent SMTP configuration test"  # type: ignore[index]
    assert raw_message["Message-ID"] == (  # type: ignore[index]
        f"<smtp-config-v7-test-{test_id}@example.test>"
    )
    assert "Configuration version: 7" in raw_message.get_content()  # type: ignore[attr-defined]
    assert _TOKEN not in raw_message.get_content()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "values",
    (
        {"host": "https://smtp.example.test"},
        {"host": "localhost"},
        {"port": 0},
        {"port": True},
        {"security": "plain"},
        {"username": "user\nBcc: victim@example.test"},
        {"password": "password\r\n"},
        {"reply_to_address": "invalid"},
        {"timeout_seconds": 30.1},
    ),
)
def test_smtp_config_rejects_unsafe_values(values: dict[str, object]) -> None:
    arguments: dict[str, object] = {
        "public_origin": "https://next.jxhh.com",
        "host": "smtp.example.test",
        "port": 587,
        "security": "starttls",
        "username": "smtp-user",
        "password": _SMTP_PASSWORD,
        "from_address": "verify@example.test",
    }
    arguments.update(values)
    with pytest.raises(ValueError):
        SmtpEmailVerificationConfig(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "code", "retryable", "pre_side_effect"),
    (
        (
            smtplib.SMTPAuthenticationError(535, b"credential-secret"),
            "email_verification_provider_authentication_rejected",
            False,
            True,
        ),
        (
            smtplib.SMTPServerDisconnected("recipient-secret"),
            "email_verification_provider_unavailable",
            True,
            False,
        ),
    ),
)
def test_smtp_sender_classifies_failures_without_secret_leak(
    failure: Exception,
    code: str,
    retryable: bool,
    pre_side_effect: bool,
) -> None:
    connection = _SmtpConnection(failure)
    sender = SmtpEmailVerificationSender(
        SmtpEmailVerificationConfig(
            public_origin="https://next.jxhh.com",
            host="smtp.example.test",
            port=587,
            security="starttls",
            username="smtp-user",
            password=_SMTP_PASSWORD,
            from_address="verify@example.test",
        ),
        connection_factory=lambda config: connection,
    )

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert raised.value.code == code
    assert raised.value.retryable is retryable
    assert raised.value.pre_side_effect is pre_side_effect
    assert connection.close_called
    rendered = "".join(
        traceback.format_exception(type(raised.value), raised.value, raised.value.__traceback__)
    )
    assert _SMTP_PASSWORD not in rendered
    assert _RECIPIENT not in rendered


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(200, json={}),
        httpx.Response(200, json={"id": "not-a-provider-uuid"}),
        httpx.Response(200, content=b"provider-sensitive-non-json"),
        httpx.Response(200, content=b"x" * 4097),
    ),
)
def test_resend_sender_treats_invalid_success_receipt_as_retryable_after_effect(
    sender_factory: Callable[
        [Callable[[httpx.Request], httpx.Response]], ResendEmailVerificationSender
    ],
    response: httpx.Response,
) -> None:
    sender = sender_factory(lambda _request: response)

    with pytest.raises(EmailVerificationDeliveryError) as raised:
        sender.send_verification(event_id=_EVENT_ID, message=_message())

    assert raised.value.code == "email_verification_provider_protocol_invalid"
    assert raised.value.retryable
    assert not raised.value.pre_side_effect
    assert "provider-sensitive" not in repr(raised.value)


class _Envelope:
    def __init__(self, message: EmailVerificationMessage) -> None:
        self.message = message

    def open(self, *, event_id: UUID, payload: dict[str, object]) -> EmailVerificationMessage:
        del event_id, payload
        return self.message


class _RegistrationRecorder:
    def __init__(self) -> None:
        self.records: list[tuple[bool, str | None]] = []

    def email_delivery_is_current(self, **_values: object) -> bool:
        return True

    def record_email_delivery(
        self,
        *,
        message: EmailVerificationMessage,
        succeeded: bool,
        error_code: str | None,
    ) -> None:
        del message
        self.records.append((succeeded, error_code))


class _FailingSender:
    def __init__(self, error: EmailVerificationDeliveryError) -> None:
        self.error = error

    def send_verification(self, *, event_id: UUID, message: EmailVerificationMessage) -> None:
        del event_id, message
        raise self.error


@pytest.mark.parametrize(
    ("delivery_error", "retryable", "pre_side_effect"),
    (
        (
            EmailVerificationDeliveryError(
                "email_verification_provider_unavailable",
                retryable=True,
                pre_side_effect=False,
            ),
            True,
            False,
        ),
        (
            EmailVerificationDeliveryError(
                "email_verification_provider_rejected",
                retryable=False,
                pre_side_effect=True,
            ),
            False,
            True,
        ),
    ),
)
def test_onboarding_publisher_preserves_typed_sender_failure_disposition(
    delivery_error: EmailVerificationDeliveryError,
    retryable: bool,
    pre_side_effect: bool,
) -> None:
    message = _message(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    registrations = _RegistrationRecorder()
    publisher = OnboardingOutboxPublisher(
        registrations=cast(SelfServiceOnboardingService, registrations),
        coordinator=cast(TenantOnboardingCoordinator, object()),
        envelopes=cast(VerificationEnvelopeKeyring, _Envelope(message)),
        email_sender=cast(EmailVerificationSender, _FailingSender(delivery_error)),
    )

    with pytest.raises(OutboxPublishError) as raised:
        publisher.publish(
            event_id=_EVENT_ID,
            event_type="onboarding.email_verification.requested",
            aggregate_type="self_service_registration",
            aggregate_key=str(_REGISTRATION_ID),
            payload={},
        )

    assert raised.value.code == delivery_error.code
    assert raised.value.retryable is retryable
    assert raised.value.pre_side_effect is pre_side_effect
    assert registrations.records == [(False, "delivery_unavailable")]
