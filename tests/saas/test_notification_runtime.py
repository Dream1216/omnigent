from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane.db_models import GlobalUser, SaasBase
from saas.control_plane.notification_delivery import (
    NotificationDeliveryError,
    NotificationErrorDigester,
)
from saas.control_plane.platform_models import (
    PlatformRoleAssignmentRecord,
    PlatformStaffPrincipalRecord,
)
from saas.notification_bootstrap import resolve_bootstrap_actor
from saas.notification_runtime import (
    DatabaseNotificationRecipientResolver,
    EmptyNotificationRenderContextResolver,
    HttpEmailNotificationProvider,
    InAppNotificationProvider,
)

NOW = datetime(2026, 8, 10, 13, 0, tzinfo=timezone.utc)
DIGESTER = NotificationErrorDigester("runtime-key", b"r" * 32)


def _sessions() -> sessionmaker[Session]:
    engine = sa.create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def test_https_email_provider_contract_and_secret_redaction() -> None:
    observed: dict[str, object] = {}

    def send(request: httpx.Request) -> httpx.Response:
        observed["authorization"] = request.headers["Authorization"]
        observed["idempotency"] = request.headers["Idempotency-Key"]
        observed["payload"] = json.loads(request.content)
        return httpx.Response(
            202,
            headers={"X-Request-Id": "request-123", "X-Message-Id": "message-456"},
        )

    client = httpx.Client(
        transport=httpx.MockTransport(send), trust_env=False, follow_redirects=False
    )
    provider = HttpEmailNotificationProvider(
        endpoint="https://mail.example.test/v1/messages",
        bearer_token="provider-secret-token",
        digesters={DIGESTER.key_id: DIGESTER},
        client=client,
    )
    receipt = provider.send(
        channel="email",
        address="person@example.test",
        subject="Approval required",
        body="Review the pending operation.",
        idempotency_key="delivery-1:0",
        hmac_key_id=DIGESTER.key_id,
    )

    assert observed == {
        "authorization": "Bearer provider-secret-token",
        "idempotency": "delivery-1:0",
        "payload": {
            "to": "person@example.test",
            "subject": "Approval required",
            "text": "Review the pending operation.",
            "idempotency_key": "delivery-1:0",
        },
    }
    assert receipt.provider == "https_email"
    assert all(
        len(value) == 64 and set(value) <= set("0123456789abcdef")
        for value in (
            receipt.provider_request_hmac,
            receipt.provider_receipt_hmac,
            receipt.provider_message_hmac,
        )
    )
    representation = repr(provider)
    assert "provider-secret-token" not in representation
    assert "person@example.test" not in representation
    assert "Review the pending operation" not in representation


@pytest.mark.parametrize(
    ("status", "code"),
    (
        (400, "notification_provider_rejected"),
        (429, "notification_provider_rate_limited"),
        (503, "notification_provider_unavailable"),
    ),
)
def test_https_email_provider_classifies_status_without_response_leak(
    status: int, code: str
) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, content=b"raw-provider-secret", request=request)
        ),
        trust_env=False,
        follow_redirects=False,
    )
    provider = HttpEmailNotificationProvider(
        endpoint="https://mail.example.test/v1/messages",
        bearer_token="provider-secret-token",
        digesters={DIGESTER.key_id: DIGESTER},
        client=client,
    )

    with pytest.raises(NotificationDeliveryError) as raised:
        provider.send(
            channel="email",
            address="person@example.test",
            subject="subject",
            body="body",
            idempotency_key="delivery-2:0",
            hmac_key_id=DIGESTER.key_id,
        )
    assert raised.value.code == code
    assert raised.value.provider_status == status
    assert "raw-provider-secret" not in repr(raised.value)
    assert "provider-secret-token" not in repr(raised.value)


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://mail.example.test/v1/messages",
        "https://user:password@mail.example.test/v1/messages",
        "https://mail.example.test/v1/messages?redirect=evil",
        "https://mail.example.test/v1/messages#fragment",
        "https://mail.example.test:444/v1/messages",
    ),
)
def test_https_email_provider_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError):
        HttpEmailNotificationProvider(
            endpoint=endpoint,
            bearer_token="secret",
            digesters={DIGESTER.key_id: DIGESTER},
            client=httpx.Client(
                transport=httpx.MockTransport(lambda request: httpx.Response(204)),
                trust_env=False,
                follow_redirects=False,
            ),
        )


@pytest.mark.parametrize(
    "headers",
    (
        {"X-Request-Id": "request-only"},
        {"X-Request-Id": "r" * 257, "X-Message-Id": "message"},
        {"X-Request-Id": "request", "X-Message-Id": "m" * 257},
    ),
)
def test_https_email_provider_requires_bounded_native_receipt_ids(
    headers: dict[str, str],
) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(202, request=request, headers=headers)
        ),
        trust_env=False,
        follow_redirects=False,
    )
    provider = HttpEmailNotificationProvider(
        endpoint="https://mail.example.test/v1/messages",
        bearer_token="secret",
        digesters={DIGESTER.key_id: DIGESTER},
        client=client,
    )

    with pytest.raises(NotificationDeliveryError) as raised:
        provider.send(
            channel="email",
            address="person@example.test",
            subject="subject",
            body="body",
            idempotency_key="delivery-3:0",
            hmac_key_id=DIGESTER.key_id,
        )
    assert raised.value.code == "notification_provider_protocol_invalid"


def test_directory_resolver_revalidates_active_recipients_for_every_channel() -> None:
    sessions = _sessions()
    user_id, inactive_id, staff_id = uuid4(), uuid4(), uuid4()
    with sessions.begin() as db:
        db.add_all(
            (
                GlobalUser(
                    id=user_id,
                    status="active",
                    primary_email_normalized="user@example.test",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                GlobalUser(
                    id=inactive_id,
                    status="suspended",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                PlatformStaffPrincipalRecord(
                    id=staff_id,
                    identity_connection_ref=f"runtime:{staff_id}",
                    issuer="https://staff-idp.example.test",
                    subject="runtime-operator",
                    email_normalized="staff@example.test",
                    status="active",
                    security_version=1,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            )
        )
    resolver = DatabaseNotificationRecipientResolver(sessions)

    email = resolver.resolve(
        recipient_ref=f"user:{user_id}",
        channel="email",
        purpose="notification_delivery",
        now=NOW,
    )
    in_app = resolver.resolve(
        recipient_ref=f"principal:{staff_id}",
        channel="in_app",
        purpose="notification_delivery",
        now=NOW,
    )
    assert email.address == "user@example.test"
    assert in_app.address == f"in_app:principal:{staff_id}"
    assert "user@example.test" not in repr(email)
    assert f"in_app:principal:{staff_id}" not in repr(in_app)
    with pytest.raises(NotificationDeliveryError) as raised:
        resolver.resolve(
            recipient_ref=f"user:{inactive_id}",
            channel="in_app",
            purpose="notification_delivery",
            now=NOW,
        )
    assert raised.value.code == "notification_recipient_address_invalid"


def test_in_app_provider_and_variable_free_context_are_content_blind() -> None:
    provider = InAppNotificationProvider({DIGESTER.key_id: DIGESTER})
    receipt = provider.send(
        channel="in_app",
        address=f"in_app:user:{uuid4()}",
        subject="private subject",
        body="private body",
        idempotency_key="delivery-4:0",
        hmac_key_id=DIGESTER.key_id,
    )
    context = EmptyNotificationRenderContextResolver().resolve(
        delivery_id=uuid4(),
        event_type="approval.requested",
        expected_hmac="a" * 64,
        purpose="notification_render",
        now=NOW,
    )
    assert receipt.provider == "in_app"
    assert context.variables == {}
    assert context.expires_at == NOW + timedelta(seconds=20)
    assert "private subject" not in repr(provider)
    assert "private body" not in repr(provider)


def test_bootstrap_actor_permissions_are_database_derived() -> None:
    sessions = _sessions()
    principal_id = uuid4()
    with sessions.begin() as db:
        db.add(
            PlatformStaffPrincipalRecord(
                id=principal_id,
                identity_connection_ref=f"bootstrap:{principal_id}",
                issuer="https://staff-idp.example.test",
                subject="bootstrap-operator",
                status="active",
                security_version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add(
            PlatformRoleAssignmentRecord(
                id=uuid4(),
                principal_id=principal_id,
                role="platform_operator",
                status="active",
                version=1,
                assigned_by_principal_id=principal_id,
                approval_ref="approval:notification-bootstrap",
                reason="Publish reviewed immutable notification defaults",
                created_at=NOW,
                updated_at=NOW,
            )
        )

    actor = resolve_bootstrap_actor(sessions, principal_id=principal_id, now=NOW)
    assert actor.realm == "staff"
    assert actor.actor_id == principal_id
    assert "platform.notification_template.manage" in actor.permissions
