from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import (
    ControlPlaneOutboxEvent,
    EnqueuedWebhookDelivery,
    GlobalUser,
    ResolvedWebhookTarget,
    SaasBase,
    Tenant,
    TlsPinnedWebhookHttpSender,
    WebhookDeliveryControlPlane,
    WebhookDeliveryError,
    WebhookDeliveryRecord,
    WebhookDispatchResult,
    WebhookEndpointRecord,
    WebhookHttpResult,
    WebhookTargetPolicy,
)

NOW = datetime(2026, 8, 5, 2, 0, tzinfo=timezone.utc)


@pytest.fixture
def sessions() -> sessionmaker[Session]:
    engine = sa.create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def _seed(sessions: sessionmaker[Session]) -> tuple[UUID, UUID]:
    user_id, tenant_id = uuid4(), uuid4()
    with sessions.begin() as db:
        db.add(GlobalUser(id=user_id, status="active", security_version=1))
        db.add(
            Tenant(
                id=tenant_id,
                slug=f"webhooks-{tenant_id.hex}",
                name="Webhook Tenant",
                status="active",
                plan="team",
                home_region="cn-east-1",
            )
        )
    return user_id, tenant_id


class _Resolver:
    def __init__(self, answers: tuple[str, ...] = ("8.8.8.8",)) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    def resolve(self, *, hostname: str, port: int) -> tuple[str, ...]:
        self.calls.append((hostname, port))
        return self.answers


class _Secrets:
    def __init__(self) -> None:
        self.values = {
            ("vault://tenant/webhook", 1): b"a" * 32,
            ("vault://tenant/webhook", 2): b"b" * 32,
        }
        self.calls: list[tuple[str, int]] = []

    def get_secret(self, *, secret_ref: str, version: int) -> bytes:
        self.calls.append((secret_ref, version))
        return self.values[(secret_ref, version)]


class _ReplayAuthorizer:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[UUID, UUID, UUID, UUID]] = []

    def authorize_replay(
        self,
        *,
        tenant_id: UUID,
        endpoint_id: UUID,
        delivery_id: UUID,
        actor_id: UUID,
    ) -> bool:
        self.calls.append((tenant_id, endpoint_id, delivery_id, actor_id))
        return self.allowed


class _Sender:
    def __init__(self, statuses: tuple[int, ...]) -> None:
        self.statuses = deque(statuses)
        self.calls: list[tuple[ResolvedWebhookTarget, dict[str, str], bytes]] = []

    def send(
        self,
        *,
        target: ResolvedWebhookTarget,
        headers: dict[str, str],
        payload: bytes,
    ) -> WebhookHttpResult:
        self.calls.append((target, headers, payload))
        status = self.statuses.popleft()
        return WebhookHttpResult(status, hashlib.sha256(f"response-{status}".encode()).hexdigest())


def _control(
    sessions: sessionmaker[Session],
    resolver: _Resolver,
    secrets: _Secrets,
    sender: _Sender,
) -> WebhookDeliveryControlPlane:
    return WebhookDeliveryControlPlane(
        sessions,
        WebhookTargetPolicy(resolver),
        secrets,
        sender,
        lease_duration=timedelta(seconds=10),
        max_backoff=timedelta(seconds=30),
        replay_authorizer=_ReplayAuthorizer(),
    )


def test_webhook_delivery_is_idempotent_signed_rotatable_and_dns_repinned(
    sessions: sessionmaker[Session],
) -> None:
    user_id, tenant_id = _seed(sessions)
    resolver = _Resolver()
    secrets = _Secrets()
    sender = _Sender((503, 204))
    control = _control(sessions, resolver, secrets, sender)
    endpoint = control.register_endpoint(
        tenant_id=tenant_id,
        space_id=None,
        project_id=None,
        url="https://hooks.example.com/v1/events?source=omnigent",
        event_types=("run.completed", "run.failed", "run.completed"),
        secret_ref="vault://tenant/webhook",
        secret_version=1,
        created_by=user_id,
    )
    rotated = control.rotate_secret(
        endpoint_id=endpoint.endpoint_id,
        new_version=2,
        overlap=timedelta(minutes=10),
        now=NOW,
    )
    assert rotated.active_secret_version == 2
    assert rotated.previous_secret_version == 1
    assert rotated.security_version == 2

    event_id = uuid4()
    sender_run_id = str(uuid4())
    first = control.enqueue(
        endpoint_id=endpoint.endpoint_id,
        event_id=event_id,
        event_type="run.completed",
        event_version=1,
        occurred_at=NOW - timedelta(seconds=1),
        payload={"run_id": sender_run_id, "status": "completed"},
        max_attempts=3,
        now=NOW,
    )
    duplicate = control.enqueue(
        endpoint_id=endpoint.endpoint_id,
        event_id=event_id,
        event_type="run.completed",
        event_version=1,
        occurred_at=NOW - timedelta(seconds=1),
        payload={"run_id": sender_run_id, "status": "completed"},
        max_attempts=3,
        now=NOW,
    )
    assert duplicate.delivery_id == first.delivery_id

    failed = control.dispatch_once(now=NOW)
    assert (failed.claimed, failed.delivered, failed.retried, failed.dead_lettered) == (
        1,
        0,
        1,
        0,
    )
    resolver.answers = ("1.1.1.1",)
    delivered = control.dispatch_once(now=NOW + timedelta(seconds=2))
    assert (
        delivered.claimed,
        delivered.delivered,
        delivered.retried,
        delivered.dead_lettered,
    ) == (1, 1, 0, 0)
    assert [call[0].address for call in sender.calls] == ["8.8.8.8", "1.1.1.1"]
    assert len(resolver.calls) == 3  # registration plus every delivery attempt

    target, headers, payload = sender.calls[0]
    assert target.request_target == "/v1/events?source=omnigent"
    assert headers["x-omnigent-signature"].startswith("v2=")
    assert ",v1=" in headers["x-omnigent-signature"]
    message = b"\n".join(
        (
            headers["x-omnigent-timestamp"].encode(),
            headers["x-omnigent-delivery-id"].encode(),
            headers["x-omnigent-event-id"].encode(),
            payload,
        )
    )
    expected = hmac.new(b"b" * 32, message, hashlib.sha256).hexdigest()
    assert headers["x-omnigent-signature"].split(",", 1)[0] == f"v2={expected}"

    with sessions() as db:
        stored = db.get(WebhookDeliveryRecord, first.delivery_id)
        stored_endpoint = db.get(WebhookEndpointRecord, endpoint.endpoint_id)
        assert stored is not None and stored.status == "delivered"
        assert stored.attempt_count == 2
        assert stored.response_status == 204
        assert stored_endpoint is not None
        assert stored_endpoint.secret_ref == "vault://tenant/webhook"
        serialized = repr((stored_endpoint.__dict__, stored.__dict__))
        assert "aaaaaaaa" not in serialized and "bbbbbbbb" not in serialized


def test_webhook_event_conflict_redirect_and_permanent_failure_go_to_dlq(
    sessions: sessionmaker[Session],
) -> None:
    user_id, tenant_id = _seed(sessions)
    resolver, secrets, sender = _Resolver(), _Secrets(), _Sender((302,))
    control = _control(sessions, resolver, secrets, sender)
    endpoint = control.register_endpoint(
        tenant_id=tenant_id,
        space_id=None,
        project_id=None,
        url="https://hooks.example.com/events",
        event_types=("audit.created",),
        secret_ref="vault://tenant/webhook",
        secret_version=1,
        created_by=user_id,
    )
    event_id = uuid4()
    delivery = control.enqueue(
        endpoint_id=endpoint.endpoint_id,
        event_id=event_id,
        event_type="audit.created",
        event_version=1,
        occurred_at=NOW,
        payload={"audit_id": "one"},
        now=NOW,
    )
    with pytest.raises(WebhookDeliveryError) as conflict:
        control.enqueue(
            endpoint_id=endpoint.endpoint_id,
            event_id=event_id,
            event_type="audit.created",
            event_version=1,
            occurred_at=NOW,
            payload={"audit_id": "different"},
            now=NOW,
        )
    assert conflict.value.code == "webhook_event_conflict"
    result = control.dispatch_once(now=NOW)
    assert (result.claimed, result.delivered, result.retried, result.dead_lettered) == (
        1,
        0,
        0,
        1,
    )
    with sessions() as db:
        stored = db.get(WebhookDeliveryRecord, delivery.delivery_id)
        assert stored is not None and stored.status == "dead_letter"
        assert stored.response_status == 302
    denied_control = WebhookDeliveryControlPlane(
        sessions,
        WebhookTargetPolicy(resolver),
        secrets,
        sender,
        replay_authorizer=_ReplayAuthorizer(allowed=False),
    )
    with pytest.raises(WebhookDeliveryError) as denied_replay:
        denied_control.requeue_dead_letter(
            delivery_id=delivery.delivery_id,
            replayed_by=user_id,
            now=NOW + timedelta(seconds=1),
        )
    assert denied_replay.value.code == "webhook_replay_forbidden"
    replayed = control.requeue_dead_letter(
        delivery_id=delivery.delivery_id,
        replayed_by=user_id,
        now=NOW + timedelta(seconds=1),
    )
    assert replayed.delivery_id == delivery.delivery_id
    assert replayed.event_id == event_id
    assert replayed.replay_generation == 1
    sender.statuses.append(204)
    replay_result = control.dispatch_once(now=NOW + timedelta(seconds=1))
    assert (replay_result.claimed, replay_result.delivered) == (1, 1)
    with sessions() as db:
        stored = db.get(WebhookDeliveryRecord, delivery.delivery_id)
        outbox = db.scalar(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.aggregate_key == str(delivery.delivery_id)
            )
        )
        assert stored is not None and stored.status == "delivered"
        assert stored.replay_generation == 1
        assert outbox is not None
        assert outbox.event_type == "webhook.delivery.requeued"


@pytest.mark.parametrize(
    "url",
    (
        "http://hooks.example.com/events",
        "https://user:password@hooks.example.com/events",
        "https://127.0.0.1/events",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/computeMetadata/v1",
        "https://hooks.example.com/events#fragment",
        "https://bad_host.example/events",
        "https://hooks.example.com/%zz",
        "https://hooks.example.com/\x01events",
        "https://%31%32%37.0.0.1/events",
    ),
)
def test_webhook_target_policy_rejects_unsafe_urls_and_mixed_dns_answers(url: str) -> None:
    policy = WebhookTargetPolicy(_Resolver())
    with pytest.raises(WebhookDeliveryError) as denied:
        policy.resolve(url)
    assert denied.value.code in {"webhook_url_invalid", "webhook_target_forbidden"}

    mixed = WebhookTargetPolicy(_Resolver(("8.8.8.8", "10.0.0.10")))
    with pytest.raises(WebhookDeliveryError) as rebound:
        mixed.resolve("https://hooks.example.com/events")
    assert rebound.value.code == "webhook_target_forbidden"

    for transition_address in (
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2002:0808:0808::",
    ):
        transition = WebhookTargetPolicy(_Resolver((transition_address,)))
        with pytest.raises(WebhookDeliveryError) as denied_transition:
            transition.resolve("https://hooks.example.com/events")
        assert denied_transition.value.code == "webhook_target_forbidden"

    unicode_target = policy.resolve("https://hooks.example.com/事件?来源=omnigent")
    assert unicode_target.request_target == ("/%E4%BA%8B%E4%BB%B6?%E6%9D%A5%E6%BA%90=omnigent")


def _tls_files(root: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Webhook CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hooks.example.com")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("hooks.example.com")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = root / "ca.pem", root / "server.pem", root / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def test_tls_sender_pins_ip_but_verifies_original_sni_and_never_follows_redirect(
    tmp_path: Path,
) -> None:
    ca_path, cert_path, key_path = _tls_files(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(cert_path, key_path)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    observed: list[bytes] = []

    def serve() -> None:
        connection, _address = listener.accept()
        with connection, server_context.wrap_socket(connection, server_side=True) as tls:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(tls.recv(4096))
            head, body = bytes(request).split(b"\r\n\r\n", 1)
            length_line = next(
                line for line in head.split(b"\r\n") if line.startswith(b"content-length")
            )
            length = int(length_line.split(b":", 1)[1])
            while len(body) < length:
                body += tls.recv(4096)
            observed.append(head + b"\r\n\r\n" + body)
            tls.sendall(
                b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    sender = TlsPinnedWebhookHttpSender(client_context)
    try:
        result = sender.send(
            target=ResolvedWebhookTarget(
                canonical_url=f"https://hooks.example.com:{port}/events",
                server_name="hooks.example.com",
                port=port,
                request_target="/events",
                address=str(ipaddress.ip_address("127.0.0.1")),
            ),
            headers={"x-omnigent-signature": "v1=" + "a" * 64},
            payload=b'{"ok":true}',
        )
    finally:
        listener.close()
        thread.join(timeout=5)
    assert result.status_code == 204
    assert len(result.response_digest_sha256) == 64
    assert b"host: hooks.example.com:" in observed[0]
    assert b"x-omnigent-signature: v1=" in observed[0]


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for P5 Webhook acceptance")
    return value


def _migrate(connection: sa.Connection, root: Path) -> None:
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _role_factory(
    engine: sa.Engine,
    role: str,
    *,
    tenant_id: UUID | None = None,
) -> sessionmaker[Session]:
    factory = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(factory, "after_begin")
    def _bind_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")
        connection.execute(
            sa.text("SELECT set_config('app.tenant_id', :tenant, true)"),
            {"tenant": str(tenant_id) if tenant_id else ""},
        )

    return factory


def test_real_postgresql_webhook_forced_rls_dispatcher_role_and_immutable_fact() -> None:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url(), pool_size=4, max_overflow=0)
    actor_id, tenant_a, tenant_b = uuid4(), uuid4(), uuid4()
    try:
        with engine.begin() as connection:
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_global_users (id, status, security_version) "
                    "VALUES (:actor, 'active', 1)"
                ),
                {"actor": actor_id},
            )
            for tenant_id, suffix in ((tenant_a, "a"), (tenant_b, "b")):
                connection.execute(
                    sa.text(
                        "INSERT INTO saas_tenants "
                        "(id, slug, name, status, plan, home_region) VALUES "
                        "(:id, :slug, 'Webhook RLS', 'active', 'team', 'cn-east-1')"
                    ),
                    {"id": tenant_id, "slug": f"webhook-rls-{suffix}-{tenant_id.hex}"},
                )

        resolver, secrets, sender = _Resolver(), _Secrets(), _Sender((204, 204, 204))
        app_a = _role_factory(engine, "saas_app", tenant_id=tenant_a)
        app_b = _role_factory(engine, "saas_app", tenant_id=tenant_b)
        dispatcher = _role_factory(engine, "saas_webhook_dispatcher")
        controls = tuple(
            WebhookDeliveryControlPlane(
                factory,
                WebhookTargetPolicy(resolver),
                secrets,
                sender,
            )
            for factory in (app_a, app_b)
        )
        endpoints = tuple(
            control.register_endpoint(
                tenant_id=tenant_id,
                space_id=None,
                project_id=None,
                url=f"https://hooks-{suffix}.example.com/events",
                event_types=("run.completed",),
                secret_ref="vault://tenant/webhook",
                secret_version=1,
                created_by=actor_id,
            )
            for control, tenant_id, suffix in zip(
                controls, (tenant_a, tenant_b), ("a", "b"), strict=True
            )
        )
        with app_a() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(WebhookEndpointRecord)) == 1
            assert db.get(WebhookEndpointRecord, endpoints[1].endpoint_id) is None
        deliveries = tuple(
            control.enqueue(
                endpoint_id=endpoint.endpoint_id,
                event_id=uuid4(),
                event_type="run.completed",
                event_version=1,
                occurred_at=NOW,
                payload={"tenant": suffix},
                now=NOW,
            )
            for control, endpoint, suffix in zip(controls, endpoints, ("a", "b"), strict=True)
        )
        concurrent_event_id = uuid4()
        enqueue_barrier = threading.Barrier(2)

        def enqueue_same_event() -> EnqueuedWebhookDelivery:
            enqueue_barrier.wait(timeout=5)
            return controls[0].enqueue(
                endpoint_id=endpoints[0].endpoint_id,
                event_id=concurrent_event_id,
                event_type="run.completed",
                event_version=1,
                occurred_at=NOW,
                payload={"tenant": "a", "concurrent": True},
                now=NOW,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent_receipts = tuple(
                executor.map(lambda _index: enqueue_same_event(), range(2))
            )
        assert concurrent_receipts[0] == concurrent_receipts[1]
        dispatch_control = WebhookDeliveryControlPlane(
            dispatcher,
            WebhookTargetPolicy(resolver),
            secrets,
            sender,
            replay_authorizer=_ReplayAuthorizer(),
        )
        dispatched = dispatch_control.dispatch_once(batch_size=10, now=NOW)
        assert (dispatched.claimed, dispatched.delivered) == (3, 3)
        sender.statuses.append(204)
        single = controls[0].enqueue(
            endpoint_id=endpoints[0].endpoint_id,
            event_id=uuid4(),
            event_type="run.completed",
            event_version=1,
            occurred_at=NOW,
            payload={"tenant": "a", "single_claim": True},
            now=NOW + timedelta(milliseconds=1),
        )
        dispatch_barrier = threading.Barrier(2)

        def compete_for_delivery() -> WebhookDispatchResult:
            dispatch_barrier.wait(timeout=5)
            return dispatch_control.dispatch_once(
                batch_size=1, now=NOW + timedelta(milliseconds=1)
            )

        before_calls = len(sender.calls)
        with ThreadPoolExecutor(max_workers=2) as executor:
            competing_results = tuple(
                executor.map(lambda _index: compete_for_delivery(), range(2))
            )
        assert sum(result.claimed for result in competing_results) == 1
        assert sum(result.delivered for result in competing_results) == 1
        assert len(sender.calls) == before_calls + 1
        sender.statuses.append(302)
        dead = controls[0].enqueue(
            endpoint_id=endpoints[0].endpoint_id,
            event_id=uuid4(),
            event_type="run.completed",
            event_version=1,
            occurred_at=NOW,
            payload={"tenant": "a", "replay": True},
            now=NOW,
        )
        dead_result = dispatch_control.dispatch_once(batch_size=10, now=NOW + timedelta(seconds=1))
        assert (dead_result.claimed, dead_result.dead_lettered) == (1, 1)
        replayed = dispatch_control.requeue_dead_letter(
            delivery_id=dead.delivery_id,
            replayed_by=actor_id,
            now=NOW + timedelta(seconds=2),
        )
        assert replayed.replay_generation == 1
        sender.statuses.append(204)
        replay_result = dispatch_control.dispatch_once(
            batch_size=10, now=NOW + timedelta(seconds=2)
        )
        assert (replay_result.claimed, replay_result.delivered) == (1, 1)
        with dispatcher.begin() as db:
            rows = list(db.scalars(sa.select(WebhookDeliveryRecord)))
            assert {row.id for row in rows} == {
                *(delivery.delivery_id for delivery in deliveries),
                concurrent_receipts[0].delivery_id,
                single.delivery_id,
                dead.delivery_id,
            }
        with pytest.raises(sa.exc.DBAPIError):
            with dispatcher.begin() as db:
                db.execute(
                    sa.update(WebhookEndpointRecord)
                    .where(WebhookEndpointRecord.id == endpoints[0].endpoint_id)
                    .values(status="disabled", security_version=2)
                )
        with pytest.raises(sa.exc.DBAPIError):
            with dispatcher.begin() as db:
                db.execute(
                    sa.update(WebhookDeliveryRecord)
                    .where(WebhookDeliveryRecord.id == deliveries[0].delivery_id)
                    .values(payload={"tampered": True})
                )
    finally:
        engine.dispose()
