"""Durable signed Webhook delivery with DNS-rebinding-resistant target pinning."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.webhook_models import WebhookDeliveryRecord, WebhookEndpointRecord

_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_SECRET_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HTTP_REQUEST_TARGET = re.compile(
    r"^/[A-Za-z0-9!$&'()*+,\-./:;=@_~%]*(?:\?[A-Za-z0-9!$&'()*+,\-./:;=?@_~%]*)?$"
)
_MAX_EVENT_TYPES = 64
_MAX_EVENT_PAYLOAD = 262_144
_MAX_WIRE_PAYLOAD = 524_288
_MAX_RESPONSE_HEAD = 16_384
_DEFAULT_DENIED_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data.ec2.internal",
    }
)
_DEFAULT_DENIED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::ffff:0:0/96",  # IPv4-mapped ambiguity
        "64:ff9b::/96",  # well-known NAT64 translation
        "64:ff9b:1::/48",  # local-use NAT64 translation
        "2001::/32",  # Teredo transition addressing
        "2002::/16",  # 6to4 transition addressing
    )
)


class WebhookDeliveryError(RuntimeError):
    """Stable Webhook control error without secrets, payloads, or topology."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WebhookHostnameResolver(Protocol):
    def resolve(self, *, hostname: str, port: int) -> tuple[str, ...]: ...


class WebhookSecretProvider(Protocol):
    def get_secret(self, *, secret_ref: str, version: int) -> bytes: ...


class WebhookReplayAuthorizer(Protocol):
    def authorize_replay(
        self,
        *,
        tenant_id: UUID,
        endpoint_id: UUID,
        delivery_id: UUID,
        actor_id: UUID,
    ) -> bool: ...


class WebhookHttpSender(Protocol):
    def send(
        self,
        *,
        target: ResolvedWebhookTarget,
        headers: dict[str, str],
        payload: bytes,
    ) -> WebhookHttpResult: ...


@dataclass(frozen=True, slots=True)
class ResolvedWebhookTarget:
    canonical_url: str
    server_name: str
    port: int
    request_target: str
    address: str


@dataclass(frozen=True, slots=True)
class WebhookHttpResult:
    status_code: int
    response_digest_sha256: str


@dataclass(frozen=True, slots=True)
class RegisteredWebhookEndpoint:
    endpoint_id: UUID
    tenant_id: UUID
    space_id: UUID | None
    project_id: UUID | None
    canonical_url: str
    event_types: tuple[str, ...]
    active_secret_version: int
    previous_secret_version: int | None
    previous_secret_valid_until: datetime | None
    status: str
    security_version: int


@dataclass(frozen=True, slots=True)
class EnqueuedWebhookDelivery:
    delivery_id: UUID
    endpoint_id: UUID
    event_id: UUID
    event_type: str
    event_version: int
    status: str
    attempt_count: int
    replay_generation: int


@dataclass(frozen=True, slots=True)
class WebhookDispatchResult:
    claimed: int
    delivered: int
    retried: int
    dead_lettered: int


@dataclass(frozen=True, slots=True)
class _ClaimedDelivery:
    delivery_id: UUID
    tenant_id: UUID
    endpoint_id: UUID
    canonical_url: str
    secret_ref: str
    active_secret_version: int
    previous_secret_version: int | None
    previous_secret_valid_until: datetime | None
    event_id: UUID
    event_type: str
    event_version: int
    occurred_at: datetime
    payload: dict[str, object]
    payload_sha256: str
    attempt_count: int
    max_attempts: int
    replay_generation: int
    lease_token: str


class SystemWebhookHostnameResolver:
    """Resolve all A/AAAA answers; policy validation happens after resolution."""

    def resolve(self, *, hostname: str, port: int) -> tuple[str, ...]:
        try:
            answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise WebhookDeliveryError(
                "webhook_dns_unavailable", "Webhook target cannot be resolved"
            ) from exc
        addresses = tuple(sorted({str(answer[4][0]) for answer in answers}))
        if not addresses or len(addresses) > 16:
            raise WebhookDeliveryError(
                "webhook_dns_invalid", "Webhook target resolution is invalid"
            )
        return addresses


class WebhookTargetPolicy:
    """Canonicalize HTTPS targets and reject every unsafe answer on each attempt."""

    def __init__(
        self,
        resolver: WebhookHostnameResolver | None = None,
        *,
        denied_hosts: frozenset[str] = _DEFAULT_DENIED_HOSTS,
        denied_networks: tuple[str, ...] = (),
    ) -> None:
        self._resolver = resolver or SystemWebhookHostnameResolver()
        normalized_hosts = {host.lower().rstrip(".") for host in denied_hosts}
        if any(not host or len(host) > 253 for host in normalized_hosts):
            raise ValueError("Webhook denied host configuration is invalid")
        self._denied_hosts = frozenset(normalized_hosts)
        try:
            self._denied_networks = _DEFAULT_DENIED_NETWORKS + tuple(
                ipaddress.ip_network(value, strict=True) for value in denied_networks
            )
        except ValueError as exc:
            raise ValueError("Webhook denied network configuration is invalid") from exc

    @staticmethod
    def canonicalize(url: str) -> str:
        if not isinstance(url, str) or not url or len(url) > 2048 or url.strip() != url:
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid")
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "\\" in url
            or any(ord(character) < 32 or ord(character) == 127 for character in url)
        ):
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid")
        try:
            hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            port = parsed.port or 443
        except (UnicodeError, ValueError) as exc:
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid") from exc
        if not hostname or len(hostname) > 253 or not 1 <= port <= 65535:
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            labels = hostname.split(".")
            if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
                raise WebhookDeliveryError(
                    "webhook_url_invalid", "Webhook URL is invalid"
                ) from None
        path = parsed.path or "/"
        query = parsed.query
        if (
            not path.startswith("/")
            or len(path) > 1536
            or len(query) > 512
            or _INVALID_PERCENT_ESCAPE.search(path)
            or _INVALID_PERCENT_ESCAPE.search(query)
        ):
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid")
        path = quote(path, safe="/!$&'()*+,-.:;=@_~%")
        query = quote(query, safe="!$&'()*+,-./:;=?@_~%")
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        authority = display_host if port == 443 else f"{display_host}:{port}"
        canonical = urlunsplit(("https", authority, path, query, ""))
        if len(canonical) > 2048:
            raise WebhookDeliveryError("webhook_url_invalid", "Webhook URL is invalid")
        return canonical

    def _host_forbidden(self, hostname: str) -> bool:
        return (
            hostname in self._denied_hosts
            or hostname.endswith((".localhost", ".local", ".internal", ".home.arpa"))
            or any(hostname.endswith(f".{suffix}") for suffix in self._denied_hosts)
        )

    def _address(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if "%" in value:
            raise WebhookDeliveryError(
                "webhook_dns_invalid", "Webhook target resolution is invalid"
            )
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise WebhookDeliveryError(
                "webhook_dns_invalid", "Webhook target resolution is invalid"
            ) from exc
        if (
            not address.is_global
            or address.is_loopback
            or address.is_link_local
            or address.is_private
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or any(address in network for network in self._denied_networks)
        ):
            raise WebhookDeliveryError(
                "webhook_target_forbidden", "Webhook target is not publicly routable"
            )
        return address

    def resolve(self, url: str) -> ResolvedWebhookTarget:
        canonical = self.canonicalize(url)
        parsed = urlsplit(canonical)
        hostname = cast(str, parsed.hostname)
        port = parsed.port or 443
        if self._host_forbidden(hostname):
            raise WebhookDeliveryError(
                "webhook_target_forbidden", "Webhook target is not publicly routable"
            )
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            answers = self._resolver.resolve(hostname=hostname, port=port)
        else:
            answers = (str(literal),)
        if not answers or len(answers) > 16:
            raise WebhookDeliveryError(
                "webhook_dns_invalid", "Webhook target resolution is invalid"
            )
        safe = tuple(sorted(str(self._address(value)) for value in set(answers)))
        request_target = parsed.path or "/"
        if parsed.query:
            request_target += f"?{parsed.query}"
        return ResolvedWebhookTarget(
            canonical_url=canonical,
            server_name=hostname,
            port=port,
            request_target=request_target,
            address=safe[0],
        )


class TlsPinnedWebhookHttpSender:
    """Connect to a validated IP while preserving original TLS SNI and Host identity."""

    def __init__(
        self,
        tls_context: ssl.SSLContext,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if (
            tls_context.verify_mode != ssl.CERT_REQUIRED
            or not tls_context.check_hostname
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise ValueError("Webhook TLS sender configuration is invalid")
        self._tls_context = tls_context
        self._tls_context.set_alpn_protocols(["http/1.1"])
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _headers(headers: dict[str, str]) -> bytes:
        encoded: list[bytes] = []
        for name, value in sorted(headers.items()):
            lowered = name.lower()
            if (
                not lowered
                or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                    for character in lowered
                )
                or not value
                or len(value) > 2048
                or any(character in value for character in ("\r", "\n", "\x00"))
            ):
                raise WebhookDeliveryError(
                    "webhook_request_invalid", "Webhook request headers are invalid"
                )
            encoded.append(f"{lowered}: {value}\r\n".encode("ascii"))
        return b"".join(encoded)

    @staticmethod
    def _response_head(sock: ssl.SSLSocket) -> bytes:
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(min(4096, _MAX_RESPONSE_HEAD + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > _MAX_RESPONSE_HEAD:
                raise WebhookDeliveryError(
                    "webhook_response_invalid", "Webhook response headers are oversized"
                )
        marker = response.find(b"\r\n\r\n")
        if marker < 0:
            raise WebhookDeliveryError(
                "webhook_response_invalid", "Webhook response headers are incomplete"
            )
        return bytes(response[: marker + 4])

    def send(
        self,
        *,
        target: ResolvedWebhookTarget,
        headers: dict[str, str],
        payload: bytes,
    ) -> WebhookHttpResult:
        if not 1 <= len(payload) <= _MAX_WIRE_PAYLOAD:
            raise WebhookDeliveryError(
                "webhook_payload_invalid", "Webhook payload size is invalid"
            )
        try:
            ipaddress.ip_address(target.address)
            target.server_name.encode("ascii")
        except (UnicodeEncodeError, ValueError) as exc:
            raise WebhookDeliveryError(
                "webhook_request_invalid", "Webhook request target is invalid"
            ) from exc
        try:
            ipaddress.ip_address(target.server_name)
        except ValueError:
            valid_server_name = all(
                _DNS_LABEL.fullmatch(label) is not None for label in target.server_name.split(".")
            )
        else:
            valid_server_name = True
        if (
            not target.server_name
            or len(target.server_name) > 253
            or not 1 <= target.port <= 65535
            or not valid_server_name
            or _HTTP_REQUEST_TARGET.fullmatch(target.request_target) is None
            or _INVALID_PERCENT_ESCAPE.search(target.request_target)
        ):
            raise WebhookDeliveryError(
                "webhook_request_invalid", "Webhook request target is invalid"
            )
        display_host = (
            f"[{target.server_name}]" if ":" in target.server_name else target.server_name
        )
        host = display_host if target.port == 443 else f"{display_host}:{target.port}"
        fixed_headers = {
            **headers,
            "accept": "application/json",
            "connection": "close",
            "content-length": str(len(payload)),
            "content-type": "application/json",
            "host": host,
            "user-agent": "omnigent-saas-webhook/1",
        }
        request = (
            f"POST {target.request_target} HTTP/1.1\r\n".encode("ascii")
            + self._headers(fixed_headers)
            + b"\r\n"
            + payload
        )
        try:
            with (
                socket.create_connection(
                    (target.address, target.port), timeout=self._timeout_seconds
                ) as raw,
                self._tls_context.wrap_socket(
                    raw, server_hostname=target.server_name
                ) as tls_socket,
            ):
                tls_socket.settimeout(self._timeout_seconds)
                tls_socket.sendall(request)
                response_head = self._response_head(tls_socket)
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            raise WebhookDeliveryError(
                "webhook_transport_unavailable", "Webhook transport is unavailable"
            ) from exc
        try:
            status_line = response_head.split(b"\r\n", 1)[0].decode("ascii")
            version, status_text, _reason = status_line.split(" ", 2)
            status = int(status_text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise WebhookDeliveryError(
                "webhook_response_invalid", "Webhook response is invalid"
            ) from exc
        if version != "HTTP/1.1" or not 100 <= status <= 599:
            raise WebhookDeliveryError("webhook_response_invalid", "Webhook response is invalid")
        return WebhookHttpResult(
            status_code=status,
            response_digest_sha256=hashlib.sha256(response_head).hexdigest(),
        )


def _time(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("Webhook time must include a timezone")
    return value.astimezone(timezone.utc)


def _database_time(value: datetime) -> datetime:
    """Treat SQLite's timezone-naive round trip as UTC; PostgreSQL remains aware."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_payload(payload: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError) as exc:
        raise WebhookDeliveryError(
            "webhook_payload_invalid", "Webhook event payload is invalid"
        ) from exc
    if not 2 <= len(encoded) <= _MAX_EVENT_PAYLOAD:
        raise WebhookDeliveryError(
            "webhook_payload_invalid", "Webhook event payload size is invalid"
        )
    return encoded


def _event_types(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(sorted(set(values)))
    if (
        not normalized
        or len(normalized) > _MAX_EVENT_TYPES
        or any(_EVENT_TYPE.fullmatch(value) is None for value in normalized)
    ):
        raise WebhookDeliveryError(
            "webhook_event_types_invalid", "Webhook event types are invalid"
        )
    return normalized


def _secret(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not 32 <= len(value) <= 128:
        raise WebhookDeliveryError("webhook_signing_key_invalid", "Webhook signing key is invalid")
    return value


class WebhookDeliveryControlPlane:
    """Register, enqueue, lease, sign, deliver, retry, and dead-letter Webhooks."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        target_policy: WebhookTargetPolicy,
        secret_provider: WebhookSecretProvider,
        sender: WebhookHttpSender,
        *,
        lease_duration: timedelta = timedelta(seconds=30),
        max_backoff: timedelta = timedelta(minutes=15),
        replay_authorizer: WebhookReplayAuthorizer | None = None,
    ) -> None:
        if lease_duration <= timedelta(0) or max_backoff <= timedelta(0):
            raise ValueError("Webhook lease and backoff must be positive")
        self._session_factory = session_factory
        self._target_policy = target_policy
        self._secret_provider = secret_provider
        self._sender = sender
        self._lease_duration = lease_duration
        self._max_backoff = max_backoff
        self._replay_authorizer = replay_authorizer

    @staticmethod
    def _endpoint(record: WebhookEndpointRecord) -> RegisteredWebhookEndpoint:
        return RegisteredWebhookEndpoint(
            endpoint_id=record.id,
            tenant_id=record.tenant_id,
            space_id=record.space_id,
            project_id=record.project_id,
            canonical_url=record.canonical_url,
            event_types=tuple(record.event_types),
            active_secret_version=record.active_secret_version,
            previous_secret_version=record.previous_secret_version,
            previous_secret_valid_until=(
                _database_time(record.previous_secret_valid_until)
                if record.previous_secret_valid_until is not None
                else None
            ),
            status=record.status,
            security_version=record.security_version,
        )

    def register_endpoint(
        self,
        *,
        tenant_id: UUID,
        space_id: UUID | None,
        project_id: UUID | None,
        url: str,
        event_types: tuple[str, ...],
        secret_ref: str,
        secret_version: int,
        created_by: UUID,
    ) -> RegisteredWebhookEndpoint:
        canonical_url = self._target_policy.resolve(url).canonical_url
        events = _event_types(event_types)
        if _SECRET_REF.fullmatch(secret_ref) is None or secret_version <= 0:
            raise WebhookDeliveryError(
                "webhook_secret_reference_invalid", "Webhook secret reference is invalid"
            )
        _secret(self._secret_provider.get_secret(secret_ref=secret_ref, version=secret_version))
        record = WebhookEndpointRecord(
            tenant_id=tenant_id,
            space_id=space_id,
            project_id=project_id,
            canonical_url=canonical_url,
            event_types=list(events),
            secret_ref=secret_ref,
            active_secret_version=secret_version,
            status="active",
            security_version=1,
            created_by=created_by,
        )
        try:
            with self._session_factory.begin() as db:
                db.add(record)
                db.flush()
                return self._endpoint(record)
        except IntegrityError as exc:
            raise WebhookDeliveryError(
                "webhook_endpoint_conflict", "Webhook endpoint conflicts with existing state"
            ) from exc

    def rotate_secret(
        self,
        *,
        endpoint_id: UUID,
        new_version: int,
        overlap: timedelta = timedelta(minutes=10),
        now: datetime | None = None,
    ) -> RegisteredWebhookEndpoint:
        changed_at = _time(now or _now())
        if new_version <= 0 or not timedelta(0) <= overlap <= timedelta(hours=24):
            raise WebhookDeliveryError(
                "webhook_secret_rotation_invalid", "Webhook secret rotation is invalid"
            )
        with self._session_factory() as db:
            observed = db.get(WebhookEndpointRecord, endpoint_id)
            if observed is None or observed.status != "active":
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            if new_version == observed.active_secret_version:
                return self._endpoint(observed)
            secret_ref = observed.secret_ref
        _secret(self._secret_provider.get_secret(secret_ref=secret_ref, version=new_version))
        with self._session_factory.begin() as db:
            record = db.execute(
                sa.select(WebhookEndpointRecord)
                .where(WebhookEndpointRecord.id == endpoint_id)
                .with_for_update()
            ).scalar_one_or_none()
            if record is None or record.status != "active":
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            if new_version == record.active_secret_version:
                return self._endpoint(record)
            if record.secret_ref != secret_ref:
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            previous = record.active_secret_version if overlap > timedelta(0) else None
            record.previous_secret_version = previous
            record.previous_secret_valid_until = changed_at + overlap if previous else None
            record.active_secret_version = new_version
            record.security_version += 1
            db.flush()
            return self._endpoint(record)

    def enqueue(
        self,
        *,
        endpoint_id: UUID,
        event_id: UUID,
        event_type: str,
        event_version: int,
        occurred_at: datetime,
        payload: dict[str, object],
        max_attempts: int = 8,
        now: datetime | None = None,
    ) -> EnqueuedWebhookDelivery:
        queued_at = _time(now or _now())
        occurred = _time(occurred_at)
        encoded = _canonical_payload(payload)
        if (
            _EVENT_TYPE.fullmatch(event_type) is None
            or event_version <= 0
            or not 1 <= max_attempts <= 32
            or occurred > queued_at + timedelta(minutes=5)
        ):
            raise WebhookDeliveryError("webhook_event_invalid", "Webhook event is invalid")
        with self._session_factory.begin() as db:
            endpoint = db.get(WebhookEndpointRecord, endpoint_id)
            if (
                endpoint is None
                or endpoint.status != "active"
                or event_type not in endpoint.event_types
            ):
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            existing = db.execute(
                sa.select(WebhookDeliveryRecord).where(
                    WebhookDeliveryRecord.endpoint_id == endpoint_id,
                    WebhookDeliveryRecord.event_id == event_id,
                )
            ).scalar_one_or_none()
            digest = hashlib.sha256(encoded).hexdigest()
            if existing is not None:
                if (
                    existing.event_type != event_type
                    or existing.event_version != event_version
                    or _database_time(existing.occurred_at) != occurred
                    or existing.payload_sha256 != digest
                    or existing.max_attempts != max_attempts
                ):
                    raise WebhookDeliveryError(
                        "webhook_event_conflict", "Webhook event conflicts with existing state"
                    )
                return EnqueuedWebhookDelivery(
                    existing.id,
                    existing.endpoint_id,
                    existing.event_id,
                    existing.event_type,
                    existing.event_version,
                    existing.status,
                    existing.attempt_count,
                    existing.replay_generation,
                )
            delivery = WebhookDeliveryRecord(
                tenant_id=endpoint.tenant_id,
                endpoint_id=endpoint.id,
                event_id=event_id,
                event_type=event_type,
                event_version=event_version,
                occurred_at=occurred,
                payload=payload,
                payload_sha256=digest,
                status="pending",
                attempt_count=0,
                max_attempts=max_attempts,
                available_at=queued_at,
                replay_generation=0,
            )
            try:
                with db.begin_nested():
                    db.add(delivery)
                    db.flush()
            except IntegrityError as exc:
                concurrent = db.execute(
                    sa.select(WebhookDeliveryRecord).where(
                        WebhookDeliveryRecord.endpoint_id == endpoint_id,
                        WebhookDeliveryRecord.event_id == event_id,
                    )
                ).scalar_one_or_none()
                if (
                    concurrent is None
                    or concurrent.event_type != event_type
                    or concurrent.event_version != event_version
                    or _database_time(concurrent.occurred_at) != occurred
                    or concurrent.payload_sha256 != digest
                    or concurrent.max_attempts != max_attempts
                ):
                    raise WebhookDeliveryError(
                        "webhook_event_conflict", "Webhook event conflicts with existing state"
                    ) from exc
                return EnqueuedWebhookDelivery(
                    concurrent.id,
                    concurrent.endpoint_id,
                    concurrent.event_id,
                    concurrent.event_type,
                    concurrent.event_version,
                    concurrent.status,
                    concurrent.attempt_count,
                    concurrent.replay_generation,
                )
            return EnqueuedWebhookDelivery(
                delivery.id,
                delivery.endpoint_id,
                delivery.event_id,
                delivery.event_type,
                delivery.event_version,
                delivery.status,
                delivery.attempt_count,
                delivery.replay_generation,
            )

    def requeue_dead_letter(
        self,
        *,
        delivery_id: UUID,
        replayed_by: UUID,
        now: datetime | None = None,
    ) -> EnqueuedWebhookDelivery:
        """Audited manual replay reuses the original Delivery and Event identities."""

        replayed_at = _time(now or _now())
        if self._replay_authorizer is None:
            raise WebhookDeliveryError(
                "webhook_replay_forbidden", "Webhook delivery replay is forbidden"
            )
        with self._session_factory() as db:
            observed = db.get(WebhookDeliveryRecord, delivery_id)
            if observed is None or observed.status != "dead_letter":
                raise WebhookDeliveryError(
                    "webhook_delivery_not_replayable", "Webhook delivery is not replayable"
                )
            endpoint = db.get(WebhookEndpointRecord, observed.endpoint_id)
            if endpoint is None or endpoint.status != "active":
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            tenant_id = observed.tenant_id
            endpoint_id = observed.endpoint_id
        if not self._replay_authorizer.authorize_replay(
            tenant_id=tenant_id,
            endpoint_id=endpoint_id,
            delivery_id=delivery_id,
            actor_id=replayed_by,
        ):
            raise WebhookDeliveryError(
                "webhook_replay_forbidden", "Webhook delivery replay is forbidden"
            )
        with self._session_factory.begin() as db:
            record = db.execute(
                sa.select(WebhookDeliveryRecord)
                .where(WebhookDeliveryRecord.id == delivery_id)
                .with_for_update()
            ).scalar_one_or_none()
            if (
                record is None
                or record.status != "dead_letter"
                or record.tenant_id != tenant_id
                or record.endpoint_id != endpoint_id
            ):
                raise WebhookDeliveryError(
                    "webhook_delivery_not_replayable", "Webhook delivery is not replayable"
                )
            endpoint = db.get(WebhookEndpointRecord, record.endpoint_id)
            if endpoint is None or endpoint.status != "active":
                raise WebhookDeliveryError(
                    "webhook_endpoint_unavailable", "Webhook endpoint is unavailable"
                )
            record.status = "retry"
            record.attempt_count = 0
            record.available_at = replayed_at
            record.response_status = None
            record.response_digest_sha256 = None
            record.last_error_code = None
            record.replay_generation += 1
            record.last_replayed_at = replayed_at
            record.last_replayed_by = replayed_by
            outbox_payload: dict[str, object] = {
                "delivery_id": str(record.id),
                "endpoint_id": str(record.endpoint_id),
                "event_id": str(record.event_id),
                "replay_generation": record.replay_generation,
                "replayed_by": str(replayed_by),
            }
            request_hash = hashlib.sha256(_canonical_payload(outbox_payload)).hexdigest()
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=record.tenant_id,
                    event_type="webhook.delivery.requeued",
                    aggregate_type="webhook_delivery",
                    aggregate_key=str(record.id),
                    payload=outbox_payload,
                    idempotency_key=(f"webhook-replay:{record.id}:{record.replay_generation}"),
                    request_hash=request_hash,
                    attempt_count=0,
                    available_at=replayed_at,
                    created_at=replayed_at,
                )
            )
            db.flush()
            return EnqueuedWebhookDelivery(
                record.id,
                record.endpoint_id,
                record.event_id,
                record.event_type,
                record.event_version,
                record.status,
                record.attempt_count,
                record.replay_generation,
            )

    def _claim(self, *, batch_size: int, now: datetime) -> list[_ClaimedDelivery]:
        with self._session_factory.begin() as db:
            query = (
                sa.select(WebhookDeliveryRecord)
                .join(WebhookEndpointRecord)
                .where(
                    WebhookEndpointRecord.status == "active",
                    WebhookDeliveryRecord.attempt_count < WebhookDeliveryRecord.max_attempts,
                    sa.or_(
                        sa.and_(
                            WebhookDeliveryRecord.status.in_(("pending", "retry")),
                            WebhookDeliveryRecord.available_at <= now,
                        ),
                        sa.and_(
                            WebhookDeliveryRecord.status == "leased",
                            WebhookDeliveryRecord.lease_expires_at < now,
                        ),
                    ),
                )
                .order_by(WebhookDeliveryRecord.available_at, WebhookDeliveryRecord.created_at)
                .limit(batch_size)
            )
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True, of=WebhookDeliveryRecord)
            records = list(db.execute(query).scalars())
            claimed: list[_ClaimedDelivery] = []
            for record in records:
                endpoint = db.get(WebhookEndpointRecord, record.endpoint_id)
                if endpoint is None or endpoint.status != "active":
                    continue
                token = secrets.token_urlsafe(32)
                record.status = "leased"
                record.attempt_count += 1
                record.leased_at = now
                record.lease_expires_at = now + self._lease_duration
                record.lease_token_hash = hashlib.sha256(token.encode()).hexdigest()
                record.last_error_code = None
                claimed.append(
                    _ClaimedDelivery(
                        delivery_id=record.id,
                        tenant_id=record.tenant_id,
                        endpoint_id=record.endpoint_id,
                        canonical_url=endpoint.canonical_url,
                        secret_ref=endpoint.secret_ref,
                        active_secret_version=endpoint.active_secret_version,
                        previous_secret_version=endpoint.previous_secret_version,
                        previous_secret_valid_until=(
                            _database_time(endpoint.previous_secret_valid_until)
                            if endpoint.previous_secret_valid_until is not None
                            else None
                        ),
                        event_id=record.event_id,
                        event_type=record.event_type,
                        event_version=record.event_version,
                        occurred_at=_database_time(record.occurred_at),
                        payload=record.payload,
                        payload_sha256=record.payload_sha256,
                        attempt_count=record.attempt_count,
                        max_attempts=record.max_attempts,
                        replay_generation=record.replay_generation,
                        lease_token=token,
                    )
                )
            db.flush()
            return claimed

    @staticmethod
    def _wire(delivery: _ClaimedDelivery) -> bytes:
        document: dict[str, object] = {
            "delivery_id": str(delivery.delivery_id),
            "replay_generation": delivery.replay_generation,
            "event": {
                "data": delivery.payload,
                "id": str(delivery.event_id),
                "occurred_at": delivery.occurred_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "type": delivery.event_type,
                "version": delivery.event_version,
            },
        }
        encoded = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        if len(encoded) > _MAX_WIRE_PAYLOAD:
            raise WebhookDeliveryError(
                "webhook_payload_invalid", "Webhook wire payload is oversized"
            )
        return encoded

    def _signatures(
        self, delivery: _ClaimedDelivery, *, payload: bytes, now: datetime
    ) -> tuple[str, str]:
        timestamp = str(int(now.timestamp()))
        message = b"\n".join(
            (
                timestamp.encode(),
                str(delivery.delivery_id).encode(),
                str(delivery.event_id).encode(),
                payload,
            )
        )
        versions = [delivery.active_secret_version]
        if (
            delivery.previous_secret_version is not None
            and delivery.previous_secret_valid_until is not None
            and delivery.previous_secret_valid_until > now
        ):
            versions.append(delivery.previous_secret_version)
        signatures = []
        for version in versions:
            key = _secret(
                self._secret_provider.get_secret(secret_ref=delivery.secret_ref, version=version)
            )
            signatures.append(f"v{version}={hmac.new(key, message, hashlib.sha256).hexdigest()}")
        return timestamp, ",".join(signatures)

    def _finish(
        self,
        delivery: _ClaimedDelivery,
        *,
        now: datetime,
        result: WebhookHttpResult | None,
        error_code: str | None,
        permanent: bool,
    ) -> str:
        token_hash = hashlib.sha256(delivery.lease_token.encode()).hexdigest()
        with self._session_factory.begin() as db:
            record = db.execute(
                sa.select(WebhookDeliveryRecord)
                .where(
                    WebhookDeliveryRecord.id == delivery.delivery_id,
                    WebhookDeliveryRecord.status == "leased",
                    WebhookDeliveryRecord.lease_token_hash == token_hash,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if record is None:
                raise WebhookDeliveryError("webhook_lease_lost", "Webhook delivery lease was lost")
            record.leased_at = None
            record.lease_expires_at = None
            record.lease_token_hash = None
            if result is not None and 200 <= result.status_code <= 299:
                record.status = "delivered"
                record.delivered_at = now
                record.response_status = result.status_code
                record.response_digest_sha256 = result.response_digest_sha256
                record.last_error_code = None
                return "delivered"
            record.response_status = result.status_code if result is not None else None
            record.response_digest_sha256 = (
                result.response_digest_sha256 if result is not None else None
            )
            record.last_error_code = error_code or "webhook_delivery_rejected"
            exhausted = record.attempt_count >= record.max_attempts
            if permanent or exhausted:
                record.status = "dead_letter"
                return "dead_letter"
            delay = min(
                self._max_backoff.total_seconds(),
                float(2 ** min(max(record.attempt_count - 1, 0), 12)),
            )
            record.status = "retry"
            record.available_at = now + timedelta(seconds=delay)
            return "retry"

    def dispatch_once(
        self, *, batch_size: int = 100, now: datetime | None = None
    ) -> WebhookDispatchResult:
        if not 1 <= batch_size <= 500:
            raise ValueError("Webhook batch size must be between 1 and 500")
        dispatched_at = _time(now or _now())
        claimed = self._claim(batch_size=batch_size, now=dispatched_at)
        delivered = retried = dead_lettered = 0
        for delivery in claimed:
            result: WebhookHttpResult | None = None
            error_code: str | None = None
            permanent = False
            try:
                target = self._target_policy.resolve(delivery.canonical_url)
                payload = self._wire(delivery)
                timestamp, signature = self._signatures(
                    delivery, payload=payload, now=dispatched_at
                )
                result = self._sender.send(
                    target=target,
                    headers={
                        "x-omnigent-delivery-id": str(delivery.delivery_id),
                        "x-omnigent-event-id": str(delivery.event_id),
                        "x-omnigent-event-type": delivery.event_type,
                        "x-omnigent-event-version": str(delivery.event_version),
                        "x-omnigent-replay-generation": str(delivery.replay_generation),
                        "x-omnigent-signature": signature,
                        "x-omnigent-timestamp": timestamp,
                    },
                    payload=payload,
                )
                permanent = 300 <= result.status_code < 400 or (
                    result.status_code in range(400, 500)
                    and result.status_code not in {408, 409, 425, 429}
                )
            except WebhookDeliveryError as exc:
                error_code = exc.code
                permanent = exc.code in {
                    "webhook_dns_invalid",
                    "webhook_payload_invalid",
                    "webhook_request_invalid",
                    "webhook_response_invalid",
                    "webhook_signing_key_invalid",
                    "webhook_target_forbidden",
                    "webhook_url_invalid",
                }
            except Exception:  # noqa: BLE001 - external providers fail to a stable retry code
                error_code = "webhook_delivery_unavailable"
            outcome = self._finish(
                delivery,
                now=dispatched_at,
                result=result,
                error_code=error_code,
                permanent=permanent,
            )
            delivered += outcome == "delivered"
            retried += outcome == "retry"
            dead_lettered += outcome == "dead_letter"
        return WebhookDispatchResult(
            claimed=len(claimed),
            delivered=delivered,
            retried=retried,
            dead_lettered=dead_lettered,
        )


__all__ = [
    "EnqueuedWebhookDelivery",
    "RegisteredWebhookEndpoint",
    "ResolvedWebhookTarget",
    "SystemWebhookHostnameResolver",
    "TlsPinnedWebhookHttpSender",
    "WebhookDeliveryControlPlane",
    "WebhookDeliveryError",
    "WebhookDispatchResult",
    "WebhookHostnameResolver",
    "WebhookHttpResult",
    "WebhookHttpSender",
    "WebhookReplayAuthorizer",
    "WebhookSecretProvider",
    "WebhookTargetPolicy",
]
