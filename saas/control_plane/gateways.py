"""Persistent Preview Gateway discovery and Relay certificate authority."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import sqlalchemy as sa
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.gateway_models import (
    PREVIEW_GATEWAY_CERTIFICATE_PURPOSES,
    PreviewGatewayCertificateRecord,
    PreviewGatewayInstanceRecord,
)

_GATEWAY_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_REGISTERED_STATUSES = frozenset(("starting", "active", "draining"))
_ROUTABLE_STATUSES = frozenset(("active", "draining"))
_INSTANCE_SAFE_COLUMNS = (
    PreviewGatewayInstanceRecord.id,
    PreviewGatewayInstanceRecord.connect_host,
    PreviewGatewayInstanceRecord.connect_port,
    PreviewGatewayInstanceRecord.server_name,
    PreviewGatewayInstanceRecord.failure_domain,
    PreviewGatewayInstanceRecord.source_revision,
    PreviewGatewayInstanceRecord.adapter_contract_version,
    PreviewGatewayInstanceRecord.status,
    PreviewGatewayInstanceRecord.registered_at,
    PreviewGatewayInstanceRecord.activated_at,
    PreviewGatewayInstanceRecord.last_heartbeat_at,
    PreviewGatewayInstanceRecord.lease_expires_at,
    PreviewGatewayInstanceRecord.released_at,
    PreviewGatewayInstanceRecord.release_reason,
)


class PreviewGatewayLifecycleError(RuntimeError):
    """Stable fail-closed error for Gateway discovery and certificate operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RegisteredPreviewGateway:
    """Non-secret receipt for one process-lifetime Gateway registration."""

    gateway_instance_id: str
    connect_host: str
    connect_port: int
    server_name: str
    failure_domain: str
    source_revision: str
    adapter_contract_version: str
    status: str
    registered_at: datetime
    activated_at: datetime | None
    last_heartbeat_at: datetime
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class ActivatedPreviewGatewayCertificate:
    """Non-secret receipt for one activated Preview Relay leaf."""

    certificate_id: UUID
    gateway_instance_id: str
    purpose: str
    fingerprint_sha256: str
    rotation_generation: int
    certificate_not_after: datetime
    trust_bundle_version: str


@dataclass(frozen=True, slots=True)
class _InspectedGatewayCertificate:
    gateway_instance_id: str
    fingerprint_sha256: str
    spki_sha256: str
    serial_hex: str
    spiffe_id: str
    endpoint_names: frozenset[str]
    not_before: datetime
    not_after: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _time(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _text(value: str, *, field: str, maximum: int) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise PreviewGatewayLifecycleError(
            f"preview_gateway_{field}_invalid", f"Preview Gateway {field} is invalid"
        )
    return normalized


def _host(value: str, *, field: str) -> str:
    normalized = value.strip().lower()
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        if not _DNS_NAME.fullmatch(normalized):
            raise PreviewGatewayLifecycleError(
                "preview_gateway_endpoint_invalid", f"Preview Gateway {field} is invalid"
            ) from None
        return normalized


def _token_hash(token: str) -> str:
    if len(token) < 32 or len(token) > 512 or token.strip() != token or "\x00" in token:
        raise PreviewGatewayLifecycleError(
            "preview_gateway_token_invalid", "Preview Gateway registration token is invalid"
        )
    return hashlib.sha256(token.encode()).hexdigest()


def _duration(value: timedelta, *, maximum: timedelta) -> None:
    if value <= timedelta(0) or value > maximum:
        raise PreviewGatewayLifecycleError(
            "preview_gateway_lease_invalid", "Preview Gateway lease duration is invalid"
        )


def _event(
    *,
    aggregate_type: str,
    aggregate_key: str,
    event_type: str,
    payload: dict[str, object],
) -> ControlPlaneOutboxEvent:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    suffix = event_type.rsplit(".", 1)[-1]
    return ControlPlaneOutboxEvent(
        tenant_id=None,
        aggregate_type=aggregate_type,
        aggregate_key=aggregate_key,
        event_type=event_type,
        payload=payload,
        idempotency_key=f"{aggregate_type}:{aggregate_key}:{suffix}",
        request_hash=hashlib.sha256(encoded).hexdigest(),
    )


def _inspect_gateway_certificate(
    certificate_der: bytes,
    *,
    purpose: str,
) -> _InspectedGatewayCertificate:
    if purpose not in PREVIEW_GATEWAY_CERTIFICATE_PURPOSES:
        raise PreviewGatewayLifecycleError(
            "preview_gateway_certificate_purpose_invalid",
            "Preview Gateway certificate purpose is invalid",
        )
    if not certificate_der or len(certificate_der) > 32_768:
        raise PreviewGatewayLifecycleError(
            "preview_gateway_certificate_invalid", "Preview Gateway certificate is invalid"
        )
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        subject_alt_name = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        signature_hash = certificate.signature_hash_algorithm
    except (UnsupportedAlgorithm, ValueError, x509.ExtensionNotFound, TypeError) as exc:
        raise PreviewGatewayLifecycleError(
            "preview_gateway_certificate_invalid", "Preview Gateway certificate is invalid"
        ) from exc

    expected_eku = (
        ExtendedKeyUsageOID.CLIENT_AUTH
        if purpose == "preview_relay_client"
        else ExtendedKeyUsageOID.SERVER_AUTH
    )
    uri_names = list(subject_alt_name.get_values_for_type(x509.UniformResourceIdentifier))
    dns_names = [name.lower() for name in subject_alt_name.get_values_for_type(x509.DNSName)]
    ip_names = [str(name) for name in subject_alt_name.get_values_for_type(x509.IPAddress)]
    all_names = list(subject_alt_name)
    expected_name_count = (
        1 if purpose == "preview_relay_client" else 1 + len(dns_names) + len(ip_names)
    )
    if (
        basic_constraints.ca
        or not key_usage.digital_signature
        or key_usage.key_cert_sign
        or key_usage.crl_sign
        or set(extended_usage) != {expected_eku}
        or len(uri_names) != 1
        or len(all_names) != expected_name_count
        or (purpose == "preview_relay_server" and not dns_names and not ip_names)
        or signature_hash is None
        or signature_hash.name.lower() not in {"sha256", "sha384", "sha512"}
    ):
        raise PreviewGatewayLifecycleError(
            "preview_gateway_certificate_profile_invalid",
            "Preview Gateway certificate profile is invalid",
        )
    spiffe_id = uri_names[0]
    prefix = "spiffe://omnigent/preview-gateway/"
    gateway_instance_id = spiffe_id[len(prefix) :] if spiffe_id.startswith(prefix) else ""
    if not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id):
        raise PreviewGatewayLifecycleError(
            "preview_gateway_certificate_identity_invalid",
            "Preview Gateway certificate identity is invalid",
        )
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _InspectedGatewayCertificate(
        gateway_instance_id=gateway_instance_id,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        spki_sha256=hashlib.sha256(public_key).hexdigest(),
        serial_hex=format(certificate.serial_number, "x"),
        spiffe_id=spiffe_id,
        endpoint_names=frozenset((*dns_names, *ip_names)),
        not_before=_aware(certificate.not_valid_before_utc),
        not_after=_aware(certificate.not_valid_after_utc),
    )


class PreviewGatewayDirectoryAuthority:
    """Register, heartbeat, retire, and resolve immutable Gateway endpoints."""

    def __init__(
        self,
        authority_session_factory: sessionmaker[Session],
        *,
        service_session_factory: sessionmaker[Session],
        maximum_lease_duration: timedelta = timedelta(minutes=2),
    ) -> None:
        if maximum_lease_duration <= timedelta(0):
            raise ValueError("maximum_lease_duration must be positive")
        self._authority_session_factory = authority_session_factory
        self._service_session_factory = service_session_factory
        self._maximum_lease_duration = maximum_lease_duration

    def register_gateway(
        self,
        *,
        gateway_instance_id: str,
        connect_host: str,
        connect_port: int,
        server_name: str,
        failure_domain: str,
        source_revision: str,
        adapter_contract_version: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        """Register a globally unique process identity; an old ID is never reusable."""

        registered_at = _time(now or _utcnow(), field="registration time")
        _duration(lease_duration, maximum=self._maximum_lease_duration)
        if not _GATEWAY_INSTANCE.fullmatch(gateway_instance_id):
            raise PreviewGatewayLifecycleError(
                "preview_gateway_identity_invalid", "Preview Gateway identity is invalid"
            )
        normalized_connect_host = _host(connect_host, field="connect host")
        normalized_server_name = _host(server_name, field="server name")
        if isinstance(connect_port, bool) or not 1 <= connect_port <= 65_535:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_endpoint_invalid", "Preview Gateway port is invalid"
            )
        token_hash = _token_hash(registration_token)
        try:
            with self._authority_session_factory.begin() as db:
                if db.get(PreviewGatewayInstanceRecord, gateway_instance_id) is not None:
                    raise PreviewGatewayLifecycleError(
                        "preview_gateway_identity_reused",
                        "Preview Gateway identity cannot be reused",
                    )
                record = PreviewGatewayInstanceRecord(
                    id=gateway_instance_id,
                    connect_host=normalized_connect_host,
                    connect_port=connect_port,
                    server_name=normalized_server_name,
                    failure_domain=_text(failure_domain, field="failure_domain", maximum=128),
                    source_revision=_text(source_revision, field="source_revision", maximum=64),
                    adapter_contract_version=_text(
                        adapter_contract_version,
                        field="adapter_contract_version",
                        maximum=32,
                    ),
                    registration_token_hash=token_hash,
                    status="starting",
                    registered_at=registered_at,
                    last_heartbeat_at=registered_at,
                    lease_expires_at=registered_at + lease_duration,
                )
                db.add(record)
                db.flush()
                db.add(self._instance_event(record, event_type="preview.gateway.registered"))
                return self._receipt(record)
        except sa.exc.IntegrityError as exc:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_identity_reused",
                "Preview Gateway identity or registration token cannot be reused",
            ) from exc

    def heartbeat_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        lease_duration: timedelta = timedelta(seconds=45),
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        """Extend only the live process holding the unpersisted registration token."""

        heartbeat_at = _time(now or _utcnow(), field="heartbeat time")
        _duration(lease_duration, maximum=self._maximum_lease_duration)
        token_hash = _token_hash(registration_token)
        with self._service_session_factory.begin() as db:
            record = self._service_record(
                db,
                gateway_instance_id=gateway_instance_id,
                registration_token_hash=token_hash,
                lock=True,
            )
            if (
                record.status not in _REGISTERED_STATUSES
                or heartbeat_at >= record.lease_expires_at
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_lease_stale", "Preview Gateway lease is stale"
                )
            if heartbeat_at < record.last_heartbeat_at:
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_time_reversed", "Preview Gateway time cannot move backwards"
                )
            lease_expires_at = max(record.lease_expires_at, heartbeat_at + lease_duration)
            db.execute(
                sa.update(PreviewGatewayInstanceRecord)
                .where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
                .values(last_heartbeat_at=heartbeat_at, lease_expires_at=lease_expires_at)
            )
            return RegisteredPreviewGateway(
                gateway_instance_id=record.gateway_instance_id,
                connect_host=record.connect_host,
                connect_port=record.connect_port,
                server_name=record.server_name,
                failure_domain=record.failure_domain,
                source_revision=record.source_revision,
                adapter_contract_version=record.adapter_contract_version,
                status=record.status,
                registered_at=record.registered_at,
                activated_at=record.activated_at,
                last_heartbeat_at=heartbeat_at,
                lease_expires_at=lease_expires_at,
            )

    def activate_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> RegisteredPreviewGateway:
        """Publish a bound listener only after both purpose-separated leaves exist."""

        activated_at = _time(now or _utcnow(), field="activation time")
        token_hash = _token_hash(registration_token)
        with self._authority_session_factory.begin() as db:
            instance = db.scalar(
                sa.select(PreviewGatewayInstanceRecord)
                .where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
                .with_for_update()
            )
            if instance is None or not hmac.compare_digest(
                instance.registration_token_hash, token_hash
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_token_denied",
                    "Preview Gateway registration token is denied",
                )
            record = self._receipt(instance)
            if record.status == "active":
                return record
            if record.status != "starting" or activated_at >= record.lease_expires_at:
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_activation_stale",
                    "Preview Gateway activation is stale",
                )
            if activated_at < record.last_heartbeat_at:
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_time_reversed", "Preview Gateway time cannot move backwards"
                )
            active_certificates = tuple(
                db.execute(
                    sa.select(
                        PreviewGatewayCertificateRecord.purpose,
                        PreviewGatewayCertificateRecord.trust_bundle_version,
                    ).where(
                        PreviewGatewayCertificateRecord.gateway_instance_id == gateway_instance_id,
                        PreviewGatewayCertificateRecord.status == "active",
                        PreviewGatewayCertificateRecord.certificate_not_before <= activated_at,
                        PreviewGatewayCertificateRecord.certificate_not_after > activated_at,
                    )
                )
            )
            purposes = frozenset(row.purpose for row in active_certificates)
            trust_bundles = frozenset(row.trust_bundle_version for row in active_certificates)
            if (
                purposes != frozenset(PREVIEW_GATEWAY_CERTIFICATE_PURPOSES)
                or len(trust_bundles) != 1
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_certificates_incomplete",
                    "Preview Gateway certificate pair is incomplete or inconsistent",
                )
            instance.status = "active"
            instance.activated_at = activated_at
            active = RegisteredPreviewGateway(
                gateway_instance_id=record.gateway_instance_id,
                connect_host=record.connect_host,
                connect_port=record.connect_port,
                server_name=record.server_name,
                failure_domain=record.failure_domain,
                source_revision=record.source_revision,
                adapter_contract_version=record.adapter_contract_version,
                status="active",
                registered_at=record.registered_at,
                activated_at=activated_at,
                last_heartbeat_at=record.last_heartbeat_at,
                lease_expires_at=record.lease_expires_at,
            )
            db.add(self._receipt_event(active, event_type="preview.gateway.activated"))
            return active

    def begin_draining(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> bool:
        """Stop new ownership claims while retaining existing Relay routes temporarily."""

        draining_at = _time(now or _utcnow(), field="drain time")
        token_hash = _token_hash(registration_token)
        with self._service_session_factory.begin() as db:
            record = self._service_record(
                db,
                gateway_instance_id=gateway_instance_id,
                registration_token_hash=token_hash,
                lock=True,
            )
            if record.status == "draining":
                return False
            if record.status != "active" or draining_at >= record.lease_expires_at:
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_lifecycle_stale", "Preview Gateway lifecycle is stale"
                )
            db.execute(
                sa.update(PreviewGatewayInstanceRecord)
                .where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
                .values(status="draining")
            )
            draining = RegisteredPreviewGateway(
                gateway_instance_id=record.gateway_instance_id,
                connect_host=record.connect_host,
                connect_port=record.connect_port,
                server_name=record.server_name,
                failure_domain=record.failure_domain,
                source_revision=record.source_revision,
                adapter_contract_version=record.adapter_contract_version,
                status="draining",
                registered_at=record.registered_at,
                activated_at=record.activated_at,
                last_heartbeat_at=record.last_heartbeat_at,
                lease_expires_at=record.lease_expires_at,
            )
            db.add(self._receipt_event(draining, event_type="preview.gateway.draining"))
            return True

    def release_gateway(
        self,
        *,
        gateway_instance_id: str,
        registration_token: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Release one exact process identity; it can never be revived or re-registered."""

        released_at = _time(now or _utcnow(), field="release time")
        token_hash = _token_hash(registration_token)
        normalized_reason = _text(reason, field="release_reason", maximum=256)
        with self._service_session_factory.begin() as db:
            record = self._service_record(
                db,
                gateway_instance_id=gateway_instance_id,
                registration_token_hash=token_hash,
                lock=True,
            )
            if record.status in {"released", "expired"}:
                return False
            if released_at < record.last_heartbeat_at:
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_time_reversed", "Preview Gateway time cannot move backwards"
                )
            db.execute(
                sa.update(PreviewGatewayInstanceRecord)
                .where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
                .values(
                    status="released",
                    released_at=released_at,
                    release_reason=normalized_reason,
                )
            )
            released = RegisteredPreviewGateway(
                gateway_instance_id=record.gateway_instance_id,
                connect_host=record.connect_host,
                connect_port=record.connect_port,
                server_name=record.server_name,
                failure_domain=record.failure_domain,
                source_revision=record.source_revision,
                adapter_contract_version=record.adapter_contract_version,
                status="released",
                registered_at=record.registered_at,
                activated_at=record.activated_at,
                last_heartbeat_at=record.last_heartbeat_at,
                lease_expires_at=record.lease_expires_at,
            )
            db.add(self._receipt_event(released, event_type="preview.gateway.released"))
            return True

    def reconcile_expired(
        self, *, now: datetime | None = None, limit: int = 100
    ) -> tuple[str, ...]:
        """Expire bounded stale instances under the platform authority."""

        reconciled_at = _time(now or _utcnow(), field="reconcile time")
        if not 1 <= limit <= 1000:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_reconcile_limit_invalid", "Reconcile limit is invalid"
            )
        expired: list[str] = []
        with self._authority_session_factory.begin() as db:
            query = (
                sa.select(PreviewGatewayInstanceRecord)
                .where(
                    PreviewGatewayInstanceRecord.status.in_(tuple(_REGISTERED_STATUSES)),
                    PreviewGatewayInstanceRecord.lease_expires_at <= reconciled_at,
                )
                .order_by(PreviewGatewayInstanceRecord.lease_expires_at)
                .limit(limit)
            )
            query = query.with_for_update(skip_locked=db.get_bind().dialect.name == "postgresql")
            for record in db.scalars(query):
                record.status = "expired"
                record.released_at = reconciled_at
                record.release_reason = "gateway_lease_expired"
                db.add(self._instance_event(record, event_type="preview.gateway.expired"))
                expired.append(record.id)
        return tuple(expired)

    def resolve(self, placement: object):
        """Resolve only the active endpoint named by a server-selected Placement."""

        from saas.preview_relay_transport import PreviewRelayEndpoint

        gateway_instance_id = getattr(placement, "gateway_instance_id", None)
        if not isinstance(gateway_instance_id, str) or not _GATEWAY_INSTANCE.fullmatch(
            gateway_instance_id
        ):
            raise PreviewGatewayLifecycleError(
                "preview_gateway_route_invalid", "Preview Gateway route is invalid"
            )
        now = _utcnow()
        with self._service_session_factory.begin() as db:
            row = db.execute(
                sa.select(
                    PreviewGatewayInstanceRecord.connect_host,
                    PreviewGatewayInstanceRecord.connect_port,
                    PreviewGatewayInstanceRecord.server_name,
                    PreviewGatewayInstanceRecord.status,
                    PreviewGatewayInstanceRecord.lease_expires_at,
                ).where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
            ).one_or_none()
            if (
                row is None
                or row.status not in _ROUTABLE_STATUSES
                or now >= _aware(row.lease_expires_at)
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_route_unavailable", "Preview Gateway route is unavailable"
                )
            return PreviewRelayEndpoint(row.connect_host, row.connect_port, row.server_name)

    def _service_record(
        self,
        db: Session,
        *,
        gateway_instance_id: str,
        registration_token_hash: str,
        lock: bool,
    ) -> RegisteredPreviewGateway:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text("SELECT set_config('app.gateway_registration_token_hash', :digest, true)"),
                {"digest": registration_token_hash},
            )
        else:
            stored = db.scalar(
                sa.select(PreviewGatewayInstanceRecord.registration_token_hash).where(
                    PreviewGatewayInstanceRecord.id == gateway_instance_id
                )
            )
            if stored is None or not hmac.compare_digest(stored, registration_token_hash):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_token_denied", "Preview Gateway registration token is denied"
                )
        query = sa.select(*_INSTANCE_SAFE_COLUMNS).where(
            PreviewGatewayInstanceRecord.id == gateway_instance_id
        )
        if lock:
            query = query.with_for_update()
        row = db.execute(query).one_or_none()
        if row is None:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_token_denied", "Preview Gateway registration token is denied"
            )
        return RegisteredPreviewGateway(
            gateway_instance_id=row.id,
            connect_host=row.connect_host,
            connect_port=row.connect_port,
            server_name=row.server_name,
            failure_domain=row.failure_domain,
            source_revision=row.source_revision,
            adapter_contract_version=row.adapter_contract_version,
            status=row.status,
            registered_at=_aware(row.registered_at),
            activated_at=_aware(row.activated_at) if row.activated_at is not None else None,
            last_heartbeat_at=_aware(row.last_heartbeat_at),
            lease_expires_at=_aware(row.lease_expires_at),
        )

    @staticmethod
    def _receipt(record: PreviewGatewayInstanceRecord) -> RegisteredPreviewGateway:
        return RegisteredPreviewGateway(
            gateway_instance_id=record.id,
            connect_host=record.connect_host,
            connect_port=record.connect_port,
            server_name=record.server_name,
            failure_domain=record.failure_domain,
            source_revision=record.source_revision,
            adapter_contract_version=record.adapter_contract_version,
            status=record.status,
            registered_at=_aware(record.registered_at),
            activated_at=(
                _aware(record.activated_at) if record.activated_at is not None else None
            ),
            last_heartbeat_at=_aware(record.last_heartbeat_at),
            lease_expires_at=_aware(record.lease_expires_at),
        )

    @staticmethod
    def _instance_event(
        record: PreviewGatewayInstanceRecord, *, event_type: str
    ) -> ControlPlaneOutboxEvent:
        return PreviewGatewayDirectoryAuthority._receipt_event(
            PreviewGatewayDirectoryAuthority._receipt(record), event_type=event_type
        )

    @staticmethod
    def _receipt_event(
        record: RegisteredPreviewGateway, *, event_type: str
    ) -> ControlPlaneOutboxEvent:
        return _event(
            aggregate_type="preview_gateway_instance",
            aggregate_key=record.gateway_instance_id,
            event_type=event_type,
            payload={
                "adapter_contract_version": record.adapter_contract_version,
                "failure_domain": record.failure_domain,
                "gateway_instance_id": record.gateway_instance_id,
                "source_revision": record.source_revision,
                "status": record.status,
            },
        )


class PreviewGatewayCertificateAuthority:
    """Rotate and authorize purpose-separated Preview Relay leaves."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        accepted_trust_bundle_versions: Collection[str],
        maximum_certificate_lifetime: timedelta = timedelta(hours=24),
        maximum_rotation_overlap: timedelta = timedelta(minutes=15),
        allowed_clock_skew: timedelta = timedelta(minutes=2),
    ) -> None:
        versions = frozenset(
            _text(value, field="trust_bundle_version", maximum=64)
            for value in accepted_trust_bundle_versions
        )
        if (
            not versions
            or maximum_certificate_lifetime <= timedelta(0)
            or maximum_rotation_overlap < timedelta(0)
            or allowed_clock_skew < timedelta(0)
        ):
            raise ValueError("Preview Gateway certificate authority policy is invalid")
        self._session_factory = session_factory
        self._accepted_trust_bundle_versions = versions
        self._maximum_certificate_lifetime = maximum_certificate_lifetime
        self._maximum_rotation_overlap = maximum_rotation_overlap
        self._allowed_clock_skew = allowed_clock_skew

    def activate_certificate(
        self,
        *,
        gateway_instance_id: str,
        purpose: str,
        certificate_der: bytes,
        trust_bundle_version: str,
        rotation_overlap: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ActivatedPreviewGatewayCertificate:
        activated_at = _time(now or _utcnow(), field="activation time")
        normalized_bundle = _text(trust_bundle_version, field="trust_bundle_version", maximum=64)
        if normalized_bundle not in self._accepted_trust_bundle_versions:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_certificate_trust_bundle_unapproved",
                "Preview Gateway certificate trust bundle is not approved",
            )
        if rotation_overlap < timedelta(0) or rotation_overlap > self._maximum_rotation_overlap:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_certificate_rotation_invalid",
                "Preview Gateway certificate rotation is invalid",
            )
        inspected = _inspect_gateway_certificate(certificate_der, purpose=purpose)
        if inspected.gateway_instance_id != gateway_instance_id:
            raise PreviewGatewayLifecycleError(
                "preview_gateway_certificate_identity_mismatch",
                "Preview Gateway certificate does not match the selected Gateway",
            )
        if (
            inspected.not_before > activated_at + self._allowed_clock_skew
            or inspected.not_after <= activated_at
            or inspected.not_after - inspected.not_before > self._maximum_certificate_lifetime
        ):
            raise PreviewGatewayLifecycleError(
                "preview_gateway_certificate_validity_invalid",
                "Preview Gateway certificate validity is invalid",
            )
        with self._session_factory.begin() as db:
            gateway = db.scalar(
                sa.select(PreviewGatewayInstanceRecord)
                .where(PreviewGatewayInstanceRecord.id == gateway_instance_id)
                .with_for_update()
            )
            if (
                gateway is None
                or gateway.status not in _REGISTERED_STATUSES
                or activated_at >= _aware(gateway.lease_expires_at)
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_certificate_gateway_stale",
                    "Preview Gateway certificate target is stale",
                )
            if purpose == "preview_relay_server" and inspected.endpoint_names != frozenset(
                (gateway.server_name,)
            ):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_certificate_endpoint_mismatch",
                    "Preview Gateway server certificate does not cover its endpoint",
                )
            existing = db.scalar(
                sa.select(PreviewGatewayCertificateRecord).where(
                    PreviewGatewayCertificateRecord.fingerprint_sha256
                    == inspected.fingerprint_sha256
                )
            )
            if existing is not None:
                if (
                    existing.status == "active"
                    and existing.gateway_instance_id == gateway_instance_id
                    and existing.purpose == purpose
                    and existing.trust_bundle_version == normalized_bundle
                ):
                    return self._certificate_receipt(existing)
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_certificate_reuse_invalid",
                    "Preview Gateway certificate cannot be reused",
                )
            previous = list(
                db.scalars(
                    sa.select(PreviewGatewayCertificateRecord)
                    .where(
                        PreviewGatewayCertificateRecord.gateway_instance_id == gateway_instance_id,
                        PreviewGatewayCertificateRecord.purpose == purpose,
                        PreviewGatewayCertificateRecord.status.in_(("active", "retiring")),
                    )
                    .with_for_update()
                )
            )
            retire_at = activated_at + rotation_overlap
            for record in previous:
                if _aware(record.activated_at) > activated_at:
                    raise PreviewGatewayLifecycleError(
                        "preview_gateway_certificate_rotation_invalid",
                        "Preview Gateway certificate rotation cannot move backwards",
                    )
                record.status = "retiring"
                deadline = min(_aware(record.certificate_not_after), retire_at)
                if record.retire_at is not None:
                    deadline = min(_aware(record.retire_at), deadline)
                record.retire_at = deadline
            generation = (
                int(
                    db.scalar(
                        sa.select(
                            sa.func.coalesce(
                                sa.func.max(PreviewGatewayCertificateRecord.rotation_generation),
                                0,
                            )
                        ).where(
                            PreviewGatewayCertificateRecord.gateway_instance_id
                            == gateway_instance_id,
                            PreviewGatewayCertificateRecord.purpose == purpose,
                        )
                    )
                    or 0
                )
                + 1
            )
            record = PreviewGatewayCertificateRecord(
                gateway_instance_id=gateway_instance_id,
                purpose=purpose,
                fingerprint_sha256=inspected.fingerprint_sha256,
                spki_sha256=inspected.spki_sha256,
                serial_hex=inspected.serial_hex,
                spiffe_id=inspected.spiffe_id,
                trust_bundle_version=normalized_bundle,
                rotation_generation=generation,
                certificate_not_before=inspected.not_before,
                certificate_not_after=inspected.not_after,
                status="active",
                activated_at=activated_at,
            )
            db.add(record)
            db.flush()
            db.add(
                self._certificate_event(record, event_type="preview.gateway_certificate.activated")
            )
            return self._certificate_receipt(record)

    def revoke_certificate(
        self,
        *,
        fingerprint_sha256: str,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        revoked_at = _time(now or _utcnow(), field="revocation time")
        fingerprint = fingerprint_sha256.lower()
        if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise PreviewGatewayLifecycleError(
                "preview_gateway_certificate_fingerprint_invalid",
                "Preview Gateway certificate fingerprint is invalid",
            )
        normalized_reason = _text(reason, field="revocation_reason", maximum=256)
        with self._session_factory.begin() as db:
            record = db.scalar(
                sa.select(PreviewGatewayCertificateRecord)
                .where(PreviewGatewayCertificateRecord.fingerprint_sha256 == fingerprint)
                .with_for_update()
            )
            if record is None:
                return False
            if record.status == "revoked":
                return True
            if revoked_at < _aware(record.activated_at):
                raise PreviewGatewayLifecycleError(
                    "preview_gateway_certificate_revocation_time_invalid",
                    "Preview Gateway certificate revocation cannot precede activation",
                )
            record.status = "revoked"
            record.revoked_at = revoked_at
            record.revocation_reason = normalized_reason
            record.retire_at = record.retire_at or revoked_at
            db.add(
                self._certificate_event(record, event_type="preview.gateway_certificate.revoked")
            )
            return True

    def is_preview_gateway_certificate_authorized(
        self,
        *,
        gateway_instance_id: str,
        certificate_der: bytes,
        purpose: str,
        now: datetime | None = None,
    ) -> bool:
        checked_at = _time(now or _utcnow(), field="authorization time")
        try:
            inspected = _inspect_gateway_certificate(certificate_der, purpose=purpose)
        except PreviewGatewayLifecycleError:
            return False
        if inspected.gateway_instance_id != gateway_instance_id:
            return False
        with self._session_factory.begin() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text(
                        "SELECT set_config('app.presented_certificate_fingerprint', "
                        ":fingerprint, true), "
                        "set_config('app.presented_certificate_purpose', :purpose, true)"
                    ),
                    {"fingerprint": inspected.fingerprint_sha256, "purpose": purpose},
                )
            row = db.execute(
                sa.select(
                    PreviewGatewayCertificateRecord,
                    PreviewGatewayInstanceRecord.status.label("gateway_status"),
                    PreviewGatewayInstanceRecord.lease_expires_at.label(
                        "gateway_lease_expires_at"
                    ),
                    PreviewGatewayInstanceRecord.server_name.label("gateway_server_name"),
                )
                .join(
                    PreviewGatewayInstanceRecord,
                    PreviewGatewayInstanceRecord.id
                    == PreviewGatewayCertificateRecord.gateway_instance_id,
                )
                .where(
                    PreviewGatewayCertificateRecord.fingerprint_sha256
                    == inspected.fingerprint_sha256,
                    PreviewGatewayCertificateRecord.purpose == purpose,
                )
            ).first()
            if row is None:
                return False
            record = row[0]
            accepted_lifecycle = record.status == "active" or (
                record.status == "retiring"
                and record.retire_at is not None
                and checked_at < _aware(record.retire_at)
            )
            endpoint_matches = purpose == "preview_relay_client" or (
                inspected.endpoint_names == frozenset((row.gateway_server_name,))
            )
            return bool(
                accepted_lifecycle
                and row.gateway_status in _ROUTABLE_STATUSES
                and checked_at < _aware(row.gateway_lease_expires_at)
                and endpoint_matches
                and record.trust_bundle_version in self._accepted_trust_bundle_versions
                and _aware(record.certificate_not_before)
                <= checked_at
                < _aware(record.certificate_not_after)
                and record.gateway_instance_id == gateway_instance_id
                and record.spiffe_id == inspected.spiffe_id
                and record.spki_sha256 == inspected.spki_sha256
                and record.serial_hex == inspected.serial_hex
                and _aware(record.certificate_not_before) == inspected.not_before
                and _aware(record.certificate_not_after) == inspected.not_after
            )

    @staticmethod
    def _certificate_receipt(
        record: PreviewGatewayCertificateRecord,
    ) -> ActivatedPreviewGatewayCertificate:
        return ActivatedPreviewGatewayCertificate(
            certificate_id=record.id,
            gateway_instance_id=record.gateway_instance_id,
            purpose=record.purpose,
            fingerprint_sha256=record.fingerprint_sha256,
            rotation_generation=record.rotation_generation,
            certificate_not_after=_aware(record.certificate_not_after),
            trust_bundle_version=record.trust_bundle_version,
        )

    @staticmethod
    def _certificate_event(
        record: PreviewGatewayCertificateRecord, *, event_type: str
    ) -> ControlPlaneOutboxEvent:
        return _event(
            aggregate_type="preview_gateway_certificate",
            aggregate_key=record.fingerprint_sha256,
            event_type=event_type,
            payload={
                "certificate_id": str(record.id),
                "fingerprint_sha256": record.fingerprint_sha256,
                "gateway_instance_id": record.gateway_instance_id,
                "purpose": record.purpose,
                "rotation_generation": record.rotation_generation,
                "trust_bundle_version": record.trust_bundle_version,
            },
        )


__all__ = [
    "ActivatedPreviewGatewayCertificate",
    "PreviewGatewayCertificateAuthority",
    "PreviewGatewayDirectoryAuthority",
    "PreviewGatewayLifecycleError",
    "RegisteredPreviewGateway",
]
