"""One-use, certificate-bound Preview Runner tunnel registration."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.runner.identity import token_bound_runner_id
from saas.preview_relay_transport import PreviewRelayEndpointPolicy, PreviewRelayTransportError


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    if (
        not 32 <= len(token) <= 512
        or token.strip() != token
        or "\x00" in token
        or not token.isascii()
    ):
        raise PreviewTunnelRegistrationError("preview_tunnel_token_invalid")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class PreviewTunnelRegistrationError(RuntimeError):
    def __init__(self, code: str, message: str = "Preview tunnel is unavailable") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewTunnelRegistrationGrant:
    registration_id: UUID
    runner_id: UUID
    connection_generation: int
    placement_id: UUID
    official_runner_id: str
    endpoint_host: str
    endpoint_port: int
    server_name: str
    audience: str
    registration_token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PreviewTunnelBindingGrant:
    registration_id: UUID
    runner_id: UUID
    connection_generation: int
    runtime_placement_id: UUID
    tunnel_placement_id: UUID
    routing_generation: int
    relay_subject: str
    official_runner_id: str


class PreviewTunnelRegistrationIssuer:
    """Mint a one-use WS bearer from an already authenticated Runner control call."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        endpoint_policy: PreviewRelayEndpointPolicy,
        runner_tunnel_port: int,
        lifetime: timedelta = timedelta(seconds=60),
    ) -> None:
        if not timedelta(seconds=10) <= lifetime <= timedelta(minutes=2):
            raise ValueError("Preview tunnel registration lifetime is invalid")
        lifetime_seconds = lifetime.total_seconds()
        if not lifetime_seconds.is_integer():
            raise ValueError("Preview tunnel registration lifetime must use whole seconds")
        endpoint_policy.require_allowed_port(runner_tunnel_port)
        self._session_factory = session_factory
        self._endpoint_policy = endpoint_policy
        self._runner_tunnel_port = runner_tunnel_port
        self._lifetime_seconds = int(lifetime_seconds)

    def issue(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        certificate_fingerprint_sha256: str,
    ) -> PreviewTunnelRegistrationGrant:
        fingerprint = certificate_fingerprint_sha256.lower()
        if (
            connection_generation <= 0
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise PreviewTunnelRegistrationError("preview_tunnel_identity_invalid")
        connection_hash = _token_hash(connection_token)
        raw_token = secrets.token_urlsafe(32)
        registration_hash = _token_hash(raw_token)
        jti_hash = hashlib.sha256(uuid4().bytes).hexdigest()
        official_runner_id = token_bound_runner_id(raw_token)
        registration_id = uuid4()
        with self._session_factory.begin() as db:
            row = (
                db.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_issue_tunnel_registration_v1("
                        ":runner_id, :connection_generation, :connection_token_hash, "
                        ":certificate_fingerprint, :registration_id, :jti_hash, "
                        ":token_hash, :official_runner_id, :lifetime_seconds)"
                    ),
                    {
                        "runner_id": runner_id,
                        "connection_generation": connection_generation,
                        "connection_token_hash": connection_hash,
                        "certificate_fingerprint": fingerprint,
                        "registration_id": registration_id,
                        "jti_hash": jti_hash,
                        "token_hash": registration_hash,
                        "official_runner_id": official_runner_id,
                        "lifetime_seconds": self._lifetime_seconds,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise PreviewTunnelRegistrationError("preview_tunnel_runner_stale")
            try:
                endpoint_host = self._endpoint_policy.require_allowed_name(
                    str(row["endpoint_host"])
                )
                server_name = self._endpoint_policy.require_allowed_name(str(row["server_name"]))
            except PreviewRelayTransportError as exc:
                raise PreviewTunnelRegistrationError(
                    "preview_tunnel_owner_endpoint_denied"
                ) from exc
            expires_at = row["expires_at"]
            placement_id = row["placement_id"]
            issued_runner_id = row["runner_id"]
            issued_generation = row["connection_generation"]
            issued_registration_id = row["registration_id"]
            if (
                not isinstance(expires_at, datetime)
                or not isinstance(placement_id, UUID)
                or issued_runner_id != runner_id
                or issued_generation != connection_generation
                or issued_registration_id != registration_id
            ):
                raise PreviewTunnelRegistrationError("preview_tunnel_runner_stale")
            return PreviewTunnelRegistrationGrant(
                registration_id=registration_id,
                runner_id=runner_id,
                connection_generation=connection_generation,
                placement_id=placement_id,
                official_runner_id=official_runner_id,
                endpoint_host=endpoint_host,
                endpoint_port=self._runner_tunnel_port,
                server_name=server_name,
                audience=server_name,
                registration_token=raw_token,
                expires_at=expires_at,
            )

    def revoke(
        self,
        *,
        runner_id: UUID,
        connection_generation: int,
        connection_token: str,
        certificate_fingerprint_sha256: str,
        registration_id: UUID,
        registration_token: str,
    ) -> bool:
        """Revoke only this current Runner incarnation's exact unredeemed token."""

        fingerprint = certificate_fingerprint_sha256.lower()
        if (
            connection_generation <= 0
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise PreviewTunnelRegistrationError("preview_tunnel_identity_invalid")
        with self._session_factory.begin() as db:
            return bool(
                db.scalar(
                    sa.text(
                        "SELECT public.saas_preview_revoke_tunnel_registration_v1("
                        ":runner_id, :connection_generation, :connection_token_hash, "
                        ":certificate_fingerprint, :registration_id, :token_hash)"
                    ),
                    {
                        "runner_id": runner_id,
                        "connection_generation": connection_generation,
                        "connection_token_hash": _token_hash(connection_token),
                        "certificate_fingerprint": fingerprint,
                        "registration_id": registration_id,
                        "token_hash": _token_hash(registration_token),
                    },
                )
            )


class PreviewTunnelOwnerAuthority:
    """Invoke the placement-bound owner-only CAS functions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        gateway_instance_id: str,
        gateway_registration_token: str,
    ) -> None:
        self._session_factory = session_factory
        self.gateway_instance_id = gateway_instance_id
        self._gateway_token_hash = _token_hash(gateway_registration_token)

    def preauthorize(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> PreviewTunnelBindingGrant | None:
        operation_at = now or _utcnow()
        with self._session_factory.begin() as db:
            row = (
                db.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_preauthorize_tunnel_v1("
                        ":registration_hash, :official_runner_id, :gateway_id, "
                        ":gateway_token_hash, :operation_at)"
                    ),
                    self._parameters(official_runner_id, registration_token, operation_at),
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            return PreviewTunnelBindingGrant(
                registration_id=row["registration_id"],
                runner_id=row["runner_id"],
                connection_generation=row["connection_generation"],
                runtime_placement_id=row["placement_id"],
                tunnel_placement_id=UUID(int=0),
                routing_generation=0,
                relay_subject="",
                official_runner_id=official_runner_id,
            )

    def redeem(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> PreviewTunnelBindingGrant:
        operation_at = now or _utcnow()
        placement_id = uuid4()
        ownership_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        parameters = self._parameters(official_runner_id, registration_token, operation_at)
        parameters.update({"placement_id": placement_id, "ownership_hash": ownership_hash})
        with self._session_factory.begin() as db:
            row = (
                db.execute(
                    sa.text(
                        "SELECT * FROM public.saas_preview_redeem_tunnel_v1("
                        ":registration_hash, :official_runner_id, :gateway_id, "
                        ":gateway_token_hash, :placement_id, :ownership_hash, :operation_at)"
                    ),
                    parameters,
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise PreviewTunnelRegistrationError("preview_tunnel_registration_stale")
            return PreviewTunnelBindingGrant(
                registration_id=row["registration_id"],
                runner_id=row["runner_id"],
                connection_generation=row["connection_generation"],
                runtime_placement_id=row["runtime_placement_id"],
                tunnel_placement_id=row["tunnel_placement_id"],
                routing_generation=row["routing_generation"],
                relay_subject=row["relay_subject"],
                official_runner_id=official_runner_id,
            )

    def heartbeat(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> bool:
        with self._session_factory.begin() as db:
            return bool(
                db.scalar(
                    sa.text(
                        "SELECT public.saas_preview_heartbeat_tunnel_v1("
                        ":registration_hash, :official_runner_id, :gateway_id, "
                        ":gateway_token_hash, :operation_at)"
                    ),
                    self._parameters(official_runner_id, registration_token, now or _utcnow()),
                )
            )

    def disconnect(
        self,
        *,
        official_runner_id: str,
        registration_token: str,
        now: datetime | None = None,
    ) -> bool:
        with self._session_factory.begin() as db:
            return bool(
                db.scalar(
                    sa.text(
                        "SELECT public.saas_preview_disconnect_tunnel_v1("
                        ":registration_hash, :official_runner_id, :gateway_id, "
                        ":gateway_token_hash, :operation_at)"
                    ),
                    self._parameters(official_runner_id, registration_token, now or _utcnow()),
                )
            )

    def heartbeat_gateway(self) -> bool:
        """Renew only the still-live Owner endpoint selected by this token."""

        with self._session_factory.begin() as db:
            return bool(
                db.scalar(
                    sa.text(
                        "SELECT public.saas_preview_owner_heartbeat_gateway_v1("
                        ":gateway_id, :gateway_token_hash)"
                    ),
                    {
                        "gateway_id": self.gateway_instance_id,
                        "gateway_token_hash": self._gateway_token_hash,
                    },
                )
            )

    def release_gateway(self) -> bool:
        """Tombstone only this exact Owner endpoint during fail-closed shutdown."""

        with self._session_factory.begin() as db:
            return bool(
                db.scalar(
                    sa.text(
                        "SELECT public.saas_preview_owner_release_gateway_v1("
                        ":gateway_id, :gateway_token_hash)"
                    ),
                    {
                        "gateway_id": self.gateway_instance_id,
                        "gateway_token_hash": self._gateway_token_hash,
                    },
                )
            )

    def _parameters(
        self,
        official_runner_id: str,
        registration_token: str,
        operation_at: datetime,
    ) -> dict[str, object]:
        return {
            "registration_hash": _token_hash(registration_token),
            "official_runner_id": official_runner_id,
            "gateway_id": self.gateway_instance_id,
            "gateway_token_hash": self._gateway_token_hash,
            "operation_at": operation_at,
        }


__all__ = [
    "PreviewTunnelBindingGrant",
    "PreviewTunnelOwnerAuthority",
    "PreviewTunnelRegistrationError",
    "PreviewTunnelRegistrationGrant",
    "PreviewTunnelRegistrationIssuer",
]
