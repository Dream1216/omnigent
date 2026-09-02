"""Content-blind P0S9 Preview exchange, browser session, and route authority."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.isolation import PreviewRouteGrant
from saas.control_plane.placements import (
    RunnerTunnelPlacement,
    RunnerTunnelPlacementError,
)

_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_OPAQUE_KEY = re.compile(r"^pvr_[0-9A-Za-z_-]{1,92}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REQUEST_HEADERS = frozenset(
    {"accept", "accept-encoding", "accept-language", "content-type", "user-agent"}
)
_RESPONSE_HEADERS = {
    "Content-Security-Policy": (
        "sandbox allow-scripts allow-forms allow-modals allow-same-origin; "
        "default-src 'self'; connect-src 'none'; frame-src 'none'; "
        "worker-src 'none'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class PreviewSessionError(RuntimeError):
    """Stable, non-disclosing P0S9 browser-session error."""

    def __init__(self, code: str, message: str = "Preview authorization is unavailable") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PreviewBrowserSessionGrant:
    route: PreviewRouteGrant
    session_token: str | None = field(default=None, repr=False)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _canonical_host(value: str) -> str:
    normalized = value.rstrip(".").lower()
    if value != value.strip() or _HOST.fullmatch(normalized) is None:
        raise PreviewSessionError("preview_host_invalid")
    return normalized


def _token_hash(value: str) -> str:
    if (
        not 32 <= len(value) <= 512
        or value != value.strip()
        or "\x00" in value
        or not value.isascii()
    ):
        raise PreviewSessionError("preview_session_invalid")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _uuid(row: Mapping[str, object], name: str) -> UUID:
    value = row.get(name)
    if not isinstance(value, UUID) or value.int == 0:
        raise PreviewSessionError("preview_route_invalid")
    return value


def _integer(row: Mapping[str, object], name: str) -> int:
    value = row.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PreviewSessionError("preview_route_invalid")
    return value


class PreviewSessionAuthority:
    """Invoke only the narrow P0S9 SECURITY DEFINER token CAS functions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        session_lifetime: timedelta = timedelta(minutes=15),
    ) -> None:
        if not timedelta(minutes=1) <= session_lifetime <= timedelta(hours=1):
            raise ValueError("Preview browser-session lifetime is invalid")
        self._session_factory = session_factory
        self._session_lifetime = session_lifetime

    def exchange(
        self,
        *,
        host: str,
        exchange_token: str,
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrant:
        operation_at = now or _utcnow()
        session_token = secrets.token_urlsafe(32)
        row = self._call(
            "saas_preview_exchange_v1",
            "(:presented_hash, :session_id, :session_hash, :expires_at, :operation_at)",
            {
                "presented_hash": _token_hash(exchange_token),
                "session_id": uuid4(),
                "session_hash": _token_hash(session_token),
                "expires_at": operation_at + self._session_lifetime,
                "operation_at": operation_at,
            },
        )
        if row is None:
            raise PreviewSessionError("preview_exchange_invalid")
        route = self._route(row, token_hash=_token_hash(session_token), host=host)
        return PreviewBrowserSessionGrant(route=route, session_token=session_token)

    def authorize_and_rotate(
        self,
        *,
        host: str,
        session_token: str,
        incoming_headers: Mapping[str, str],
        now: datetime | None = None,
    ) -> PreviewBrowserSessionGrant:
        operation_at = now or _utcnow()
        current_hash = _token_hash(session_token)
        next_token = secrets.token_urlsafe(32)
        row = self._call(
            "saas_preview_rotate_session_v1",
            "(:presented_hash, :next_hash, :host, :expires_at, :operation_at)",
            {
                "presented_hash": current_hash,
                "next_hash": _token_hash(next_token),
                "host": _canonical_host(host),
                "expires_at": operation_at + self._session_lifetime,
                "operation_at": operation_at,
            },
        )
        if row is None:
            raise PreviewSessionError("preview_session_invalid")
        route = self._route(
            row,
            token_hash=current_hash,
            host=host,
            incoming_headers=incoming_headers,
        )
        rotated = row.get("rotated")
        if not isinstance(rotated, bool):
            raise PreviewSessionError("preview_route_invalid")
        return PreviewBrowserSessionGrant(
            route=route,
            session_token=next_token if rotated else None,
        )

    def resolve_preview_grant(
        self,
        route: PreviewRouteGrant,
        *,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        """Re-authorize the exact hash+host immediately before relay routing."""

        try:
            return self._resolve_preview_grant(route, now=now)
        except PreviewSessionError as error:
            raise RunnerTunnelPlacementError(
                "runner_tunnel_route_stale", "Preview Runner route is stale"
            ) from error

    def _resolve_preview_grant(
        self,
        route: PreviewRouteGrant,
        *,
        now: datetime | None,
    ) -> RunnerTunnelPlacement:

        if not route.preview_host:
            raise PreviewSessionError("preview_host_invalid")
        operation_at = now or _utcnow()
        row = self._call(
            "saas_preview_authorize_session_v1",
            "(:presented_hash, :host, :operation_at)",
            {
                "presented_hash": route.preview_token_hash,
                "host": _canonical_host(route.preview_host),
                "operation_at": operation_at,
            },
        )
        if row is None:
            raise PreviewSessionError("preview_session_invalid")
        verified = self._route(
            row,
            token_hash=route.preview_token_hash,
            host=route.preview_host,
            incoming_headers=route.upstream_request_headers,
        )
        if self._stable_route(verified) != self._stable_route(route):
            raise PreviewSessionError("preview_route_stale")
        return RunnerTunnelPlacement(
            placement_id=_uuid(row, "tunnel_placement_id"),
            runner_id=route.runner_id,
            runner_connection_generation=route.runner_connection_generation,
            routing_generation=_integer(row, "routing_generation"),
            gateway_instance_id=self._text(row, "gateway_instance_id", maximum=128),
            relay_subject=self._text(row, "relay_subject", maximum=256),
            status="active",
            lease_expires_at=self._time(row, "tunnel_lease_expires_at"),
        )

    def revoke(self, *, session_token: str, now: datetime | None = None) -> bool:
        operation_at = now or _utcnow()
        with self._session_factory.begin() as database:
            return bool(
                database.scalar(
                    sa.text(
                        "SELECT public.saas_preview_revoke_session_v1("
                        ":presented_hash, :operation_at)"
                    ),
                    {
                        "presented_hash": _token_hash(session_token),
                        "operation_at": operation_at,
                    },
                )
            )

    def _call(
        self,
        function: str,
        signature: str,
        parameters: Mapping[str, object],
    ) -> Mapping[str, object] | None:
        with self._session_factory.begin() as database:
            row = (
                database.execute(
                    sa.text(f"SELECT * FROM public.{function}{signature}"),
                    dict(parameters),
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else dict(row)

    def _route(
        self,
        row: Mapping[str, object],
        *,
        token_hash: str,
        host: str,
        incoming_headers: Mapping[str, str] | None = None,
    ) -> PreviewRouteGrant:
        normalized_host = _canonical_host(host)
        row_host = self._text(row, "preview_host", maximum=253)
        opaque_key = self._text(row, "opaque_preview_key", maximum=96)
        expiry = self._time(row, "expires_at")
        if (
            row_host != normalized_host
            or _OPAQUE_KEY.fullmatch(opaque_key) is None
            or not _HEX64.fullmatch(token_hash)
            or expiry <= _utcnow()
        ):
            raise PreviewSessionError("preview_route_invalid")
        safe_headers = {
            key.lower(): value
            for key, value in (incoming_headers or {}).items()
            if key.lower() in _SAFE_REQUEST_HEADERS and "\r" not in value and "\n" not in value
        }
        return PreviewRouteGrant(
            preview_id=_uuid(row, "preview_execution_id"),
            tenant_id=_uuid(row, "tenant_id"),
            space_id=_uuid(row, "space_id"),
            project_id=_uuid(row, "project_id"),
            runner_id=_uuid(row, "runner_id"),
            runner_connection_generation=_integer(row, "runner_connection_generation"),
            run_id=_uuid(row, "run_id"),
            run_fence_token=_integer(row, "run_fence_token"),
            worktree_id=_uuid(row, "worktree_id"),
            worktree_lease_generation=_integer(row, "worktree_lease_generation"),
            opaque_preview_key=opaque_key,
            preview_token_hash=token_hash,
            upstream_request_headers=safe_headers,
            response_headers=dict(_RESPONSE_HEADERS),
            expires_at=expiry,
            preview_host=normalized_host,
        )

    @staticmethod
    def _text(row: Mapping[str, object], name: str, *, maximum: int) -> str:
        value = row.get(name)
        if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
            raise PreviewSessionError("preview_route_invalid")
        return value

    @staticmethod
    def _time(row: Mapping[str, object], name: str) -> datetime:
        value = row.get(name)
        if not isinstance(value, datetime):
            raise PreviewSessionError("preview_route_invalid")
        return _aware(value)

    @staticmethod
    def _stable_route(route: PreviewRouteGrant) -> tuple[object, ...]:
        return (
            route.preview_id,
            route.tenant_id,
            route.space_id,
            route.project_id,
            route.runner_id,
            route.runner_connection_generation,
            route.run_id,
            route.run_fence_token,
            route.worktree_id,
            route.worktree_lease_generation,
            route.opaque_preview_key,
            route.preview_token_hash,
            route.upstream_request_headers,
            route.response_headers,
            route.expires_at,
            route.preview_host,
        )


__all__ = [
    "PreviewBrowserSessionGrant",
    "PreviewSessionAuthority",
    "PreviewSessionError",
]
