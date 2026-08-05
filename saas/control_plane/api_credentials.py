"""Lifecycle and authentication authority for Service Accounts and API keys."""

from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    ProjectMembershipRecord,
    ProjectRecord,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.permissions import (
    PERMISSION_CATALOG,
    PROJECT_ROLE_PERMISSIONS,
    SPACE_ROLE_PERMISSIONS,
    TENANT_ROLE_PERMISSIONS,
)
from saas.control_plane.rls import RlsContext, apply_rls_context

_TOKEN_PREFIX = "omk_"
_FRESH_AUTH_WINDOW = timedelta(minutes=5)
_LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)
_MAX_CREDENTIAL_TTL = timedelta(days=366)


@dataclass(frozen=True, slots=True)
class ServiceAccountView:
    """Non-secret Service Account representation."""

    id: UUID
    tenant_id: UUID
    space_id: UUID | None
    project_id: UUID | None
    name: str
    description: str | None
    steward_user_id: UUID
    status: str
    security_version: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class IssuedApiCredential:
    """API key creation/rotation result; token is present exactly once."""

    credential_id: UUID
    service_account_id: UUID
    display_prefix: str
    token: str | None
    permission_scopes: tuple[str, ...]
    allowed_networks: tuple[str, ...]
    expires_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class ApiCredentialView:
    """Non-secret API key metadata safe for administration responses."""

    id: UUID
    service_account_id: UUID
    name: str
    display_prefix: str
    permission_scopes: tuple[str, ...]
    allowed_networks: tuple[str, ...]
    status: str
    expires_at: datetime
    last_used_at: datetime | None
    last_used_ip: str | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class ValidatedApiCredential:
    """Current machine principal resolved from a bearer API key."""

    credential_id: UUID
    service_account_id: UUID
    tenant_id: UUID
    space_id: UUID | None
    project_id: UUID | None
    security_version: int
    permission_scopes: frozenset[str]
    authenticated_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CredentialMutation:
    """Secret-free result of revoke/suspend/steward-transfer operations."""

    service_account_id: UUID
    security_version: int
    revoked_credential_count: int
    replayed: bool


class ApiCredentialError(LifecycleError):
    """Stable, transport-neutral machine identity failure."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _comparable(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ApiCredentialError("invalid_time", f"{field} must include a timezone")


def _require_fresh_auth(authenticated_at: datetime, now: datetime) -> None:
    comparable = _comparable(authenticated_at)
    if comparable > now or now - comparable > _FRESH_AUTH_WINDOW:
        raise ApiCredentialError(
            "fresh_authentication_required",
            "API credential changes require authentication within five minutes",
        )


def _require_idempotency_key(value: str) -> None:
    if not value or len(value) > 128:
        raise ApiCredentialError("invalid_idempotency_key", "idempotency key is invalid")


def _request_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


def _token_hash(pepper: bytes, token: str) -> str:
    return hmac.new(pepper, token.encode(), sha256).hexdigest()


def _parse_token(token: str) -> UUID:
    if not token.startswith(_TOKEN_PREFIX) or len(token) > 256:
        raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "omk" or len(parts[1]) != 32 or len(parts[2]) < 32:
        raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
    try:
        return UUID(hex=parts[1])
    except ValueError as error:
        raise ApiCredentialError("invalid_api_credential", "API credential is invalid") from error


def _canonical_networks(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(values) > 32:
        raise ApiCredentialError("invalid_network_policy", "at most 32 networks are allowed")
    networks: set[str] = set()
    for value in values:
        try:
            networks.add(str(ipaddress.ip_network(value.strip(), strict=True)))
        except ValueError as error:
            raise ApiCredentialError(
                "invalid_network_policy", "API credential network policy is invalid"
            ) from error
    return tuple(sorted(networks))


def _source_ip_allowed(source_ip: str | None, allowed_networks: tuple[str, ...]) -> bool:
    if not allowed_networks:
        return True
    if not source_ip:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network) for network in allowed_networks)


class ApiCredentialService:
    """Create, rotate, authenticate, and revoke explicit machine identities."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        credential_pepper: bytes,
    ) -> None:
        if len(credential_pepper) < 32:
            raise ValueError("API credential pepper must contain at least 32 bytes")
        self._session_factory = session_factory
        self._pepper = bytes(credential_pepper)

    @staticmethod
    def is_api_credential(token: str) -> bool:
        """Recognize the non-overlapping machine-token namespace."""

        return token.startswith(_TOKEN_PREFIX)

    def create_service_account(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        steward_user_id: UUID,
        name: str,
        description: str | None,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> ServiceAccountView:
        """Create a project-bound machine identity without creator inheritance."""

        created_at = now or _now()
        _require_aware(created_at, "now")
        _require_fresh_auth(authenticated_at, created_at)
        _require_idempotency_key(idempotency_key)
        cleaned_name = name.strip()
        cleaned_description = description.strip() if description else None
        if not cleaned_name or len(cleaned_name) > 128:
            raise ApiCredentialError("invalid_service_account", "name must be 1 to 128 characters")
        if cleaned_description is not None and len(cleaned_description) > 1024:
            raise ApiCredentialError(
                "invalid_service_account", "description must not exceed 1024 characters"
            )
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "space_id": str(space_id),
            "project_id": str(project_id),
            "steward_user_id": str(steward_user_id),
            "name": cleaned_name,
            "description": cleaned_description,
        }
        digest = _request_hash(request)
        event_type = "service_account.created"
        with self._session_factory.begin() as db:
            apply_rls_context(
                db, RlsContext(actor_id=actor_id, tenant_id=tenant_id, space_id=space_id)
            )
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._account_from_payload(replay, replayed=True)
            self._require_project_manager(db, actor_id, tenant_id, space_id, project_id)
            self._require_active_steward(db, tenant_id, space_id, steward_user_id)
            account = ServiceAccountRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                space_id=space_id,
                project_id=project_id,
                name=cleaned_name,
                description=cleaned_description,
                steward_user_id=steward_user_id,
                created_by=actor_id,
                status="active",
                security_version=1,
                created_at=created_at,
                updated_at=created_at,
            )
            db.add(account)
            payload = self._account_payload(account)
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="service_account",
                aggregate_key=str(account.id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._account_from_payload(payload, replayed=False)

    def list_service_accounts(
        self, *, actor_id: UUID, tenant_id: UUID
    ) -> tuple[ServiceAccountView, ...]:
        """List non-secret machine identities visible to a Tenant administrator."""

        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            self._require_tenant_admin(db, actor_id, tenant_id)
            rows = db.execute(
                sa.select(ServiceAccountRecord)
                .where(ServiceAccountRecord.tenant_id == tenant_id)
                .order_by(ServiceAccountRecord.created_at, ServiceAccountRecord.id)
            ).scalars()
            return tuple(self._account_view(row) for row in rows)

    def issue_api_credential(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
        name: str,
        permission_scopes: tuple[str, ...],
        allowed_networks: tuple[str, ...],
        expires_at: datetime,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedApiCredential:
        """Issue one API key and return its plaintext token once."""

        issued_at = now or _now()
        _require_aware(issued_at, "now")
        _require_aware(expires_at, "expires_at")
        _require_fresh_auth(authenticated_at, issued_at)
        _require_idempotency_key(idempotency_key)
        cleaned_name = name.strip()
        if not cleaned_name or len(cleaned_name) > 128:
            raise ApiCredentialError("invalid_api_credential", "name must be 1 to 128 characters")
        if expires_at <= issued_at or expires_at - issued_at > _MAX_CREDENTIAL_TTL:
            raise ApiCredentialError(
                "invalid_api_credential_expiry", "API credential expiry must be within 366 days"
            )
        scopes = self._validate_permission_scopes(permission_scopes)
        networks = _canonical_networks(allowed_networks)
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "service_account_id": str(service_account_id),
            "name": cleaned_name,
            "permission_scopes": list(scopes),
            "allowed_networks": list(networks),
            "expires_at": expires_at.isoformat(),
        }
        digest = _request_hash(request)
        event_type = "api_credential.issued"
        credential_id = uuid4()
        raw_token = f"{_TOKEN_PREFIX}{credential_id.hex}_{secrets.token_urlsafe(32)}"
        display_prefix = f"{_TOKEN_PREFIX}{credential_id.hex[:12]}"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._credential_from_payload(replay, token=None, replayed=True)
            account = self._load_active_account(db, tenant_id, service_account_id, lock=True)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
                assigned_permissions=scopes,
            )
            credential = ApiCredentialRecord(
                id=credential_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                name=cleaned_name,
                token_hash=_token_hash(self._pepper, raw_token),
                display_prefix=display_prefix,
                permission_scopes=list(scopes),
                allowed_networks=list(networks),
                account_security_version=account.security_version,
                status="active",
                expires_at=expires_at,
                created_by=actor_id,
                created_at=issued_at,
            )
            db.add(credential)
            payload = self._credential_payload(credential)
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="api_credential",
                aggregate_key=str(credential_id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._credential_from_payload(payload, token=raw_token, replayed=False)

    def list_api_credentials(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
    ) -> tuple[ApiCredentialView, ...]:
        """List credential metadata without token hashes or plaintext secrets."""

        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            account = self._load_account(db, tenant_id, service_account_id)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
            )
            rows = db.execute(
                sa.select(ApiCredentialRecord)
                .where(
                    ApiCredentialRecord.tenant_id == tenant_id,
                    ApiCredentialRecord.service_account_id == service_account_id,
                )
                .order_by(ApiCredentialRecord.created_at, ApiCredentialRecord.id)
            ).scalars()
            return tuple(self._credential_view(row) for row in rows)

    def rotate_api_credential(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
        credential_id: UUID,
        expires_at: datetime,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> IssuedApiCredential:
        """Atomically revoke one API key and issue its one-time replacement."""

        rotated_at = now or _now()
        _require_aware(rotated_at, "now")
        _require_aware(expires_at, "expires_at")
        _require_fresh_auth(authenticated_at, rotated_at)
        _require_idempotency_key(idempotency_key)
        if expires_at <= rotated_at or expires_at - rotated_at > _MAX_CREDENTIAL_TTL:
            raise ApiCredentialError(
                "invalid_api_credential_expiry", "API credential expiry must be within 366 days"
            )
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "service_account_id": str(service_account_id),
            "credential_id": str(credential_id),
            "expires_at": expires_at.isoformat(),
        }
        digest = _request_hash(request)
        event_type = "api_credential.rotated"
        replacement_id = uuid4()
        raw_token = f"{_TOKEN_PREFIX}{replacement_id.hex}_{secrets.token_urlsafe(32)}"
        display_prefix = f"{_TOKEN_PREFIX}{replacement_id.hex[:12]}"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._credential_from_payload(replay, token=None, replayed=True)
            account = self._load_active_account(db, tenant_id, service_account_id, lock=True)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
            )
            old = db.execute(
                sa.select(ApiCredentialRecord)
                .where(
                    ApiCredentialRecord.id == credential_id,
                    ApiCredentialRecord.tenant_id == tenant_id,
                    ApiCredentialRecord.service_account_id == service_account_id,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if old is None or old.status != "active" or old.revoked_at is not None:
                raise ApiCredentialError(
                    "api_credential_not_active", "active API credential is required"
                )
            scopes = self._validate_permission_scopes(tuple(old.permission_scopes))
            self._require_assignable_permissions(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
                scopes,
            )
            old.status = "revoked"
            old.revoked_at = rotated_at
            replacement = ApiCredentialRecord(
                id=replacement_id,
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                name=old.name,
                token_hash=_token_hash(self._pepper, raw_token),
                display_prefix=display_prefix,
                permission_scopes=list(scopes),
                allowed_networks=list(old.allowed_networks),
                account_security_version=account.security_version,
                status="active",
                expires_at=expires_at,
                created_by=actor_id,
                created_at=rotated_at,
            )
            db.add(replacement)
            payload = self._credential_payload(replacement)
            payload["rotated_from_credential_id"] = str(credential_id)
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="api_credential",
                aggregate_key=str(replacement_id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._credential_from_payload(payload, token=raw_token, replayed=False)

    def revoke_api_credential(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
        credential_id: UUID,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CredentialMutation:
        """Immediately revoke one API key; idempotent replay stays secret-free."""

        revoked_at = now or _now()
        _require_aware(revoked_at, "now")
        _require_fresh_auth(authenticated_at, revoked_at)
        _require_idempotency_key(idempotency_key)
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "service_account_id": str(service_account_id),
            "credential_id": str(credential_id),
        }
        digest = _request_hash(request)
        event_type = "api_credential.revoked"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._mutation_from_payload(replay, replayed=True)
            account = self._load_account(db, tenant_id, service_account_id)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
            )
            result = cast(
                CursorResult[tuple[object]],
                db.execute(
                    sa.update(ApiCredentialRecord)
                    .where(
                        ApiCredentialRecord.id == credential_id,
                        ApiCredentialRecord.tenant_id == tenant_id,
                        ApiCredentialRecord.service_account_id == service_account_id,
                        ApiCredentialRecord.status == "active",
                        ApiCredentialRecord.revoked_at.is_(None),
                    )
                    .values(status="revoked", revoked_at=revoked_at)
                ),
            )
            if result.rowcount != 1:
                raise ApiCredentialError(
                    "api_credential_not_active", "active API credential is required"
                )
            payload: dict[str, object] = {
                "service_account_id": str(service_account_id),
                "credential_id": str(credential_id),
                "security_version": account.security_version,
                "revoked_credential_count": 1,
                "revoked_at": revoked_at.isoformat(),
            }
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="api_credential",
                aggregate_key=str(credential_id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._mutation_from_payload(payload, replayed=False)

    def transfer_steward(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
        to_user_id: UUID,
        expected_security_version: int,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CredentialMutation:
        """Transfer explicit stewardship and invalidate every prior API key."""

        changed_at = now or _now()
        _require_aware(changed_at, "now")
        _require_fresh_auth(authenticated_at, changed_at)
        _require_idempotency_key(idempotency_key)
        if expected_security_version < 1:
            raise ApiCredentialError("invalid_security_version", "security version is invalid")
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "service_account_id": str(service_account_id),
            "to_user_id": str(to_user_id),
            "expected_security_version": expected_security_version,
        }
        digest = _request_hash(request)
        event_type = "service_account.steward_transferred"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._mutation_from_payload(replay, replayed=True)
            account = self._load_active_account(db, tenant_id, service_account_id, lock=True)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
            )
            self._require_active_steward(
                db, tenant_id, cast(UUID, account.space_id), to_user_id
            )
            if account.security_version != expected_security_version:
                raise ApiCredentialError(
                    "service_account_version_conflict", "Service Account changed concurrently"
                )
            if account.steward_user_id == to_user_id:
                raise ApiCredentialError(
                    "service_account_unchanged", "target already stewards this Service Account"
                )
            account.steward_user_id = to_user_id
            account.security_version += 1
            account.updated_at = changed_at
            revoked = self._revoke_active_credentials(db, account.id, changed_at)
            payload: dict[str, object] = {
                "service_account_id": str(account.id),
                "security_version": account.security_version,
                "steward_user_id": str(to_user_id),
                "revoked_credential_count": revoked,
                "changed_at": changed_at.isoformat(),
            }
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="service_account",
                aggregate_key=str(account.id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._mutation_from_payload(payload, replayed=False)

    def suspend_service_account(
        self,
        *,
        actor_id: UUID,
        tenant_id: UUID,
        service_account_id: UUID,
        expected_security_version: int,
        authenticated_at: datetime,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CredentialMutation:
        """Suspend a machine identity and atomically revoke every active key."""

        changed_at = now or _now()
        _require_aware(changed_at, "now")
        _require_fresh_auth(authenticated_at, changed_at)
        _require_idempotency_key(idempotency_key)
        request: dict[str, object] = {
            "actor_id": str(actor_id),
            "tenant_id": str(tenant_id),
            "service_account_id": str(service_account_id),
            "expected_security_version": expected_security_version,
        }
        digest = _request_hash(request)
        event_type = "service_account.suspended"
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(actor_id=actor_id, tenant_id=tenant_id))
            replay = self._load_receipt(db, tenant_id, idempotency_key, digest, event_type)
            if replay is not None:
                return self._mutation_from_payload(replay, replayed=True)
            account = self._load_active_account(db, tenant_id, service_account_id, lock=True)
            self._require_project_manager(
                db,
                actor_id,
                tenant_id,
                cast(UUID, account.space_id),
                cast(UUID, account.project_id),
            )
            if account.security_version != expected_security_version:
                raise ApiCredentialError(
                    "service_account_version_conflict", "Service Account changed concurrently"
                )
            account.status = "suspended"
            account.security_version += 1
            account.updated_at = changed_at
            revoked = self._revoke_active_credentials(db, account.id, changed_at)
            payload: dict[str, object] = {
                "service_account_id": str(account.id),
                "security_version": account.security_version,
                "revoked_credential_count": revoked,
                "changed_at": changed_at.isoformat(),
            }
            self._add_event(
                db,
                tenant_id=tenant_id,
                aggregate_type="service_account",
                aggregate_key=str(account.id),
                event_type=event_type,
                idempotency_key=idempotency_key,
                request_hash=digest,
                payload=payload,
            )
            return self._mutation_from_payload(payload, replayed=False)

    def authenticate(
        self,
        token: str,
        *,
        source_ip: str | None,
        now: datetime | None = None,
    ) -> ValidatedApiCredential:
        """Validate key digest, account state, scope state, expiry, and network policy."""

        checked_at = now or _now()
        _require_aware(checked_at, "now")
        credential_id = _parse_token(token)
        with self._session_factory.begin() as db:
            apply_rls_context(db, RlsContext(api_credential_id=credential_id))
            credential = db.execute(
                sa.select(ApiCredentialRecord).where(ApiCredentialRecord.id == credential_id)
            ).scalar_one_or_none()
            if credential is None or not hmac.compare_digest(
                credential.token_hash, _token_hash(self._pepper, token)
            ):
                raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=credential.service_account_id,
                    tenant_id=credential.tenant_id,
                    api_credential_id=credential_id,
                ),
            )
            account = db.execute(
                sa.select(ServiceAccountRecord).where(
                    ServiceAccountRecord.id == credential.service_account_id,
                    ServiceAccountRecord.tenant_id == credential.tenant_id,
                )
            ).scalar_one_or_none()
            if not self._credential_is_current(credential, account, checked_at):
                raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=credential.service_account_id,
                    tenant_id=credential.tenant_id,
                    space_id=cast(ServiceAccountRecord, account).space_id,
                    api_credential_id=credential_id,
                ),
            )
            networks = tuple(cast(list[str], credential.allowed_networks))
            if not _source_ip_allowed(source_ip, networks):
                raise ApiCredentialError(
                    "api_credential_network_forbidden",
                    "API credential is not valid from this source network",
                )
            self._require_active_machine_scope(db, cast(ServiceAccountRecord, account))
            last_used_at = (
                _comparable(credential.last_used_at)
                if credential.last_used_at is not None
                else None
            )
            if last_used_at is None or checked_at - last_used_at >= _LAST_USED_WRITE_INTERVAL:
                credential.last_used_at = checked_at
                credential.last_used_ip = source_ip
            return ValidatedApiCredential(
                credential_id=credential.id,
                service_account_id=credential.service_account_id,
                tenant_id=credential.tenant_id,
                space_id=cast(ServiceAccountRecord, account).space_id,
                project_id=cast(ServiceAccountRecord, account).project_id,
                security_version=cast(ServiceAccountRecord, account).security_version,
                permission_scopes=frozenset(credential.permission_scopes),
                authenticated_at=checked_at,
                expires_at=_comparable(credential.expires_at),
            )

    @staticmethod
    def require_permission(
        principal: ValidatedApiCredential,
        *,
        permission: str,
        tenant_id: UUID,
        space_id: UUID | None = None,
        project_id: UUID | None = None,
    ) -> None:
        """Enforce exact key permissions and immutable scope boundaries."""

        if permission not in principal.permission_scopes:
            raise ApiCredentialError("permission_denied", "API credential permission is denied")
        if tenant_id != principal.tenant_id:
            raise ApiCredentialError("scope_mismatch", "API credential scope does not match")
        if space_id is not None and space_id != principal.space_id:
            raise ApiCredentialError("scope_mismatch", "API credential scope does not match")
        if project_id is not None and project_id != principal.project_id:
            raise ApiCredentialError("scope_mismatch", "API credential scope does not match")

    @staticmethod
    def _credential_is_current(
        credential: ApiCredentialRecord,
        account: ServiceAccountRecord | None,
        checked_at: datetime,
    ) -> bool:
        return bool(
            credential.status == "active"
            and credential.revoked_at is None
            and _comparable(credential.expires_at) > checked_at
            and account is not None
            and account.status == "active"
            and credential.account_security_version == account.security_version
        )

    @staticmethod
    def _require_active_machine_scope(db: Session, account: ServiceAccountRecord) -> None:
        tenant = db.get(Tenant, account.tenant_id)
        space = db.get(Space, account.space_id) if account.space_id is not None else None
        project = (
            db.get(ProjectRecord, account.project_id)
            if account.project_id is not None
            else None
        )
        if tenant is None or tenant.status not in ("trial", "active"):
            raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
        if account.space_id is not None and (space is None or space.status != "active"):
            raise ApiCredentialError("invalid_api_credential", "API credential is invalid")
        if account.project_id is not None and (project is None or project.status != "active"):
            raise ApiCredentialError("invalid_api_credential", "API credential is invalid")

    @staticmethod
    def _validate_permission_scopes(values: tuple[str, ...]) -> tuple[str, ...]:
        scopes = tuple(sorted(set(values)))
        if not scopes or len(scopes) > 64:
            raise ApiCredentialError(
                "invalid_permission_scope", "one to 64 permission scopes are required"
            )
        for scope in scopes:
            definition = PERMISSION_CATALOG.get(scope)
            if definition is None or not definition.service_account_allowed:
                raise ApiCredentialError(
                    "invalid_permission_scope",
                    f"permission is not allowed for Service Accounts: {scope}",
                )
        return scopes

    @classmethod
    def _require_project_manager(
        cls,
        db: Session,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        *,
        assigned_permissions: tuple[str, ...] = (),
    ) -> None:
        permissions = cls._actor_project_permissions(
            db, actor_id, tenant_id, space_id, project_id
        )
        if "grant.manage" not in permissions:
            raise ApiCredentialError(
                "forbidden", "Project grant management permission is required"
            )
        missing = set(assigned_permissions) - permissions
        if missing:
            raise ApiCredentialError(
                "permission_escalation_forbidden",
                "a Service Account cannot receive permissions its manager does not hold",
            )

    @classmethod
    def _require_assignable_permissions(
        cls,
        db: Session,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
        permissions: tuple[str, ...],
    ) -> None:
        cls._require_project_manager(
            db,
            actor_id,
            tenant_id,
            space_id,
            project_id,
            assigned_permissions=permissions,
        )

    @staticmethod
    def _actor_project_permissions(
        db: Session,
        actor_id: UUID,
        tenant_id: UUID,
        space_id: UUID,
        project_id: UUID,
    ) -> set[str]:
        checked_at = _now()
        tenant_member = db.get(TenantMembership, (tenant_id, actor_id))
        space_member = db.get(SpaceMembership, (tenant_id, space_id, actor_id))
        project = db.execute(
            sa.select(ProjectRecord).where(
                ProjectRecord.id == project_id,
                ProjectRecord.tenant_id == tenant_id,
                ProjectRecord.space_id == space_id,
                ProjectRecord.status == "active",
            )
        ).scalar_one_or_none()
        if (
            project is None
            or tenant_member is None
            or tenant_member.status != "active"
            or space_member is None
            or space_member.status != "active"
        ):
            return set()
        permissions = set(TENANT_ROLE_PERMISSIONS[tenant_member.role])
        permissions.update(SPACE_ROLE_PERMISSIONS[space_member.role])
        roles = db.execute(
            sa.select(ProjectMembershipRecord).where(
                ProjectMembershipRecord.tenant_id == tenant_id,
                ProjectMembershipRecord.space_id == space_id,
                ProjectMembershipRecord.project_id == project_id,
                ProjectMembershipRecord.status == "active",
                sa.or_(
                    ProjectMembershipRecord.expires_at.is_(None),
                    ProjectMembershipRecord.expires_at > checked_at,
                ),
                sa.or_(
                    sa.and_(
                        ProjectMembershipRecord.subject_type == "user",
                        ProjectMembershipRecord.subject_id == actor_id,
                    ),
                    sa.and_(
                        ProjectMembershipRecord.subject_type == "space",
                        ProjectMembershipRecord.subject_id == space_id,
                    ),
                ),
            )
        ).scalars()
        for membership in roles:
            permissions.update(PROJECT_ROLE_PERMISSIONS[membership.role])
        if project.visibility == "space":
            permissions.update(PROJECT_ROLE_PERMISSIONS["read"])
        return permissions

    @staticmethod
    def _require_tenant_admin(db: Session, actor_id: UUID, tenant_id: UUID) -> None:
        membership = db.get(TenantMembership, (tenant_id, actor_id))
        if (
            membership is None
            or membership.status != "active"
            or membership.role not in ("owner", "admin")
        ):
            raise ApiCredentialError("forbidden", "Tenant administrator is required")

    @staticmethod
    def _require_active_steward(
        db: Session,
        tenant_id: UUID,
        space_id: UUID,
        steward_user_id: UUID,
    ) -> None:
        tenant_member = db.get(TenantMembership, (tenant_id, steward_user_id))
        space_member = db.get(SpaceMembership, (tenant_id, space_id, steward_user_id))
        if (
            tenant_member is None
            or tenant_member.status != "active"
            or space_member is None
            or space_member.status != "active"
        ):
            raise ApiCredentialError(
                "invalid_service_account_steward",
                "Service Account steward must be an active member of its Tenant and Space",
            )

    @staticmethod
    def _load_account(
        db: Session, tenant_id: UUID, service_account_id: UUID
    ) -> ServiceAccountRecord:
        account = db.execute(
            sa.select(ServiceAccountRecord).where(
                ServiceAccountRecord.id == service_account_id,
                ServiceAccountRecord.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if account is None:
            raise ApiCredentialError("service_account_not_found", "Service Account was not found")
        return account

    @classmethod
    def _load_active_account(
        cls,
        db: Session,
        tenant_id: UUID,
        service_account_id: UUID,
        *,
        lock: bool,
    ) -> ServiceAccountRecord:
        query = sa.select(ServiceAccountRecord).where(
            ServiceAccountRecord.id == service_account_id,
            ServiceAccountRecord.tenant_id == tenant_id,
        )
        if lock:
            query = query.with_for_update()
        account = db.execute(query).scalar_one_or_none()
        if account is None or account.status != "active":
            raise ApiCredentialError(
                "service_account_not_active", "active Service Account is required"
            )
        return account

    @staticmethod
    def _revoke_active_credentials(db: Session, account_id: UUID, revoked_at: datetime) -> int:
        result = cast(
            CursorResult[tuple[object]],
            db.execute(
                sa.update(ApiCredentialRecord)
                .where(
                    ApiCredentialRecord.service_account_id == account_id,
                    ApiCredentialRecord.status == "active",
                    ApiCredentialRecord.revoked_at.is_(None),
                )
                .values(status="revoked", revoked_at=revoked_at)
            ),
        )
        return result.rowcount

    @staticmethod
    def _load_receipt(
        db: Session,
        tenant_id: UUID,
        idempotency_key: str,
        request_hash: str,
        event_type: str,
    ) -> dict[str, object] | None:
        receipt = db.execute(
            sa.select(ControlPlaneOutboxEvent).where(
                ControlPlaneOutboxEvent.idempotency_key
                == scoped_idempotency_key("tenant", tenant_id, idempotency_key)
            )
        ).scalar_one_or_none()
        if receipt is None:
            return None
        if receipt.request_hash != request_hash or receipt.event_type != event_type:
            raise ApiCredentialError(
                "idempotency_conflict", "idempotency key was used for another request"
            )
        return receipt.payload

    @staticmethod
    def _add_event(
        db: Session,
        *,
        tenant_id: UUID,
        aggregate_type: str,
        aggregate_key: str,
        event_type: str,
        idempotency_key: str,
        request_hash: str,
        payload: dict[str, object],
    ) -> None:
        db.add(
            ControlPlaneOutboxEvent(
                tenant_id=tenant_id,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                event_type=event_type,
                payload=payload,
                idempotency_key=scoped_idempotency_key("tenant", tenant_id, idempotency_key),
                request_hash=request_hash,
                attempt_count=0,
            )
        )

    @staticmethod
    def _account_payload(account: ServiceAccountRecord) -> dict[str, object]:
        return {
            "service_account_id": str(account.id),
            "tenant_id": str(account.tenant_id),
            "space_id": str(account.space_id) if account.space_id else None,
            "project_id": str(account.project_id) if account.project_id else None,
            "name": account.name,
            "description": account.description,
            "steward_user_id": str(account.steward_user_id),
            "status": account.status,
            "security_version": account.security_version,
        }

    @staticmethod
    def _account_from_payload(
        payload: dict[str, object], *, replayed: bool
    ) -> ServiceAccountView:
        return ServiceAccountView(
            id=UUID(cast(str, payload["service_account_id"])),
            tenant_id=UUID(cast(str, payload["tenant_id"])),
            space_id=UUID(cast(str, payload["space_id"])) if payload["space_id"] else None,
            project_id=(
                UUID(cast(str, payload["project_id"])) if payload["project_id"] else None
            ),
            name=cast(str, payload["name"]),
            description=cast(str | None, payload["description"]),
            steward_user_id=UUID(cast(str, payload["steward_user_id"])),
            status=cast(str, payload["status"]),
            security_version=cast(int, payload["security_version"]),
            replayed=replayed,
        )

    @staticmethod
    def _account_view(account: ServiceAccountRecord) -> ServiceAccountView:
        return ServiceAccountView(
            id=account.id,
            tenant_id=account.tenant_id,
            space_id=account.space_id,
            project_id=account.project_id,
            name=account.name,
            description=account.description,
            steward_user_id=account.steward_user_id,
            status=account.status,
            security_version=account.security_version,
        )

    @staticmethod
    def _credential_payload(credential: ApiCredentialRecord) -> dict[str, object]:
        return {
            "credential_id": str(credential.id),
            "service_account_id": str(credential.service_account_id),
            "display_prefix": credential.display_prefix,
            "permission_scopes": list(credential.permission_scopes),
            "allowed_networks": list(credential.allowed_networks),
            "expires_at": credential.expires_at.isoformat(),
        }

    @staticmethod
    def _credential_from_payload(
        payload: dict[str, object], *, token: str | None, replayed: bool
    ) -> IssuedApiCredential:
        return IssuedApiCredential(
            credential_id=UUID(cast(str, payload["credential_id"])),
            service_account_id=UUID(cast(str, payload["service_account_id"])),
            display_prefix=cast(str, payload["display_prefix"]),
            token=token,
            permission_scopes=tuple(cast(list[str], payload["permission_scopes"])),
            allowed_networks=tuple(cast(list[str], payload["allowed_networks"])),
            expires_at=datetime.fromisoformat(cast(str, payload["expires_at"])),
            replayed=replayed,
        )

    @staticmethod
    def _credential_view(credential: ApiCredentialRecord) -> ApiCredentialView:
        return ApiCredentialView(
            id=credential.id,
            service_account_id=credential.service_account_id,
            name=credential.name,
            display_prefix=credential.display_prefix,
            permission_scopes=tuple(credential.permission_scopes),
            allowed_networks=tuple(credential.allowed_networks),
            status=credential.status,
            expires_at=_comparable(credential.expires_at),
            last_used_at=(
                _comparable(credential.last_used_at)
                if credential.last_used_at is not None
                else None
            ),
            last_used_ip=credential.last_used_ip,
            revoked_at=(
                _comparable(credential.revoked_at) if credential.revoked_at is not None else None
            ),
        )

    @staticmethod
    def _mutation_from_payload(
        payload: dict[str, object], *, replayed: bool
    ) -> CredentialMutation:
        return CredentialMutation(
            service_account_id=UUID(cast(str, payload["service_account_id"])),
            security_version=cast(int, payload["security_version"]),
            revoked_credential_count=cast(int, payload["revoked_credential_count"]),
            replayed=replayed,
        )
