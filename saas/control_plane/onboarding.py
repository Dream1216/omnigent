"""Self-service registration and durable, staged Tenant onboarding."""

from __future__ import annotations

import base64
import hmac
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol
from uuid import UUID, uuid4

import sqlalchemy as sa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from omnigent.server.passwords import hash_password
from saas.control_plane.db_models import (
    ControlPlaneOutboxEvent,
    GlobalUser,
    IdentityConnection,
    PasswordCredential,
    Space,
    SpaceMembership,
    Tenant,
    TenantMembership,
)
from saas.control_plane.idempotency import scoped_idempotency_key
from saas.control_plane.lifecycle import normalize_email
from saas.control_plane.onboarding_models import (
    EmailVerificationChallengeRecord,
    RegistrationRateLimitPolicyRecord,
    RegistrationRateLimitRecord,
    SelfServiceEventRecord,
    SelfServiceRegistrationRecord,
    TenantOnboardingRecord,
)
from saas.control_plane.outbox import OutboxPublisher, OutboxPublishError
from saas.control_plane.privacy_lifecycle import password_email_locator_hash
from saas.control_plane.privacy_models import PrivacyIdentityTombstoneRecord
from saas.control_plane.rls import (
    OnboardingRlsContext,
    RegistrationRlsContext,
    apply_onboarding_rls_context,
    apply_registration_rls_context,
)

_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MIN_PASSWORD_LENGTH = 12
_MAX_PASSWORD_LENGTH = 1024
_EMAIL_EVENT = "onboarding.email_verification.requested"
_TENANT_EVENT = "onboarding.tenant.requested"
_BILLING_EVENT = "onboarding.billing.requested"
_WORKFLOW_EVENTS = frozenset(
    {
        _BILLING_EVENT,
        "onboarding.runtime.requested",
        "onboarding.project.requested",
        "onboarding.activation.requested",
        "onboarding.compensation.requested",
    }
)
_EMAIL_ISSUER = "urn:omnigent:self-service-email"
_ZERO_HASH = "0" * 64
_SENSITIVE_EVENT_KEYS = frozenset(
    {"authorization", "code", "credential", "email", "password", "prompt", "secret", "token"}
)


class OnboardingError(RuntimeError):
    """Stable, content-blind failure returned by the onboarding boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retry_after_seconds: int | None = None,
    ) -> None:
        if retry_after_seconds is not None and (
            type(retry_after_seconds) is not int or not 1 <= retry_after_seconds <= 86400
        ):
            raise ValueError("onboarding retry delay must be between 1 and 86400 seconds")
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class OnboardingPlan:
    """Server-owned plan revision; clients may select only its public key."""

    key: str
    policy_revision: str
    trial_days: int
    currency: str = "USD"
    trial_run_limit: int = 100
    trial_concurrency_limit: int = 2
    runtime_type: str = "omnigent"
    capacity_class: str = "starter"
    default_project_name: str = "Getting Started"
    default_project_visibility: str = "private"
    quota_resource: str = "interactive_runs"
    quota_limit: int = 100

    def __post_init__(self) -> None:
        if not self.key.strip() or len(self.key) > 64:
            raise ValueError("onboarding plan key is invalid")
        if not self.policy_revision.strip() or len(self.policy_revision) > 128:
            raise ValueError("onboarding plan policy revision is invalid")
        if not 1 <= self.trial_days <= 90:
            raise ValueError("onboarding trial days must be between 1 and 90")
        if len(self.currency) != 3 or self.currency != self.currency.upper():
            raise ValueError("onboarding plan currency is invalid")
        if self.trial_run_limit <= 0 or self.trial_concurrency_limit <= 0:
            raise ValueError("onboarding plan trial limits must be positive")
        for value, field, maximum in (
            (self.runtime_type, "runtime type", 64),
            (self.capacity_class, "capacity class", 64),
            (self.default_project_name, "default Project name", 256),
            (self.quota_resource, "quota resource", 64),
        ):
            if not value.strip() or len(value) > maximum:
                raise ValueError(f"onboarding plan {field} is invalid")
        if self.default_project_visibility not in {"private", "space", "restricted"}:
            raise ValueError("onboarding default Project visibility is invalid")
        if self.quota_limit <= 0:
            raise ValueError("onboarding plan quota limit must be positive")

    def snapshot(self) -> dict[str, object]:
        """Return the canonical immutable commercial and runtime plan facts."""

        return {
            "capacity_class": self.capacity_class,
            "currency": self.currency,
            "default_project_name": self.default_project_name,
            "default_project_visibility": self.default_project_visibility,
            "key": self.key,
            "policy_revision": self.policy_revision,
            "quota_limit": self.quota_limit,
            "quota_resource": self.quota_resource,
            "runtime_type": self.runtime_type,
            "trial_concurrency_limit": self.trial_concurrency_limit,
            "trial_days": self.trial_days,
            "trial_run_limit": self.trial_run_limit,
        }

    def snapshot_hash(self) -> str:
        """Bind retries to exactly one canonical plan snapshot."""

        return _digest(self.snapshot())

    def public_catalog_entry(self) -> dict[str, object]:
        """Project only customer-selectable, non-operational plan facts."""

        return {
            "currency": self.currency,
            "key": self.key,
            "trial_concurrency_limit": self.trial_concurrency_limit,
            "trial_days": self.trial_days,
            "trial_run_limit": self.trial_run_limit,
        }


@dataclass(frozen=True, slots=True)
class OnboardingPolicy:
    """Deployment-owned plans, regions, slug reservations, and verification TTL."""

    plans: tuple[OnboardingPlan, ...]
    home_regions: frozenset[str]
    reserved_slugs: frozenset[str] = frozenset()
    verification_ttl: timedelta = timedelta(minutes=30)

    def __post_init__(self) -> None:
        keys = [plan.key for plan in self.plans]
        if not keys or len(keys) != len(set(keys)):
            raise ValueError("onboarding plans must be non-empty and unique")
        if not self.home_regions or any(
            not region.strip() or len(region) > 64 for region in self.home_regions
        ):
            raise ValueError("onboarding regions must be non-empty")
        if any(_SLUG.fullmatch(value) is None for value in self.reserved_slugs):
            raise ValueError("reserved onboarding slugs must be normalized")
        if not timedelta(minutes=5) <= self.verification_ttl <= timedelta(hours=24):
            raise ValueError("verification TTL must be between 5 minutes and 24 hours")

    def require_plan(self, key: str, *, revision: str | None = None) -> OnboardingPlan:
        for plan in self.plans:
            if plan.key == key and (revision is None or plan.policy_revision == revision):
                return plan
        raise OnboardingError("plan_unavailable", "selected plan is unavailable")

    def public_catalog(self) -> dict[str, object]:
        """Return one deterministic public snapshot of selectable plans and regions."""

        snapshot: dict[str, object] = {
            "schema_version": 1,
            "plans": [
                plan.public_catalog_entry()
                for plan in sorted(self.plans, key=lambda candidate: candidate.key)
            ],
            "regions": sorted(self.home_regions),
            "verification_ttl_seconds": int(self.verification_ttl.total_seconds()),
        }
        return {**snapshot, "revision": _digest(snapshot)}


class RegistrationRateLimiter(Protocol):
    """Shared, fail-closed rate limiter supplied by the deployment."""

    def consume(
        self,
        db: Session,
        *,
        action: str,
        subject_kind: str,
        subject: str,
    ) -> RegistrationRateLimitDecision: ...

    def require(self, *, action: str, subject_kind: str, subject: str) -> None: ...


@dataclass(frozen=True, slots=True)
class RegistrationRateLimitAliases:
    """At most one active and one previous keyed alias for a subject."""

    active_key_id: str
    active_subject_hmac: str
    previous_key_id: str | None
    previous_subject_hmac: str | None
    anchor_key_id: str
    write_key_id: str


class RegistrationRateLimitSubjectKeyring:
    """Domain-separated subject HMACs with a bounded rotation overlap."""

    __slots__ = (
        "_active_key_id",
        "_anchor_key_id",
        "_keys",
        "_previous_key_id",
        "_write_key_id",
    )

    def __init__(
        self,
        *,
        keys: Mapping[str, bytes],
        active_key_id: str,
        previous_key_id: str | None = None,
        anchor_key_id: str | None = None,
        write_key_id: str | None = None,
        previous_writers_drained: bool = False,
    ) -> None:
        copied = dict(keys)
        admitted_ids = {active_key_id}
        if previous_key_id is not None:
            admitted_ids.add(previous_key_id)
        if (
            not active_key_id
            or active_key_id == previous_key_id
            or set(copied) != admitted_ids
            or any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id) is None
                for key_id in copied
            )
            or any(not isinstance(key, bytes) or len(key) < 32 for key in copied.values())
            or len(set(copied.values())) != len(copied)
            or type(previous_writers_drained) is not bool
        ):
            raise ValueError("registration rate-limit subject keyring is invalid")
        if previous_key_id is None:
            resolved_anchor = active_key_id if anchor_key_id is None else anchor_key_id
            resolved_write = active_key_id if write_key_id is None else write_key_id
            valid_rotation = (
                not previous_writers_drained
                and resolved_anchor == active_key_id
                and resolved_write == active_key_id
            )
        else:
            resolved_anchor = previous_key_id if anchor_key_id is None else anchor_key_id
            expected_write = active_key_id if previous_writers_drained else previous_key_id
            resolved_write = expected_write if write_key_id is None else write_key_id
            valid_rotation = (
                resolved_anchor == previous_key_id and resolved_write == expected_write
            )
        if not valid_rotation:
            raise ValueError("registration rate-limit rotation IDs are invalid")
        self._keys = copied
        self._active_key_id = active_key_id
        self._previous_key_id = previous_key_id
        self._anchor_key_id = resolved_anchor
        self._write_key_id = resolved_write

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def anchor_key_id(self) -> str:
        return self._anchor_key_id

    @property
    def write_key_id(self) -> str:
        return self._write_key_id

    def aliases(
        self,
        *,
        action: str,
        subject_kind: str,
        subject: str,
    ) -> RegistrationRateLimitAliases:
        if not subject or len(subject) > 1024 or "\x00" in subject:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            )
        domain = (
            b"omnigent.registration-rate-limit.v1\x00"
            + action.encode("utf-8")
            + b"\x00"
            + subject_kind.encode("utf-8")
            + b"\x00"
            + subject.encode("utf-8")
        )

        def digest(key_id: str) -> str:
            return hmac.digest(self._keys[key_id], domain, "sha256").hex()

        return RegistrationRateLimitAliases(
            active_key_id=self._active_key_id,
            active_subject_hmac=digest(self._active_key_id),
            previous_key_id=self._previous_key_id,
            previous_subject_hmac=(
                digest(self._previous_key_id) if self._previous_key_id is not None else None
            ),
            anchor_key_id=self._anchor_key_id,
            write_key_id=self._write_key_id,
        )


@dataclass(frozen=True, slots=True)
class RegistrationRateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    remaining: int
    policy_revision: str


_SQLITE_RATE_LIMIT_POLICIES = (
    ("registration.request", "email", 5, 900, 86400, 1_000_000),
    ("registration.request", "network", 60, 900, 86400, 1_000_000),
    ("registration.resend", "email", 3, 900, 86400, 1_000_000),
    ("registration.resend", "network", 60, 900, 86400, 1_000_000),
    ("registration.verify", "registration", 10, 900, 86400, 1_000_000),
    ("registration.verify", "network", 120, 900, 86400, 1_000_000),
)


class SharedRegistrationRateLimiter:
    """Database-authoritative counter shared by every onboarding replica."""

    __slots__ = ("_clock", "_keyring", "_sessions")

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        subject_keyring: RegistrationRateLimitSubjectKeyring,
        development_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(session_factory) or session_factory.kw.get("bind") is None:
            raise TypeError("registration rate limiter requires a bound Session factory")
        if (
            session_factory.kw["bind"].dialect.name == "postgresql"
            and development_clock is not None
        ):
            raise TypeError("PostgreSQL registration rate limiter uses only the database clock")
        self._sessions = session_factory
        self._keyring = subject_keyring
        self._clock = development_clock or _now
        if session_factory.kw["bind"].dialect.name != "postgresql":
            self._seed_sqlite_policies()

    def is_bound_to(self, session_factory: sessionmaker[Session]) -> bool:
        """Prove the limiter uses the exact registration database authority."""

        return self._sessions is session_factory

    def require(self, *, action: str, subject_kind: str, subject: str) -> None:
        """Consume one DB-owned allowance and raise only after denial commits."""

        try:
            with self._sessions.begin() as db:
                decision = self.consume(
                    db,
                    action=action,
                    subject_kind=subject_kind,
                    subject=subject,
                )
        except OnboardingError:
            raise
        except Exception as error:
            # The context-manager exit performs COMMIT.  A failure there must
            # remain fail-closed and must win over a pending 429 decision.
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            ) from error
        if not decision.allowed:
            raise OnboardingError(
                "registration_rate_limited",
                "registration request rate limit exceeded",
                retry_after_seconds=decision.retry_after_seconds,
            )

    def consume(
        self,
        db: Session,
        *,
        action: str,
        subject_kind: str,
        subject: str,
    ) -> RegistrationRateLimitDecision:
        """Consume within the caller transaction so replay and domain writes serialize."""

        try:
            if not db.in_transaction() or db.get_bind() is not self._sessions.kw.get("bind"):
                raise RuntimeError("registration rate limiter transaction mismatch")
            aliases = self._keyring.aliases(
                action=action,
                subject_kind=subject_kind,
                subject=subject,
            )
            if db.get_bind().dialect.name == "postgresql":
                return self._consume_postgresql(
                    db,
                    action=action,
                    subject_kind=subject_kind,
                    aliases=aliases,
                )
            return self._consume_sqlite(
                db,
                action=action,
                subject_kind=subject_kind,
                aliases=aliases,
            )
        except OnboardingError:
            raise
        except Exception as error:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            ) from error

    def _seed_sqlite_policies(self) -> None:
        with self._sessions.begin() as db:
            for (
                action,
                subject_kind,
                limit_count,
                window,
                retention,
                maximum,
            ) in _SQLITE_RATE_LIMIT_POLICIES:
                if db.get(RegistrationRateLimitPolicyRecord, (action, subject_kind)) is None:
                    db.add(
                        RegistrationRateLimitPolicyRecord(
                            action=action,
                            subject_kind=subject_kind,
                            limit_count=limit_count,
                            window_seconds=window,
                            retention_seconds=retention,
                            max_rows=maximum,
                            current_rows=0,
                            policy_revision="registration-rate-limit-v1",
                        )
                    )

    @staticmethod
    def _consume_postgresql(
        db: Session,
        *,
        action: str,
        subject_kind: str,
        aliases: RegistrationRateLimitAliases,
    ) -> RegistrationRateLimitDecision:
        row = (
            db.execute(
                sa.text(
                    "SELECT allowed, retry_after_seconds, remaining, policy_revision "
                    "FROM public.saas_consume_registration_rate_limit("
                    ":action, :subject_kind, :active_key_id, :active_subject_hmac, "
                    ":previous_key_id, :previous_subject_hmac, :anchor_key_id, :write_key_id)"
                ),
                {
                    "action": action,
                    "subject_kind": subject_kind,
                    "active_key_id": aliases.active_key_id,
                    "active_subject_hmac": aliases.active_subject_hmac,
                    "previous_key_id": aliases.previous_key_id,
                    "previous_subject_hmac": aliases.previous_subject_hmac,
                    "anchor_key_id": aliases.anchor_key_id,
                    "write_key_id": aliases.write_key_id,
                },
            )
            .mappings()
            .one()
        )
        return RegistrationRateLimitDecision(
            allowed=bool(row["allowed"]),
            retry_after_seconds=int(row["retry_after_seconds"]),
            remaining=int(row["remaining"]),
            policy_revision=str(row["policy_revision"]),
        )

    def _consume_sqlite(
        self,
        db: Session,
        *,
        action: str,
        subject_kind: str,
        aliases: RegistrationRateLimitAliases,
    ) -> RegistrationRateLimitDecision:
        checked_at = _stored_time(self._clock())
        policy = db.get(RegistrationRateLimitPolicyRecord, (action, subject_kind))
        if policy is None:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            )
        expired = list(
            db.scalars(
                sa.select(RegistrationRateLimitRecord)
                .where(
                    RegistrationRateLimitRecord.action == action,
                    RegistrationRateLimitRecord.subject_kind == subject_kind,
                    RegistrationRateLimitRecord.expires_at <= checked_at,
                )
                .order_by(RegistrationRateLimitRecord.expires_at)
                .limit(32)
            )
        )
        for record in expired:
            db.delete(record)
        policy.current_rows -= len(expired)
        alias_pairs = [(aliases.active_key_id, aliases.active_subject_hmac)]
        if aliases.previous_key_id is not None and aliases.previous_subject_hmac is not None:
            alias_pairs.append((aliases.previous_key_id, aliases.previous_subject_hmac))
        rows = list(
            db.scalars(
                sa.select(RegistrationRateLimitRecord).where(
                    RegistrationRateLimitRecord.action == action,
                    RegistrationRateLimitRecord.subject_kind == subject_kind,
                    sa.tuple_(
                        RegistrationRateLimitRecord.key_id,
                        RegistrationRateLimitRecord.subject_hmac,
                    ).in_(alias_pairs),
                )
            )
        )
        active_rows = [
            row
            for row in rows
            if checked_at
            < _stored_time(row.window_started_at) + timedelta(seconds=policy.window_seconds)
        ]
        count = sum(row.request_count for row in active_rows)
        window_started_at = (
            min(_stored_time(row.window_started_at) for row in active_rows)
            if active_rows
            else checked_at
        )
        allowed = count < policy.limit_count
        saturated_count = min(policy.limit_count, count + 1)
        write_hmac = (
            aliases.active_subject_hmac
            if aliases.write_key_id == aliases.active_key_id
            else aliases.previous_subject_hmac
        )
        if write_hmac is None:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            )
        write_record = next(
            (
                row
                for row in rows
                if row.key_id == aliases.write_key_id and row.subject_hmac == write_hmac
            ),
            None,
        )
        for row in rows:
            if row is not write_record:
                db.delete(row)
        policy.current_rows -= len(rows) - (1 if write_record is not None else 0)
        if write_record is None and policy.current_rows >= policy.max_rows:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            )
        values = {
            "window_started_at": window_started_at,
            "request_count": saturated_count,
            "expires_at": window_started_at + timedelta(seconds=policy.retention_seconds),
            "policy_revision": policy.policy_revision,
            "version": max((row.version for row in rows), default=0) + 1,
            "updated_at": checked_at,
        }
        if write_record is None:
            write_record = RegistrationRateLimitRecord(
                action=action,
                subject_kind=subject_kind,
                key_id=aliases.write_key_id,
                subject_hmac=write_hmac,
                created_at=checked_at,
                **values,
            )
            db.add(write_record)
            policy.current_rows += 1
        else:
            for name, value in values.items():
                setattr(write_record, name, value)
        policy.updated_at = checked_at
        retry_after = 0
        if not allowed:
            retry_after = max(
                1,
                int(
                    (
                        window_started_at + timedelta(seconds=policy.window_seconds) - checked_at
                    ).total_seconds()
                ),
            )
        return RegistrationRateLimitDecision(
            allowed=allowed,
            retry_after_seconds=retry_after,
            remaining=max(0, policy.limit_count - saturated_count),
            policy_revision=policy.policy_revision,
        )


class SharedRegistrationRateLimitJanitor:
    """Bounded maintenance adapter for the database-owned prune function."""

    __slots__ = ("_sessions",)

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        if not callable(session_factory) or session_factory.kw.get("bind") is None:
            raise TypeError("registration rate-limit janitor requires a bound Session factory")
        self._sessions = session_factory

    def prune(self, *, action: str, subject_kind: str, batch_size: int = 256) -> int:
        if not 1 <= batch_size <= 1000:
            raise ValueError("registration rate-limit prune batch is invalid")
        try:
            with self._sessions.begin() as db:
                return int(
                    db.scalar(
                        sa.text(
                            "SELECT public.saas_prune_registration_rate_limits("
                            ":action, :subject_kind, :batch_size)"
                        ),
                        {
                            "action": action,
                            "subject_kind": subject_kind,
                            "batch_size": batch_size,
                        },
                    )
                    or 0
                )
        except Exception as error:
            raise OnboardingError(
                "registration_rate_limit_unavailable",
                "registration abuse protection is unavailable",
            ) from error


@dataclass(frozen=True, slots=True)
class EmailVerificationMessage:
    registration_id: UUID
    challenge_id: UUID
    email: str
    verification_token: str
    expires_at: datetime


class EmailVerificationSender(Protocol):
    """Provider adapter that deduplicates delivery by immutable Outbox event ID."""

    def send_verification(self, *, event_id: UUID, message: EmailVerificationMessage) -> None: ...


class TenantOnboardingEventHandler(Protocol):
    """One-stage Saga consumer injected by the production composition root."""

    def handle_event(self, *, event_type: str, payload: dict[str, object]) -> object: ...


@dataclass(frozen=True, slots=True)
class RegistrationAccepted:
    registration_id: UUID
    expires_at: datetime
    replayed: bool


@dataclass(frozen=True, slots=True)
class OnboardingRequested:
    registration_id: UUID
    onboarding_id: UUID
    user_id: UUID
    tenant_id: UUID
    space_id: UUID
    subscription_id: UUID
    runtime_partition_id: UUID
    default_project_id: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class TenantOnboardingStarted:
    onboarding_id: UUID
    registration_id: UUID
    user_id: UUID
    tenant_id: UUID
    space_id: UUID
    default_project_id: UUID
    status: str
    replayed: bool


class VerificationEnvelopeKeyring:
    """AES-GCM envelope for email address and one-time verification token."""

    def __init__(self, *, active_key_id: str, keys: dict[str, bytes]) -> None:
        if not active_key_id or len(active_key_id) > 128 or active_key_id not in keys:
            raise ValueError("verification envelope active key is invalid")
        if any(not key_id or len(key_id) > 128 or len(key) != 32 for key_id, key in keys.items()):
            raise ValueError("verification envelope keys must be named 256-bit keys")
        self._active_key_id = active_key_id
        self._keys = dict(keys)

    def seal(self, *, event_id: UUID, message: EmailVerificationMessage) -> dict[str, object]:
        body = json.dumps(
            {
                "registration_id": str(message.registration_id),
                "challenge_id": str(message.challenge_id),
                "email": message.email,
                "verification_token": message.verification_token,
                "expires_at": _stored_time(message.expires_at).isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(self._keys[self._active_key_id])
        encrypted = cipher.encrypt(nonce, body, _email_aad(event_id))
        return {
            "schema_version": 1,
            "key_id": self._active_key_id,
            "ciphertext": _b64(nonce + encrypted),
            "expires_at": _stored_time(message.expires_at).isoformat(),
        }

    def open(self, *, event_id: UUID, payload: dict[str, object]) -> EmailVerificationMessage:
        try:
            if payload.get("schema_version") != 1:
                raise ValueError("schema")
            key_id = payload["key_id"]
            encoded = payload["ciphertext"]
            if not isinstance(key_id, str) or key_id not in self._keys:
                raise ValueError("key")
            if not isinstance(encoded, str):
                raise ValueError("ciphertext")
            packed = _unb64(encoded)
            if len(packed) <= 12:
                raise ValueError("ciphertext")
            plaintext = AESGCM(self._keys[key_id]).decrypt(
                packed[:12], packed[12:], _email_aad(event_id)
            )
            body = json.loads(plaintext)
            if not isinstance(body, dict):
                raise ValueError("body")
            expires_at = datetime.fromisoformat(str(body["expires_at"]))
            return EmailVerificationMessage(
                registration_id=UUID(str(body["registration_id"])),
                challenge_id=UUID(str(body["challenge_id"])),
                email=str(body["email"]),
                verification_token=str(body["verification_token"]),
                expires_at=_stored_time(expires_at),
            )
        except Exception as error:
            raise OnboardingError(
                "verification_envelope_invalid", "verification delivery envelope is invalid"
            ) from error


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stored_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return _hash(encoded)


def _text(value: str, field: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum:
        raise OnboardingError("registration_invalid", f"{field} is invalid")
    return cleaned


def _slug(value: str, field: str, reserved: frozenset[str]) -> str:
    cleaned = value.strip().lower()
    if _SLUG.fullmatch(cleaned) is None or cleaned in reserved:
        raise OnboardingError("registration_invalid", f"{field} is invalid")
    return cleaned


def _idempotency_key(scope: str, scope_id: UUID | str, value: str) -> str:
    if not value or len(value) > 128:
        raise OnboardingError("invalid_idempotency_key", "idempotency key is invalid")
    return scoped_idempotency_key(scope, scope_id, value)


def _validated_password(password: str) -> str:
    if (
        not isinstance(password, str)
        or not _MIN_PASSWORD_LENGTH <= len(password) <= _MAX_PASSWORD_LENGTH
    ):
        raise OnboardingError(
            "password_policy",
            f"password must contain {_MIN_PASSWORD_LENGTH} to {_MAX_PASSWORD_LENGTH} characters",
        )
    return password


def _password_hash(password: str) -> str:
    return hash_password(_validated_password(password))


def _lock_registration_idempotency(db: Session, scoped_key: str) -> None:
    """Serialize one registration idempotency key across PostgreSQL replicas."""

    if db.get_bind().dialect.name != "postgresql":
        return
    db.execute(
        sa.text(
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:lock_key, 0))"
        ),
        {"lock_key": f"registration-idempotency|{scoped_key}"},
    )


def _rate_limit_error(decision: RegistrationRateLimitDecision) -> OnboardingError:
    return OnboardingError(
        "registration_rate_limited",
        "registration request rate limit exceeded",
        retry_after_seconds=decision.retry_after_seconds,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _email_aad(event_id: UUID) -> bytes:
    return f"{_EMAIL_EVENT}\0{event_id}".encode()


def _integrity_constraint(error: IntegrityError) -> str | None:
    """Return a stable constraint name across psycopg and SQLite test failures."""

    diagnostic = getattr(error.orig, "diag", None)
    name = getattr(diagnostic, "constraint_name", None)
    if isinstance(name, str) and name:
        return name
    message = str(error.orig)
    if "saas_self_service_registrations.email_hash" in message:
        return "uq_open_self_service_email"
    if "saas_self_service_registrations.tenant_slug" in message:
        return "uq_open_self_service_tenant_slug"
    return None


class SelfServiceOnboardingService:
    """Register an identity and persist Tenant provisioning intent without fake readiness."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        policy: OnboardingPolicy,
        envelope_keyring: VerificationEnvelopeKeyring,
        rate_limiter: RegistrationRateLimiter,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy
        self._envelopes = envelope_keyring
        self._rate_limiter = rate_limiter

    def require_network_rate_limit(self, *, action: str, subject: str) -> None:
        """Consume the transport-derived network bucket before HTTP body parsing."""

        self._rate_limiter.require(
            action=action,
            subject_kind="network",
            subject=subject,
        )

    def public_catalog(self) -> dict[str, object]:
        """Return the deployment policy's allowlisted anonymous catalog projection."""

        return self._policy.public_catalog()

    def request_registration(
        self,
        *,
        email: str,
        display_name: str | None,
        tenant_name: str,
        tenant_slug: str,
        default_space_name: str,
        default_space_slug: str,
        plan_key: str,
        home_region: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RegistrationAccepted:
        requested_at = _stored_time(now or _now())
        normalized_email = normalize_email(email)
        email_hash = password_email_locator_hash(normalized_email)
        cleaned_display_name = (
            _text(display_name, "display_name", 256) if display_name is not None else None
        )
        cleaned_tenant_name = _text(tenant_name, "tenant_name", 256)
        cleaned_tenant_slug = _slug(tenant_slug, "tenant_slug", self._policy.reserved_slugs)
        cleaned_space_name = _text(default_space_name, "default_space_name", 256)
        cleaned_space_slug = _slug(
            default_space_slug, "default_space_slug", self._policy.reserved_slugs
        )
        plan = self._policy.require_plan(plan_key)
        plan_snapshot = plan.snapshot()
        plan_snapshot_hash = plan.snapshot_hash()
        if home_region not in self._policy.home_regions:
            raise OnboardingError("region_unavailable", "selected home region is unavailable")
        scoped_key = _idempotency_key("registration-request", email_hash, idempotency_key)
        request_payload: dict[str, object] = {
            "email_hash": email_hash,
            "display_name": cleaned_display_name,
            "tenant_name": cleaned_tenant_name,
            "tenant_slug": cleaned_tenant_slug,
            "default_space_name": cleaned_space_name,
            "default_space_slug": cleaned_space_slug,
            "plan_key": plan.key,
            "plan_policy_revision": plan.policy_revision,
            "plan_snapshot_hash": plan_snapshot_hash,
            "home_region": home_region,
        }
        request_hash = _digest(request_payload)
        registration_id = uuid4()
        challenge_id = uuid4()
        event_id = uuid4()
        token = secrets.token_urlsafe(32)
        token_hash = _hash(token)
        expires_at = requested_at + self._policy.verification_ttl
        delivery_key = scoped_idempotency_key(
            "registration-delivery", registration_id, "generation-1"
        )
        record = SelfServiceRegistrationRecord(
            id=registration_id,
            email_normalized=normalized_email,
            email_hash=email_hash,
            display_name=cleaned_display_name,
            tenant_name=cleaned_tenant_name,
            tenant_slug=cleaned_tenant_slug,
            default_space_name=cleaned_space_name,
            default_space_slug=cleaned_space_slug,
            plan_key=plan.key,
            plan_policy_revision=plan.policy_revision,
            home_region=home_region,
            status="pending_verification",
            challenge_generation=1,
            expires_at=expires_at,
            verified_at=None,
            terminal_at=None,
            user_id=uuid4(),
            tenant_id=uuid4(),
            space_id=uuid4(),
            subscription_id=uuid4(),
            pricing_snapshot_id=uuid4(),
            entitlement_id=uuid4(),
            runtime_partition_id=uuid4(),
            default_project_id=uuid4(),
            runtime_binding_id=uuid4(),
            plan_snapshot=plan_snapshot,
            plan_snapshot_hash=plan_snapshot_hash,
            onboarding_id=uuid4(),
            idempotency_key=scoped_key,
            request_hash=request_hash,
            version=1,
            created_at=requested_at,
            updated_at=requested_at,
        )
        try:
            with self._session_factory.begin() as db:
                self._registration_context(
                    db,
                    registration_id=registration_id,
                    token_hash=token_hash,
                    email_hash=email_hash,
                    idempotency_key=scoped_key,
                )
                _lock_registration_idempotency(db, scoped_key)
                replay = db.scalar(
                    sa.select(SelfServiceRegistrationRecord).where(
                        SelfServiceRegistrationRecord.idempotency_key == scoped_key
                    )
                )
                if replay is not None:
                    return self._registration_replay(replay, request_hash)
                decision = self._rate_limiter.consume(
                    db,
                    action="registration.request",
                    subject_kind="email",
                    subject=normalized_email,
                )
                if not decision.allowed:
                    # Keep email-specific throttling non-enumerating.  The HTTP
                    # network bucket is the only anonymous 429 surface.
                    return RegistrationAccepted(registration_id, expires_at, replayed=False)
                db.add(record)
                db.flush()
                if self._email_is_blocked(db, record):
                    record.status = "suppressed"
                    record.terminal_at = requested_at
                    record.version += 1
                    self._append_event(
                        db,
                        aggregate_type="registration",
                        aggregate_id=record.id,
                        tenant_id=None,
                        user_id=None,
                        event_type="registration.suppressed",
                        from_status="pending_verification",
                        to_status="suppressed",
                        facts={"plan_policy_revision": plan.policy_revision},
                        occurred_at=requested_at,
                    )
                else:
                    challenge = EmailVerificationChallengeRecord(
                        id=challenge_id,
                        registration_id=record.id,
                        generation=1,
                        token_hash=token_hash,
                        status="pending",
                        delivery_status="pending",
                        delivery_attempts=0,
                        delivery_idempotency_key=delivery_key,
                        expires_at=expires_at,
                        created_at=requested_at,
                        updated_at=requested_at,
                    )
                    db.add(challenge)
                    message = EmailVerificationMessage(
                        registration_id=record.id,
                        challenge_id=challenge.id,
                        email=record.email_normalized,
                        verification_token=token,
                        expires_at=expires_at,
                    )
                    envelope = self._envelopes.seal(event_id=event_id, message=message)
                    db.add(
                        ControlPlaneOutboxEvent(
                            id=event_id,
                            tenant_id=None,
                            aggregate_type="self_service_registration",
                            aggregate_key=str(record.id),
                            event_type=_EMAIL_EVENT,
                            idempotency_key=delivery_key,
                            request_hash=_digest(envelope),
                            payload=envelope,
                            attempt_count=0,
                        )
                    )
                    self._append_event(
                        db,
                        aggregate_type="registration",
                        aggregate_id=record.id,
                        tenant_id=None,
                        user_id=None,
                        event_type="registration.requested",
                        from_status=None,
                        to_status=None,
                        facts={
                            "challenge_generation": 1,
                            "plan_policy_revision": plan.policy_revision,
                            "plan_snapshot_hash": plan_snapshot_hash,
                            "home_region": home_region,
                        },
                        occurred_at=requested_at,
                    )
        except IntegrityError as error:
            replay = self._load_registration_replay(
                scoped_key=scoped_key,
                email_hash=email_hash,
                request_hash=request_hash,
            )
            if replay is not None:
                return replay
            if _integrity_constraint(error) == "uq_open_self_service_email":
                # Preserve the same public response for an address that already has a
                # pending challenge. The synthetic ID is deliberately not persisted;
                # the original delivery remains the sole verification authority.
                return RegistrationAccepted(registration_id, expires_at, replayed=False)
            raise OnboardingError(
                "registration_unavailable", "registration request cannot be accepted"
            ) from error
        return RegistrationAccepted(registration_id, expires_at, replayed=False)

    def resend_verification(
        self,
        *,
        registration_id: UUID,
        email: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RegistrationAccepted:
        attempted_at = _stored_time(now or _now())
        normalized_email = normalize_email(email)
        email_hash = password_email_locator_hash(normalized_email)
        scoped_key = _idempotency_key("registration-resend", registration_id, idempotency_key)
        public_expiry = attempted_at + self._policy.verification_ttl
        token = secrets.token_urlsafe(32)
        token_hash = _hash(token)
        event_id = uuid4()
        with self._session_factory.begin() as db:
            self._registration_context(
                db,
                registration_id=registration_id,
                email_hash=email_hash,
                idempotency_key=scoped_key,
            )
            record = db.scalar(
                sa.select(SelfServiceRegistrationRecord)
                .where(SelfServiceRegistrationRecord.id == registration_id)
                .with_for_update()
            )
            if (
                record is None
                or not hmac.compare_digest(record.email_hash, email_hash)
                or record.status != "pending_verification"
            ):
                return RegistrationAccepted(registration_id, public_expiry, replayed=False)
            replay = db.scalar(
                sa.select(EmailVerificationChallengeRecord).where(
                    EmailVerificationChallengeRecord.registration_id == registration_id,
                    EmailVerificationChallengeRecord.delivery_idempotency_key == scoped_key,
                )
            )
            if replay is not None:
                return RegistrationAccepted(
                    registration_id, _stored_time(replay.expires_at), replayed=True
                )
            decision = self._rate_limiter.consume(
                db,
                action="registration.resend",
                subject_kind="email",
                subject=record.email_normalized,
            )
            if not decision.allowed:
                # A 429 here would reveal which registration/email pair exists.
                # Commit only the counter and preserve the generic 202 shape.
                return RegistrationAccepted(registration_id, public_expiry, replayed=False)
            current = db.scalar(
                sa.select(EmailVerificationChallengeRecord)
                .where(
                    EmailVerificationChallengeRecord.registration_id == registration_id,
                    EmailVerificationChallengeRecord.status == "pending",
                )
                .with_for_update()
            )
            if current is not None:
                current.status = "revoked"
                current.revoked_at = attempted_at
                current.updated_at = attempted_at
            record.challenge_generation += 1
            record.expires_at = public_expiry
            record.version += 1
            record.updated_at = attempted_at
            challenge = EmailVerificationChallengeRecord(
                id=uuid4(),
                registration_id=record.id,
                generation=record.challenge_generation,
                token_hash=token_hash,
                status="pending",
                delivery_status="pending",
                delivery_attempts=0,
                delivery_idempotency_key=scoped_key,
                expires_at=public_expiry,
                created_at=attempted_at,
                updated_at=attempted_at,
            )
            db.add(challenge)
            envelope = self._envelopes.seal(
                event_id=event_id,
                message=EmailVerificationMessage(
                    registration_id=record.id,
                    challenge_id=challenge.id,
                    email=record.email_normalized,
                    verification_token=token,
                    expires_at=public_expiry,
                ),
            )
            db.add(
                ControlPlaneOutboxEvent(
                    id=event_id,
                    tenant_id=None,
                    aggregate_type="self_service_registration",
                    aggregate_key=str(record.id),
                    event_type=_EMAIL_EVENT,
                    idempotency_key=scoped_key,
                    request_hash=_digest(envelope),
                    payload=envelope,
                    attempt_count=0,
                )
            )
            self._append_event(
                db,
                aggregate_type="registration",
                aggregate_id=record.id,
                tenant_id=None,
                user_id=None,
                event_type="registration.verification_resent",
                from_status="pending_verification",
                to_status="pending_verification",
                facts={"challenge_generation": record.challenge_generation},
                occurred_at=attempted_at,
            )
        return RegistrationAccepted(registration_id, public_expiry, replayed=False)

    def verify_and_request_onboarding(
        self,
        *,
        registration_id: UUID,
        verification_token: str,
        password: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> OnboardingRequested:
        verified_at = _stored_time(now or _now())
        token_hash = _hash(_text(verification_token, "verification_token", 1024))
        _validated_password(password)
        scoped_key = _idempotency_key("registration-verify", registration_id, idempotency_key)
        failure: OnboardingError | None = None
        result: OnboardingRequested | None = None
        try:
            with self._session_factory.begin() as db:
                self._registration_context(
                    db,
                    registration_id=registration_id,
                    token_hash=token_hash,
                    idempotency_key=scoped_key,
                )
                record = db.scalar(
                    sa.select(SelfServiceRegistrationRecord)
                    .where(SelfServiceRegistrationRecord.id == registration_id)
                    .with_for_update()
                )
                challenge = db.scalar(
                    sa.select(EmailVerificationChallengeRecord)
                    .where(
                        EmailVerificationChallengeRecord.registration_id == registration_id,
                        EmailVerificationChallengeRecord.token_hash == token_hash,
                    )
                    .with_for_update()
                )
                if record is None or challenge is None:
                    raise OnboardingError(
                        "verification_invalid", "verification request is invalid"
                    )
                if record.status == "verified" and challenge.status == "consumed":
                    self._require_verification_receipt(db, record, scoped_key)
                    return self._requested(record, replayed=True)
                if (
                    record.status != "pending_verification"
                    or challenge.status != "pending"
                    or challenge.generation != record.challenge_generation
                ):
                    raise OnboardingError(
                        "verification_invalid", "verification request is invalid"
                    )
                if _stored_time(challenge.expires_at) <= verified_at:
                    challenge.status = "expired"
                    challenge.expired_at = verified_at
                    challenge.updated_at = verified_at
                    record.status = "expired"
                    record.terminal_at = verified_at
                    record.version += 1
                    record.updated_at = verified_at
                    self._append_event(
                        db,
                        aggregate_type="registration",
                        aggregate_id=record.id,
                        tenant_id=None,
                        user_id=None,
                        event_type="registration.expired",
                        from_status="pending_verification",
                        to_status="expired",
                        facts={"challenge_generation": challenge.generation},
                        occurred_at=verified_at,
                    )
                    failure = OnboardingError(
                        "verification_invalid", "verification request is invalid"
                    )
                elif self._email_is_blocked(db, record):
                    challenge.status = "revoked"
                    challenge.revoked_at = verified_at
                    challenge.updated_at = verified_at
                    record.status = "revoked"
                    record.terminal_at = verified_at
                    record.version += 1
                    record.updated_at = verified_at
                    self._append_event(
                        db,
                        aggregate_type="registration",
                        aggregate_id=record.id,
                        tenant_id=None,
                        user_id=None,
                        event_type="registration.identity_conflict",
                        from_status="pending_verification",
                        to_status="revoked",
                        facts={"challenge_generation": challenge.generation},
                        occurred_at=verified_at,
                    )
                    failure = OnboardingError(
                        "identity_confirmation_required",
                        "existing identity must be confirmed by signing in",
                    )
                else:
                    self._policy.require_plan(
                        record.plan_key, revision=record.plan_policy_revision
                    )
                    decision = self._rate_limiter.consume(
                        db,
                        action="registration.verify",
                        subject_kind="registration",
                        subject=str(record.id),
                    )
                    if not decision.allowed:
                        # Raise only after the surrounding context has committed the
                        # saturated counter. No domain state changes occur on this branch.
                        failure = _rate_limit_error(decision)
                    else:
                        # Run the expensive KDF only after the single-use challenge has
                        # been authenticated and locked. Random public requests must not
                        # be able to consume Argon2 capacity.
                        password_hash = _password_hash(password)
                        challenge.status = "consumed"
                        challenge.consumed_at = verified_at
                        challenge.updated_at = verified_at
                        record.status = "verified"
                        record.verified_at = verified_at
                        record.terminal_at = verified_at
                        record.version += 1
                        record.updated_at = verified_at
                        # RLS for the identity and Tenant-request Outbox requires the
                        # durable registration row to already be verified. Flush only
                        # these locked state transitions before adding dependent rows;
                        # the surrounding transaction still rolls everything back on
                        # any later failure.
                        db.flush()
                        db.add(
                            GlobalUser(
                                id=record.user_id,
                                status="active",
                                display_name=record.display_name,
                                primary_email_normalized=record.email_normalized,
                                security_version=1,
                            )
                        )
                        db.add(
                            IdentityConnection(
                                id=uuid4(),
                                user_id=record.user_id,
                                provider="password",
                                issuer=_EMAIL_ISSUER,
                                subject=_hash(f"{_EMAIL_ISSUER}\0{record.email_normalized}"),
                                email_normalized=record.email_normalized,
                                email_verified=True,
                                status="active",
                            )
                        )
                        db.add(
                            PasswordCredential(
                                user_id=record.user_id,
                                login_email_normalized=record.email_normalized,
                                password_hash=password_hash,
                                password_version=1,
                                failed_attempts=0,
                            )
                        )
                        event_payload: dict[str, object] = {
                            "registration_id": str(record.id),
                            "onboarding_id": str(record.onboarding_id),
                            "user_id": str(record.user_id),
                            "tenant_id": str(record.tenant_id),
                            "plan_policy_revision": record.plan_policy_revision,
                        }
                        db.add(
                            ControlPlaneOutboxEvent(
                                tenant_id=None,
                                aggregate_type="tenant_onboarding",
                                aggregate_key=str(record.onboarding_id),
                                event_type=_TENANT_EVENT,
                                idempotency_key=scoped_idempotency_key(
                                    "registration", record.id, "tenant-requested"
                                ),
                                request_hash=_digest(event_payload),
                                payload=event_payload,
                                attempt_count=0,
                            )
                        )
                        self._append_event(
                            db,
                            aggregate_type="registration",
                            aggregate_id=record.id,
                            tenant_id=None,
                            user_id=record.user_id,
                            event_type="registration.verified",
                            from_status="pending_verification",
                            to_status="verified",
                            facts={
                                "challenge_generation": challenge.generation,
                                "onboarding_id": str(record.onboarding_id),
                                "verification_receipt_hash": scoped_key,
                            },
                            occurred_at=verified_at,
                        )
                        db.flush()
                        result = self._requested(record, replayed=False)
        except IntegrityError as error:
            raise OnboardingError(
                "registration_unavailable", "registration cannot be verified"
            ) from error
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def verify_and_provision(self, **kwargs: object) -> OnboardingRequested:
        """Compatibility alias; provisioning remains asynchronous and fail-closed."""

        return self.verify_and_request_onboarding(**kwargs)  # type: ignore[arg-type]

    def record_email_delivery(
        self,
        *,
        message: EmailVerificationMessage,
        succeeded: bool,
        error_code: str | None,
        attempted_at: datetime | None = None,
    ) -> None:
        recorded_at = _stored_time(attempted_at or _now())
        token_hash = _hash(message.verification_token)
        with self._session_factory.begin() as db:
            self._registration_context(
                db,
                registration_id=message.registration_id,
                token_hash=token_hash,
            )
            challenge = db.scalar(
                sa.select(EmailVerificationChallengeRecord)
                .where(
                    EmailVerificationChallengeRecord.id == message.challenge_id,
                    EmailVerificationChallengeRecord.registration_id == message.registration_id,
                    EmailVerificationChallengeRecord.token_hash == token_hash,
                )
                .with_for_update()
            )
            if challenge is None:
                return
            challenge.delivery_attempts += 1
            challenge.delivery_status = "sent" if succeeded else "failed"
            challenge.delivered_at = recorded_at if succeeded else None
            challenge.last_delivery_error_code = None if succeeded else error_code
            challenge.updated_at = recorded_at
            self._append_event(
                db,
                aggregate_type="registration",
                aggregate_id=message.registration_id,
                tenant_id=None,
                user_id=None,
                event_type=(
                    "registration.email_delivery_succeeded"
                    if succeeded
                    else "registration.email_delivery_failed"
                ),
                from_status=None,
                to_status=None,
                facts={
                    "challenge_generation": challenge.generation,
                    "delivery_attempt": challenge.delivery_attempts,
                    "outcome": "sent" if succeeded else "failed",
                },
                occurred_at=recorded_at,
            )

    def email_delivery_is_current(
        self,
        *,
        message: EmailVerificationMessage,
        now: datetime | None = None,
    ) -> bool:
        """Confirm an Outbox envelope still names the active challenge generation."""

        checked_at = _stored_time(now or _now())
        token_hash = _hash(message.verification_token)
        with self._session_factory() as db:
            self._registration_context(
                db,
                registration_id=message.registration_id,
                token_hash=token_hash,
            )
            record = db.get(SelfServiceRegistrationRecord, message.registration_id)
            challenge = db.scalar(
                sa.select(EmailVerificationChallengeRecord).where(
                    EmailVerificationChallengeRecord.id == message.challenge_id,
                    EmailVerificationChallengeRecord.registration_id == message.registration_id,
                    EmailVerificationChallengeRecord.token_hash == token_hash,
                )
            )
            return bool(
                record is not None
                and challenge is not None
                and record.status == "pending_verification"
                and challenge.status == "pending"
                and challenge.generation == record.challenge_generation
                and _stored_time(challenge.expires_at) > checked_at
            )

    def _load_registration_replay(
        self, *, scoped_key: str, email_hash: str, request_hash: str
    ) -> RegistrationAccepted | None:
        with self._session_factory() as db:
            self._registration_context(db, email_hash=email_hash, idempotency_key=scoped_key)
            record = db.scalar(
                sa.select(SelfServiceRegistrationRecord).where(
                    SelfServiceRegistrationRecord.idempotency_key == scoped_key
                )
            )
            if record is None:
                return None
            return self._registration_replay(record, request_hash)

    @staticmethod
    def _registration_replay(
        record: SelfServiceRegistrationRecord, request_hash: str
    ) -> RegistrationAccepted:
        if not hmac.compare_digest(record.request_hash, request_hash):
            raise OnboardingError(
                "idempotency_conflict", "idempotency key belongs to another request"
            )
        return RegistrationAccepted(record.id, _stored_time(record.expires_at), replayed=True)

    @staticmethod
    def _requested(
        record: SelfServiceRegistrationRecord, *, replayed: bool
    ) -> OnboardingRequested:
        return OnboardingRequested(
            registration_id=record.id,
            onboarding_id=record.onboarding_id,
            user_id=record.user_id,
            tenant_id=record.tenant_id,
            space_id=record.space_id,
            subscription_id=record.subscription_id,
            runtime_partition_id=record.runtime_partition_id,
            default_project_id=record.default_project_id,
            replayed=replayed,
        )

    @staticmethod
    def _require_verification_receipt(
        db: Session,
        record: SelfServiceRegistrationRecord,
        scoped_key: str,
    ) -> None:
        event = db.scalar(
            sa.select(SelfServiceEventRecord)
            .where(
                SelfServiceEventRecord.aggregate_type == "registration",
                SelfServiceEventRecord.aggregate_id == record.id,
                SelfServiceEventRecord.event_type == "registration.verified",
            )
            .order_by(SelfServiceEventRecord.sequence.desc())
            .limit(1)
        )
        receipt_hash = None if event is None else event.facts.get("verification_receipt_hash")
        if not isinstance(receipt_hash, str) or not hmac.compare_digest(receipt_hash, scoped_key):
            raise OnboardingError(
                "idempotency_conflict",
                "verification receipt belongs to another request",
            )

    @staticmethod
    def _email_is_blocked(db: Session, record: SelfServiceRegistrationRecord) -> bool:
        password_user = db.scalar(
            sa.select(PasswordCredential.user_id).where(
                PasswordCredential.login_email_normalized == record.email_normalized
            )
        )
        if password_user is not None:
            return True
        identity_user = db.scalar(
            sa.select(IdentityConnection.user_id)
            .where(
                IdentityConnection.email_normalized == record.email_normalized,
                IdentityConnection.email_verified.is_(True),
                IdentityConnection.status == "active",
            )
            .limit(1)
        )
        if identity_user is not None:
            return True
        tombstone = db.scalar(
            sa.select(PrivacyIdentityTombstoneRecord.id).where(
                PrivacyIdentityTombstoneRecord.locator_kind == "password_email",
                PrivacyIdentityTombstoneRecord.locator_hash == record.email_hash,
            )
        )
        return tombstone is not None

    @staticmethod
    def _registration_context(
        db: Session,
        *,
        registration_id: UUID | None = None,
        token_hash: str | None = None,
        email_hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        apply_registration_rls_context(
            db,
            RegistrationRlsContext(
                registration_id=registration_id,
                token_hash=token_hash,
                email_hash=email_hash,
                idempotency_key=idempotency_key,
            ),
        )

    @staticmethod
    def _append_event(
        db: Session,
        *,
        aggregate_type: str,
        aggregate_id: UUID,
        tenant_id: UUID | None,
        user_id: UUID | None,
        event_type: str,
        from_status: str | None,
        to_status: str | None,
        facts: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        _reject_sensitive_event_facts(facts)
        statement = (
            sa.select(SelfServiceEventRecord)
            .where(
                SelfServiceEventRecord.aggregate_type == aggregate_type,
                SelfServiceEventRecord.aggregate_id == aggregate_id,
            )
            .order_by(SelfServiceEventRecord.sequence.desc())
            .limit(1)
        )
        if db.get_bind().dialect.name == "postgresql":
            # The event role intentionally has no UPDATE privilege. Serialize the
            # empty-chain case and subsequent appends with an aggregate-scoped
            # transaction lock instead of SELECT FOR UPDATE on immutable rows.
            db.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"self-service-event:{aggregate_type}:{aggregate_id}"},
            )
        else:
            statement = statement.with_for_update()
        previous = db.scalar(statement)
        sequence = 1 if previous is None else previous.sequence + 1
        previous_hash = _ZERO_HASH if previous is None else previous.event_hash
        facts_hash = _digest(facts)
        event_hash = _digest(
            {
                "aggregate_type": aggregate_type,
                "aggregate_id": str(aggregate_id),
                "sequence": sequence,
                "event_type": event_type,
                "from_status": from_status,
                "to_status": to_status,
                "facts_hash": facts_hash,
                "previous_hash": previous_hash,
                "occurred_at": _stored_time(occurred_at).isoformat(),
            }
        )
        db.add(
            SelfServiceEventRecord(
                id=uuid4(),
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                tenant_id=tenant_id,
                user_id=user_id,
                sequence=sequence,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                facts=facts,
                facts_hash=facts_hash,
                previous_hash=previous_hash,
                event_hash=event_hash,
                occurred_at=occurred_at,
            )
        )


class TenantOnboardingCoordinator:
    """Create fail-closed Tenant/Space state and hand Billing to its own role."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        policy: OnboardingPolicy,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy

    def start(
        self,
        *,
        registration_id: UUID,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> TenantOnboardingStarted:
        started_at = _stored_time(now or _now())
        scoped_key = _idempotency_key("tenant-onboarding", registration_id, idempotency_key)
        with self._session_factory.begin() as db:
            apply_onboarding_rls_context(db, OnboardingRlsContext(registration_id=registration_id))
            registration = db.scalar(
                sa.select(SelfServiceRegistrationRecord).where(
                    SelfServiceRegistrationRecord.id == registration_id
                )
            )
            if registration is None or registration.status != "verified":
                raise OnboardingError("onboarding_not_ready", "verified registration is required")
            apply_onboarding_rls_context(
                db,
                OnboardingRlsContext(
                    onboarding_id=registration.onboarding_id,
                    registration_id=registration.id,
                    actor_id=registration.user_id,
                    tenant_id=registration.tenant_id,
                ),
            )
            existing = db.scalar(
                sa.select(TenantOnboardingRecord).where(
                    TenantOnboardingRecord.id == registration.onboarding_id
                )
            )
            if existing is not None:
                if not hmac.compare_digest(existing.idempotency_key, scoped_key):
                    raise OnboardingError(
                        "idempotency_conflict", "onboarding request already exists"
                    )
                return self._started(existing, replayed=True)
            plan = self._policy.require_plan(
                registration.plan_key, revision=registration.plan_policy_revision
            )
            expected_plan_snapshot = plan.snapshot()
            expected_plan_hash = plan.snapshot_hash()
            if (
                registration.plan_snapshot != expected_plan_snapshot
                or not hmac.compare_digest(
                    _digest(registration.plan_snapshot), registration.plan_snapshot_hash
                )
                or not hmac.compare_digest(registration.plan_snapshot_hash, expected_plan_hash)
            ):
                raise OnboardingError(
                    "onboarding_plan_snapshot_invalid",
                    "registration plan snapshot no longer matches the reviewed policy",
                )
            db.add(
                Tenant(
                    id=registration.tenant_id,
                    slug=registration.tenant_slug,
                    name=registration.tenant_name,
                    status="provisioning",
                    plan=plan.key,
                    home_region=registration.home_region,
                    lifecycle_version=1,
                )
            )
            db.flush()
            db.add(
                Space(
                    id=registration.space_id,
                    tenant_id=registration.tenant_id,
                    slug=registration.default_space_slug,
                    name=registration.default_space_name,
                    status="suspended",
                )
            )
            db.add(
                TenantMembership(
                    tenant_id=registration.tenant_id,
                    user_id=registration.user_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=started_at,
                )
            )
            db.flush()
            db.add(
                SpaceMembership(
                    tenant_id=registration.tenant_id,
                    space_id=registration.space_id,
                    user_id=registration.user_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=started_at,
                )
            )
            request_payload: dict[str, object] = {
                "onboarding_id": str(registration.onboarding_id),
                "registration_id": str(registration.id),
                "user_id": str(registration.user_id),
                "tenant_id": str(registration.tenant_id),
                "space_id": str(registration.space_id),
                "subscription_id": str(registration.subscription_id),
                "pricing_snapshot_id": str(registration.pricing_snapshot_id),
                "entitlement_id": str(registration.entitlement_id),
                "runtime_partition_id": str(registration.runtime_partition_id),
                "default_project_id": str(registration.default_project_id),
                "runtime_binding_id": str(registration.runtime_binding_id),
                "plan_key": registration.plan_key,
                "plan_policy_revision": registration.plan_policy_revision,
                "plan_snapshot": registration.plan_snapshot,
                "plan_snapshot_hash": registration.plan_snapshot_hash,
                "expected_status": "tenant_created",
                "version": 1,
            }
            saga = TenantOnboardingRecord(
                id=registration.onboarding_id,
                registration_id=registration.id,
                user_id=registration.user_id,
                tenant_id=registration.tenant_id,
                space_id=registration.space_id,
                subscription_id=registration.subscription_id,
                pricing_snapshot_id=registration.pricing_snapshot_id,
                entitlement_id=registration.entitlement_id,
                runtime_partition_id=registration.runtime_partition_id,
                default_project_id=registration.default_project_id,
                runtime_binding_id=registration.runtime_binding_id,
                plan_key=plan.key,
                plan_policy_revision=plan.policy_revision,
                plan_snapshot=registration.plan_snapshot,
                plan_snapshot_hash=registration.plan_snapshot_hash,
                home_region=registration.home_region,
                trial_days=plan.trial_days,
                trial_started_at=None,
                trial_ends_at=None,
                status="tenant_created",
                idempotency_key=scoped_key,
                request_hash=_digest(request_payload),
                version=1,
                attempt_count=0,
                available_at=started_at,
                last_transition_at=started_at,
                created_at=started_at,
                updated_at=started_at,
            )
            db.add(saga)
            # The restrictive billing-Outbox policy admits only an already
            # durable Saga in the same transaction. SQLAlchemy has no foreign
            # key that orders these independent tables, so flush the authority
            # row explicitly instead of depending on unit-of-work table order.
            db.flush()
            db.add(
                ControlPlaneOutboxEvent(
                    tenant_id=registration.tenant_id,
                    aggregate_type="tenant_onboarding",
                    aggregate_key=str(saga.id),
                    event_type=_BILLING_EVENT,
                    idempotency_key=scoped_idempotency_key(
                        "tenant-onboarding", saga.id, "billing-requested"
                    ),
                    request_hash=_digest(request_payload),
                    payload=request_payload,
                    attempt_count=0,
                )
            )
            SelfServiceOnboardingService._append_event(
                db,
                aggregate_type="tenant_onboarding",
                aggregate_id=saga.id,
                tenant_id=saga.tenant_id,
                user_id=saga.user_id,
                event_type="tenant_onboarding.created",
                from_status=None,
                to_status=None,
                facts={
                    "plan_policy_revision": saga.plan_policy_revision,
                    "plan_snapshot_hash": saga.plan_snapshot_hash,
                    "home_region": saga.home_region,
                },
                occurred_at=started_at,
            )
            db.flush()
            return self._started(saga, replayed=False)

    @staticmethod
    def _started(saga: TenantOnboardingRecord, *, replayed: bool) -> TenantOnboardingStarted:
        return TenantOnboardingStarted(
            onboarding_id=saga.id,
            registration_id=saga.registration_id,
            user_id=saga.user_id,
            tenant_id=saga.tenant_id,
            space_id=saga.space_id,
            default_project_id=saga.default_project_id,
            status=saga.status,
            replayed=replayed,
        )


class OnboardingOutboxPublisher:
    """Route onboarding events while preserving the existing global Outbox chain."""

    def __init__(
        self,
        *,
        registrations: SelfServiceOnboardingService,
        coordinator: TenantOnboardingCoordinator,
        envelopes: VerificationEnvelopeKeyring,
        email_sender: EmailVerificationSender,
        workflow: TenantOnboardingEventHandler | None = None,
        fallback: OutboxPublisher | None = None,
    ) -> None:
        self._registrations = registrations
        self._coordinator = coordinator
        self._envelopes = envelopes
        self._email_sender = email_sender
        self._workflow = workflow
        self._fallback = fallback

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        if event_type == _EMAIL_EVENT:
            try:
                message = self._envelopes.open(event_id=event_id, payload=payload)
            except OnboardingError as error:
                raise OutboxPublishError(
                    error.code,
                    retryable=False,
                    pre_side_effect=True,
                ) from error
            except Exception as error:
                raise OutboxPublishError(
                    "verification_envelope_unavailable",
                    retryable=True,
                    pre_side_effect=True,
                ) from error
            if aggregate_type != "self_service_registration" or aggregate_key != str(
                message.registration_id
            ):
                raise OutboxPublishError(
                    "onboarding_event_invalid",
                    retryable=False,
                    pre_side_effect=True,
                )
            if _stored_time(message.expires_at) <= _now():
                self._registrations.record_email_delivery(
                    message=message,
                    succeeded=False,
                    error_code="delivery_expired",
                )
                return
            if not self._registrations.email_delivery_is_current(message=message):
                self._registrations.record_email_delivery(
                    message=message,
                    succeeded=False,
                    error_code="challenge_inactive",
                )
                return
            try:
                self._email_sender.send_verification(event_id=event_id, message=message)
            except Exception as error:
                self._registrations.record_email_delivery(
                    message=message,
                    succeeded=False,
                    error_code="delivery_unavailable",
                )
                raise OutboxPublishError(
                    "email_verification_delivery_failed",
                    retryable=True,
                    pre_side_effect=False,
                ) from error
            self._registrations.record_email_delivery(
                message=message, succeeded=True, error_code=None
            )
            return
        if event_type == _TENANT_EVENT:
            if aggregate_type != "tenant_onboarding" or aggregate_key != str(
                payload.get("onboarding_id", "")
            ):
                raise OutboxPublishError(
                    "onboarding_event_invalid",
                    retryable=False,
                    pre_side_effect=True,
                )
            try:
                registration_id = UUID(str(payload["registration_id"]))
            except (KeyError, TypeError, ValueError) as error:
                raise OutboxPublishError(
                    "onboarding_event_invalid",
                    retryable=False,
                    pre_side_effect=True,
                ) from error
            try:
                self._coordinator.start(
                    registration_id=registration_id,
                    idempotency_key=str(event_id),
                )
            except IntegrityError as error:
                raise OutboxPublishError(
                    "tenant_onboarding_integrity_conflict",
                    retryable=True,
                    pre_side_effect=True,
                ) from error
            return
        if aggregate_type == "tenant_onboarding" and event_type in _WORKFLOW_EVENTS:
            if self._workflow is None:
                raise OutboxPublishError(
                    "outbox_route_unavailable",
                    retryable=True,
                    pre_side_effect=True,
                )
            if aggregate_key != str(payload.get("onboarding_id", "")):
                raise OutboxPublishError(
                    "onboarding_event_invalid",
                    retryable=False,
                    pre_side_effect=True,
                )
            try:
                self._workflow.handle_event(event_type=event_type, payload=payload)
            except Exception as error:
                code = getattr(error, "code", "onboarding_workflow_unavailable")
                retryable = getattr(error, "retryable", True)
                if not isinstance(code, str) or not code or len(code) > 128:
                    code = "onboarding_workflow_unavailable"
                if not isinstance(retryable, bool):
                    retryable = True
                raise OutboxPublishError(
                    code,
                    retryable=retryable,
                    pre_side_effect=not retryable,
                ) from error
            return
        if self._fallback is None:
            raise OutboxPublishError(
                "outbox_route_unavailable",
                retryable=True,
                pre_side_effect=True,
            )
        self._fallback.publish(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )


def _reject_sensitive_event_facts(value: object, *, path: str = "facts") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in _SENSITIVE_EVENT_KEYS):
                raise ValueError(f"self-service event contains sensitive key at {path}")
            _reject_sensitive_event_facts(nested, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject_sensitive_event_facts(nested, path=f"{path}[{index}]")


__all__ = [
    "EmailVerificationMessage",
    "EmailVerificationSender",
    "OnboardingError",
    "OnboardingOutboxPublisher",
    "OnboardingPlan",
    "OnboardingPolicy",
    "OnboardingRequested",
    "RegistrationAccepted",
    "RegistrationRateLimitAliases",
    "RegistrationRateLimitDecision",
    "RegistrationRateLimitSubjectKeyring",
    "RegistrationRateLimiter",
    "SelfServiceOnboardingService",
    "SharedRegistrationRateLimitJanitor",
    "SharedRegistrationRateLimiter",
    "TenantOnboardingCoordinator",
    "TenantOnboardingStarted",
    "VerificationEnvelopeKeyring",
]
