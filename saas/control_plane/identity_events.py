"""Normalized identity notifications and authoritative provider readback contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Protocol
from urllib.parse import parse_qs

from saas.control_plane.lifecycle import normalize_email

_ACTIONS = frozenset({"update-user", "delete-user", "set-password"})
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class IdentitySyncError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code, self.retryable = code, retryable


class IdentityNotificationIgnored(RuntimeError):
    pass


_SAFE_IDENTITY_ERRORS = frozenset(
    {
        "identity_inbox_claim_stale",
        "identity_mapping_unavailable",
        "identity_notification_idempotency_conflict",
        "identity_notification_invalid",
        "identity_notification_scope_mismatch",
        "identity_notification_attempts_exhausted",
        "identity_provider_locator_mismatch",
        "identity_provider_password_policy_unqualified",
        "identity_provider_response_invalid",
        "identity_provider_subject_invalid",
        "identity_provider_unavailable",
        "identity_reader_authentication_failed",
        "identity_reader_response_invalid",
        "identity_reader_unavailable",
        "identity_state_busy",
        "identity_state_claim_stale",
        "identity_sync_failed",
    }
)


def safe_identity_error_code(error: IdentitySyncError) -> str:
    return (
        error.code
        if isinstance(error.code, str) and error.code in _SAFE_IDENTITY_ERRORS
        else "identity_sync_failed"
    )


def identity_digest(document: dict[str, object]) -> str:
    return sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _aware(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError
    return result.astimezone(timezone.utc)


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class IdentityNotification:
    event_id: str
    action: str
    organization: str
    subject: str | None
    username: str = field(repr=False)
    occurred_at: datetime
    invalidates_sessions: bool = False

    def digest(self) -> str:
        return identity_digest(
            {
                "event_id": self.event_id,
                "action": self.action,
                "organization": self.organization,
                "subject": self.subject,
                "username": self.username,
                "occurred_at": self.occurred_at.isoformat(),
                "invalidates_sessions": self.invalidates_sessions,
            }
        )


def parse_casdoor_notification(
    payload: bytes,
    *,
    organization: str,
    now: datetime,
) -> IdentityNotification:
    """Keep only routing facts; never persist raw audit objects, responses or tokens."""
    try:
        if not 1 <= len(payload) <= 65536 or now.tzinfo is None:
            raise ValueError
        document = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(document, dict):
            raise ValueError
        action = document.get("action")
        if not isinstance(action, str):
            raise ValueError
        if action not in _ACTIONS:
            raise IdentityNotificationIgnored
        event_id = document.get("name")
        if not isinstance(event_id, str) or not _LABEL.fullmatch(event_id):
            raise ValueError
        response = document.get("response")
        # The pinned audit response is intentionally not JSON: {status:"ok", msg:"..."}.
        if not isinstance(response, str) or len(response) > 8192:
            raise ValueError
        status = re.match(r'^\{status:"(ok|error)"(?:,|\})', response)
        if status is None:
            raise ValueError
        if status[1] != "ok":
            raise IdentityNotificationIgnored
        raw = document.get("object")
        invalidates_sessions = action in {"set-password", "delete-user"}
        if not isinstance(raw, str) or not 1 <= len(raw) <= 32768:
            raise ValueError
        if raw.lstrip().startswith("{"):
            target = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(target, dict):
                raise ValueError
            owner, username, subject = target.get("owner"), target.get("name"), target.get("id")
            invalidates_sessions |= (
                target.get("isForbidden") is True or target.get("isDeleted") is True
            )
        else:
            if action != "set-password":
                raise ValueError
            form = parse_qs(raw, keep_blank_values=True, max_num_fields=32)
            if any(len(values) != 1 for values in form.values()):
                raise ValueError
            owner, username, subject = (
                form.get("userOwner", [None])[0],
                form.get("userName", [None])[0],
                None,
            )
        if owner != organization:
            raise IdentityNotificationIgnored
        if (
            not isinstance(username, str)
            or not 1 <= len(username) <= 128
            or any(ord(char) < 32 or char == "/" for char in username)
            or (
                subject is not None
                and (
                    not isinstance(subject, str)
                    or not 1 <= len(subject) <= 512
                    or any(ord(char) < 32 for char in subject)
                )
            )
        ):
            raise ValueError
        occurred_at = _aware(document["createdTime"])
        if occurred_at > now + timedelta(seconds=60):
            raise ValueError
        return IdentityNotification(
            event_id, action, organization, subject, username, occurred_at, invalidates_sessions
        )
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise IdentitySyncError("identity_notification_invalid") from None


@dataclass(frozen=True, slots=True)
class ProviderIdentityState:
    issuer: str
    organization: str
    subject: str
    exists: bool
    username: str | None = field(default=None, repr=False)
    email: str | None = field(default=None, repr=False)
    email_verified: bool = False
    disabled: bool = False
    deleted: bool = False
    normal_customer: bool = True
    password_configured: bool = False
    password_revision_sha256: str | None = field(default=None, repr=False)
    password_changed_at: datetime | None = None

    @property
    def usable(self) -> bool:
        return self.exists and not self.disabled and not self.deleted and self.normal_customer

    def snapshot_sha256(self) -> str:
        return identity_digest(
            {
                "issuer": self.issuer,
                "organization": self.organization,
                "subject": self.subject,
                "exists": self.exists,
                "username": self.username,
                "email_sha256": sha256(normalize_email(self.email).encode()).hexdigest()
                if self.email
                else None,
                "email_verified": self.email_verified,
                "disabled": self.disabled,
                "deleted": self.deleted,
                "normal_customer": self.normal_customer,
                "password_configured": self.password_configured,
                "password_revision_sha256": self.password_revision_sha256,
            }
        )


class IdentityStateProvider(Protocol):
    def read_identity(self, subject: str) -> ProviderIdentityState: ...
