"""A bounded credential-free state snapshot for the private read service."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from saas.control_plane.identity import validate_phone_proof
from saas.control_plane.identity_events import (
    IdentitySyncError,
    ProviderIdentityState,
    _aware,
    _unique_object,
)
from saas.control_plane.identity_inbox import _utc
from saas.control_plane.lifecycle import LifecycleError, normalize_email

IDENTITY_READ_PATH = "/internal/casdoor/identity-state"
IDENTITY_READ_KEY_ID = "X-Omnigent-Identity-Reader-Key-Id"
IDENTITY_READ_SECRET = "X-Omnigent-Identity-Reader-Secret"
IDENTITY_READ_MAX_BYTES = 16384
_STATE_FIELDS = (
    "issuer",
    "organization",
    "subject",
    "exists",
    "username",
    "email",
    "email_verified",
    "phone_e164",
    "phone_verified",
    "disabled",
    "deleted",
    "normal_customer",
    "password_configured",
    "password_revision_sha256",
    "password_changed_at",
)


def validate_provider_state(
    state: ProviderIdentityState, *, issuer: str, organization: str, subject: str, now: datetime
) -> None:
    if (
        not isinstance(state, ProviderIdentityState)
        or (state.issuer, state.organization, state.subject) != (issuer, organization, subject)
        or any(
            type(getattr(state, name)) is not bool
            for name in (
                "exists",
                "email_verified",
                "phone_verified",
                "disabled",
                "deleted",
                "normal_customer",
                "password_configured",
            )
        )
        or (
            state.exists
            and (
                not isinstance(state.username, str)
                or not 1 <= len(state.username) <= 128
                or any(ord(char) < 32 or char == "/" for char in state.username)
            )
        )
        or (state.email is not None and not isinstance(state.email, str))
        or (state.email_verified and not state.email)
        or (
            state.password_revision_sha256 is not None
            and (
                not isinstance(state.password_revision_sha256, str)
                or re.fullmatch(r"[a-f0-9]{64}", state.password_revision_sha256) is None
            )
        )
        or (state.exists and state.password_revision_sha256 is None)
        or (
            state.password_changed_at is not None
            and (
                not isinstance(state.password_changed_at, datetime)
                or state.password_changed_at.tzinfo is None
                or state.password_changed_at > now + timedelta(seconds=60)
            )
        )
    ):
        raise IdentitySyncError("identity_provider_response_invalid", retryable=True)
    try:
        validate_phone_proof(state.phone_e164, state.phone_verified)
        if state.email:
            normalize_email(state.email)
    except LifecycleError:
        raise IdentitySyncError("identity_provider_response_invalid", retryable=True) from None


def encode_identity_read(
    state: ProviderIdentityState,
    *,
    observed_at: datetime,
    broker_revision: str,
    provider_source_lock_sha256: str,
) -> dict[str, object]:
    document: dict[str, object] = {name: getattr(state, name) for name in _STATE_FIELDS}
    document["password_changed_at"] = (
        state.password_changed_at.isoformat() if state.password_changed_at else None
    )
    return {
        "schema_version": 2,
        "broker_revision": broker_revision,
        "provider_source_lock_sha256": provider_source_lock_sha256,
        "observed_at": _utc(observed_at).isoformat(),
        "identity": document,
    }


def decode_identity_read(
    payload: bytes,
    *,
    issuer: str,
    organization: str,
    subject: str,
    broker_revision: str,
    provider_source_lock_sha256: str,
    now: datetime,
) -> ProviderIdentityState:
    try:
        if not 1 <= len(payload) <= IDENTITY_READ_MAX_BYTES:
            raise ValueError
        document = json.loads(payload, object_pairs_hook=_unique_object)
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema_version",
                "broker_revision",
                "provider_source_lock_sha256",
                "observed_at",
                "identity",
            }
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 2
            or document["broker_revision"] != broker_revision
            or document["provider_source_lock_sha256"] != provider_source_lock_sha256
            or not isinstance(document["identity"], dict)
            or set(document["identity"]) != set(_STATE_FIELDS)
        ):
            raise ValueError
        observed = _aware(document["observed_at"])
        if not now - timedelta(seconds=30) <= observed <= now + timedelta(seconds=30):
            raise ValueError
        identity = document["identity"]
        if identity["password_changed_at"] is not None:
            identity["password_changed_at"] = _aware(identity["password_changed_at"])
        state = ProviderIdentityState(**identity)
        validate_provider_state(
            state, issuer=issuer, organization=organization, subject=subject, now=now
        )
        return state
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError, IdentitySyncError):
        raise IdentitySyncError("identity_reader_response_invalid", retryable=True) from None
