"""Read-only, pinned-organization Casdoor state and credential revision metadata."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import httpx

from saas.control_plane.credential_migration import CredentialMigrationError
from saas.control_plane.identity_events import IdentitySyncError, ProviderIdentityState, _aware
from saas.control_plane.lifecycle import LifecycleError, normalize_email
from saas.production.credential_migration import (
    CasdoorCredentialImportConfig,
    CasdoorCredentialImportProvider,
)


class CasdoorIdentityStateProvider:
    def __init__(
        self,
        config: CasdoorCredentialImportConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ):
        if config.marker_keyring is not None:
            raise ValueError("identity sync must not hold credential import marker keys")
        self._config, self._transport = config, transport
        self._organization_verified = False

    def _read(self, path: str, params: dict[str, str]):
        config = self._config
        try:
            with httpx.Client(
                base_url=config.issuer,
                auth=httpx.BasicAuth(config.migration_client_id, config.migration_client_secret),
                headers={"Accept": "application/json", "Origin": config.issuer},
                timeout=httpx.Timeout(10.0),
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                response = CasdoorCredentialImportProvider._request(
                    client, "GET", path, params=params
                )
            if response["status"] != "ok" or "data" not in response:
                raise IdentitySyncError("identity_provider_response_invalid", retryable=True)
            return response["data"]
        except CredentialMigrationError as error:
            raise IdentitySyncError(
                "identity_provider_unavailable", retryable=error.retryable
            ) from None

    def verify_organization(self) -> None:
        self._organization_verified = False
        data = self._read("/api/get-organization", {"id": "admin/" + self._config.organization})
        if (
            not isinstance(data, dict)
            or data.get("name") != self._config.organization
            or data.get("passwordType") != "argon2id"
            or data.get("passwordSalt") != ""
        ):
            raise IdentitySyncError("identity_provider_password_policy_unqualified")
        self._organization_verified = True

    def read_identity(self, subject: str) -> ProviderIdentityState:
        if not self._organization_verified:
            raise IdentitySyncError("identity_provider_password_policy_unqualified")
        if not subject or len(subject) > 512 or any(ord(char) < 32 for char in subject):
            raise IdentitySyncError("identity_provider_subject_invalid")
        config = self._config
        data = self._read("/api/get-user", {"owner": config.organization, "userId": subject})
        if data is None:
            return ProviderIdentityState(config.issuer, config.organization, subject, exists=False)
        try:
            if (
                not isinstance(data, dict)
                or data.get("owner") != config.organization
                or data.get("id") != subject
                or not isinstance(data.get("name"), str)
                or not 1 <= len(data["name"]) <= 128
                or any(ord(char) < 32 or char == "/" for char in data["name"])
                or not isinstance(data.get("type"), str)
                or not isinstance(data.get("email"), str)
                or len(data["email"]) > 320
                or any(
                    type(data.get(name)) is not bool
                    for name in ("emailVerified", "isForbidden", "isDeleted", "isAdmin")
                )
                or type(data.get("isGlobalAdmin", False)) is not bool
                or data.get("password") not in {"", "***"}
                or any(
                    not isinstance(data.get(name), str) or len(data[name]) > limit
                    for name, limit in (
                        ("passwordType", 128),
                        ("passwordSalt", 4096),
                        ("lastChangePasswordTime", 64),
                    )
                )
            ):
                raise ValueError
            email = normalize_email(data["email"]) if data["email"] else None
            if data["emailVerified"] and email is None:
                raise ValueError
            changed = (
                _aware(data["lastChangePasswordTime"]) if data["lastChangePasswordTime"] else None
            )
            if changed is not None and changed > datetime.now(timezone.utc) + timedelta(
                seconds=60
            ):
                raise ValueError
            revision = sha256(
                b"omnigent.casdoor.password-revision.v1\x00"
                + json.dumps(
                    {
                        "organization": config.organization,
                        "subject": subject,
                        "configured": data["password"] == "***",
                        "type": data["passwordType"],
                        "salt": data["passwordSalt"],
                        "changed_at": data["lastChangePasswordTime"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode()
            ).hexdigest()
            return ProviderIdentityState(
                config.issuer,
                config.organization,
                subject,
                exists=True,
                username=data["name"],
                email=email,
                email_verified=data["emailVerified"],
                disabled=data["isForbidden"],
                deleted=data["isDeleted"],
                normal_customer=data["type"] == "normal-user"
                and not data["isAdmin"]
                and not data.get("isGlobalAdmin", False),
                password_configured=data["password"] == "***" and bool(data["passwordType"]),
                password_revision_sha256=revision,
                password_changed_at=changed,
            )
        except (ValueError, TypeError, KeyError, LifecycleError):
            raise IdentitySyncError("identity_provider_response_invalid", retryable=True) from None
