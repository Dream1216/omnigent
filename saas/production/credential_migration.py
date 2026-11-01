"""Organization-scoped Casdoor credential import through fixed private APIs."""

from __future__ import annotations

import base64
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

import httpx

from saas.control_plane.credential_migration import (
    CredentialImportClaim,
    CredentialMigrationError,
    CredentialMigrationPolicy,
    VerifiedMigrationIdentity,
)
from saas.production.server_config import (
    ProductionIdentityConfig,
    ProductionServerConfigError,
    _absolute_regular_file,
    _required,
    _secret_bytes,
)

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MARKER_PROPERTY = "omnigentCredentialMigration"
_MARKER_DOMAIN = b"omnigent.casdoor.credential-import.v1\x00"
_MAX_RESPONSE_BYTES = 65_536


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True, slots=True)
class CredentialImportKeyring:
    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.keys) <= 8
            or self.active_key_id not in self.keys
            or any(
                not _KEY_ID.fullmatch(key_id) or not isinstance(key, bytes) or len(key) < 32
                for key_id, key in self.keys.items()
            )
        ):
            raise ValueError("credential import keyring is invalid")
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    def sign(self, claim: CredentialImportClaim) -> str:
        key_id = self.active_key_id
        digest = hmac.new(
            self.keys[key_id], _MARKER_DOMAIN + _canonical(claim.marker_document()), sha256
        ).hexdigest()
        return f"v1.{key_id}.{digest}"

    def verify(self, marker: object, claim: CredentialImportClaim) -> None:
        if not isinstance(marker, str) or len(marker) > 132:
            raise CredentialMigrationError("provider_mapping_conflict")
        parts = marker.split(".")
        if (
            len(parts) != 3
            or parts[0] != "v1"
            or not _KEY_ID.fullmatch(parts[1])
            or not re.fullmatch(r"[0-9a-f]{64}", parts[2])
        ):
            raise CredentialMigrationError("provider_mapping_conflict")
        key = self.keys.get(parts[1])
        if key is None:
            raise CredentialMigrationError("provider_marker_key_unavailable", retryable=True)
        expected = hmac.new(
            key, _MARKER_DOMAIN + _canonical(claim.marker_document()), sha256
        ).hexdigest()
        if not hmac.compare_digest(parts[2], expected):
            raise CredentialMigrationError("provider_mapping_conflict")


@dataclass(frozen=True, slots=True)
class CasdoorCredentialImportConfig:
    issuer: str
    organization: str
    customer_application: str
    migration_client_id: str
    migration_client_secret: str = field(repr=False)
    source_lock_sha256: str
    policy_revision: str
    marker_keyring: CredentialImportKeyring = field(repr=False)
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        if (
            any(
                not _LABEL.fullmatch(value)
                for value in (
                    self.organization,
                    self.customer_application,
                    self.migration_client_id,
                    self.policy_revision,
                )
            )
            or self.organization == "built-in"
            or self.customer_application == "app-built-in"
            or len(self.migration_client_secret) < 16
            or any(ord(char) < 32 for char in self.migration_client_secret)
            or not re.fullmatch(r"[0-9a-f]{64}", self.source_lock_sha256)
        ):
            raise ValueError("Casdoor credential import configuration is invalid")
        # Share the worker's origin and organization validation.
        self.policy()

    def policy(self) -> CredentialMigrationPolicy:
        return CredentialMigrationPolicy(
            issuer=self.issuer,
            organization=self.organization,
            policy_sha256=sha256(
                _canonical(
                    {
                        "schema_version": 1,
                        "issuer": self.issuer,
                        "organization": self.organization,
                        "customer_application": self.customer_application,
                        "migration_client_id": self.migration_client_id,
                        "source_lock_sha256": self.source_lock_sha256,
                        "policy_revision": self.policy_revision,
                    }
                )
            ).hexdigest(),
            allow_insecure_loopback=self.allow_insecure_loopback,
        )


def load_casdoor_credential_import_config(
    environ: Mapping[str, str], *, identity: ProductionIdentityConfig
) -> CasdoorCredentialImportConfig:
    """Load dedicated API credentials and a replica-shared marker keyring from files."""
    config_name = "OMNIGENT_SAAS_CREDENTIAL_IMPORT_CONFIG_FILE"
    secret_name = "OMNIGENT_SAAS_CREDENTIAL_IMPORT_CLIENT_SECRET_FILE"
    key_name = "OMNIGENT_SAAS_CREDENTIAL_IMPORT_MARKER_KEYRING_FILE"
    try:
        path = _absolute_regular_file(
            _required(environ, config_name), name=config_name, owner_only=False
        )
        payload = json.loads(path.read_bytes())
        if not isinstance(payload, dict) or set(payload) != {
            "issuer",
            "organization",
            "customer_application",
            "migration_client_id",
            "source_lock_sha256",
            "policy_revision",
        }:
            raise ValueError
        if any(not isinstance(value, str) for value in payload.values()):
            raise ValueError
        provider = identity.provider
        if (
            provider is None
            or provider.provider != "casdoor"
            or payload["issuer"] != provider.issuer
            or provider.allow_insecure_loopback
            or provider.allowed_identity_owners != (payload["organization"],)
            or payload["migration_client_id"] == provider.client_id
            or provider.jwks_uri
            != f"{provider.issuer}/.well-known/{payload['customer_application']}/jwks"
            or payload["source_lock_sha256"]
            != sha256(
                (Path(__file__).parent / "casdoor/source-lock.json").read_bytes()
            ).hexdigest()
        ):
            raise ValueError
        document = json.loads(_secret_bytes(environ, key_name))
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "active_key_id", "keys"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["active_key_id"], str)
            or not isinstance(document["keys"], dict)
            or any(not isinstance(value, str) for value in document["keys"].values())
        ):
            raise ValueError
        return CasdoorCredentialImportConfig(
            **payload,
            migration_client_secret=_secret_bytes(environ, secret_name, minimum=16).decode(),
            marker_keyring=CredentialImportKeyring(
                document["active_key_id"],
                {
                    key: base64.b64decode(value, validate=True)
                    for key, value in document["keys"].items()
                },
            ),
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ProductionServerConfigError(
            "Casdoor credential import configuration is invalid"
        ) from None


def load_credential_recovery_keys(environ: Mapping[str, str]):
    from saas.control_plane.credential_recovery import CredentialRecoveryKeyring

    name = "OMNIGENT_SAAS_CREDENTIAL_RECOVERY_PUBLIC_KEYS_FILE"
    try:
        path = _absolute_regular_file(_required(environ, name), name=name, owner_only=False)
        document = json.loads(path.read_bytes())
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "public_keys"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["public_keys"], dict)
            or any(not isinstance(value, str) for value in document["public_keys"].values())
        ):
            raise ValueError
        return CredentialRecoveryKeyring(
            {
                key_id: base64.b64decode(value, validate=True)
                for key_id, value in document["public_keys"].items()
            }
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ProductionServerConfigError(
            "credential recovery verification keys are invalid"
        ) from None


class CasdoorCredentialImportProvider:
    def __init__(
        self,
        config: CasdoorCredentialImportConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    @staticmethod
    def _request(
        client: httpx.Client,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        try:
            with client.stream(method, path, params=params, json=json_body) as response:
                if response.status_code in {401, 403, 408, 429} or response.status_code >= 500:
                    raise CredentialMigrationError("provider_import_unavailable", retryable=True)
                if response.status_code != 200:
                    raise CredentialMigrationError("provider_import_response_invalid")
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise CredentialMigrationError("provider_import_response_invalid")
                document = json.loads(body)
            if not isinstance(document, dict) or document.get("status") not in {"ok", "error"}:
                raise ValueError
            return document
        except (httpx.HTTPError, OSError):
            raise CredentialMigrationError("provider_import_unavailable", retryable=True) from None
        except (UnicodeError, ValueError, TypeError):
            raise CredentialMigrationError("provider_import_response_invalid") from None

    def _read(
        self, client: httpx.Client, claim: CredentialImportClaim
    ) -> dict[str, object] | None:
        response = self._request(
            client, "GET", "/api/get-user", params={"id": f"{claim.organization}/{claim.username}"}
        )
        if response["status"] != "ok" or "data" not in response:
            raise CredentialMigrationError("provider_import_response_invalid")
        data = response["data"]
        if data is not None and not isinstance(data, dict):
            raise CredentialMigrationError("provider_import_response_invalid")
        return data

    def ensure_import(self, claim: CredentialImportClaim) -> VerifiedMigrationIdentity:
        config = self._config
        if (
            claim.issuer != config.issuer
            or claim.organization != config.organization
            or claim.policy_sha256 != config.policy().policy_sha256
            or claim.subject != str(claim.user_id)
            or claim.username != "omnigent-" + claim.user_id.hex
            or sha256(claim.password_hash.encode()).hexdigest() != claim.source_password_sha256
            or sha256(claim.email.encode()).hexdigest() != claim.source_email_sha256
        ):
            raise CredentialMigrationError("provider_import_claim_invalid")
        with httpx.Client(
            base_url=config.issuer,
            auth=httpx.BasicAuth(config.migration_client_id, config.migration_client_secret),
            headers={"Accept": "application/json", "Origin": config.issuer},
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        ) as client:
            data = self._read(client, claim)
            if data is None:
                # Never update an existing identity or merge by email. A lost response
                # is retried by reading the durable marker before attempting creation.
                self._request(
                    client,
                    "POST",
                    "/api/add-user",
                    json_body={
                        "owner": claim.organization,
                        "name": claim.username,
                        "id": claim.subject,
                        "displayName": claim.username,
                        "email": claim.email,
                        "emailVerified": True,
                        "type": "normal-user",
                        "password": claim.password_hash,
                        "passwordType": "argon2id",
                        "passwordSalt": "",
                        "signupApplication": config.customer_application,
                        "properties": {_MARKER_PROPERTY: config.marker_keyring.sign(claim)},
                    },
                )
                data = self._read(client, claim)
                if data is None:
                    raise CredentialMigrationError("provider_import_not_observed", retryable=True)
        if (
            data.get("owner") != claim.organization
            or data.get("name") != claim.username
            or data.get("id") != claim.subject
            or data.get("type") != "normal-user"
            or not isinstance(data.get("email"), str)
            or any(
                type(data.get(name)) is not bool
                for name in ("emailVerified", "isAdmin", "isForbidden", "isDeleted")
            )
            or type(data.get("isGlobalAdmin", False)) is not bool
            or not isinstance(data.get("properties"), dict)
        ):
            raise CredentialMigrationError("provider_import_response_invalid")
        config.marker_keyring.verify(data["properties"].get(_MARKER_PROPERTY), claim)
        return VerifiedMigrationIdentity(
            issuer=config.issuer,
            organization=claim.organization,
            subject=claim.subject,
            username=claim.username,
            email=data["email"],
            email_verified=data["emailVerified"] is True,
            active=not data["isForbidden"] and not data["isDeleted"],
            is_admin=data["isAdmin"] is True,
            is_global_admin=data.get("isGlobalAdmin", False) is True,
            marker_verified=True,
        )
