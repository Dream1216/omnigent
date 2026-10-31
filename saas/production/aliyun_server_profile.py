"""Explicit release-bound Server configuration for the Aliyun managed provider."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

from saas.production.aliyun_model_client import validated_server_origin
from saas.production.aliyun_model_lease import HostModelLeaseAuthority
from saas.production.aliyun_sandbox import AliyunSandboxLauncher, AliyunSandboxScope
from saas.production.aliyun_storage import AliyunOssStorageConfig
from saas.production.aliyun_tenant_sandbox import AliyunManagedSandbox
from saas.production.platform_model_relay import validated_model_gateway_url
from saas.production.tenant_model_keys import _read_file
from saas.runner_adapter.platform_model_gateway import PlatformModelGatewayTokenAuthority

PROFILE_FILE_ENV = "OMNIGENT_SAAS_ALIYUN_PROFILE_FILE"
PROFILE_HASH_ENV = "OMNIGENT_SAAS_ALIYUN_PROFILE_SHA256"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_HOST_IMAGE = re.compile(
    r"ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}"
)
_FIELDS = {
    "schema_version",
    "product_revision",
    "server_image_digest",
    "region",
    "team_id",
    "generation",
    "template_id",
    "host_image",
    "server_origin",
    "model_gateway_url",
    "lifetime_seconds",
    "credential_file",
    "lease_key_file",
    "lease_key_sha256",
    "tenants",
}


def _path(value: object) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("Aliyun profile file reference is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Aliyun profile file reference is invalid")
    return path


def _secret(path: Path, expected: object) -> bytes:
    if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
        raise ValueError("Aliyun profile authority digest is invalid")
    key = _read_file(path, private=True, maximum=4096).rstrip(b"\r\n")
    if not 32 <= len(key) <= 4096 or b"\x00" in key or hashlib.sha256(key).hexdigest() != expected:
        raise ValueError("Aliyun profile authority material does not match")
    return key


@dataclass(frozen=True)
class AliyunServerProfile:
    source_sha256: str
    product_revision: str
    server_image_digest: str
    host_image: str
    team_id: UUID
    managed: AliyunManagedSandbox = field(repr=False)
    authorities: Mapping[UUID, PlatformModelGatewayTokenAuthority] = field(repr=False)
    authority_files: tuple[tuple[Path, str], ...] = field(repr=False)
    storage_configs: tuple[AliyunOssStorageConfig, ...] = ()
    storage_credential_file: Path | None = field(default=None, repr=False)

    def assert_ready(self) -> None:
        """Check installed SDK and local credentials without making a cloud API call."""

        AliyunSandboxLauncher(
            template=self.managed.template,
            credential_file=self.managed.credential_file,
            scope=self.managed.scopes[0],
            lifetime_s=self.managed.lifetime_s,
            model_leases=self.managed.model_leases,
            model_gateway_url=self.managed.model_gateway_url,
        ).prepare()
        management = _read_file(self.managed.credential_file, private=True, maximum=512).rstrip(
            b"\r\n"
        )
        if hashlib.sha256(management).hexdigest() in {
            expected for _, expected in self.authority_files
        }:
            raise ValueError("Aliyun management and signing authorities must be independent")
        for path, expected in self.authority_files:
            _secret(path, expected)
        if self.storage_configs:
            from saas.production.aliyun_volume_control import AliyunVolumeControlClient

            if self.storage_credential_file is None:
                raise ValueError("Aliyun storage control credential is unavailable")
            AliyunVolumeControlClient(
                team_id=self.team_id, credential_file=self.storage_credential_file
            ).prepare()


def load_aliyun_server_profile(
    source: Mapping[str, str],
    *,
    product_revision: str,
    server_image_digest: str,
    public_origin: str,
) -> AliyunServerProfile | None:
    """Load a canonical, hash-pinned allowlist; absence keeps the provider disabled."""

    if any(
        name.startswith("OMNIGENT_SAAS_ALIYUN_")
        and name not in {PROFILE_FILE_ENV, PROFILE_HASH_ENV}
        for name in source
    ):
        raise ValueError("Aliyun profile environment is invalid")
    filename, expected = source.get(PROFILE_FILE_ENV), source.get(PROFILE_HASH_ENV)
    if filename is None and expected is None:
        return None
    if not filename or not expected or _SHA256.fullmatch(expected) is None:
        raise ValueError("Aliyun profile requires a file and SHA-256")
    raw = _read_file(_path(filename), private=False, maximum=32768)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Aliyun profile digest does not match")
    try:
        document = json.loads(raw)
        canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if (
            raw != canonical
            or not isinstance(document, dict)
            or set(document)
            != _FIELDS | ({"storage"} if document.get("schema_version") == 2 else set())
            or type(document["schema_version"]) is not int
            or document["schema_version"] not in (1, 2)
            or document["product_revision"] != product_revision
            or document["server_image_digest"] != server_image_digest
            or document["region"] != "cn-hangzhou"
            or type(document["generation"]) is not int
            or document["generation"] != 2
            or not isinstance(document["template_id"], str)
            or re.fullmatch(r"[a-z0-9]{20}", document["template_id"]) is None
            or not isinstance(document["host_image"], str)
            or _HOST_IMAGE.fullmatch(document["host_image"]) is None
            or any(
                part in {"", ".", ".."}
                for part in document["host_image"].partition("@")[0].split("/")
            )
            or document["server_origin"] != validated_server_origin(public_origin)
            or type(document["lifetime_seconds"]) is not int
            or not 60 <= document["lifetime_seconds"] <= 3600
            or not isinstance(document["tenants"], list)
            or not 1 <= len(document["tenants"]) <= 32
        ):
            raise ValueError
        team_id = UUID(document["team_id"])
        if team_id.int == 0 or str(team_id) != document["team_id"]:
            raise ValueError
        gateway = validated_model_gateway_url(document["model_gateway_url"])
        if not gateway.startswith("https://"):
            raise ValueError
        credential_file = _path(document["credential_file"])
        lease_file = _path(document["lease_key_file"])
        lease_hash = document["lease_key_sha256"]
        lease_key = _secret(lease_file, lease_hash)
        credential = _read_file(credential_file, private=True, maximum=512).rstrip(b"\r\n")
        digests = {hashlib.sha256(credential).digest(), hashlib.sha256(lease_key).digest()}
        paths = {credential_file, lease_file}
        if len(digests) != 2 or len(paths) != 2:
            raise ValueError
        scopes = []
        authorities = {}
        authority_files = [(lease_file, lease_hash)]
        for row in document["tenants"]:
            if not isinstance(row, dict) or set(row) != {
                "tenant_id",
                "workspace_id",
                "gateway_key_file",
                "gateway_key_sha256",
            }:
                raise ValueError
            tenant = UUID(row["tenant_id"])
            if str(tenant) != row["tenant_id"]:
                raise ValueError
            scope = AliyunSandboxScope(tenant, row["workspace_id"])
            key_file = _path(row["gateway_key_file"])
            key = _secret(key_file, row["gateway_key_sha256"])
            digest = hashlib.sha256(key).digest()
            if digest in digests or key_file in paths:
                raise ValueError
            paths.add(key_file)
            digests.add(digest)
            scopes.append(scope)
            authorities[tenant] = PlatformModelGatewayTokenAuthority(
                signing_key=key, tenant_id=tenant
            )
            authority_files.append((key_file, row["gateway_key_sha256"]))
        storage_configs = []
        storage_credential_file = None
        if document["schema_version"] == 2:
            storage = document["storage"]
            if (
                not isinstance(storage, dict)
                or set(storage) != {"credential_file", "tenants"}
                or not isinstance(storage["tenants"], list)
                or len(storage["tenants"]) != len(scopes)
            ):
                raise ValueError
            storage_credential_file = _path(storage["credential_file"])
            if storage_credential_file in paths:
                raise ValueError
            workspaces = {scope.tenant_id: scope.workspace_id for scope in scopes}
            seen = set()
            for row in storage["tenants"]:
                if not isinstance(row, dict) or set(row) != {
                    "tenant_id",
                    "bucket",
                    "role_arn",
                    "prefix",
                }:
                    raise ValueError
                tenant = UUID(row["tenant_id"])
                if str(tenant) != row["tenant_id"] or tenant not in workspaces or tenant in seen:
                    raise ValueError
                seen.add(tenant)
                storage_configs.append(
                    AliyunOssStorageConfig(
                        team_id,
                        tenant,
                        workspaces[tenant],
                        row["bucket"],
                        row["role_arn"],
                        row["prefix"],
                    )
                )
        managed = AliyunManagedSandbox(
            template=document["template_id"],
            credential_file=credential_file,
            server_url=document["server_origin"],
            model_gateway_url=gateway,
            scopes=tuple(scopes),
            model_leases=HostModelLeaseAuthority(lease_key),
            lifetime_s=document["lifetime_seconds"],
        )
        profile = AliyunServerProfile(
            expected,
            product_revision,
            server_image_digest,
            document["host_image"],
            team_id,
            managed,
            MappingProxyType(authorities),
            tuple(authority_files),
            tuple(storage_configs),
            storage_credential_file,
        )
        profile.assert_ready()
        return profile
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Aliyun profile configuration is invalid") from None
