"""Short-lived, project-scoped delegation to the independent DCP service."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from saas.compatibility import RequestContext


@dataclass(frozen=True)
class DeliveryProject:
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    name: str
    preview_environment: str
    production_environment: str
    preview_domain_binding_id: str | None = None


@dataclass(frozen=True)
class DeliveryConfig:
    endpoint: str
    issuer: str
    key_id: str
    private_key: bytes = field(repr=False)
    projects: tuple[DeliveryProject, ...]
    ca_file: Path | None = None
    repository_mirrors: dict[str, Path] = field(default_factory=dict)
    client_certificate_file: Path | None = None
    client_private_key_file: Path | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for url in (self.endpoint, self.issuer):
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("delivery authority URLs must use HTTPS")
        key = serialization.load_pem_private_key(self.private_key, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("delivery signing key must be RSA with at least 2048 bits")
        if not self.key_id or len({p.project_id for p in self.projects}) != len(self.projects):
            raise ValueError("delivery key or project configuration is invalid")
        if (self.client_certificate_file is None) != (self.client_private_key_file is None):
            raise ValueError("delivery mTLS requires both a client certificate and private key")
        for path in (self.client_certificate_file, self.client_private_key_file):
            if path is None:
                continue
            metadata = path.lstat()
            if not path.is_absolute() or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("delivery mTLS files require absolute regular files")
            if path == self.client_private_key_file and (
                metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise ValueError("delivery mTLS private key requires an owner-only file")
        for mirror in self.repository_mirrors.values():
            if not mirror.is_absolute() or mirror.is_symlink() or not mirror.is_dir():
                raise ValueError(
                    "checkpoint repository mirrors must be existing absolute directories"
                )
        for project in self.projects:
            if any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
                for value in (project.preview_environment, project.production_environment)
            ):
                raise ValueError("delivery targets must use stable environment identifiers")
            if project.preview_environment == project.production_environment:
                raise ValueError("preview and production targets must be distinct")

    @classmethod
    def from_file(cls, path: Path) -> DeliveryConfig:
        def private_file(source: Path) -> bytes:
            metadata = source.lstat()
            if (
                not source.is_absolute()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
                or not 0 < metadata.st_size <= 1024 * 1024
            ):
                raise ValueError("delivery configuration and keys require owner-only files")
            return source.read_bytes()

        raw = json.loads(private_file(path))
        return cls(
            endpoint=raw["endpoint"],
            issuer=raw["issuer"],
            key_id=raw["key_id"],
            private_key=private_file(Path(raw["private_key_file"])),
            ca_file=Path(raw["ca_file"]) if raw.get("ca_file") else None,
            client_certificate_file=(
                Path(raw["client_certificate_file"])
                if raw.get("client_certificate_file")
                else None
            ),
            client_private_key_file=(
                Path(raw["client_private_key_file"])
                if raw.get("client_private_key_file")
                else None
            ),
            repository_mirrors={
                key: Path(value) for key, value in raw.get("repository_mirrors", {}).items()
            },
            projects=tuple(
                DeliveryProject(
                    tenant_id=UUID(item["tenant_id"]),
                    space_id=UUID(item["space_id"]),
                    project_id=UUID(item["project_id"]),
                    name=item["name"],
                    preview_environment=item["preview_environment"],
                    production_environment=item["production_environment"],
                    preview_domain_binding_id=item.get("preview_domain_binding_id"),
                )
                for item in raw["projects"]
            ),
        )


class DcpResponseError(RuntimeError):
    def __init__(self, status: int, code: str, retryable: bool = False) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.retryable = retryable


class DeliveryClient:
    def __init__(
        self, config: DeliveryConfig, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.config = config
        self.transport = transport

    def jwks(self) -> dict[str, Any]:
        key = serialization.load_pem_private_key(self.config.private_key, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        return {"keys": [{**public, "kid": self.config.key_id, "alg": "RS256", "use": "sig"}]}

    def token(self, context: RequestContext, permissions: frozenset[str]) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": self.config.issuer,
                "aud": "omnigent-deployment-control-plane",
                "sub": str(context.actor_id),
                "tenant_id": str(context.tenant_id),
                "space_id": str(context.space_id),
                "project_id": str(context.project_id),
                "membership_version": context.tenant_membership_version,
                "token_schema_version": 1,
                "permissions": sorted(permissions),
                "iat": now,
                "exp": now + 60,
                "jti": uuid4().hex,
            },
            self.config.private_key,
            algorithm="RS256",
            headers={"kid": self.config.key_id},
        )

    async def request(
        self,
        context: RequestContext,
        permissions: frozenset[str],
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        key: str | None = None,
    ) -> Any:
        headers = {
            "Authorization": f"Bearer {self.token(context, permissions)}",
            "X-Correlation-ID": uuid4().hex,
        }
        if key:
            headers["Idempotency-Key"] = key
        try:
            async with self._http() as client:
                response = await client.request(method, path, json=body, headers=headers)
            payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise DcpResponseError(503, "delivery_service_unavailable", True) from error
        if not response.is_success:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            raise DcpResponseError(
                response.status_code,
                error.get("code", "delivery_rejected"),
                error.get("retryable") is True,
            )
        return payload

    def _tls_context(self) -> bool | ssl.SSLContext:
        if self.config.ca_file is None and self.config.client_certificate_file is None:
            return True
        context = ssl.create_default_context(
            cafile=str(self.config.ca_file) if self.config.ca_file is not None else None
        )
        if self.config.client_certificate_file is not None:
            assert self.config.client_private_key_file is not None
            context.load_cert_chain(
                str(self.config.client_certificate_file), str(self.config.client_private_key_file)
            )
        return context

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.config.endpoint,
            transport=self.transport,
            verify=self._tls_context(),
            timeout=httpx.Timeout(180, connect=10),
            trust_env=False,
            follow_redirects=False,
        )

    async def check_contract(self) -> None:
        frozen = (Path(__file__).parents[1] / "production" / "dcp-openapi-v1.json").read_bytes()
        async with self._http() as client:
            response = await client.get("/v1/openapi.json")
            response.raise_for_status()
        current = (
            json.dumps(response.json(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        if hashlib.sha256(current).digest() != hashlib.sha256(frozen).digest():
            raise ValueError("App and DCP contract revisions differ")

    def assert_ready(self) -> None:
        with httpx.Client(
            verify=self._tls_context(), timeout=5, trust_env=False, follow_redirects=False
        ) as client:
            response = client.get(self.config.endpoint.rstrip("/") + "/v1/openapi.json")
            response.raise_for_status()
        current = (
            json.dumps(response.json(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        frozen = (Path(__file__).parents[1] / "production" / "dcp-openapi-v1.json").read_bytes()
        if hashlib.sha256(current).digest() != hashlib.sha256(frozen).digest():
            raise ValueError("App and DCP contract revisions differ")
