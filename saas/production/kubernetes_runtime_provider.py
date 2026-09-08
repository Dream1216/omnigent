"""Production composition for the Kubernetes Runtime Provider.

The provider materializes one immutable ConfigMap per Runtime Partition and
default Project.  Kubernetes object names and request annotations are
deterministic, so create/delete operations can be reconciled after an unknown
transport outcome without relaxing the durable PostgreSQL journal fence.

All secret-bearing inputs are owner-only files.  Runtime receipts are signed
by an OpenBao Transit key whose private key is non-exportable; the same Transit
authority verifies every receipt before the control plane persists it.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url

from saas.control_plane.runtime_provider import (
    ProductionRuntimePartitionAdapter,
    RuntimeProviderBinding,
    RuntimeProviderClient,
    RuntimeProviderCredential,
    RuntimeProviderCredentialAuthority,
    RuntimeProviderError,
    RuntimeProviderFailureDisposition,
    RuntimeProviderOperation,
    RuntimeProviderOperationJournal,
    RuntimeProviderOperationKind,
    RuntimeProviderOutcome,
    RuntimeProviderReceipt,
    RuntimeProviderReceiptVerifier,
    RuntimeProviderResponse,
    canonical_sha256,
)
from saas.control_plane.runtime_provider_journal import (
    PostgresqlRuntimeProviderOperationJournal,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_CONFIG_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE"
_JOURNAL_DSN_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_JOURNAL_DATABASE_URL_FILE"
_KUBERNETES_TOKEN_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_SERVICE_ACCOUNT_TOKEN_FILE"
_KUBERNETES_CA_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_KUBERNETES_CA_FILE"
_OPENBAO_TOKEN_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_OPENBAO_TOKEN_FILE"
_OPENBAO_CA_ENV = "OMNIGENT_SAAS_RUNTIME_PROVIDER_OPENBAO_CA_FILE"
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_SECRET_BYTES = 16 * 1024
_MAX_CA_BYTES = 1024 * 1024
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SAFE_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_LOWER_HEX_40 = re.compile(r"[0-9a-f]{40}")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_LOGIN_FRAGMENTS = ("admin", "migration", "owner", "postgres", "root")
_DIRECT_SECRET_ENV = frozenset(
    {
        "DATABASE_URL",
        "VAULT_TOKEN",
        "OMNIGENT_SAAS_RUNTIME_PROVIDER_JOURNAL_DATABASE_URL",
        "OMNIGENT_SAAS_RUNTIME_PROVIDER_SERVICE_ACCOUNT_TOKEN",
        "OMNIGENT_SAAS_RUNTIME_PROVIDER_OPENBAO_TOKEN",
    }
)


def _verify_runtime_provider_journal_binding(
    source: Mapping[str, str], *, journal_login: str
) -> None:
    """Bind the Provider journal DSN identity to the shared role manifest."""

    try:
        service_role_bindings = load_production_service_role_bindings(source)
    except ProductionServiceRoleBindingsError:
        raise KubernetesRuntimeProviderConfigError(
            "production service-role bindings are invalid"
        ) from None
    if service_role_bindings.login_for("runtime_provider_journal") != journal_login:
        raise KubernetesRuntimeProviderConfigError(
            "journal_login does not match the production service-role binding"
        )


class KubernetesRuntimeProviderConfigError(ValueError):
    """Stable startup error that never includes a credential or DSN value."""


@dataclass(frozen=True, slots=True)
class KubernetesRuntimeProviderConfig:
    placement_id: UUID
    binding_revision: str
    endpoint: str
    endpoint_ref: str
    credential_ref: str = field(repr=False)
    account_ref_hash: str
    region: str
    runtime_namespace: str
    runtime_version: str
    source_revision: str
    adapter_contract_version: str
    placement_generation: int
    journal_login: str
    openbao_address: str
    transit_mount: str
    receipt_key_name: str
    receipt_key_version: int
    request_timeout_seconds: float

    @property
    def binding(self) -> RuntimeProviderBinding:
        return RuntimeProviderBinding(
            provider_type="kubernetes",
            placement_id=self.placement_id,
            binding_revision=self.binding_revision,
            endpoint_ref=self.endpoint_ref,
            credential_ref=self.credential_ref,
            account_ref_hash=self.account_ref_hash,
            region=self.region,
        )


@dataclass(frozen=True, slots=True)
class _KubernetesCredentialMaterial:
    bearer_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class KubernetesApiResponse:
    status_code: int
    document: Mapping[str, object]
    request_id: str


class KubernetesApiTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        path: str,
        bearer_token: str,
        body: Mapping[str, object] | None = None,
    ) -> KubernetesApiResponse: ...


class ReceiptSigner(Protocol):
    production_capable: bool
    test_only: bool
    signature_key_id: str

    def sign(self, payload: bytes) -> str: ...

    def verify_signature(self, payload: bytes, signature_hex: str) -> bool: ...


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name, "")
    if not value or value != value.strip() or "\x00" in value:
        raise KubernetesRuntimeProviderConfigError(f"{name} is required and must be well formed")
    return value


def _owner_file(source: Mapping[str, str], name: str, *, maximum_bytes: int) -> tuple[Path, bytes]:
    value = _required(source, name)
    path = Path(value)
    if not path.is_absolute():
        raise KubernetesRuntimeProviderConfigError(f"{name} must be an absolute path")
    try:
        inspected = path.lstat()
    except OSError:
        raise KubernetesRuntimeProviderConfigError(f"{name} cannot be inspected") from None
    if (
        stat.S_ISLNK(inspected.st_mode)
        or not stat.S_ISREG(inspected.st_mode)
        or inspected.st_uid != os.geteuid()
        or stat.S_IMODE(inspected.st_mode) != 0o400
        or not 0 < inspected.st_size <= maximum_bytes
    ):
        raise KubernetesRuntimeProviderConfigError(
            f"{name} must be an owner-only regular file with mode 0400"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o400
            or not 0 < opened.st_size <= maximum_bytes
            or (opened.st_dev, opened.st_ino) != (inspected.st_dev, inspected.st_ino)
        ):
            raise KubernetesRuntimeProviderConfigError(f"{name} changed during inspection")
        raw = os.read(descriptor, maximum_bytes + 1)
    except KubernetesRuntimeProviderConfigError:
        raise
    except OSError:
        raise KubernetesRuntimeProviderConfigError(f"{name} cannot be read") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not 0 < len(raw) <= maximum_bytes:
        raise KubernetesRuntimeProviderConfigError(f"{name} has an invalid size")
    return path, raw


def _secret_text(source: Mapping[str, str], name: str) -> tuple[Path, str]:
    path, raw = _owner_file(source, name, maximum_bytes=_MAX_SECRET_BYTES)
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeError:
        raise KubernetesRuntimeProviderConfigError(f"{name} is malformed") from None
    if not value or value != value.strip() or "\n" in value or "\r" in value:
        raise KubernetesRuntimeProviderConfigError(f"{name} is malformed")
    return path, value


def _https_origin(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise KubernetesRuntimeProviderConfigError(f"{name} must be an HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise KubernetesRuntimeProviderConfigError(f"{name} must be an HTTPS origin") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise KubernetesRuntimeProviderConfigError(f"{name} must be an HTTPS origin")
    authority = parsed.hostname if port is None else f"{parsed.hostname}:{port}"
    return f"https://{authority}"


def _safe_text(document: Mapping[str, object], name: str, maximum: int) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise KubernetesRuntimeProviderConfigError(f"{name} is invalid")
    return value


def load_kubernetes_runtime_provider_config(
    environ: Mapping[str, str] | None = None,
) -> KubernetesRuntimeProviderConfig:
    source = os.environ if environ is None else environ
    present = sorted(name for name in _DIRECT_SECRET_ENV if source.get(name))
    if present:
        raise KubernetesRuntimeProviderConfigError(
            "direct secret environment variables are forbidden: " + ", ".join(present)
        )
    _path, raw = _owner_file(source, _CONFIG_ENV, maximum_bytes=_MAX_CONFIG_BYTES)
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError):
        raise KubernetesRuntimeProviderConfigError(f"{_CONFIG_ENV} is not valid JSON") from None
    expected = {
        "schema_version",
        "provider_type",
        "placement_id",
        "binding_revision",
        "endpoint",
        "endpoint_ref",
        "credential_ref",
        "account_ref_hash",
        "region",
        "runtime_namespace",
        "runtime_version",
        "source_revision",
        "adapter_contract_version",
        "placement_generation",
        "journal_login",
        "openbao_address",
        "transit_mount",
        "receipt_key_name",
        "receipt_key_version",
        "request_timeout_seconds",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise KubernetesRuntimeProviderConfigError(f"{_CONFIG_ENV} has an invalid shape")
    typed = cast(dict[str, object], document)
    canonical = (json.dumps(typed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if (
        raw != canonical
        or typed.get("schema_version") != 1
        or typed.get("provider_type") != "kubernetes"
    ):
        raise KubernetesRuntimeProviderConfigError(
            f"{_CONFIG_ENV} must contain canonical schema v1"
        )
    try:
        placement_id = UUID(_safe_text(typed, "placement_id", 36))
    except ValueError:
        raise KubernetesRuntimeProviderConfigError("placement_id is invalid") from None
    namespace = _safe_text(typed, "runtime_namespace", 63)
    if _DNS_LABEL.fullmatch(namespace) is None:
        raise KubernetesRuntimeProviderConfigError("runtime_namespace is invalid")
    source_revision = _safe_text(typed, "source_revision", 40)
    account_hash = _safe_text(typed, "account_ref_hash", 64)
    if (
        _LOWER_HEX_40.fullmatch(source_revision) is None
        or _LOWER_HEX_64.fullmatch(account_hash) is None
    ):
        raise KubernetesRuntimeProviderConfigError("source or account revision is invalid")
    for name in ("binding_revision", "region", "transit_mount", "receipt_key_name"):
        if _SAFE_TOKEN.fullmatch(_safe_text(typed, name, 128)) is None:
            raise KubernetesRuntimeProviderConfigError(f"{name} is invalid")
    journal_login = _safe_text(typed, "journal_login", 63)
    if _SAFE_TOKEN.fullmatch(journal_login) is None or any(
        fragment in journal_login.lower() for fragment in _FORBIDDEN_LOGIN_FRAGMENTS
    ):
        raise KubernetesRuntimeProviderConfigError("journal_login is invalid")
    generation = typed.get("placement_generation")
    key_version = typed.get("receipt_key_version")
    timeout = typed.get("request_timeout_seconds")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
        or isinstance(key_version, bool)
        or not isinstance(key_version, int)
        or key_version < 1
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0.1 <= float(timeout) <= 30
    ):
        raise KubernetesRuntimeProviderConfigError("numeric Runtime Provider values are invalid")
    config = KubernetesRuntimeProviderConfig(
        placement_id=placement_id,
        binding_revision=_safe_text(typed, "binding_revision", 128),
        endpoint=_https_origin(typed.get("endpoint"), "endpoint"),
        endpoint_ref=_safe_text(typed, "endpoint_ref", 512),
        credential_ref=_safe_text(typed, "credential_ref", 512),
        account_ref_hash=account_hash,
        region=_safe_text(typed, "region", 128),
        runtime_namespace=namespace,
        runtime_version=_safe_text(typed, "runtime_version", 64),
        source_revision=source_revision,
        adapter_contract_version=_safe_text(typed, "adapter_contract_version", 32),
        placement_generation=generation,
        journal_login=journal_login,
        openbao_address=_https_origin(typed.get("openbao_address"), "openbao_address"),
        transit_mount=_safe_text(typed, "transit_mount", 128),
        receipt_key_name=_safe_text(typed, "receipt_key_name", 128),
        receipt_key_version=key_version,
        request_timeout_seconds=float(timeout),
    )
    try:
        binding = config.binding
    except ValueError:
        raise KubernetesRuntimeProviderConfigError("Runtime Provider binding is invalid") from None
    endpoint = urlsplit(config.endpoint)
    endpoint_ref = urlsplit(config.endpoint_ref)
    credential_ref = urlsplit(config.credential_ref)
    if (
        binding.provider_type != "kubernetes"
        or endpoint_ref.scheme != "service"
        or endpoint_ref.hostname != endpoint.hostname
        or endpoint_ref.path not in {"", "/"}
        or endpoint_ref.query
        or endpoint_ref.fragment
        or credential_ref.scheme != "workload-identity"
        or not credential_ref.hostname
        or not credential_ref.path.strip("/")
        or credential_ref.query
        or credential_ref.fragment
    ):
        raise KubernetesRuntimeProviderConfigError("Runtime Provider binding is invalid")
    return config


def _verify_installed_lineage(config: KubernetesRuntimeProviderConfig) -> None:
    try:
        from omnigent import _build_info
        from omnigent.version import VERSION

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError):
        raise KubernetesRuntimeProviderConfigError(
            "Runtime Provider build lineage is unavailable"
        ) from None
    if (
        not isinstance(installed_revision, str)
        or not hmac.compare_digest(installed_revision, config.source_revision)
        or not hmac.compare_digest(VERSION, config.runtime_version)
    ):
        raise KubernetesRuntimeProviderConfigError(
            "Runtime Provider configuration does not match the installed build"
        )


class ProjectedServiceAccountCredentialAuthority:
    """Acquire a fresh projected Kubernetes token for every Provider call."""

    production_capable: bool = True
    uses_ambient_credentials: bool = False

    def __init__(self, *, token_file: Path) -> None:
        self._token_file = token_file

    @contextmanager
    def acquire(
        self,
        *,
        binding: RuntimeProviderBinding,
        operation: RuntimeProviderOperationKind,
    ) -> Iterator[RuntimeProviderCredential]:
        del operation
        source = {_KUBERNETES_TOKEN_ENV: str(self._token_file)}
        _path, token = _secret_text(source, _KUBERNETES_TOKEN_ENV)
        try:
            yield RuntimeProviderCredential(
                credential_ref_hash=binding.credential_ref_hash,
                version=sha256(token.encode("utf-8")).hexdigest(),
                material=_KubernetesCredentialMaterial(bearer_token=token),
            )
        finally:
            token = ""


class HttpxKubernetesApiTransport:
    """Small explicit Kubernetes REST transport with a pinned CA bundle."""

    def __init__(self, *, endpoint: str, ca_file: Path, timeout_seconds: float) -> None:
        self._endpoint = endpoint
        self._ca_file = ca_file
        self._timeout = timeout_seconds

    def request(
        self,
        *,
        method: str,
        path: str,
        bearer_token: str,
        body: Mapping[str, object] | None = None,
    ) -> KubernetesApiResponse:
        try:
            with httpx.Client(
                base_url=self._endpoint,
                verify=str(self._ca_file),
                timeout=self._timeout,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {bearer_token}"},
                    json=None if body is None else dict(body),
                )
        except httpx.HTTPError as error:
            raise RuntimeProviderError(
                "kubernetes_transport_unavailable",
                RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE,
            ) from error
        try:
            document = response.json() if response.content else {}
        except ValueError:
            document = {}
        if not isinstance(document, dict):
            document = {}
        request_id = response.headers.get("Audit-Id", "")
        return KubernetesApiResponse(
            status_code=response.status_code,
            document=MappingProxyType(cast(dict[str, object], document)),
            request_id=request_id,
        )


class OpenBaoTransitReceiptAuthority:
    """Sign and verify receipts with one pinned non-exporting Transit key."""

    production_capable: bool = True
    test_only: bool = False

    def __init__(
        self,
        *,
        address: str,
        ca_file: Path,
        token_file: Path,
        mount_point: str,
        key_name: str,
        key_version: int,
    ) -> None:
        self.signature_key_id = f"{key_name}-v{key_version}"
        if _SAFE_TOKEN.fullmatch(self.signature_key_id) is None:
            raise KubernetesRuntimeProviderConfigError("receipt signature key id is invalid")
        self._address = address
        self._ca_file = ca_file
        self._token_file = token_file
        self._mount = mount_point
        self._key = key_name
        self._version = key_version

    def _client(self) -> Any:
        try:
            import hvac
        except ImportError as error:  # pragma: no cover - image packaging guard
            raise RuntimeError("the SaaS image is missing the OpenBao client") from error
        _path, token = _secret_text(
            {_OPENBAO_TOKEN_ENV: str(self._token_file)}, _OPENBAO_TOKEN_ENV
        )
        return hvac.Client(url=self._address, token=token, verify=str(self._ca_file))

    def sign(self, payload: bytes) -> str:
        response = self._client().secrets.transit.sign_data(
            name=self._key,
            mount_point=self._mount,
            hash_input=base64.b64encode(payload).decode("ascii"),
            key_version=self._version,
        )
        signature = response["data"]["signature"]
        prefix = f"vault:v{self._version}:"
        if not isinstance(signature, str) or not signature.startswith(prefix):
            raise RuntimeError("OpenBao returned an unexpected signature version")
        try:
            decoded = base64.b64decode(signature.removeprefix(prefix), validate=True)
        except (TypeError, ValueError):
            raise RuntimeError("OpenBao returned a malformed signature") from None
        return decoded.hex()

    def verify_signature(self, payload: bytes, signature_hex: str) -> bool:
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        rendered = f"vault:v{self._version}:{base64.b64encode(signature).decode('ascii')}"
        response = self._client().secrets.transit.verify_signed_data(
            name=self._key,
            mount_point=self._mount,
            hash_input=base64.b64encode(payload).decode("ascii"),
            signature=rendered,
        )
        return response.get("data", {}).get("valid") is True

    def verify(
        self,
        *,
        binding: RuntimeProviderBinding,
        receipt: RuntimeProviderReceipt,
        payload: bytes,
    ) -> bool:
        return (
            binding.binding_hash == receipt.binding_hash
            and receipt.signature_key_id == self.signature_key_id
            and self.verify_signature(payload, receipt.signature_hex)
        )


class KubernetesRuntimeProviderClient:
    provider_type: str = "kubernetes"
    production_capable: bool = True
    test_only: bool = False

    def __init__(
        self,
        *,
        config: KubernetesRuntimeProviderConfig,
        transport: KubernetesApiTransport,
        signer: ReceiptSigner,
    ) -> None:
        if not signer.production_capable or signer.test_only:
            raise ValueError("a production receipt signer is required")
        self._config = config
        self._transport = transport
        self._signer = signer

    def execute(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse:
        return self._apply(operation, credential)

    def reconcile(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse:
        return self._apply(operation, credential)

    def _apply(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
    ) -> RuntimeProviderResponse:
        material = credential.material
        if not isinstance(material, _KubernetesCredentialMaterial):
            raise RuntimeProviderError(
                "kubernetes_credential_invalid",
                RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
            )
        target = operation.target
        is_project = operation.kind in {
            RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT,
            RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
        }
        identity = _target_uuid(target, "project_id" if is_project else "runtime_partition_id")
        resource_kind = "project" if is_project else "partition"
        name = f"omnigent-{resource_kind}-{identity}"
        collection = (
            f"/api/v1/namespaces/{quote(self._config.runtime_namespace, safe='')}/configmaps"
        )
        resource_path = f"{collection}/{quote(name, safe='')}"
        resource_id = f"k8s://{self._config.runtime_namespace}/configmaps/{name}"
        if operation.kind in {
            RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
            RuntimeProviderOperationKind.COMPENSATE_PARTITION,
        }:
            observed = self._transport.request(
                method="DELETE",
                path=resource_path,
                bearer_token=material.bearer_token,
                body={
                    "kind": "DeleteOptions",
                    "apiVersion": "v1",
                    "propagationPolicy": "Foreground",
                },
            )
            if observed.status_code == 404:
                return self._response(
                    operation,
                    credential,
                    attributes={},
                    outcome=RuntimeProviderOutcome.ALREADY_ABSENT,
                    provider_resource_id=None,
                    request_id=observed.request_id,
                )
            if observed.status_code not in {200, 202}:
                self._raise_status(observed.status_code, compensation=True)
            return self._response(
                operation,
                credential,
                attributes={},
                outcome=RuntimeProviderOutcome.APPLIED,
                provider_resource_id=resource_id,
                request_id=observed.request_id,
            )

        existing = self._transport.request(
            method="GET",
            path=resource_path,
            bearer_token=material.bearer_token,
        )
        outcome = RuntimeProviderOutcome.REPLAYED
        request_id = existing.request_id
        if existing.status_code == 200:
            _verify_existing(existing.document, operation)
            outcome = RuntimeProviderOutcome.REPLAYED
            request_id = existing.request_id
        elif existing.status_code == 404:
            created = self._transport.request(
                method="POST",
                path=collection,
                bearer_token=material.bearer_token,
                body=_config_map(name, resource_kind, operation),
            )
            if created.status_code == 409:
                raced = self._transport.request(
                    method="GET",
                    path=resource_path,
                    bearer_token=material.bearer_token,
                )
                if raced.status_code != 200:
                    self._raise_status(raced.status_code, compensation=False)
                _verify_existing(raced.document, operation)
                outcome = RuntimeProviderOutcome.REPLAYED
                request_id = raced.request_id
            elif created.status_code != 201:
                self._raise_status(created.status_code, compensation=False)
            else:
                _verify_existing(created.document, operation)
                outcome = RuntimeProviderOutcome.APPLIED
                request_id = created.request_id
        else:
            self._raise_status(existing.status_code, compensation=False)
            raise AssertionError("unreachable")

        if is_project:
            attributes: dict[str, object] = {"runtime_resource_id": resource_id}
        else:
            partition = cast(Mapping[str, object], target)
            runtime_partition_id = _target_uuid(partition, "runtime_partition_id")
            attributes = {
                "runtime_version": self._config.runtime_version,
                # The ConfigMap URI is the Provider resource locator recorded
                # on the signed receipt.  The permanent Omnigent adapter,
                # however, requires a canonical positive integer workspace
                # key.  Derive that key deterministically from the immutable
                # Runtime Partition UUID; the database uniqueness constraint
                # remains the collision fence.
                "physical_partition_key": str(int(runtime_partition_id.hex[:12], 16) or 1),
                "placement_generation": self._config.placement_generation,
                "source_revision": self._config.source_revision,
                "adapter_contract_version": self._config.adapter_contract_version,
                "runtime_user_key": (
                    f"tenant:{_target_uuid(partition, 'tenant_id')}:"
                    f"space:{_target_uuid(partition, 'space_id')}"
                ),
            }
        return self._response(
            operation,
            credential,
            attributes=attributes,
            outcome=outcome,
            provider_resource_id=resource_id,
            request_id=request_id,
        )

    @staticmethod
    def _raise_status(status: int, *, compensation: bool) -> None:
        if status in {401, 403, 422}:
            disposition = RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT
        elif compensation:
            disposition = RuntimeProviderFailureDisposition.COMPENSATION_UNKNOWN
        else:
            disposition = RuntimeProviderFailureDisposition.UNKNOWN_EFFECT_RECONCILE
        raise RuntimeProviderError("kubernetes_request_failed", disposition)

    def _response(
        self,
        operation: RuntimeProviderOperation,
        credential: RuntimeProviderCredential,
        *,
        attributes: Mapping[str, object],
        outcome: RuntimeProviderOutcome,
        provider_resource_id: str | None,
        request_id: str,
    ) -> RuntimeProviderResponse:
        result_hash = canonical_sha256(attributes)
        unsigned = RuntimeProviderReceipt(
            schema_version=1,
            provider_type=self.provider_type,
            operation=operation.kind,
            outcome=outcome,
            placement_id=operation.placement_id,
            binding_revision=operation.binding_revision,
            binding_hash=operation.binding_hash,
            target_hash=operation.target_hash,
            idempotency_hash=operation.idempotency_hash,
            request_hash=operation.request_hash,
            credential_ref_hash=credential.credential_ref_hash,
            credential_version_hash=credential.version_hash,
            result_hash=result_hash,
            provider_request_id=request_id or f"k8s-{operation.request_hash[:32]}",
            provider_resource_id=provider_resource_id,
            observed_at=datetime.now(timezone.utc),
            receipt_hash="0" * 64,
            signature_key_id=self._signer.signature_key_id,
            signature_hex="0" * 64,
        )
        payload = unsigned.unsigned_payload()
        receipt = replace(
            unsigned,
            receipt_hash=sha256(payload).hexdigest(),
            signature_hex=self._signer.sign(payload),
        )
        return RuntimeProviderResponse(
            receipt=receipt,
            attributes=MappingProxyType(dict(attributes)),
        )


def _target_uuid(target: Mapping[str, object], name: str) -> UUID:
    value = target.get(name)
    if value is None and name == "project_id":
        value = target.get("project_id")
    try:
        return UUID(cast(str, value))
    except (TypeError, ValueError, AttributeError):
        raise RuntimeProviderError(
            "kubernetes_target_invalid",
            RuntimeProviderFailureDisposition.PERMANENT_NO_EFFECT,
        ) from None


def _config_map(
    name: str,
    resource_kind: str,
    operation: RuntimeProviderOperation,
) -> Mapping[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "labels": {
                "app.kubernetes.io/managed-by": "omnigent-saas",
                "ai.omnigent.runtime/resource-kind": resource_kind,
            },
            "annotations": {
                "ai.omnigent.runtime/request-hash": operation.request_hash,
                "ai.omnigent.runtime/target-hash": operation.target_hash,
                "ai.omnigent.runtime/binding-hash": operation.binding_hash,
            },
        },
        "immutable": True,
        "data": {"target.json": operation.target_json},
    }


def _verify_existing(document: Mapping[str, object], operation: RuntimeProviderOperation) -> None:
    metadata = document.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    data = document.get("data")
    if not isinstance(annotations, dict) or not isinstance(data, dict):
        raise RuntimeProviderError(
            "kubernetes_resource_conflict",
            RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
        )
    expected = {
        "ai.omnigent.runtime/request-hash": operation.request_hash,
        "ai.omnigent.runtime/target-hash": operation.target_hash,
        "ai.omnigent.runtime/binding-hash": operation.binding_hash,
    }
    if (
        any(annotations.get(key) != value for key, value in expected.items())
        or data.get("target.json") != operation.target_json
    ):
        raise RuntimeProviderError(
            "kubernetes_resource_conflict",
            RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT,
        )


def _journal_database_url(source: Mapping[str, str], *, expected_login: str) -> tuple[Path, str]:
    path, value = _secret_text(source, _JOURNAL_DSN_ENV)
    try:
        parsed: URL = make_url(value)
    except ValueError:
        raise KubernetesRuntimeProviderConfigError(f"{_JOURNAL_DSN_ENV} is malformed") from None
    query = {str(key).lower(): str(item) for key, item in parsed.query.items()}
    if (
        parsed.drivername != "postgresql+psycopg"
        or parsed.username != expected_login
        or parsed.password is None
        or not parsed.host
        or not parsed.database
        or "role" in query
        or "options" in query
        or query.get("sslmode") != "verify-full"
        or query.get("sslrootcert") != "/runtime/postgresql-ca.crt"
    ):
        raise KubernetesRuntimeProviderConfigError(
            f"{_JOURNAL_DSN_ENV} must contain the exact restricted PostgreSQL login"
        )
    return path, value


def build_kubernetes_runtime_provider() -> ProductionRuntimePartitionAdapter:
    """Zero-argument production factory used by the onboarding Outbox worker."""

    source = os.environ
    config = load_kubernetes_runtime_provider_config(source)
    _verify_runtime_provider_journal_binding(source, journal_login=config.journal_login)
    _verify_installed_lineage(config)
    token_path, _token = _secret_text(source, _KUBERNETES_TOKEN_ENV)
    kubernetes_ca, _ = _owner_file(source, _KUBERNETES_CA_ENV, maximum_bytes=_MAX_CA_BYTES)
    openbao_token, _secret = _secret_text(source, _OPENBAO_TOKEN_ENV)
    openbao_ca, _ = _owner_file(source, _OPENBAO_CA_ENV, maximum_bytes=_MAX_CA_BYTES)
    _journal_path, journal_url = _journal_database_url(source, expected_login=config.journal_login)
    receipt_authority = OpenBaoTransitReceiptAuthority(
        address=config.openbao_address,
        ca_file=openbao_ca,
        token_file=openbao_token,
        mount_point=config.transit_mount,
        key_name=config.receipt_key_name,
        key_version=config.receipt_key_version,
    )
    transport = HttpxKubernetesApiTransport(
        endpoint=config.endpoint,
        ca_file=kubernetes_ca,
        timeout_seconds=config.request_timeout_seconds,
    )
    journal_engine = sa.create_engine(
        journal_url,
        pool_pre_ping=True,
        hide_parameters=True,
    )
    try:
        journal = PostgresqlRuntimeProviderOperationJournal(journal_engine)
        return ProductionRuntimePartitionAdapter(
            bindings={config.placement_id: config.binding},
            client=cast(
                RuntimeProviderClient,
                KubernetesRuntimeProviderClient(
                    config=config,
                    transport=transport,
                    signer=receipt_authority,
                ),
            ),
            credentials=cast(
                RuntimeProviderCredentialAuthority,
                ProjectedServiceAccountCredentialAuthority(token_file=token_path),
            ),
            receipt_verifier=cast(RuntimeProviderReceiptVerifier, receipt_authority),
            operation_journal=cast(RuntimeProviderOperationJournal, journal),
        )
    except Exception:
        journal_engine.dispose()
        raise


__all__ = [
    "HttpxKubernetesApiTransport",
    "KubernetesApiResponse",
    "KubernetesRuntimeProviderClient",
    "KubernetesRuntimeProviderConfig",
    "KubernetesRuntimeProviderConfigError",
    "OpenBaoTransitReceiptAuthority",
    "ProjectedServiceAccountCredentialAuthority",
    "build_kubernetes_runtime_provider",
    "load_kubernetes_runtime_provider_config",
]
