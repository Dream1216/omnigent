"""Canonical allowlist for production PostgreSQL service-login memberships."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_MAX_BINDINGS_BYTES = 16 * 1024
EXPECTED_PRODUCTION_SERVICE_ROLES: Mapping[str, str] = MappingProxyType(
    {
        "runtime": "omnigent_runtime_app",
        "authenticator": "saas_authenticator",
        "app": "saas_app",
        "governance": "saas_governance",
        "public_api": "saas_public_api",
        "dispatcher": "saas_dispatcher",
        "executor": "saas_executor",
        "onboarding": "saas_onboarding",
        "onboarding_status": "saas_onboarding_status",
        "platform_governance": "saas_platform_governance",
        "secret_broker": "saas_secret_broker",
        "preview_edge": "saas_preview_edge",
        "preview_owner": "saas_preview_owner",
        "registration": "saas_registration",
        "runtime_provider_journal": "saas_runtime_provider_journal",
    }
)
EXPECTED_PLATFORM_MODEL_SERVICE_ROLES: Mapping[str, str] = MappingProxyType(
    {
        "app": "saas_app",
        "authenticator": "saas_authenticator",
        "billing": "saas_billing",
        "platform_app": "saas_platform_app",
        "secret_broker": "saas_secret_broker",
    }
)
EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES: Mapping[str, str] = MappingProxyType(
    {
        "platform_app": "saas_platform_app",
        "platform_authenticator": "saas_platform_authenticator",
        "platform_governance": "saas_platform_governance",
    }
)


class ProductionServiceRoleBindingsError(ValueError):
    """Stable rejection for malformed or mutable service-login authority."""


@dataclass(frozen=True, slots=True)
class ProductionServiceRoleBinding:
    """One exact deployment service, login, and NOLOGIN base-role edge."""

    service: str
    login: str
    base_role: str


@dataclass(frozen=True, slots=True)
class ProductionServiceRoleBindings:
    """Owner-only canonical manifest shared by migration, server, and workers."""

    path: Path
    sha256: str
    bindings: tuple[ProductionServiceRoleBinding, ...]

    def login_for(self, service: str) -> str:
        """Return the only admitted login for one exact service."""

        for binding in self.bindings:
            if binding.service == service:
                return binding.login
        raise KeyError(service)

    @property
    def by_service(self) -> Mapping[str, ProductionServiceRoleBinding]:
        return MappingProxyType({binding.service: binding for binding in self.bindings})


@dataclass(frozen=True, slots=True)
class ProductionServiceRoleGraph:
    """Exact union of the core and optional release-scoped service profiles."""

    sha256: str
    bindings: tuple[ProductionServiceRoleBinding, ...]

    def login_for(self, service: str) -> str:
        """Return the only admitted login for one exact service."""

        for binding in self.bindings:
            if binding.service == service:
                return binding.login
        raise KeyError(service)

    @property
    def by_service(self) -> Mapping[str, ProductionServiceRoleBinding]:
        return MappingProxyType({binding.service: binding for binding in self.bindings})


def _canonical_document(
    bindings: tuple[ProductionServiceRoleBinding, ...],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "bindings": [
            {
                "service": binding.service,
                "login": binding.login,
                "base_role": binding.base_role,
            }
            for binding in bindings
        ],
    }


def render_production_service_role_bindings(
    bindings: tuple[ProductionServiceRoleBinding, ...],
) -> str:
    """Render the unique byte representation hashed into migration evidence."""

    ordered = tuple(sorted(bindings, key=lambda binding: binding.service))
    return (
        json.dumps(
            _canonical_document(ordered),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    )


def compose_production_service_role_graph(
    production: ProductionServiceRoleBindings,
    platform_model: ProductionServiceRoleBindings | None = None,
    platform_admin: ProductionServiceRoleBindings | None = None,
) -> ProductionServiceRoleGraph:
    """Compose profiles without permitting an overlap or login to change meaning."""

    by_service = {binding.service: binding for binding in production.bindings}
    for extension in (platform_model, platform_admin):
        if extension is None:
            continue
        for binding in extension.bindings:
            existing = by_service.get(binding.service)
            if existing is not None and existing != binding:
                raise ProductionServiceRoleBindingsError(
                    "service-role profiles assign different bindings to the same service"
                )
            by_service[binding.service] = binding
    bindings = tuple(sorted(by_service.values(), key=lambda binding: binding.service))
    logins = {binding.login for binding in bindings}
    if len(logins) != len(bindings):
        duplicate_services = {
            binding.service
            for binding in bindings
            if sum(item.login == binding.login for item in bindings) > 1
        }
        raise ProductionServiceRoleBindingsError(
            "service-role profiles reuse a login across services: "
            + ",".join(sorted(duplicate_services))
        )
    canonical = render_production_service_role_bindings(bindings)
    return ProductionServiceRoleGraph(
        sha256=hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        bindings=bindings,
    )


def load_production_service_role_bindings(
    source: Mapping[str, str],
) -> ProductionServiceRoleBindings:
    """Load the exact production service-role profile without database access."""

    return _load_service_role_bindings(
        source,
        name="OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE",
        expected_roles=EXPECTED_PRODUCTION_SERVICE_ROLES,
    )


def load_platform_model_service_role_bindings(
    source: Mapping[str, str],
) -> ProductionServiceRoleBindings:
    """Load the isolated five-login Platform model deployment profile."""

    return _load_service_role_bindings(
        source,
        name="OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS_FILE",
        expected_roles=EXPECTED_PLATFORM_MODEL_SERVICE_ROLES,
    )


def load_platform_admin_service_role_bindings(
    source: Mapping[str, str],
) -> ProductionServiceRoleBindings:
    """Load the isolated three-login Platform Admin deployment profile."""

    return _load_service_role_bindings(
        source,
        name="OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS_FILE",
        expected_roles=EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES,
    )


def _load_service_role_bindings(
    source: Mapping[str, str],
    *,
    name: str,
    expected_roles: Mapping[str, str],
) -> ProductionServiceRoleBindings:
    path_value = source.get(name)
    if path_value is None or not path_value.strip() or path_value != path_value.strip():
        raise ProductionServiceRoleBindingsError(f"{name} is required")
    path = Path(path_value)
    if not path.is_absolute():
        raise ProductionServiceRoleBindingsError(f"{name} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProductionServiceRoleBindingsError(f"{name} cannot be inspected") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or mode != 0o400
        or not 0 < metadata.st_size <= _MAX_BINDINGS_BYTES
    ):
        raise ProductionServiceRoleBindingsError(
            f"{name} must be an owner-readable, owner-only, read-only regular file"
        )
    try:
        raw = path.read_text(encoding="ascii")
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductionServiceRoleBindingsError(f"{name} cannot be loaded") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "bindings"}:
        raise ProductionServiceRoleBindingsError(f"{name} has an invalid document shape")
    rows = document.get("bindings")
    if document.get("schema_version") != 1 or not isinstance(rows, list):
        raise ProductionServiceRoleBindingsError(f"{name} has an invalid schema version")
    parsed: list[ProductionServiceRoleBinding] = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"service", "login", "base_role"}
            or not all(isinstance(row.get(key), str) for key in row)
        ):
            raise ProductionServiceRoleBindingsError(f"{name} has an invalid binding")
        service = cast(str, row["service"])
        login = cast(str, row["login"])
        base_role = cast(str, row["base_role"])
        if any(_ROLE_NAME.fullmatch(value) is None for value in (service, login, base_role)):
            raise ProductionServiceRoleBindingsError(f"{name} has an invalid role name")
        parsed.append(
            ProductionServiceRoleBinding(
                service=service,
                login=login,
                base_role=base_role,
            )
        )
    bindings = tuple(sorted(parsed, key=lambda binding: binding.service))
    expected_services = set(expected_roles)
    if (
        len(bindings) != len(expected_services)
        or {binding.service for binding in bindings} != expected_services
        or len({binding.login for binding in bindings}) != len(bindings)
        or len({binding.base_role for binding in bindings}) != len(bindings)
        or any(binding.base_role != expected_roles[binding.service] for binding in bindings)
    ):
        raise ProductionServiceRoleBindingsError(
            f"{name} must contain the exact production service-role profile"
        )
    canonical = render_production_service_role_bindings(bindings)
    if raw != canonical:
        raise ProductionServiceRoleBindingsError(f"{name} must contain canonical JSON")
    return ProductionServiceRoleBindings(
        path=path,
        sha256=hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        bindings=bindings,
    )


__all__ = [
    "EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES",
    "EXPECTED_PLATFORM_MODEL_SERVICE_ROLES",
    "EXPECTED_PRODUCTION_SERVICE_ROLES",
    "ProductionServiceRoleBinding",
    "ProductionServiceRoleBindings",
    "ProductionServiceRoleBindingsError",
    "ProductionServiceRoleGraph",
    "compose_production_service_role_graph",
    "load_platform_admin_service_role_bindings",
    "load_platform_model_service_role_bindings",
    "load_production_service_role_bindings",
    "render_production_service_role_bindings",
]
