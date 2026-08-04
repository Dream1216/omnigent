"""Versioned, machine-readable permission catalog and immutable built-in roles."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

POLICY_VERSION: Final = "2026-08-04.p2"


class PermissionScope(StrEnum):
    PLATFORM = "platform"
    TENANT = "tenant"
    SPACE = "space"
    PROJECT = "project"
    RESOURCE = "resource"


class PermissionRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class PermissionDefinition:
    """Stable permission metadata consumed by API, UI, policy, and tests."""

    name: str
    scope: PermissionScope
    risk: PermissionRisk
    reads_content: bool = False
    service_account_allowed: bool = False
    fresh_auth_required: bool = False
    approval_required: bool = False


def _permission(
    name: str,
    scope: PermissionScope,
    risk: PermissionRisk,
    *,
    reads_content: bool = False,
    service_account_allowed: bool = False,
    fresh_auth_required: bool = False,
    approval_required: bool = False,
) -> PermissionDefinition:
    return PermissionDefinition(
        name=name,
        scope=scope,
        risk=risk,
        reads_content=reads_content,
        service_account_allowed=service_account_allowed,
        fresh_auth_required=fresh_auth_required,
        approval_required=approval_required,
    )


_DEFINITIONS = (
    _permission("tenant.read", PermissionScope.TENANT, PermissionRisk.LOW),
    _permission("tenant.update", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("tenant.suspend", PermissionScope.TENANT, PermissionRisk.CRITICAL),
    _permission(
        "tenant.delete",
        PermissionScope.TENANT,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
    ),
    _permission(
        "tenant.ownership.transfer",
        PermissionScope.TENANT,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
    _permission("membership.invite", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("membership.role.update", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("membership.suspend", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("membership.remove", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("space.create", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("space.read", PermissionScope.SPACE, PermissionRisk.LOW),
    _permission("space.update", PermissionScope.SPACE, PermissionRisk.MEDIUM),
    _permission("space.policy.update", PermissionScope.SPACE, PermissionRisk.HIGH),
    _permission(
        "space.delete",
        PermissionScope.SPACE,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
    _permission(
        "space.ownership.transfer",
        PermissionScope.SPACE,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
    _permission("project.create", PermissionScope.SPACE, PermissionRisk.MEDIUM),
    _permission("project.read_metadata", PermissionScope.PROJECT, PermissionRisk.LOW),
    _permission(
        "project.content.read",
        PermissionScope.PROJECT,
        PermissionRisk.MEDIUM,
        reads_content=True,
        service_account_allowed=True,
    ),
    _permission(
        "project.content.edit",
        PermissionScope.PROJECT,
        PermissionRisk.HIGH,
        reads_content=True,
        service_account_allowed=True,
    ),
    _permission("project.update", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission(
        "project.delete",
        PermissionScope.PROJECT,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
    _permission("grant.read", PermissionScope.PROJECT, PermissionRisk.MEDIUM),
    _permission("grant.manage", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("role.preview", PermissionScope.PROJECT, PermissionRisk.LOW),
    _permission("billing.read", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("billing.manage", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("usage.export", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("audit.read", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("audit.export", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("security.policy.update", PermissionScope.TENANT, PermissionRisk.CRITICAL),
    _permission("run.create", PermissionScope.PROJECT, PermissionRisk.MEDIUM),
    _permission("run.read_metadata", PermissionScope.PROJECT, PermissionRisk.LOW),
    _permission(
        "run.read_content",
        PermissionScope.PROJECT,
        PermissionRisk.MEDIUM,
        reads_content=True,
    ),
    _permission("run.cancel", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("run.retry", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("runtime.binding.manage", PermissionScope.PROJECT, PermissionRisk.HIGH),
)

PERMISSION_CATALOG = MappingProxyType({definition.name: definition for definition in _DEFINITIONS})

TENANT_ROLE_PERMISSIONS = MappingProxyType(
    {
        "owner": frozenset(
            {
                "tenant.read",
                "tenant.update",
                "tenant.suspend",
                "tenant.delete",
                "tenant.ownership.transfer",
                "membership.invite",
                "membership.role.update",
                "membership.suspend",
                "membership.remove",
                "space.create",
                "project.create",
                "billing.read",
                "billing.manage",
                "usage.export",
                "audit.read",
                "audit.export",
                "security.policy.update",
                "project.read_metadata",
                "project.update",
            }
        ),
        "admin": frozenset(
            {
                "tenant.read",
                "tenant.update",
                "membership.invite",
                "membership.role.update",
                "membership.suspend",
                "membership.remove",
                "space.create",
                "project.create",
                "billing.read",
                "audit.read",
                "security.policy.update",
                "project.read_metadata",
                "project.update",
            }
        ),
        "billing_admin": frozenset(
            {"tenant.read", "billing.read", "billing.manage", "usage.export"}
        ),
        "security_auditor": frozenset(
            {"tenant.read", "audit.read", "audit.export", "project.read_metadata", "grant.read"}
        ),
        "operator": frozenset({"tenant.read", "run.read_metadata", "run.cancel", "run.retry"}),
        "member": frozenset({"tenant.read"}),
    }
)

SPACE_ROLE_PERMISSIONS = MappingProxyType(
    {
        "owner": frozenset(
            {
                "space.read",
                "space.update",
                "space.policy.update",
                "space.delete",
                "space.ownership.transfer",
                "project.create",
                "project.read_metadata",
                "project.update",
                "project.delete",
                "grant.read",
                "grant.manage",
                "role.preview",
            }
        ),
        "admin": frozenset(
            {
                "space.read",
                "space.update",
                "space.policy.update",
                "project.create",
                "project.read_metadata",
                "project.update",
                "grant.read",
                "grant.manage",
                "role.preview",
            }
        ),
        "operator": frozenset(
            {"space.read", "project.read_metadata", "run.read_metadata", "run.cancel", "run.retry"}
        ),
        "member": frozenset({"space.read"}),
        "viewer": frozenset({"space.read"}),
    }
)

PROJECT_ROLE_PERMISSIONS = MappingProxyType(
    {
        "owner": frozenset(
            {
                "project.read_metadata",
                "project.content.read",
                "project.content.edit",
                "project.update",
                "project.delete",
                "grant.read",
                "grant.manage",
                "role.preview",
                "run.create",
                "run.read_metadata",
                "run.read_content",
                "run.cancel",
                "run.retry",
                "runtime.binding.manage",
            }
        ),
        # Manage is deliberately content-blind. Product copy must not imply otherwise.
        "manage": frozenset(
            {
                "project.read_metadata",
                "project.update",
                "project.delete",
                "grant.read",
                "grant.manage",
                "role.preview",
                "runtime.binding.manage",
            }
        ),
        "operate": frozenset(
            {"project.read_metadata", "run.read_metadata", "run.cancel", "run.retry"}
        ),
        "edit": frozenset(
            {
                "project.read_metadata",
                "project.content.read",
                "project.content.edit",
                "run.create",
                "run.read_metadata",
                "run.read_content",
            }
        ),
        "read": frozenset(
            {
                "project.read_metadata",
                "project.content.read",
                "run.read_metadata",
                "run.read_content",
            }
        ),
    }
)

# Exact Resource Grants intentionally expose a strict subset of Project roles.
# A resource selector must never turn a Resource Grant into Project administration.
RESOURCE_ROLE_PERMISSIONS = MappingProxyType(
    {
        "conversation": MappingProxyType(
            {
                "owner": frozenset({"project.content.read", "project.content.edit"}),
                "manage": frozenset(),
                "operate": frozenset(),
                "edit": frozenset({"project.content.read", "project.content.edit"}),
                "read": frozenset({"project.content.read"}),
            }
        ),
        "run": MappingProxyType(
            {
                "owner": frozenset(
                    {"run.read_metadata", "run.read_content", "run.cancel", "run.retry"}
                ),
                "manage": frozenset(),
                "operate": frozenset({"run.read_metadata", "run.cancel", "run.retry"}),
                "edit": frozenset({"run.read_metadata", "run.read_content"}),
                "read": frozenset({"run.read_metadata", "run.read_content"}),
            }
        ),
    }
)


def permission_catalog_payload() -> dict[str, object]:
    """Return the versioned JSON-safe catalog exposed to admin clients."""

    return {
        "policy_version": POLICY_VERSION,
        "permissions": [
            {
                **asdict(definition),
                "scope": definition.scope.value,
                "risk": definition.risk.value,
            }
            for definition in _DEFINITIONS
        ],
        "roles": {
            "tenant": {role: sorted(values) for role, values in TENANT_ROLE_PERMISSIONS.items()},
            "space": {role: sorted(values) for role, values in SPACE_ROLE_PERMISSIONS.items()},
            "project": {role: sorted(values) for role, values in PROJECT_ROLE_PERMISSIONS.items()},
            "resource": {
                resource_type: {role: sorted(values) for role, values in role_map.items()}
                for resource_type, role_map in RESOURCE_ROLE_PERMISSIONS.items()
            },
        },
    }


def _validate_catalog() -> None:
    if len(PERMISSION_CATALOG) != len(_DEFINITIONS):
        raise RuntimeError("permission catalog contains duplicate names")
    known = frozenset(PERMISSION_CATALOG)
    for role_map in (TENANT_ROLE_PERMISSIONS, SPACE_ROLE_PERMISSIONS, PROJECT_ROLE_PERMISSIONS):
        for role, permissions in role_map.items():
            unknown = permissions - known
            if unknown:
                raise RuntimeError(
                    f"built-in role {role} references unknown permissions: {unknown}"
                )
    for resource_type, role_map in RESOURCE_ROLE_PERMISSIONS.items():
        if set(role_map) != set(PROJECT_ROLE_PERMISSIONS):
            raise RuntimeError(f"resource role coverage is incomplete for {resource_type}")
        for role, permissions in role_map.items():
            unknown = permissions - known
            widened = permissions - PROJECT_ROLE_PERMISSIONS[role]
            if unknown or widened:
                raise RuntimeError(
                    f"resource role {resource_type}/{role} is invalid: "
                    f"unknown={unknown}, widened={widened}"
                )
    content_actions = {name for name, item in PERMISSION_CATALOG.items() if item.reads_content}
    for role in ("owner", "admin"):
        if TENANT_ROLE_PERMISSIONS[role] & content_actions:
            raise RuntimeError("Tenant governance roles must not imply content access")
    for role in ("owner", "admin"):
        if SPACE_ROLE_PERMISSIONS[role] & content_actions:
            raise RuntimeError("Space governance roles must not imply content access")


_validate_catalog()
