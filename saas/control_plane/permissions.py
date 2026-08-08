"""Versioned, machine-readable permission catalog and immutable built-in roles."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

POLICY_VERSION: Final = "2026-08-08.pc5-scim-foundation"


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
    api_surfaces: tuple[str, ...] = ()
    ui_surface: str | None = None
    audit_event: str | None = None


def _permission(
    name: str,
    scope: PermissionScope,
    risk: PermissionRisk,
    *,
    reads_content: bool = False,
    service_account_allowed: bool = False,
    fresh_auth_required: bool = False,
    approval_required: bool = False,
    api_surfaces: tuple[str, ...] = (),
    ui_surface: str | None = None,
    audit_event: str | None = None,
) -> PermissionDefinition:
    return PermissionDefinition(
        name=name,
        scope=scope,
        risk=risk,
        reads_content=reads_content,
        service_account_allowed=service_account_allowed,
        fresh_auth_required=fresh_auth_required,
        approval_required=approval_required,
        api_surfaces=api_surfaces,
        ui_surface=ui_surface,
        audit_event=audit_event,
    )


_DEFINITIONS = (
    _permission(
        "platform.context.read",
        PermissionScope.PLATFORM,
        PermissionRisk.LOW,
        api_surfaces=("GET /v2/platform-admin/context",),
        ui_surface="platform-shell",
        audit_event="platform.context.read",
    ),
    _permission(
        "platform.permission.read",
        PermissionScope.PLATFORM,
        PermissionRisk.LOW,
        api_surfaces=("GET /v2/platform-admin/permissions",),
        ui_surface="access-control",
        audit_event="platform.permission_catalog.read",
    ),
    _permission(
        "platform.staff.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=("GET /v2/platform-admin/staff",),
        ui_surface="identity-security",
        audit_event="platform.staff.read",
    ),
    _permission(
        "platform.role.read",
        PermissionScope.PLATFORM,
        PermissionRisk.LOW,
        api_surfaces=("GET /v2/platform-admin/role-assignments",),
        ui_surface="access-control",
        audit_event="platform.role_assignment.read",
    ),
    _permission(
        "platform.role.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=(
            "POST /v2/platform-admin/role-assignments",
            "DELETE /v2/platform-admin/role-assignments/{id}",
        ),
        ui_surface="access-control",
        audit_event="platform.role_assignment.changed",
    ),
    _permission(
        "platform.tenant.read",
        PermissionScope.PLATFORM,
        PermissionRisk.LOW,
        api_surfaces=(
            "GET /v2/platform-admin/tenants",
            "GET /v2/platform-admin/tenants/{id}/lifecycle-preview",
        ),
        ui_surface="tenants",
        audit_event="platform.tenant_projection.read",
    ),
    _permission(
        "platform.tenant.lifecycle.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=(
            "POST /v2/platform-admin/tenants/{id}/suspend",
            "POST /v2/platform-admin/tenants/{id}/restore",
        ),
        ui_surface="tenants",
        audit_event="platform.tenant_lifecycle.requested",
    ),
    _permission(
        "platform.tenant.owner_recover",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=(
            "GET /v2/platform-admin/tenants/{id}/owner-recovery-preview",
            "POST /v2/platform-admin/tenants/{id}/owner-recovery",
        ),
        ui_surface="tenants",
        audit_event="platform.tenant_owner_recovery.requested",
    ),
    _permission(
        "platform.user.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=(
            "GET /v2/platform-admin/users",
            "GET /v2/platform-admin/users/{id}/lifecycle-preview",
        ),
        ui_surface="global-users",
        audit_event="platform.user_projection.read",
    ),
    _permission(
        "platform.user.pii.read",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        fresh_auth_required=True,
        api_surfaces=("GET /v2/platform-admin/users/{id}/pii",),
        ui_surface="global-users",
        audit_event="platform.user_pii.read",
    ),
    _permission(
        "platform.user.suspend",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/users/{id}/suspend",),
        ui_surface="global-users",
        audit_event="platform.user.suspension.requested",
    ),
    _permission(
        "platform.user.restore",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/users/{id}/restore",),
        ui_surface="global-users",
        audit_event="platform.user.restore.requested",
    ),
    _permission(
        "platform.user.sessions.revoke",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        fresh_auth_required=True,
        api_surfaces=("POST /v2/platform-admin/users/{id}/revoke-sessions",),
        ui_surface="global-users",
        audit_event="platform.user_sessions.revoked",
    ),
    _permission(
        "platform.identity_conflict.read",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        api_surfaces=("GET /v2/platform-admin/identity-conflicts",),
        ui_surface="identity-security",
        audit_event="platform.identity_conflict.read",
    ),
    _permission(
        "platform.identity_conflict.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=(
            "POST /v2/platform-admin/identity-conflicts/{id}/assign",
            "POST /v2/platform-admin/identity-conflicts/{id}/block",
        ),
        ui_surface="identity-security",
        audit_event="platform.identity_conflict.reviewed",
    ),
    _permission(
        "platform.support.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=("GET /v2/platform-admin/support-access-grants",),
        ui_surface="support-access",
        audit_event="platform.support_access.read",
    ),
    _permission(
        "platform.support.request",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        fresh_auth_required=True,
        api_surfaces=("POST /v2/platform-admin/support-access-grants",),
        ui_surface="support-access",
        audit_event="platform.support_access.requested",
    ),
    _permission(
        "platform.break_glass.request",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/support-access-grants",),
        ui_surface="support-access",
        audit_event="platform.break_glass.requested",
    ),
    _permission(
        "platform.support_grant.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=(
            "POST /v2/platform-admin/support-access-grants/{id}/approve",
            "POST /v2/platform-admin/support-access-grants/{id}/revoke",
        ),
        ui_surface="support-access",
        audit_event="platform.support_access.decided",
    ),
    _permission(
        "platform.operations.read",
        PermissionScope.PLATFORM,
        PermissionRisk.LOW,
        api_surfaces=("GET /v2/platform-admin/operations",),
        ui_surface="operations",
        audit_event="platform.operations.read",
    ),
    _permission(
        "platform.operation.approve",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/operations/{id}/approve",),
        ui_surface="operations",
        audit_event="platform.operation.approved",
    ),
    _permission(
        "platform.runner.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/runners/{id}/transition",),
        ui_surface="operations",
        audit_event="platform.runner_transition.requested",
    ),
    _permission(
        "platform.billing.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=("GET /v2/platform-admin/billing",),
        ui_surface="billing-finance",
        audit_event="platform.billing_projection.read",
    ),
    _permission(
        "platform.billing.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/subscriptions/{id}/transition",),
        ui_surface="billing-finance",
        audit_event="platform.billing_transition.requested",
    ),
    _permission(
        "platform.security.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=("GET /v2/platform-admin/security",),
        ui_surface="identity-security",
        audit_event="platform.security_projection.read",
    ),
    _permission(
        "platform.audit.read",
        PermissionScope.PLATFORM,
        PermissionRisk.MEDIUM,
        api_surfaces=("GET /v2/platform-admin/audit-events",),
        ui_surface="audit-compliance",
        audit_event="platform.audit.read",
    ),
    _permission(
        "platform.audit.export",
        PermissionScope.PLATFORM,
        PermissionRisk.HIGH,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/audit-exports",),
        ui_surface="audit-compliance",
        audit_event="platform.audit_export.requested",
    ),
    _permission(
        "platform.data_request.manage",
        PermissionScope.PLATFORM,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
        approval_required=True,
        api_surfaces=("POST /v2/platform-admin/data-requests",),
        ui_surface="data-lifecycle",
        audit_event="platform.data_request.changed",
    ),
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
    _permission("membership.read", PermissionScope.TENANT, PermissionRisk.LOW),
    _permission("membership.role.update", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("membership.suspend", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("membership.remove", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("group.read", PermissionScope.TENANT, PermissionRisk.LOW),
    _permission("group.manage", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("enterprise_identity.read", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission(
        "enterprise_identity.manage",
        PermissionScope.TENANT,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
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
    _permission(
        "project.read_metadata",
        PermissionScope.PROJECT,
        PermissionRisk.LOW,
        service_account_allowed=True,
    ),
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
    _permission("custom_role.read", PermissionScope.PROJECT, PermissionRisk.MEDIUM),
    _permission("custom_role.manage", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("billing.read", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("billing.manage", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("usage.export", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("audit.read", PermissionScope.TENANT, PermissionRisk.MEDIUM),
    _permission("audit.export", PermissionScope.TENANT, PermissionRisk.HIGH),
    _permission("security.policy.update", PermissionScope.TENANT, PermissionRisk.CRITICAL),
    _permission(
        "run.create",
        PermissionScope.PROJECT,
        PermissionRisk.MEDIUM,
        service_account_allowed=True,
    ),
    _permission(
        "run.read_metadata",
        PermissionScope.PROJECT,
        PermissionRisk.LOW,
        service_account_allowed=True,
    ),
    _permission(
        "run.read_content",
        PermissionScope.PROJECT,
        PermissionRisk.MEDIUM,
        reads_content=True,
        service_account_allowed=True,
    ),
    _permission(
        "run.cancel",
        PermissionScope.PROJECT,
        PermissionRisk.HIGH,
        service_account_allowed=True,
    ),
    _permission(
        "run.retry",
        PermissionScope.PROJECT,
        PermissionRisk.HIGH,
        service_account_allowed=True,
    ),
    _permission("runtime.binding.manage", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("environment.manage", PermissionScope.PROJECT, PermissionRisk.HIGH),
    _permission("egress.policy.manage", PermissionScope.PROJECT, PermissionRisk.CRITICAL),
    _permission(
        "secret.manage",
        PermissionScope.PROJECT,
        PermissionRisk.CRITICAL,
        fresh_auth_required=True,
    ),
    _permission(
        "preview.open",
        PermissionScope.PROJECT,
        PermissionRisk.MEDIUM,
        reads_content=True,
        service_account_allowed=True,
    ),
)

PERMISSION_CATALOG = MappingProxyType({definition.name: definition for definition in _DEFINITIONS})

PLATFORM_ROLE_PERMISSIONS = MappingProxyType(
    {
        "platform_operator": frozenset(
            {
                "platform.context.read",
                "platform.permission.read",
                "platform.staff.read",
                "platform.role.read",
                "platform.role.manage",
                "platform.tenant.read",
                "platform.tenant.lifecycle.manage",
                "platform.tenant.owner_recover",
                "platform.user.read",
                "platform.user.suspend",
                "platform.user.restore",
                "platform.user.sessions.revoke",
                "platform.identity_conflict.read",
                "platform.identity_conflict.manage",
                "platform.operations.read",
                "platform.operation.approve",
                "platform.runner.manage",
                "platform.billing.read",
                "platform.support.read",
                "platform.support_grant.manage",
            }
        ),
        "platform_security_auditor": frozenset(
            {
                "platform.context.read",
                "platform.permission.read",
                "platform.staff.read",
                "platform.role.read",
                "platform.tenant.read",
                "platform.user.read",
                "platform.identity_conflict.read",
                "platform.support.read",
                "platform.operations.read",
                "platform.security.read",
                "platform.audit.read",
                "platform.audit.export",
            }
        ),
        "support_agent": frozenset(
            {
                "platform.context.read",
                "platform.permission.read",
                "platform.tenant.read",
                "platform.user.read",
                "platform.support.read",
                "platform.support.request",
                "platform.break_glass.request",
                "platform.operations.read",
            }
        ),
        "billing_operator": frozenset(
            {
                "platform.context.read",
                "platform.permission.read",
                "platform.tenant.read",
                "platform.billing.read",
                "platform.billing.manage",
            }
        ),
        "compliance_operator": frozenset(
            {
                "platform.context.read",
                "platform.permission.read",
                "platform.tenant.read",
                "platform.user.read",
                "platform.user.pii.read",
                "platform.operations.read",
                "platform.audit.read",
                "platform.audit.export",
                "platform.data_request.manage",
            }
        ),
    }
)

PLATFORM_FIELD_PERMISSIONS = MappingProxyType(
    {
        "tenant": MappingProxyType(
            {
                "tenant_id": "platform.tenant.read",
                "slug": "platform.tenant.read",
                "name": "platform.tenant.read",
                "status": "platform.tenant.read",
                "plan": "platform.tenant.read",
                "home_region": "platform.tenant.read",
                "member_count": "platform.tenant.read",
                "space_count": "platform.tenant.read",
                "updated_at": "platform.tenant.read",
            }
        ),
        "user": MappingProxyType(
            {
                "user_id": "platform.user.read",
                "status": "platform.user.read",
                "display_name": "platform.user.read",
                "email_masked": "platform.user.read",
                "primary_email": "platform.user.pii.read",
                "membership_count": "platform.user.read",
                "security_version": "platform.security.read",
                "created_at": "platform.user.read",
                "updated_at": "platform.user.read",
            }
        ),
    }
)

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
                "membership.read",
                "membership.role.update",
                "membership.suspend",
                "membership.remove",
                "group.read",
                "group.manage",
                "enterprise_identity.read",
                "enterprise_identity.manage",
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
                "membership.read",
                "membership.role.update",
                "membership.suspend",
                "membership.remove",
                "group.read",
                "group.manage",
                "enterprise_identity.read",
                "enterprise_identity.manage",
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
            {
                "tenant.read",
                "membership.read",
                "group.read",
                "enterprise_identity.read",
                "audit.read",
                "audit.export",
                "project.read_metadata",
                "grant.read",
            }
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
                "custom_role.read",
                "custom_role.manage",
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
                "custom_role.read",
                "custom_role.manage",
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
                "custom_role.read",
                "custom_role.manage",
                "run.create",
                "run.read_metadata",
                "run.read_content",
                "run.cancel",
                "run.retry",
                "runtime.binding.manage",
                "environment.manage",
                "egress.policy.manage",
                "secret.manage",
                "preview.open",
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
                "custom_role.read",
                "custom_role.manage",
                "runtime.binding.manage",
                "environment.manage",
                "egress.policy.manage",
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
                "preview.open",
            }
        ),
        "read": frozenset(
            {
                "project.read_metadata",
                "project.content.read",
                "run.read_metadata",
                "run.read_content",
                "preview.open",
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
            "platform": {
                role: sorted(values) for role, values in PLATFORM_ROLE_PERMISSIONS.items()
            },
            "tenant": {role: sorted(values) for role, values in TENANT_ROLE_PERMISSIONS.items()},
            "space": {role: sorted(values) for role, values in SPACE_ROLE_PERMISSIONS.items()},
            "project": {role: sorted(values) for role, values in PROJECT_ROLE_PERMISSIONS.items()},
            "resource": {
                resource_type: {role: sorted(values) for role, values in role_map.items()}
                for resource_type, role_map in RESOURCE_ROLE_PERMISSIONS.items()
            },
        },
        "field_permissions": {
            projection: dict(fields) for projection, fields in PLATFORM_FIELD_PERMISSIONS.items()
        },
    }


def _validate_catalog() -> None:
    if len(PERMISSION_CATALOG) != len(_DEFINITIONS):
        raise RuntimeError("permission catalog contains duplicate names")
    known = frozenset(PERMISSION_CATALOG)
    for role_map in (
        PLATFORM_ROLE_PERMISSIONS,
        TENANT_ROLE_PERMISSIONS,
        SPACE_ROLE_PERMISSIONS,
        PROJECT_ROLE_PERMISSIONS,
    ):
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
    for role, permissions in PLATFORM_ROLE_PERMISSIONS.items():
        if permissions & content_actions:
            raise RuntimeError(f"Platform role {role} must remain content-blind")
    for name, definition in PERMISSION_CATALOG.items():
        if name.startswith("platform.") and (
            definition.scope is not PermissionScope.PLATFORM
            or not definition.api_surfaces
            or not definition.ui_surface
            or not definition.audit_event
            or definition.service_account_allowed
        ):
            raise RuntimeError(f"Platform permission {name} has an incomplete contract")
        if "allow_all" in name:
            raise RuntimeError("permission catalog must not contain allow_all")
    for role in ("owner", "admin"):
        if TENANT_ROLE_PERMISSIONS[role] & content_actions:
            raise RuntimeError("Tenant governance roles must not imply content access")
    for role in ("owner", "admin"):
        if SPACE_ROLE_PERMISSIONS[role] & content_actions:
            raise RuntimeError("Space governance roles must not imply content access")


_validate_catalog()
