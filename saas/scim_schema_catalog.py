"""Immutable RFC 7643 discovery catalog for the public SCIM surface."""

from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import Literal, cast

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_GOVERNANCE_USER_SCHEMA = "urn:omnigent:params:scim:schemas:extension:governance:1.0:User"
SCIM_GOVERNANCE_GROUP_SCHEMA = "urn:omnigent:params:scim:schemas:extension:governance:1.0:Group"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_BULK_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
SCIM_BULK_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

_Mutability = Literal["readOnly", "readWrite", "immutable", "writeOnly"]
_Returned = Literal["always", "never", "default", "request"]
_Uniqueness = Literal["none", "server", "global"]


def _attribute(
    name: str,
    kind: str,
    *,
    multi_valued: bool = False,
    required: bool = False,
    case_exact: bool = False,
    mutability: _Mutability = "readWrite",
    returned: _Returned = "default",
    uniqueness: _Uniqueness = "none",
    canonical_values: tuple[str, ...] = (),
    reference_types: tuple[str, ...] = (),
    sub_attributes: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    value: dict[str, object] = {
        "name": name,
        "type": kind,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": returned,
        "uniqueness": uniqueness,
    }
    if canonical_values:
        value["canonicalValues"] = list(canonical_values)
    if reference_types:
        value["referenceTypes"] = list(reference_types)
    if sub_attributes:
        value["subAttributes"] = list(sub_attributes)
    return value


_TYPE_PRIMARY = (
    _attribute("value", "string"),
    _attribute("display", "string"),
    _attribute("type", "string"),
    _attribute("primary", "boolean"),
)
_NAME = (
    _attribute("formatted", "string"),
    _attribute("familyName", "string"),
    _attribute("givenName", "string"),
    _attribute("middleName", "string"),
    _attribute("honorificPrefix", "string"),
    _attribute("honorificSuffix", "string"),
)
_ADDRESS = (
    _attribute("formatted", "string"),
    _attribute("streetAddress", "string"),
    _attribute("locality", "string"),
    _attribute("region", "string"),
    _attribute("postalCode", "string"),
    _attribute("country", "string"),
    _attribute("type", "string"),
    _attribute("primary", "boolean"),
)
_MANAGER = (
    _attribute("value", "string"),
    _attribute(
        "$ref",
        "reference",
        case_exact=True,
        reference_types=("User",),
    ),
    _attribute("displayName", "string", mutability="readOnly"),
)

_SCHEMAS = MappingProxyType(
    {
        SCIM_USER_SCHEMA: {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_USER_SCHEMA,
            "name": "User",
            "description": "SCIM core User resource",
            "attributes": [
                _attribute(
                    "userName",
                    "string",
                    required=True,
                    uniqueness="server",
                ),
                _attribute("name", "complex", sub_attributes=_NAME),
                _attribute("displayName", "string"),
                _attribute("title", "string"),
                _attribute("userType", "string"),
                _attribute("preferredLanguage", "string"),
                _attribute("locale", "string"),
                _attribute("timezone", "string"),
                _attribute("active", "boolean"),
                _attribute(
                    "emails",
                    "complex",
                    multi_valued=True,
                    sub_attributes=_TYPE_PRIMARY,
                ),
                _attribute(
                    "phoneNumbers",
                    "complex",
                    multi_valued=True,
                    sub_attributes=_TYPE_PRIMARY,
                ),
                _attribute(
                    "addresses",
                    "complex",
                    multi_valued=True,
                    sub_attributes=_ADDRESS,
                ),
            ],
        },
        SCIM_GROUP_SCHEMA: {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "SCIM core Group resource",
            "attributes": [
                _attribute("displayName", "string", required=True),
                _attribute(
                    "members",
                    "complex",
                    multi_valued=True,
                    sub_attributes=(
                        _attribute("value", "string", mutability="immutable"),
                        _attribute(
                            "$ref",
                            "reference",
                            case_exact=True,
                            mutability="immutable",
                            reference_types=("User",),
                        ),
                        _attribute("display", "string", mutability="readOnly"),
                        _attribute("type", "string", mutability="immutable"),
                    ),
                ),
            ],
        },
        SCIM_ENTERPRISE_USER_SCHEMA: {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_ENTERPRISE_USER_SCHEMA,
            "name": "EnterpriseUser",
            "description": "RFC 7643 enterprise User extension",
            "attributes": [
                _attribute("employeeNumber", "string"),
                _attribute("costCenter", "string"),
                _attribute("organization", "string"),
                _attribute("division", "string"),
                _attribute("department", "string"),
                _attribute("manager", "complex", sub_attributes=_MANAGER),
            ],
        },
        SCIM_GOVERNANCE_USER_SCHEMA: {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_GOVERNANCE_USER_SCHEMA,
            "name": "OmnigentGovernanceUser",
            "description": "Content-blind Omnigent User governance projection",
            "attributes": [
                _attribute("disposition", "string", mutability="readOnly"),
                _attribute("requiresOwnerRecovery", "boolean", mutability="readOnly"),
            ],
        },
        SCIM_GOVERNANCE_GROUP_SCHEMA: {
            "schemas": [SCIM_SCHEMA_SCHEMA],
            "id": SCIM_GOVERNANCE_GROUP_SCHEMA,
            "name": "OmnigentGovernanceGroup",
            "description": "Content-blind Omnigent Group governance projection",
            "attributes": [
                _attribute("active", "boolean", mutability="readOnly"),
                _attribute("disposition", "string", mutability="readOnly"),
                _attribute(
                    "blockedExternalIds",
                    "string",
                    multi_valued=True,
                    mutability="readOnly",
                ),
            ],
        },
    }
)

_RESOURCE_TYPES = MappingProxyType(
    {
        "User": {
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "Tenant Directory User",
            "schema": SCIM_USER_SCHEMA,
            "schemaExtensions": [
                {"schema": SCIM_ENTERPRISE_USER_SCHEMA, "required": False},
                {"schema": SCIM_GOVERNANCE_USER_SCHEMA, "required": False},
            ],
        },
        "Group": {
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Tenant Directory Group",
            "schema": SCIM_GROUP_SCHEMA,
            "schemaExtensions": [{"schema": SCIM_GOVERNANCE_GROUP_SCHEMA, "required": False}],
        },
    }
)

IDP_PROVIDER_TYPES = frozenset({"generic", "microsoft_entra", "okta", "google_workspace"})
SUPPORTED_IDP_ATTRIBUTE_PATHS = frozenset(
    {
        "userName",
        "displayName",
        "active",
        "name.formatted",
        "name.familyName",
        "name.givenName",
        "name.middleName",
        "title",
        "userType",
        "preferredLanguage",
        "locale",
        "timezone",
        "emails",
        "phoneNumbers",
        "addresses",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:employeeNumber",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:costCenter",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:organization",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:division",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:department",
        f"{SCIM_ENTERPRISE_USER_SCHEMA}:manager.value",
    }
)
_IDP_PROFILES = MappingProxyType(
    {
        "generic": {
            "displayName": "Generic SCIM 2.0",
            "documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
            "defaultMappings": {},
        },
        "microsoft_entra": {
            "displayName": "Microsoft Entra ID",
            "documentationUri": "https://learn.microsoft.com/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups",
            "defaultMappings": {
                "userPrincipalName": "userName",
                "displayName": "displayName",
                "givenName": "name.givenName",
                "surname": "name.familyName",
                "mail": "emails",
                "employeeId": f"{SCIM_ENTERPRISE_USER_SCHEMA}:employeeNumber",
                "department": f"{SCIM_ENTERPRISE_USER_SCHEMA}:department",
            },
        },
        "okta": {
            "displayName": "Okta",
            "documentationUri": "https://developer.okta.com/docs/reference/scim/scim-20/",
            "defaultMappings": {
                "userName": "userName",
                "displayName": "displayName",
                "givenName": "name.givenName",
                "familyName": "name.familyName",
                "email": "emails",
                "employeeNumber": f"{SCIM_ENTERPRISE_USER_SCHEMA}:employeeNumber",
                "department": f"{SCIM_ENTERPRISE_USER_SCHEMA}:department",
            },
        },
        "google_workspace": {
            "displayName": "Google Workspace",
            "documentationUri": "https://support.google.com/a/answer/10040025",
            "defaultMappings": {
                "primaryEmail": "userName",
                "name.fullName": "displayName",
                "name.givenName": "name.givenName",
                "name.familyName": "name.familyName",
                "organizations.department": f"{SCIM_ENTERPRISE_USER_SCHEMA}:department",
                "organizations.title": "title",
            },
        },
    }
)


def schema_resources() -> tuple[dict[str, object], ...]:
    return tuple(cast(dict[str, object], deepcopy(value)) for value in _SCHEMAS.values())


def schema_resource(schema_id: str) -> dict[str, object] | None:
    value = _SCHEMAS.get(schema_id)
    return cast(dict[str, object], deepcopy(value)) if value is not None else None


def resource_type_resources() -> tuple[dict[str, object], ...]:
    return tuple(cast(dict[str, object], deepcopy(value)) for value in _RESOURCE_TYPES.values())


def resource_type_resource(resource_id: str) -> dict[str, object] | None:
    canonical = next(
        (key for key in _RESOURCE_TYPES if key.casefold() == resource_id.casefold()),
        None,
    )
    return (
        cast(dict[str, object], deepcopy(_RESOURCE_TYPES[canonical]))
        if canonical is not None
        else None
    )


def idp_configuration_profile(
    provider_type: str,
    overrides: dict[str, str] | None = None,
) -> dict[str, object] | None:
    value = _IDP_PROFILES.get(provider_type)
    if value is None:
        return None
    result = cast(dict[str, object], deepcopy(value))
    raw_mappings = result["defaultMappings"]
    if not isinstance(raw_mappings, dict):  # pragma: no cover - immutable catalog contract
        raise TypeError("IdP profile mappings are invalid")
    mappings = cast(dict[str, str], raw_mappings).copy()
    mappings.update(overrides or {})
    result["providerType"] = provider_type
    result["attributeMappings"] = mappings
    return result


__all__ = [
    "IDP_PROVIDER_TYPES",
    "SCIM_BULK_REQUEST_SCHEMA",
    "SCIM_BULK_RESPONSE_SCHEMA",
    "SCIM_CONFIG_SCHEMA",
    "SCIM_ENTERPRISE_USER_SCHEMA",
    "SCIM_ERROR_SCHEMA",
    "SCIM_GOVERNANCE_GROUP_SCHEMA",
    "SCIM_GOVERNANCE_USER_SCHEMA",
    "SCIM_GROUP_SCHEMA",
    "SCIM_LIST_SCHEMA",
    "SCIM_PATCH_SCHEMA",
    "SCIM_RESOURCE_TYPE_SCHEMA",
    "SCIM_SCHEMA_SCHEMA",
    "SCIM_USER_SCHEMA",
    "SUPPORTED_IDP_ATTRIBUTE_PATHS",
    "idp_configuration_profile",
    "resource_type_resource",
    "resource_type_resources",
    "schema_resource",
    "schema_resources",
]
