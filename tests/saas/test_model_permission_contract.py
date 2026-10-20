from __future__ import annotations

import pytest

from saas.control_plane.permissions import (
    PERMISSION_CATALOG,
    PLATFORM_ROLE_PERMISSIONS,
    POLICY_VERSION,
    TENANT_ROLE_PERMISSIONS,
    PermissionRisk,
)
from tests.saas.test_model_connections import _fixture

_MODEL_ROUTES = {
    "platform.model_provider.read": (
        "GET /v2/platform-admin/model-provider",
        "GET /v2/platform-admin/model-connections",
        "GET /v2/platform-admin/model-connections/{connection_id}/credential-versions",
        "GET /v2/platform-admin/model-deployments",
        "GET /v2/platform-admin/model-deployments/current-generation",
        "GET /v2/platform-admin/model-operations",
        "GET /v2/platform-admin/model-operations/{operation_id}",
        "GET /v2/platform-admin/model-test-funding",
        "GET /v2/platform-admin/model-operations/{operation_id}/verification",
        "GET /v2/platform-admin/model-publications",
        "GET /v2/platform-admin/model-publications/current-generation",
        "GET /v2/platform-admin/model-operations/{operation_id}/publication",
        "GET /v2/platform-admin/model-publication-disablements",
        "GET /v2/platform-admin/model-publication-disablements/{disablement_id}",
        "GET /v2/platform-admin/model-publication-revocations",
        "GET /v2/platform-admin/model-publication-revocations/{revocation_id}",
    ),
    "platform.model_provider.manage": (
        "PUT /v2/platform-admin/model-provider",
        "POST /v2/platform-admin/model-connections",
        "POST /v2/platform-admin/model-connections/{connection_id}/credential-versions",
        "POST /v2/platform-admin/model-deployments",
        "PUT /v2/platform-admin/model-test-funding",
    ),
    "platform.model_provider.test": (
        "POST /v2/platform-admin/model-provider/test",
        "POST /v2/platform-admin/model-deployments/{deployment_id}/test",
    ),
    "platform.model_provider.publish": (
        "POST /v2/platform-admin/model-deployments/{deployment_id}/publish",
        "POST /v2/platform-admin/model-publications/{publication_id}/disable",
        "POST /v2/platform-admin/model-publication-disablements/{disablement_id}/revoke",
    ),
}


@pytest.mark.parametrize("enabled", (False, True))
def test_registered_model_routes_have_exact_permission_declarations(enabled):
    _, _, _, _, client, _ = _fixture(enabled=enabled)
    registered = {
        f"{method} {route.path}"
        for route in client.app.routes
        if getattr(route, "path", "").startswith("/v2/platform-admin/model-")
        for method in route.methods
    }
    expected = {surface: name for name, surfaces in _MODEL_ROUTES.items() for surface in surfaces}
    assert len(expected) == len(registered) == 26
    assert registered == set(expected)
    declared = {
        surface: {
            name for name, item in PERMISSION_CATALOG.items() if surface in item.api_surfaces
        }
        for surface in registered
    }
    assert declared == {surface: {name} for surface, name in expected.items()}
    for name, surfaces in _MODEL_ROUTES.items():
        assert set(PERMISSION_CATALOG[name].api_surfaces) == set(surfaces)


@pytest.mark.parametrize("resource", ("model-deployments", "model-publications"))
def test_current_generation_routes_require_staff_authentication(resource):
    _, _, _, _, client, _ = _fixture()
    client.cookies.clear()
    response = client.get(
        f"/v2/platform-admin/{resource}/current-generation",
        params={
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "public_model_id": "deepseek-flash",
            "wire_api": "openai_chat_completions",
        },
    )
    assert response.status_code == 401


def test_model_catalog_repair_preserves_risk_fresh_auth_and_role_boundaries():
    names = set(_MODEL_ROUTES)
    for name, risk in (
        ("platform.model_provider.read", PermissionRisk.MEDIUM),
        ("platform.model_provider.manage", PermissionRisk.CRITICAL),
        ("platform.model_provider.test", PermissionRisk.HIGH),
        ("platform.model_provider.publish", PermissionRisk.CRITICAL),
    ):
        item = PERMISSION_CATALOG[name]
        assert item.risk is risk and not item.reads_content
        assert not item.service_account_allowed and not item.approval_required
        assert item.fresh_auth_required is (name != "platform.model_provider.read")
    for role, granted in PLATFORM_ROLE_PERMISSIONS.items():
        expected = (
            names
            if role == "platform_operator"
            else {"platform.model_provider.read"}
            if role == "platform_security_auditor"
            else set()
        )
        assert granted & names == expected
    assert all(not (granted & names) for granted in TENANT_ROLE_PERMISSIONS.values())


def test_staff_permission_endpoint_exposes_complete_model_catalog_version():
    _, _, _, _, client, _ = _fixture()
    response = client.get("/v2/platform-admin/permissions")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["policy_version"] == POLICY_VERSION
    values = {item["name"]: item for item in payload["permissions"]}
    for name, surfaces in _MODEL_ROUTES.items():
        assert set(values[name]["api_surfaces"]) == set(surfaces)
        assert values[name]["ui_surface"] and values[name]["audit_event"]
