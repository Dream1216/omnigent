from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from saas.control_plane import BILLING_ADMIN_ROUTE_PERMISSIONS
from tests.saas.test_http_cookie_auth import _build_fastapi_app


def _login(client: TestClient, *, email: str, password: str) -> str:
    response = client.post(
        "/saas/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _write_headers(csrf: str, idempotency_key: str) -> dict[str, str]:
    return {
        "Origin": "http://testserver",
        "X-CSRF-Token": csrf,
        "Idempotency-Key": idempotency_key,
    }


def test_billing_admin_http_is_cookie_bound_content_blind_and_least_privileged() -> None:
    app, scope = _build_fastapi_app()
    tenant_base = f"/saas/tenants/{scope['tenant_id']}/billing"

    anonymous = TestClient(app)
    unauthenticated = anonymous.get(tenant_base)
    assert unauthenticated.status_code == 401

    owner = TestClient(app)
    owner_csrf = _login(
        owner,
        email="http@example.com",
        password="initial-http-password",
    )
    catalog = owner.get("/saas/admin/permissions").json()
    catalog_names = {item["name"] for item in catalog["permissions"]}
    assert set(BILLING_ADMIN_ROUTE_PERMISSIONS.values()) <= catalog_names

    empty = owner.get(tenant_base)
    assert empty.status_code == 200
    assert empty.headers["cache-control"] == "private, no-store"
    assert empty.json() == {
        "subscription": None,
        "balance": None,
        "entitlements": [],
        "latest_reconciliation": None,
    }

    subscription_body = {
        "plan_key": "team-v1",
        "status": "active",
        "current_period_start": "2026-08-01T00:00:00Z",
        "current_period_end": "2026-09-01T00:00:00Z",
    }
    missing_csrf = owner.put(
        f"{tenant_base}/subscription",
        json=subscription_body,
        headers={"Origin": "http://testserver", "Idempotency-Key": "http-billing-missing-csrf"},
    )
    assert missing_csrf.status_code == 401
    hostile_origin = owner.put(
        f"{tenant_base}/subscription",
        json=subscription_body,
        headers={
            "Origin": "https://attacker.example",
            "X-CSRF-Token": owner_csrf,
            "Idempotency-Key": "http-billing-hostile-origin",
        },
    )
    assert hostile_origin.status_code == 403

    subscription = owner.put(
        f"{tenant_base}/subscription",
        json=subscription_body,
        headers=_write_headers(owner_csrf, "http-billing-subscription"),
    )
    assert subscription.status_code == 200
    assert subscription.json()["plan_key"] == "team-v1"
    assert subscription.json()["version"] == 1
    replay = owner.put(
        f"{tenant_base}/subscription",
        json=subscription_body,
        headers=_write_headers(owner_csrf, "http-billing-subscription"),
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True

    pricing = owner.post(
        f"{tenant_base}/pricing-snapshots",
        json={
            "plan_key": "team-v1",
            "currency": "USD",
            "rates": {
                "llm.input_tokens": {
                    "unit": "tokens",
                    "unit_size": "1000",
                    "minor_per_unit": 25,
                }
            },
            "effective_from": "2026-08-01T00:00:00Z",
        },
        headers=_write_headers(owner_csrf, "http-billing-pricing"),
    )
    assert pricing.status_code == 201
    assert pricing.json()["currency"] == "USD"

    entitlement = owner.put(
        f"{tenant_base}/entitlements",
        json={
            "scope_type": "tenant",
            "meter": "llm.input_tokens",
            "unit": "tokens",
            "limit_quantity": "100000",
            "concurrency_limit": 2,
            "period": "month",
            "period_start": "2026-08-01T00:00:00Z",
            "period_end": "2026-09-01T00:00:00Z",
        },
        headers=_write_headers(owner_csrf, "http-billing-entitlement"),
    )
    assert entitlement.status_code == 200
    assert entitlement.json()["limit_quantity"] == "100000"

    configured = owner.get(tenant_base)
    assert configured.status_code == 200
    assert configured.json()["subscription"]["plan_key"] == "team-v1"
    assert configured.json()["entitlements"][0]["meter"] == "llm.input_tokens"
    serialized = configured.text.lower()
    for forbidden_field in (
        "prompt",
        "response_body",
        "access_token",
        "refresh_token",
        "password_hash",
    ):
        assert forbidden_field not in serialized

    tenant_admin = TestClient(app)
    tenant_admin_csrf = _login(
        tenant_admin,
        email="member@example.com",
        password="initial-member-password",
    )
    admin_read = tenant_admin.get(tenant_base)
    assert admin_read.status_code == 200
    admin_write = tenant_admin.put(
        f"{tenant_base}/subscription",
        json={**subscription_body, "expected_version": 1},
        headers=_write_headers(tenant_admin_csrf, "http-billing-admin-write"),
    )
    assert admin_write.status_code == 403
    assert admin_write.json()["detail"]["code"] == "billing_forbidden"

    ordinary_member = TestClient(app)
    _login(
        ordinary_member,
        email="viewer@example.com",
        password="initial-viewer-password",
    )
    denied = ordinary_member.get(tenant_base)
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "billing_forbidden"
    assert "team-v1" not in denied.text

    cross_tenant = owner.get(f"/saas/tenants/{uuid4()}/billing")
    assert cross_tenant.status_code == 403
    assert "team-v1" not in cross_tenant.text


def test_billing_admin_http_does_not_expose_financial_or_metering_ingestion() -> None:
    app, scope = _build_fastapi_app()
    client = TestClient(app)
    csrf = _login(
        client,
        email="http@example.com",
        password="initial-http-password",
    )
    tenant_base = f"/saas/tenants/{scope['tenant_id']}/billing"
    headers = _write_headers(csrf, "http-billing-prohibited-surface")

    for path in (
        f"{tenant_base}/credits",
        f"{tenant_base}/reservations",
        f"{tenant_base}/usage-events",
        f"{tenant_base}/provider-costs",
        f"{tenant_base}/refunds",
    ):
        response = client.post(path, json={}, headers=headers)
        assert response.status_code in {404, 405}
