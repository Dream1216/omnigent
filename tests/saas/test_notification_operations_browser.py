from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from playwright.sync_api import Browser, BrowserContext, Page, expect, sync_playwright

from saas.control_plane.http_auth import SaasPrincipal
from saas.control_plane.lifecycle import LifecycleError, ValidatedAuthSession
from saas.control_plane.notification_http import (
    TenantNotificationHttpConfig,
    create_notification_router,
)
from saas.control_plane.platform_http import PlatformHttpConfig
from saas.control_plane.platform_notification_http import create_platform_notification_router
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)
from tests.saas.test_notification_operations_http import (
    NOW,
    STAFF_ACTOR,
    TENANT_ACTOR,
    TENANT_ID,
    _Approvals,
    _Notifications,
)


class _BrowserTenantAuth:
    def extract_token(self, request: Any) -> tuple[str | None, str | None]:
        cookie = request.cookies.get("__Host-omnigent_saas_session")
        bearer = request.headers.get("authorization", "")
        if cookie and bearer:
            return bearer, "ambiguous"
        if cookie:
            return cookie, "cookie"
        if bearer.startswith("Bearer "):
            return bearer[7:], "bearer"
        return None, None

    def validate_csrf(self, token: str, csrf_token: str) -> None:
        if token != "tenant-session" or csrf_token != "tenant-csrf":
            raise LifecycleError("csrf_invalid", "invalid")

    def get_principal(self, request: Any) -> SaasPrincipal | None:
        token, source = self.extract_token(request)
        if token != "tenant-session" or source != "cookie":
            return None
        return SaasPrincipal(
            session=ValidatedAuthSession(
                session_id=TENANT_ACTOR,
                user_id=TENANT_ACTOR,
                security_version=7,
                authn_method="password",
                authenticated_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=1),
            ),
            runtime_context=None,
        )


class _BrowserStaffSessions:
    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.audience = "omnigent-platform"

    def validate_session(
        self,
        token: str,
        *,
        origin: str,
        audience: str,
        now: datetime | None = None,
    ) -> ValidatedPlatformPrincipal:
        if token != "staff-session" or origin != self.origin or audience != self.audience:
            raise PlatformSecurityError("platform_session_invalid", "invalid")
        return ValidatedPlatformPrincipal(
            session_id=STAFF_ACTOR,
            principal_id=STAFF_ACTOR,
            security_version=11,
            authn_method="webauthn",
            authenticated_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(hours=1),
            roles=frozenset({"platform_operator"}),
            permissions=frozenset(
                {
                    "platform.operation.approve",
                    "platform.notification.read",
                    "platform.notification.replay",
                    "platform.notification_template.manage",
                }
            ),
        )

    def validate_csrf(self, token: str, csrf_token: str) -> None:
        if token != "staff-session" or csrf_token != "staff-csrf":
            raise PlatformSecurityError("platform_csrf_invalid", "invalid")


def _write_certificate(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / "notification-operations-browser.crt"
    key_path = directory / "notification-operations-browser.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


@pytest.fixture
def notification_operations_server(tmp_path: Path) -> Iterator[str]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    origin = f"https://127.0.0.1:{port}"
    approvals = _Approvals()
    notifications = _Notifications()
    notifications.delivery.status = "dead_letter"
    notifications.delivery.channel = "email"
    notifications.delivery.last_error_code = "provider_unavailable"
    notifications.delivery.raw_body = "secret-message-body"
    notifications.delivery.recipient_address = "secret-recipient@example.test"
    notifications.delivery.raw_error = "secret-provider-stack"

    app = FastAPI()
    app.include_router(
        create_notification_router(
            config=TenantNotificationHttpConfig(origin=origin),
            auth_provider=_BrowserTenantAuth(),  # type: ignore[arg-type]
            approvals=approvals,
            notifications=notifications,
            now=lambda: NOW,
        ),
        prefix="/saas",
    )
    app.include_router(
        create_platform_notification_router(
            config=PlatformHttpConfig(
                enabled=True,
                origin=origin,
                audience="omnigent-platform",
            ),
            sessions=_BrowserStaffSessions(origin),
            approvals=approvals,
            notifications=notifications,
            now=lambda: NOW,
        )
    )
    certificate_path, key_path = _write_certificate(tmp_path)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            ssl_certfile=str(certificate_path),
            ssl_keyfile=str(key_path),
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        raise RuntimeError("notification browser server failed to start")
    try:
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()


def _context(browser: Browser, origin: str, *, realm: str) -> BrowserContext:
    context = browser.new_context(
        ignore_https_errors=True, viewport={"width": 1280, "height": 900}
    )
    if realm == "tenant":
        cookie = {"name": "__Host-omnigent_saas_session", "value": "tenant-session"}
        csrf = "tenant-csrf"
        storage_key = "omnigent.saas.csrf"
    else:
        cookie = {"name": "__Host-omnigent_platform_session", "value": "staff-session"}
        csrf = "staff-csrf"
        storage_key = "omnigent.platform.csrf"
    context.add_cookies([{**cookie, "url": origin, "secure": True, "sameSite": "Lax"}])
    context.add_init_script(f"sessionStorage.setItem({storage_key!r}, {csrf!r});")
    return context


def _wait_loaded(page: Page) -> None:
    expect(page.locator("#notification-ops-shell")).to_have_attribute("aria-busy", "false")


def test_chromium_realms_delegation_partial_batch_dlq_and_mobile_keyboard(
    notification_operations_server: str,
) -> None:
    origin = notification_operations_server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            tenant = _context(browser, origin, realm="tenant")
            page = tenant.new_page()
            page.goto(f"{origin}/saas/tenants/{TENANT_ID}/notification-ops")
            _wait_loaded(page)
            expect(page.locator("[data-inbox-list] .work-card")).to_have_count(1)
            expect(
                page.get_by_role("heading", name="privacy_delete / approve", exact=True)
            ).to_be_visible()

            page.locator(".work-card input[type=checkbox]").check()
            page.locator("[data-batch-reason]").fill("browser batch authorization")
            page.get_by_role("button", name="预检通过").click()
            expect(page.locator("[data-batch-execute]")).to_be_visible()
            expect(page.locator("[data-batch-reason]")).to_have_value("")
            page.locator("[data-batch-reason]").fill("browser batch authorization")
            page.locator("[data-batch-execute]").click()
            expect(page.locator("[data-toast]")).to_contain_text("batch_partial")
            expect(page.locator("[data-batch-result]")).to_contain_text("成功 1 · 失败 1")

            page.get_by_role("button", name="建立委派").click()
            page.locator("[data-delegate-id]").fill("10000000-0000-4000-8000-000000000003")
            page.locator("[data-delegation-reason]").fill("coverage while primary is away")
            page.get_by_role("button", name="创建时限委派").click()
            expect(page.locator("[data-toast]")).to_contain_text("approval_delegation_created")
            expect(page.locator("[data-delegation-list] .delegation-row")).to_have_count(1)

            page.get_by_role("button", name="02 投递").click()
            expect(page.get_by_text("provider_unavailable")).to_be_visible()
            page.get_by_role("button", name="重放").click()
            expect(page.locator("[data-toast]")).to_contain_text("delivery_replay_accepted")
            body = page.locator("body").inner_text()
            assert "secret-message-body" not in body
            assert "secret-recipient@example.test" not in body
            assert "secret-provider-stack" not in body

            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            page.get_by_role("button", name="01 审批").click()
            page.get_by_role("button", name="建立委派").click()
            expect(page.locator("[data-delegation-dialog]")).to_have_attribute("open", "")
            page.keyboard.press("Escape")
            expect(page.locator("[data-delegation-dialog]")).not_to_have_attribute("open", "")
            page.keyboard.press("Tab")
            assert page.evaluate("document.activeElement !== document.body")
            tenant.close()

            staff = _context(browser, origin, realm="staff")
            staff_page = staff.new_page()
            staff_page.goto(f"{origin}/platform-notification-ops")
            _wait_loaded(staff_page)
            expect(
                staff_page.get_by_role("heading", name="support_access / approve", exact=True)
            ).to_be_visible()
            assert "privacy_delete / approve" not in staff_page.locator("body").inner_text()
            assert "secret-message-body" not in staff_page.locator("body").inner_text()
            staff.close()
        finally:
            browser.close()
