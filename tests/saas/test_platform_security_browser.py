from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
from sqlalchemy.orm import sessionmaker

from saas.control_plane import (
    PlatformAuthorizationService,
    PlatformHttpConfig,
    PlatformProjectionService,
    PlatformRoleAssignmentRecord,
    PlatformSessionService,
    SaasBase,
    StaffIdentityAssertion,
    TenantProjectionInput,
    UserProjectionInput,
    create_platform_admin_app,
)

_AUDIENCE = "omnigent-platform-admin"
_COOKIE_NAME = "__Host-omnigent_platform_session"
_TENANT_COOKIE_NAME = "__Host-omnigent_saas_session"


@dataclass(frozen=True, slots=True)
class PlatformBrowserFixture:
    origin: str
    operator_token: str
    roleless_token: str


def _write_loopback_certificate(directory: Path) -> tuple[Path, Path]:
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
    cert_path = directory / "platform-browser.crt"
    key_path = directory / "platform-browser.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def platform_browser_server(tmp_path: Path) -> Iterator[PlatformBrowserFixture]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    origin = f"https://127.0.0.1:{port}"
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'platform-browser.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=origin, audience=_AUDIENCE)
    projections = PlatformProjectionService(factory)
    operator_id = authorization.provision_staff_principal(
        identity_connection_ref="browser-staff-idp:operator",
        issuer="https://staff-idp.browser.test",
        subject="operator",
        now=now,
    )
    roleless_id = authorization.provision_staff_principal(
        identity_connection_ref="browser-staff-idp:roleless",
        issuer="https://staff-idp.browser.test",
        subject="roleless",
        now=now,
    )
    with factory.begin() as db:
        db.add(
            PlatformRoleAssignmentRecord(
                principal_id=operator_id,
                role="platform_security_auditor",
                status="active",
                version=1,
                assigned_by_principal_id=roleless_id,
                approval_ref="browser-bootstrap-approval",
                reason="real Chromium PC1 acceptance",
                created_at=now,
                updated_at=now,
            )
        )
    operator = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.browser.test",
            subject="operator",
            authn_method="webauthn",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    roleless = sessions.issue_session(
        StaffIdentityAssertion(
            issuer="https://staff-idp.browser.test",
            subject="roleless",
            authn_method="passkey",
            mfa_strength="phishing_resistant",
            authenticated_at=now,
        ),
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    projections.upsert_tenant(
        TenantProjectionInput(
            tenant_id=operator_id,
            slug="browser-customer",
            name="Browser Customer",
            status="active",
            plan="team",
            home_region="cn-east-1",
            member_count=2,
            space_count=1,
            source_version=1,
            updated_at=now,
        )
    )
    projections.upsert_user(
        UserProjectionInput(
            user_id=roleless_id,
            status="active",
            display_name="Customer User",
            email_masked="c***@browser.test",
            membership_count=1,
            security_version=1,
            source_version=1,
            created_at=now,
            updated_at=now,
        )
    )
    app = create_platform_admin_app(
        config=PlatformHttpConfig(enabled=True, origin=origin, audience=_AUDIENCE),
        sessions=sessions,
        authorization=authorization,
        projections=projections,
    )
    cert_path, key_path = _write_loopback_certificate(tmp_path)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        engine.dispose()
        raise RuntimeError("Platform Admin HTTPS browser fixture did not start")
    try:
        yield PlatformBrowserFixture(origin, operator.token, roleless.token)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        engine.dispose()


def _platform_context(browser: Browser, fixture: PlatformBrowserFixture) -> BrowserContext:
    context = browser.new_context(ignore_https_errors=True)
    context.add_cookies(
        [
            {
                "name": _COOKIE_NAME,
                "value": fixture.operator_token,
                "url": fixture.origin,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Strict",
            }
        ]
    )
    return context


def _navigate_json(page: Page, url: str) -> tuple[int, dict[str, object]]:
    response = page.goto(url)
    assert response is not None
    return response.status, json.loads(page.locator("body").inner_text())


def _run_in_fresh_browser_thread(
    fixture: PlatformBrowserFixture,
    case: Callable[[Browser, PlatformBrowserFixture], None],
) -> None:
    """Keep sync Playwright's loop out of pytest-asyncio's main thread."""

    captured: dict[str, BaseException] = {}

    def worker() -> None:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    case(browser, fixture)
                finally:
                    browser.close()
        except BaseException as error:
            captured["error"] = error

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=60)
    if thread.is_alive():
        raise RuntimeError("Platform Chromium acceptance did not terminate")
    if error := captured.get("error"):
        raise error


def _realm_and_role_negative_matrix(
    browser: Browser,
    fixture: PlatformBrowserFixture,
) -> None:
    context = _platform_context(browser, fixture)
    page = context.new_page()
    try:
        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/context")
        assert status == 200
        assert payload["realm"] == "staff"
        assert payload["content_access"] == "none"
        assert "platform_security_auditor" in payload["roles"]

        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/permissions")
        assert status == 200
        assert payload["policy_version"] == "2026-08-08.pc2-user-tenant-lifecycle"

        context.add_cookies(
            [
                {
                    "name": _TENANT_COOKIE_NAME,
                    "value": "customer-realm-session",
                    "url": fixture.origin,
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Strict",
                }
            ]
        )
        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/context")
        assert status == 401
        assert payload["error"]["code"] == "platform_realm_mismatch"  # type: ignore[index]

        context.clear_cookies()
        context.add_cookies(
            [
                {
                    "name": _COOKIE_NAME,
                    "value": fixture.roleless_token,
                    "url": fixture.origin,
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Strict",
                }
            ]
        )
        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/permissions")
        assert status == 403
        assert payload["error"]["code"] == "platform_permission_denied"  # type: ignore[index]
    finally:
        context.close()


def _wrong_origin_and_bearer_matrix(
    browser: Browser,
    fixture: PlatformBrowserFixture,
) -> None:
    context = _platform_context(browser, fixture)
    page = context.new_page()
    try:
        page.set_extra_http_headers({"Origin": "https://tenant.example.test"})
        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/context")
        assert status == 401
        assert payload["error"]["code"] == "platform_realm_mismatch"  # type: ignore[index]

        page.set_extra_http_headers({"Authorization": "Bearer customer-token"})
        status, payload = _navigate_json(page, f"{fixture.origin}/v2/platform-admin/context")
        assert status == 401
        assert payload["error"]["code"] == "platform_realm_mismatch"  # type: ignore[index]
    finally:
        context.close()


def test_real_chromium_platform_realm_and_role_negative_matrix(
    platform_browser_server: PlatformBrowserFixture,
) -> None:
    _run_in_fresh_browser_thread(
        platform_browser_server,
        _realm_and_role_negative_matrix,
    )


def test_real_chromium_platform_rejects_wrong_origin_and_bearer(
    platform_browser_server: PlatformBrowserFixture,
) -> None:
    _run_in_fresh_browser_thread(
        platform_browser_server,
        _wrong_origin_and_bearer_matrix,
    )
