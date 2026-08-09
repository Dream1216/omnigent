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
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from playwright.sync_api import Browser, BrowserContext, Page, expect, sync_playwright
from sqlalchemy.orm import sessionmaker

from saas.control_plane import (
    AuditSigningKey,
    GlobalUser,
    IdentityConflict,
    PlatformAuthorizationService,
    PlatformGovernedAccessService,
    PlatformHttpConfig,
    PlatformLifecycleService,
    PlatformProjectionService,
    PlatformRoleAssignmentRecord,
    PlatformSessionService,
    SaasBase,
    StaffIdentityAssertion,
    Tenant,
    TenantMembership,
    TenantProjectionInput,
    UserProjectionInput,
    create_platform_admin_app,
)

_AUDIENCE = "omnigent-platform-admin"
_COOKIE = "__Host-omnigent_platform_session"


@dataclass(frozen=True, slots=True)
class BrowserIdentity:
    token: str
    csrf: str


@dataclass(frozen=True, slots=True)
class PlatformAdminFixture:
    origin: str
    operator: BrowserIdentity
    auditor: BrowserIdentity
    support: BrowserIdentity
    roleless: BrowserIdentity
    user_id: UUID
    tenant_id: UUID
    conflict_id: UUID


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
    certificate_path = directory / "platform-admin-browser.crt"
    key_path = directory / "platform-admin-browser.key"
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
def platform_admin_server(tmp_path: Path) -> Iterator[PlatformAdminFixture]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    origin = f"https://127.0.0.1:{port}"
    now = datetime.now(timezone.utc)
    engine = sa.create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'platform-admin-browser.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    authorization = PlatformAuthorizationService(factory)
    sessions = PlatformSessionService(factory, origin=origin, audience=_AUDIENCE)
    projections = PlatformProjectionService(factory)

    principals = {
        name: authorization.provision_staff_principal(
            identity_connection_ref=f"pc4-browser:{name}",
            issuer="https://staff-idp.browser.test",
            subject=name,
            now=now,
        )
        for name in ("operator", "auditor", "support", "roleless")
    }
    role_by_name = {
        "operator": "platform_operator",
        "auditor": "compliance_operator",
        "support": "support_agent",
    }
    user_id, tenant_id, conflict_id = uuid4(), uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all(
            PlatformRoleAssignmentRecord(
                principal_id=principals[name],
                role=role,
                status="active",
                version=1,
                assigned_by_principal_id=principals["roleless"],
                approval_ref=f"pc4-browser-{name}",
                reason="PC4 Chromium role matrix",
                created_at=now,
                updated_at=now,
            )
            for name, role in role_by_name.items()
        )
        db.add_all(
            [
                GlobalUser(
                    id=user_id,
                    display_name="Contoso Owner",
                    status="active",
                    security_version=1,
                    created_at=now,
                    updated_at=now,
                ),
                Tenant(
                    id=tenant_id,
                    slug="contoso-labs",
                    name="Contoso Labs",
                    status="active",
                    plan="enterprise",
                    home_region="cn-east-1",
                    lifecycle_version=1,
                    created_at=now,
                    updated_at=now,
                ),
                TenantMembership(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    role="owner",
                    status="active",
                    version=1,
                    joined_at=now,
                ),
                IdentityConflict(
                    id=conflict_id,
                    provider="oidc",
                    issuer="https://private-idp.browser.test",
                    subject="private-subject",
                    email_normalized="private@browser.test",
                    status="pending",
                    version=1,
                    created_at=now,
                    updated_at=now,
                ),
            ]
        )

    projections.upsert_tenant(
        TenantProjectionInput(
            tenant_id=tenant_id,
            slug="contoso-labs",
            name="Contoso Labs",
            status="active",
            plan="enterprise",
            home_region="cn-east-1",
            member_count=1,
            space_count=2,
            source_version=1,
            updated_at=now,
        )
    )
    projections.upsert_user(
        UserProjectionInput(
            user_id=user_id,
            status="active",
            display_name="Contoso Owner",
            email_masked="c***@browser.test",
            membership_count=1,
            security_version=1,
            source_version=1,
            created_at=now,
            updated_at=now,
        )
    )

    issued = {}
    for name in principals:
        session = sessions.issue_session(
            StaffIdentityAssertion(
                issuer="https://staff-idp.browser.test",
                subject=name,
                authn_method="passkey",
                mfa_strength="phishing_resistant",
                authenticated_at=now,
            ),
            expires_at=now + timedelta(hours=1),
            now=now,
        )
        issued[name] = BrowserIdentity(session.token, session.csrf_token)

    governed = PlatformGovernedAccessService(
        factory,
        signing_key=AuditSigningKey(key_id="pc4-browser-v1", secret=b"p" * 32),
    )
    support_actor = sessions.validate_session(
        issued["support"].token,
        origin=origin,
        audience=_AUDIENCE,
        now=now + timedelta(seconds=1),
    )
    governed.request_support_grant(
        support_actor,
        tenant_id=tenant_id,
        mode="break_glass",
        scopes=("runtime.diagnostics.read",),
        project_ids=(),
        reason="diagnose active incident",
        incident_ref="INC-PC4-BROWSER",
        expires_at=now + timedelta(minutes=10),
        idempotency_key="pc4-browser-support-request",
        now=now + timedelta(seconds=2),
    )

    app = create_platform_admin_app(
        config=PlatformHttpConfig(enabled=True, origin=origin, audience=_AUDIENCE),
        sessions=sessions,
        authorization=authorization,
        projections=projections,
        lifecycle=PlatformLifecycleService(factory),
        governed_access=governed,
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
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        engine.dispose()
        raise RuntimeError("PC4 Platform Admin HTTPS fixture did not start")
    try:
        yield PlatformAdminFixture(
            origin=origin,
            operator=issued["operator"],
            auditor=issued["auditor"],
            support=issued["support"],
            roleless=issued["roleless"],
            user_id=user_id,
            tenant_id=tenant_id,
            conflict_id=conflict_id,
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        engine.dispose()


def _context(
    browser: Browser,
    fixture: PlatformAdminFixture,
    identity: BrowserIdentity,
) -> BrowserContext:
    context = browser.new_context(ignore_https_errors=True)
    context.add_cookies(
        [
            {
                "name": _COOKIE,
                "value": identity.token,
                "url": fixture.origin,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Strict",
            }
        ]
    )
    context.add_init_script(
        f"sessionStorage.setItem('omnigent.platform.csrf', {json.dumps(identity.csrf)});"
    )
    return context


def _open_console(context: BrowserContext, fixture: PlatformAdminFixture) -> Page:
    page = context.new_page()
    response = page.goto(f"{fixture.origin}/platform-admin")
    assert response is not None and response.status == 200
    expect(page.locator("#console-shell")).to_have_attribute("aria-busy", "false")
    return page


def _submit_dialog(page: Page, values: dict[str, str]) -> None:
    dialog = page.get_by_test_id("action-dialog")
    expect(dialog).to_be_visible()
    for name, value in values.items():
        dialog.locator(f'[name="{name}"]').fill(value)
    page.get_by_test_id("dialog-confirm").click()
    expect(dialog).to_be_hidden()


def _role_page_action_matrix(browser: Browser, fixture: PlatformAdminFixture) -> None:
    operator_context = _context(browser, fixture, fixture.operator)
    operator = _open_console(operator_context, fixture)
    try:
        expect(operator.get_by_test_id("realm-lock")).to_contain_text("STAFF REALM")
        expect(operator.get_by_test_id("view-overview")).to_be_visible()
        expect(operator.locator("#metric-tenants")).to_have_text("01")
        expect(operator.locator("#metric-users")).to_have_text("01")
        expect(operator.get_by_test_id("nav-audit")).to_be_disabled()

        operator.get_by_test_id("nav-users").click()
        expect(operator.get_by_test_id("view-users")).to_be_visible()
        operator.get_by_test_id(f"user-suspend-{fixture.user_id}").click()
        _submit_dialog(
            operator,
            {
                "approval_ref": "APPROVAL-PC4-USER",
                "reason": "browser verified account compromise",
            },
        )
        expect(operator.get_by_test_id(f"user-restore-{fixture.user_id}")).to_be_visible()

        operator.get_by_test_id("nav-tenants").click()
        expect(operator.get_by_test_id("view-tenants")).to_be_visible()
        expect(operator.get_by_test_id(f"tenant-suspend-{fixture.tenant_id}")).to_be_enabled()

        operator.get_by_test_id("nav-access").click()
        expect(operator.get_by_test_id("view-access")).to_be_visible()
        operator.get_by_test_id(f"conflict-block-{fixture.conflict_id}").click()
        _submit_dialog(
            operator,
            {
                "approval_ref": "APPROVAL-PC4-CONFLICT",
                "reason": "candidate ownership cannot be proven",
            },
        )
        expect(operator.locator("#conflicts-total")).to_have_text("00")

        operator.get_by_test_id("nav-support").click()
        expect(operator.get_by_test_id("view-support")).to_be_visible()
        approval = operator.locator('[data-testid^="support-approve-"]')
        expect(approval).to_have_count(1)
        approval.click()
        _submit_dialog(operator, {"reason": "independent incident approval"})
        expect(operator.get_by_test_id("support-list")).to_contain_text("ACTIVE")

        operator.get_by_test_id("operations-toggle").click()
        drawer = operator.get_by_test_id("operations-drawer")
        expect(drawer).to_be_visible()
        expect(drawer).to_have_attribute("role", "dialog")
        expect(drawer).to_have_attribute("aria-modal", "true")
        expect(operator.locator("#operations-close")).to_be_focused()
        operator.keyboard.press("Tab")
        assert drawer.evaluate("drawer => drawer.contains(document.activeElement)") is True
        expect(operator.get_by_test_id("operations-list")).to_contain_text("USER SUSPEND")
        operator.keyboard.press("Escape")
        expect(drawer).to_be_hidden()
        expect(operator.get_by_test_id("operations-toggle")).to_be_focused()
    finally:
        operator_context.close()

    auditor_context = _context(browser, fixture, fixture.auditor)
    auditor = _open_console(auditor_context, fixture)
    try:
        auditor.get_by_test_id("nav-audit").click()
        expect(auditor.get_by_test_id("view-audit")).to_be_visible()
        expect(auditor.locator("#audit-list .audit-row").first).to_be_visible()
        auditor.get_by_test_id("audit-export-open").click()
        _submit_dialog(auditor, {"reason": "quarterly control evidence"})
        expect(auditor.get_by_test_id("operations-drawer")).to_be_visible()
        expect(auditor.get_by_test_id("operations-list")).to_contain_text("AUDIT EXPORT")
    finally:
        auditor_context.close()

    approver_context = _context(browser, fixture, fixture.operator)
    approver = _open_console(approver_context, fixture)
    try:
        approver.get_by_test_id("operations-toggle").click()
        approve_export = approver.locator('[data-testid^="operation-approve-"]')
        expect(approve_export).to_have_count(1)
        approve_export.click()
        _submit_dialog(approver, {"reason": "second Staff chain verification"})
        expect(approver.get_by_test_id("toast-stack")).to_contain_text("Signed Export")
    finally:
        approver_context.close()

    support_context = _context(browser, fixture, fixture.support)
    support = _open_console(support_context, fixture)
    try:
        expect(support.get_by_test_id("nav-users")).to_be_enabled()
        expect(support.get_by_test_id("nav-access")).to_be_disabled()
        support.get_by_test_id("nav-support").click()
        issue_session = support.locator('[data-testid^="support-session-"]')
        expect(issue_session).to_have_count(1)
        issue_session.click()
        expect(support.get_by_test_id("token-dialog")).to_be_visible()
        expect(support.get_by_test_id("support-one-time-token")).not_to_have_text("")
        support.locator("#token-dismiss").click()
        expect(support.get_by_test_id("token-dialog")).to_be_hidden()
        expect(support.get_by_test_id("support-one-time-token")).to_have_text("")
    finally:
        support_context.close()

    roleless_context = _context(browser, fixture, fixture.roleless)
    roleless = _open_console(roleless_context, fixture)
    try:
        expect(roleless.get_by_test_id("no-platform-access")).to_be_visible()
        expect(roleless.get_by_test_id("nav-users")).to_be_disabled()
        expect(roleless.get_by_test_id("nav-tenants")).to_be_disabled()
        expect(roleless.get_by_test_id("nav-support")).to_be_disabled()
        expect(roleless.get_by_test_id("nav-audit")).to_be_disabled()
    finally:
        roleless_context.close()


def _run_in_browser_thread(
    fixture: PlatformAdminFixture,
    case: Callable[[Browser, PlatformAdminFixture], None],
) -> None:
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
    thread.join(timeout=90)
    if thread.is_alive():
        raise RuntimeError("PC4 Chromium role/page/action matrix did not terminate")
    if error := captured.get("error"):
        raise error


def test_real_chromium_platform_console_role_page_and_action_matrix(
    platform_admin_server: PlatformAdminFixture,
) -> None:
    _run_in_browser_thread(platform_admin_server, _role_page_action_matrix)
