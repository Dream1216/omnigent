from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from saas.control_plane.approval_operations import (
    ApprovalActor,
    ApprovalDelegationView,
    ApprovalOperationsError,
    ApprovalWorkItemPage,
    ApprovalWorkItemView,
    OperationBatchItemView,
    OperationBatchView,
)
from saas.control_plane.http_auth import (
    SaasCookieConfig,
    SaasPrincipal,
    create_saas_http_integration,
)
from saas.control_plane.lifecycle import LifecycleError, ValidatedAuthSession
from saas.control_plane.notification_http import (
    TenantNotificationHttpConfig,
    create_notification_router,
)
from saas.control_plane.platform_http import PlatformHttpConfig, create_platform_admin_app
from saas.control_plane.platform_notification_http import create_platform_notification_router
from saas.control_plane.platform_security import (
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)

ORIGIN = "https://notify.example.test"
NOW = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)
TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
TENANT_ACTOR = UUID("10000000-0000-4000-8000-000000000002")
STAFF_ACTOR = UUID("20000000-0000-4000-8000-000000000002")
DELEGATE_ID = UUID("10000000-0000-4000-8000-000000000003")


class _TenantAuth:
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
                session_id=uuid4(),
                user_id=TENANT_ACTOR,
                security_version=7,
                authn_method="password",
                authenticated_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=1),
            ),
            runtime_context=None,
        )


class _TenantLifecycle:
    def validate_auth_session(self, token: str) -> ValidatedAuthSession:
        if token != "tenant-session":
            raise LifecycleError("session_invalid", "invalid")
        return ValidatedAuthSession(
            session_id=uuid4(),
            user_id=TENANT_ACTOR,
            security_version=7,
            authn_method="password",
            authenticated_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(hours=1),
        )

    def validate_csrf(self, token: str, csrf_token: str) -> None:
        if token != "tenant-session" or csrf_token != "tenant-csrf":
            raise LifecycleError("csrf_invalid", "invalid")


class _StaffSessions:
    origin = ORIGIN
    audience = "omnigent-platform"

    def validate_session(
        self,
        token: str,
        *,
        origin: str,
        audience: str,
        now: datetime | None = None,
    ) -> ValidatedPlatformPrincipal:
        if token != "staff-session" or origin != ORIGIN or audience != self.audience:
            raise PlatformSecurityError("platform_session_invalid", "invalid")
        return ValidatedPlatformPrincipal(
            session_id=uuid4(),
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


def _work(realm: str, actor: UUID, tenant_id: UUID | None) -> ApprovalWorkItemView:
    return ApprovalWorkItemView(
        id=uuid4(),
        realm=realm,
        tenant_id=tenant_id,
        hmac_key_id="hidden-key",
        requester_realm=realm,
        requester_id=uuid4(),
        assignee_id=actor,
        operation_kind="privacy_delete" if realm == "tenant" else "support_access",
        operation_id=uuid4(),
        action="approve",
        target_type="tenant" if realm == "tenant" else "support_session",
        target_locator_hmac="a" * 64,
        required_permission="tenant.privacy.approve" if realm == "tenant" else "support.approve",
        risk_level="critical",
        snapshot_hash="b" * 64,
        status="pending",
        priority="high",
        due_at=NOW + timedelta(hours=2),
        escalation_at=NOW + timedelta(hours=1),
        escalation_count=0,
        decision_code=None,
        decided_at=None,
        version=1,
    )


class _Approvals:
    def __init__(self) -> None:
        self.works = {
            "tenant": _work("tenant", TENANT_ACTOR, TENANT_ID),
            "staff": _work("staff", STAFF_ACTOR, None),
        }
        self.delegations: list[ApprovalDelegationView] = []
        self.last: dict[str, Any] = {}
        self.batch_reason: str | None = None

    def list_work_items(self, actor: ApprovalActor, **_: Any) -> ApprovalWorkItemPage:
        return ApprovalWorkItemPage(items=(self.works[actor.realm],), next_cursor=None)

    def decide(self, actor: ApprovalActor, **values: Any) -> ApprovalWorkItemView:
        self.last = {"actor": actor, **values}
        value = replace(
            self.works[actor.realm],
            status="approved" if values["decision"] == "approve" else "rejected",
            decision_code=values["decision_code"],
            decided_at=NOW,
            version=2,
        )
        self.works[actor.realm] = value
        return value

    def create_delegation(self, actor: ApprovalActor, **values: Any) -> ApprovalDelegationView:
        self.last = {"actor": actor, **values}
        work = self.works[actor.realm]
        delegation = ApprovalDelegationView(
            id=uuid4(),
            realm=actor.realm,
            tenant_id=actor.tenant_id,
            delegator_id=actor.actor_id,
            delegate_id=values["delegate_id"],
            permission_code=work.required_permission,
            scope_type="operation",
            scope_id=work.operation_id,
            starts_at=values["starts_at"],
            expires_at=values["expires_at"],
            status="active",
            version=1,
        )
        self.delegations.append(delegation)
        return delegation

    def list_delegations(self, actor: ApprovalActor, **_: Any) -> object:
        return _Page(tuple(value for value in self.delegations if value.realm == actor.realm))

    def revoke_delegation(self, actor: ApprovalActor, **values: Any) -> ApprovalDelegationView:
        self.last = {"actor": actor, **values}
        current = next(value for value in self.delegations if value.id == values["delegation_id"])
        revoked = replace(current, status="revoked", version=current.version + 1)
        self.delegations = [
            revoked if value.id == revoked.id else value for value in self.delegations
        ]
        return revoked

    def preview_batch(self, actor: ApprovalActor, **values: Any) -> OperationBatchView:
        self.last = {"actor": actor, **values}
        self.batch_reason = values["decision_reason"]
        work = self.works[actor.realm]
        return _batch(actor, work, status="pending", success=0, failure=0, version=1)

    def execute_batch(self, actor: ApprovalActor, **values: Any) -> OperationBatchView:
        self.last = {"actor": actor, **values}
        if values["decision_reason"] != self.batch_reason:
            raise ApprovalOperationsError("operation_batch_reason_conflict")
        work = self.works[actor.realm]
        return _batch(actor, work, status="partial", success=1, failure=1, version=2)


def _batch(
    actor: ApprovalActor,
    work: ApprovalWorkItemView,
    *,
    status: str,
    success: int,
    failure: int,
    version: int,
) -> OperationBatchView:
    item = OperationBatchItemView(
        id=uuid4(),
        sequence=0,
        work_item_id=work.id,
        expected_work_item_version=work.version,
        target_type=work.target_type,
        target_locator_hmac="c" * 64,
        operation_id=work.operation_id,
        status="failed" if failure else "pending",
        error_code="approval_stale" if failure else None,
        result_hmac="d" * 64 if failure else None,
    )
    return OperationBatchView(
        id=UUID("30000000-0000-4000-8000-000000000001"),
        realm=actor.realm,
        tenant_id=actor.tenant_id,
        operation_kind=work.operation_kind,
        action=work.action,
        decision="approve",
        item_count=2,
        status=status,
        success_count=success,
        failure_count=failure,
        version=version,
        created_at=NOW,
        items=(item,),
    )


@dataclass
class _Page:
    items: tuple[object, ...]
    next_cursor: UUID | None = None


class _Notifications:
    def __init__(self) -> None:
        self.delivery = SimpleNamespace(
            id=uuid4(),
            realm="tenant",
            tenant_id=TENANT_ID,
            event_type="approval.pending",
            channel="in_app",
            status="succeeded",
            attempt_count=1,
            max_attempts=8,
            source_delivery_id=None,
            available_at=NOW,
            recipient_read_at=None,
            acknowledged_at=None,
            last_error_code=None,
            version=1,
        )
        self.preference = SimpleNamespace(
            id=uuid4(),
            event_type="approval.pending",
            channel="in_app",
            enabled=True,
            locale="zh-CN",
            version=1,
        )
        self.template = SimpleNamespace(
            id=uuid4(),
            template_key="approval.pending",
            channel="in_app",
            locale="zh-CN",
            version=1,
            status="active",
            created_at=NOW,
            retired_at=None,
        )
        self.last: dict[str, Any] = {}

    def list_deliveries(self, actor: ApprovalActor, **_: Any) -> _Page:
        return _Page(
            (replace_namespace(self.delivery, realm=actor.realm, tenant_id=actor.tenant_id),)
        )

    def replay(self, actor: ApprovalActor, **values: Any) -> object:
        self.last = {"actor": actor, **values}
        return replace_namespace(self.delivery, realm=actor.realm, tenant_id=actor.tenant_id)

    def mark_read(self, actor: ApprovalActor, **values: Any) -> object:
        self.last = {"actor": actor, **values}
        self.delivery.recipient_read_at = NOW
        self.delivery.version += 1
        return replace_namespace(self.delivery, realm=actor.realm, tenant_id=actor.tenant_id)

    def list_preferences(self, actor: ApprovalActor, **_: Any) -> tuple[object, ...]:
        return (self.preference,)

    def update_preference(self, actor: ApprovalActor, **values: Any) -> object:
        self.last = {"actor": actor, **values}
        self.preference.enabled = values["enabled"]
        self.preference.locale = values["locale"]
        self.preference.version += 1
        return self.preference

    def list_templates(self, actor: ApprovalActor, **_: Any) -> tuple[object, ...]:
        return (self.template,)

    def create_template(self, actor: ApprovalActor, **values: Any) -> object:
        self.last = {"actor": actor, **values}
        self.template = SimpleNamespace(
            id=uuid4(),
            template_key=values["template_key"],
            channel=values["channel"],
            locale=values["locale"],
            version=values["version"],
            status="active",
            created_at=NOW,
            retired_at=None,
        )
        return self.template

    def retire_template(self, actor: ApprovalActor, **values: Any) -> object:
        self.last = {"actor": actor, **values}
        self.template.status = "retired"
        self.template.retired_at = NOW
        return self.template


def replace_namespace(value: SimpleNamespace, **changes: Any) -> SimpleNamespace:
    return SimpleNamespace(**{**vars(value), **changes})


def _client() -> tuple[TestClient, _Approvals, _Notifications]:
    approvals = _Approvals()
    notifications = _Notifications()
    app = FastAPI()
    app.include_router(
        create_notification_router(
            config=TenantNotificationHttpConfig(origin=ORIGIN),
            auth_provider=_TenantAuth(),  # type: ignore[arg-type]
            approvals=approvals,
            notifications=notifications,
            now=lambda: NOW,
        ),
        prefix="/saas",
    )
    app.include_router(
        create_platform_notification_router(
            config=PlatformHttpConfig(enabled=True, origin=ORIGIN, audience="omnigent-platform"),
            sessions=_StaffSessions(),
            approvals=approvals,
            notifications=notifications,
            now=lambda: NOW,
        )
    )
    return TestClient(app, base_url=ORIGIN), approvals, notifications


def _tenant_headers() -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": "tenant-csrf", "Idempotency-Key": "tenant-1"}


def _staff_headers() -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": "staff-csrf", "Idempotency-Key": "staff-1"}


def test_tenant_inbox_is_cookie_only_content_blind_and_validation_is_collapsed() -> None:
    client, _, _ = _client()
    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    path = f"/saas/tenants/{TENANT_ID}/notification-operations/inbox"
    response = client.get(path)
    assert response.status_code == 200
    body = response.json()
    serialized = response.text
    assert body["items"][0]["realm"] == "tenant"
    assert body["items"][0]["routing"] == "assigned_to_me"
    assert "target_locator_hmac" not in serialized
    assert "snapshot_hash" not in serialized
    assert "requester_id" not in serialized
    assert "hidden-key" not in serialized

    client.cookies.clear()
    assert client.get(path, headers={"Authorization": "Bearer tenant-session"}).status_code == 401

    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    secret = "must-never-return-this-reason"
    invalid = client.post(
        f"{path}/{uuid4()}/decision",
        headers=_tenant_headers(),
        json={"expected_version": "one", "reason": secret, "unexpected": secret},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": {"code": "notification_request_invalid"}}
    assert secret not in invalid.text

    console = client.get(f"/saas/tenants/{TENANT_ID}/notification-ops")
    assert console.status_code == 200
    assert console.headers["cache-control"] == "private, no-store"
    assert console.headers["x-content-type-options"] == "nosniff"
    assert console.headers["referrer-policy"] == "no-referrer"


def test_tenant_mutations_forward_fresh_csrf_idempotency_and_transient_reason() -> None:
    client, approvals, notifications = _client()
    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    work = approvals.works["tenant"]
    decision = client.post(
        f"/saas/tenants/{TENANT_ID}/notification-operations/inbox/{work.id}/decision",
        headers=_tenant_headers(),
        json={
            "expected_version": 1,
            "decision": "approve",
            "decision_code": "operator_verified",
            "reason": "verified against change ticket",
        },
    )
    assert decision.status_code == 200
    assert approvals.last["idempotency_key"] == "tenant-1"
    assert approvals.last["decision_reason"] == "verified against change ticket"
    assert "verified against change ticket" not in decision.text

    read = client.post(
        f"/saas/tenants/{TENANT_ID}/notification-operations/deliveries/{notifications.delivery.id}/read",
        headers={**_tenant_headers(), "Idempotency-Key": "read-1"},
        json={"expected_version": 1},
    )
    assert read.status_code == 200
    assert read.json()["recipient_read_at"] is not None
    assert read.json()["source_delivery_id"] is None
    assert notifications.last["idempotency_key"] == "read-1"

    preference = client.patch(
        f"/saas/tenants/{TENANT_ID}/notification-operations/preferences/{notifications.preference.id}",
        headers={**_tenant_headers(), "Idempotency-Key": "pref-1"},
        json={"expected_version": 1, "enabled": False, "locale": "zh-CN"},
    )
    assert preference.status_code == 200
    assert preference.json()["enabled"] is False
    assert notifications.last["idempotency_key"] == "pref-1"

    tenant_template_write = client.post(
        f"/saas/tenants/{TENANT_ID}/notification-operations/templates",
        headers=_tenant_headers(),
        json={},
    )
    assert tenant_template_write.status_code == 405


def test_staff_realm_rejects_tenant_or_bearer_and_governs_template_without_echo() -> None:
    client, approvals, _ = _client()
    client.cookies.set("__Host-omnigent_platform_session", "staff-session")
    inbox = client.get("/v2/platform-admin/notification-operations/inbox")
    assert inbox.status_code == 200
    assert inbox.json()["items"][0]["realm"] == "staff"
    assert inbox.json()["items"][0]["work_item_id"] == str(approvals.works["staff"].id)

    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    assert client.get("/v2/platform-admin/notification-operations/inbox").status_code == 401
    client.cookies.clear()
    assert (
        client.get(
            "/v2/platform-admin/notification-operations/inbox",
            headers={"Authorization": "Bearer staff-session"},
        ).status_code
        == 401
    )

    client.cookies.set("__Host-omnigent_platform_session", "staff-session")
    handle = "opaque-package-0000000001"
    content_hash = "e" * 64
    schema_hash = "f" * 64
    created = client.post(
        "/v2/platform-admin/notification-operations/templates",
        headers=_staff_headers(),
        json={
            "tenant_id": None,
            "template_key": "approval.completed",
            "channel": "in_app",
            "locale": "zh-CN",
            "version": 2,
            "content_artifact_handle": handle,
            "content_sha256": content_hash,
            "variables_schema_sha256": schema_hash,
        },
    )
    assert created.status_code == 201
    assert created.json()["template_key"] == "approval.completed"
    assert handle not in created.text
    assert content_hash not in created.text
    assert schema_hash not in created.text


def test_batch_execute_rechecks_transient_reason_without_echoing_it() -> None:
    client, approvals, _ = _client()
    client.cookies.set("__Host-omnigent_saas_session", "tenant-session")
    work = approvals.works["tenant"]
    preview_reason = "ticket-approved-browser-secret"
    preview = client.post(
        f"/saas/tenants/{TENANT_ID}/notification-operations/batches/preview",
        headers=_tenant_headers(),
        json={
            "decision": "approve",
            "decision_code": "operator_verified",
            "reason": preview_reason,
            "items": [{"work_item_id": str(work.id), "expected_version": work.version}],
        },
    )
    assert preview.status_code == 201
    assert preview_reason not in preview.text
    batch = preview.json()
    execute_path = (
        f"/saas/tenants/{TENANT_ID}/notification-operations/batches/{batch['batch_id']}/execute"
    )
    wrong_reason = "different-secret-reason"
    mismatch = client.post(
        execute_path,
        headers={"Origin": ORIGIN, "X-CSRF-Token": "tenant-csrf"},
        json={"expected_version": batch["version"], "reason": wrong_reason},
    )
    assert mismatch.status_code == 409
    assert mismatch.json() == {"detail": {"code": "operation_batch_reason_conflict"}}
    assert wrong_reason not in mismatch.text

    executed = client.post(
        execute_path,
        headers={"Origin": ORIGIN, "X-CSRF-Token": "tenant-csrf"},
        json={"expected_version": batch["version"], "reason": preview_reason},
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "partial"
    assert preview_reason not in executed.text


def test_optional_tenant_and_platform_composition_exposes_capability_only_when_wired() -> None:
    approvals = _Approvals()
    notifications = _Notifications()
    cookie = SaasCookieConfig(trusted_origins=frozenset({ORIGIN}))
    lifecycle = _TenantLifecycle()

    def tenant_app(*, enabled: bool) -> FastAPI:
        options: dict[str, object] = {}
        if enabled:
            options = {
                "approval_operations": approvals,
                "notification_operations": notifications,
                "notification_origin": ORIGIN,
            }
        integration = create_saas_http_integration(
            lifecycle=lifecycle,  # type: ignore[arg-type]
            identities=SimpleNamespace(),  # type: ignore[arg-type]
            passwords=SimpleNamespace(),  # type: ignore[arg-type]
            context_resolver=SimpleNamespace(),  # type: ignore[arg-type]
            cookie_config=cookie,
            **options,  # type: ignore[arg-type]
        )
        app = FastAPI()
        app.include_router(integration.router, prefix="/saas")
        return app

    disabled_client = TestClient(tenant_app(enabled=False), base_url=ORIGIN)
    disabled_client.cookies.set(cookie.name, "tenant-session")
    capability_path = f"/saas/tenants/{TENANT_ID}/notification-operations/capabilities"
    disabled_capability = disabled_client.get(capability_path)
    assert disabled_capability.status_code == 200
    assert disabled_capability.json() == {
        "notification_operations_enabled": False,
        "template_management": "unavailable",
        "content_access": "none",
    }

    enabled_client = TestClient(tenant_app(enabled=True), base_url=ORIGIN)
    enabled_client.cookies.set(cookie.name, "tenant-session")
    capability = enabled_client.get(capability_path)
    assert capability.status_code == 200
    assert capability.json()["notification_operations_enabled"] is True

    platform_config = PlatformHttpConfig(enabled=True, origin=ORIGIN, audience="omnigent-platform")
    sessions = _StaffSessions()
    plain_platform = create_platform_admin_app(
        config=platform_config,
        sessions=sessions,  # type: ignore[arg-type]
        authorization=SimpleNamespace(),  # type: ignore[arg-type]
        projections=SimpleNamespace(),  # type: ignore[arg-type]
    )
    plain_client = TestClient(plain_platform, base_url=ORIGIN)
    plain_client.cookies.set(platform_config.cookie_name, "staff-session")
    plain_context = plain_client.get("/v2/platform-admin/context")
    assert plain_context.json()["capabilities"]["notification_operations_enabled"] is False
    plain_html = plain_client.get("/platform-admin")
    assert 'id="notification-operations-link"' in plain_html.text
    assert "hidden" in plain_html.text.split('id="notification-operations-link"', 1)[1][:200]
    assert plain_client.get("/platform-notification-ops").status_code == 404

    wired_platform = create_platform_admin_app(
        config=platform_config,
        sessions=sessions,  # type: ignore[arg-type]
        authorization=SimpleNamespace(),  # type: ignore[arg-type]
        projections=SimpleNamespace(),  # type: ignore[arg-type]
        approval_operations=approvals,
        notification_operations=notifications,
    )
    wired_client = TestClient(wired_platform, base_url=ORIGIN)
    wired_client.cookies.set(platform_config.cookie_name, "staff-session")
    wired_context = wired_client.get("/v2/platform-admin/context")
    assert wired_context.json()["capabilities"]["notification_operations_enabled"] is True
    assert wired_client.get("/platform-notification-ops").status_code == 200
