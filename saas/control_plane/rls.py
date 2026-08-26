"""Transaction-local PostgreSQL RLS context binding."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class RlsContext:
    """Server-verified actor and Tenant used by PostgreSQL policies."""

    actor_id: UUID | None = None
    tenant_id: UUID | None = None
    space_id: UUID | None = None
    project_id: UUID | None = None
    api_credential_id: UUID | None = None
    invitation_token_hash: str | None = None
    scim_token_hash: str | None = None
    target_support_grant_id: UUID | None = None
    target_admin_operation_id: UUID | None = None
    privacy_locator_hash: str | None = None


@dataclass(frozen=True, slots=True)
class RegistrationRlsContext:
    """Server-generated facts for the unauthenticated registration boundary."""

    registration_id: UUID | None = None
    token_hash: str | None = None
    email_hash: str | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class OnboardingRlsContext:
    """Trusted worker facts for one durable Tenant-onboarding Saga."""

    onboarding_id: UUID | None = None
    registration_id: UUID | None = None
    actor_id: UUID | None = None
    tenant_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PlatformRlsContext:
    """Server-verified Staff Realm facts used by platform-only policies."""

    principal_id: UUID | None = None
    session_token_hash: str | None = None
    identity_issuer: str | None = None
    identity_subject: str | None = None
    target_tenant_id: UUID | None = None
    target_user_id: UUID | None = None
    target_identity_conflict_id: UUID | None = None
    target_support_grant_id: UUID | None = None
    target_admin_operation_id: UUID | None = None
    support_session_token_hash: str | None = None
    privacy_manifest_id: UUID | None = None
    privacy_locator_hash: str | None = None


def _set_local(session: Session, name: str, value: str) -> None:
    session.execute(
        sa.text("SELECT set_config(:name, :value, true)"),
        {"name": name, "value": value},
    )


def apply_rls_context(session: Session, context: RlsContext) -> None:
    """Bind RLS facts to the current transaction; never accept raw client values."""

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _set_local(session, "app.platform_principal_id", "")
    _set_local(session, "app.platform_session_token_hash", "")
    _set_local(session, "app.platform_identity_issuer", "")
    _set_local(session, "app.platform_identity_subject", "")
    _set_local(session, "app.platform_target_tenant_id", "")
    _set_local(session, "app.platform_target_user_id", "")
    _set_local(session, "app.platform_target_identity_conflict_id", "")
    _set_local(session, "app.platform_target_support_grant_id", "")
    _set_local(session, "app.platform_target_admin_operation_id", "")
    _set_local(session, "app.platform_support_session_token_hash", "")
    _set_local(session, "app.platform_privacy_manifest_id", "")
    _clear_registration_context(session)
    _set_local(session, "app.privacy_locator_hash", context.privacy_locator_hash or "")
    _set_local(session, "app.actor_id", str(context.actor_id) if context.actor_id else "")
    _set_local(session, "app.tenant_id", str(context.tenant_id) if context.tenant_id else "")
    _set_local(session, "app.space_id", str(context.space_id) if context.space_id else "")
    _set_local(
        session,
        "app.project_id",
        str(context.project_id) if context.project_id else "",
    )
    _set_local(
        session,
        "app.api_credential_id",
        str(context.api_credential_id) if context.api_credential_id else "",
    )
    _set_local(session, "app.invitation_token_hash", context.invitation_token_hash or "")
    _set_local(session, "app.scim_token_hash", context.scim_token_hash or "")
    _set_local(
        session,
        "app.platform_target_support_grant_id",
        str(context.target_support_grant_id) if context.target_support_grant_id else "",
    )
    _set_local(
        session,
        "app.platform_target_admin_operation_id",
        str(context.target_admin_operation_id) if context.target_admin_operation_id else "",
    )


def apply_platform_rls_context(session: Session, context: PlatformRlsContext) -> None:
    """Bind Staff facts and explicitly clear every Customer Realm GUC."""

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for name in (
        "app.actor_id",
        "app.tenant_id",
        "app.space_id",
        "app.project_id",
        "app.api_credential_id",
        "app.invitation_token_hash",
        "app.scim_token_hash",
        "app.privacy_locator_hash",
    ):
        _set_local(session, name, "")
    _clear_registration_context(session)
    _set_local(
        session,
        "app.platform_principal_id",
        str(context.principal_id) if context.principal_id else "",
    )
    _set_local(
        session,
        "app.platform_session_token_hash",
        context.session_token_hash or "",
    )
    _set_local(session, "app.platform_identity_issuer", context.identity_issuer or "")
    _set_local(session, "app.platform_identity_subject", context.identity_subject or "")
    _set_local(
        session,
        "app.platform_target_tenant_id",
        str(context.target_tenant_id) if context.target_tenant_id else "",
    )
    _set_local(
        session,
        "app.platform_target_user_id",
        str(context.target_user_id) if context.target_user_id else "",
    )
    _set_local(
        session,
        "app.platform_target_identity_conflict_id",
        str(context.target_identity_conflict_id) if context.target_identity_conflict_id else "",
    )
    _set_local(
        session,
        "app.platform_target_support_grant_id",
        str(context.target_support_grant_id) if context.target_support_grant_id else "",
    )
    _set_local(
        session,
        "app.platform_target_admin_operation_id",
        str(context.target_admin_operation_id) if context.target_admin_operation_id else "",
    )
    _set_local(
        session,
        "app.platform_support_session_token_hash",
        context.support_session_token_hash or "",
    )
    _set_local(
        session,
        "app.platform_privacy_manifest_id",
        str(context.privacy_manifest_id) if context.privacy_manifest_id else "",
    )
    _set_local(session, "app.privacy_locator_hash", context.privacy_locator_hash or "")


def apply_registration_rls_context(session: Session, context: RegistrationRlsContext) -> None:
    """Bind one public registration request and clear authenticated realms."""

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _clear_customer_context(session)
    _clear_platform_context(session)
    _set_local(
        session,
        "app.registration_id",
        str(context.registration_id) if context.registration_id else "",
    )
    _set_local(session, "app.registration_token_hash", context.token_hash or "")
    _set_local(session, "app.registration_email_hash", context.email_hash or "")
    _set_local(
        session,
        "app.registration_idempotency_key",
        context.idempotency_key or "",
    )
    _set_local(session, "app.onboarding_id", "")


def apply_onboarding_rls_context(session: Session, context: OnboardingRlsContext) -> None:
    """Bind one trusted onboarding worker and clear all unrelated realms."""

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _clear_customer_context(session)
    _clear_platform_context(session)
    _set_local(session, "app.registration_token_hash", "")
    _set_local(session, "app.registration_email_hash", "")
    _set_local(session, "app.registration_idempotency_key", "")
    _set_local(
        session,
        "app.registration_id",
        str(context.registration_id) if context.registration_id else "",
    )
    _set_local(
        session,
        "app.onboarding_id",
        str(context.onboarding_id) if context.onboarding_id else "",
    )
    _set_local(session, "app.actor_id", str(context.actor_id) if context.actor_id else "")
    _set_local(session, "app.tenant_id", str(context.tenant_id) if context.tenant_id else "")


def _clear_registration_context(session: Session) -> None:
    for name in (
        "app.registration_id",
        "app.registration_token_hash",
        "app.registration_email_hash",
        "app.registration_idempotency_key",
        "app.onboarding_id",
    ):
        _set_local(session, name, "")


def _clear_customer_context(session: Session) -> None:
    for name in (
        "app.actor_id",
        "app.tenant_id",
        "app.space_id",
        "app.api_credential_id",
        "app.invitation_token_hash",
        "app.scim_token_hash",
        "app.privacy_locator_hash",
    ):
        _set_local(session, name, "")


def _clear_platform_context(session: Session) -> None:
    for name in (
        "app.platform_principal_id",
        "app.platform_session_token_hash",
        "app.platform_identity_issuer",
        "app.platform_identity_subject",
        "app.platform_target_tenant_id",
        "app.platform_target_user_id",
        "app.platform_target_identity_conflict_id",
        "app.platform_target_support_grant_id",
        "app.platform_target_admin_operation_id",
        "app.platform_support_session_token_hash",
        "app.platform_privacy_manifest_id",
    ):
        _set_local(session, name, "")
