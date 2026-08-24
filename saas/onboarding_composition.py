"""Supported production composition for self-service Tenant onboarding.

The generic Outbox process deliberately knows nothing about customer identity,
Billing, or Runtime adapters.  This module is the narrow composition boundary
that wires those authorities together without reusing the dispatcher database
login for domain writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.compatibility import RequestContext
from saas.control_plane.execution import (
    ExecutionControlPlane,
    ExecutionRevisionSet,
    RunAdmission,
)
from saas.control_plane.onboarding import (
    EmailVerificationSender,
    OnboardingOutboxPublisher,
    OnboardingPolicy,
    RegistrationRateLimiter,
    SelfServiceOnboardingService,
    TenantOnboardingCoordinator,
    VerificationEnvelopeKeyring,
)
from saas.control_plane.onboarding_workflow import (
    OnboardingScope,
    OnboardingWorkflowError,
    OnboardingWorkflowResult,
    RuntimePartitionProvisioner,
    TenantOnboardingWorkflow,
)
from saas.control_plane.outbox import OutboxPublisher

OnboardingDatabaseAuthority = Literal["registration", "onboarding", "execution"]
_ONBOARDING_DATABASE_ROLES: dict[OnboardingDatabaseAuthority, str] = {
    "registration": "saas_registration",
    "onboarding": "saas_onboarding",
    "execution": "saas_executor",
}


@dataclass(frozen=True, slots=True)
class TenantOnboardingWorkflowConfig:
    """Bounded lease and retry policy for one onboarding worker deployment."""

    lease_duration: timedelta = timedelta(minutes=2)
    max_attempts: int = 3
    retry_base: timedelta = timedelta(seconds=5)

    def __post_init__(self) -> None:
        if self.lease_duration <= timedelta(0):
            raise ValueError("onboarding lease duration must be positive")
        if self.max_attempts < 1:
            raise ValueError("onboarding max attempts must be positive")
        if self.retry_base <= timedelta(0):
            raise ValueError("onboarding retry base must be positive")


@dataclass(frozen=True, slots=True)
class TenantOnboardingDependencies:
    """Explicit authorities required by the onboarding composition.

    Production deployments must bind the three factories to their respective
    non-bypass PostgreSQL logins: ``saas_registration``, ``saas_onboarding``,
    and ``saas_executor``.  The dispatcher factory is intentionally absent;
    the generic Outbox worker owns only its restricted dispatcher connection.
    """

    registration_sessions: sessionmaker[Session]
    onboarding_sessions: sessionmaker[Session]
    execution_sessions: sessionmaker[Session]
    policy: OnboardingPolicy
    envelopes: VerificationEnvelopeKeyring
    rate_limiter: RegistrationRateLimiter
    email_sender: EmailVerificationSender
    runtime: RuntimePartitionProvisioner
    fallback: OutboxPublisher | None = None

    def __post_init__(self) -> None:
        for name, factory in (
            ("registration_sessions", self.registration_sessions),
            ("onboarding_sessions", self.onboarding_sessions),
            ("execution_sessions", self.execution_sessions),
        ):
            if not callable(factory):
                raise TypeError(f"{name} must be a SQLAlchemy Session factory")
        for name, dependency, methods in (
            ("rate_limiter", self.rate_limiter, ("require",)),
            ("email_sender", self.email_sender, ("send_verification",)),
            (
                "runtime",
                self.runtime,
                (
                    "allocate_partition",
                    "provision_default_project",
                    "compensate_default_project",
                    "compensate_partition",
                ),
            ),
        ):
            if any(not callable(getattr(dependency, method, None)) for method in methods):
                raise TypeError(f"onboarding {name} adapter is incomplete")
        if self.fallback is not None and not callable(getattr(self.fallback, "publish", None)):
            raise TypeError("onboarding fallback must provide publish()")
        self._require_separate_postgresql_authorities()

    def _require_separate_postgresql_authorities(self) -> None:
        authorities: tuple[tuple[OnboardingDatabaseAuthority, sessionmaker[Session]], ...] = (
            ("registration", self.registration_sessions),
            ("onboarding", self.onboarding_sessions),
            ("execution", self.execution_sessions),
        )
        binds = tuple(_session_bind(factory) for _, factory in authorities)
        if any(bind is None for bind in binds):
            raise RuntimeError("onboarding Session factories must be bound")
        if not any(bind is not None and bind.dialect.name == "postgresql" for bind in binds):
            return
        if any(bind is None or bind.dialect.name != "postgresql" for bind in binds):
            raise RuntimeError("onboarding production authorities must all use PostgreSQL")
        if len({id(bind) for bind in binds}) != len(binds):
            raise RuntimeError(
                "registration, onboarding, and execution require separate PostgreSQL engines"
            )
        for (authority, _), bind in zip(authorities, binds, strict=True):
            assert bind is not None
            verify_onboarding_database_authority(bind, authority=authority)


@dataclass(frozen=True, slots=True)
class ObservedFirstRunAdmission:
    """A committed Run admission paired with durable onboarding completion."""

    admission: RunAdmission
    onboarding: OnboardingWorkflowResult


class CommittedRunAdmissionObserver:
    """Record only a normally admitted Run that is visible after commit.

    Callers must invoke :meth:`record_committed_admission` only after
    ``ExecutionControlPlane.admit_run`` returns.  The workflow then performs an
    independent read of the Run, quota reservation, and ``run.queued`` event;
    an invented or uncommitted ``RunAdmission`` cannot complete onboarding.
    """

    def __init__(self, workflow: TenantOnboardingWorkflow) -> None:
        self._workflow = workflow

    def record_committed_admission(
        self,
        *,
        scope: OnboardingScope,
        request: RequestContext,
        project_id: UUID,
        admission: RunAdmission,
        now: datetime | None = None,
    ) -> OnboardingWorkflowResult:
        if (
            scope.actor_id != request.actor_id
            or scope.tenant_id != request.tenant_id
            or request.space_id is None
            or (request.project_id is not None and request.project_id != project_id)
            or admission.status == "created"
        ):
            raise OnboardingWorkflowError(
                "first_run_scope_mismatch",
                "first Run admission does not match the onboarding scope",
                retryable=False,
            )
        return self._workflow.record_first_run(scope, run_id=admission.run_id, now=now)


class OnboardingFirstRunAdmissionAdapter:
    """Admit through the normal execution authority, then record after commit.

    If observation fails, the Run remains committed.  Retrying this method with
    the same execution idempotency key replays that Run and safely retries the
    onboarding observation.
    """

    def __init__(
        self,
        execution: ExecutionControlPlane,
        observer: CommittedRunAdmissionObserver,
    ) -> None:
        self._execution = execution
        self._observer = observer

    def admit_first_run(
        self,
        scope: OnboardingScope,
        request: RequestContext,
        *,
        project_id: UUID,
        task_id: UUID,
        session_id: UUID | None,
        input_payload: dict[str, object],
        quota_resource: str,
        quota_units: int,
        idempotency_key: str,
        revisions: ExecutionRevisionSet,
        queue_class: str = "interactive",
        priority: int = 0,
        observed_at: datetime | None = None,
    ) -> ObservedFirstRunAdmission:
        admission = self._execution.admit_run(
            request,
            project_id=project_id,
            task_id=task_id,
            session_id=session_id,
            input_payload=input_payload,
            quota_resource=quota_resource,
            quota_units=quota_units,
            idempotency_key=idempotency_key,
            revisions=revisions,
            queue_class=queue_class,
            priority=priority,
        )
        onboarding = self._observer.record_committed_admission(
            scope=scope,
            request=request,
            project_id=project_id,
            admission=admission,
            now=observed_at,
        )
        return ObservedFirstRunAdmission(admission=admission, onboarding=onboarding)


@dataclass(frozen=True, slots=True)
class TenantOnboardingComposition:
    """Validated publisher composition exposed to the generic Outbox worker."""

    registrations: SelfServiceOnboardingService
    coordinator: TenantOnboardingCoordinator
    workflow: TenantOnboardingWorkflow
    publisher: OnboardingOutboxPublisher
    first_run_observer: CommittedRunAdmissionObserver

    def validate_outbox_configuration(self) -> None:
        """Fail process startup if workflow routing was not preserved."""

        if not callable(getattr(self.workflow, "handle_event", None)):
            raise RuntimeError("Tenant onboarding workflow is not configured")
        if not callable(getattr(self.publisher, "publish", None)):
            raise RuntimeError("Tenant onboarding Outbox publisher is not configured")

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        self.publisher.publish(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )

    def execution_adapter(
        self, execution: ExecutionControlPlane
    ) -> OnboardingFirstRunAdmissionAdapter:
        return OnboardingFirstRunAdmissionAdapter(execution, self.first_run_observer)


def create_tenant_onboarding_composition(
    dependencies: TenantOnboardingDependencies,
    *,
    config: TenantOnboardingWorkflowConfig | None = None,
) -> TenantOnboardingComposition:
    """Build the only supported onboarding Outbox publisher composition."""

    effective_config = config or TenantOnboardingWorkflowConfig()
    registrations = SelfServiceOnboardingService(
        dependencies.registration_sessions,
        policy=dependencies.policy,
        envelope_keyring=dependencies.envelopes,
        rate_limiter=dependencies.rate_limiter,
    )
    coordinator = TenantOnboardingCoordinator(
        dependencies.onboarding_sessions,
        policy=dependencies.policy,
    )
    workflow = TenantOnboardingWorkflow(
        dependencies.onboarding_sessions,
        runtime=dependencies.runtime,
        execution_session_factory=dependencies.execution_sessions,
        lease_duration=effective_config.lease_duration,
        max_attempts=effective_config.max_attempts,
        retry_base=effective_config.retry_base,
    )
    publisher = OnboardingOutboxPublisher(
        registrations=registrations,
        coordinator=coordinator,
        envelopes=dependencies.envelopes,
        email_sender=dependencies.email_sender,
        workflow=workflow,
        fallback=dependencies.fallback,
    )
    composition = TenantOnboardingComposition(
        registrations=registrations,
        coordinator=coordinator,
        workflow=workflow,
        publisher=publisher,
        first_run_observer=CommittedRunAdmissionObserver(workflow),
    )
    composition.validate_outbox_configuration()
    return composition


def validate_production_outbox_publisher(publisher: OutboxPublisher) -> None:
    """Reject the raw optional-workflow publisher at the process boundary."""

    if isinstance(publisher, OnboardingOutboxPublisher):
        raise RuntimeError(
            "raw OnboardingOutboxPublisher is unsupported in production; "
            "use create_tenant_onboarding_composition()"
        )
    validator = getattr(publisher, "validate_outbox_configuration", None)
    if validator is not None:
        if not callable(validator):
            raise TypeError("Outbox publisher validation hook is not callable")
        validator()


def verify_onboarding_database_authority(
    engine: Engine,
    *,
    authority: OnboardingDatabaseAuthority,
) -> None:
    """Fail startup unless one Engine has exactly one onboarding authority.

    The check deliberately runs through the Engine itself instead of trusting
    its URL or deployment configuration.  A production login must be the
    original PostgreSQL session identity, inherit one dedicated NOLOGIN role,
    and have no transitive role-membership escape hatch.
    """

    if engine.dialect.name != "postgresql":
        raise RuntimeError("onboarding production authorities require PostgreSQL")
    expected_role = _ONBOARDING_DATABASE_ROLES[authority]
    with engine.connect() as connection:
        schema_facts = connection.execute(
            sa.text("SELECT current_schema(), current_schemas(false)")
        ).one()
        login_facts = connection.execute(
            sa.text(
                "SELECT current_user, session_user, role.rolcanlogin, role.rolsuper, "
                "role.rolbypassrls, role.rolinherit "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
        base_facts = connection.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = :expected_role"
            ),
            {"expected_role": expected_role},
        ).one_or_none()
        login_memberships = (
            connection.execute(
                sa.text(
                    "SELECT granted.rolname FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE member.rolname = current_user ORDER BY granted.rolname"
                )
            )
            .scalars()
            .all()
        )
        base_memberships = (
            connection.execute(
                sa.text(
                    "SELECT granted.rolname FROM pg_auth_members AS membership "
                    "JOIN pg_roles AS member ON member.oid = membership.member "
                    "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                    "WHERE member.rolname = :expected_role ORDER BY granted.rolname"
                ),
                {"expected_role": expected_role},
            )
            .scalars()
            .all()
        )

    current_schema, search_path = schema_facts
    if current_schema != "public" or list(search_path) != ["public"]:
        raise RuntimeError(f"{authority} database login must use only the public search_path")
    current_user, session_user, can_login, is_superuser, bypasses_rls, inherits_roles = login_facts
    if current_user != session_user:
        raise RuntimeError(f"{authority} connection must not start under an assumed database role")
    if not can_login or is_superuser or bypasses_rls or not inherits_roles:
        raise RuntimeError(f"{authority} database login violates the non-bypass RLS posture")
    if base_facts != (False, False, False, True):
        raise RuntimeError(f"{expected_role} must remain a NOLOGIN non-bypass base role")
    if list(login_memberships) != [expected_role] or base_memberships:
        raise RuntimeError(f"{authority} database login must inherit only {expected_role}")


def _session_bind(factory: sessionmaker[Session]) -> Engine | None:
    bind = factory.kw.get("bind")
    return cast(Engine | None, bind)


__all__ = [
    "CommittedRunAdmissionObserver",
    "ObservedFirstRunAdmission",
    "OnboardingDatabaseAuthority",
    "OnboardingFirstRunAdmissionAdapter",
    "TenantOnboardingComposition",
    "TenantOnboardingDependencies",
    "TenantOnboardingWorkflowConfig",
    "create_tenant_onboarding_composition",
    "validate_production_outbox_publisher",
    "verify_onboarding_database_authority",
]
