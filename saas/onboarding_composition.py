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
    SharedRegistrationRateLimiter,
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
from saas.control_plane.runtime_provider import ProductionRuntimePartitionAdapter

OnboardingDatabaseAuthority = Literal["registration", "onboarding", "execution", "status"]
_ONBOARDING_DATABASE_ROLES: dict[OnboardingDatabaseAuthority, str] = {
    "registration": "saas_registration",
    "onboarding": "saas_onboarding",
    "execution": "saas_executor",
    "status": "saas_onboarding_status",
}
_STATUS_SELECT_COLUMNS: dict[str, frozenset[str]] = {
    "saas_tenant_onboardings": frozenset(
        {
            "id",
            "user_id",
            "tenant_id",
            "space_id",
            "default_project_id",
            "status",
            "version",
            "trial_ends_at",
            "last_transition_at",
            "created_at",
        }
    ),
    "saas_tenant_memberships": frozenset({"tenant_id", "user_id", "status"}),
    "saas_platform_role_assignments": frozenset({"principal_id", "role", "status", "expires_at"}),
    "saas_platform_support_sessions": frozenset(
        {"principal_id", "token_hash", "revoked_at", "expires_at"}
    ),
}
_STATUS_COLUMN_AUTHORITIES = frozenset(
    (table, column, "SELECT")
    for table, columns in _STATUS_SELECT_COLUMNS.items()
    for column in columns
)
_POSTGRESQL_MAINTAIN_PRIVILEGE_VERSION = 170000


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
            ("rate_limiter", self.rate_limiter, ("consume", "require")),
            ("email_sender", self.email_sender, ("send_verification",)),
            (
                "runtime",
                self.runtime,
                (
                    "binding_snapshot",
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
        self._require_production_rate_limiter()
        self._require_production_runtime_for_postgresql()

    def _require_production_rate_limiter(self) -> None:
        bind = _session_bind(self.registration_sessions)
        if bind is None or bind.dialect.name != "postgresql":
            return
        if type(self.rate_limiter) is not SharedRegistrationRateLimiter:
            raise RuntimeError(
                "PostgreSQL registration rate limiter is construction-sealed; "
                "use SharedRegistrationRateLimiter"
            )
        limiter = cast(SharedRegistrationRateLimiter, self.rate_limiter)
        if not limiter.is_bound_to(self.registration_sessions):
            raise RuntimeError(
                "PostgreSQL registration rate limiter must use the registration authority"
            )

    def _require_production_runtime_for_postgresql(self) -> None:
        binds = (
            _session_bind(self.registration_sessions),
            _session_bind(self.onboarding_sessions),
            _session_bind(self.execution_sessions),
        )
        if not any(bind is not None and bind.dialect.name == "postgresql" for bind in binds):
            return
        if not isinstance(self.runtime, ProductionRuntimePartitionAdapter):
            raise RuntimeError("PostgreSQL onboarding requires ProductionRuntimePartitionAdapter")
        self.runtime.assert_production_ready()

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
            sa.text(
                "SELECT current_schema(), current_schemas(false), "
                "has_schema_privilege(current_user, 'public', 'CREATE')"
            )
        ).one()
        login_facts = connection.execute(
            sa.text(
                "SELECT current_user, session_user, role.rolcanlogin, role.rolsuper, "
                "role.rolcreatedb, role.rolcreaterole, role.rolreplication, "
                "role.rolbypassrls, role.rolinherit "
                "FROM pg_roles AS role WHERE role.rolname = current_user"
            )
        ).one()
        base_facts = connection.execute(
            sa.text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls, rolinherit "
                "FROM pg_roles WHERE rolname = :expected_role"
            ),
            {"expected_role": expected_role},
        ).one_or_none()
        membership_projection = (
            "granted.rolname, membership.admin_option, "
            "COALESCE((to_jsonb(membership) ->> 'inherit_option')::boolean, true), "
            "COALESCE((to_jsonb(membership) ->> 'set_option')::boolean, true) "
        )
        login_memberships = connection.execute(
            sa.text(
                f"SELECT {membership_projection}"
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE member.rolname = current_user ORDER BY granted.rolname"
            )
        ).all()
        base_memberships = connection.execute(
            sa.text(
                f"SELECT {membership_projection}"
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "WHERE member.rolname = :expected_role ORDER BY granted.rolname"
            ),
            {"expected_role": expected_role},
        ).all()
        direct_object_authorities = connection.execute(
            sa.text(
                "WITH login AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
                "direct_authority AS ("
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(object.relacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_attribute attribute "
                "JOIN pg_class object ON object.oid = attribute.attrelid "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "CROSS JOIN LATERAL aclexplode(attribute.attacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "CROSS JOIN LATERAL aclexplode(object.proacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_namespace object "
                "CROSS JOIN LATERAL aclexplode(object.nspacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE object.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_database object "
                "CROSS JOIN LATERAL aclexplode(object.datacl) grant_acl "
                "JOIN login ON grant_acl.grantee = login.oid "
                "WHERE object.datname = current_database() UNION ALL "
                "SELECT 1 FROM pg_default_acl defaults JOIN login "
                "ON defaults.defaclrole = login.oid UNION ALL "
                "SELECT 1 FROM pg_class object "
                "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                "JOIN login ON object.relowner = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_proc object "
                "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                "JOIN login ON object.proowner = login.oid "
                "WHERE namespace.nspname = 'public' UNION ALL "
                "SELECT 1 FROM pg_namespace object JOIN login ON object.nspowner = login.oid "
                "WHERE object.nspname = 'public') "
                "SELECT count(*) FROM direct_authority"
            )
        ).scalar_one()
        status_column_authorities: tuple[tuple[str, str, str], ...] = ()
        status_table_authorities: tuple[tuple[str, str], ...] = ()
        status_sequence_authorities: tuple[tuple[str, str], ...] = ()
        status_delegable_authorities = 0
        if authority == "status":
            server_version_num = int(
                connection.execute(
                    sa.text("SELECT current_setting('server_version_num')::integer")
                ).scalar_one()
            )
            # Owners and ACL grantees with a grant option can delegate authority
            # beyond the audited status projection.  Default ACLs are rejected
            # even without a grant option because they silently widen future
            # objects.  Inspect catalogs directly: has_*_privilege() deliberately
            # collapses ordinary and grantable privileges.
            status_delegable_authorities = int(
                connection.execute(
                    sa.text(
                        "WITH base_role AS ("
                        "SELECT oid FROM pg_roles WHERE rolname = :expected_role), "
                        "delegable_authority AS ("
                        "SELECT 1 FROM pg_class object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                        "CROSS JOIN LATERAL aclexplode(object.relacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE namespace.nspname = 'public' AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_attribute attribute "
                        "JOIN pg_class object ON object.oid = attribute.attrelid "
                        "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                        "CROSS JOIN LATERAL aclexplode(attribute.attacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE namespace.nspname = 'public' AND attribute.attnum > 0 "
                        "AND NOT attribute.attisdropped AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_proc object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                        "CROSS JOIN LATERAL aclexplode(object.proacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE namespace.nspname = 'public' AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_type object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                        "CROSS JOIN LATERAL aclexplode(object.typacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE namespace.nspname = 'public' AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_namespace object "
                        "CROSS JOIN LATERAL aclexplode(object.nspacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE object.nspname = 'public' AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_database object "
                        "CROSS JOIN LATERAL aclexplode(object.datacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "WHERE object.datname = current_database() AND grant_acl.is_grantable "
                        "UNION ALL SELECT 1 FROM pg_class object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.relnamespace "
                        "JOIN base_role ON object.relowner = base_role.oid "
                        "WHERE namespace.nspname = 'public' "
                        "UNION ALL SELECT 1 FROM pg_proc object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.pronamespace "
                        "JOIN base_role ON object.proowner = base_role.oid "
                        "WHERE namespace.nspname = 'public' "
                        "UNION ALL SELECT 1 FROM pg_type object "
                        "JOIN pg_namespace namespace ON namespace.oid = object.typnamespace "
                        "JOIN base_role ON object.typowner = base_role.oid "
                        "WHERE namespace.nspname = 'public' "
                        "UNION ALL SELECT 1 FROM pg_namespace object "
                        "JOIN base_role ON object.nspowner = base_role.oid "
                        "WHERE object.nspname = 'public' "
                        "UNION ALL SELECT 1 FROM pg_database object "
                        "JOIN base_role ON object.datdba = base_role.oid "
                        "WHERE object.datname = current_database() "
                        "UNION ALL SELECT 1 FROM pg_default_acl defaults "
                        "JOIN base_role ON defaults.defaclrole = base_role.oid "
                        "LEFT JOIN pg_namespace namespace "
                        "ON namespace.oid = defaults.defaclnamespace "
                        "WHERE defaults.defaclnamespace = 0 OR namespace.nspname = 'public' "
                        "UNION ALL SELECT 1 FROM pg_default_acl defaults "
                        "CROSS JOIN LATERAL aclexplode(defaults.defaclacl) grant_acl "
                        "JOIN base_role ON grant_acl.grantee = base_role.oid "
                        "LEFT JOIN pg_namespace namespace "
                        "ON namespace.oid = defaults.defaclnamespace "
                        "WHERE defaults.defaclnamespace = 0 OR namespace.nspname = 'public') "
                        "SELECT count(*) FROM delegable_authority"
                    ),
                    {"expected_role": expected_role},
                ).scalar_one()
            )
            status_column_authorities = tuple(
                (str(row[0]), str(row[1]), str(row[2]))
                for row in connection.execute(
                    sa.text(
                        "SELECT object.relname, attribute.attname, "
                        "privilege.privilege_type FROM pg_class AS object "
                        "JOIN pg_namespace AS namespace "
                        "ON namespace.oid = object.relnamespace "
                        "JOIN pg_attribute AS attribute "
                        "ON attribute.attrelid = object.oid "
                        "CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), "
                        "('REFERENCES')) AS privilege(privilege_type) "
                        "WHERE namespace.nspname = 'public' "
                        "AND object.relkind IN ('r', 'p', 'v', 'm', 'f') "
                        "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                        "AND has_column_privilege(CAST(:expected_role AS text), "
                        "object.oid, attribute.attnum, privilege.privilege_type) "
                        "ORDER BY object.relname, attribute.attnum, privilege.privilege_type"
                    ),
                    {"expected_role": expected_role},
                ).all()
            )
            table_privileges = ["DELETE", "TRUNCATE", "TRIGGER"]
            if server_version_num >= _POSTGRESQL_MAINTAIN_PRIVILEGE_VERSION:
                table_privileges.append("MAINTAIN")
            table_privilege_values = ", ".join(
                f"('{privilege}')" for privilege in table_privileges
            )
            status_table_authorities = tuple(
                (str(row[0]), str(row[1]))
                for row in connection.execute(
                    sa.text(
                        "SELECT object.relname, privilege.privilege_type "
                        "FROM pg_class AS object JOIN pg_namespace AS namespace "
                        "ON namespace.oid = object.relnamespace "
                        f"CROSS JOIN (VALUES {table_privilege_values}) "
                        "AS privilege(privilege_type) "
                        "WHERE namespace.nspname = 'public' "
                        "AND object.relkind IN ('r', 'p', 'v', 'm', 'f') "
                        "AND has_table_privilege(CAST(:expected_role AS text), "
                        "object.oid, privilege.privilege_type) "
                        "ORDER BY object.relname, privilege.privilege_type"
                    ),
                    {"expected_role": expected_role},
                ).all()
            )
            status_sequence_authorities = tuple(
                (str(row[0]), str(row[1]))
                for row in connection.execute(
                    sa.text(
                        "SELECT object.relname, privilege.privilege_type "
                        "FROM pg_class AS object JOIN pg_namespace AS namespace "
                        "ON namespace.oid = object.relnamespace "
                        "CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) "
                        "AS privilege(privilege_type) "
                        "WHERE namespace.nspname = 'public' AND object.relkind = 'S' "
                        "AND has_sequence_privilege(CAST(:expected_role AS text), "
                        "object.oid, privilege.privilege_type) "
                        "ORDER BY object.relname, privilege.privilege_type"
                    ),
                    {"expected_role": expected_role},
                ).all()
            )

    current_schema, search_path, can_create_in_schema = schema_facts
    if current_schema != "public" or list(search_path) != ["public"] or can_create_in_schema:
        raise RuntimeError(f"{authority} database login must use only the public search_path")
    (
        current_user,
        session_user,
        can_login,
        is_superuser,
        can_create_database,
        can_create_role,
        can_replicate,
        bypasses_rls,
        inherits_roles,
    ) = login_facts
    if current_user != session_user:
        raise RuntimeError(f"{authority} connection must not start under an assumed database role")
    if (
        not can_login
        or is_superuser
        or can_create_database
        or can_create_role
        or can_replicate
        or bypasses_rls
        or not inherits_roles
    ):
        raise RuntimeError(f"{authority} database login violates the non-bypass RLS posture")
    if base_facts != (False, False, False, False, False, False, True):
        raise RuntimeError(f"{expected_role} must remain a NOLOGIN non-bypass base role")
    if len(login_memberships) != 1 or login_memberships[0][0] != expected_role:
        raise RuntimeError(f"{authority} database login must inherit only {expected_role}")
    if tuple(login_memberships[0][1:]) != (False, True, True):
        raise RuntimeError(f"{authority} database login has unsafe role membership options")
    if base_memberships:
        raise RuntimeError(f"{expected_role} must not inherit another database role")
    if direct_object_authorities:
        raise RuntimeError(
            f"{authority} database login must not own objects or receive direct object grants"
        )
    if authority == "status" and status_delegable_authorities:
        raise RuntimeError(
            "status base role must not own objects, hold grant options, or define default ACLs"
        )
    if authority == "status" and (
        frozenset(status_column_authorities) != _STATUS_COLUMN_AUTHORITIES
        or status_table_authorities
        or status_sequence_authorities
    ):
        raise RuntimeError(
            "status base role privileges differ from the exact read-only projection"
        )


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
