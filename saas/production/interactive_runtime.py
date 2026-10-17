"""Bind an authenticated interactive lease to the existing Runtime context."""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.query_context import query_name_scope
from omnigent.entities import Conversation
from omnigent.server.auth import LEVEL_EDIT
from omnigent.server.routes._auth_helpers import require_access_and_level
from omnigent.server.schemas import SessionEventInput
from saas.compatibility import RuntimeContext, bind_runtime_context
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.dispatch_binding import dispatch_requirements_hash
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.interactive_execution import MANAGED_EXECUTION_SNAPSHOT_KEY
from saas.control_plane.interactive_launch import interactive_conversation_launch
from saas.control_plane.interactive_run_route import (
    INTERACTIVE_EXECUTION_KIND,
    INTERACTIVE_QUEUE_CLASS,
    decode_interactive_run_route,
    interactive_session_identity,
)
from saas.control_plane.resolver import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.runner_execution_spec import production_run_execution_spec
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerRegistrationRecord,
)
from saas.control_plane.tenant_model_catalog import TenantModelCatalog
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    RunnerControlClientLease,
    RunnerControlError,
)

if TYPE_CHECKING:
    from saas.production.model_run_credentials import IssuedModelRunCredential


class InteractiveRunnerIdentity(Protocol):
    @property
    def runner_id(self) -> UUID: ...

    @property
    def connection_generation(self) -> int: ...

    @property
    def product_revision(self) -> str: ...

    @property
    def image_digest(self) -> str: ...


class InteractiveLeaseControl(Protocol):
    async def heartbeat_run(self, lease: RunnerControlClientLease) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class AuthorizedInteractiveInput:
    """A current delegated context, not a model or billing grant."""

    run_id: UUID
    fence_token: int
    runtime: RuntimeContext
    session_id: str
    conversation: Conversation = field(repr=False)
    event: SessionEventInput = field(repr=False)
    launch: dict[str, Any] = field(repr=False)
    publication: dict[str, object] = field(repr=False)


def _reject() -> NoReturn:
    raise RunnerControlError(
        "interactive_runtime_authority_invalid", "Interactive Runtime authority changed"
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def resolve_interactive_run_runtime(
    run: RunRecord,
    *,
    app_sessions: sessionmaker[Session],
    resolver: SqlAlchemyContextResolver,
    authorization: ProjectAuthorizer,
) -> RuntimeContext:
    """Recheck the same delegated Session, project and price binding for every consumer."""
    assert run.created_by is not None
    route = decode_interactive_run_route(run.input)
    request = resolver.resolve_request_context(
        actor_id=run.created_by,
        tenant_id=run.tenant_id,
        space_id=run.space_id,
        trace_id=f"interactive-run:{run.id}",
    )
    request = authorization.bind_project_context(
        request, action="run.create", project_id=run.project_id
    )
    runtime = resolver.resolve_existing_resource(
        request, resource_type="project", saas_resource_id=run.project_id, action="run.create"
    )
    if (
        runtime.runtime_partition_id != route.partition_id
        or runtime.placement_generation != route.partition_generation
    ):
        _reject()
    with query_name_scope("saas.interactive_runtime.verify_session_binding"), app_sessions() as db:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=runtime.actor_id,
                tenant_id=runtime.tenant_id,
                space_id=runtime.space_id,
                project_id=runtime.project_id,
            ),
        )
        session = db.get(ExecutionSessionRecord, run.session_id)
        binding = db.scalar(
            sa.select(RuntimeResourceBindingRecord).where(
                RuntimeResourceBindingRecord.runtime_partition_id == route.partition_id,
                RuntimeResourceBindingRecord.saas_resource_id == run.project_id,
                RuntimeResourceBindingRecord.resource_type == "project",
                RuntimeResourceBindingRecord.status == "active",
                RuntimeResourceBindingRecord.binding_generation == runtime.binding_generation,
            )
        )
        if (
            session is None
            or session.tenant_id != run.tenant_id
            or session.space_id != run.space_id
            or session.project_id != run.project_id
            or session.status != "active"
            or session.customer_pricing_snapshot_id != run.customer_pricing_snapshot_id
            or not session.customer_pricing_frozen
            or binding is None
            or binding.runtime_resource_id != route.project_id
            or binding.project_id != run.project_id
            or binding.partition_generation != route.partition_generation
        ):
            _reject()
    return runtime


class InteractiveRuntimeAuthority:
    """Read only the claimed Run, then re-authorize its real human in App scope.

    Runner sessions must use the existing identity-pinned saas_runner_agent login;
    App sessions remain separate. Composition owns fleet/role verification.
    """

    def __init__(
        self,
        *,
        identity: InteractiveRunnerIdentity,
        control: InteractiveLeaseControl,
        runner_sessions: sessionmaker[Session],
        app_sessions: sessionmaker[Session],
        compatibility: RuntimeCompatibilityPolicy,
        conversation_store: Any,
        permission_store: Any,
        verify_machine_database: Callable[[], None] | None = None,
    ) -> None:
        self._identity = identity
        self._control = control
        self._runner_sessions = runner_sessions
        self._app_sessions = app_sessions
        self._authorization = ProjectAuthorizer(app_sessions)
        self._resolver = SqlAlchemyContextResolver(
            app_sessions, compatibility, project_authorizer=self._authorization
        )
        self._catalog = TenantModelCatalog(app_sessions.kw["bind"])
        self._conversations = conversation_store
        self._permissions = permission_store
        self._verify_machine_database = verify_machine_database

    def _read_run(self, lease: RunnerControlClientLease) -> RunRecord:
        envelope = lease.execution_envelope
        if (
            envelope is None
            or envelope.execution_kind != INTERACTIVE_EXECUTION_KIND
            or envelope.change_set_id is not None
            or envelope.launch_argv
            or envelope.runner_id != self._identity.runner_id
            or envelope.run_id != lease.run_id
            or envelope.fence_token != lease.fence_token
            or envelope.product_revision != self._identity.product_revision
            or envelope.image_digest != self._identity.image_digest
        ):
            _reject()
        assert envelope is not None
        checked_at = datetime.now(timezone.utc)
        with (
            query_name_scope("saas.interactive_runtime.read_leased_input"),
            self._runner_sessions() as db,
        ):
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=envelope.tenant_id,
                    space_id=envelope.space_id,
                    project_id=envelope.project_id,
                ),
            )
            run = db.get(RunRecord, lease.run_id)
            dispatch = db.get(RunDispatchRecord, lease.run_id)
            capability = db.execute(
                sa.select(
                    CapabilityTokenRecord.tenant_id,
                    CapabilityTokenRecord.space_id,
                    CapabilityTokenRecord.project_id,
                    CapabilityTokenRecord.run_id,
                    CapabilityTokenRecord.runner_id,
                    CapabilityTokenRecord.runner_connection_generation,
                    CapabilityTokenRecord.dispatch_generation,
                    CapabilityTokenRecord.fence_token,
                    CapabilityTokenRecord.allowed_actions,
                    CapabilityTokenRecord.resource_scope,
                    CapabilityTokenRecord.revoked_at,
                    CapabilityTokenRecord.expires_at,
                ).where(CapabilityTokenRecord.id == lease.capability_id)
            ).one_or_none()
            runner = db.execute(
                sa.select(
                    RunnerRegistrationRecord.status,
                    RunnerRegistrationRecord.connection_generation,
                    RunnerRegistrationRecord.pool_id,
                ).where(RunnerRegistrationRecord.id == envelope.runner_id)
            ).one_or_none()
            if (
                run is None
                or dispatch is None
                or capability is None
                or runner is None
                or run.tenant_id != envelope.tenant_id
                or run.space_id != envelope.space_id
                or run.project_id != envelope.project_id
                or run.product_revision != envelope.product_revision
                or run.queue_class != INTERACTIVE_QUEUE_CLASS
                or run.status != "running"
                or run.created_by is None
                or run.created_by_service_account_id is not None
                or run.lease_owner != str(envelope.runner_id)
                or run.lease_token != lease.lease_token
                or run.fence_token != envelope.fence_token
                or run.lease_expires_at is None
                or _aware(run.lease_expires_at) <= checked_at
                or not run.customer_pricing_frozen
                or run.customer_pricing_snapshot_id is None
                or runner.status not in {"online", "draining"}
                or runner.connection_generation != self._identity.connection_generation
                or dispatch.pool_id != runner.pool_id
                or dispatch.status != "leased"
                or dispatch.queue_class != run.queue_class
                or dispatch.selected_runner_id != envelope.runner_id
                or dispatch.selected_failure_domain != lease.failure_domain
                or dispatch.dispatch_generation != lease.dispatch_generation
                or dispatch.execution_profile_id != envelope.execution_profile_id
                or dispatch.execution_profile_hash != envelope.execution_profile_hash
                or dispatch.egress_policy_id != envelope.egress_policy_id
                or dispatch.egress_policy_hash != envelope.egress_policy_hash
                or dispatch.requirements_hash
                != dispatch_requirements_hash(
                    tenant_id=dispatch.tenant_id,
                    space_id=dispatch.space_id,
                    project_id=dispatch.project_id,
                    pool_id=dispatch.pool_id,
                    execution_profile_id=dispatch.execution_profile_id,
                    execution_profile_hash=dispatch.execution_profile_hash,
                    egress_policy_id=dispatch.egress_policy_id,
                    egress_policy_hash=dispatch.egress_policy_hash,
                    queue_class=dispatch.queue_class,
                    required_capabilities=list(dispatch.required_capabilities),
                    cost_units=dispatch.cost_units,
                    eligible_at=dispatch.eligible_at,
                    max_wait_at=dispatch.max_wait_at,
                )
                or capability.tenant_id != run.tenant_id
                or capability.space_id != run.space_id
                or capability.project_id != run.project_id
                or capability.run_id != run.id
                or capability.runner_id != envelope.runner_id
                or capability.runner_connection_generation != runner.connection_generation
                or capability.dispatch_generation != lease.dispatch_generation
                or capability.fence_token != lease.fence_token
                or capability.revoked_at is not None
                or _aware(capability.expires_at) <= checked_at
                or set(capability.allowed_actions)
                != {"run.execute", "runtime.interactive.execute"}
            ):
                _reject()
            assert run is not None and capability is not None
            spec = production_run_execution_spec(run.input)
            route = decode_interactive_run_route(run.input)
            expected_scope = {
                "tenant_id": str(run.tenant_id),
                "space_id": str(run.space_id),
                "project_id": str(run.project_id),
                "run_id": str(run.id),
                "runner_id": str(envelope.runner_id),
                "session_id": str(run.session_id),
                "runtime_partition_id": str(route.partition_id),
                "runtime_partition_generation": str(route.partition_generation),
                "runtime_session_id": route.session_id,
                "runtime_project_id": route.project_id,
                "execution_spec_hash": spec.spec_hash,
            }
            if (
                spec.kind != envelope.execution_kind
                or spec.spec_hash != envelope.execution_spec_hash
                or any(
                    capability.resource_scope.get(key) != val
                    for key, val in expected_scope.items()
                )
                or run.session_id
                != interactive_session_identity(
                    run.tenant_id, run.space_id, route.partition_id, route.session_id
                )
            ):
                _reject()
            db.expunge(run)
            return run

    def _resolve_runtime(self, run: RunRecord) -> RuntimeContext:
        return resolve_interactive_run_runtime(
            run,
            app_sessions=self._app_sessions,
            resolver=self._resolver,
            authorization=self._authorization,
        )

    def verify_recovery(self, record) -> None:
        """Historical ownership permits cleanup, never a new execution or model credential."""
        if self._verify_machine_database is not None:
            self._verify_machine_database()
        if (
            record.grant.runner_id != self._identity.runner_id
            or record.connection_generation != self._identity.connection_generation
            or record.product_revision != self._identity.product_revision
            or record.image_digest != self._identity.image_digest
        ):
            _reject()
        with (
            query_name_scope("saas.interactive_runtime.verify_recovery_ownership"),
            self._runner_sessions() as db,
        ):
            scope = record.scope
            if db.get_bind().dialect.name == "postgresql":
                binding = {
                    name: str(getattr(scope, name))
                    for name in (
                        "tenant_id",
                        "space_id",
                        "project_id",
                        "actor_id",
                        "session_id",
                        "partition_id",
                        "official_session_id",
                        "publication_sha256",
                    )
                }
                binding["product_revision"] = record.product_revision
                owned = db.scalar(
                    sa.text(
                        "SELECT public.saas_interactive_recovery_owner_v1("
                        ":run,:fence,:runner,:generation,CAST(:binding AS jsonb))"
                    ),
                    {
                        "run": record.run_id,
                        "fence": record.fence_token,
                        "runner": record.grant.runner_id,
                        "generation": record.connection_generation,
                        "binding": json.dumps(binding, sort_keys=True),
                    },
                )
                if owned is not True:
                    _reject()
                return
            apply_rls_context(
                db,
                RlsContext(
                    tenant_id=scope.tenant_id, space_id=scope.space_id, project_id=scope.project_id
                ),
            )
            run = db.get(RunRecord, record.run_id)
            if (
                run is None
                or run.fence_token != record.fence_token
                or run.tenant_id != scope.tenant_id
                or run.space_id != scope.space_id
                or run.project_id != scope.project_id
                or run.session_id != scope.session_id
                or run.created_by != scope.actor_id
                or run.product_revision != record.product_revision
                or run.queue_class != INTERACTIVE_QUEUE_CLASS
            ):
                _reject()
            route = decode_interactive_run_route(run.input)
            execution = cast(dict[str, Any], run.input["execution"])
            if (
                route.session_id != scope.official_session_id
                or route.partition_id != scope.partition_id
                or execution["model_publication"]["snapshot_sha256"] != scope.publication_sha256
            ):
                _reject()
            capability = db.execute(
                sa.select(CapabilityTokenRecord.id).where(
                    CapabilityTokenRecord.run_id == run.id,
                    CapabilityTokenRecord.runner_id == record.grant.runner_id,
                    CapabilityTokenRecord.runner_connection_generation
                    == record.connection_generation,
                    CapabilityTokenRecord.fence_token == record.fence_token,
                )
            ).first()
            if capability is None:
                _reject()

    async def authorize(self, lease: RunnerControlClientLease) -> AuthorizedInteractiveInput:
        """Recheck lease, current membership, project, session access and frozen input."""
        if self._permissions is None or self._conversations is None:
            _reject()
        if self._verify_machine_database is not None:
            await asyncio.to_thread(self._verify_machine_database)
        run = await asyncio.to_thread(self._read_run, lease)
        # Token hashes are intentionally unreadable to the machine login.
        # The existing mTLS control authority verifies the opaque capability.
        try:
            state = await self._control.heartbeat_run(lease)
        except Exception:  # noqa: BLE001 - redact control and database transport diagnostics.
            raise RunnerControlError(
                "interactive_runtime_authority_invalid", "Interactive Runtime authority changed"
            ) from None
        if state.get("status") != "running":
            _reject()
        runtime = await asyncio.to_thread(self._resolve_runtime, run)
        route = decode_interactive_run_route(run.input)
        execution = run.input["execution"]
        assert isinstance(execution, dict)
        with bind_runtime_context(runtime):
            access = await require_access_and_level(
                runtime.runtime_user_key,
                route.session_id,
                LEVEL_EDIT,
                self._permissions,
                self._conversations,
            )
            conversation = access.conversation or await asyncio.to_thread(
                self._conversations.get_conversation, route.session_id
            )
            if (
                conversation is None
                or conversation.kind != "default"
                or conversation.parent_conversation_id is not None
                or conversation.sub_agent_name is not None
                or conversation.project_id != route.project_id
                or (conversation.inference_snapshot or {}).get(MANAGED_EXECUTION_SNAPSHOT_KEY)
                != execution["model_publication"]
                or interactive_conversation_launch(conversation) != execution["launch"]
                or conversation.model_override != execution["model_publication"]["public_model_id"]
            ):
                _reject()
            await asyncio.to_thread(
                self._catalog.require_version, runtime, execution["model_publication"]
            )
        # Authorization and store reads may have outlived the original lease.
        await asyncio.to_thread(self._read_run, lease)
        assert conversation is not None
        return AuthorizedInteractiveInput(
            run_id=run.id,
            fence_token=run.fence_token,
            runtime=runtime,
            session_id=route.session_id,
            conversation=conversation,
            event=SessionEventInput.model_validate(copy.deepcopy(execution["event"])),
            launch=copy.deepcopy(execution["launch"]),
            publication=copy.deepcopy(execution["model_publication"]),
        )


class ProductionInteractiveRuntimeFactory:
    """Runtime-owned composition; never pass App database authority to a workload."""

    def __init__(
        self,
        *,
        product_revision: str,
        image_digest: str,
        app_sessions: sessionmaker[Session],
        authenticator_sessions: sessionmaker[Session] | None = None,
        compatibility: RuntimeCompatibilityPolicy,
        conversation_store: Any,
        permission_store: Any,
    ) -> None:
        self._product_revision = product_revision
        self._image_digest = image_digest
        self._app_sessions = app_sessions
        self._authenticator_sessions = authenticator_sessions
        self._compatibility = compatibility
        self._conversations = conversation_store
        self._permissions = permission_store

    async def authorize_model(
        self,
        *,
        lease: RunnerControlClientLease,
        identity: InteractiveRunnerIdentity,
        control: MutualTlsRunnerControlClient,
        runner_sessions: sessionmaker[Session],
        fleet_source: Mapping[str, str],
    ) -> tuple[AuthorizedInteractiveInput, IssuedModelRunCredential]:
        """Only the trusted mTLS controller can provision a model credential."""
        from saas.production.model_run_credentials import ModelRunCredentialService

        if self._authenticator_sessions is None or self._authenticator_sessions.kw.get(
            "bind"
        ) is self._app_sessions.kw.get("bind"):
            _reject()
        authority = await asyncio.to_thread(
            self.create_authority,
            identity=identity,
            control=control,
            runner_sessions=runner_sessions,
            fleet_source=fleet_source,
        )
        authorized = await authority.authorize(lease)
        credentials = ModelRunCredentialService(
            app_sessions=self._app_sessions,
            authenticator_sessions=self._authenticator_sessions,
            compatibility=self._compatibility,
        )
        issued = await asyncio.to_thread(credentials.issue, authorized, lease)
        return authorized, issued

    def create_authority(
        self,
        *,
        identity: InteractiveRunnerIdentity,
        control: MutualTlsRunnerControlClient,
        runner_sessions: sessionmaker[Session],
        fleet_source: Mapping[str, str],
    ) -> InteractiveRuntimeAuthority:
        """Admit only the pinned read-only machine login and reviewed fleet contract."""
        from saas.production.runner_database_fleet import (
            verify_runner_database_fleet_runtime_admission,
            verify_runner_database_fleet_runtime_catalog_binding,
        )
        from saas.production.runner_executor import _verify_runner_agent_database_authority

        if (
            identity.product_revision != self._product_revision
            or identity.image_digest != self._image_digest
            or runner_sessions.kw.get("bind") is self._app_sessions.kw.get("bind")
            or not isinstance(control, MutualTlsRunnerControlClient)
        ):
            _reject()
        source = dict(fleet_source)

        def verify_machine_database() -> None:
            try:
                admission, members = verify_runner_database_fleet_runtime_admission(
                    source,
                    runner_id=identity.runner_id,
                    connection_generation=identity.connection_generation,
                )
                contract = _verify_runner_agent_database_authority(
                    runner_sessions.kw["bind"],
                    runner_id=identity.runner_id,
                    connection_generation=identity.connection_generation,
                    fleet_members=members,
                    allow_leased_interactive=True,
                )
                verify_runner_database_fleet_runtime_catalog_binding(
                    admission, runtime_authority_contract_sha256=contract
                )
            except Exception:  # noqa: BLE001 - redact fleet files and database diagnostics.
                raise RunnerControlError(
                    "interactive_runtime_database_unavailable",
                    "Interactive Runtime machine database admission is unavailable",
                ) from None

        verify_machine_database()
        return InteractiveRuntimeAuthority(
            identity=identity,
            control=control,
            runner_sessions=runner_sessions,
            app_sessions=self._app_sessions,
            compatibility=self._compatibility,
            conversation_store=self._conversations,
            permission_store=self._permissions,
            verify_machine_database=verify_machine_database,
        )
