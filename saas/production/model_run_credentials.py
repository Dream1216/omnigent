"""Opaque, renewable model credentials derived only from a real interactive Run."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.query_context import query_name_scope
from saas.compatibility import RuntimeContext
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.interactive_run_route import INTERACTIVE_QUEUE_CLASS
from saas.control_plane.model_gateway_evidence import GatewayRunBinding, GatewayRunRequestEvidence
from saas.control_plane.model_pricing import PlatformModelPrice
from saas.control_plane.model_routing_models import ModelRunTokenRecord
from saas.control_plane.resolver import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.control_plane.tenant_model_catalog import TenantModelCatalog
from saas.production.interactive_runtime import (
    AuthorizedInteractiveInput,
    resolve_interactive_run_runtime,
)
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from saas.runner_adapter.platform_model_gateway import (
    DEFAULT_PLATFORM_MODEL_TOKEN_TTL_SECONDS,
    PlatformModelGatewayTokenError,
    PlatformModelGatewayTokenExpired,
)

MODEL_RUN_TOKEN_PREFIX = "mrt_"
_TOKEN = re.compile(r"^mrt_[0-9a-f]{64}$")
_MAX_CHAIN = 256
_TOKEN_FIELDS = (
    "id",
    "tenant_id",
    "space_id",
    "project_id",
    "actor_id",
    "run_id",
    "capability_id",
    "fence_token",
    "generation",
    "parent_id",
    "issued_at",
    "expires_at",
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _derived(key: str, identifier: UUID) -> str:
    return MODEL_RUN_TOKEN_PREFIX + hmac.new(key.encode(), identifier.bytes, sha256).hexdigest()


def _digest(token: str) -> str:
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise PlatformModelGatewayTokenError("model Run credential is invalid")
    return sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ModelRunClaims:
    token_id: UUID
    tenant_id: UUID
    space_id: UUID
    project_id: UUID
    actor_id: UUID
    run_id: UUID
    capability_id: UUID
    fence_token: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedModelRunCredential:
    value: str = field(repr=False)
    expires_at: datetime
    run_id: UUID
    fence_token: int
    generation: int


@dataclass(frozen=True, slots=True)
class AuthorizedModelRun:
    claims: ModelRunClaims
    runtime: RuntimeContext
    publication: dict[str, object] = field(repr=False)
    customer_pricing_snapshot_id: UUID
    configuration: dict[str, object] = field(repr=False)
    execution_session_id: UUID

    def gateway_request(self, *, output_token_limit: int) -> GatewayRunRequestEvidence:
        frozen = self.configuration
        cost = frozen["provider_cost"]
        if not isinstance(cost, dict):
            raise ValueError("platform_model_gateway_frozen_price_invalid")
        maximum = frozen["max_output_tokens"]
        if (
            type(maximum) is not int
            or type(output_token_limit) is not int
            or not 1 <= output_token_limit <= maximum
        ):
            raise ValueError("platform_model_gateway_output_limit_invalid")
        generation = self.publication["generation"]
        digest = self.publication["snapshot_sha256"]
        if type(generation) is not int or not isinstance(digest, str):
            raise ValueError("platform_model_gateway_publication_invalid")
        return GatewayRunRequestEvidence(
            str(frozen["public_model_id"]),
            str(frozen["wire_api"]),
            cost["pricing_revision"],
            PlatformModelPrice(**cost["price"]),
            output_token_limit,
            GatewayRunBinding(
                str(self.claims.run_id),
                str(self.execution_session_id),
                str(self.claims.space_id),
                str(self.claims.project_id),
                str(self.claims.actor_id),
                str(self.claims.capability_id),
                str(self.claims.token_id),
                str(self.customer_pricing_snapshot_id),
                self.claims.fence_token,
                generation,
                digest,
            ),
        )


class ModelRunCredentialService:
    """Keep credential lookup separate from current user/Run authorization."""

    def __init__(
        self,
        *,
        app_sessions: sessionmaker[Session],
        authenticator_sessions: sessionmaker[Session],
        compatibility: RuntimeCompatibilityPolicy,
        ttl: timedelta = timedelta(seconds=DEFAULT_PLATFORM_MODEL_TOKEN_TTL_SECONDS),
    ) -> None:
        if not timedelta(0) < ttl <= timedelta(hours=8):
            raise ValueError("model Run credential lifetime is invalid")
        self._app = app_sessions
        self._authenticator = authenticator_sessions
        self._ttl = ttl
        self._authorization = ProjectAuthorizer(app_sessions)
        self._resolver = SqlAlchemyContextResolver(
            app_sessions, compatibility, project_authorizer=self._authorization
        )
        self._catalog = TenantModelCatalog(app_sessions.kw["bind"])

    @staticmethod
    def _context(db: Session, claims: ModelRunClaims) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=claims.actor_id,
                tenant_id=claims.tenant_id,
                space_id=claims.space_id,
                project_id=claims.project_id,
            ),
        )
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                sa.text(
                    "SELECT set_config('app.model_run_id',:run,true), "
                    "set_config('app.model_capability_id',:cap,true)"
                ),
                {"run": str(claims.run_id), "cap": str(claims.capability_id)},
            )

    @staticmethod
    def _token_row(db: Session, token_id: UUID):
        return (
            db.execute(
                sa.select(*(getattr(ModelRunTokenRecord, name) for name in _TOKEN_FIELDS)).where(
                    ModelRunTokenRecord.id == token_id
                )
            )
            .mappings()
            .one_or_none()
        )

    @staticmethod
    def _claims(row) -> ModelRunClaims:
        return ModelRunClaims(
            token_id=row["id"],
            tenant_id=row["tenant_id"],
            space_id=row["space_id"],
            project_id=row["project_id"],
            actor_id=row["actor_id"],
            run_id=row["run_id"],
            capability_id=row["capability_id"],
            fence_token=row["fence_token"],
            expires_at=_aware(row["expires_at"]),
        )

    def authenticate(
        self, token: str, *, allow_expired: bool = False, now: datetime | None = None
    ) -> ModelRunClaims:
        digest = _digest(token)
        at = _aware(now or datetime.now(timezone.utc))
        with (
            query_name_scope("saas.model_run_credentials.authenticate"),
            self._authenticator() as db,
        ):
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT set_config('app.model_token_hash',:hash,true)"),
                    {"hash": digest},
                )
            row = (
                db.execute(
                    sa.select(
                        *(getattr(ModelRunTokenRecord, name) for name in _TOKEN_FIELDS)
                    ).where(ModelRunTokenRecord.token_hash == digest)
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise PlatformModelGatewayTokenError("model Run credential is invalid")
            if not allow_expired and _aware(row["expires_at"]) <= at:
                raise PlatformModelGatewayTokenExpired("model Run credential expired")
            return self._claims(row)

    def _run(self, db: Session, claims: ModelRunClaims, at: datetime) -> RunRecord:
        self._context(db, claims)
        run = db.scalar(
            sa.select(RunRecord).where(RunRecord.id == claims.run_id).with_for_update()
        )
        capability_query = (
            sa.text("SELECT * FROM public.saas_model_run_capability_v1(:run,:cap)").bindparams(
                run=claims.run_id, cap=claims.capability_id
            )
            if db.get_bind().dialect.name == "postgresql"
            else sa.select(
                CapabilityTokenRecord.id,
                CapabilityTokenRecord.run_id,
                CapabilityTokenRecord.runner_id,
                CapabilityTokenRecord.fence_token,
                CapabilityTokenRecord.tenant_id,
                CapabilityTokenRecord.space_id,
                CapabilityTokenRecord.project_id,
                CapabilityTokenRecord.allowed_actions,
                CapabilityTokenRecord.expires_at,
                CapabilityTokenRecord.revoked_at,
            ).where(CapabilityTokenRecord.id == claims.capability_id)
        )
        capability = db.execute(capability_query).one_or_none()
        if (
            run is None
            or capability is None
            or run.tenant_id != claims.tenant_id
            or run.space_id != claims.space_id
            or run.project_id != claims.project_id
            or run.created_by != claims.actor_id
            or run.created_by_service_account_id is not None
            or run.queue_class != INTERACTIVE_QUEUE_CLASS
            or run.status != "running"
            or run.fence_token != claims.fence_token
            or run.lease_expires_at is None
            or _aware(run.lease_expires_at) <= at
            or not run.customer_pricing_frozen
            or run.customer_pricing_snapshot_id is None
            or capability.run_id != run.id
            or (capability.tenant_id, capability.space_id, capability.project_id)
            != (run.tenant_id, run.space_id, run.project_id)
            or set(capability.allowed_actions) != {"run.execute", "runtime.interactive.execute"}
            or capability.fence_token != claims.fence_token
            or run.lease_owner != str(capability.runner_id)
            or capability.revoked_at is not None
            or _aware(capability.expires_at) <= at
        ):
            raise PlatformModelGatewayTokenError("model Run authority is unavailable")
        return run

    def require_in_flight(self, claims: ModelRunClaims, *, now: datetime | None = None) -> None:
        """Recheck Run/control authority without applying ordinary model cutoffs."""
        from saas.control_plane.model_revocations import run_security_revoked

        at = _aware(now or datetime.now(timezone.utc))
        with (
            query_name_scope("saas.model_run_credentials.check_in_flight_run"),
            self._app.begin() as db,
        ):
            self._run(db, claims, at)
            if run_security_revoked(db, claims.run_id):
                raise PlatformModelGatewayTokenError("model Run authority is unavailable")

    def authorize(
        self, claims: ModelRunClaims, *, now: datetime | None = None
    ) -> AuthorizedModelRun:
        at = _aware(now or datetime.now(timezone.utc))
        with query_name_scope("saas.model_run_credentials.authorize"), self._app.begin() as db:
            run = self._run(db, claims, at)
            execution = run.input["execution"]
            assert isinstance(execution, dict)
            publication = execution["model_publication"]
            assert isinstance(publication, dict)
            pricing_id = run.customer_pricing_snapshot_id
            assert pricing_id is not None
            session_id = run.session_id
            if session_id is None:
                raise PlatformModelGatewayTokenError("model Run session is unavailable")
        try:
            runtime = resolve_interactive_run_runtime(
                run,
                app_sessions=self._app,
                resolver=self._resolver,
                authorization=self._authorization,
            )
        except RunnerControlError:
            raise PlatformModelGatewayTokenError("model Run route changed") from None
        configuration = self._catalog.require_version(runtime, publication)
        return AuthorizedModelRun(
            claims, runtime, publication, pricing_id, configuration, session_id
        )

    def issue(
        self,
        authorized: AuthorizedInteractiveInput,
        lease: RunnerControlClientLease,
        *,
        now: datetime | None = None,
    ) -> IssuedModelRunCredential:
        if (
            authorized.run_id != lease.run_id
            or authorized.fence_token != lease.fence_token
            or authorized.runtime.project_id is None
        ):
            raise PlatformModelGatewayTokenError("model Run issuance scope is invalid")
        at = _aware(now or datetime.now(timezone.utc))
        claims = ModelRunClaims(
            uuid4(),
            authorized.runtime.tenant_id,
            authorized.runtime.space_id,
            authorized.runtime.project_id,
            authorized.runtime.actor_id,
            lease.run_id,
            lease.capability_id,
            lease.fence_token,
            at + self._ttl,
        )
        self.authorize(claims, now=at)
        with query_name_scope("saas.model_run_credentials.issue"), self._app.begin() as db:
            run = self._run(db, claims, at)
            execution = run.input["execution"]
            assert isinstance(execution, dict)
            if execution["model_publication"] != authorized.publication:
                raise PlatformModelGatewayTokenError("model Run publication changed")
            root = db.scalar(
                sa.select(ModelRunTokenRecord.id).where(
                    ModelRunTokenRecord.run_id == claims.run_id,
                    ModelRunTokenRecord.fence_token == claims.fence_token,
                    ModelRunTokenRecord.generation == 0,
                )
            )
            if root is None:
                value = _derived(lease.capability_token, claims.token_id)
                db.add(self._new_row(claims, value, at=at, generation=0, parent_id=None))
                db.flush()
                row = self._token_row(db, claims.token_id)
            else:
                row = self._token_row(db, root)
                value = _derived(lease.capability_token, root)
            assert row is not None
            return self._advance(db, claims, row, value, at=at)

    def renew(self, token: str, *, now: datetime | None = None) -> IssuedModelRunCredential:
        at = _aware(now or datetime.now(timezone.utc))
        claims = self.authenticate(token, allow_expired=True, now=at)
        self.authorize(claims, now=at)
        with query_name_scope("saas.model_run_credentials.renew"), self._app.begin() as db:
            self._run(db, claims, at)
            row = self._token_row(db, claims.token_id)
            if row is None:
                raise PlatformModelGatewayTokenError("model Run credential is unavailable")
            return self._advance(db, claims, row, token, at=at)

    def _advance(self, db, claims, row, token, *, at):
        for _ in range(_MAX_CHAIN + 1):
            child_id = db.scalar(
                sa.select(ModelRunTokenRecord.id).where(ModelRunTokenRecord.parent_id == row["id"])
            )
            if child_id is None:
                break
            token = _derived(token, child_id)
            child = self._token_row(db, child_id)
            if (
                child is None
                or any(
                    child[name] != row[name]
                    for name in (
                        "tenant_id",
                        "space_id",
                        "project_id",
                        "actor_id",
                        "run_id",
                        "capability_id",
                        "fence_token",
                    )
                )
                or child["generation"] != row["generation"] + 1
            ):
                raise PlatformModelGatewayTokenError("model Run credential chain is invalid")
            row = child
        else:
            raise PlatformModelGatewayTokenError("model Run credential chain exceeds its bound")
        if _aware(row["expires_at"]) <= at + min(timedelta(minutes=5), self._ttl / 10):
            if row["generation"] >= _MAX_CHAIN:
                raise PlatformModelGatewayTokenError(
                    "model Run credential chain exceeds its bound"
                )
            identifier, generation = uuid4(), row["generation"] + 1
            token = _derived(token, identifier)
            child_claims = ModelRunClaims(
                identifier,
                claims.tenant_id,
                claims.space_id,
                claims.project_id,
                claims.actor_id,
                claims.run_id,
                claims.capability_id,
                claims.fence_token,
                at + self._ttl,
            )
            db.add(
                self._new_row(
                    child_claims, token, at=at, generation=generation, parent_id=row["id"]
                )
            )
            db.flush()
            row = self._token_row(db, identifier)
            assert row is not None
        return IssuedModelRunCredential(
            token, _aware(row["expires_at"]), claims.run_id, claims.fence_token, row["generation"]
        )

    @staticmethod
    def _new_row(claims, token, *, at, generation, parent_id):
        return ModelRunTokenRecord(
            id=claims.token_id,
            token_hash=_digest(token),
            tenant_id=claims.tenant_id,
            space_id=claims.space_id,
            project_id=claims.project_id,
            actor_id=claims.actor_id,
            run_id=claims.run_id,
            capability_id=claims.capability_id,
            fence_token=claims.fence_token,
            generation=generation,
            parent_id=parent_id,
            issued_at=at,
            expires_at=claims.expires_at,
        )
