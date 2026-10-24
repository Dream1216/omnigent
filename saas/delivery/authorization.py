"""DCP's dedicated mTLS backchannel for current SaaS production authorization.

Run with ``python -m saas.delivery.authorization``. This app is deliberately
separate from the public Cookie application; its listener requires client TLS.
"""

from __future__ import annotations

import os
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.authorization import ProjectAuthorizationError, ProjectAuthorizer
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.delivery.checkpoints import CheckpointExportBody
from saas.delivery.client import DeliveryConfig
from saas.delivery.snapshot_objects import (
    SnapshotObjectAllocation,
    SnapshotObjectAuthority,
    SnapshotObjectReference,
    SnapshotObjectSettings,
)


class AuthorizationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(max_length=128)
    actor_id: UUID
    tenant_id: UUID
    project_id: UUID
    membership_version: int = Field(ge=1)
    token_id: str = Field(min_length=1, max_length=128)
    resource: dict[str, str | int]
    request_nonce: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")


@dataclass
class DeliveryAuthorization:
    config: DeliveryConfig
    resolver: SqlAlchemyContextResolver
    sessions: sessionmaker[Session]

    def decide(self, body: AuthorizationBody) -> dict[str, Any]:
        allowed = False
        project = next(
            (
                p
                for p in self.config.projects
                if p.project_id == body.project_id and p.tenant_id == body.tenant_id
            ),
            None,
        )
        if project is not None and (
            (
                body.action == "preview.open"
                and body.resource.get("environment_id") == project.preview_environment
                and body.resource.get("environment_type") == "preview"
            )
            or (
                body.action
                in {
                    "deployment:create:production",
                    "deployment:promote:production",
                    "deployment:rollback:production",
                }
                and body.resource.get("environment_id") == project.production_environment
                and body.resource.get("environment_type") == "production"
            )
        ):
            try:
                current = self.resolver.resolve_request_context(
                    actor_id=body.actor_id,
                    tenant_id=body.tenant_id,
                    space_id=project.space_id,
                    trace_id=body.request_nonce,
                )
                authorizer = ProjectAuthorizer(self.sessions)
                required_action = (
                    "preview.open" if body.action == "preview.open" else "environment.manage"
                )
                for action in ("project.content.read", required_action):
                    current = authorizer.bind_project_context(
                        current, action=action, project_id=project.project_id
                    )
                allowed = current.tenant_membership_version == body.membership_version
            except (ControlPlaneResolutionError, ProjectAuthorizationError):
                pass
        return {
            **body.model_dump(mode="json"),
            "allowed": allowed,
            "authorized_at": int(time.time()),
            "decision_id": uuid4().hex,
        }


def create_authorization_app(
    authority: DeliveryAuthorization,
    *,
    checkpoint_exporter: Any = None,
    snapshot_objects: SnapshotObjectAuthority | None = None,
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/authorize")
    def authorize(body: AuthorizationBody) -> dict[str, Any]:
        return authority.decide(body)

    if checkpoint_exporter is not None:

        @app.post("/checkpoints/export")
        def checkpoint_export(body: CheckpointExportBody) -> Response:
            try:
                return checkpoint_exporter.export(body)
            except (ControlPlaneResolutionError, ProjectAuthorizationError) as error:
                raise HTTPException(
                    403, detail={"code": "checkpoint_authorization_denied"}
                ) from error

    if snapshot_objects is not None:
        objects = snapshot_objects

        def invoke(operation: Callable[..., Any], *args: Any) -> Any:
            try:
                return operation(*args)
            except HTTPException:
                raise
            except (ControlPlaneResolutionError, ProjectAuthorizationError):
                raise HTTPException(403, detail={"code": "snapshot_object_scope_denied"}) from None
            except Exception:  # noqa: BLE001 - never expose provider credentials in HTTP errors.
                raise HTTPException(503, detail={"code": "snapshot_object_unavailable"}) from None

        def authenticated(authorization: str | None) -> None:
            invoke(objects.authenticate, authorization)

        @app.post("/v1/snapshot-upload-targets", status_code=201)
        def snapshot_allocate(
            body: SnapshotObjectAllocation,
            authorization: Annotated[str | None, Header()] = None,
        ) -> dict[str, Any]:
            authenticated(authorization)
            return invoke(objects.allocate, body)

        @app.post("/v1/snapshot-objects:head")
        def snapshot_head(
            body: SnapshotObjectReference,
            authorization: Annotated[str | None, Header()] = None,
        ) -> dict[str, Any]:
            authenticated(authorization)
            return invoke(objects.head, body.object_ref)

        @app.post("/v1/snapshot-objects:stream")
        def snapshot_stream(
            body: SnapshotObjectReference,
            authorization: Annotated[str | None, Header()] = None,
        ) -> StreamingResponse:
            authenticated(authorization)
            return StreamingResponse(
                invoke(objects.stream, body.object_ref), media_type="application/octet-stream"
            )

        @app.post("/v1/snapshot-upload-targets:revoke", status_code=204)
        def snapshot_revoke(
            body: SnapshotObjectReference,
            authorization: Annotated[str | None, Header()] = None,
        ) -> Response:
            authenticated(authorization)
            invoke(objects.revoke, body.object_ref)
            return Response(status_code=204)

    return app


def main() -> None:
    import uvicorn

    from saas.control_plane import RuntimeCompatibilityPolicy
    from saas.production.postgresql_migration import verify_production_postgresql_state
    from saas.production.server import create_role_session_factories
    from saas.production.server_config import (
        _absolute_regular_file,
        load_production_server_config,
    )

    files = {}
    for name in ("CERT", "KEY", "CLIENT_CA"):
        variable = f"OMNIGENT_SAAS_DCP_AUTH_TLS_{name}_FILE"
        files[name] = _absolute_regular_file(
            os.environ[variable], name=variable, owner_only=name == "KEY"
        )
    config = load_production_server_config()
    if config.delivery_config is None:
        raise ValueError("DCP authorization requires configured delivery projects")
    sessions = create_role_session_factories(
        config,
        verify_state=lambda engines, config: verify_production_postgresql_state(
            engines=engines, config=config
        ),
    )
    try:
        resolver = SqlAlchemyContextResolver(
            sessions.app,
            RuntimeCompatibilityPolicy(
                runtime_type="omnigent",
                allowed_runtime_versions=frozenset({config.runtime_version}),
                allowed_source_revisions=frozenset({config.upstream_revision}),
                allowed_schema_revisions=frozenset({config.official_schema_revision}),
                adapter_contract_version=config.adapter_contract_version,
            ),
        )
        authority = DeliveryAuthorization(config.delivery_config, resolver, sessions.app)
        checkpoint_exporter = None
        snapshot_objects = None
        snapshot_settings_file = os.environ.get(
            "OMNIGENT_SAAS_SNAPSHOT_OBJECT_AUTHORITY_FILE", ""
        ).strip()
        built_artifacts = None
        if config.delivery_config.repository_mirrors or snapshot_settings_file:
            from saas.production.artifact_store import build_production_s3_artifact_store

            built_artifacts = build_production_s3_artifact_store(config)
        if config.delivery_config.repository_mirrors:
            assert built_artifacts is not None
            from saas.delivery.checkpoints import CheckpointExporter
            from saas.runner_adapter.worktrees import ObjectRecoveryArtifactStore

            checkpoint_exporter = CheckpointExporter(
                authority,
                ObjectRecoveryArtifactStore(built_artifacts.store),
                config.delivery_config.repository_mirrors,
            )
        if snapshot_settings_file:
            from pathlib import Path

            assert built_artifacts is not None
            snapshot_objects = SnapshotObjectAuthority(
                authority,
                SnapshotObjectSettings.from_file(Path(snapshot_settings_file)),
                client=built_artifacts.client,
                artifact_store_uri=config.artifact_store_uri,
                endpoint_url=config.artifact_endpoint_url,
            )
        app = create_authorization_app(
            authority, checkpoint_exporter=checkpoint_exporter, snapshot_objects=snapshot_objects
        )
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8444,
            ssl_certfile=str(files["CERT"]),
            ssl_keyfile=str(files["KEY"]),
            ssl_ca_certs=str(files["CLIENT_CA"]),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            access_log=False,
        )
    finally:
        sessions.close()


if __name__ == "__main__":
    main()
