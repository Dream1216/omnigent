"""DCP's dedicated mTLS backchannel for current SaaS production authorization.

Run with ``python -m saas.delivery.authorization``. This app is deliberately
separate from the public Cookie application; its listener requires client TLS.
"""

from __future__ import annotations

import os
import ssl
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.authorization import ProjectAuthorizationError, ProjectAuthorizer
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver
from saas.delivery.checkpoints import CheckpointExportBody
from saas.delivery.client import DeliveryConfig


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
        if (
            project is not None
            and body.action
            in {
                "deployment:create:production",
                "deployment:promote:production",
                "deployment:rollback:production",
            }
            and body.resource.get("environment_id") == project.production_environment
            and body.resource.get("environment_type") == "production"
        ):
            try:
                current = self.resolver.resolve_request_context(
                    actor_id=body.actor_id,
                    tenant_id=body.tenant_id,
                    space_id=project.space_id,
                    trace_id=body.request_nonce,
                )
                authorizer = ProjectAuthorizer(self.sessions)
                for action in ("project.content.read", "environment.manage"):
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
    authority: DeliveryAuthorization, *, checkpoint_exporter: Any = None
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
        if config.delivery_config.repository_mirrors:
            from saas.delivery.checkpoints import CheckpointExporter
            from saas.production.artifact_store import build_production_s3_artifact_store
            from saas.runner_adapter.worktrees import ObjectRecoveryArtifactStore

            checkpoint_exporter = CheckpointExporter(
                authority,
                ObjectRecoveryArtifactStore(build_production_s3_artifact_store(config).store),
                config.delivery_config.repository_mirrors,
            )
        app = create_authorization_app(authority, checkpoint_exporter=checkpoint_exporter)
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
