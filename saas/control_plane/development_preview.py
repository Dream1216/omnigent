"""Persistent, scoped one-use grants for interactive development previews."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Literal, cast
from uuid import UUID

import jwt
import sqlalchemy as sa
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.db_models import DevelopmentPreviewGrantRecord as Grant
from saas.control_plane.rls import RlsContext, apply_rls_context


class DevelopmentPreviewScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    actor_id: UUID
    tenant_id: UUID
    space_id: UUID
    auth_session_id: UUID
    security_version: int = Field(gt=0)
    runtime_partition_id: UUID
    release_incarnation: str = Field(pattern=r"^[0-9a-f]{32}$")
    session_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    endpoint_id: str = Field(pattern=r"^[0-9a-f]{32}$")

    def canonical(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class DevelopmentPreviewToken(DevelopmentPreviewScope):
    kind: Literal["launch", "session"]
    exp: int
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{32,128}$")
    aud: Literal["omnigent-development-preview"] = "omnigent-development-preview"

    def scope_value(self) -> DevelopmentPreviewScope:
        return DevelopmentPreviewScope.model_validate(
            {field: getattr(self, field) for field in DevelopmentPreviewScope.model_fields}
        )


class DevelopmentPreviewGrants:
    def __init__(self, sessions: sessionmaker[Session], key: bytes) -> None:
        if not 32 <= len(key) <= 4096:
            raise ValueError(
                "Development preview signing key must contain between 32 and 4096 bytes"
            )
        self.sessions, self.key = sessions, key
        with sessions() as db:
            engine = db.get_bind()
        if not isinstance(engine, sa.Engine):
            raise ValueError("Development preview requires an engine-bound session factory")
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.development_preview", immediate=True
        )

    def token(
        self, scope: DevelopmentPreviewScope, kind: Literal["launch", "session"], expiry: int
    ) -> str:
        value = DevelopmentPreviewToken(
            **scope.model_dump(), kind=kind, exp=expiry, nonce=secrets.token_urlsafe(32)
        )
        return jwt.encode(value.model_dump(mode="json"), self.key, algorithm="HS256")

    def decode(self, token: str, kind: Literal["launch", "session"]) -> DevelopmentPreviewToken:
        try:
            if not token or len(token) > 4096:
                raise ValueError("token length")
            value = DevelopmentPreviewToken.model_validate(
                jwt.decode(
                    token,
                    self.key,
                    algorithms=["HS256"],
                    audience="omnigent-development-preview",
                    options={"require": ["exp", "aud"]},
                )
            )
            if value.kind != kind:
                raise ValueError("wrong token purpose")
            return value
        except (jwt.InvalidTokenError, ValueError):
            raise HTTPException(
                403, detail={"code": "development_preview_access_denied"}
            ) from None

    @staticmethod
    def bind(db: Session, scope: DevelopmentPreviewScope) -> None:
        apply_rls_context(
            db,
            RlsContext(
                actor_id=scope.actor_id, tenant_id=scope.tenant_id, space_id=scope.space_id
            ),
        )

    def issue(self, scope: DevelopmentPreviewScope, expires: int) -> str:
        now = datetime.now(timezone.utc)
        launch = self.token(scope, "launch", min(expires, int(now.timestamp()) + 60))
        with self._session("issue_handoff") as db:
            self.bind(db, scope)
            if db.get_bind().dialect.name == "postgresql":
                db.execute(
                    sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:actor, 0))"),
                    {"actor": f"dev-preview:{scope.actor_id}"},
                )
            count = (
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(Grant)
                    .where(
                        Grant.actor_id == scope.actor_id,
                        Grant.revoked_at.is_(None),
                        Grant.expires_at > now,
                    )
                )
                or 0
            )
            if count >= 16:
                raise HTTPException(409, detail={"code": "preview_quota_exhausted"})
            db.add(
                Grant(
                    id=scope.id,
                    actor_id=scope.actor_id,
                    tenant_id=scope.tenant_id,
                    space_id=scope.space_id,
                    context_json=scope.canonical(),
                    launch_hash=hashlib.sha256(launch.encode()).hexdigest(),
                    expires_at=datetime.fromtimestamp(expires, timezone.utc),
                )
            )
        return launch

    def exchange(self, launch: str, host_id: UUID) -> tuple[str, DevelopmentPreviewScope]:
        value = self.decode(launch, "launch")
        scope = value.scope_value()
        if scope.id != host_id:
            raise HTTPException(403)
        now = datetime.now(timezone.utc)
        with self._session("redeem_handoff") as db:
            self.bind(db, scope)
            grant = db.get(Grant, host_id)
            if grant is None or grant.context_json != scope.canonical():
                raise HTTPException(403)
            expiry = grant.expires_at.replace(tzinfo=timezone.utc).timestamp()
            cookie = self.token(scope, "session", int(expiry))
            changed = db.execute(
                sa.update(Grant)
                .where(
                    Grant.id == host_id,
                    Grant.launch_hash == hashlib.sha256(launch.encode()).hexdigest(),
                    Grant.context_json == scope.canonical(),
                    Grant.session_hash.is_(None),
                    Grant.revoked_at.is_(None),
                    Grant.expires_at > now,
                )
                .values(session_hash=hashlib.sha256(cookie.encode()).hexdigest(), redeemed_at=now)
                .execution_options(synchronize_session=False)
            )
            if cast(CursorResult[tuple[object]], changed).rowcount != 1:
                raise HTTPException(403, detail={"code": "preview_exchange_consumed"})
        return cookie, scope

    def authorize(self, cookie: str, host_id: UUID) -> DevelopmentPreviewScope:
        scope = self.decode(cookie, "session").scope_value()
        if scope.id != host_id:
            raise HTTPException(403)
        with self._session("authorize_preview") as db:
            self.bind(db, scope)
            grant = db.scalar(
                sa.select(Grant).where(
                    Grant.id == host_id,
                    Grant.context_json == scope.canonical(),
                    Grant.session_hash == hashlib.sha256(cookie.encode()).hexdigest(),
                    Grant.revoked_at.is_(None),
                    Grant.expires_at > datetime.now(timezone.utc),
                )
            )
            if grant is None:
                raise HTTPException(403)
        return scope

    def revoke(self, scope: DevelopmentPreviewScope) -> None:
        with self._session("revoke_preview") as db:
            self.bind(db, scope)
            db.execute(
                sa.update(Grant)
                .where(Grant.id == scope.id, Grant.context_json == scope.canonical())
                .values(revoked_at=datetime.now(timezone.utc))
            )

    def owned_scope(
        self, grant_id: UUID, *, actor_id: UUID, tenant_id: UUID, space_id: UUID
    ) -> DevelopmentPreviewScope:
        with self._session("find_owned_preview") as db:
            apply_rls_context(
                db, RlsContext(actor_id=actor_id, tenant_id=tenant_id, space_id=space_id)
            )
            grant = db.scalar(
                sa.select(Grant).where(
                    Grant.id == grant_id,
                    Grant.actor_id == actor_id,
                    Grant.tenant_id == tenant_id,
                    Grant.space_id == space_id,
                )
            )
            if grant is None:
                raise HTTPException(404)
            return DevelopmentPreviewScope.model_validate_json(grant.context_json)
