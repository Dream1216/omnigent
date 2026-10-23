"""Customer-safe, tenant-scoped projection of managed model candidates."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from hashlib import sha256
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine, RowMapping

from omnigent.db.utils import make_named_managed_session_maker
from saas.compatibility import RuntimeContext
from saas.control_plane.db_models import SpaceMembership, TenantMembership
from saas.control_plane.model_disablement import publication_is_disabled
from saas.control_plane.model_paging import ModelPage, model_page_cursor, validate_model_page
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord as Publication
from saas.control_plane.platform_security import PlatformSecurityError
from saas.control_plane.rls import RlsContext, apply_rls_context


class TenantModelCatalogError(RuntimeError):
    """A catalog cannot safely be shown; never render stored raw metadata."""


class TenantModelPageError(TenantModelCatalogError):
    """An unknown, invalid or differently scoped continuation is not usable."""


class TenantModelCatalog:
    def __init__(self, engine: Engine) -> None:
        self._postgresql_rls = engine.dialect.name == "postgresql"
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.tenant_model_catalog"
        )

    def _membership_scope(self, runtime: RuntimeContext) -> sa.ColumnElement[bool]:
        """Bind membership checks once per statement before traversing RLS history."""
        if not self._postgresql_rls:
            return sa.true()
        return sa.and_(
            sa.select(sa.literal(1))
            .select_from(TenantMembership)
            .where(
                TenantMembership.tenant_id == runtime.tenant_id,
                TenantMembership.user_id == runtime.actor_id,
                TenantMembership.status == "active",
            )
            .exists(),
            sa.select(sa.literal(1))
            .select_from(SpaceMembership)
            .where(
                SpaceMembership.tenant_id == runtime.tenant_id,
                SpaceMembership.space_id == runtime.space_id,
                SpaceMembership.user_id == runtime.actor_id,
                SpaceMembership.status == "active",
            )
            .exists(),
        )

    @staticmethod
    def _snapshot(row: RowMapping, runtime: RuntimeContext) -> dict[str, Any]:
        try:
            raw = row["canonical_snapshot"]
            if sha256(raw.encode("ascii")).hexdigest() != row["snapshot_sha256"]:
                raise ValueError
            snapshot = json.loads(raw)
            if (
                snapshot["schema_version"] != 1
                or snapshot["tenant_id"] != str(runtime.tenant_id)
                or snapshot["public_model_id"] != row["public_model_id"]
                or snapshot["wire_api"] != row["wire_api"]
                or snapshot["generation"] != row["generation"]
                or snapshot["provider_id"] != "deepseek"
                or snapshot["channel_id"] != "deepseek"
                or snapshot["transport"] != "litellm"
                or not isinstance(snapshot["display_name"], str)
                or not 1 <= len(snapshot["display_name"]) <= 128
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeError):
            raise TenantModelCatalogError("managed model catalog unavailable") from None
        return snapshot

    def require_version(
        self, runtime: RuntimeContext, reference: Mapping[str, object]
    ) -> dict[str, Any]:
        """Read a verified frozen configuration without granting inference or billing."""
        generation = reference.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise TenantModelCatalogError("managed model catalog unavailable")
        with self._session("verify_session_publication") as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=runtime.actor_id,
                    tenant_id=runtime.tenant_id,
                    space_id=runtime.space_id,
                    project_id=runtime.project_id,
                ),
            )
            row = (
                db.execute(
                    sa.select(
                        Publication.tenant_id,
                        Publication.public_model_id,
                        Publication.wire_api,
                        Publication.generation,
                        Publication.canonical_snapshot,
                        Publication.snapshot_sha256,
                    ).where(
                        Publication.tenant_id == runtime.tenant_id,
                        Publication.public_model_id == reference.get("public_model_id"),
                        Publication.wire_api == reference.get("wire_api"),
                        Publication.generation == generation,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None or row["snapshot_sha256"] != reference.get("snapshot_sha256"):
                raise TenantModelCatalogError("managed model catalog unavailable")
            if publication_is_disabled(
                db,
                tenant_id=runtime.tenant_id,
                public_model_id=row["public_model_id"],
                wire_api=row["wire_api"],
                generation=row["generation"],
            ):
                raise TenantModelCatalogError("managed model disabled")
            return self._snapshot(row, runtime)

    def resolve_selection(
        self, runtime: RuntimeContext, *, model_id: str, configuration_revision: str
    ) -> dict[str, object]:
        """Resolve a customer reference from stored metadata, never caller snapshots."""
        match = re.fullmatch(
            r"managed-model:(openai_chat_completions|openai_responses):([1-9][0-9]{0,9}):([0-9a-f]{64})",
            configuration_revision,
        )
        if match is None:
            raise TenantModelCatalogError("managed model selection invalid")
        wire_api, generation, digest = match.groups()
        with self._session("resolve_create_selection") as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=runtime.actor_id,
                    tenant_id=runtime.tenant_id,
                    space_id=runtime.space_id,
                    project_id=runtime.project_id,
                ),
            )
            row = (
                db.execute(
                    sa.select(
                        Publication.tenant_id,
                        Publication.public_model_id,
                        Publication.wire_api,
                        Publication.generation,
                        Publication.canonical_snapshot,
                        Publication.snapshot_sha256,
                    )
                    .where(
                        Publication.tenant_id == runtime.tenant_id,
                        Publication.public_model_id == model_id,
                        Publication.wire_api == wire_api,
                        self._membership_scope(runtime),
                    )
                    .order_by(Publication.generation.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
            if (
                row is None
                or row["generation"] != int(generation)
                or row["snapshot_sha256"] != digest
                or publication_is_disabled(
                    db,
                    tenant_id=runtime.tenant_id,
                    public_model_id=row["public_model_id"],
                    wire_api=row["wire_api"],
                    generation=row["generation"],
                )
            ):
                raise TenantModelCatalogError("managed model selection changed")
            self._snapshot(row, runtime)
            return {
                "schema_version": 1,
                "public_model_id": model_id,
                "wire_api": wire_api,
                "generation": row["generation"],
                "snapshot_sha256": digest,
            }

    def list(self, runtime: RuntimeContext) -> list[dict[str, object]]:
        """Read candidate metadata without authorizing inference or customer charges."""
        return list(self.page(runtime).items)

    def page(
        self, runtime: RuntimeContext, *, limit: int = 100, cursor: UUID | None = None
    ) -> ModelPage[dict[str, object]]:
        try:
            validate_model_page(limit, cursor)
        except PlatformSecurityError:
            raise TenantModelPageError("managed model page invalid") from None
        with self._session("read_current_candidates") as db:
            apply_rls_context(
                db,
                RlsContext(
                    actor_id=runtime.actor_id,
                    tenant_id=runtime.tenant_id,
                    space_id=runtime.space_id,
                    project_id=runtime.project_id,
                ),
            )
            query = sa.select(
                Publication.id,
                Publication.created_at,
                Publication.tenant_id,
                Publication.public_model_id,
                Publication.wire_api,
                Publication.generation,
                Publication.canonical_snapshot,
                Publication.snapshot_sha256,
            ).where(Publication.tenant_id == runtime.tenant_id, self._membership_scope(runtime))
            if cursor is not None:
                anchor = db.execute(
                    sa.select(Publication.created_at, Publication.id).where(
                        Publication.id == cursor, Publication.tenant_id == runtime.tenant_id
                    )
                ).one_or_none()
                if anchor is None:
                    raise TenantModelPageError("managed model page invalid")
                query = query.where(
                    sa.tuple_(Publication.created_at, Publication.id) < tuple(anchor)
                )
            rows = (
                db.execute(
                    query.order_by(Publication.created_at.desc(), Publication.id.desc()).limit(
                        limit + 1
                    )
                )
                .mappings()
                .all()
            )
            result: list[dict[str, object]] = []
            for row in rows[:limit]:
                latest = db.scalar(
                    sa.select(
                        Publication.generation,
                    )
                    .where(
                        Publication.tenant_id == runtime.tenant_id,
                        Publication.public_model_id == row["public_model_id"],
                        Publication.wire_api == row["wire_api"],
                        self._membership_scope(runtime),
                    )
                    .order_by(Publication.generation.desc())
                    .limit(1)
                )
                if row["generation"] != latest or publication_is_disabled(
                    db,
                    tenant_id=runtime.tenant_id,
                    public_model_id=row["public_model_id"],
                    wire_api=row["wire_api"],
                    generation=row["generation"],
                ):
                    continue
                snapshot = self._snapshot(row, runtime)
                result.append(
                    {
                        "model_id": row["public_model_id"],
                        "display_name": snapshot["display_name"],
                        "provider_id": "deepseek",
                        "channel_id": "deepseek",
                        "transport": "litellm",
                        "wire_api": row["wire_api"],
                        "generation": row["generation"],
                        "configuration_revision": (
                            f"managed-model:{row['wire_api']}:{row['generation']}:"
                            f"{row['snapshot_sha256']}"
                        ),
                        "available": False,
                        "unavailable_reason": "runtime_not_enabled",
                    }
                )
            return ModelPage(tuple(result), model_page_cursor([row["id"] for row in rows], limit))
