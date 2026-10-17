"""Customer-safe, tenant-scoped projection of managed model candidates."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Engine, RowMapping

from omnigent.db.utils import make_named_managed_session_maker
from saas.compatibility import RuntimeContext
from saas.control_plane.model_routing_models import ModelPublicationVersionRecord as Publication
from saas.control_plane.rls import RlsContext, apply_rls_context


class TenantModelCatalogError(RuntimeError):
    """A catalog cannot safely be shown; never render stored raw metadata."""


class TenantModelCatalog:
    def __init__(self, engine: Engine) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.tenant_model_catalog"
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
            latest = (
                sa.select(
                    Publication.public_model_id,
                    Publication.wire_api,
                    sa.func.max(Publication.generation).label("generation"),
                )
                .where(Publication.tenant_id == runtime.tenant_id)
                .group_by(Publication.public_model_id, Publication.wire_api)
                .subquery()
            )
            rows = db.execute(
                sa.select(
                    Publication.tenant_id,
                    Publication.public_model_id,
                    Publication.wire_api,
                    Publication.generation,
                    Publication.canonical_snapshot,
                    Publication.snapshot_sha256,
                )
                .join(
                    latest,
                    sa.and_(
                        Publication.public_model_id == latest.c.public_model_id,
                        Publication.wire_api == latest.c.wire_api,
                        Publication.generation == latest.c.generation,
                    ),
                )
                .where(Publication.tenant_id == runtime.tenant_id)
                .order_by(Publication.public_model_id, Publication.wire_api)
                .limit(100)
            ).mappings()
            result: list[dict[str, object]] = []
            for row in rows:
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
            return result
