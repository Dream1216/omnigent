"""Resolve delegated Runtime aliases without treating their spelling as identity."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.db_models import (
    RuntimeIdentityAliasRecord,
    RuntimePartitionRecord,
    RuntimePlacementRecord,
)


def resolve_runner_actor(db: Session, *, workspace_id: int, runtime_user_key: str) -> UUID | None:
    if (
        type(workspace_id) is not int
        or not 0 < workspace_id < 2**63
        or not isinstance(runtime_user_key, str)
        or not 1 <= len(runtime_user_key) <= 128
        or runtime_user_key != runtime_user_key.strip()
    ):
        return None
    if db.get_bind().dialect.name == "postgresql":
        return db.scalar(
            sa.text("SELECT public.saas_delegated_runner_actor_v1(:workspace,:owner)"),
            {"workspace": workspace_id, "owner": runtime_user_key},
        )
    rows = db.scalars(
        sa.select(RuntimeIdentityAliasRecord.user_id)
        .join(
            RuntimePartitionRecord,
            RuntimePartitionRecord.id == RuntimeIdentityAliasRecord.runtime_partition_id,
        )
        .join(
            RuntimePlacementRecord,
            RuntimePlacementRecord.id == RuntimePartitionRecord.placement_id,
        )
        .where(
            RuntimeIdentityAliasRecord.runtime_user_key == runtime_user_key,
            RuntimeIdentityAliasRecord.status == "active",
            RuntimePartitionRecord.physical_partition_key == str(workspace_id),
            RuntimePartitionRecord.runtime_type == "omnigent",
            RuntimePartitionRecord.status == "active",
            RuntimePlacementRecord.runtime_type == "omnigent",
            RuntimePlacementRecord.status == "active",
        )
        .limit(2)
    ).all()
    return rows[0] if len(rows) == 1 else None
