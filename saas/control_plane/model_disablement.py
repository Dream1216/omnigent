"""Immutable model cutoff, shared by catalog and the existing single-send fence."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from saas.control_plane.model_routing_models import ModelPublicationDisablementRecord as Disabled

DISABLEMENT_EVENT = "platform.model_publication.disabled"


def disabled_publication(
    tenant_id: UUID, public_model_id, wire_api, generation
) -> sa.ColumnElement[bool]:
    return (
        sa.select(sa.literal(1))
        .select_from(Disabled)
        .where(
            Disabled.tenant_id == tenant_id,
            Disabled.public_model_id == public_model_id,
            Disabled.wire_api == wire_api,
            Disabled.through_generation >= generation,
        )
        .exists()
    )


def publication_is_disabled(
    db: Session, *, tenant_id: UUID, public_model_id: str, wire_api: str, generation: int
) -> bool:
    return bool(
        db.scalar(
            sa.select(disabled_publication(tenant_id, public_model_id, wire_api, generation))
        )
    )
