"""Canonical immutable inputs for one Run dispatch binding."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID


def dispatch_requirements_hash(
    *,
    tenant_id: UUID,
    space_id: UUID,
    project_id: UUID,
    pool_id: UUID,
    execution_profile_id: UUID,
    execution_profile_hash: str,
    egress_policy_id: UUID,
    egress_policy_hash: str,
    queue_class: str,
    required_capabilities: list[str],
    cost_units: int,
    eligible_at: datetime,
    max_wait_at: datetime,
) -> str:
    """Hash every persisted authority input consumed before a dispatch side effect."""

    payload = {
        "tenant_id": str(tenant_id),
        "space_id": str(space_id),
        "project_id": str(project_id),
        "pool_id": str(pool_id),
        "execution_profile_id": str(execution_profile_id),
        "execution_profile_hash": execution_profile_hash,
        "egress_policy_id": str(egress_policy_id),
        "egress_policy_hash": egress_policy_hash,
        "queue_class": queue_class,
        "required_capabilities": required_capabilities,
        "cost_units": cost_units,
        "eligible_at": _aware(eligible_at).isoformat(),
        "max_wait_at": _aware(max_wait_at).isoformat(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    # PostgreSQL materializes ``timestamptz`` values in the connection's current
    # timezone.  Bind the hash to the instant, not to that presentation offset,
    # so prepare/replay/claim agree across database and process timezones.
    return aware.astimezone(timezone.utc)
