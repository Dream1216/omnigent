"""Verify and atomically promote the signed exact A/B Runner database fleet."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from saas.production.runner_database_fleet import (
    load_runner_database_fleet,
    load_runner_database_fleet_admin_database_url,
    load_runner_database_fleet_evidence_context,
    promote_runner_database_fleet_after_admission,
    verify_installed_runner_database_fleet_lineage,
    verify_runner_database_fleet_release_facts,
)


def build_runner_database_fleet_promotion_engine(database_url: str) -> Engine:
    """Build a one-shot promotion connection without a reusable credential pool."""

    return sa.create_engine(database_url, poolclass=NullPool)


def promote_signed_runner_database_fleet(
    source: Mapping[str, str],
    *,
    engine_factory: Callable[[str], Engine] = build_runner_database_fleet_promotion_engine,
) -> tuple[str, str]:
    """Load immutable evidence and promote only after in-lock receipt verification."""

    fleet = load_runner_database_fleet(source)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)
    verify_runner_database_fleet_release_facts(source, context)
    verify_installed_runner_database_fleet_lineage(context)
    database_url, _parsed, _path = load_runner_database_fleet_admin_database_url(
        source,
        context=context,
    )
    engine = engine_factory(database_url)
    try:
        factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
        runner_ids = promote_runner_database_fleet_after_admission(factory, source)
        return tuple(str(runner_id) for runner_id in runner_ids)  # type: ignore[return-value]
    finally:
        engine.dispose()


def main() -> int:
    """Emit only a secret-free success/failure envelope."""

    try:
        runner_ids = promote_signed_runner_database_fleet(os.environ)
    except Exception:  # noqa: BLE001 - never expose DSN, token, or catalog diagnostics.
        print(
            json.dumps(
                {
                    "code": "runner_database_fleet_promotion_failed",
                    "schema_version": 1,
                    "status": "fail",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            {
                "runner_ids": list(runner_ids),
                "schema_version": 1,
                "status": "pass",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "build_runner_database_fleet_promotion_engine",
    "main",
    "promote_signed_runner_database_fleet",
]
