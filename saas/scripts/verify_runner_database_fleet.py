"""Verify the exact A/B Runner database fleet and emit a secret-free receipt."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.pool import NullPool

import saas.production.runner_database_fleet as fleet_contract
from saas.production.runner_database_fleet import (
    load_and_verify_runner_database_fleet_environment_attestation,
    load_runner_database_fleet,
    load_runner_database_fleet_admin_database_url,
    load_runner_database_fleet_evidence_context,
    load_runner_database_fleet_trust_pins,
    run_runner_database_fleet_admission,
    sign_runner_database_fleet_admission_receipt,
    verify_installed_runner_database_fleet_lineage,
    verify_runner_database_fleet_release_facts,
)


def runner_database_fleet_source_sha256s() -> dict[str, str]:
    """Hash the exact cluster, role, contract, and admission-tool sources."""

    return fleet_contract.runner_database_fleet_source_sha256s()


def build_runner_database_fleet_engine(database_url: str) -> Engine:
    """Build the one-shot managed-admin connection without a reusable pool."""

    return sa.create_engine(database_url, poolclass=NullPool)


def admit_runner_database_fleet(
    source: Mapping[str, str],
    *,
    engine_factory: Callable[[str], Engine] = build_runner_database_fleet_engine,
) -> dict[str, object]:
    """Load immutable inputs, inspect PostgreSQL read-only, and return one receipt."""

    fleet = load_runner_database_fleet(source)
    context = load_runner_database_fleet_evidence_context(source, fleet=fleet)
    verify_runner_database_fleet_release_facts(source, context)
    verify_installed_runner_database_fleet_lineage(context)
    trust_pins = load_runner_database_fleet_trust_pins(
        source,
        fleet=fleet,
        context=context,
    )
    checked_at = datetime.now(UTC)
    environment_attestation = load_and_verify_runner_database_fleet_environment_attestation(
        source,
        fleet=fleet,
        context=context,
        pins=trust_pins,
        now=checked_at,
    )
    database_url, _parsed, _path = load_runner_database_fleet_admin_database_url(
        source,
        context=context,
    )
    source_sha256s = runner_database_fleet_source_sha256s()
    engine = engine_factory(database_url)
    try:
        receipt = run_runner_database_fleet_admission(
            engine=engine,
            fleet=fleet,
            context=context,
            trust_pins=trust_pins,
            environment_attestation=environment_attestation,
            source_sha256s=source_sha256s,
        )
        signed = sign_runner_database_fleet_admission_receipt(
            source,
            receipt=receipt,
            trust_pins=trust_pins,
        )
        return {
            "receipt": json.loads(signed.receipt),
            "receipt_sha256": signed.receipt_sha256,
            "schema_version": 1,
            "signature": signed.signature,
            "signature_sha256": signed.signature_sha256,
        }
    finally:
        engine.dispose()


def main() -> int:
    """Emit exactly one canonical JSON result without secret-adjacent diagnostics."""

    try:
        receipt = admit_runner_database_fleet(os.environ)
    except Exception:  # noqa: BLE001 - this CLI must not expose DSN/catalog diagnostics.
        print(
            json.dumps(
                {
                    "code": "runner_database_fleet_admission_failed",
                    "schema_version": 1,
                    "status": "fail",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "admit_runner_database_fleet",
    "build_runner_database_fleet_engine",
    "main",
    "runner_database_fleet_source_sha256s",
]
