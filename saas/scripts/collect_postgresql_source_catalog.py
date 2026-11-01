"""Collect review-only schema anchors from an owned empty PostgreSQL replay.

This checkout-only engineering tool does not qualify production or update source
anchors. Review its catalogs, commit the anchors, then run the strict replay lane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections.abc import Mapping
from inspect import unwrap
from pathlib import Path

import pytest
import sqlalchemy as sa

from saas.production import postgresql_migration as pg
from tests.saas import test_production_migration_replay as replay


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _writable(anchors: Mapping[tuple[int, str, str], str]) -> dict[tuple[int, str, str], str]:
    if not isinstance(anchors, dict):
        raise TypeError("source catalog review requires copied dictionaries")
    return anchors


def collect(major: int, profile: str, output: Path, work: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=repository, check=True)
    output.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    phase = "clean"
    captured: dict[str, str] = {}
    original_require = pg._require_source_catalog_baselines
    original_inventory = pg._verify_public_schema_inventory_digest
    original_security = pg._verify_source_security_catalog_digest

    with pytest.MonkeyPatch.context() as patch:
        # Discovery lives in copied dictionaries; imported release anchors stay intact.
        for name, value in vars(pg).copy().items():
            if (
                name.endswith("_SHA256")
                and isinstance(value, dict)
                and any(
                    isinstance(key, tuple) and len(key) == 3 and isinstance(key[0], int)
                    for key in value
                )
            ):
                patch.setattr(pg, name, dict(value))
        patch.setenv("OMNIGENT_SAAS_REPLAY_ROLE_PROFILE", profile)

        def preflight(server_major, *, bindings=None, saas_head=None):
            assert server_major == major
            key = (major, pg._expected_head("official"), pg._expected_head("saas"))
            pg._PUBLIC_SCHEMA_INVENTORY_SHA256.setdefault(key, "0" * 64)
            _writable(pg._source_security_catalog_baselines(bindings)).setdefault(key, "0" * 64)
            return original_require(major, bindings=bindings, saas_head=saas_head)

        def inventory(rows, *, key):
            label = phase + "-inventory"
            if label not in captured:
                captured[label] = _digest(rows)
                (output / (label + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
                target = (
                    pg._PUBLIC_SCHEMA_INVENTORY_SHA256
                    if phase == "clean"
                    else pg._PREVIEW_AUTHORITY_PUBLIC_SCHEMA_INVENTORY_SHA256
                )
                _writable(target)[key] = captured[label]
            return original_inventory(rows, key=key)

        def security(catalog, *, key, role_aliases, bindings=None):
            normalized = pg._normalize_source_catalog(catalog, role_aliases=role_aliases)
            normalized = pg._source_catalog_without_dormant_projection_role(
                normalized, saas_head=key[2]
            )
            normalized = pg._sort_normalized_source_catalog_rows(normalized)
            label = phase + "-security"
            if label not in captured:
                captured[label] = _digest(normalized)
                (output / (label + ".json")).write_text(
                    json.dumps(normalized, indent=2, sort_keys=True) + "\n"
                )
                if phase == "clean":
                    target = pg._source_security_catalog_baselines(bindings)
                elif profile == "admin":
                    target = pg._PREVIEW_AUTHORITY_PLATFORM_ADMIN_SOURCE_SECURITY_CATALOG_SHA256
                else:
                    target = pg._PREVIEW_AUTHORITY_MODEL_PROJECTION_SOURCE_SECURITY_CATALOG_SHA256
                _writable(target)[key] = captured[label]
            return original_security(
                catalog, key=key, role_aliases=role_aliases, bindings=bindings
            )

        patch.setattr(pg, "_require_source_catalog_baselines", preflight)
        patch.setattr(pg, "_verify_public_schema_inventory_digest", inventory)
        patch.setattr(pg, "_verify_source_security_catalog_digest", security)
        fixture = unwrap(replay.production_replay)(work, patch)
        try:
            # The shared fixture requires a fresh loopback cluster containing only
            # postgres, then configures verified TLS and four non-bypass authorities.
            plan = next(fixture)
            first = pg.run_production_postgresql_migration(plan)
            verified = pg.run_production_postgresql_migration(plan, verify_only=True)
            repeated = pg.run_production_postgresql_migration(plan)
            assert first.catalog_sha256 == verified.catalog_sha256 == repeated.catalog_sha256
            if profile in {"admin", "projection"}:
                url = sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"])
                engine = sa.create_engine(
                    url.set(database="admission_replay", query=plan.saas_owner.url.query)
                )
                try:
                    with engine.begin() as connection:
                        connection.exec_driver_sql(
                            (
                                repository / "tests/saas/fixtures/production_preview_authority.sql"
                            ).read_text()
                        )
                finally:
                    engine.dispose()
                phase = "preview"
                preview = pg.run_production_postgresql_migration(plan, verify_only=True)
                reapplied = pg.run_production_postgresql_migration(plan)
                assert preview.catalog_sha256 == reapplied.catalog_sha256 != first.catalog_sha256
            inputs = [
                *sorted((repository / "saas/control_plane/migrations").rglob("*.py")),
                *sorted((repository / "saas/control_plane").glob("postgresql*.sql")),
                repository / "saas/production/postgresql_pg.py",
                repository / "tests/saas/test_production_migration_replay.py",
            ]
            document = {
                "schema_version": 1,
                "kind": "postgresql_source_catalog_review_candidate",
                "admission_eligible": False,
                "production_qualification": False,
                "source_revision": revision,
                "major": major,
                "profile": profile,
                "official_head": first.official_head,
                "saas_head": first.saas_head,
                "fixture_installed_metadata_override": True,
                "fixture_product_revision": plan.product_revision,
                "digests": captured,
                "input_sha256": {
                    str(path.relative_to(repository)): hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                    for path in inputs
                },
            }
            (output / "candidate.json").write_text(json.dumps(document, indent=2) + "\n")
        finally:
            fixture.close()
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=repository, check=True)
    print(
        json.dumps(
            {
                "status": "review_candidates_collected",
                "major": major,
                "profile": profile,
                "admission_eligible": False,
                "production_qualification": False,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=[16, 18], required=True)
    parser.add_argument(
        "--profile", choices=["core", "model", "admin", "projection"], required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    collect(args.major, args.profile, args.output, args.work)


if __name__ == "__main__":
    main()
