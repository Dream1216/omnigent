"""Exercise current SQLite migration protection and the legacy reversible chain.

Every invocation owns two new temporary databases. PostgreSQL preserving rollback
and its independent backup/drill remain separate release gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CURRENT = "p0s000000018"
LEGACY = "p0s000000016"
REFUSAL = (
    "P18 downgrade requires reviewed runtime-maintenance inverse; "
    "never remove policy contracts implicitly"
)
P17_REFUSAL = "P17 downgrade requires reviewed preserving-driver archive; never DROP durable facts"


def _run(root: Path, database: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "OMNIGENT_SAAS_DB_URL": "sqlite:///" + str(database)}
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "saas/control_plane/alembic.ini",
            *arguments,
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def _success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode:
        raise RuntimeError("migration CLI failed:\n" + (result.stdout + result.stderr)[-8192:])


def _snapshot(database: Path) -> bytes:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        rows = {}
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ):
            quoted = '"' + name.replace('"', '""') + '"'
            # These new CI fixtures contain at most one row per table. Full-row
            # serialization also catches a lossy downgrade which raises afterward.
            rows[name] = sorted(connection.execute("SELECT * FROM " + quoted).fetchall(), key=repr)
        return json.dumps({"schema": schema, "rows": rows}, sort_keys=True).encode()


def _head(database: Path) -> str:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute("SELECT version_num FROM saas_alembic_version").fetchone()[0]


def _seed_receipt(database: Path) -> None:
    """Synthetic migration fixture, never an assertion of actual revocation delivery."""
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            "INSERT INTO saas_control_plane_outbox "
            "(id,aggregate_type,aggregate_key,event_type,payload,idempotency_key,"
            "request_hash,attempt_count) VALUES (?,?,?,?,?,?,?,?)",
            (
                "1" * 32,
                "migration_cli",
                "migration-cli-durable-fixture",
                "migration.cli.fixture",
                "{}",
                "migration-cli-durable-fixture",
                "a" * 64,
                0,
            ),
        )
        connection.execute(
            "INSERT INTO saas_revocation_replica_applied "
            "(outbox_event_id,replica_uid,process_boot_uid,listener_epoch_uid,product_revision,"
            "version_floor,applied_digest,source_created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "1" * 32,
                "2" * 32,
                "3" * 32,
                "4" * 32,
                "5" * 40,
                1,
                "b" * 64,
                "2026-10-22 00:00:00",
            ),
        )
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("migration fixture violates actual foreign keys")


def _assert_protected(
    before: bytes,
    after: bytes,
    result: subprocess.CompletedProcess[str],
    *,
    refusal: str = REFUSAL,
) -> None:
    if result.returncode == 0 or refusal not in result.stderr:
        raise RuntimeError("current downgrade did not produce the exact preserving refusal")
    if before != after:
        raise RuntimeError("rejected current downgrade changed durable schema, head, or facts")


def verify(root: Path = ROOT) -> dict[str, object]:
    # There is intentionally no database URL/path argument. An inherited business
    # database URL is never used, and existing databases are never opened for writes.
    with tempfile.TemporaryDirectory(prefix="saas-migration-cli-") as directory:
        current, legacy = (Path(directory) / name for name in ("current.db", "legacy.db"))
        if current.exists() or legacy.exists():
            raise RuntimeError("fresh independent migration fixtures required")
        _success(_run(root, current, "upgrade", "head"))
        _success(_run(root, current, "check"))
        if _head(current) != CURRENT:
            raise RuntimeError("current CLI did not migrate to the reviewed P18 head")
        _seed_receipt(current)
        before = _snapshot(current)
        rejected = _run(root, current, "downgrade", "base")
        after = _snapshot(current)
        _assert_protected(before, after, rejected)
        if _head(current) != CURRENT:
            raise RuntimeError("rejected downgrade changed the current head")
        historical = Path(directory) / "historical-p17.db"
        _success(_run(root, historical, "upgrade", "p0s000000017"))
        _seed_receipt(historical)
        historical_before = _snapshot(historical)
        historical_rejected = _run(root, historical, "downgrade", "base")
        _assert_protected(
            historical_before,
            _snapshot(historical),
            historical_rejected,
            refusal=P17_REFUSAL,
        )
        if _head(historical) != "p0s000000017":
            raise RuntimeError("historical P17 rejection changed its head")
        _success(_run(root, legacy, "upgrade", LEGACY))
        if _head(legacy) != LEGACY:
            raise RuntimeError("legacy fixture did not reach its explicit P16 head")
        _success(_run(root, legacy, "downgrade", "base"))
        with sqlite3.connect(f"file:{legacy}?mode=ro", uri=True) as connection:
            tables = {
                r[0]
                for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not tables <= {"saas_alembic_version"}:
                raise RuntimeError("legacy downgrade left application tables")
            if (
                "saas_alembic_version" in tables
                and connection.execute("SELECT count(*) FROM saas_alembic_version").fetchone()[0]
            ):
                raise RuntimeError("legacy downgrade left a revision marker")
        return {
            "status": "pass",
            "current_head": CURRENT,
            "current_upgrade_and_check": True,
            "current_base_downgrade_rejected": True,
            "historical_p17_base_downgrade_rejected": True,
            "nonempty_receipt_schema_head_and_data_preserved": True,
            "current_snapshot_sha256": hashlib.sha256(after).hexdigest(),
            "legacy_head": LEGACY,
            "legacy_downgrade_base": True,
            "independent_new_temporary_databases": True,
            "postgresql_preserving_rollback_qualified": False,
        }


def main() -> None:
    print(json.dumps(verify(), sort_keys=True))


if __name__ == "__main__":
    main()
