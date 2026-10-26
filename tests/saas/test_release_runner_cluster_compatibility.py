from __future__ import annotations

import re
from pathlib import Path

_SQL = (
    Path(__file__).resolve().parents[2] / "saas/control_plane/postgresql_runner_agent_cluster.sql"
).read_text()
_MODEL_HEADS = ("lm2r00000001", "lm2s00000001", "lm2t00000001", "dp1a00000001")


def _heads(pattern: str) -> tuple[str, ...]:
    match = re.search(pattern, _SQL)
    assert match is not None
    return tuple(re.findall(r"'([^']+)'", match.group(1)))


def test_cluster_bootstrap_accepts_only_exact_p0_and_model_successor_heads():
    accepted = _heads(r"IF schema_head NOT IN \(([^)]+)\) THEN")
    assert accepted == ("p0s000000015", *_MODEL_HEADS)
    assert all(head not in accepted for head in ("", "lm2u00000001", "lm2t00000001-extra"))


def test_t_bootstrap_preserves_recovery_api_and_support_grant_scope():
    recovery = _heads(r"IF schema_head IN \(([^)]+)\) THEN")
    grants = _heads(
        r"IF \(SELECT version_num FROM public\.saas_alembic_version\)\s+IN \(([^)]+)\) THEN"
    )
    assert recovery == grants == _MODEL_HEADS
    assert "'saas_interactive_recovery_owner_v1(uuid,bigint,uuid,bigint,jsonb)'" in _SQL
    assert "GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint)" in _SQL
    assert "GRANT EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_xact_lock(bigint)" in _SQL


def test_t_support_does_not_relax_cluster_or_owner_admission():
    assert "IF server_major <> 18 OR NOT COALESCE(caller_is_superuser, false) THEN" in _SQL
    assert "'Runner cluster admission rejected: PostgreSQL 18 superuser required'" in _SQL
    assert "runner_role.rolsuper" in _SQL and "runner_role.rolbypassrls" in _SQL
    assert "schema_owner.rolsuper" in _SQL and "schema_owner.rolbypassrls" in _SQL
    assert "'Runner cluster admission rejected: Runner API owner drifted'" in _SQL
