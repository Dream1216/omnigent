from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa

from saas.control_plane.retained_model_audit import (
    _CONTRACTS,
    verify_retained_model_audit_functions,
)
from saas.production.postgresql_migration import _expected_head
from tests.saas.test_scheduling_postgresql import _migrate


def test_packaged_audit_contract_is_exact_and_drift_is_rejected_without_repair(
    isolated_postgres_url: str,
):
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(isolated_postgres_url)
    try:
        with engine.begin() as db:
            _migrate(db, root)
            db.exec_driver_sql((root / "saas/control_plane/postgresql_roles.sql").read_text())
            original = verify_retained_model_audit_functions(db)
            if _expected_head("saas") == "p0s000000015":
                assert original == ()
                return
            assert _expected_head("saas") == "lm2s00000001"
            assert len(original) == len(set(original)) == 3
            for contract in _CONTRACTS:
                signature = contract.function + "(uuid,jsonb)"
                for mutation in (
                    f"ALTER FUNCTION {signature} SECURITY INVOKER",
                    f"ALTER FUNCTION {signature} SET search_path=public",
                    f"ALTER FUNCTION {signature} STABLE",
                    f"GRANT EXECUTE ON FUNCTION {signature} TO PUBLIC",
                    f"GRANT EXECUTE ON FUNCTION {signature} TO saas_app",
                    f"GRANT EXECUTE ON FUNCTION {signature} TO saas_dispatcher WITH GRANT OPTION",
                ):
                    with db.begin_nested() as savepoint:
                        db.exec_driver_sql(mutation)
                        with pytest.raises(RuntimeError, match="function_contract_rejected"):
                            verify_retained_model_audit_functions(db)
                        savepoint.rollback()
                    assert verify_retained_model_audit_functions(db) == original
                with db.begin_nested() as savepoint:
                    db.exec_driver_sql(f"DROP FUNCTION {signature}")
                    with pytest.raises(RuntimeError, match="function_set_incomplete"):
                        verify_retained_model_audit_functions(db)
                    savepoint.rollback()
                assert verify_retained_model_audit_functions(db) == original
    finally:
        engine.dispose()
