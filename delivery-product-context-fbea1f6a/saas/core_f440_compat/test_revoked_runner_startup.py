"""Run only against the isolated f440 PG18 replay fixture in the candidate image."""

import os

import pytest
import sqlalchemy as sa

from saas.production import postgresql_migration as migration
from tests.saas.test_production_migration_replay import _startup_config


def test_f440_revoked_management_edge_preserves_source_and_receipt(tmp_path, production_replay):
    plan = production_replay
    first = migration.run_production_postgresql_migration(plan)
    config, engines = _startup_config(plan, first, tmp_path)
    admin = sa.create_engine(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"])
    try:
        migration.verify_production_postgresql_state(engines=engines, config=config)
        with admin.begin() as connection:
            connection.exec_driver_sql(
                f'REVOKE saas_runner_agent FROM "{plan.principal_operator.login}" '
                "GRANTED BY CURRENT_USER RESTRICT"
            )
        verified = migration.run_production_postgresql_migration(plan, verify_only=True)
        assert verified.catalog_sha256 == first.catalog_sha256
        migration.verify_production_postgresql_state(engines=engines, config=config)
        with admin.begin() as connection:
            connection.exec_driver_sql(
                f'GRANT saas_app TO "{plan.principal_operator.login}" WITH INHERIT TRUE'
            )
        with pytest.raises(migration.PostgreSqlMigrationError):
            migration.verify_production_postgresql_state(engines=engines, config=config)
    finally:
        admin.dispose()
        for engine in engines.values():
            engine.dispose()
