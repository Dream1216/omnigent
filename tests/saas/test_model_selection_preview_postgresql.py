from __future__ import annotations

from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane.billing_metering import BillingMeteringError
from saas.production.model_run_inference import require_current_customer_pricing
from tests.saas.test_gateway_machine_metering import _customer_prices
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def test_preview_reads_prices_only_through_dedicated_billing_login(priced_execution):
    f = priced_execution
    _customer_prices(f.factory, actor=f.scope.owner_id, tenant=f.scope.tenant_id)
    login = "preview_billing_" + uuid4().hex
    billing = None
    created = False
    try:
        with f.engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {login} LOGIN PASSWORD 'isolated-preview-test-only' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
            )
            connection.exec_driver_sql(
                f"GRANT saas_billing TO {login} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {login}'
            )
        created = True
        billing = sa.create_engine(
            f.engine.url.set(username=login, password="isolated-preview-test-only")
        )
        sessions = sessionmaker(billing, expire_on_commit=False)
        require_current_customer_pricing(sessions, f.scope.tenant_id)
        with pytest.raises(BillingMeteringError, match="unavailable"):
            require_current_customer_pricing(sessions, uuid4())
        with billing.connect() as connection:
            assert connection.exec_driver_sql("SELECT current_user=session_user").scalar_one()
            assert (
                connection.exec_driver_sql("SELECT id FROM public.saas_pricing_snapshots").all()
                == []
            )
        with pytest.raises(sa.exc.DBAPIError, match="permission denied"):
            require_current_customer_pricing(f.app_factory, f.scope.tenant_id)
        with pytest.raises(sa.exc.DBAPIError, match="permission denied"):
            with billing.begin() as connection:
                connection.exec_driver_sql("SET LOCAL ROLE saas_app")
    finally:
        if billing is not None:
            billing.dispose()
        if created:
            with f.engine.begin() as connection:
                connection.exec_driver_sql(f"DROP OWNED BY {login}")
                connection.exec_driver_sql(f"DROP ROLE {login}")
