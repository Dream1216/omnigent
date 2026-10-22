from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa

from saas.control_plane.db_models import TenantMembership
from saas.control_plane.platform_models import ModelProviderBudgetReservationRecord
from saas.production.model_run_credentials import ModelRunCredentialService
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_credentials_postgresql import _authenticator_login, _claim
from tests.saas.test_model_run_gateway import _document, _gateway
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


def test_gateway_reads_frozen_configuration_through_actual_app_and_authenticator_logins(
    interactive_postgresql,
):
    fixture = interactive_postgresql
    f = fixture.base
    with _worker_logins(f) as workers, _authenticator_login(f) as authentication:
        authority, authorized, lease = _claim(fixture, workers)
        service = ModelRunCredentialService(
            app_sessions=f.app_factory,
            authenticator_sessions=authentication,
            compatibility=authority._resolver._compatibility_policy,
        )
        issued = service.issue(authorized, lease)
        grant = service.authorize(service.authenticate(issued.value))
        client, accessed = _gateway(service, [datetime.now(timezone.utc)])
        responses = grant.configuration["wire_api"] == "openai_responses"
        path = "/v1/responses" if responses else "/v1/chat/completions"
        body = _document(grant.configuration["public_model_id"], responses=responses)
        with f.factory() as db:
            original_count = db.scalar(
                sa.select(sa.func.count()).select_from(ModelProviderBudgetReservationRecord)
            )
        try:
            result = client.post(
                path, json=body, headers={"Authorization": "Bearer " + issued.value}
            )
            assert result.status_code == 503
            assert result.json()["error"]["code"] == "platform_model_run_execution_unavailable"
            with f.factory.begin() as db:
                db.execute(
                    sa.update(TenantMembership)
                    .where(
                        TenantMembership.tenant_id == authorized.runtime.tenant_id,
                        TenantMembership.user_id == authorized.runtime.actor_id,
                    )
                    .values(status="suspended")
                )
            denied = client.post(
                path, json=body, headers={"Authorization": "Bearer " + issued.value}
            )
            assert denied.status_code == 403
            assert denied.json()["error"]["code"] == "platform_model_run_authority_unavailable"
            assert accessed == []
            with f.factory() as db:
                assert (
                    db.scalar(
                        sa.select(sa.func.count()).select_from(
                            ModelProviderBudgetReservationRecord
                        )
                    )
                    == original_count
                )
        finally:
            client.close()
