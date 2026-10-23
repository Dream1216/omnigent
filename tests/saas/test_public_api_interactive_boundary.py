from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from saas.control_plane import AdmissionQuotaRecord, ApiCredentialService, RunRecord, TaskRecord
from saas.control_plane.public_api import PublicApiError
from tests.saas import test_api_credentials as credentials
from tests.saas.test_public_api_postgresql import _public_service


@pytest.mark.parametrize("reserved", ["queue", "kind"])
@pytest.mark.parametrize("operation", ["create", "retry"])
def test_service_account_cannot_submit_browser_interactive_execution(
    monkeypatch, reserved, operation
):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(credentials, "_NOW", now)
    factory, ids = credentials._fixture()
    authority = ApiCredentialService(factory, credential_pepper=credentials._PEPPER)
    account = credentials._create_account(authority, ids)
    issued = authority.issue_api_credential(
        actor_id=ids["owner"],
        tenant_id=ids["tenant"],
        service_account_id=account.id,
        name="machine-key",
        permission_scopes=("run.create", "run.retry", "run.cancel"),
        allowed_networks=(),
        expires_at=now + timedelta(days=1),
        authenticated_at=now,
        idempotency_key="machine-key",
        now=now,
    )
    principal = authority.authenticate(issued.token, source_ip=None, now=now)
    with factory.begin() as db:
        db.add(
            AdmissionQuotaRecord(
                tenant_id=ids["tenant"],
                space_id=ids["space"],
                project_id=ids["project"],
                resource="run",
                limit_units=10,
                reserved_units=0,
                consumed_units=0,
                version=1,
            )
        )
    service = _public_service(factory)
    common = {
        "project_id": ids["project"],
        "title": "An authorized machine request",
        "session_id": None,
        "metadata": {},
        "trace_id": "interactive-boundary",
    }
    allowed = service.create_run(
        principal,
        **common,
        input_payload={"prompt": "ordinary machine input"},
        idempotency_key="normal-machine-run",
    )
    assert allowed.status == "queued"
    if operation == "retry":
        allowed = service.cancel_run(
            principal,
            project_id=ids["project"],
            run_id=allowed.id,
            reason="Finish the original request",
            expected_version=allowed.version,
            idempotency_key="cancel-original-run",
            trace_id="interactive-boundary",
        )
        assert allowed.status == "cancelled"
        ordinary_retry = service.retry_run(
            principal,
            project_id=ids["project"],
            run_id=allowed.id,
            expected_version=allowed.version,
            idempotency_key="ordinary-machine-retry",
            trace_id="interactive-boundary",
            input_override=None,
            metadata={},
        )
        assert ordinary_retry.status == "queued"
    input_payload = (
        {"execution": {"kind": "omnigent.interactive.v1"}} if reserved == "kind" else {}
    )
    with pytest.raises(PublicApiError) as rejected:
        if operation == "create":
            service.create_run(
                principal,
                **common,
                input_payload=input_payload,
                queue_class="managed_interactive" if reserved == "queue" else "interactive",
                idempotency_key="reserved-machine-run",
            )
        else:
            service.retry_run(
                principal,
                project_id=ids["project"],
                run_id=allowed.id,
                expected_version=allowed.version,
                idempotency_key="reserved-machine-retry",
                trace_id="interactive-boundary",
                input_override=input_payload,
                metadata={},
                queue_class="managed_interactive" if reserved == "queue" else "interactive",
            )
    assert rejected.value.code == "interactive_execution_requires_human_session"
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == (
            2 if operation == "retry" else 1
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 1
        assert db.scalar(sa.select(AdmissionQuotaRecord.reserved_units)) == 1
