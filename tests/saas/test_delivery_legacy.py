"""Original browser request shapes use Cookie -> project RBAC -> JWT -> DCP."""

from uuid import uuid4

from fastapi.testclient import TestClient

from saas.delivery.access import DeliveryAccess
from saas.delivery.legacy import create_legacy_delivery_router
from tests.saas.test_delivery_http import harness, post, tick  # noqa: F401


def mount(h):
    h.app.include_router(
        create_legacy_delivery_router(
            DeliveryAccess(
                h.app.state.saas_test_auth, h.authority.resolver, h.authority.sessions, h.transport
            )
        ),
        prefix="/v1",
    )


def preview(h, mode):
    result = post(h, h.base + "/build", {"snapshot_id": h.snapshot_id, "mode": mode})
    assert result.status_code == 202, result.text
    for _ in range(3):
        tick(h)
    return h.client.get(h.base).json()["deliveries"][0]


def test_original_lists_create_actions_rollback_and_replays(harness):  # noqa: F811
    h = harness
    mount(h)
    for path in ("/v1/deployments", "/v1/builds"):
        response = h.client.get(path)
        assert response.status_code == 200, response.text
        assert response.json() == {"data": []}
    preview(h, "static")
    artifact = h.client.get(h.base).json()["releases"][0]["artifact_ref"]
    # Old create request omits source_snapshot_digest; server derives it from the verified Build.
    created = post(
        h,
        "/v1/deployments",
        {
            "project_id": str(h.project.project_id),
            "environment": "production",
            "source_revision": "a" * 40,
            "artifact_ref": artifact,
            "service_port": 8080,
            "health_path": "/",
        },
    )
    assert created.status_code == 201, created.text
    first = created.json()
    for action in ("approve", "execute"):
        result = post(h, f"/v1/deployments/{first['id']}/{action}", None)
        assert result.status_code == 200, result.text
        assert result.json()["execution_mode"] == "dcp_managed"
    tick(h)
    b = preview(h, "auto")
    promoted = post(h, f"/v1/deployments/{b['release_id']}/promote", None, "legacy-promote-repeat")
    assert promoted.status_code == 200, promoted.text
    second = promoted.json()
    tick(h)
    assert first["artifact_ref"] != second["artifact_ref"]
    again = post(h, f"/v1/deployments/{b['release_id']}/promote", None, "legacy-promote-repeat")
    assert again.status_code == 200 and again.json()["id"] == second["id"], again.text
    rollback = post(h, f"/v1/deployments/{second['id']}/rollback", None, "legacy-rollback-repeat")
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["artifact_ref"] == first["artifact_ref"]
    repeat = post(h, f"/v1/deployments/{second['id']}/rollback", None, "legacy-rollback-repeat")
    assert repeat.status_code == 200 and repeat.json()["id"] == rollback.json()["id"], repeat.text
    tick(h)
    # Historical B cannot roll back past current C with a fresh command.
    stale = post(h, f"/v1/deployments/{second['id']}/rollback", None, "new-stale-rollback")
    assert stale.status_code == 409, stale.text


def test_early_cancel_retry_and_authority_boundaries(harness):  # noqa: F811
    h = harness
    mount(h)
    created = post(h, h.base + "/build", {"snapshot_id": h.snapshot_id}).json()
    cancelled = post(h, f"/v1/builds/{created['id']}/cancel", None)
    assert cancelled.status_code == 202, cancelled.text
    assert cancelled.json()["cancel_requested"]
    tick(h)
    assert h.client.get(f"/v1/builds/{created['id']}").json()["status"] == "cancelled"
    path = f"/v1/builds/{created['id']}/retry"
    first = post(h, path, None, "same-build-retry")
    second = post(h, path, None, "same-build-retry")
    assert first.status_code == second.status_code == 202, first.text + second.text
    assert first.json()["id"] == second.json()["id"]
    assert h.client.get("/v1/deployments?project_id=" + str(uuid4())).status_code == 404
    assert h.client.post(path, json={}).status_code == 403
    with TestClient(h.app) as anonymous:
        assert anonymous.get("/v1/builds").status_code == 401


def test_session_build_shape_resolves_current_run_and_uses_checkpoint_authority(tmp_path):
    from datetime import datetime, timezone

    from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord, TaskRecord
    from tests.saas.test_delivery_http import build_harness

    class Checkpoints:
        calls = []

        async def create(self, *, identity, request, idempotency_key, correlation_id):
            assert identity.actor_id == str(h.context.actor_id)
            assert identity.project_id == str(h.project.project_id)
            assert "snapshot:create" in identity.permissions
            assert request.run_id == run_id and request.context_path == "."
            self.calls.append(idempotency_key)
            return h.delivery.snapshots.repository.get(
                identity=identity, snapshot_id=h.snapshot_id
            )

    checkpoints = Checkpoints()
    h = build_harness(
        app_database=f"sqlite+pysqlite:///{tmp_path / 'sessions.db'}",
        checkpoint_service=checkpoints,
    )
    mount(h)
    session_id, task_id, run_id = uuid4(), uuid4(), uuid4()
    scope = {
        "tenant_id": h.context.tenant_id,
        "space_id": h.context.space_id,
        "project_id": h.project.project_id,
        "created_by": h.context.actor_id,
    }
    try:
        with h.authority.sessions.begin() as db:
            db.add(ExecutionSessionRecord(id=session_id, **scope))
            db.add(TaskRecord(id=task_id, title="Build source", **scope))
            db.flush()
            db.add(
                RunRecord(
                    id=run_id,
                    session_id=session_id,
                    task_id=task_id,
                    status="succeeded",
                    terminal_at=datetime.now(timezone.utc),
                    idempotency_key="completed-run",
                    request_hash="a" * 64,
                    input={},
                    product_revision="test",
                    upstream_revision="a" * 40,
                    schema_revision="test",
                    adapter_contract_version="0.2.0",
                    **scope,
                )
            )
        session = h.client.get(f"/saas/delivery/sessions/{session_id}")
        assert session.status_code == 200, session.text
        assert session.json()["runs"][0]["id"] == str(run_id)
        body = {
            "project_id": str(h.project.project_id),
            "session_id": str(session_id),
            "environment": "preview",
            "context_path": ".",
            "mode": "auto",
            "dockerfile_path": "Dockerfile",
            "service_port": 8080,
            "health_path": "/",
        }
        result = post(h, "/v1/deployments/build", body, "legacy-session-build")
        assert result.status_code == 202, result.text
        again = post(h, "/v1/deployments/build", body, "legacy-session-build")
        assert (
            again.status_code == 202
            and again.json()["build"]["id"] == result.json()["build"]["id"]
        ), again.text
        modern = post(
            h, h.base + "/build-from-run", {"run_id": str(run_id)}, "modern-session-build"
        )
        assert modern.status_code == 202, modern.text
        assert len(checkpoints.calls) == 3
        snapshot = h.client.get(h.base).json()["snapshots"][0]
        explicit = {
            **body,
            "snapshot_ref": snapshot["oci_artifact_ref"],
            "snapshot_digest": snapshot["archive_digest"],
        }
        verified = post(h, "/v1/deployments/build", explicit, "verified-old-snapshot")
        assert verified.status_code == 202, verified.text
        rejected = post(
            h, "/v1/deployments/build", {**explicit, "snapshot_digest": "sha256:" + "0" * 64}
        )
        assert rejected.status_code == 409, rejected.text
        assert len(checkpoints.calls) == 3
        bad = post(h, "/v1/deployments/build", {**body, "context_path": "../escape"})
        assert bad.status_code == 422, bad.text
        assert h.client.get(f"/saas/delivery/sessions/{uuid4()}").json()["runs"] == []
    finally:
        h.client.close()
        h.engine.dispose()
        h.app.state.saas_test_engine.dispose()
