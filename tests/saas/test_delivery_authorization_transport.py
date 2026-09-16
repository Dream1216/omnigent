"""Real TLS transport for the dedicated DCP authorization backchannel."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from uuid import UUID, uuid4

import httpx
import pytest
import uvicorn

from saas.control_plane.db_models import GlobalUser
from saas.delivery.authorization import create_authorization_app
from tests.saas.test_billing_metering_transport import _certificate_fixture
from tests.saas.test_delivery_http import build_harness


def test_real_mtls_authorization_and_fail_closed_revocation(tmp_path):
    from omnigent_dcp.auth.revalidation import HttpHighRiskRevalidator, OnlineAuthorizationConfig
    from omnigent_dcp.domain.models import ActorContext

    h = build_harness(app_database=f"sqlite+pysqlite:///{tmp_path / 'authority.sqlite3'}")
    certs = _certificate_fixture(tmp_path, (uuid4(),))
    server_files, client_files = certs["server"], certs["runner-0"]
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(
        uvicorn.Config(
            create_authorization_app(h.authority),
            ssl_certfile=str(server_files.certificate),
            ssl_keyfile=str(server_files.private_key),
            ssl_ca_certs=str(server_files.ca),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            access_log=False,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    endpoint = f"https://127.0.0.1:{listener.getsockname()[1]}/authorize"
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        adapter = HttpHighRiskRevalidator(
            OnlineAuthorizationConfig(
                endpoint=endpoint,
                ca_file=client_files.ca,
                certificate_file=client_files.certificate,
                private_key_file=client_files.private_key,
            )
        )
        actor = ActorContext(
            tenant_id=str(h.context.tenant_id),
            project_id=str(h.project.project_id),
            actor_id=str(h.context.actor_id),
            membership_version=h.context.tenant_membership_version,
            token_id="transport-test",
            permissions=frozenset(),
        )
        resource = {
            "environment_id": "production",
            "environment_type": "production",
            "artifact_ref": "registry.test/app@sha256:" + "a" * 64,
        }

        def allowed(identity=actor, target=resource):
            return adapter.authorize_resource(
                identity=identity, action="deployment:rollback:production", resource=target
            )

        assert allowed()
        assert not allowed(actor.model_copy(update={"project_id": str(uuid4())}))
        assert not allowed(actor.model_copy(update={"membership_version": 99}))
        assert not allowed(target={**resource, "environment_id": "other"})
        # The public Cookie listener never exposes this authority.
        assert (
            h.client.post(
                "/authorize",
                json={},
                headers={"Origin": "http://testserver", "X-CSRF-Token": h.csrf},
            ).status_code
            == 404
        )
        with httpx.Client(
            verify=ssl.create_default_context(cafile=str(server_files.ca)),
            trust_env=False,
            timeout=2,
        ) as client:
            with pytest.raises(httpx.HTTPError):
                client.post(endpoint, json={})
        with h.app.state.saas_test_sessions.begin() as session:
            session.get(GlobalUser, UUID(h.scope["user_id"])).status = "suspended"
        assert not allowed()
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert not allowed()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        h.client.close()
        h.engine.dispose()
        h.app.state.saas_test_engine.dispose()
