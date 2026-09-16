"""Exercise the App client against a real DCP-style mutual TLS listener."""

from __future__ import annotations

import asyncio
import json
import ssl
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from saas.compatibility import RequestContext
from saas.delivery.client import DeliveryClient
from tests.saas.test_billing_metering_transport import _certificate_fixture
from tests.saas.test_delivery_config import delivery_config as _delivery_config

delivery_config = _delivery_config


def test_delivery_client_uses_mtls_for_requests_and_both_readiness_paths(
    tmp_path, delivery_config
):
    certs = _certificate_fixture(tmp_path, (uuid4(),))
    server_files, client_files = certs["server"], certs["runner-0"]
    client_files.private_key.chmod(0o600)
    frozen = Path("saas/production/dcp-openapi-v1.json").read_bytes()
    public_key = serialization.load_pem_private_key(
        delivery_config.private_key, password=None
    ).public_key()
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/v1/openapi.json":
                body = frozen
            elif self.path == "/v1/builds":
                claims = jwt.decode(
                    self.headers["Authorization"].removeprefix("Bearer "),
                    public_key,
                    algorithms=["RS256"],
                    issuer=delivery_config.issuer,
                    audience="omnigent-deployment-control-plane",
                )
                observed.append(claims)
                body = json.dumps({"items": []}).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(server_files.certificate), str(server_files.private_key))
    tls.load_verify_locations(cafile=str(server_files.ca))
    tls.verify_mode = ssl.CERT_REQUIRED
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = replace(
        delivery_config,
        endpoint=f"https://127.0.0.1:{server.server_port}",
        ca_file=client_files.ca,
        client_certificate_file=client_files.certificate,
        client_private_key_file=client_files.private_key,
    )
    project = config.projects[0]
    context = RequestContext(
        actor_id=uuid4(),
        tenant_id=project.tenant_id,
        space_id=project.space_id,
        project_id=project.project_id,
        user_security_version=1,
        tenant_membership_version=1,
        space_membership_version=1,
        trace_id="delivery-mtls",
    )
    try:
        client = DeliveryClient(config)
        client.assert_ready()
        asyncio.run(client.check_contract())
        assert asyncio.run(
            client.request(context, frozenset({"build:read"}), "GET", "/v1/builds")
        ) == {"items": []}
        assert len(observed) == 1
        assert observed[0]["tenant_id"] == str(project.tenant_id)
        assert observed[0]["project_id"] == str(project.project_id)
        assert observed[0]["permissions"] == ["build:read"]
        missing = DeliveryClient(
            replace(config, client_certificate_file=None, client_private_key_file=None)
        )
        with pytest.raises(httpx.HTTPError):
            missing.assert_ready()
        with pytest.raises(httpx.HTTPError):
            asyncio.run(missing.check_contract())
        wrong_root = tmp_path / "wrong-root"
        wrong_root.mkdir()
        untrusted = _certificate_fixture(wrong_root, (uuid4(),))["runner-0"]
        untrusted.private_key.chmod(0o600)
        with pytest.raises(httpx.HTTPError):
            DeliveryClient(
                replace(
                    config,
                    client_certificate_file=untrusted.certificate,
                    client_private_key_file=untrusted.private_key,
                )
            ).assert_ready()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        assert not thread.is_alive()


def test_delivery_mtls_rejects_partial_or_exposed_private_key(tmp_path, delivery_config):
    certs = _certificate_fixture(tmp_path, (uuid4(),))["runner-0"]
    with pytest.raises(ValueError, match="both"):
        replace(delivery_config, client_certificate_file=certs.certificate)
    with pytest.raises(ValueError, match="owner-only"):
        replace(
            delivery_config,
            client_certificate_file=certs.certificate,
            client_private_key_file=certs.private_key,
        )
    certs.private_key.chmod(0o600)
    link = tmp_path / "linked-key.pem"
    link.symlink_to(certs.private_key)
    with pytest.raises(ValueError, match="regular files"):
        replace(
            delivery_config,
            client_certificate_file=certs.certificate,
            client_private_key_file=link,
        )
