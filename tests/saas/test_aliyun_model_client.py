from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from omnigent.db.db_models import workspace_scope
from saas.production.aliyun_model_client import (
    AliyunHostModelTokenIssuer,
    AliyunModelCredentialError,
    validated_server_origin,
)
from saas.production.platform_model_relay import PlatformModelRelay, validated_model_gateway_url
from tests.saas.test_aliyun_model_broker import broker_case as broker_case
from tests.saas.test_control_plane_resolver import control_plane as control_plane


def _issuer(case, handler):
    return AliyunHostModelTokenIssuer(
        server_url="https://cloud-control.invalid",
        host_id=case.host_id,
        workspace_id=case.runtime.physical_workspace_id,
        tenant_id=case.runtime.tenant_id,
        host_token=case.token,
        lease=case.lease,
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )


def _broker_response(case, request):
    assert request.url == (
        f"https://cloud-control.invalid/v1/hosts/{case.host_id}/sessions/"
        f"{case.session_id.hex}/model-token"
    )
    assert request.method == "POST" and request.content == b""
    assert "authorization" not in request.headers
    with workspace_scope(int(request.headers["X-Omnigent-Workspace-Id"])):
        result = case.broker.issue(
            host_id=case.host_id,
            launch_token=request.headers["X-Omnigent-Host-Token"],
            lease_token=request.headers["X-Omnigent-Model-Lease"],
            session_id=case.session_id,
        )
    return httpx.Response(200, json={"token": result.token, "expires_at": result.expires_at})


def test_cloud_host_can_renew_using_only_its_host_and_lease_credentials(broker_case):
    c = broker_case
    issuer = _issuer(c, lambda request: _broker_response(c, request))
    first = issuer.issue(session_id=c.session_id, now=c.clock[0])
    assert c.authority.validate(first, now=c.clock[0]).tenant_id == c.runtime.tenant_id
    c.clock[0] += 301
    c.broker = c.build()
    second = issuer.issue(session_id=c.session_id, now=c.clock[0])
    assert first != second
    assert c.authority.validate(second, now=c.clock[0]).session_id == c.session_id
    assert c.token not in repr(issuer) and c.lease not in repr(issuer)


def test_cloud_model_relay_reaches_the_explicit_tls_gateway_and_stops_after_revocation(
    broker_case,
):
    c = broker_case
    issued_requests = []
    upstream_requests = []

    def admission(request):
        issued_requests.append(request)
        return _broker_response(c, request)

    def upstream(request):
        assert request.url == "https://cloud-model.invalid/platform-model/v1/responses"
        bearer = request.headers["authorization"].removeprefix("Bearer ")
        claims = c.authority.validate(bearer, now=c.clock[0])
        assert claims.session_id == c.session_id and claims.tenant_id == c.runtime.tenant_id
        assert c.token not in str(request.headers) and c.lease not in str(request.headers)
        upstream_requests.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b'data: {"done":true}\n\n'))

    relay = PlatformModelRelay(
        authority=_issuer(c, admission),
        session_id=c.session_id,
        ttl_seconds=300,
        gateway_base_url="https://cloud-model.invalid/platform-model/v1",
        clock=lambda: c.clock[0],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )
    with TestClient(relay.app) as client:
        headers = {"Authorization": f"Bearer {relay.capability}"}
        assert client.post("/v1/responses", headers=headers, json={}).status_code == 200
        c.clock[0] += 226
        assert client.post("/v1/responses", headers=headers, json={}).status_code == 200
        with workspace_scope(c.runtime.physical_workspace_id):
            c.hosts.revoke_launch_token(c.host_id)
        c.clock[0] += 301
        result = client.post("/v1/responses", headers=headers, json={})
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "platform_model_authentication_recovery_failed"
    assert len(issued_requests) == 3 and len(upstream_requests) == 2


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 500])
def test_remote_credential_failure_is_sanitized_and_never_redirected(broker_case, status):
    c = broker_case
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            status,
            headers={"Location": "https://foreign-origin.invalid/"},
            json={"error": c.token + c.lease},
        )

    with pytest.raises(AliyunModelCredentialError) as failure:
        _issuer(c, handler).issue(session_id=c.session_id, now=c.clock[0])
    assert len(requests) == 1
    assert c.token not in str(failure.value) and c.lease not in str(failure.value)


@pytest.mark.parametrize(
    "failure", ["tenant", "session", "expired", "long-lived", "expiry-mismatch", "oversized"]
)
def test_remote_credential_response_must_match_this_tenant_session_and_bounded_lifetime(
    broker_case, failure
):
    c = broker_case
    authority = c.authority
    if failure == "tenant":
        authority = type(authority)(signing_key=b"x" * 32, tenant_id=uuid4())
    token = authority.issue(
        session_id=uuid4() if failure == "session" else c.session_id,
        ttl_seconds=301 if failure == "long-lived" else 300,
        now=c.clock[0] - (301 if failure == "expired" else 0),
    )
    expires_at = c.clock[0] + (301 if failure in ("long-lived", "expiry-mismatch") else 300)

    def response(_request):
        if failure == "oversized":
            return httpx.Response(200, content=b"x" * 16385)
        return httpx.Response(200, json={"token": token, "expires_at": expires_at})

    with pytest.raises(AliyunModelCredentialError):
        _issuer(c, response).issue(session_id=c.session_id, now=c.clock[0])


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/foreign",
        "https://user:password@example.com",
        "https://example.com?redirect=foreign",
        "https://example.com#fragment",
        "https://example.com:8443",
        "https://example.com\\foreign",
        "https://example.com\n",
    ],
)
def test_host_control_origin_rejects_ambiguous_or_non_tls_urls(url):
    with pytest.raises(ValueError, match="TLS origin"):
        validated_server_origin(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://foreign.invalid/v1",
        "https://foreign.invalid/v1?redirect=elsewhere",
        "https://user:password@foreign.invalid/v1",
        "https://foreign.invalid/a/../v1",
        "https://foreign.invalid/a//v1",
        "https://foreign.invalid/%2e/v1",
    ],
)
def test_public_model_gateway_requires_an_explicit_canonical_tls_endpoint(url):
    with pytest.raises(ValueError, match="TLS endpoint"):
        validated_model_gateway_url(url)
