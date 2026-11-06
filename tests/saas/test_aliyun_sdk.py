from __future__ import annotations

import httpx
import pytest
from e2b.api import ApiClient
from e2b.api.client.models import SandboxDetail
from e2b.exceptions import AuthenticationException, SandboxException, SandboxNotFoundException

from saas.production.aliyun_sandbox import ALIYUN_API_URL, ALIYUN_DOMAIN
from saas.production.aliyun_sdk import (
    attach_running_sandbox,
    read_sandbox_details,
    require_qualified_sdk,
)


def _options():
    return {
        "api_key": "e2b_" + "a" * 32,
        "api_url": ALIYUN_API_URL,
        "domain": ALIYUN_DOMAIN,
        "request_timeout": 45,
        "debug": False,
    }


def _document():
    return {
        "clientID": "synthetic-client",
        "cpuCount": 2,
        "diskSizeMB": 15360,
        "endAt": "2026-10-31T00:01:00.123456Z",
        "envdVersion": "0.7.0",
        "memoryMB": 4096,
        "sandboxID": "sbx-test-1234",
        "startedAt": "2026-10-31T00:00:00.123456Z",
        "state": "running",
        "templateID": "host-template",
        "metadata": {"omnigent-lifetime-seconds": "60"},
        "domain": ALIYUN_DOMAIN,
        "envdAccessToken": "synthetic-envd-credential",
    }


def _transport(monkeypatch, status, document):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(status, json=document)

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr("e2b.api.ApiClient", lambda config: ApiClient(config, transport=transport))
    return requests


def test_real_sdk_read_and_attachment_use_only_get_and_preserve_expiry(monkeypatch):
    monkeypatch.setenv("E2B_DEBUG", "true")
    document = _document()
    requests = _transport(monkeypatch, 200, document)
    detail = read_sandbox_details("sbx-test-1234", _options())
    handle = attach_running_sandbox(detail, _options())
    assert [(r.method, str(r.url)) for r in requests] == [
        ("GET", ALIYUN_API_URL + "/sandboxes/sbx-test-1234")
    ]
    assert requests[0].headers["x-api-key"] == _options()["api_key"]
    assert handle.sandbox_id == detail.sandbox_id
    assert not handle.connection_config.debug
    assert handle.sandbox_domain == ALIYUN_DOMAIN
    assert (
        handle.connection_config.sandbox_headers["X-Access-Token"] == document["envdAccessToken"]
    )
    assert detail.end_at.isoformat() == "2026-10-31T00:01:00.123456+00:00"
    assert detail.started_at.isoformat() == "2026-10-31T00:00:00.123456+00:00"


@pytest.mark.parametrize(
    ("status", "error"),
    [(404, SandboxNotFoundException), (401, AuthenticationException), (503, SandboxException)],
)
def test_read_errors_do_not_fall_back_to_connect(monkeypatch, status, error):
    requests = _transport(monkeypatch, status, {"code": status, "message": "synthetic failure"})
    with pytest.raises(error):
        read_sandbox_details("sbx-test-1234", _options())
    assert [r.method for r in requests] == ["GET"]


@pytest.mark.parametrize("document", [{}, {**_document(), "startedAt": "invalid-private-value"}])
def test_invalid_metadata_response_is_sanitized(monkeypatch, document):
    _transport(monkeypatch, 200, document)
    with pytest.raises(SandboxException) as raised:
        read_sandbox_details("sbx-test-1234", _options())
    assert "invalid-private-value" not in str(raised.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("domain", "foreign.example.test"),
        ("envdAccessToken", "bad token"),
        ("envdVersion", "private-invalid"),
    ],
)
def test_attachment_rejects_unqualified_transport_material(field, value):
    detail = SandboxDetail.from_dict({**_document(), field: value})
    with pytest.raises(ValueError) as raised:
        attach_running_sandbox(detail, _options())
    assert value not in str(raised.value)


def test_sdk_upgrade_requires_explicit_qualification(monkeypatch):
    monkeypatch.setattr("saas.production.aliyun_sdk.version", lambda _: "2.32.0")
    with pytest.raises(ValueError, match="not qualified"):
        require_qualified_sdk()
