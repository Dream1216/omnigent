from __future__ import annotations

import json
import ssl
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from saas.control_plane.identity_events import IdentitySyncError, ProviderIdentityState
from saas.control_plane.identity_private_channel import PrivateIdentityKeys
from saas.control_plane.identity_read_protocol import (
    IDENTITY_READ_KEY_ID,
    IDENTITY_READ_PATH,
    IDENTITY_READ_SECRET,
    encode_identity_read,
)
from saas.production.identity_read_broker import (
    IdentityReadBrokerPins,
    create_identity_read_broker,
)
from saas.production.identity_read_client import IdentityReadClient, IdentityReadClientConfig
from tests.saas.test_identity_sync import ISSUER, SUBJECT, Provider

REVISION = "a" * 40
SOURCE_LOCK = "b" * 64
SECRET = "worker-read-only-" + "s" * 40
HEADERS = {IDENTITY_READ_KEY_ID: "current", IDENTITY_READ_SECRET: SECRET}


class Reader(Provider):
    def __init__(self):
        super().__init__()
        self.verifications = 0

    def verify_organization(self):
        self.verifications += 1
        if self.error:
            raise self.error


@pytest.fixture
def broker():
    provider = Reader()
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    app = create_identity_read_broker(
        provider, pins=pins, keys=PrivateIdentityKeys({"current": SECRET})
    )
    with TestClient(app, base_url="https://reader.example.test") as client:
        yield provider, pins, client


def bridge(client):
    def handle(request):
        response = client.request(
            request.method, str(request.url), headers=request.headers, content=request.read()
        )
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )

    return httpx.MockTransport(handle)


def reader_client(pins, transport, **changes):
    config = IdentityReadClientConfig("https://reader.example.test", "current", SECRET, pins)
    return IdentityReadClient(replace(config, **changes), transport=transport)


def test_worker_read_capability_receives_only_validated_credential_free_state(broker):
    provider, pins, api = broker
    client = reader_client(pins, bridge(api))
    assert client.read_identity(SUBJECT) == provider.state
    assert client.read_identity(SUBJECT) == provider.state
    assert provider.verifications == 2 and provider.calls == [SUBJECT, SUBJECT]
    response = api.get(IDENTITY_READ_PATH, params={"subject": SUBJECT}, headers=HEADERS)
    assert response.headers["cache-control"] == "no-store"
    assert set(response.json()["identity"]) == set(ProviderIdentityState.__dataclass_fields__)
    assert all(
        term not in response.text for term in (SECRET, "passwordSalt", "password_hash", "$argon2")
    )
    assert SECRET not in repr(client._config)


def test_phone_state_uses_explicit_v2_wire_contract_and_rejects_old_schema(broker):
    provider, pins, api = broker
    provider.state = replace(provider.state, phone_e164="+12025550100", phone_verified=True)
    observed = reader_client(pins, bridge(api)).read_identity(SUBJECT)
    assert observed.phone_e164 == "+12025550100" and observed.phone_verified
    payload = api.get(IDENTITY_READ_PATH, params={"subject": SUBJECT}, headers=HEADERS).json()
    assert payload["schema_version"] == 2
    payload["schema_version"] = 1
    with pytest.raises(IdentitySyncError, match="reader_response_invalid"):
        reader_client(
            pins, httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
        ).read_identity(SUBJECT)


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", IDENTITY_READ_PATH),
        ("PUT", IDENTITY_READ_PATH),
        ("DELETE", IDENTITY_READ_PATH),
        ("POST", "/api/add-user"),
        ("POST", "/api/update-user"),
        ("POST", "/api/delete-user"),
        ("POST", "/api/set-password"),
        ("GET", "/api/get-user"),
        ("GET", "/api/get-organization"),
        ("GET", "/openapi.json"),
        ("GET", "/docs"),
    ],
)
def test_read_credential_does_not_enable_any_provider_api_or_mutation(broker, method, path):
    provider, _pins, api = broker
    response = api.request(method, path, headers=HEADERS, params={"subject": SUBJECT})
    assert response.status_code in {404, 405}
    assert provider.calls == [] and provider.verifications == 0


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Cookie": "session=valid-browser-session"},
        {"Authorization": "Basic aWQ6c2VjcmV0"},
        {**HEADERS, IDENTITY_READ_KEY_ID: "unknown"},
        {**HEADERS, IDENTITY_READ_SECRET: "wrong"},
        [
            (IDENTITY_READ_KEY_ID, "current"),
            (IDENTITY_READ_KEY_ID, "previous"),
            (IDENTITY_READ_SECRET, SECRET),
        ],
    ],
)
def test_broker_authentication_is_independent_of_browser_oauth_and_duplicate_headers(
    broker, headers
):
    provider, _pins, api = broker
    response = api.get(IDENTITY_READ_PATH, params={"subject": SUBJECT}, headers=headers)
    assert response.status_code == 401 and provider.verifications == 0


@pytest.mark.parametrize(
    "query",
    [
        {},
        {"email": "owner@example.test"},
        {"subject": ""},
        {"subject": "a" * 513},
        {"subject": SUBJECT, "organization": "built-in"},
        {"subject": SUBJECT, "owner": "other"},
        {"subject": SUBJECT, "url": "https://attacker.test"},
        [("subject", SUBJECT), ("subject", "other")],
        {"subject": "bad\nsubject"},
    ],
)
def test_target_namespace_paths_and_locator_kinds_cannot_be_supplied_by_client(broker, query):
    provider, _pins, api = broker
    assert api.get(IDENTITY_READ_PATH, params=query, headers=HEADERS).status_code == 400
    assert provider.verifications == 0


def test_even_authenticated_get_body_is_not_forwarded_to_provider(broker):
    provider, _pins, api = broker
    response = api.request(
        "GET",
        IDENTITY_READ_PATH,
        params={"subject": SUBJECT},
        headers=HEADERS,
        content=b'{"owner":"built-in","isAdmin":true}',
    )
    assert response.status_code == 400 and provider.verifications == 0


def test_https_cannot_be_forged_by_forwarded_headers(broker):
    provider, _pins, api = broker
    response = api.get(
        "http://reader.example.test" + IDENTITY_READ_PATH,
        params={"subject": SUBJECT},
        headers={**HEADERS, "X-Forwarded-Proto": "https", "Forwarded": "proto=https"},
    )
    assert response.status_code == 403 and provider.verifications == 0


def test_provider_policy_is_rechecked_and_failure_never_looks_like_deleted_identity(broker):
    provider, pins, api = broker
    client = reader_client(pins, bridge(api))
    assert client.read_identity(SUBJECT).exists
    provider.error = IdentitySyncError("unredacted upstream secret=" + SECRET)
    response = api.get(IDENTITY_READ_PATH, params={"subject": SUBJECT}, headers=HEADERS)
    assert response.status_code == 503 and SECRET not in response.text
    with pytest.raises(IdentitySyncError, match="reader_unavailable"):
        client.read_identity(SUBJECT)
    assert provider.calls == [SUBJECT]


def test_only_successful_authenticated_null_read_can_report_missing_user(broker):
    provider, pins, api = broker
    provider.state = ProviderIdentityState(ISSUER, "customers", SUBJECT, False)
    result = reader_client(pins, bridge(api)).read_identity(SUBJECT)
    assert result.exists is False


def test_wrong_subject_readback_is_rejected_before_returning_any_provider_data(broker):
    provider, pins, api = broker
    provider.state = replace(provider.state, subject="another-user")
    with pytest.raises(IdentitySyncError, match="reader_unavailable"):
        reader_client(pins, bridge(api)).read_identity(SUBJECT)


def test_overlapping_rotation_accepts_old_and_new_reader_keys():
    provider = Reader()
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    keys = PrivateIdentityKeys({"current": SECRET, "previous": "p" * 40})
    with TestClient(
        create_identity_read_broker(provider, pins=pins, keys=keys),
        base_url="https://reader.example.test",
    ) as api:
        assert reader_client(pins, bridge(api), key_id="previous", secret="p" * 40).read_identity(
            SUBJECT
        )


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503, 302, 307])
def test_http_failure_or_redirect_cannot_be_interpreted_as_user_deletion(status):
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            status, headers={"Location": "https://attacker.test"}, json={"identity": None}
        )

    with pytest.raises(IdentitySyncError):
        reader_client(pins, httpx.MockTransport(handle)).read_identity(SUBJECT)
    assert len(calls) == 1 and calls[0].url.host == "reader.example.test"


def document():
    return encode_identity_read(
        Reader().state,
        observed_at=datetime.now(timezone.utc),
        broker_revision=REVISION,
        provider_source_lock_sha256=SOURCE_LOCK,
    )


@pytest.mark.parametrize(
    "change",
    [
        "revision",
        "source",
        "old",
        "future",
        "unknown",
        "duplicate",
        "organization",
        "subject",
        "missing",
        "flags",
        "revision_hash",
        "password_hash",
        "timestamp",
        "email",
        "oversize",
    ],
)
def test_client_rejects_unpinned_stale_malformed_or_extended_snapshot(change):
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    data = document()
    if change == "revision":
        data["broker_revision"] = "c" * 40
    if change == "source":
        data["provider_source_lock_sha256"] = "c" * 64
    if change in {"old", "future"}:
        data["observed_at"] = (
            datetime.now(timezone.utc) + timedelta(seconds=-31 if change == "old" else 31)
        ).isoformat()
    if change == "unknown":
        data["unreviewed"] = "secret"
    if change == "organization":
        data["identity"]["organization"] = "built-in"
    if change == "subject":
        data["identity"]["subject"] = "another-user"
    if change == "missing":
        data["identity"].pop("exists")
    if change == "flags":
        data["identity"]["exists"] = 1
    if change == "revision_hash":
        data["identity"]["password_revision_sha256"] = None
    if change == "password_hash":
        data["identity"]["password_hash"] = "$argon2..."
    if change == "timestamp":
        data["identity"]["password_changed_at"] = "naive-time"
    if change == "email":
        data["identity"]["email"] = "malformed"
    payload = json.dumps(data).encode()
    if change == "duplicate":
        payload = b'{"schema_version":1,' + payload[1:]
    if change == "oversize":
        payload += b" " * 17000
    with pytest.raises(IdentitySyncError, match="reader_response_invalid"):
        reader_client(
            pins,
            httpx.MockTransport(
                lambda _: httpx.Response(
                    200, headers={"Content-Type": "application/json"}, content=payload
                )
            ),
        ).read_identity(SUBJECT)


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "http://reader.example.test"},
        {"origin": "https://user:secret@reader.example.test"},
        {"origin": "https://reader.example.test/api"},
        {"origin": "https://reader.example.test?proxy=1"},
        {"origin": "https://reader.example.test:bad"},
        {"origin": "https://reader.example.test:0"},
        {"origin": "https://reader.example.test\n"},
        {"tls_context": False},
        {"tls_context": ssl._create_unverified_context()},
        {"timeout_seconds": True},
        {"timeout_seconds": 21},
    ],
)
def test_reader_client_refuses_unverified_tls_redirect_bases_and_unbounded_timeout(changes):
    pins = IdentityReadBrokerPins(ISSUER, "customers", REVISION, SOURCE_LOCK)
    with pytest.raises(ValueError):
        reader_client(pins, httpx.MockTransport(lambda _: httpx.Response(200)), **changes)
