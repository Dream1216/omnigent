from __future__ import annotations

import json
from hashlib import sha256
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from alibabacloud_tea_openapi.utils import Utils
from darabonba.request import DaraRequest

from saas.production.aliyun_storage import AliyunStorageError
from saas.production.aliyun_volume_control import AliyunVolumeControlClient
from tests.saas.test_aliyun_storage import _config, _volume
from tests.saas.test_tenant_sandbox import _runtime


@pytest.fixture
def api_case(tmp_path):
    runtime = _runtime()
    config = _config(runtime)
    document = {
        "schema_version": 1,
        "issued_at": 990,
        "expires_at": 1300,
        "access_key_id": "STS." + "a" * 24,
        "access_key_secret": "synthetic-private-secret-1234",
        "security_token": "synthetic-private-session-token",
    }
    path = tmp_path / "storage-sts"

    def save():
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
        path.chmod(0o600)

    save()
    requests = []
    result = {"code": "200", "volumes": []}

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=result)

    def build(respond=handler, *, redirects=False):
        return AliyunVolumeControlClient(
            team_id=config.team_id,
            credential_file=path,
            clock=lambda: 1000,
            client_factory=lambda: httpx.Client(
                transport=httpx.MockTransport(respond), follow_redirects=redirects, trust_env=False
            ),
        )

    return SimpleNamespace(
        runtime=runtime,
        config=config,
        document=document,
        path=path,
        save=save,
        requests=requests,
        result=result,
        build=build,
    )


def _assert_signature(request, document):
    signed = DaraRequest()
    signed.method = request.method
    signed.pathname = request.url.path
    signed.query = dict(request.url.params)
    names = (
        request.headers["authorization"]
        .split("SignedHeaders=", 1)[1]
        .split(",Signature=", 1)[0]
        .split(";")
    )
    assert {
        "host",
        "x-acs-action",
        "x-acs-date",
        "x-acs-content-sha256",
        "x-acs-accesskey-id",
        "x-acs-security-token",
        "x-acs-signature-nonce",
        "x-acs-version",
    }.issubset(names)
    signed.headers = {name: request.headers[name] for name in names}
    assert signed.headers["x-acs-content-sha256"] == sha256(request.content).hexdigest()
    expected = Utils.get_authorization(
        signed,
        "ACS3-HMAC-SHA256",
        sha256(request.content).hexdigest(),
        document["access_key_id"],
        document["access_key_secret"],
    )
    assert request.headers["authorization"] == expected


def test_real_sdk_models_and_signer_use_fixed_endpoint_and_explicit_sts(
    api_case, monkeypatch, capsys
):
    c = api_case
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://untrusted.invalid:99")
    monkeypatch.setenv("DEBUG", "sdk")
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "wrong-ambient-secret")
    api = c.build()
    spec = c.config.session(c.runtime, uuid4()).volumes[0]
    c.result.update({"volume": _volume(spec)})
    result = api.create(spec)
    assert result["volumeName"] == spec.name
    request = c.requests[-1]
    assert request.method == "POST"
    assert str(request.url) == "https://sandbox.cn-hangzhou.aliyuncs.com/pop/2026-08-20/volumes"
    body = json.loads(request.content)
    assert body["teamID"] == str(c.config.team_id)
    assert body["ossVolumeConfig"]["readOnly"] is True
    assert body["ossVolumeConfig"]["bucketPath"] == spec.bucket_path
    assert body["mountConfig"]["role"] == c.config.role_arn
    assert request.headers["x-acs-security-token"] == c.document["security_token"]
    assert c.document["access_key_secret"] not in str(request.headers)
    assert c.document["security_token"] not in str(request.url)
    _assert_signature(request, c.document)
    assert c.document["security_token"] not in capsys.readouterr().out


def test_list_and_get_use_team_scoped_native_sdk_queries(api_case):
    c = api_case
    spec = c.config.session(c.runtime, uuid4()).volumes[1]
    volume = _volume(spec)
    c.result.update({"volumes": [volume], "volume": volume})
    api = c.build()
    assert api.find(team_id=c.config.team_id, name=spec.name)[0]["volumeID"] == volume["volumeID"]
    assert dict(c.requests[-1].url.params) == {
        "teamID": str(c.config.team_id),
        "volumeName": spec.name,
        "maxResults": "2",
    }
    assert (
        api.read(team_id=c.config.team_id, volume_id=volume["volumeID"])["volumeName"] == spec.name
    )
    assert c.requests[-1].url.path.endswith("/" + volume["volumeID"])
    assert dict(c.requests[-1].url.params) == {"teamID": str(c.config.team_id)}
    for request in c.requests:
        _assert_signature(request, c.document)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_do_not_export_sts_headers_even_with_redirecting_client(api_case, status):
    c = api_case
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://untrusted.example"})

    with pytest.raises(AliyunStorageError):
        c.build(handler, redirects=True).find(team_id=c.config.team_id, name="omni-in-" + "a" * 40)
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("issued_at", 2000),
        ("expires_at", 1001),
        ("expires_at", 10000),
        ("access_key_id", "LTAI" + "a" * 24),
        ("security_token", ""),
        ("access_key_secret", "private secret with spaces"),
    ],
)
def test_invalid_or_long_term_credentials_never_reach_transport(api_case, field, value):
    c = api_case
    c.document[field] = value
    c.save()
    with pytest.raises(AliyunStorageError) as raised:
        c.build().find(team_id=c.config.team_id, name="omni-in-" + "a" * 40)
    assert c.requests == []
    assert c.document["access_key_secret"] not in str(raised.value)


def test_sts_rotation_is_read_from_private_file_for_every_operation(api_case):
    c = api_case
    api = c.build()
    name = "omni-in-" + "a" * 40
    api.find(team_id=c.config.team_id, name=name)
    c.document["security_token"] += "-rotated"
    c.save()
    api.find(team_id=c.config.team_id, name=name)
    assert (
        c.requests[0].headers["x-acs-security-token"]
        != c.requests[1].headers["x-acs-security-token"]
    )


def test_wrong_team_and_unsafe_names_are_denied_without_network(api_case):
    c = api_case
    for team, name in ((uuid4(), "omni-in-" + "a" * 40), (c.config.team_id, "../other")):
        with pytest.raises(AliyunStorageError):
            c.build().find(team_id=team, name=name)
    assert c.requests == []


def test_ambiguous_transport_failure_has_no_retry_or_private_diagnostic(api_case):
    c = api_case
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("private signed request material")

    with pytest.raises(AliyunStorageError) as raised:
        c.build(handler).find(team_id=c.config.team_id, name="omni-in-" + "a" * 40)
    assert len(calls) == 1
    assert "private signed request material" not in str(raised.value)


def test_ambiguous_or_paged_volume_lookup_is_not_accepted(api_case):
    c = api_case
    c.result["nextToken"] = "more-results"
    with pytest.raises(AliyunStorageError, match="ambiguous"):
        c.build().find(team_id=c.config.team_id, name="omni-in-" + "a" * 40)


def test_unqualified_pop_sdk_version_requires_revalidation(api_case, monkeypatch):
    monkeypatch.setattr("saas.production.aliyun_volume_control.version", lambda _: "1.3.0")
    with pytest.raises(AliyunStorageError, match="not qualified"):
        api_case.build().prepare()


@pytest.mark.parametrize("kind", ["permissions", "symlink", "hardlink"])
def test_sts_file_must_be_private_owned_and_unlinked(api_case, tmp_path, kind):
    c = api_case
    if kind == "permissions":
        c.path.chmod(0o640)
    elif kind == "symlink":
        original = tmp_path / "original"
        c.path.rename(original)
        c.path.symlink_to(original)
    else:
        import os

        os.link(c.path, tmp_path / "other-link")
    with pytest.raises(AliyunStorageError):
        c.build().find(team_id=c.config.team_id, name="omni-in-" + "a" * 40)
    assert c.requests == []


def test_large_control_responses_are_bounded_and_redacted(api_case):
    c = api_case
    with pytest.raises(AliyunStorageError) as raised:
        c.build(lambda _: httpx.Response(200, content=b"private" * 50000)).find(
            team_id=c.config.team_id, name="omni-in-" + "a" * 40
        )
    assert "private" not in str(raised.value)
