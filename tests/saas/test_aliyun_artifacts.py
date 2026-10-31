from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from saas.compatibility.runtime_partition import bind_runtime_context
from saas.compatibility.store_adapter import OmnigentStoreAdapter
from saas.control_plane.authorization import ProjectAuthorizer
from saas.control_plane.db_models import RuntimeResourceBindingRecord
from saas.control_plane.http_auth import (
    SaasAuthContextMiddleware,
    SaasAuthProvider,
    SaasCookieConfig,
)
from saas.control_plane.lifecycle import MembershipLifecycleService
from saas.control_plane.resolver import SqlAlchemyContextResolver
from saas.production.aliyun_artifacts import (
    AliyunArtifactReader,
    ArtifactAccessDenied,
    ArtifactUnavailable,
    create_aliyun_artifact_router,
)
from tests.saas.test_aliyun_model_broker import broker_case as broker_case
from tests.saas.test_aliyun_storage_admission import _binding, _project
from tests.saas.test_aliyun_storage_admission import storage_case as storage_case
from tests.saas.test_control_plane_resolver import COMPATIBILITY_POLICY
from tests.saas.test_control_plane_resolver import control_plane as control_plane

ETAG = '"' + "a" * 32 + '"'


class CloudStream(httpx.AsyncByteStream):
    def __init__(self, chunks, on_chunk=None):
        self.chunks = chunks
        self.closed = False
        self.on_chunk = on_chunk

    async def __aiter__(self):
        for index, chunk in enumerate(self.chunks):
            if self.on_chunk is not None:
                self.on_chunk(index)
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.fixture
def artifact_case(storage_case, tmp_path):
    c = storage_case
    c.storage_config = replace(c.storage_config, project_scoped=True)
    c.requests, c.streams, c.clients = [], [], []
    c.now = int(time.time())
    c.payload = b"saved output\n"
    c.file_path = "report.txt"
    c.xml_override = None
    c.cloud_status = 200
    c.headers_override = {}
    c.chunks_override, c.on_chunk = None, None
    c.sent = []
    c.read_credential = tmp_path / "output-reader.json"
    c.credentials = {
        "schema_version": 1,
        "issued_at": c.now - 1,
        "expires_at": c.now + 1800,
        "access_key_id": "STS." + "r" * 24,
        "access_key_secret": "s" * 32,
        "security_token": "t" * 64,
    }
    c.read_credential.write_text(
        json.dumps(c.credentials, sort_keys=True, separators=(",", ":")) + "\n"
    )
    c.read_credential.chmod(0o600)

    def cloud(request):
        c.requests.append(request)
        if "list-type" in request.url.params:
            prefix = request.url.params["prefix"]
            payload = (
                c.xml_override
                or (
                    "<ListBucketResult><EncodingType>url</EncodingType><Prefix>"
                    + quote(prefix, safe="")
                    + "</Prefix><IsTruncated>false</IsTruncated><Contents><Key>"
                    + quote(prefix + c.file_path, safe="")
                    + f"</Key><ETag>{ETAG}</ETag><Size>{len(c.payload)}</Size>"
                    + "</Contents></ListBucketResult>"
                ).encode()
            )
            headers = {"content-type": "application/xml"}
        else:
            payload = c.payload
            headers = {"content-length": str(len(payload)), "etag": ETAG}
        stream = CloudStream(c.chunks_override or [payload], c.on_chunk)
        c.streams.append(stream)
        return httpx.Response(
            c.cloud_status, stream=stream, headers={**headers, **c.headers_override}
        )

    def client():
        value = httpx.AsyncClient(transport=httpx.MockTransport(cloud), trust_env=False)
        c.clients.append(value)
        return value

    c.reader = AliyunArtifactReader(
        (c.storage_config,),
        credential_file=c.read_credential,
        authorize=c.authorize.read,
        clock=lambda: c.now,
        client_factory=client,
    )
    c.lifecycle = MembershipLifecycleService(c.factory)
    c.login = c.lifecycle.issue_auth_session(
        user_id=c.runtime.actor_id,
        authn_method="test",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    cookie = SaasCookieConfig()
    c.auth = SaasAuthProvider(c.lifecycle, cookie)
    app = FastAPI()
    app.include_router(create_aliyun_artifact_router(c.reader, c.auth), prefix="/v1")
    app.add_middleware(
        SaasAuthContextMiddleware,
        auth_provider=c.auth,
        context_resolver=SqlAlchemyContextResolver(
            c.factory, COMPATIBILITY_POLICY, ProjectAuthorizer(c.factory)
        ),
        cookie_config=cookie,
        runtime_store_adapter=OmnigentStoreAdapter("0.2.0"),
    )

    class CaptureBody:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            async def capture(message):
                if message["type"] == "http.response.body":
                    c.sent.append(message.get("body", b""))
                await send(message)

            await self.app(scope, receive, capture)

    app.add_middleware(CaptureBody)
    c.app, c.cookie = app, cookie
    c.base = f"/v1/sessions/{c.session_id.hex}/artifacts"
    return c


def _client(c, *, scoped=True):
    value = TestClient(c.app, base_url="https://next.example.test")
    value.cookies.set(c.cookie.name, c.login.token)
    if scoped:
        value.headers.update(
            {
                "X-SaaS-Tenant-Id": str(c.runtime.tenant_id),
                "X-SaaS-Space-Id": str(c.runtime.space_id),
            }
        )
    return value


def test_actual_cookie_middleware_lists_and_downloads_persisted_outputs_without_a_runner(
    artifact_case,
):
    c = artifact_case
    with _client(c) as client:
        available = client.get(c.base + "/availability")
        assert available.status_code == 200
        assert c.requests == []
        listed = client.get(c.base)
        assert listed.status_code == 200, listed.text
        assert listed.json()["data"] == [
            {
                "path": "report.txt",
                "name": "report.txt",
                "type": "file",
                "bytes": len(c.payload),
                "etag": ETAG,
            }
        ]
        downloaded = client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
        assert downloaded.status_code == 200, downloaded.text
        assert downloaded.content == c.payload
        assert downloaded.headers["content-disposition"].startswith("attachment;")
        assert downloaded.headers["cache-control"] == "private, no-store"
        assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)
    assert c.requests[-1].headers["if-match"] == ETAG
    assert c.requests[-1].headers["authorization"].startswith("OSS4-HMAC-SHA256 ")
    assert c.control.creates == []


@pytest.mark.parametrize(
    "path", ["../other.txt", "/etc/passwd", "a/../b", "a//b", "a\\b", "a\x00b"]
)
def test_traversal_is_denied_before_cloud_access(artifact_case, path):
    c = artifact_case
    with _client(c) as client:
        denied = client.get(c.base + "/content", params={"path": path, "etag": ETAG})
    assert denied.status_code == 403
    assert c.requests == []


@pytest.mark.parametrize("operation", ["availability", "list", "content"])
def test_unauthenticated_or_foreign_session_cannot_touch_oss(artifact_case, operation):
    c = artifact_case
    suffix = {"availability": "/availability", "list": "", "content": "/content"}[operation]
    params = {"path": "report.txt", "etag": ETAG} if operation == "content" else {}
    with TestClient(c.app, base_url="https://next.example.test") as client:
        assert client.get(c.base + suffix, params=params).status_code == 401
    with _client(c) as client:
        foreign = c.base.replace(c.session_id.hex, uuid4().hex)
        assert client.get(foreign + suffix, params=params).status_code == 403
    assert c.requests == []


@pytest.mark.parametrize("status", [301, 302, 307, 403, 500])
def test_provider_failure_does_not_follow_redirects_or_reveal_credentials(artifact_case, status):
    c = artifact_case
    c.cloud_status = status
    c.headers_override = {"location": "https://example.invalid/secret"}
    with _client(c) as client:
        result = client.get(c.base)
    assert result.status_code == 503
    assert len(c.requests) == 1
    assert c.credentials["access_key_id"] not in result.text
    assert all(v.is_closed for v in c.clients)


def test_cloud_listing_outside_the_admitted_prefix_is_never_forwarded(artifact_case):
    c = artifact_case
    c.xml_override = (
        b"<ListBucketResult><EncodingType>url</EncodingType><Prefix>other-session/</Prefix>"
        b"<IsTruncated>false</IsTruncated><Contents><Key>secrets.txt</Key>"
        b"<ETag>secret</ETag><Size>1</Size></Contents></ListBucketResult>"
    )
    with _client(c) as client:
        result = client.get(c.base)
    assert result.status_code == 502
    assert "secrets.txt" not in result.text


def test_xml_entities_are_rejected_without_expansion(artifact_case):
    c = artifact_case
    c.xml_override = b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><ListBucketResult>&secret;</ListBucketResult>'
    with _client(c) as client:
        assert client.get(c.base).status_code == 502


def test_oss_listing_decodes_immediate_children_folders_and_an_opaque_next_page():
    namespace = "allowed/session/outputs/"
    directory = namespace + "reports/"
    payload = (
        '<ListBucketResult xmlns="http://doc.oss-cn-hangzhou.aliyuncs.com">'
        "<EncodingType>url</EncodingType><Prefix>"
        + quote(directory, safe="")
        + "</Prefix><IsTruncated>true</IsTruncated><CommonPrefixes><Prefix>"
        + quote(directory + "drafts/", safe="")
        + "</Prefix></CommonPrefixes><Contents><Key>"
        + quote(directory + "中文 %.html", safe="")
        + f"</Key><ETag>{ETAG}</ETag><Size>0</Size></Contents>"
        + "<NextContinuationToken>opaque+cursor=</NextContinuationToken></ListBucketResult>"
    ).encode()
    result = AliyunArtifactReader._listing(payload, namespace, directory, 2)
    assert result == {
        "object": "session.artifacts",
        "next_cursor": "opaque+cursor=",
        "data": [
            {
                "path": "reports/drafts",
                "name": "drafts",
                "type": "directory",
                "bytes": None,
                "etag": None,
            },
            {
                "path": "reports/中文 %.html",
                "name": "中文 %.html",
                "type": "file",
                "bytes": 0,
                "etag": ETAG,
            },
        ],
    }


@pytest.mark.parametrize(
    "entry",
    [
        "<Contents><Key>another-session/secret.txt</Key></Contents>",
        f"<Contents><Key>outputs/nested/file</Key><ETag>{ETAG}</ETag><Size>1</Size></Contents>",
        f"<Contents><Key>outputs/../secret</Key><ETag>{ETAG}</ETag><Size>1</Size></Contents>",
        "<CommonPrefixes><Prefix>outputs/no-slash</Prefix></CommonPrefixes>",
        "<Contents><Key>outputs/file</Key><ETag>unquoted</ETag><Size>1</Size></Contents>",
        f"<Contents><Key>outputs/file</Key><ETag>{ETAG}</ETag><Size>-1</Size></Contents>",
        "<Contents><Key>outputs/%not-encoded</Key></Contents>",
    ],
)
def test_untrusted_listing_cannot_expand_the_admitted_directory(entry):
    payload = (
        "<ListBucketResult><EncodingType>url</EncodingType><Prefix>outputs/</Prefix>"
        "<IsTruncated>false</IsTruncated>" + entry + "</ListBucketResult>"
    ).encode()
    with pytest.raises((ArtifactUnavailable, ArtifactAccessDenied)):
        AliyunArtifactReader._listing(payload, "outputs/", "outputs/", 50)


def test_listing_then_revoking_browser_login_stops_download_before_cloud_access(artifact_case):
    c = artifact_case
    with _client(c) as client:
        assert client.get(c.base).status_code == 200
        c.lifecycle.revoke_auth_session(c.login.token)
        denied = client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
    assert denied.status_code == 401
    assert len(c.requests) == 1


def test_browser_download_preserves_multi_tenant_scope_without_request_headers(artifact_case):
    c = artifact_case
    with _client(c) as client:
        available = client.get(c.base + "/availability").json()
    params = {
        "path": "report.txt",
        "etag": ETAG,
        "tenant_id": available["tenant_id"],
        "space_id": available["space_id"],
        "scope": available["scope_key"],
    }
    with _client(c, scoped=False) as browser:
        assert browser.get(c.base + "/content", params=params).content == c.payload
        assert browser.get(c.base).status_code == 403
    assert len(c.requests) == 1


@pytest.mark.parametrize("change", ["tenant", "space", "partial", "scope_key"])
def test_download_context_mismatch_cannot_choose_another_output_namespace(artifact_case, change):
    c = artifact_case
    params = {
        "path": "report.txt",
        "etag": ETAG,
        "tenant_id": str(c.runtime.tenant_id),
        "space_id": str(c.runtime.space_id),
    }
    if change == "tenant":
        params["tenant_id"] = str(uuid4())
    elif change == "space":
        params["space_id"] = str(uuid4())
    elif change == "partial":
        del params["space_id"]
    else:
        params["scope"] = "0" * 64
    with _client(c) as client:
        assert client.get(c.base + "/content", params=params).status_code == 403
    assert c.requests == []


@pytest.mark.parametrize("binding_kind", ["session", "native_project"])
def test_project_move_cannot_reuse_cached_scope_or_read_the_previous_projects_outputs(
    artifact_case, binding_kind
):
    c = artifact_case
    before, after = _project(c), _project(c)
    native = uuid4()
    binding = _binding(
        c,
        project_id=before,
        **(
            {
                "resource_type": "project",
                "runtime_resource_id": native.hex,
                "saas_resource_id": before,
            }
            if binding_kind == "native_project"
            else {}
        ),
    )
    if binding_kind == "native_project":
        with bind_runtime_context(c.runtime):
            c.conversations.set_conversation_project(c.session_id.hex, native.hex)
    with _client(c) as client:
        old = client.get(c.base + "/availability").json()
        assert client.get(c.base, params={"scope": old["scope_key"]}).status_code == 200
        old_prefix = c.requests[-1].url.params["prefix"]
        assert f"/projects/{before}/" in old_prefix
        with c.factory.begin() as db:
            row = db.get(RuntimeResourceBindingRecord, binding)
            row.project_id = after
            row.binding_generation += 1
            if binding_kind == "native_project":
                row.saas_resource_id = after
        calls = len(c.requests)
        assert client.get(c.base, params={"scope": old["scope_key"]}).status_code == 403
        assert (
            client.get(
                c.base + "/content",
                params={"path": c.file_path, "etag": ETAG, "scope": old["scope_key"]},
            ).status_code
            == 403
        )
        assert len(c.requests) == calls
        fresh = client.get(c.base + "/availability").json()
        assert fresh["scope_key"] != old["scope_key"]
        assert client.get(c.base, params={"scope": fresh["scope_key"]}).status_code == 200
        new_prefix = c.requests[-1].url.params["prefix"]
        assert f"/projects/{after}/" in new_prefix and new_prefix != old_prefix
        downloaded = client.get(
            c.base + "/content",
            params={"path": c.file_path, "etag": ETAG, "scope": fresh["scope_key"]},
        )
        assert downloaded.content == c.payload
        assert c.requests[-1].url.path == "/" + new_prefix + c.file_path
        c.xml_override = (
            "<ListBucketResult><EncodingType>url</EncodingType><Prefix>"
            + quote(old_prefix, safe="")
            + "</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>"
        ).encode()
        assert client.get(c.base, params={"scope": fresh["scope_key"]}).status_code == 502
    assert c.control.creates == []


@pytest.mark.parametrize("revocation", ["login", "session", "credential_expiry", "project_move"])
def test_revocation_during_download_stops_bytes_and_closes_the_provider_stream(
    artifact_case, revocation
):
    c = artifact_case
    c.payload = b"a" * (3 * 65536)
    c.chunks_override = [c.payload[i : i + 65536] for i in range(0, len(c.payload), 65536)]
    binding = _binding(c, project_id=_project(c)) if revocation == "project_move" else None
    destination = _project(c) if binding is not None else None

    def revoke(index):
        if index != 2:
            return
        if revocation == "login":
            c.lifecycle.revoke_auth_session(c.login.token)
        elif revocation == "session":
            c.permissions.revoke(c.runtime.runtime_user_key, c.session_id.hex)
        elif revocation == "credential_expiry":
            c.now = c.credentials["expires_at"]
        else:
            with c.factory.begin() as db:
                row = db.get(RuntimeResourceBindingRecord, binding)
                row.project_id = destination
                row.binding_generation += 1

    c.on_chunk = revoke
    with _client(c) as client, pytest.raises(ArtifactAccessDenied):
        client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
    assert b"".join(c.sent) == c.payload[:65536]
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)


@pytest.mark.parametrize("length", ["2", "999999", "-1", "NaN"])
def test_inconsistent_download_length_is_not_reported_as_a_complete_file(artifact_case, length):
    c = artifact_case
    c.headers_override["content-length"] = length
    with _client(c) as client:
        if length in {"-1", "NaN"}:
            assert (
                client.get(
                    c.base + "/content", params={"path": "report.txt", "etag": ETAG}
                ).status_code
                == 502
            )
        else:
            with pytest.raises((ArtifactAccessDenied, ArtifactUnavailable)):
                client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
            assert b"".join(c.sent) == b""
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)


def test_chinese_percent_and_html_filename_is_a_scoped_attachment(artifact_case):
    c = artifact_case
    c.file_path = "中文 %.html"
    c.payload = b"<script>never inline</script>"
    with _client(c) as client:
        listed = client.get(c.base).json()["data"][0]
        result = client.get(
            c.base + "/content", params={"path": listed["path"], "etag": listed["etag"]}
        )
    assert result.status_code == 200 and result.content == c.payload
    assert result.headers["content-type"] == "application/octet-stream"
    assert "filename*=UTF-8''" in result.headers["content-disposition"]
    assert b"%25.html" in c.requests[-1].url.raw_path


@pytest.mark.asyncio
async def test_disconnect_before_iteration_still_closes_the_unread_upstream(artifact_case):
    from starlette.requests import ClientDisconnect

    c = artifact_case
    with bind_runtime_context(c.runtime):
        response = await c.reader.download(
            c.session_id, path="report.txt", etag=ETAG, check_auth=lambda: None
        )

        async def send(_message):
            raise OSError("client gone")

        async def receive():
            return {"type": "http.disconnect"}

        with pytest.raises(ClientDisconnect):
            await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)


@pytest.mark.asyncio
async def test_cancelling_an_open_request_closes_its_client(artifact_case):
    c = artifact_case
    entered, forever = asyncio.Event(), asyncio.Event()

    async def cloud(_request):
        entered.set()
        await forever.wait()

    client = httpx.AsyncClient(transport=httpx.MockTransport(cloud), trust_env=False)
    c.reader._client_factory = lambda: client
    with bind_runtime_context(c.runtime):
        task = asyncio.create_task(
            c.reader.download(c.session_id, path="report.txt", etag=ETAG, check_auth=lambda: None)
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert client.is_closed


@pytest.mark.asyncio
async def test_a_stalled_downstream_cannot_keep_the_stream_alive_past_credential_expiry(
    artifact_case,
):
    c = artifact_case
    with bind_runtime_context(c.runtime):
        response = await c.reader.download(
            c.session_id, path="report.txt", etag=ETAG, check_auth=lambda: None
        )
        c.now = c.credentials["expires_at"] - 5 - 0.02
        entered = asyncio.Event()

        async def stalled_send(_message):
            entered.set()
            await asyncio.Event().wait()

        async def receive():
            return {"type": "http.disconnect"}

        with pytest.raises(ArtifactAccessDenied, match="expired"):
            await asyncio.wait_for(
                response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, stalled_send),
                timeout=1,
            )
    assert entered.is_set()
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)


@pytest.mark.parametrize("change", ["expired", "permissions", "sdk"])
def test_invalid_reader_credentials_or_sdk_fail_before_any_cloud_request(
    artifact_case, monkeypatch, change
):
    c = artifact_case
    if change == "expired":
        c.now = c.credentials["expires_at"]
    elif change == "permissions":
        c.read_credential.chmod(0o644)
    else:
        monkeypatch.setattr("saas.production.aliyun_artifacts.version", lambda _name: "1.4.1")
    with _client(c) as client:
        assert client.get(c.base).status_code == 503
    assert c.requests == []


@pytest.mark.parametrize("change", ["etag", "compressed", "partial"])
def test_download_does_not_accept_replaced_compressed_or_partial_objects(artifact_case, change):
    c = artifact_case
    if change == "etag":
        c.headers_override["etag"] = '"replaced"'
    elif change == "compressed":
        c.headers_override["content-encoding"] = "gzip"
    else:
        c.cloud_status = 206
    with _client(c) as client:
        result = client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
    assert result.status_code in {502, 503} and c.payload not in result.content
    assert all(s.closed for s in c.streams) and all(v.is_closed for v in c.clients)


@pytest.mark.parametrize("status", [404, 412])
def test_missing_or_conditionally_changed_objects_preserve_the_safe_status(artifact_case, status):
    c = artifact_case
    c.cloud_status = status
    with _client(c) as client:
        result = client.get(c.base + "/content", params={"path": "report.txt", "etag": ETAG})
    assert result.status_code == status
    assert c.credentials["access_key_id"] not in result.text
    assert len(c.requests) == 1
