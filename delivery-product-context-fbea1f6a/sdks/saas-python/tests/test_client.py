from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from omnigent_saas_client import (
    ApiTimeoutError,
    OmnigentSaasClient,
    PreconditionFailedError,
    RateLimitError,
    RunCreate,
    RunRetry,
)

_PROJECT_ID = "018f2f2a-1ee4-7d0d-9e61-49f9a23fc001"
_RUN_ID = "018f2f2a-1ee4-7d0d-9e61-49f9a23fc002"
_PROJECT = {
    "id": _PROJECT_ID,
    "space_id": "018f2f2a-1ee4-7d0d-9e61-49f9a23fc003",
    "name": "Automation",
    "visibility": "private",
    "status": "active",
    "authorization_version": 4,
    "created_at": "2026-08-10T01:00:00Z",
    "updated_at": "2026-08-10T02:00:00Z",
    "etag": 'W/"4"',
}
_RUN = {
    "id": _RUN_ID,
    "project_id": _PROJECT_ID,
    "task_id": "018f2f2a-1ee4-7d0d-9e61-49f9a23fc004",
    "session_id": None,
    "parent_run_id": None,
    "status": "queued",
    "version": 2,
    "event_sequence": 2,
    "queue_class": "interactive",
    "priority": 0,
    "metadata": {"client": "test"},
    "created_at": "2026-08-10T01:00:00Z",
    "updated_at": "2026-08-10T01:00:01Z",
    "terminal_at": None,
    "etag": 'W/"2"',
}
_CONTENT = {
    "run_id": _RUN_ID,
    "input": {"prompt": "private"},
    "product_revision": "product-sha",
    "upstream_revision": "upstream-sha",
    "schema_revision": "pc6",
    "adapter_contract_version": "v1",
    "etag": 'W/"2"',
}


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> OmnigentSaasClient:
    return OmnigentSaasClient(
        base_url="http://localhost:8765",
        api_key="omk_not-logged",
        timeout=httpx.Timeout(1.0),
        allow_insecure_localhost=True,
        transport=httpx.MockTransport(handler),
    )


def test_projects_and_cursors_are_typed_opaque_and_metadata_only() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/v1/projects":
            return httpx.Response(
                200,
                json={"items": [_PROJECT], "next_cursor": "opaque.cursor"},
            )
        return httpx.Response(200, json=_PROJECT, headers={"ETag": 'W/"4"'})

    with _client(handler) as client:
        page = client.list_projects(limit=10, cursor="prior.cursor", status="active")
        project = client.get_project(_PROJECT_ID)
        assert "omk_not-logged" not in repr(client)

    assert page.items[0].name == "Automation"
    assert page.next_cursor == "opaque.cursor"
    assert project.etag == 'W/"4"'
    assert "input" not in _PROJECT
    assert requests[0].url.params.multi_items() == [
        ("limit", "10"),
        ("cursor", "prior.cursor"),
        ("status", "active"),
    ]
    assert requests[0].headers["Authorization"] == "Bearer omk_not-logged"


def test_run_mutations_send_idempotency_etag_and_content_is_explicit() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/content"):
            return httpx.Response(200, json=_CONTENT, headers={"ETag": 'W/"2"'})
        return httpx.Response(
            201 if request.url.path.endswith(("/runs", "/retry")) else 200,
            json=_RUN,
            headers={"ETag": 'W/"2"'},
        )

    with _client(handler) as client:
        created = client.create_run(
            _PROJECT_ID,
            RunCreate(title="Review", input={"prompt": "secret"}),
            idempotency_key="create-42",
        )
        cancelled = client.cancel_run(
            _PROJECT_ID,
            _RUN_ID,
            if_match=created.etag,
            idempotency_key="cancel-42",
            reason="operator request",
        )
        retried = client.retry_run(
            _PROJECT_ID,
            _RUN_ID,
            RunRetry(priority=10),
            if_match=cancelled.etag,
            idempotency_key="retry-42",
        )
        content = client.get_run_content(_PROJECT_ID, _RUN_ID)

    assert created.id == _RUN_ID
    assert retried.priority == 0
    assert content.input == {"prompt": "private"}
    assert content.product_revision == "product-sha"
    create, cancel, retry, content_request = requests
    assert create.headers["Idempotency-Key"] == "create-42"
    assert "If-Match" not in create.headers
    assert cancel.headers["Idempotency-Key"] == "cancel-42"
    assert cancel.headers["If-Match"] == 'W/"2"'
    assert retry.headers["Idempotency-Key"] == "retry-42"
    assert retry.headers["If-Match"] == 'W/"2"'
    assert content_request.url.path.endswith(f"/{_RUN_ID}/content")


def test_error_types_preserve_request_id_and_rate_limit_retry_after() -> None:
    def precondition(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            412,
            json={
                "error": {
                    "code": "etag_mismatch",
                    "message": "resource changed",
                    "request_id": "req-body",
                    "details": {"current_etag": 'W/"3"'},
                }
            },
            headers={"X-Request-Id": "req-header"},
        )

    with _client(precondition) as client, pytest.raises(PreconditionFailedError) as captured:
        client.cancel_run(
            _PROJECT_ID,
            _RUN_ID,
            if_match='W/"2"',
            idempotency_key="cancel-stale",
        )
    assert captured.value.code == "etag_mismatch"
    assert captured.value.request_id == "req-body"
    assert captured.value.details == {"current_etag": 'W/"3"'}

    def limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "7", "X-Request-Id": "req-limit"})

    with _client(limited) as client, pytest.raises(RateLimitError) as captured:
        client.list_projects()
    assert captured.value.request_id == "req-limit"
    assert captured.value.retry_after == "7"


def test_timeout_and_client_side_concurrency_validation_are_fail_closed() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("deadline", request=request)

    with _client(timeout) as client, pytest.raises(ApiTimeoutError):
        client.get_run(_PROJECT_ID, _RUN_ID)
    with _client(lambda _request: httpx.Response(200, json=_RUN)) as client:
        with pytest.raises(ValueError, match="weak version ETag"):
            client.cancel_run(
                _PROJECT_ID,
                _RUN_ID,
                if_match="2",
                idempotency_key="cancel-invalid",
            )
        with pytest.raises(ValueError, match="idempotency_key"):
            client.create_run(
                _PROJECT_ID,
                RunCreate(title="Review", input={}),
                idempotency_key=" padded ",
            )
        with pytest.raises(ValueError, match="between 1 and 100"):
            client.list_runs(_PROJECT_ID, limit=101)
        with pytest.raises(ValueError, match="non-negative integer"):
            client.list_run_events(_PROJECT_ID, _RUN_ID, after_sequence=-1)
