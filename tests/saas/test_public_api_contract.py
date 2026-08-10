from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from saas.control_plane.api_http import create_public_api_router
from saas.public_api_compatibility import find_breaking_changes
from saas.public_api_contract import (
    PUBLIC_API_PREFIX,
    PUBLIC_API_VERSION,
    ApiVersionPolicy,
    CursorError,
    FilterBoundCursorCodec,
    RunCreateRequest,
    public_openapi_document,
)
from saas.scripts.dump_public_openapi import serialized_document

_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
_CURSOR_FILTERS = {"status": ["queued", "running"]}


def _codec(*, active: str = "2026-08") -> FilterBoundCursorCodec:
    return FilterBoundCursorCodec(
        keys={
            "2026-07": b"cursor-signing-key-for-2026-07-rotation",
            "2026-08": b"cursor-signing-key-for-2026-08-rotation",
        },
        active_key_id=active,
        lifetime=timedelta(hours=2),
    )


def _encode(codec: FilterBoundCursorCodec) -> str:
    return codec.encode(
        resource="runs",
        scope="tenant:t1/space:s1/project:p1",
        filters=_CURSOR_FILTERS,
        sort=("created_at", "id"),
        position={"created_at": "2026-08-10T11:00:00Z", "id": "r1"},
        now=_NOW,
    )


def _decode(codec: FilterBoundCursorCodec, token: str, **overrides: object):
    arguments = {
        "resource": "runs",
        "scope": "tenant:t1/space:s1/project:p1",
        "filters": _CURSOR_FILTERS,
        "sort": ("created_at", "id"),
        "now": _NOW + timedelta(minutes=15),
    }
    arguments.update(overrides)
    return codec.decode(token, **arguments)  # type: ignore[arg-type]


def test_cursor_is_hmac_signed_expiring_rotatable_and_filter_bound() -> None:
    token = _encode(_codec(active="2026-07"))
    state = _decode(_codec(active="2026-08"), token)
    assert state.position == {"created_at": "2026-08-10T11:00:00Z", "id": "r1"}
    assert state.issued_at == _NOW
    assert state.expires_at == _NOW + timedelta(hours=2)

    with pytest.raises(CursorError, match="cursor is invalid"):
        _decode(_codec(), token[:-1] + ("A" if token[-1] != "A" else "B"))
    with pytest.raises(CursorError):
        _decode(_codec(), token, filters={"status": ["failed"]})
    with pytest.raises(CursorError):
        _decode(_codec(), token, scope="tenant:t1/space:s1/project:p2")
    with pytest.raises(CursorError):
        _decode(_codec(), token, resource="events")
    with pytest.raises(CursorError):
        _decode(_codec(), token, now=_NOW + timedelta(hours=2))


def test_cursor_rejects_weak_keys_invalid_json_and_naive_times() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        FilterBoundCursorCodec(keys={"weak": b"secret"}, active_key_id="weak")
    with pytest.raises(CursorError):
        _decode(_codec(), "not-json.not-a-signature")
    with pytest.raises(ValueError, match="timezone"):
        _codec().encode(
            resource="projects",
            scope="tenant:t1/space:s1",
            filters={},
            sort=("id",),
            position={"id": "p1"},
            now=_NOW.replace(tzinfo=None),
        )


def test_version_headers_are_explicit_and_deprecation_requires_a_safe_window() -> None:
    assert ApiVersionPolicy().headers() == {"X-Omnigent-API-Version": PUBLIC_API_VERSION}
    sunset = datetime(2027, 2, 10, tzinfo=timezone.utc)
    assert ApiVersionPolicy(
        deprecated=True,
        sunset_at=sunset,
        deprecation_document="https://docs.omnigent.example/migrations/v1",
    ).headers() == {
        "X-Omnigent-API-Version": PUBLIC_API_VERSION,
        "Deprecation": "true",
        "Sunset": "Wed, 10 Feb 2027 00:00:00 GMT",
        "Link": (
            '<https://docs.omnigent.example/migrations/v1>; rel="deprecation"; type="text/html"'
        ),
    }
    with pytest.raises(ValueError, match="HTTPS"):
        ApiVersionPolicy(
            deprecated=True,
            sunset_at=sunset,
            deprecation_document="http://unsafe.example/v1",
        ).headers()


def test_frozen_openapi_matches_source_and_contains_only_the_public_surface() -> None:
    frozen = Path("saas/openapi-v1.json").read_text(encoding="utf-8")
    assert frozen == serialized_document()
    document = json.loads(frozen)
    assert document["x-omnigent-api-version"] == PUBLIC_API_VERSION
    assert document["x-omnigent-stability"] == "stable"
    operations = {
        operation["operationId"]
        for path in document["paths"].values()
        for method, operation in path.items()
        if method in {"get", "post"}
    }
    assert operations == {
        "listProjects",
        "getProject",
        "createRun",
        "listRuns",
        "getRun",
        "getRunContent",
        "cancelRun",
        "retryRun",
        "listRunEvents",
    }
    assert document["components"]["securitySchemes"] == {
        "BearerAuth": {"scheme": "bearer", "type": "http"}
    }
    run_path = document["paths"]["/api/v1/projects/{project_id}/runs"]
    create_headers = {parameter["name"]: parameter for parameter in run_path["post"]["parameters"]}
    assert create_headers["Idempotency-Key"]["required"] is True
    cancel_path = document["paths"]["/api/v1/projects/{project_id}/runs/{run_id}/cancel"]["post"]
    cancel_headers = {parameter["name"]: parameter for parameter in cancel_path["parameters"]}
    assert cancel_headers["If-Match"]["required"] is True
    assert cancel_headers["Idempotency-Key"]["required"] is True
    event_operation = document["paths"]["/api/v1/projects/{project_id}/runs/{run_id}/events"][
        "get"
    ]
    assert event_operation["x-omnigent-required-permission"] == "run.read_content"
    assert event_operation["x-omnigent-cursor-binding"] == {
        "scope": ["machine_tenant_id", "machine_space_id", "project_id", "run_id"],
        "filters": ["after_sequence"],
        "sort": ["sequence", "id"],
    }
    run_metadata = document["components"]["schemas"]["RunResource"]["properties"]
    assert "input" not in run_metadata
    assert "product_revision" not in run_metadata
    assert set(document["components"]["schemas"]["RunContent"]["properties"]) == {
        "run_id",
        "input",
        "product_revision",
        "upstream_revision",
        "schema_revision",
        "adapter_contract_version",
        "etag",
    }
    assert (
        document["paths"]["/api/v1/projects/{project_id}/runs/{run_id}/content"]["get"][
            "x-omnigent-required-permission"
        ]
        == "run.read_content"
    )


def test_openapi_compatibility_guard_detects_surface_and_schema_breaks() -> None:
    baseline = public_openapi_document()
    assert find_breaking_changes(baseline, deepcopy(baseline)) == ()

    missing_operation = deepcopy(baseline)
    del missing_operation["paths"]["/api/v1/projects"]["get"]  # type: ignore[index]
    rendered = [change.render() for change in find_breaking_changes(baseline, missing_operation)]
    assert "GET /api/v1/projects: operation was removed" in rendered

    required_query = deepcopy(baseline)
    parameters = required_query["paths"]["/api/v1/projects"]["get"]["parameters"]  # type: ignore[index]
    status_parameter = next(value for value in parameters if value["name"] == "status")
    status_parameter["required"] = True
    rendered = [change.render() for change in find_breaking_changes(baseline, required_query)]
    assert any("query:status" in change and "became required" in change for change in rendered)

    missing_response_property = deepcopy(baseline)
    del missing_response_property["components"]["schemas"]["RunResource"]["properties"][  # type: ignore[index]
        "etag"
    ]
    rendered = [
        change.render() for change in find_breaking_changes(baseline, missing_response_property)
    ]
    assert any(".etag: schema property was removed" in change for change in rendered)

    required_request_property = deepcopy(baseline)
    required_request_property["components"]["schemas"]["RunCreateRequest"][  # type: ignore[index]
        "required"
    ].append("metadata")
    rendered = [
        change.render() for change in find_breaking_changes(baseline, required_request_property)
    ]
    assert any("request properties became required" in change for change in rendered)

    additive_strict_response = deepcopy(baseline)
    additive_strict_response["components"]["schemas"]["RunResource"]["properties"][  # type: ignore[index]
        "new_server_field"
    ] = {"type": "string"}
    rendered = [
        change.render() for change in find_breaking_changes(baseline, additive_strict_response)
    ]
    assert any("strict response properties were added" in change for change in rendered)

    changed_operation = deepcopy(baseline)
    changed_operation["paths"]["/api/v1/projects"]["get"]["operationId"] = "projectsV2"  # type: ignore[index]
    changed_operation["paths"]["/api/v1/projects"]["get"][  # type: ignore[index]
        "x-omnigent-required-permission"
    ] = "project.admin"
    changed_operation["paths"]["/api/v1/projects"]["get"][  # type: ignore[index]
        "x-omnigent-cursor-binding"
    ]["filters"] = []
    rendered = [
        change.render() for change in find_breaking_changes(baseline, changed_operation)
    ]
    assert "GET /api/v1/projects: operationId changed" in rendered
    assert "GET /api/v1/projects: x-omnigent-required-permission changed" in rendered
    assert "GET /api/v1/projects: x-omnigent-cursor-binding changed" in rendered


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_public_request_models_reject_non_finite_json(value: float) -> None:
    with pytest.raises(ValidationError, match="JSON numbers must be finite"):
        RunCreateRequest(title="invalid", input={"nested": [value]})
    with pytest.raises(ValidationError, match="JSON numbers must be finite"):
        RunCreateRequest(title="invalid", input={}, metadata={"nested": {"value": value}})


def test_actual_public_router_conforms_to_frozen_contract_core() -> None:
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(
        create_public_api_router(
            auth_provider=cast(object, object()),  # type: ignore[arg-type]
            public_execution=cast(object, object()),  # type: ignore[arg-type]
        ),
        prefix=PUBLIC_API_PREFIX,
    )
    actual = app.openapi()
    frozen = public_openapi_document()
    assert set(actual["paths"]) == set(frozen["paths"])  # type: ignore[arg-type]
    assert actual["components"] == frozen["components"]  # type: ignore[index]
    compared_keys = ("operationId", "parameters", "requestBody", "responses", "security")
    for path, frozen_path in frozen["paths"].items():  # type: ignore[union-attr]
        for method, frozen_operation in frozen_path.items():  # type: ignore[union-attr]
            if method not in {"get", "post"}:
                continue
            actual_operation = actual["paths"][path][method]
            assert {
                key: frozen_operation.get(key) for key in compared_keys  # type: ignore[union-attr]
            } == {key: actual_operation.get(key) for key in compared_keys}
