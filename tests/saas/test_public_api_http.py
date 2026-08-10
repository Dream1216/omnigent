from __future__ import annotations

from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from saas.control_plane.api_credentials import ApiCredentialError
from saas.control_plane.api_http import create_public_api_router
from saas.control_plane.http_auth import SaasAuthContextMiddleware, SaasCookieConfig
from saas.public_api_contract import PUBLIC_API_PREFIX, PUBLIC_API_VERSION


class _NoMachineAuth:
    @staticmethod
    def get_machine_principal(_request: object) -> None:
        return None


def _client() -> TestClient:
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.include_router(
        create_public_api_router(
            auth_provider=cast(object, _NoMachineAuth()),  # type: ignore[arg-type]
            public_execution=cast(object, object()),  # type: ignore[arg-type]
        ),
        prefix=PUBLIC_API_PREFIX,
    )
    return TestClient(app)


def test_public_api_auth_and_validation_failures_use_stable_envelope() -> None:
    client = _client()
    unauthenticated = client.get(
        "/api/v1/projects",
        headers={"X-Request-Id": "public-http-acceptance"},
    )
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["X-Request-Id"] == "public-http-acceptance"
    assert unauthenticated.headers["X-Omnigent-API-Version"] == PUBLIC_API_VERSION
    assert unauthenticated.json() == {
        "error": {
            "code": "service_account_authentication_required",
            "message": "Service Account authentication is required",
            "request_id": "public-http-acceptance",
            "details": {},
        }
    }

    invalid = client.get(
        "/api/v1/projects?limit=0",
        headers={"X-Request-Id": "public-validation-acceptance"},
    )
    assert invalid.status_code == 422
    assert invalid.headers["X-Omnigent-API-Version"] == PUBLIC_API_VERSION
    body = invalid.json()
    assert body["error"]["code"] == "request_validation_failed"
    assert body["error"]["request_id"] == "public-validation-acceptance"
    assert body["error"]["details"]["errors"] == [
        {"path": "query.limit", "type": "greater_than_equal"}
    ]


def test_public_openapi_is_served_from_the_isolated_authority() -> None:
    response = _client().get(
        "/api/v1/openapi.json",
        headers={"X-Request-Id": "public-openapi-acceptance"},
    )
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "public-openapi-acceptance"
    assert response.headers["X-Omnigent-API-Version"] == PUBLIC_API_VERSION
    assert response.json()["x-omnigent-api-version"] == PUBLIC_API_VERSION
    assert "/api/v1/projects" in response.json()["paths"]


def test_middleware_machine_rejection_keeps_the_public_error_contract() -> None:
    class _InvalidMachineAuth:
        @staticmethod
        def extract_token(_connection: object) -> tuple[str, str]:
            return "machine-token", "bearer"

        @staticmethod
        def is_machine_token(_token: str) -> bool:
            return True

        @staticmethod
        def validate_machine_token(_token: str, *, source_ip: str | None) -> None:
            _ = source_ip
            raise ApiCredentialError("invalid_api_credential", "API credential is invalid")

    app = FastAPI()
    app.add_middleware(
        SaasAuthContextMiddleware,
        auth_provider=cast(object, _InvalidMachineAuth()),
        context_resolver=cast(object, object()),
        cookie_config=SaasCookieConfig(),
    )
    response = TestClient(app).get(
        "/api/v1/projects",
        headers={
            "Authorization": "Bearer machine-token",
            "X-Request-Id": "middleware-public-acceptance",
        },
    )
    assert response.status_code == 401
    assert response.headers["X-Omnigent-API-Version"] == PUBLIC_API_VERSION
    assert response.json() == {
        "error": {
            "code": "invalid_api_credential",
            "message": "API credential is invalid",
            "request_id": "middleware-public-acceptance",
            "details": {},
        }
    }
