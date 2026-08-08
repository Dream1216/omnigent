"""Tenant configuration and RFC 7643/7644 SCIM resource adapter."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Coroutine, Mapping
from datetime import datetime
from typing import Any, NoReturn, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from saas.compatibility import RequestContext
from saas.control_plane.enterprise_identity import (
    EnterpriseScimService,
    IssuedScimDirectory,
    ScimFilterExpression,
    ScimGroupView,
    ScimUserView,
)
from saas.control_plane.http_auth import SaasAuthProvider
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.resolver import ControlPlaneResolutionError, SqlAlchemyContextResolver

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_ETAG = re.compile(r'^W/"([1-9][0-9]*)"$')
_FILTER_ATTRIBUTES = {
    "id": "id",
    "externalid": "externalId",
    "username": "userName",
    "displayname": "displayName",
    "active": "active",
}
_MEMBER_FILTER_PATH = re.compile(
    r'^members\s*\[\s*value\s+eq\s+"([0-9a-f-]{36})"\s*\]$', re.IGNORECASE
)


class _ScimHttpError(Exception):
    def __init__(self, *, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        super().__init__(message)


class _ScimRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def scim_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except _ScimHttpError as error:
                return JSONResponse(
                    {
                        "schemas": [_ERROR_SCHEMA],
                        "status": str(error.status),
                        "scimType": error.code,
                        "detail": str(error),
                    },
                    status_code=error.status,
                    media_type="application/scim+json",
                )

        return scim_handler


class DirectoryCreateBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)


class DirectoryMutationBody(BaseModel):
    expected_version: int = Field(ge=1)


class ScimMemberBody(BaseModel):
    value: str = Field(min_length=1, max_length=64)


class ScimUserBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(min_length=1, max_length=8)
    external_id: str = Field(alias="externalId", min_length=1, max_length=256)
    user_name: str = Field(alias="userName", min_length=1, max_length=320)
    display_name: str | None = Field(default=None, alias="displayName", max_length=256)
    active: bool = Field(default=True, strict=True)


class ScimGroupBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(min_length=1, max_length=8)
    external_id: str = Field(alias="externalId", min_length=1, max_length=256)
    display_name: str = Field(alias="displayName", min_length=1, max_length=128)
    members: list[ScimMemberBody] = Field(default_factory=list, max_length=1000)


class ScimPatchBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schemas: list[str] = Field(min_length=1, max_length=8)
    operations: list[dict[str, object]] = Field(alias="Operations", min_length=1, max_length=32)


def _error(error: Exception, *, status: int | None = None) -> _ScimHttpError:
    code = getattr(error, "code", "scim_request_failed")
    resolved = status
    if resolved is None:
        if code in {"scim_authentication_failed"}:
            resolved = 401
        elif code in {"scim_resource_not_found"}:
            resolved = 404
        elif code == "scim_etag_mismatch":
            resolved = 412
        elif code in {
            "scim_event_conflict",
            "scim_external_id_immutable",
            "scim_version_conflict",
        }:
            resolved = 409
        else:
            resolved = 400
    return _ScimHttpError(status=resolved, code=code, message=str(error))


def _token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not value or len(value) > 256:
        raise _error(LifecycleError("scim_authentication_failed", "SCIM bearer token is required"))
    return value


def _tenant_context(
    request: Request,
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    tenant_id: UUID,
) -> tuple[RequestContext, datetime]:
    principal = auth_provider.get_principal(request)
    if principal is None:
        raise HTTPException(status_code=401, detail={"code": "authentication_required"})
    try:
        scopes = resolver.list_available_scopes(actor_id=principal.session.user_id)
        scope = next((value for value in scopes if value.tenant_id == tenant_id), None)
        if scope is None:
            raise ControlPlaneResolutionError("scope_not_authorized", "scope is not accessible")
        context = resolver.resolve_request_context(
            actor_id=principal.session.user_id,
            tenant_id=tenant_id,
            space_id=scope.space_id,
            trace_id=request.headers.get("x-request-id") or uuid4().hex,
        )
    except ControlPlaneResolutionError as error:
        raise HTTPException(
            status_code=404,
            detail={"code": error.code, "message": str(error)},
        ) from error
    if context.user_security_version != principal.session.security_version:
        raise HTTPException(status_code=401, detail={"code": "authorization_snapshot_stale"})
    return context, principal.session.authenticated_at


def _directory_management_error(error: LifecycleError) -> HTTPException:
    if error.code == "fresh_auth_required":
        status = 401
    elif error.code.endswith("_forbidden"):
        status = 403
    elif error.code == "scim_directory_not_found":
        status = 404
    elif error.code in {
        "invalid_idempotency_key",
        "scim_directory_version_invalid",
    }:
        status = 400
    else:
        status = 409
    return HTTPException(
        status_code=status,
        detail={"code": error.code, "message": str(error)},
    )


def _directory_payload(value: IssuedScimDirectory) -> dict[str, object]:
    return {
        "id": str(value.id),
        "tenant_id": str(value.tenant_id),
        "display_name": value.display_name,
        "token_prefix": value.token_prefix,
        "bearer_token": value.bearer_token,
        "status": value.status,
        "version": value.version,
        "replayed": value.replayed,
    }


class _ScimFilterParser:
    def __init__(self, value: str) -> None:
        self._tokens = self._tokenize(value)
        self._index = 0
        self._depth = 0

    def parse(self) -> ScimFilterExpression:
        if not self._tokens:
            self._invalid()
        expression = self._parse_or()
        if self._index != len(self._tokens):
            self._invalid()
        return expression

    def _parse_or(self) -> ScimFilterExpression:
        expression = self._parse_and()
        while self._word_at("or"):
            self._index += 1
            expression = ScimFilterExpression(
                operator="or",
                operands=(expression, self._parse_and()),
            )
        return expression

    def _parse_and(self) -> ScimFilterExpression:
        expression = self._parse_not()
        while self._word_at("and"):
            self._index += 1
            expression = ScimFilterExpression(
                operator="and",
                operands=(expression, self._parse_not()),
            )
        return expression

    def _parse_not(self) -> ScimFilterExpression:
        if self._word_at("not"):
            self._index += 1
            return ScimFilterExpression(operator="not", operands=(self._parse_not(),))
        return self._parse_primary()

    def _parse_primary(self) -> ScimFilterExpression:
        if self._kind_at("left"):
            self._index += 1
            self._depth += 1
            if self._depth > 4:
                self._invalid("SCIM filter nesting is too deep")
            expression = self._parse_or()
            if not self._kind_at("right"):
                self._invalid()
            self._index += 1
            self._depth -= 1
            return expression
        attribute_word = self._consume_word()
        attribute = _FILTER_ATTRIBUTES.get(attribute_word.casefold())
        if attribute is None:
            self._invalid("SCIM filter attribute is unsupported")
        operator = self._consume_word().casefold()
        if operator == "pr":
            return ScimFilterExpression(operator=operator, attribute=attribute)
        if operator not in {"eq", "ne", "co", "sw", "ew"}:
            self._invalid("SCIM filter operator is unsupported")
        if self._index >= len(self._tokens):
            self._invalid()
        kind, value = self._tokens[self._index]
        if kind not in {"string", "boolean"}:
            self._invalid()
        self._index += 1
        return ScimFilterExpression(operator=operator, attribute=attribute, value=value)

    def _consume_word(self) -> str:
        if not self._kind_at("word"):
            self._invalid()
        value = self._tokens[self._index][1]
        self._index += 1
        return cast(str, value)

    def _kind_at(self, kind: str) -> bool:
        return self._index < len(self._tokens) and self._tokens[self._index][0] == kind

    def _word_at(self, value: str) -> bool:
        return self._kind_at("word") and str(self._tokens[self._index][1]).casefold() == value

    @staticmethod
    def _tokenize(value: str) -> list[tuple[str, str | bool]]:
        tokens: list[tuple[str, str | bool]] = []
        index = 0
        while index < len(value):
            if value[index].isspace():
                index += 1
                continue
            if value[index] == "(":
                tokens.append(("left", "("))
                index += 1
                continue
            if value[index] == ")":
                tokens.append(("right", ")"))
                index += 1
                continue
            if value[index] == '"':
                start = index
                index += 1
                escaped = False
                while index < len(value):
                    character = value[index]
                    index += 1
                    if escaped:
                        escaped = False
                    elif character == "\\":
                        escaped = True
                    elif character == '"':
                        break
                else:
                    _ScimFilterParser._invalid()
                try:
                    decoded = json.loads(value[start:index])
                except json.JSONDecodeError as error:
                    raise _error(
                        LifecycleError("invalidFilter", "SCIM filter is invalid")
                    ) from error
                if not isinstance(decoded, str) or len(decoded) > 320:
                    _ScimFilterParser._invalid()
                tokens.append(("string", decoded))
                continue
            start = index
            while index < len(value) and not value[index].isspace() and value[index] not in "()":
                index += 1
            word = value[start:index]
            if not word or len(word) > 320:
                _ScimFilterParser._invalid()
            if word.casefold() in {"true", "false"}:
                tokens.append(("boolean", word.casefold() == "true"))
            else:
                tokens.append(("word", word))
        return tokens

    @staticmethod
    def _invalid(message: str = "SCIM filter is invalid") -> NoReturn:
        raise _error(LifecycleError("invalidFilter", message))


def _filter_expression(value: str | None) -> ScimFilterExpression | None:
    if value is None:
        return None
    if len(value) > 1024:
        raise _error(LifecycleError("invalidFilter", "SCIM filter is too long"))
    return _ScimFilterParser(value).parse()


def _sort_parts(sort_by: str | None, sort_order: str) -> tuple[str | None, str]:
    resolved_order = sort_order.casefold()
    if resolved_order not in {"ascending", "descending"}:
        raise _error(LifecycleError("invalidValue", "SCIM sort order is invalid"))
    if sort_by is None:
        return None, resolved_order
    if len(sort_by) > 64:
        raise _error(LifecycleError("invalidValue", "SCIM sort attribute is invalid"))
    resolved_attribute = _FILTER_ATTRIBUTES.get(sort_by.casefold())
    if resolved_attribute is None:
        raise _error(LifecycleError("invalidValue", "SCIM sort attribute is unsupported"))
    return resolved_attribute, resolved_order


def _list_payload(
    resources: list[dict[str, object]],
    *,
    total_results: int,
    start_index: int,
    items_per_page: int,
) -> dict[str, object]:
    return {
        "schemas": [_LIST_SCHEMA],
        "totalResults": total_results,
        "startIndex": start_index,
        "itemsPerPage": items_per_page,
        "Resources": resources,
    }


def _etag(version: int) -> str:
    return f'W/"{version}"'


def _required_version(value: str | None) -> int:
    match = _ETAG.fullmatch(value or "")
    if match is None:
        raise _error(
            LifecycleError("scim_etag_mismatch", "a valid If-Match ETag is required"),
            status=412,
        )
    return int(match.group(1))


def _response(
    payload: dict[str, object],
    *,
    status: int = 200,
    version: int | None = None,
    location: str | None = None,
) -> JSONResponse:
    headers: dict[str, str] = {}
    if version is not None:
        headers["ETag"] = _etag(version)
    if location is not None:
        headers["Location"] = location
    return JSONResponse(
        payload,
        status_code=status,
        headers=headers,
        media_type="application/scim+json",
    )


def _user_payload(value: ScimUserView, request: Request) -> dict[str, object]:
    location = str(request.base_url).rstrip("/") + f"/saas/scim/v2/Users/{value.id}"
    return {
        "schemas": [_USER_SCHEMA],
        "id": str(value.id),
        "externalId": value.external_id,
        "userName": value.user_name,
        "displayName": value.display_name,
        "active": value.active,
        "meta": {
            "resourceType": "User",
            "version": _etag(value.version),
            "location": location,
        },
        "urn:omnigent:params:scim:schemas:extension:governance:1.0:User": {
            "disposition": value.disposition,
            "requiresOwnerRecovery": value.requires_owner_recovery,
        },
    }


def _group_payload(value: ScimGroupView, request: Request) -> dict[str, object]:
    base = str(request.base_url).rstrip("/") + "/saas/scim/v2"
    return {
        "schemas": [_GROUP_SCHEMA],
        "id": str(value.id),
        "externalId": value.external_id,
        "displayName": value.display_name,
        "members": [
            {"value": str(item), "$ref": f"{base}/Users/{item}"}
            for item in value.member_scim_user_ids
        ],
        "meta": {
            "resourceType": "Group",
            "version": _etag(value.version),
            "location": f"{base}/Groups/{value.id}",
        },
        "urn:omnigent:params:scim:schemas:extension:governance:1.0:Group": {
            "active": value.active,
            "disposition": value.disposition,
            "blockedExternalIds": list(value.blocked_external_ids),
        },
    }


def _patched_user(current: ScimUserView, patch: ScimPatchBody) -> dict[str, object]:
    if _PATCH_SCHEMA not in patch.schemas:
        raise _error(LifecycleError("scim_schema_invalid", "SCIM PatchOp schema is required"))
    state: dict[str, object] = {
        "userName": current.user_name,
        "displayName": current.display_name,
        "active": current.active,
    }
    for operation in patch.operations:
        action = str(operation.get("op", "")).casefold()
        if action not in {"add", "replace", "remove"}:
            raise _error(LifecycleError("scim_patch_unsupported", "PATCH op is unsupported"))
        path = operation.get("path")
        value = operation.get("value")
        if path is None and action in {"add", "replace"} and isinstance(value, Mapping):
            for key in ("userName", "displayName", "active"):
                if key in value:
                    state[key] = value[key]
        elif isinstance(path, str) and path.casefold() in {
            "username",
            "displayname",
            "active",
        }:
            key = {
                "username": "userName",
                "displayname": "displayName",
                "active": "active",
            }[path.casefold()]
            if action == "remove":
                if key != "displayName":
                    raise _error(
                        LifecycleError("scim_patch_path_invalid", f"{key} cannot be removed")
                    )
                state[key] = None
            else:
                state[key] = value
        else:
            raise _error(LifecycleError("scim_patch_path_invalid", "PATCH path is invalid"))
    if not isinstance(state["userName"], str):
        raise _error(LifecycleError("scim_user_name_invalid", "userName is invalid"))
    if state["displayName"] is not None and not isinstance(state["displayName"], str):
        raise _error(LifecycleError("scim_display_name_invalid", "displayName is invalid"))
    if type(state["active"]) is not bool:
        raise _error(LifecycleError("scim_active_invalid", "active must be a Boolean"))
    return state


def _patched_group(current: ScimGroupView, patch: ScimPatchBody) -> dict[str, object]:
    if _PATCH_SCHEMA not in patch.schemas:
        raise _error(LifecycleError("scim_schema_invalid", "SCIM PatchOp schema is required"))
    state: dict[str, object] = {
        "displayName": current.display_name,
        "members": [{"value": str(item)} for item in current.member_scim_user_ids],
    }
    for operation in patch.operations:
        action = str(operation.get("op", "")).casefold()
        if action not in {"add", "replace", "remove"}:
            raise _error(LifecycleError("scim_patch_unsupported", "PATCH op is unsupported"))
        path = operation.get("path")
        value = operation.get("value")
        if path is None and action in {"add", "replace"} and isinstance(value, Mapping):
            for key in ("displayName", "members"):
                if key in value:
                    if key == "members" and action == "add":
                        state[key] = _merged_members(state[key], value[key])
                    else:
                        state[key] = value[key]
        elif isinstance(path, str) and path.casefold() == "displayname":
            if action == "remove":
                raise _error(
                    LifecycleError("scim_patch_path_invalid", "displayName cannot be removed")
                )
            state["displayName"] = value
        elif isinstance(path, str) and path.casefold() == "members":
            if action == "remove":
                state["members"] = []
            elif action == "add":
                state["members"] = _merged_members(state["members"], value)
            else:
                state["members"] = value
        elif isinstance(path, str) and action == "remove":
            match = _MEMBER_FILTER_PATH.fullmatch(path)
            if match is None:
                raise _error(LifecycleError("scim_patch_path_invalid", "PATCH path is invalid"))
            member_id = str(UUID(match.group(1)))
            state["members"] = [
                member
                for member in _member_values(state["members"])
                if member["value"] != member_id
            ]
        else:
            raise _error(LifecycleError("scim_patch_path_invalid", "PATCH path is invalid"))
    if not isinstance(state["displayName"], str):
        raise _error(LifecycleError("scim_group_name_invalid", "displayName is invalid"))
    state["members"] = _member_values(state["members"])
    return state


def _member_values(raw_members: object) -> list[dict[str, str]]:
    values = raw_members if isinstance(raw_members, list) else [raw_members]
    if len(values) > 1000:
        raise _error(LifecycleError("scim_group_members_invalid", "members are invalid"))
    normalized: dict[str, dict[str, str]] = {}
    for raw in values:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("value"), str):
            raise _error(LifecycleError("scim_group_members_invalid", "members are invalid"))
        try:
            member_id = str(UUID(raw["value"]))
        except ValueError as error:
            raise _error(
                LifecycleError("scim_group_members_invalid", "members are invalid")
            ) from error
        normalized[member_id] = {"value": member_id}
    return [normalized[key] for key in sorted(normalized)]


def _merged_members(current: object, added: object) -> list[dict[str, str]]:
    return _member_values([*_member_values(current), *_member_values(added)])


def _member_external_ids(
    service: EnterpriseScimService, token: str, raw_members: object
) -> list[str]:
    if not isinstance(raw_members, list) or len(raw_members) > 1000:
        raise _error(LifecycleError("scim_group_members_invalid", "members are invalid"))
    values: list[str] = []
    for raw in raw_members:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("value"), str):
            raise _error(LifecycleError("scim_group_members_invalid", "members are invalid"))
        try:
            user_id = UUID(raw["value"])
            values.append(service.get_user(token, scim_user_id=user_id).external_id)
        except (ValueError, LifecycleError) as error:
            raise _error(error) from error
    return values


def create_enterprise_scim_router(
    *,
    auth_provider: SaasAuthProvider,
    resolver: SqlAlchemyContextResolver,
    service: EnterpriseScimService,
) -> APIRouter:
    router = APIRouter(route_class=_ScimRoute)

    @router.post("/tenants/{tenant_id}/enterprise/scim-directories", status_code=201)
    def issue_directory(
        tenant_id: UUID,
        body: DirectoryCreateBody,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context, reauthenticated_at = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            value = service.issue_directory(
                context,
                display_name=body.display_name,
                reauthenticated_at=reauthenticated_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _directory_management_error(error) from error
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return _directory_payload(value)

    @router.post(
        "/tenants/{tenant_id}/enterprise/scim-directories/{directory_id}/rotate",
        status_code=201,
    )
    def rotate_directory_credential(
        tenant_id: UUID,
        directory_id: UUID,
        body: DirectoryMutationBody,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context, reauthenticated_at = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            value = service.rotate_directory_credential(
                context,
                directory_id=directory_id,
                expected_version=body.expected_version,
                reauthenticated_at=reauthenticated_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _directory_management_error(error) from error
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return _directory_payload(value)

    @router.post("/tenants/{tenant_id}/enterprise/scim-directories/{directory_id}/disable")
    def disable_directory(
        tenant_id: UUID,
        directory_id: UUID,
        body: DirectoryMutationBody,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128),
    ) -> dict[str, object]:
        context, reauthenticated_at = _tenant_context(
            request,
            auth_provider=auth_provider,
            resolver=resolver,
            tenant_id=tenant_id,
        )
        try:
            value = service.disable_directory(
                context,
                directory_id=directory_id,
                expected_version=body.expected_version,
                reauthenticated_at=reauthenticated_at,
                idempotency_key=idempotency_key,
            )
        except LifecycleError as error:
            raise _directory_management_error(error) from error
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return _directory_payload(value)

    @router.get("/scim/v2/ServiceProviderConfig")
    def service_provider_config() -> JSONResponse:
        return _response(
            {
                "schemas": [_CONFIG_SCHEMA],
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 100},
                "changePassword": {"supported": False},
                "sort": {"supported": True},
                "etag": {"supported": True},
                "authenticationSchemes": [
                    {
                        "type": "oauthbearertoken",
                        "name": "SCIM Bearer Token",
                        "description": "Tenant-scoped, hash-stored SCIM credential",
                        "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                        "primary": True,
                    }
                ],
            }
        )

    @router.post("/scim/v2/Users")
    def create_user(
        body: ScimUserBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> Response:
        if _USER_SCHEMA not in body.schemas:
            raise _error(LifecycleError("scim_schema_invalid", "SCIM User schema is required"))
        try:
            value = service.upsert_user(
                _token(request),
                event_id=idempotency_key,
                external_id=body.external_id,
                user_name=body.user_name,
                display_name=body.display_name,
                active=body.active,
                source_version=1,
            )
        except LifecycleError as error:
            raise _error(error) from error
        location = str(request.base_url).rstrip("/") + f"/saas/scim/v2/Users/{value.id}"
        return _response(
            _user_payload(value, request), status=201, version=value.version, location=location
        )

    @router.get("/scim/v2/Users")
    def list_users(
        request: Request,
        filter_value: str | None = Query(default=None, alias="filter"),
        start_index: int = Query(default=1, alias="startIndex"),
        count: int = Query(default=100),
        sort_by: str | None = Query(default=None, alias="sortBy"),
        sort_order: str = Query(default="ascending", alias="sortOrder"),
    ) -> JSONResponse:
        resolved_filter = _filter_expression(filter_value)
        resolved_sort_by, resolved_sort_order = _sort_parts(sort_by, sort_order)
        try:
            page = service.list_users(
                _token(request),
                start_index=start_index,
                count=count,
                filter_expression=resolved_filter,
                sort_by=resolved_sort_by,
                sort_order=resolved_sort_order,
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(
            _list_payload(
                [_user_payload(value, request) for value in page.resources],
                total_results=page.total_results,
                start_index=page.start_index,
                items_per_page=page.items_per_page,
            )
        )

    @router.get("/scim/v2/Users/{scim_user_id}")
    def get_user(scim_user_id: UUID, request: Request) -> JSONResponse:
        try:
            value = service.get_user(_token(request), scim_user_id=scim_user_id)
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_user_payload(value, request), version=value.version)

    @router.put("/scim/v2/Users/{scim_user_id}")
    def replace_user(
        scim_user_id: UUID,
        body: ScimUserBody,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> JSONResponse:
        if _USER_SCHEMA not in body.schemas:
            raise _error(LifecycleError("scim_schema_invalid", "SCIM User schema is required"))
        try:
            value = service.upsert_user(
                _token(request),
                event_id=idempotency_key,
                external_id=body.external_id,
                user_name=body.user_name,
                display_name=body.display_name,
                active=body.active,
                source_version=None,
                scim_user_id=scim_user_id,
                expected_version=_required_version(if_match),
                operation="replace",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_user_payload(value, request), version=value.version)

    @router.patch("/scim/v2/Users/{scim_user_id}")
    def patch_user(
        scim_user_id: UUID,
        body: ScimPatchBody,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> JSONResponse:
        token = _token(request)
        try:
            current = service.get_user(token, scim_user_id=scim_user_id)
            state = _patched_user(current, body)
            value = service.upsert_user(
                token,
                event_id=idempotency_key,
                external_id=current.external_id,
                user_name=str(state["userName"]),
                display_name=(
                    str(state["displayName"]) if state.get("displayName") is not None else None
                ),
                active=cast(bool, state["active"]),
                source_version=None,
                scim_user_id=scim_user_id,
                expected_version=_required_version(if_match),
                operation="patch",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_user_payload(value, request), version=value.version)

    @router.delete("/scim/v2/Users/{scim_user_id}", status_code=204)
    def delete_user(
        scim_user_id: UUID,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> Response:
        token = _token(request)
        try:
            current = service.get_user(token, scim_user_id=scim_user_id)
            service.upsert_user(
                token,
                event_id=idempotency_key,
                external_id=current.external_id,
                user_name=current.user_name,
                display_name=current.display_name,
                active=False,
                source_version=None,
                scim_user_id=scim_user_id,
                expected_version=_required_version(if_match),
                operation="delete",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return Response(status_code=204)

    @router.post("/scim/v2/Groups")
    def create_group(
        body: ScimGroupBody,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> Response:
        if _GROUP_SCHEMA not in body.schemas:
            raise _error(LifecycleError("scim_schema_invalid", "SCIM Group schema is required"))
        token = _token(request)
        try:
            value = service.sync_group(
                token,
                event_id=idempotency_key,
                external_id=body.external_id,
                display_name=body.display_name,
                member_external_ids=_member_external_ids(
                    service, token, [member.model_dump() for member in body.members]
                ),
                active=True,
                source_version=1,
            )
        except LifecycleError as error:
            raise _error(error) from error
        location = str(request.base_url).rstrip("/") + f"/saas/scim/v2/Groups/{value.id}"
        return _response(
            _group_payload(value, request), status=201, version=value.version, location=location
        )

    @router.get("/scim/v2/Groups")
    def list_groups(
        request: Request,
        filter_value: str | None = Query(default=None, alias="filter"),
        start_index: int = Query(default=1, alias="startIndex"),
        count: int = Query(default=100),
        sort_by: str | None = Query(default=None, alias="sortBy"),
        sort_order: str = Query(default="ascending", alias="sortOrder"),
    ) -> JSONResponse:
        resolved_filter = _filter_expression(filter_value)
        resolved_sort_by, resolved_sort_order = _sort_parts(sort_by, sort_order)
        try:
            page = service.list_groups(
                _token(request),
                start_index=start_index,
                count=count,
                filter_expression=resolved_filter,
                sort_by=resolved_sort_by,
                sort_order=resolved_sort_order,
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(
            _list_payload(
                [_group_payload(value, request) for value in page.resources],
                total_results=page.total_results,
                start_index=page.start_index,
                items_per_page=page.items_per_page,
            )
        )

    @router.get("/scim/v2/Groups/{scim_group_id}")
    def get_group(scim_group_id: UUID, request: Request) -> JSONResponse:
        try:
            value = service.get_group(_token(request), scim_group_id=scim_group_id)
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_group_payload(value, request), version=value.version)

    @router.put("/scim/v2/Groups/{scim_group_id}")
    def replace_group(
        scim_group_id: UUID,
        body: ScimGroupBody,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> JSONResponse:
        if _GROUP_SCHEMA not in body.schemas:
            raise _error(LifecycleError("scim_schema_invalid", "SCIM Group schema is required"))
        token = _token(request)
        try:
            value = service.sync_group(
                token,
                event_id=idempotency_key,
                external_id=body.external_id,
                display_name=body.display_name,
                member_external_ids=_member_external_ids(
                    service, token, [member.model_dump() for member in body.members]
                ),
                active=True,
                source_version=None,
                scim_group_id=scim_group_id,
                expected_version=_required_version(if_match),
                operation="replace",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_group_payload(value, request), version=value.version)

    @router.patch("/scim/v2/Groups/{scim_group_id}")
    def patch_group(
        scim_group_id: UUID,
        body: ScimPatchBody,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> JSONResponse:
        token = _token(request)
        try:
            current = service.get_group(token, scim_group_id=scim_group_id)
            state = _patched_group(current, body)
            value = service.sync_group(
                token,
                event_id=idempotency_key,
                external_id=current.external_id,
                display_name=str(state["displayName"]),
                member_external_ids=_member_external_ids(service, token, state["members"]),
                active=current.active,
                source_version=None,
                scim_group_id=scim_group_id,
                expected_version=_required_version(if_match),
                operation="patch",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return _response(_group_payload(value, request), version=value.version)

    @router.delete("/scim/v2/Groups/{scim_group_id}", status_code=204)
    def delete_group(
        scim_group_id: UUID,
        request: Request,
        if_match: str | None = Header(default=None, alias="If-Match"),
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=256),
    ) -> Response:
        token = _token(request)
        try:
            current = service.get_group(token, scim_group_id=scim_group_id)
            service.sync_group(
                token,
                event_id=idempotency_key,
                external_id=current.external_id,
                display_name=current.display_name,
                member_external_ids=[],
                active=False,
                source_version=None,
                scim_group_id=scim_group_id,
                expected_version=_required_version(if_match),
                operation="delete",
            )
        except LifecycleError as error:
            raise _error(error) from error
        return Response(status_code=204)

    return router
