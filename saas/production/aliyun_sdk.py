"""Read-only attachment for the qualified E2B SDK; never resume or renew a VM."""

from __future__ import annotations

from importlib.metadata import version
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from e2b import Sandbox
    from e2b.api.client.models import SandboxDetail


def require_qualified_sdk() -> None:
    if version("e2b") != "2.31.0":
        raise ValueError("Aliyun sandbox SDK version is not qualified")


def read_sandbox_details(sandbox_id: str, options: dict[str, Any]) -> SandboxDetail:
    """Use the SDK's generated GET API without its mutating connect endpoint."""

    require_qualified_sdk()
    from e2b.api import ApiClient, handle_api_exception
    from e2b.api.client.api.sandboxes import get_sandboxes_sandbox_id
    from e2b.api.client.models import SandboxDetail
    from e2b.connection_config import ConnectionConfig
    from e2b.exceptions import SandboxException, SandboxNotFoundException

    try:
        with ApiClient(ConnectionConfig(**options)) as client:
            response = get_sandboxes_sandbox_id.sync_detailed(sandbox_id, client=client)
    except (ValueError, TypeError, KeyError):
        raise SandboxException("Aliyun sandbox metadata response is invalid") from None
    if response.status_code == 404:
        raise SandboxNotFoundException("Aliyun sandbox is no longer available")
    if response.status_code >= 300:
        raise handle_api_exception(response)
    if not isinstance(response.parsed, SandboxDetail):
        raise SandboxException("Aliyun sandbox metadata response is invalid")
    return response.parsed


def attach_running_sandbox(detail: SandboxDetail, options: dict[str, Any]) -> Sandbox:
    """Construct the SDK command/file transport locally after scope admission."""

    require_qualified_sdk()
    from e2b import Sandbox
    from e2b.api.client.types import Unset
    from e2b.connection_config import ConnectionConfig
    from packaging.version import InvalidVersion, Version

    domain = options["domain"]
    if not isinstance(detail.domain, (Unset, type(None))) and detail.domain != domain:
        raise ValueError("Aliyun sandbox domain is invalid")
    token = detail.envd_access_token
    if isinstance(token, Unset):
        token = None
    if token is not None and (
        not isinstance(token, str)
        or not 1 <= len(token) <= 8192
        or any(c.isspace() for c in token)
    ):
        raise ValueError("Aliyun sandbox transport credential is invalid")
    try:
        envd_version = Version(detail.envd_version)
    except (InvalidVersion, TypeError):
        raise ValueError("Aliyun sandbox transport version is invalid") from None
    headers = {
        "E2b-Sandbox-Id": detail.sandbox_id,
        "E2b-Sandbox-Port": str(ConnectionConfig.envd_port),
    }
    if token is not None:
        headers["X-Access-Token"] = token
    # This is the same local constructor used by SDK create/connect, without POST.
    return Sandbox(
        sandbox_id=detail.sandbox_id,
        sandbox_domain=domain,
        envd_version=envd_version,
        envd_access_token=token,
        traffic_access_token=None,
        connection_config=ConnectionConfig(extra_sandbox_headers=headers, **options),
    )
