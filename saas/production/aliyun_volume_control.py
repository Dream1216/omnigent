"""Explicit STS-file authentication for the server-only Aliyun Volume API."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from saas.production.aliyun_storage import (
    OSS_ENDPOINT,
    AliyunOssVolumeSpec,
    AliyunStorageError,
    AliyunVolumeControl,
)
from saas.production.aliyun_sts import read_sts_document


class AliyunVolumeControlClient(AliyunVolumeControl):
    """Use one admitted Team, a fixed HTTPS endpoint and no ambient credentials."""

    def __init__(
        self,
        *,
        team_id: UUID,
        credential_file: Path,
        clock: Callable[[], float] = time.time,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        if not isinstance(team_id, UUID) or team_id.int == 0:
            raise AliyunStorageError("Aliyun volume Team is invalid")
        self.team_id = team_id
        self._credential_file = credential_file
        self._clock = clock
        self._client_factory = client_factory or (
            lambda: httpx.Client(
                timeout=httpx.Timeout(15.0, connect=5.0), trust_env=False, follow_redirects=False
            )
        )

    def prepare(self) -> None:
        if version("alibabacloud-sandbox20260820") != "1.2.0":
            raise AliyunStorageError("Aliyun volume SDK version is not qualified")
        self._credentials()

    def _credentials(self) -> dict[str, str]:
        value = read_sts_document(self._credential_file, now=self._clock())
        return {
            key: value[key] for key in ("access_key_id", "access_key_secret", "security_token")
        }

    def _client(self):
        from alibabacloud_sandbox20260820.client import Client
        from alibabacloud_tea_openapi.utils import Utils
        from darabonba.core import DaraCore
        from darabonba.request import DaraRequest

        self.prepare()
        credentials = self._credentials()
        factory = self._client_factory

        class OwnedTransport(Client):
            def __init__(self) -> None:
                # Selected generated methods need only this transport hook.
                pass

            def call_api(self, params, request, runtime) -> dict[str, Any]:
                del runtime  # This channel owns transport policy independently of SDK defaults.
                route_ok = (
                    re.fullmatch(
                        r"/pop/2026-08-20/volumes/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                        params.pathname or "",
                    )
                    is not None
                    if params.action == "GetVolume"
                    else params.pathname == "/pop/2026-08-20/volumes"
                )
                if (
                    params.version != "2026-08-20"
                    or params.action not in {"CreateVolume", "GetVolume", "ListVolumes"}
                    or params.style != "ROA"
                    or params.auth_type != "AK"
                    or params.body_type != "json"
                    or params.method != ("POST" if params.action == "CreateVolume" else "GET")
                    or not route_ok
                ):
                    raise AliyunStorageError("Aliyun volume operation is not admitted")
                signed = DaraRequest()
                signed.method, signed.pathname = params.method, params.pathname
                signed.query = request.query or {}
                payload = (
                    DaraCore.to_json_string(request.body).encode()
                    if request.body is not None
                    else b""
                )
                if len(payload) > 16384:
                    raise AliyunStorageError("Aliyun volume request is too large")
                digest = sha256(payload).hexdigest()
                signed.headers = {
                    "host": "sandbox.cn-hangzhou.aliyuncs.com",
                    "x-acs-version": "2026-08-20",
                    "x-acs-action": params.action,
                    "x-acs-date": Utils.get_timestamp(),
                    "x-acs-signature-nonce": Utils.get_nonce(),
                    "x-acs-content-sha256": digest,
                    "x-acs-accesskey-id": credentials["access_key_id"],
                    "x-acs-security-token": credentials["security_token"],
                    "accept": "application/json",
                    "accept-encoding": "identity",
                }
                if request.body is not None:
                    signed.headers["content-type"] = "application/json; charset=utf-8"
                signed.headers["Authorization"] = Utils.get_authorization(
                    signed,
                    "ACS3-HMAC-SHA256",
                    digest,
                    credentials["access_key_id"],
                    credentials["access_key_secret"],
                )
                with factory() as client:
                    outbound = client.build_request(
                        params.method,
                        f"https://sandbox.cn-hangzhou.aliyuncs.com{params.pathname}",
                        params=signed.query,
                        headers=signed.headers,
                        content=payload,
                    )
                    response = client.send(outbound, stream=True, follow_redirects=False)
                    try:
                        if response.status_code != 200:
                            raise AliyunStorageError("Aliyun volume control request failed")
                        if response.headers.get("content-encoding", "identity") != "identity":
                            raise AliyunStorageError("Aliyun volume response encoding is invalid")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if len(body) + len(chunk) > 262144:
                                raise AliyunStorageError("Aliyun volume response is too large")
                            body.extend(chunk)
                        document = json.loads(body)
                        if not isinstance(document, dict):
                            raise AliyunStorageError("Aliyun volume response is invalid")
                        return {
                            "statusCode": 200,
                            "headers": dict(response.headers),
                            "body": document,
                        }
                    finally:
                        response.close()

        return OwnedTransport()

    def _call(self, team_id: UUID, operation: Callable[[Any, Any], Any]) -> Any:
        if team_id != self.team_id:
            raise AliyunStorageError("Aliyun volume Team does not match")
        from darabonba.runtime import RuntimeOptions

        try:
            response = operation(
                self._client(),
                RuntimeOptions(
                    autoretry=False,
                    max_attempts=1,
                    ignore_ssl=False,
                    connect_timeout=5000,
                    read_timeout=15000,
                    http_proxy="",
                    https_proxy="",
                    no_proxy="*",
                ),
            )
            if (
                response.status_code != 200
                or response.body is None
                or response.body.code not in (None, "200", "Success")
            ):
                raise ValueError
            return response.body
        except Exception:  # noqa: BLE001 - SDK diagnostics can contain signed request material.
            raise AliyunStorageError("Aliyun volume control request failed") from None

    def find(self, *, team_id: UUID, name: str) -> Sequence[Mapping[str, object]]:
        from alibabacloud_sandbox20260820 import models

        if re.fullmatch(r"omni-(?:in|out)-[0-9a-f]{40}", name) is None:
            raise AliyunStorageError("Aliyun volume name is invalid")
        body = self._call(
            team_id,
            lambda client, runtime: client.list_volumes_with_options(
                models.ListVolumesRequest(team_id=str(team_id), volume_name=name, max_results=2),
                {},
                runtime,
            ),
        )
        if body.next_token or len(body.volumes or []) > 1:
            raise AliyunStorageError("Aliyun volume lookup is ambiguous")
        return [volume.to_map() for volume in (body.volumes or [])]

    def create(self, spec: AliyunOssVolumeSpec) -> Mapping[str, object]:
        from alibabacloud_sandbox20260820 import models

        body = self._call(
            spec.team_id,
            lambda client, runtime: client.create_volume_with_options(
                models.CreateVolumeRequest(
                    body=models.CreateVolumeInput(
                        team_id=str(spec.team_id),
                        volume_name=spec.name,
                        mount_config=models.CreateVolumeInputMountConfig(role=spec.role_arn),
                        oss_volume_config=models.OSSVolumeConfig(
                            bucket_name=spec.bucket,
                            bucket_path=spec.bucket_path,
                            endpoint=OSS_ENDPOINT,
                            read_only=spec.read_only,
                        ),
                    )
                ),
                {},
                runtime,
            ),
        )
        if body.volume is None:
            raise AliyunStorageError("Aliyun volume creation is unconfirmed")
        return body.volume.to_map()

    def read(self, *, team_id: UUID, volume_id: str) -> Mapping[str, object]:
        from alibabacloud_sandbox20260820 import models

        if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", volume_id) is None:
            raise AliyunStorageError("Aliyun volume identity is invalid")
        body = self._call(
            team_id,
            lambda client, runtime: client.get_volume_with_options(
                volume_id, models.GetVolumeRequest(team_id=str(team_id)), {}, runtime
            ),
        )
        if body.volume is None:
            raise AliyunStorageError("Aliyun volume lookup is unconfirmed")
        return body.volume.to_map()
