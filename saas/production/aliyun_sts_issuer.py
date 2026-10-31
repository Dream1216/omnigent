"""Issue Team-scoped Volume credentials outside the Server's request process."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from saas.production.aliyun_storage import AliyunStorageError
from saas.production.aliyun_sts import (
    encode_sts_document,
    read_sts_document,
    validate_sts_document,
    validate_sts_secrets,
)
from saas.production.tenant_model_keys import _read_file

_IMDS = "http://100.100.100.200/latest/"
_STS_HOST = "sts.cn-hangzhou.aliyuncs.com"


@dataclass(frozen=True)
class AliyunStsIssuerConfig:
    source_role_name: str
    role_arn: str
    team_id: UUID
    credential_file: Path

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_role_name, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", self.source_role_name) is None
            or not isinstance(self.role_arn, str)
            or re.fullmatch(r"acs:ram::[0-9]{10,20}:role/[a-z][a-z0-9-]{2,63}", self.role_arn)
            is None
            or self.role_arn.rsplit("/", 1)[-1] == self.source_role_name.lower()
            or not isinstance(self.team_id, UUID)
            or self.team_id.int == 0
            or not isinstance(self.credential_file, Path)
            or not self.credential_file.is_absolute()
            or ".." in self.credential_file.parts
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.json", self.credential_file.name) is None
        ):
            raise AliyunStorageError("Aliyun STS issuer configuration is invalid")

    @property
    def policy(self) -> str:
        account = self.role_arn.split(":")[3]
        return json.dumps(
            {
                "Version": "1",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sandbox:CreateVolume",
                            "sandbox:GetVolume",
                            "sandbox:ListVolumes",
                        ],
                        "Resource": (
                            f"acs:sandbox:cn-hangzhou:{account}:teams/{self.team_id}/volumes/*"
                        ),
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def load_issuer_config(path: Path, expected_sha256: str) -> AliyunStsIssuerConfig:
    try:
        raw = _read_file(path, private=True, maximum=16384)
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or hashlib.sha256(raw).hexdigest() != expected_sha256
        ):
            raise ValueError
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value)
            != {"schema_version", "source_role_name", "role_arn", "team_id", "credential_file"}
            or raw != encode_sts_document(value)
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or str(UUID(value["team_id"])) != value["team_id"]
        ):
            raise ValueError
        config = AliyunStsIssuerConfig(
            value["source_role_name"],
            value["role_arn"],
            UUID(value["team_id"]),
            Path(value["credential_file"]),
        )
        if path == config.credential_file:
            raise ValueError
        return config
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        raise AliyunStorageError("Aliyun STS issuer configuration is invalid") from None


def _expiration(value: Any) -> int:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z", value) is None
    ):
        raise ValueError
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _cloud_secrets(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError
    result = {
        "access_key_id": value["AccessKeyId"],
        "access_key_secret": value["AccessKeySecret"],
        "security_token": value["SecurityToken"],
    }
    validate_sts_secrets(result)
    return result


@contextmanager
def _output_lock(path: Path) -> Iterator[int]:
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock = None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError
        lock = os.open(
            f".{path.name}.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600,
            dir_fd=parent,
        )
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            old = _read_file(path, private=True, maximum=32768)
        except ValueError:
            if path.exists() or path.is_symlink():
                raise
        else:
            validate_sts_document(old, now=json.loads(old)["issued_at"])
        yield parent
    finally:
        if lock is not None:
            os.close(lock)
        os.close(parent)


def _publish(path: Path, parent: int, document: dict[str, Any], now: float) -> None:
    body = encode_sts_document(document)
    validate_sts_document(body, now=now)
    expected, linked = os.fstat(parent), path.parent.lstat()
    if (
        (expected.st_dev, expected.st_ino) != (linked.st_dev, linked.st_ino)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
    ):
        raise ValueError
    temporary = f".{path.name}.{secrets.token_hex(12)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent)


class AliyunVolumeStsIssuer:
    def __init__(
        self,
        config: AliyunStsIssuerConfig,
        *,
        clock: Callable[[], float] = time.time,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        self.config, self._clock = config, clock
        self._client_factory = client_factory or (
            lambda: httpx.Client(
                timeout=httpx.Timeout(15, connect=3), trust_env=False, follow_redirects=False
            )
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        query: dict[str, str] | None = None,
        maximum: int = 32768,
    ) -> bytes:
        with self._client_factory() as client:
            request = client.build_request(method, url, params=query, headers=headers, content=b"")
            response = client.send(request, stream=True, follow_redirects=False)
            try:
                if (
                    response.status_code != 200
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise ValueError
                body = bytearray()
                for part in response.iter_bytes():
                    if len(body) + len(part) > maximum:
                        raise ValueError
                    body.extend(part)
                return bytes(body)
            finally:
                response.close()

    def _source(self) -> dict[str, str]:
        token = self._request(
            "PUT",
            _IMDS + "api/token",
            maximum=4096,
            headers={
                "X-aliyun-ecs-metadata-token-ttl-seconds": "60",
                "accept-encoding": "identity",
            },
        ).decode("ascii")
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError
        result = json.loads(
            self._request(
                "GET",
                _IMDS + "meta-data/ram/security-credentials/" + self.config.source_role_name,
                headers={"X-aliyun-ecs-metadata-token": token, "accept-encoding": "identity"},
            )
        )
        if (
            not isinstance(result, dict)
            or result.get("Code") != "Success"
            or not self._clock() + 60
            < _expiration(result.get("Expiration"))
            <= self._clock() + 21600
        ):
            raise ValueError
        return _cloud_secrets(result)

    def _assume(self, credentials: dict[str, str]) -> dict[str, Any]:
        from alibabacloud_sts20150401 import models
        from alibabacloud_sts20150401.client import Client
        from alibabacloud_tea_openapi.utils import Utils
        from darabonba.request import DaraRequest
        from darabonba.runtime import RuntimeOptions

        session = "omnigent-volume-" + secrets.token_hex(8)
        expected = {
            "DurationSeconds": "900",
            "RoleArn": self.config.role_arn,
            "RoleSessionName": session,
            "Policy": self.config.policy,
            "ExternalId": str(self.config.team_id),
        }
        transport = self._request

        class OwnedTransport(Client):
            def __init__(self) -> None:
                pass

            def call_api(self, params, request, runtime) -> dict[str, Any]:
                del runtime
                query = {k: str(v) for k, v in (request.query or {}).items()}
                if (
                    params.action != "AssumeRole"
                    or params.version != "2015-04-01"
                    or params.method != "POST"
                    or params.pathname != "/"
                    or params.style != "RPC"
                    or params.auth_type != "AK"
                    or params.req_body_type != "formData"
                    or params.body_type != "json"
                    or query != expected
                ):
                    raise ValueError
                signed = DaraRequest()
                signed.method, signed.pathname, signed.query = "POST", "/", query
                digest = hashlib.sha256(b"").hexdigest()
                signed.headers = {
                    "host": _STS_HOST,
                    "x-acs-action": "AssumeRole",
                    "x-acs-version": "2015-04-01",
                    "x-acs-date": Utils.get_timestamp(),
                    "x-acs-signature-nonce": Utils.get_nonce(),
                    "x-acs-content-sha256": digest,
                    "x-acs-accesskey-id": credentials["access_key_id"],
                    "x-acs-security-token": credentials["security_token"],
                    "accept": "application/json",
                    "accept-encoding": "identity",
                }
                signed.headers["Authorization"] = Utils.get_authorization(
                    signed,
                    "ACS3-HMAC-SHA256",
                    digest,
                    credentials["access_key_id"],
                    credentials["access_key_secret"],
                )
                result = json.loads(
                    transport("POST", f"https://{_STS_HOST}/", headers=signed.headers, query=query)
                )
                if not isinstance(result, dict):
                    raise ValueError
                return {"statusCode": 200, "headers": {}, "body": result}

        response = OwnedTransport().assume_role_with_options(
            models.AssumeRoleRequest(
                duration_seconds=900,
                role_arn=self.config.role_arn,
                role_session_name=session,
                policy=self.config.policy,
                external_id=str(self.config.team_id),
            ),
            RuntimeOptions(autoretry=False, max_attempts=1, ignore_ssl=False),
        )
        body = response.body
        if (
            body is None
            or body.assumed_role_user is None
            or body.assumed_role_user.arn != f"{self.config.role_arn}/{session}"
            or body.credentials is None
        ):
            raise ValueError
        expiration = _expiration(body.credentials.expiration)
        now = int(self._clock())
        if not now + 60 < expiration <= now + 930:
            raise ValueError
        return {
            "schema_version": 1,
            "issued_at": now,
            "expires_at": expiration,
            "access_key_id": body.credentials.access_key_id,
            "access_key_secret": body.credentials.access_key_secret,
            "security_token": body.credentials.security_token,
        }

    def refresh(self) -> int:
        try:
            qualified = version("alibabacloud-sts20150401") == "1.2.0"
        except PackageNotFoundError:
            qualified = False
        if not qualified:
            raise AliyunStorageError("Aliyun STS SDK version is not qualified")
        try:
            with _output_lock(self.config.credential_file) as parent:
                document = self._assume(self._source())
                _publish(self.config.credential_file, parent, document, self._clock())
                return document["expires_at"]
        except Exception:  # noqa: BLE001 - metadata and SDK exceptions may include credentials.
            raise AliyunStorageError("Aliyun storage STS refresh failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--print-policy", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = load_issuer_config(args.config, args.config_sha256)
        if args.print_policy:
            print(config.policy)
            return 0
        if args.check:
            read_sts_document(config.credential_file, now=time.time())
            return 0
        issuer = AliyunVolumeStsIssuer(config)
        stop = threading.Event()
        if not args.once:
            for name in (signal.SIGINT, signal.SIGTERM):
                signal.signal(name, lambda *_: stop.set())
        while not stop.is_set():
            try:
                expiration = issuer.refresh()
                print(json.dumps({"status": "refreshed", "expires_at": expiration}), flush=True)
                delay = 300
            except AliyunStorageError:
                print("Aliyun storage STS refresh failed", file=sys.stderr, flush=True)
                if args.once:
                    return 1
                delay = 30
            if args.once:
                return 0
            stop.wait(delay)
    except AliyunStorageError:
        print("Aliyun storage STS issuer is unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
