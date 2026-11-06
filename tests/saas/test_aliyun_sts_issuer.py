from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from saas.production import aliyun_sts_issuer as module
from saas.production.aliyun_artifacts import AliyunArtifactReader
from saas.production.aliyun_storage import AliyunOssStorageConfig, AliyunStorageError
from saas.production.aliyun_sts import encode_sts_document, read_sts_document
from saas.production.aliyun_sts_issuer import (
    AliyunOutputReadStsIssuerConfig,
    AliyunStsIssuerConfig,
    AliyunVolumeStsIssuer,
    load_issuer_config,
)
from saas.production.aliyun_volume_control import AliyunVolumeControlClient
from tests.saas.test_aliyun_volume_control import _assert_signature
from tests.saas.test_tenant_sandbox import _runtime


def _utc(epoch):
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def issuer_case(tmp_path, request):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    mode = getattr(request, "param", "volume")
    config = AliyunStsIssuerConfig(
        "synthetic-source-role",
        "acs:ram::1234567890123456:role/omnigent-volume-control",
        uuid4(),
        directory / "storage-sts.json",
        sts_vpc=mode.endswith("_vpc"),
    )
    runtime = replace(_runtime(), project_id=uuid4())
    storage = AliyunOssStorageConfig(
        config.team_id,
        runtime.tenant_id,
        runtime.physical_workspace_id,
        "omnigent-p4-test-bucket",
        "acs:ram::1234567890123456:role/synthetic-fc-mount",
        project_scoped=True,
    )
    if mode.startswith("output_read"):
        config = AliyunOutputReadStsIssuerConfig(
            config.source_role_name,
            "acs:ram::1234567890123456:role/omnigent-output-read",
            config.team_id,
            directory / "outputs-read-sts.json",
            storage.bucket,
            (storage.session(runtime, uuid4()).volumes[1].bucket_path,),
            sts_vpc=config.sts_vpc,
        )
    c = SimpleNamespace(
        config=config,
        runtime=runtime,
        storage=storage,
        requests=[],
        now=1000,
        fail_phase=None,
        failure=None,
        source={
            "Code": "Success",
            "AccessKeyId": "STS." + "s" * 24,
            "AccessKeySecret": "synthetic-source-private-secret",
            "SecurityToken": "synthetic-source-private-token",
            "Expiration": _utc(4600),
        },
        token=b"synthetic-imds-token",
        target_token="synthetic-target-private-token",
        target_changes={},
    )

    def handler(request):
        c.requests.append(request)
        phase = (
            "sts"
            if request.url.scheme == "https"
            else "token"
            if request.method == "PUT"
            else "source"
        )
        if phase == c.fail_phase:
            if isinstance(c.failure, Exception):
                raise c.failure
            return httpx.Response(c.failure, headers={"Location": "https://untrusted.invalid"})
        if phase == "token":
            return httpx.Response(200, content=c.token)
        if phase == "source":
            return httpx.Response(200, json=c.source)
        body = {
            "RequestId": str(uuid4()),
            "AssumedRoleUser": {
                "Arn": config.role_arn + "/" + request.url.params["RoleSessionName"]
            },
            "Credentials": {
                "AccessKeyId": "STS." + "t" * 24,
                "AccessKeySecret": "synthetic-target-private-secret",
                "SecurityToken": c.target_token,
                "Expiration": _utc(c.now + 900),
            },
        }
        body.update(c.target_changes)
        return httpx.Response(200, json=body)

    c.build = lambda: AliyunVolumeStsIssuer(
        config,
        clock=lambda: c.now,
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
            trust_env=False,
        ),
    )
    c.handler = handler
    c.config_file = tmp_path / "issuer.json"
    document = {
        "schema_version": 1,
        "source_role_name": config.source_role_name,
        "role_arn": config.role_arn,
        "team_id": str(config.team_id),
        "credential_file": str(config.credential_file),
    }
    if config.sts_vpc or isinstance(config, AliyunOutputReadStsIssuerConfig):
        document.update(
            schema_version=2,
            purpose="volume_control",
            network="vpc" if config.sts_vpc else "public",
        )
    if isinstance(config, AliyunOutputReadStsIssuerConfig):
        document.update(
            schema_version=2,
            purpose="output_read",
            bucket=config.bucket,
            output_prefixes=list(config.output_prefixes),
        )
    c.config_file.write_bytes(encode_sts_document(document))
    c.config_file.chmod(0o600)
    c.config_hash = hashlib.sha256(c.config_file.read_bytes()).hexdigest()
    return c


@pytest.mark.parametrize(
    "issuer_case", ["volume", "volume_vpc", "output_read", "output_read_vpc"], indirect=True
)
@pytest.mark.parametrize("source_lifetime", [3600, 22065])
def test_real_sdk_signs_scoped_assumption_and_publishes_consumer_document(
    issuer_case, monkeypatch, capsys, source_lifetime
):
    c = issuer_case
    c.source["Expiration"] = _utc(c.now + source_lifetime)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://untrusted.invalid:99")
    monkeypatch.setenv("DEBUG", "sdk")
    monkeypatch.setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "untrusted-ambient-secret")
    assert c.build().refresh() == 1900
    assert [(r.method, r.url.host) for r in c.requests] == [
        ("PUT", "100.100.100.200"),
        ("GET", "100.100.100.200"),
        (
            "POST",
            "sts-vpc.cn-hangzhou.aliyuncs.com"
            if c.config.sts_vpc
            else "sts.cn-hangzhou.aliyuncs.com",
        ),
    ]
    assert c.requests[0].headers["x-aliyun-ecs-metadata-token-ttl-seconds"] == "60"
    assert c.requests[1].headers["x-aliyun-ecs-metadata-token"] == c.token.decode()
    assert c.requests[1].url.path.endswith("/" + c.config.source_role_name)
    query = dict(c.requests[2].url.params)
    assert set(query) == {"DurationSeconds", "RoleArn", "RoleSessionName", "Policy", "ExternalId"}
    assert query["DurationSeconds"] == "900"
    assert query["RoleArn"] == c.config.role_arn
    assert query["ExternalId"] == str(c.config.team_id)
    if isinstance(c.config, AliyunOutputReadStsIssuerConfig):
        assert query["RoleSessionName"].startswith("omnigent-output-read-")
        assert json.loads(query["Policy"])["Statement"] == [
            {
                "Effect": "Allow",
                "Action": ["oss:ListObjects"],
                "Resource": ["acs:oss:*:*:omnigent-p4-test-bucket"],
                "Condition": {
                    "StringLike": {"oss:Prefix": [c.config.output_prefixes[0].lstrip("/") + "*"]}
                },
            },
            {
                "Effect": "Allow",
                "Action": ["oss:GetObject"],
                "Resource": [
                    "acs:oss:*:*:omnigent-p4-test-bucket" + c.config.output_prefixes[0] + "*"
                ],
            },
        ]
    else:
        assert query["RoleSessionName"].startswith("omnigent-volume-")
        assert json.loads(query["Policy"])["Statement"] == [
            {
                "Effect": "Allow",
                "Action": ["sandbox:CreateVolume", "sandbox:GetVolume", "sandbox:ListVolumes"],
                "Resource": (
                    f"acs:sandbox:cn-hangzhou:1234567890123456:teams/{c.config.team_id}/volumes/*"
                ),
            }
        ]
    _assert_signature(
        c.requests[2],
        {
            "access_key_id": c.source["AccessKeyId"],
            "access_key_secret": c.source["AccessKeySecret"],
        },
    )
    stored = read_sts_document(c.config.credential_file, now=c.now)
    assert stored["security_token"] == c.target_token
    assert stored["issued_at"] == c.now
    assert c.config.credential_file.stat().st_mode & 0o777 == 0o600
    assert c.source["SecurityToken"].encode() not in c.config.credential_file.read_bytes()
    if isinstance(c.config, AliyunOutputReadStsIssuerConfig):
        AliyunArtifactReader(
            (c.storage,),
            credential_file=c.config.credential_file,
            authorize=lambda _: c.runtime,
            clock=lambda: c.now,
        ).prepare()
    else:
        AliyunVolumeControlClient(
            team_id=c.config.team_id,
            credential_file=c.config.credential_file,
            clock=lambda: c.now,
        ).prepare()
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize(
    "issuer_case", ["volume", "volume_vpc", "output_read", "output_read_vpc"], indirect=True
)
def test_rotation_changes_inode_and_keeps_existing_consumer_usable(issuer_case):
    c = issuer_case
    if isinstance(c.config, AliyunOutputReadStsIssuerConfig):
        reader = AliyunArtifactReader(
            (c.storage,),
            credential_file=c.config.credential_file,
            authorize=lambda _: c.runtime,
            clock=lambda: c.now,
        )
        credentials = reader.prepare
    else:
        client = AliyunVolumeControlClient(
            team_id=c.config.team_id,
            credential_file=c.config.credential_file,
            clock=lambda: c.now,
        )
        credentials = client._credentials
    c.build().refresh()
    inode = c.config.credential_file.stat().st_ino
    assert credentials()["security_token"] == c.target_token
    c.target_token += "-rotated"
    c.now += 300
    assert c.build().refresh() == 2200
    assert c.config.credential_file.stat().st_ino != inode
    assert credentials()["security_token"] == c.target_token


@pytest.mark.parametrize("issuer_case", ["volume", "volume_vpc"], indirect=True)
def test_default_transport_disables_ambient_proxies_and_redirects(issuer_case, monkeypatch):
    c = issuer_case
    original = httpx.Client
    options = []

    def build(**kwargs):
        options.append(kwargs)
        return original(transport=httpx.MockTransport(c.handler), **kwargs)

    monkeypatch.setattr(module.httpx, "Client", build)
    assert AliyunVolumeStsIssuer(c.config, clock=lambda: c.now).refresh() == 1900
    assert len(options) == 3
    assert all(o["trust_env"] is False and o["follow_redirects"] is False for o in options)
    assert all(o["timeout"].connect == 3 and o["timeout"].read == 15 for o in options)


@pytest.mark.parametrize("phase", ["token", "source", "sts"])
@pytest.mark.parametrize("issuer_case", ["volume", "output_read"], indirect=True)
@pytest.mark.parametrize(
    "failure", [301, 302, 307, 308, 403, httpx.ReadTimeout("private-signed-request")]
)
def test_failed_or_redirected_refresh_retains_last_file_without_replay(
    issuer_case, phase, failure
):
    c = issuer_case
    c.build().refresh()
    previous = c.config.credential_file.read_bytes()
    c.requests.clear()
    c.fail_phase, c.failure = phase, failure
    with pytest.raises(AliyunStorageError) as raised:
        c.build().refresh()
    assert c.config.credential_file.read_bytes() == previous
    assert len(c.requests) == {"token": 1, "source": 2, "sts": 3}[phase]
    assert "private-signed-request" not in str(raised.value)
    assert not any(r.url.host == "untrusted.invalid" for r in c.requests)


@pytest.mark.parametrize("token", [b"", b"bad\ntoken", b"x" * 4097, b"\xff"])
def test_invalid_metadata_token_stops_before_requesting_source_credentials(issuer_case, token):
    c = issuer_case
    c.token = token
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert len(c.requests) == 1
    assert not c.config.credential_file.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Code", "Failed"),
        ("AccessKeyId", "LTAI" + "a" * 24),
        ("SecurityToken", ""),
        ("Expiration", _utc(1030)),
        ("Expiration", _utc(1060)),
        ("Expiration", "2026-10-31T00:00:00+08:00"),
    ],
)
def test_invalid_source_credentials_never_reach_sts(issuer_case, field, value):
    c = issuer_case
    c.source[field] = value
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert len(c.requests) == 2
    assert not c.config.credential_file.exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"AssumedRoleUser": {"Arn": "acs:ram::1234567890123456:role/other/synthetic"}},
        {"Credentials": {"AccessKeyId": "LTAI" + "a" * 24}},
        {"Credentials": {"Expiration": _utc(9000)}},
        {"Credentials": None},
    ],
)
def test_wrong_identity_or_invalid_assumed_credentials_cannot_be_published(issuer_case, changes):
    c = issuer_case
    c.target_changes = changes
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert not c.config.credential_file.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "symlink",
        "hardlink",
        "permissions",
        "unknown",
        "parent_permissions",
        "lock_symlink",
        "lock_permissions",
    ],
)
@pytest.mark.parametrize("issuer_case", ["volume", "output_read"], indirect=True)
def test_unsafe_destination_is_rejected_before_network(issuer_case, tmp_path, kind):
    c = issuer_case
    if kind == "parent_permissions":
        c.config.credential_file.parent.chmod(0o750)
    elif kind == "symlink":
        c.config.credential_file.symlink_to(tmp_path / "other")
    elif kind == "hardlink":
        other = tmp_path / "other"
        other.write_text("unrelated")
        os.link(other, c.config.credential_file)
    elif kind.startswith("lock_"):
        lock = c.config.credential_file.with_name(f".{c.config.credential_file.name}.lock")
        if kind == "lock_symlink":
            lock.symlink_to(tmp_path / "other")
        else:
            lock.write_text("unrelated")
            lock.chmod(0o644)
    else:
        c.config.credential_file.write_text("unrelated")
        c.config.credential_file.chmod(0o640 if kind == "permissions" else 0o600)
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert c.requests == []


def test_failed_atomic_replace_preserves_previous_credentials_and_removes_temporary(
    issuer_case, monkeypatch
):
    c = issuer_case
    c.build().refresh()
    previous = c.config.credential_file.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert c.config.credential_file.read_bytes() == previous
    assert list(c.config.credential_file.parent.glob("*.tmp")) == []


def test_expired_valid_document_can_be_replaced_and_other_writers_are_excluded(issuer_case):
    c = issuer_case
    c.build().refresh()
    c.now = 2000
    with pytest.raises(AliyunStorageError):
        read_sts_document(c.config.credential_file, now=c.now)
    with module._output_lock(c.config.credential_file):
        c.requests.clear()
        with pytest.raises(AliyunStorageError):
            c.build().refresh()
        assert c.requests == []
    assert c.build().refresh() == 2900


def test_directory_sync_failure_leaves_a_complete_valid_document(issuer_case, monkeypatch):
    c = issuer_case
    original = os.fsync

    def fail_directory(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("synthetic directory durability failure")
        return original(descriptor)

    monkeypatch.setattr(module.os, "fsync", fail_directory)
    with pytest.raises(AliyunStorageError):
        c.build().refresh()
    assert (
        read_sts_document(c.config.credential_file, now=c.now)["security_token"] == c.target_token
    )
    assert list(c.config.credential_file.parent.glob("*.tmp")) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_role_name", "../../other"),
        ("source_role_name", ""),
        ("source_role_name", "."),
        ("source_role_name", ".."),
        ("source_role_name", "omnigent-volume-control"),
        ("team_id", None),
        ("role_arn", "acs:ram::1234567890123456:role/*"),
        ("sts_vpc", "https://untrusted.invalid"),
        ("sts_vpc", 1),
    ],
)
def test_invalid_configuration_is_not_an_ambient_role_fallback(issuer_case, field, value):
    with pytest.raises(AliyunStorageError):
        replace(issuer_case.config, **{field: value})


@pytest.mark.parametrize(
    "issuer_case", ["volume", "volume_vpc", "output_read", "output_read_vpc"], indirect=True
)
def test_config_is_private_canonical_and_hash_pinned(issuer_case):
    c = issuer_case
    assert load_issuer_config(c.config_file, c.config_hash) == c.config
    with pytest.raises(AliyunStorageError):
        load_issuer_config(c.config_file, "0" * 64)
    document = json.loads(c.config_file.read_bytes())
    document["endpoint"] = "https://untrusted.invalid"
    c.config_file.write_bytes(encode_sts_document(document))
    with pytest.raises(AliyunStorageError):
        load_issuer_config(c.config_file, hashlib.sha256(c.config_file.read_bytes()).hexdigest())


def test_unqualified_sdk_does_not_fetch_metadata(issuer_case, monkeypatch):
    monkeypatch.setattr(module, "version", lambda _: "1.3.0")
    with pytest.raises(AliyunStorageError, match="not qualified"):
        issuer_case.build().refresh()
    assert issuer_case.requests == []


def test_missing_sdk_is_reported_without_fetching_metadata(issuer_case, monkeypatch):
    def missing(_):
        raise module.PackageNotFoundError

    monkeypatch.setattr(module, "version", missing)
    with pytest.raises(AliyunStorageError, match="not qualified"):
        issuer_case.build().refresh()
    assert issuer_case.requests == []


@pytest.mark.parametrize("issuer_case", ["volume", "output_read"], indirect=True)
def test_cli_once_and_readiness_never_print_credentials(issuer_case, monkeypatch, capsys):
    c = issuer_case
    issuer = c.build()
    monkeypatch.setattr(module, "AliyunVolumeStsIssuer", lambda _: issuer)
    monkeypatch.setattr(module.time, "time", lambda: c.now)
    arguments = ["--config", str(c.config_file), "--config-sha256", c.config_hash]
    assert module.main([*arguments, "--once"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "refreshed", "expires_at": 1900}
    assert output.err == ""
    c.requests.clear()
    assert module.main([*arguments, "--check"]) == 0
    assert c.requests == []
    c.now = 2000
    assert module.main([*arguments, "--check"]) == 1
    output = capsys.readouterr()
    assert c.target_token not in output.err + output.out
    assert c.source["SecurityToken"] not in output.err + output.out


@pytest.mark.parametrize("issuer_case", ["volume", "output_read"], indirect=True)
def test_continuous_cli_retries_failed_issuance_and_stops_cleanly(
    issuer_case, monkeypatch, capsys
):
    delays = []

    class Stop:
        done = False

        def is_set(self):
            return self.done

        def set(self):
            self.done = True

        def wait(self, seconds):
            delays.append(seconds)
            self.done = len(delays) == 2

    class Issuer:
        def refresh(self):
            if not delays:
                raise AliyunStorageError("private-synthetic-error")
            return 1900

    stop = Stop()
    monkeypatch.setattr(module.threading, "Event", lambda: stop)
    monkeypatch.setattr(module.signal, "signal", lambda *_: None)
    monkeypatch.setattr(module, "AliyunVolumeStsIssuer", lambda _: Issuer())
    c = issuer_case
    assert module.main(["--config", str(c.config_file), "--config-sha256", c.config_hash]) == 0
    assert delays == [30, 300]
    output = capsys.readouterr()
    assert output.err == "Aliyun storage STS refresh failed\n"
    assert "private-synthetic-error" not in output.out + output.err


@pytest.mark.parametrize("issuer_case", ["volume", "output_read"], indirect=True)
def test_policy_review_command_does_not_fetch_or_write_credentials(issuer_case, capsys):
    c = issuer_case
    assert (
        module.main(
            [
                "--config",
                str(c.config_file),
                "--config-sha256",
                c.config_hash,
                "--print-policy",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert json.loads(output.out) == json.loads(c.config.policy)
    assert output.err == ""
    assert not c.config.credential_file.exists()
    assert c.requests == []


@pytest.mark.parametrize("issuer_case", ["output_read"], indirect=True)
@pytest.mark.parametrize(
    "kind",
    [
        "inputs",
        "unbound",
        "session_wildcard",
        "zero_project",
        "relative",
        "missing_slash",
        "traversal",
        "duplicate",
        "mutable",
        "empty",
        "bucket_wildcard",
        "oversize_policy",
    ],
)
def test_output_issuer_rejects_unbound_wildcard_or_excess_scope_before_network(issuer_case, kind):
    c = issuer_case
    prefix = c.config.output_prefixes[0]
    values = {"output_prefixes": (prefix,)}
    if kind == "inputs":
        values["output_prefixes"] = (prefix.replace("/outputs/", "/inputs/"),)
    elif kind in {"unbound", "session_wildcard", "zero_project"}:
        parts = prefix.split("/")
        parts[-3 if kind == "session_wildcard" else -4] = {
            "unbound": "unbound",
            "session_wildcard": "*",
            "zero_project": "A" * 22,
        }[kind]
        values["output_prefixes"] = ("/".join(parts),)
    elif kind == "relative":
        values["output_prefixes"] = (prefix.lstrip("/"),)
    elif kind == "missing_slash":
        values["output_prefixes"] = (prefix.rstrip("/"),)
    elif kind == "traversal":
        values["output_prefixes"] = (prefix + "../",)
    elif kind == "duplicate":
        values["output_prefixes"] = (prefix, prefix)
    elif kind == "mutable":
        values["output_prefixes"] = [prefix]
    elif kind == "empty":
        values["output_prefixes"] = ()
    elif kind == "bucket_wildcard":
        values["bucket"] = "*"
    else:
        values["output_prefixes"] = tuple(
            c.storage.session(c.runtime, uuid4()).volumes[1].bucket_path for _ in range(32)
        )
    with pytest.raises(AliyunStorageError):
        replace(c.config, **values)
    assert c.requests == []


@pytest.mark.parametrize("issuer_case", ["output_read"], indirect=True)
@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 1},
        {"purpose": "volume"},
        {"network": "https://untrusted.invalid"},
        {"network": "cn-shanghai"},
        {"network": True},
        {"output_prefixes": "not-a-list"},
        {"output_prefixes": [None]},
        {"output_prefixes": []},
        {"bucket": "../other"},
        {"endpoint": "https://untrusted.invalid"},
    ],
)
def test_output_issuer_config_cannot_downgrade_or_select_ambient_authority(issuer_case, changes):
    c = issuer_case
    document = json.loads(c.config_file.read_bytes())
    document.update(changes)
    c.config_file.write_bytes(encode_sts_document(document))
    with pytest.raises(AliyunStorageError):
        load_issuer_config(c.config_file, hashlib.sha256(c.config_file.read_bytes()).hexdigest())
    assert c.requests == []


@pytest.mark.parametrize("issuer_case", ["output_read_vpc"], indirect=True)
def test_output_policy_covers_five_admitted_sessions_without_matching_other_scopes(issuer_case):
    c = issuer_case
    prefixes = tuple(
        c.storage.session(c.runtime, uuid4()).volumes[1].bucket_path for _ in range(5)
    )
    config = replace(c.config, output_prefixes=prefixes)
    policy = json.loads(config.policy)
    assert len(config.policy) <= 2048
    listing, objects = policy["Statement"]
    assert listing["Action"] == ["oss:ListObjects"]
    assert objects["Action"] == ["oss:GetObject"]
    bucket = "acs:oss:*:*:" + c.storage.bucket
    for prefix in prefixes:
        assert any(fnmatchcase(bucket + prefix + "file.txt", p) for p in objects["Resource"])
        assert any(
            fnmatchcase(prefix.lstrip("/") + "folder/", p)
            for p in listing["Condition"]["StringLike"]["oss:Prefix"]
        )
    foreign = [
        c.storage.session(c.runtime, uuid4()).volumes[1].bucket_path,
        c.storage.session(replace(c.runtime, project_id=uuid4()), uuid4()).volumes[1].bucket_path,
        prefixes[0].replace("/outputs/", "/inputs/"),
    ]
    for prefix in foreign:
        assert not any(fnmatchcase(bucket + prefix + "file.txt", p) for p in objects["Resource"])
        assert not any(
            fnmatchcase(prefix.lstrip("/"), p)
            for p in listing["Condition"]["StringLike"]["oss:Prefix"]
        )
