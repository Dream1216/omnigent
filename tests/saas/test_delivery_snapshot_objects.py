"""Actual SaaS authorization and S3 signing; storage fault fixtures, not live P4."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import boto3
import pytest
from botocore.config import Config
from fastapi.testclient import TestClient

from saas.control_plane.db_models import GlobalUser
from saas.delivery.authorization import create_authorization_app
from saas.delivery.snapshot_objects import SnapshotObjectAuthority, SnapshotObjectSettings
from tests.saas.test_delivery_http import build_harness


class _StorageError(Exception):
    def __init__(self, status):
        self.response = {"ResponseMetadata": {"HTTPStatusCode": status}}


class _MemoryS3:
    def __init__(self):
        self.signer = boto3.client(
            "s3",
            endpoint_url="https://objects.test",
            region_name="us-east-1",
            aws_access_key_id="unit-access",
            aws_secret_access_key="unit-only-signature-key",
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
        self.targets, self.objects, self.calls = {}, {}, []
        self.last_body = None

    def generate_presigned_url(self, operation, **kwargs):
        self.calls.append("sign")
        self.targets[kwargs["Params"]["Key"]] = copy.deepcopy(kwargs["Params"])
        return self.signer.generate_presigned_url(operation, **kwargs)

    def upload(self, target, payload):
        key = urlsplit(target["object_ref"]).path[1:]
        self.put_object(**self.targets[key], Body=payload)

    def put_object(self, **kwargs):
        self.calls.append("put")
        if kwargs["Key"] in self.objects and kwargs.get("IfNoneMatch") == "*":
            raise _StorageError(412)
        self.objects[kwargs["Key"]] = copy.deepcopy(kwargs)

    def get_object(self, **kwargs):
        self.calls.append("get")
        if kwargs["Key"] not in self.objects:
            raise _StorageError(404)
        obj = self.objects[kwargs["Key"]]
        if kwargs["SSECustomerKey"] != obj["SSECustomerKey"]:
            raise _StorageError(400)
        self.last_body = io.BytesIO(obj["Body"])
        return {
            "Body": self.last_body,
            "ContentLength": obj.get("observed_length", len(obj["Body"])),
            "Metadata": obj.get("Metadata", {}),
            "ContentType": obj["ContentType"],
            "SSECustomerAlgorithm": obj.get("observed_encryption", "AES256"),
            "SSECustomerKeyMD5": base64.b64encode(
                hashlib.md5(obj["SSECustomerKey"], usedforsecurity=False).digest()
            ).decode(),
        }


def _object_authority(tmp_path, authority):
    token = tmp_path / "snapshot-object.token"
    token.write_text("unit-object-authority-" + "a" * 32)
    token.chmod(0o600)
    storage = _MemoryS3()
    objects = SnapshotObjectAuthority(
        authority,
        SnapshotObjectSettings(token, "key-v1", {"key-v1": b"a" * 32}, max_bytes=4096),
        client=storage,
        artifact_store_uri="s3://unit-snapshot-bucket/isolated",
        endpoint_url="https://objects.test",
    )
    return objects, storage


def _allocation_body(h):
    return {
        "identity": {
            "tenant_id": str(h.project.tenant_id),
            "project_id": str(h.project.project_id),
            "actor_id": str(h.context.actor_id),
            "membership_version": h.context.tenant_membership_version,
            "token_id": "unit-delegation",
        },
        "request": {
            "space_id": str(h.project.space_id),
            "environment_id": h.project.preview_environment,
            "build_id": str(uuid4()),
            "max_bytes": 4096,
        },
    }


@pytest.fixture
def objects(tmp_path):
    h = build_harness(app_database=f"sqlite+pysqlite:///{tmp_path / 'objects.sqlite3'}")
    authority, storage = _object_authority(tmp_path, h.authority)
    client = TestClient(create_authorization_app(h.authority, snapshot_objects=authority))
    client.headers["Authorization"] = "Bearer " + authority.settings.bearer_token().decode()
    try:
        yield h, authority, storage, client
    finally:
        client.close()
        h.client.close()
        h.engine.dispose()
        h.app.state.saas_test_engine.dispose()


def test_private_object_roundtrip_signs_scope_encryption_and_no_overwrite(objects):
    h, authority, storage, client = objects
    body = _allocation_body(h)
    response = client.post("/v1/snapshot-upload-targets", json=body)
    assert response.status_code == 201
    target = response.json()
    signed_headers = parse_qs(urlsplit(target["put_url"]).query)["X-Amz-SignedHeaders"][0]
    headers = {h["name"].lower(): h["value"] for h in target["headers"]}
    assert set(headers) == set(signed_headers.split(";")) - {"host"}
    assert headers["if-none-match"] == "*"
    assert headers["x-amz-meta-tenant-id"] == str(h.project.tenant_id)
    assert headers["x-amz-meta-project-id"] == str(h.project.project_id)
    assert headers["x-amz-meta-build-id"] == body["request"]["build_id"]
    assert headers["x-amz-server-side-encryption-customer-algorithm"] == "AES256"
    assert len(base64.b64decode(headers["x-amz-server-side-encryption-customer-key"])) == 32
    assert "customer-key=" not in target["put_url"]
    payload = b"actual source archive bytes in this unit fixture"
    storage.upload(target, payload)
    reference = {"object_ref": target["object_ref"]}
    head = client.post("/v1/snapshot-objects:head", json=reference)
    assert head.status_code == 200
    assert head.json() == {
        **reference,
        "size": len(payload),
        "archive_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "tenant_id": str(h.project.tenant_id),
        "project_id": str(h.project.project_id),
        "build_id": body["request"]["build_id"],
        "encrypted": True,
    }
    assert storage.last_body.closed
    assert client.post("/v1/snapshot-objects:stream", json=reference).content == payload
    assert storage.last_body.closed
    assert client.post("/v1/snapshot-upload-targets:revoke", json=reference).status_code == 204
    with pytest.raises(_StorageError):
        storage.upload(target, b"forbidden overwrite")
    assert client.post("/v1/snapshot-objects:stream", json=reference).content == payload
    assert authority.settings.keys["key-v1"] not in repr(authority.settings).encode()


@pytest.mark.parametrize(
    "fault",
    ["tenant", "project", "actor", "space", "environment", "membership", "size", "suspended"],
)
def test_current_database_scope_rejected_before_signing_or_storage(objects, fault):
    h, _authority, storage, client = objects
    body = _allocation_body(h)
    if fault in {"tenant", "project", "actor"}:
        body["identity"][fault + "_id"] = str(uuid4())
    elif fault == "space":
        body["request"]["space_id"] = str(uuid4())
    elif fault == "environment":
        body["request"]["environment_id"] = "other"
    elif fault == "membership":
        body["identity"]["membership_version"] += 1
    elif fault == "size":
        body["request"]["max_bytes"] += 1
    else:
        with h.app.state.saas_test_sessions.begin() as session:
            session.get(GlobalUser, UUID(h.scope["user_id"])).status = "suspended"
    assert client.post("/v1/snapshot-upload-targets", json=body).status_code in {403, 413}
    assert storage.calls == []


@pytest.mark.parametrize("fault", ["tenant", "project", "build", "encryption", "length"])
def test_independent_observation_refuses_mismatched_or_unencrypted_objects(objects, fault):
    h, _authority, storage, client = objects
    target = client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).json()
    storage.upload(target, b"source")
    entry = storage.objects[urlsplit(target["object_ref"]).path[1:]]
    if fault in {"tenant", "project", "build"}:
        entry["Metadata"][fault + "-id"] = "other"
    elif fault == "encryption":
        entry["observed_encryption"] = None
    else:
        entry["observed_length"] = 9000
    response = client.post("/v1/snapshot-objects:head", json={"object_ref": target["object_ref"]})
    assert response.status_code == 409
    assert storage.last_body.closed


def test_rotation_retains_old_keys_and_revocation_fences_unused_upload(objects):
    h, authority, storage, client = objects
    target = client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).json()
    storage.upload(target, b"old retained object")
    authority.settings = replace(
        authority.settings, active_key_id="key-v2", keys={"key-v1": b"a" * 32, "key-v2": b"b" * 32}
    )
    assert (
        client.post(
            "/v1/snapshot-objects:head", json={"object_ref": target["object_ref"]}
        ).status_code
        == 200
    )
    fresh = client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).json()
    assert "/key-v2/" in fresh["object_ref"]
    assert (
        client.post(
            "/v1/snapshot-upload-targets:revoke", json={"object_ref": fresh["object_ref"]}
        ).status_code
        == 204
    )
    with pytest.raises(_StorageError):
        storage.upload(fresh, b"late upload")
    assert (
        client.post(
            "/v1/snapshot-objects:head", json={"object_ref": fresh["object_ref"]}
        ).status_code
        == 409
    )
    authority.settings.bearer_token_file.write_text("unit-object-authority-" + "b" * 32)
    assert client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).status_code == 401
    client.headers["Authorization"] = "Bearer " + authority.settings.bearer_token().decode()
    assert client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).status_code == 201


def test_wrong_reference_or_bearer_never_reaches_object_store(objects):
    h, _authority, storage, client = objects
    for value in [
        "s3://other-bucket/key",
        "file:///etc/passwd",
        "https://other/source",
        "s3://unit-snapshot-bucket/isolated/../escape",
    ]:
        assert (
            client.post("/v1/snapshot-objects:head", json={"object_ref": value}).status_code == 404
        )
    client.headers["Authorization"] = "Bearer wrong"
    assert client.post("/v1/snapshot-upload-targets", json=_allocation_body(h)).status_code == 401
    assert storage.calls == []
    # The public Cookie application and an unconfigured private listener expose no object API.
    assert (
        h.client.post(
            "/v1/snapshot-upload-targets",
            json={},
            headers={"Origin": "http://testserver", "X-CSRF-Token": h.csrf},
        ).status_code
        == 404
    )
    with TestClient(create_authorization_app(h.authority)) as disabled:
        assert disabled.post("/v1/snapshot-upload-targets", json={}).status_code == 404


@pytest.mark.parametrize(
    "fault", ["none", "public-key", "short-key", "unknown-active", "duplicate", "extra"]
)
def test_settings_use_only_private_files_and_keep_key_material_out_of_errors(tmp_path, fault):
    token, key, config = (tmp_path / name for name in ["token", "key", "settings.json"])
    token.write_bytes(b"unit-object-authority-" + b"a" * 32)
    key.write_bytes(b"k" * (31 if fault == "short-key" else 32))
    for path in [token, key]:
        path.chmod(0o600)
    value = {
        "schema_version": "omnigent.saas.snapshot-object-authority/v1",
        "bearer_token_file": str(token),
        "active_key_id": "unknown" if fault == "unknown-active" else "key-v1",
        "keys": {"key-v1": str(key)},
        "ttl_seconds": 300,
        "max_bytes": 4096,
    }
    if fault == "extra":
        value["scope"] = "*"
    raw = json.dumps(value)
    if fault == "duplicate":
        raw = raw[:-1] + ',"ttl_seconds":600}'
    config.write_text(raw)
    config.chmod(0o600)
    if fault == "public-key":
        key.chmod(0o644)
    if fault == "none":
        settings = SnapshotObjectSettings.from_file(config)
        assert settings.keys["key-v1"] == b"k" * 32
        assert settings.keys["key-v1"] not in repr(settings).encode()
    else:
        with pytest.raises(ValueError, match="invalid private Snapshot") as error:
            SnapshotObjectSettings.from_file(config)
        assert "kkkk" not in str(error.value) and "unit-object-authority" not in str(error.value)
