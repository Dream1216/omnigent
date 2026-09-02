from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from saas.production.artifact_admission import (
    ProductionArtifactAdmissionError,
    run_artifact_admission,
    verify_installed_artifact_admission_lineage,
)
from saas.production.server_config import (
    ProductionArtifactStoreConfig,
    ProductionS3Credentials,
    load_production_artifact_admission_receipt,
)


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def read(self, amount: int) -> bytes:
        return self.payload[:amount]

    def close(self) -> None:
        self.closed = True


class _Client:
    def __init__(
        self,
        *,
        corrupt_get: bool = False,
        store_then_raise: bool = False,
    ) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.calls: list[str] = []
        self.put_keys: list[str] = []
        self.body: _Body | None = None
        self.corrupt_get = corrupt_get
        self.store_then_raise = store_then_raise

    def put_object(self, **kwargs: Any) -> None:
        self.calls.append("put")
        assert set(kwargs) == {"Bucket", "Key", "Body"}
        identity = (kwargs["Bucket"], kwargs["Key"])
        assert identity not in self.objects
        self.put_keys.append(kwargs["Key"])
        self.objects[identity] = kwargs["Body"]
        if self.store_then_raise:
            self.store_then_raise = False
            raise TimeoutError("provider diagnostic must be redacted")

    def head_object(self, **kwargs: str) -> dict[str, int]:
        self.calls.append("head")
        identity = (kwargs["Bucket"], kwargs["Key"])
        return {"ContentLength": len(self.objects[identity])}

    def get_object(self, **kwargs: str) -> dict[str, _Body]:
        self.calls.append("get")
        payload = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        if self.corrupt_get:
            payload += b"corrupt"
        self.body = _Body(payload)
        return {"Body": self.body}

    def delete_object(self, **kwargs: str) -> None:
        self.calls.append("delete")
        self.objects.pop((kwargs["Bucket"], kwargs["Key"]), None)


def _config(tmp_path: Path) -> ProductionArtifactStoreConfig:
    return ProductionArtifactStoreConfig(
        product_revision="1" * 40,
        source_revision="1" * 40,
        image_digest="sha256:" + "3" * 64,
        release_incarnation="4" * 32,
        store_uri="s3://production-artifacts/omnigent/server",
        endpoint_url="https://objects.example.test",
        region="production-1",
        credential_revision="sha256:" + "2" * 64,
        credentials=ProductionS3Credentials(
            source_path=tmp_path / "credentials",
            source_sha256="2" * 64,
            profile="omnigent-saas-artifacts",
            access_key_id="not-used-in-crud-test",
            secret_access_key="not-used-in-crud-test-secret",
        ),
    )


def test_artifact_admission_proves_crud_hash_and_logical_delete(tmp_path: Path) -> None:
    client = _Client()
    receipt = run_artifact_admission(
        _config(tmp_path),
        client,
        nonce_factory=lambda: "a" * 32,
        now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert client.calls == ["put", "head", "get", "delete"] * 4
    assert client.objects == {}
    assert client.body is not None and client.body.closed is True
    assert receipt["status"] == "pass"
    assert receipt["product_revision"] == "1" * 40
    assert receipt["source_revision"] == "1" * 40
    assert receipt["image_digest"] == "sha256:" + "3" * 64
    assert receipt["release_incarnation"] == "4" * 32
    assert receipt["credential_revision"] == "sha256:" + "2" * 64
    assert receipt["artifact_region"] == "production-1"
    assert receipt["verified_key_spaces"] == [
        "admission",
        "file_id",
        "agent_bundle",
        "executor_storage",
    ]
    assert set(receipt["object_key_sha256s"]) == set(receipt["verified_key_spaces"])
    assert client.put_keys == [
        "omnigent/server/admission/" + "1" * 40 + "/" + "a" * 32 + ".json",
        "omnigent/server/" + "a" * 32,
        "omnigent/server/"
        + "a" * 32
        + "/"
        + hashlib.sha256(
            (
                '{"nonce":"'
                + "a" * 32
                + '","product_revision":"'
                + "1" * 40
                + '","schema_version":1}'
            ).encode("ascii")
        ).hexdigest(),
        "omnigent/server/executor_storage/" + "a" * 32 + "/agent.tar.gz",
    ]
    assert receipt["operations"] == ["put", "head", "get_hash", "delete"]
    rendered = repr(receipt)
    assert "production-artifacts" not in rendered
    assert "not-used-in-crud-test" not in rendered


def test_real_admission_receipt_is_accepted_by_server_loader(tmp_path: Path) -> None:
    config = _config(tmp_path)
    receipt = run_artifact_admission(
        config,
        _Client(),
        nonce_factory=lambda: "d" * 32,
        now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    path = tmp_path / "artifact-admission-receipt.json"
    path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o400)

    loaded = load_production_artifact_admission_receipt(
        {"OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE": str(path)},
        artifact_config=config,
    )

    assert loaded.operations == ("put", "head", "get_hash", "delete")
    assert loaded.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_artifact_admission_cleans_up_and_redacts_corrupt_read(tmp_path: Path) -> None:
    client = _Client(corrupt_get=True)
    with pytest.raises(ProductionArtifactAdmissionError, match="GET did not match") as captured:
        run_artifact_admission(
            _config(tmp_path),
            client,
            nonce_factory=lambda: "b" * 32,
        )
    assert client.calls[-1] == "delete"
    assert client.objects == {}
    assert captured.value.__cause__ is None


def test_artifact_admission_rejects_noncanonical_nonce_before_s3(tmp_path: Path) -> None:
    client = _Client()
    with pytest.raises(ProductionArtifactAdmissionError, match="nonce is invalid"):
        run_artifact_admission(
            _config(tmp_path),
            client,
            nonce_factory=lambda: "attacker/key",
        )
    assert client.calls == []


def test_artifact_admission_cleans_up_ambiguous_put_timeout(tmp_path: Path) -> None:
    client = _Client(store_then_raise=True)
    with pytest.raises(
        ProductionArtifactAdmissionError,
        match="CRUD admission failed",
    ) as captured:
        run_artifact_admission(
            _config(tmp_path),
            client,
            nonce_factory=lambda: "c" * 32,
        )
    assert client.calls == ["put", "delete"]
    assert client.objects == {}
    assert captured.value.__cause__ is None


def test_artifact_admission_build_lineage_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from omnigent import _build_info

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "1" * 40)
    verify_installed_artifact_admission_lineage(_config(tmp_path))

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "9" * 40)
    with pytest.raises(ProductionArtifactAdmissionError, match="does not match"):
        verify_installed_artifact_admission_lineage(_config(tmp_path))
