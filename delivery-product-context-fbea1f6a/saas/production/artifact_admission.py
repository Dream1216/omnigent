"""One-shot CRUD admission for the production Server artifact authority."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from saas.production.server_config import (
    ProductionArtifactStoreConfig,
    load_production_artifact_store_config,
)


class ProductionArtifactAdmissionError(RuntimeError):
    """Stable, content-blind artifact admission failure."""


_KEY_SPACES = ("admission", "file_id", "agent_bundle", "executor_storage")
_OPERATIONS = ("put", "head", "get_hash", "delete")


def build_artifact_admission_client(config: ProductionArtifactStoreConfig) -> Any:
    """Construct one explicit, bounded S3 client without a default Session."""

    try:
        import boto3
        from botocore.config import Config

        credentials = config.credentials
        return boto3.client(
            "s3",
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            endpoint_url=config.endpoint_url,
            region_name=config.region,
            config=Config(
                signature_version="s3v4",
                connect_timeout=2,
                read_timeout=10,
                retries={"mode": "standard", "total_max_attempts": 2},
            ),
        )
    except Exception:  # noqa: BLE001 - provider diagnostics may contain authority material.
        raise ProductionArtifactAdmissionError(
            "production artifact admission client could not be composed"
        ) from None


def _delete_best_effort(client: Any, *, bucket: str, key: str) -> None:
    # Cleanup cannot replace the original content-blind admission failure.
    with suppress(Exception):
        client.delete_object(Bucket=bucket, Key=key)


def _probe_object(client: Any, *, bucket: str, key: str, payload: bytes) -> None:
    """Exercise the same primitive S3 calls as the official artifact wrapper."""

    payload_sha256 = hashlib.sha256(payload).hexdigest()
    cleanup_required = False
    try:
        # Keep this call shape identical to S3ArtifactStore.put().  Provider-
        # optional checksum and conditional-write headers are deliberately not
        # admission requirements for the supported S3-compatible backends.
        cleanup_required = True
        client.put_object(Bucket=bucket, Key=key, Body=payload)
        head = client.head_object(Bucket=bucket, Key=key)
        if head.get("ContentLength") != len(payload):
            raise ProductionArtifactAdmissionError(
                "production artifact admission HEAD did not match"
            )
        response = client.get_object(Bucket=bucket, Key=key)
        body = response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise ProductionArtifactAdmissionError(
                "production artifact admission GET body is unavailable"
            )
        try:
            observed = body.read(len(payload) + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if (
            not isinstance(observed, bytes)
            or len(observed) != len(payload)
            or hashlib.sha256(observed).hexdigest() != payload_sha256
        ):
            raise ProductionArtifactAdmissionError(
                "production artifact admission GET did not match"
            )
        client.delete_object(Bucket=bucket, Key=key)
        cleanup_required = False
    except ProductionArtifactAdmissionError:
        if cleanup_required:
            _delete_best_effort(client, bucket=bucket, key=key)
        raise
    except Exception:  # noqa: BLE001 - all provider diagnostics are secret-adjacent.
        if cleanup_required:
            _delete_best_effort(client, bucket=bucket, key=key)
        raise ProductionArtifactAdmissionError(
            "production artifact CRUD admission failed"
        ) from None


def run_artifact_admission(
    config: ProductionArtifactStoreConfig,
    client: Any,
    *,
    nonce_factory: Callable[[], str] = lambda: uuid4().hex,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Prove create/read/hash and an accepted logical delete without listing."""

    nonce = nonce_factory()
    if len(nonce) != 32 or any(character not in "0123456789abcdef" for character in nonce):
        raise ProductionArtifactAdmissionError("artifact admission nonce is invalid")
    parsed = urlsplit(config.store_uri)
    bucket = parsed.netloc
    prefix = parsed.path.strip("/")
    payload = json.dumps(
        {
            "nonce": nonce,
            "product_revision": config.product_revision,
            "schema_version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    relative_keys = {
        "admission": f"admission/{config.product_revision}/{nonce}.json",
        # Production file, agent, and conversation identifiers are bare UUID
        # hex.  These paths intentionally match the real business-key shapes.
        "file_id": nonce,
        "agent_bundle": f"{nonce}/{payload_sha256}",
        "executor_storage": f"executor_storage/{nonce}/agent.tar.gz",
    }
    object_keys = {
        name: f"{prefix}/{relative_key}" if prefix else relative_key
        for name, relative_key in relative_keys.items()
    }
    for name in _KEY_SPACES:
        _probe_object(client, bucket=bucket, key=object_keys[name], payload=payload)

    completed_at = now().astimezone(timezone.utc).replace(microsecond=0)
    return {
        "schema_version": 1,
        "status": "pass",
        "product_revision": config.product_revision,
        "source_revision": config.source_revision,
        "image_digest": config.image_digest,
        "release_incarnation": config.release_incarnation,
        "artifact_store_uri_sha256": hashlib.sha256(config.store_uri.encode("utf-8")).hexdigest(),
        "artifact_endpoint_url_sha256": hashlib.sha256(
            config.endpoint_url.encode("utf-8")
        ).hexdigest(),
        "artifact_region": config.region,
        "credential_revision": config.credential_revision,
        "verified_key_spaces": list(_KEY_SPACES),
        "object_key_sha256s": {
            name: hashlib.sha256(object_keys[name].encode("utf-8")).hexdigest()
            for name in _KEY_SPACES
        },
        "operations": list(_OPERATIONS),
        "completed_at": completed_at.isoformat(),
    }


def verify_installed_artifact_admission_lineage(
    config: ProductionArtifactStoreConfig,
) -> None:
    """Reject a Job whose installed wheel is not the configured exact source."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (ImportError, AttributeError):
        raise ProductionArtifactAdmissionError(
            "production artifact admission build lineage is unavailable"
        ) from None
    if (
        installed_revision != config.product_revision
        or installed_revision != config.source_revision
    ):
        raise ProductionArtifactAdmissionError(
            "production artifact admission build lineage does not match"
        )


def main() -> None:
    """Emit exactly one content-blind JSON receipt and fail with no traceback."""

    try:
        config = load_production_artifact_store_config(os.environ)
        verify_installed_artifact_admission_lineage(config)
        client = build_artifact_admission_client(config)
        receipt = run_artifact_admission(config, client)
    except Exception:  # noqa: BLE001 - CLI boundary must never print provider diagnostics.
        print(
            json.dumps(
                {"schema_version": 1, "status": "fail", "code": "artifact_admission_failed"},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        raise SystemExit(1) from None
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()


__all__ = [
    "ProductionArtifactAdmissionError",
    "build_artifact_admission_client",
    "main",
    "run_artifact_admission",
    "verify_installed_artifact_admission_lineage",
]
