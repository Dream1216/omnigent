"""Explicit production S3 client composition without ambient credentials."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from saas.production.server_config import ProductionServerConfig


class ProductionArtifactStoreError(RuntimeError):
    """Stable fail-closed production artifact-store composition error."""


@dataclass(frozen=True, slots=True)
class BuiltProductionS3ArtifactStore:
    """Official store plus its bounded, content-blind readiness probe."""

    store: Any = field(repr=False)
    client: Any = field(repr=False)
    readiness_client: Any = field(repr=False)
    bucket: str
    readiness_object_key: str
    readiness_sha256: str

    def assert_ready(self) -> None:
        """Read and hash only the small, immutable deployment canary."""

        try:
            head = self.readiness_client.head_object(
                Bucket=self.bucket,
                Key=self.readiness_object_key,
            )
            size = head.get("ContentLength")
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 4096:
                raise ProductionArtifactStoreError(
                    "production artifact readiness canary has an invalid size"
                )
            response = self.readiness_client.get_object(
                Bucket=self.bucket,
                Key=self.readiness_object_key,
                Range=f"bytes=0-{size - 1}",
            )
            body = response.get("Body")
            if body is None or not callable(getattr(body, "read", None)):
                raise ProductionArtifactStoreError(
                    "production artifact readiness canary body is unavailable"
                )
            try:
                payload = body.read(4097)
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
            if (
                not isinstance(payload, bytes)
                or len(payload) != size
                or not hmac.compare_digest(
                    hashlib.sha256(payload).hexdigest(), self.readiness_sha256
                )
            ):
                raise ProductionArtifactStoreError(
                    "production artifact readiness canary digest does not match"
                )
        except ProductionArtifactStoreError:
            raise
        except Exception:  # noqa: BLE001 - redact all provider diagnostics at HTTP boundary.
            raise ProductionArtifactStoreError(
                "production artifact store readiness failed"
            ) from None


def build_production_s3_artifact_store(
    config: ProductionServerConfig,
) -> BuiltProductionS3ArtifactStore:
    """Build the official S3 store from one validated credential profile.

    The production configuration loader has already rejected every supported
    ambient AWS credential provider.  Supplying the credentials directly to
    the client keeps boto3 from consulting instance metadata, web identity,
    container credentials, a home-directory profile, or process environment.
    """

    try:
        import boto3
        from botocore.config import Config

        from omnigent.stores.artifact_store.s3 import S3ArtifactStore
    except ImportError as error:
        raise ProductionArtifactStoreError(
            "production S3 artifact-store dependencies are unavailable"
        ) from error

    credentials = config.secrets.artifact_credentials
    try:
        client = boto3.client(
            "s3",
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            endpoint_url=config.artifact_endpoint_url,
            region_name=config.artifact_region,
            config=Config(
                signature_version="s3v4",
                connect_timeout=5,
                read_timeout=30,
                retries={"mode": "standard", "max_attempts": 3},
            ),
        )
        # Kubelet gives the HTTP readiness probe three seconds.  A dedicated
        # client keeps HEAD+GET bounded below that deadline and prevents an S3
        # outage from accumulating long-lived readiness threads.  Business
        # traffic retains the separately tuned retry policy above.
        readiness_client = boto3.client(
            "s3",
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            endpoint_url=config.artifact_endpoint_url,
            region_name=config.artifact_region,
            config=Config(
                signature_version="s3v4",
                connect_timeout=0.5,
                read_timeout=0.75,
                retries={"mode": "standard", "total_max_attempts": 1},
            ),
        )
        store = S3ArtifactStore(config.artifact_store_uri, client=client)
        parsed = urlsplit(config.artifact_store_uri)
        prefix = parsed.path.strip("/")
        readiness_object_key = (
            f"{prefix}/{config.artifact_readiness_key}"
            if prefix
            else config.artifact_readiness_key
        )
        return BuiltProductionS3ArtifactStore(
            store=store,
            client=client,
            readiness_client=readiness_client,
            bucket=parsed.netloc,
            readiness_object_key=readiness_object_key,
            readiness_sha256=config.artifact_readiness_sha256,
        )
    except Exception:  # noqa: BLE001 - SDK/plugin errors may contain credential material.
        raise ProductionArtifactStoreError(
            "production S3 artifact store could not be composed"
        ) from None


__all__ = [
    "BuiltProductionS3ArtifactStore",
    "ProductionArtifactStoreError",
    "build_production_s3_artifact_store",
]
