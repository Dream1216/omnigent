"""Synthetic metadata for isolated paging UI tests, not supplier attestations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from uuid import UUID, uuid4

from saas.control_plane.model_deployments import (
    CreateModelDeploymentDraft,
    compile_model_deployment_draft,
)
from saas.control_plane.model_routing_models import (
    ModelConnectionRecord,
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
    ModelProjectionOperationRecord,
    ModelPublicationVersionRecord,
)


def seed_model_pages(factory, principal_id: UUID, tenant_id: UUID) -> None:
    at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    connection_id, credential_id = UUID(int=10001), UUID(int=11001)
    with factory.begin() as db:
        for index in range(1, 32):
            db.add(
                ModelConnectionRecord(
                    id=UUID(int=10000 + index),
                    display_name=f"Pagination connection {index:02}",
                    provider_id="deepseek",
                    base_url="https://api.deepseek.com",
                    version=1,
                    credential_generation=1,
                    updated_by_principal_id=principal_id,
                    created_at=at,
                    updated_at=at,
                )
            )
        db.add(
            ModelCredentialVersionRecord(
                id=credential_id,
                connection_id=connection_id,
                generation=1,
                credential_name="pagination-synthetic-credential",
                api_key_ciphertext="browser-cipher::synthetic-metadata-only",
                created_by_principal_id=principal_id,
                created_at=at,
            )
        )
        db.add(
            ModelProjectionOperationRecord(
                id=UUID(int=12001),
                connection_id=connection_id,
                credential_version_id=credential_id,
                deployment_version_id=None,
                action="create_connection",
                actor_principal_id=principal_id,
                idempotency_key="pagination-synthetic-connection",
                request_hash="a" * 64,
                status="applied",
                version=2,
                created_at=at,
                updated_at=at,
            )
        )
        for index in range(32):
            public_id = "deepseek-off-page" if index == 0 else f"deepseek-page-{index:02}"
            created = datetime(2025, 1, 1, tzinfo=timezone.utc) if index == 0 else at
            compiled = compile_model_deployment_draft(
                CreateModelDeploymentDraft(
                    public_model_id=public_id,
                    display_name=f"Pagination draft {index:02}",
                    connection_id=connection_id,
                    credential_version_id=credential_id,
                    expected_generation=12 if index == 0 else 0,
                    wire_api="openai_chat_completions",
                    max_output_tokens=32,
                ),
                deployment_id=UUID(int=20000 + index),
            )
            db.add(
                ModelDeploymentVersionRecord(
                    id=compiled.deployment_id,
                    public_model_id=public_id,
                    display_name=compiled.display_name,
                    provider_model=public_id,
                    connection_id=connection_id,
                    credential_version_id=credential_id,
                    generation=compiled.generation,
                    deployment_alias=compiled.alias,
                    wire_api=compiled.wire_api,
                    max_output_tokens=32,
                    configuration_sha256=compiled.configuration_sha256,
                    canonical_configuration=compiled.canonical_configuration,
                    created_by_principal_id=principal_id,
                    created_at=created,
                )
            )
            db.add(
                ModelProjectionOperationRecord(
                    id=UUID(int=30000 + index),
                    connection_id=connection_id,
                    credential_version_id=credential_id,
                    deployment_version_id=compiled.deployment_id,
                    action="create_deployment",
                    actor_principal_id=principal_id,
                    idempotency_key=f"pagination-synthetic-draft-{index}",
                    request_hash=compiled.request_hash,
                    status="applied",
                    version=2,
                    created_at=created,
                    updated_at=created,
                )
            )
        for index in range(1, 32):
            public_id = f"deepseek-catalog-{index:02}"
            snapshot = json.dumps(
                {
                    "schema_version": 1,
                    "tenant_id": str(tenant_id),
                    "public_model_id": public_id,
                    "wire_api": "openai_chat_completions",
                    "generation": 1,
                    "provider_id": "deepseek",
                    "channel_id": "deepseek",
                    "transport": "litellm",
                    "display_name": f"Pagination catalog {index:02}",
                    "provider_cost": {"pricing_revision": "synthetic"},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            db.add(
                ModelPublicationVersionRecord(
                    id=UUID(int=40000 + index),
                    operation_id=uuid4(),
                    tenant_id=tenant_id,
                    deployment_version_id=UUID(int=20000 + index),
                    public_model_id=public_id,
                    wire_api="openai_chat_completions",
                    generation=1,
                    configuration_sha256="a" * 64,
                    price_sha256="b" * 64,
                    inventory_sha256="c" * 64,
                    canonical_snapshot=snapshot,
                    snapshot_sha256=sha256(snapshot.encode()).hexdigest(),
                    canonical_readiness="{}",
                    readiness_sha256=sha256(b"{}").hexdigest(),
                    created_at=at,
                )
            )
