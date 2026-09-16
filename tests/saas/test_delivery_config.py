from __future__ import annotations

import json
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from saas.delivery.client import DeliveryClient, DeliveryConfig, DeliveryProject
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_server_config,
)
from tests.saas.test_production_server_config import _environment


@pytest.fixture
def delivery_config():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return DeliveryConfig(
        endpoint="https://dcp.test",
        issuer="https://app.test/saas/delivery",
        key_id="delivery-test",
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        projects=(DeliveryProject(uuid4(), uuid4(), uuid4(), "Project", "preview", "production"),),
    )


def test_delivery_configuration_requires_private_files_and_explicit_capability(
    tmp_path, delivery_config
):
    config = delivery_config
    key = tmp_path / "signing.pem"
    key.write_bytes(config.private_key)
    key.chmod(0o600)
    path = tmp_path / "delivery.json"
    project = config.projects[0]
    path.write_text(
        json.dumps(
            {
                "endpoint": config.endpoint,
                "issuer": config.issuer,
                "key_id": config.key_id,
                "private_key_file": str(key),
                "projects": [
                    {
                        "tenant_id": str(project.tenant_id),
                        "space_id": str(project.space_id),
                        "project_id": str(project.project_id),
                        "name": project.name,
                        "preview_environment": "preview",
                        "production_environment": "production",
                    }
                ],
            }
        )
    )
    path.chmod(0o600)
    environment = _environment(tmp_path)
    environment["OMNIGENT_SAAS_CAPABILITIES"] += ",delivery"
    with pytest.raises(ProductionServerConfigError, match="configuration file"):
        load_production_server_config(environment)
    environment["OMNIGENT_SAAS_DELIVERY_CONFIG_FILE"] = str(path)
    assert load_production_server_config(environment).delivery_config == config
    key.chmod(0o640)
    with pytest.raises(ValueError, match="owner-only"):
        DeliveryConfig.from_file(path)


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint": "http://dcp.test"},
        {"issuer": "https://user:secret@app.test"},
    ],
)
def test_delivery_authority_rejects_unsafe_origins(delivery_config, changes):
    with pytest.raises(ValueError):
        replace(delivery_config, **changes)


def test_preview_and_production_cannot_share_target(delivery_config):
    with pytest.raises(ValueError, match="distinct"):
        replace(
            delivery_config,
            projects=(replace(delivery_config.projects[0], preview_environment="production"),),
        )


@pytest.mark.asyncio
async def test_contract_drift_blocks_readiness(delivery_config):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"openapi": "3.1.0"}))
    with pytest.raises(ValueError, match="contract revisions differ"):
        await DeliveryClient(delivery_config, transport=transport).check_contract()
