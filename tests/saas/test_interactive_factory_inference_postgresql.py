from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa

from saas.control_plane.model_deployments import compile_stored_model_deployment
from saas.control_plane.model_routing_models import (
    ModelCredentialVersionRecord,
    ModelDeploymentVersionRecord,
)
from saas.production.litellm_configuration_attestation import LiteLLMConfigurationAttestor
from tests.saas.test_interactive_factory_fleet_postgresql import _factory_run, _signed_fleet
from tests.saas.test_model_connections import _KEY
from tests.saas.test_model_run_evidence_postgresql import (
    publication_protocol as publication_protocol,
)
from tests.saas.test_model_run_inference_postgresql import (
    _exercise_run_inference,
    _real_litellm,
)
from tests.saas.test_model_run_inference_postgresql import (
    funded_publication as funded_publication,
)


def test_signed_fleet_factory_actual_litellm_and_existing_machine_billing(
    isolated_postgres_url, tmp_path, db_uri, monkeypatch
):
    path = os.environ.get("OMNIGENT_SAAS_TEST_LITELLM_RUNTIME_FILE")
    if path is None:
        pytest.skip("requires an explicitly provisioned isolated LiteLLM process")
    document = json.loads(Path(path).read_text())
    assert document["synthetic_scope"] == "internal-network-verified-tls-no-real-provider"
    assert document["provider_base"] == "https://api.deepseek.com"
    assert document["provider_key"] == _KEY

    def inference(state):
        engine = sa.create_engine(document["attestation_database_url"], hide_parameters=True)
        attestor = LiteLLMConfigurationAttestor(
            engine, salt_key=document["salt_key"], expected_database="probe"
        )
        bindings = []

        def configuration(publication):
            with state.fixture.base.factory() as db:
                draft = compile_stored_model_deployment(
                    db.get(ModelDeploymentVersionRecord, UUID(publication["deployment_id"]))
                )
                name = db.get(
                    ModelCredentialVersionRecord, draft.credential_version_id
                ).credential_name
            actual = _real_litellm(publication, credential_name=name)
            attestor.validate_authority()
            attestor.attest(draft=draft, credential_name=name, expected_api_key=_KEY)
            bindings.append((draft, name))
            return actual

        try:
            _exercise_run_inference(
                state.fixture,
                tmp_path,
                True,
                factory_state=state,
                configuration_probe=configuration,
            )
            assert len(bindings) == 1
            draft, name = bindings[0]
            attestor.attest(draft=draft, credential_name=name, expected_api_key=_KEY)
        finally:
            engine.dispose()

    _signed_fleet(
        isolated_postgres_url,
        tmp_path,
        monkeypatch,
        runtime_probe=lambda case: _factory_run(
            case,
            db_uri=db_uri,
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
            inference_probe=inference,
        ),
    )
