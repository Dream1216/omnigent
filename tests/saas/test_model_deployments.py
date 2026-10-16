from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from uuid import UUID, uuid4

import pytest

from saas.control_plane.model_deployments import (
    CreateModelDeploymentDraft,
    ModelDeploymentValidationError,
    compile_model_deployment_draft,
)
from saas.runner_adapter.platform_models import PLATFORM_MODEL_MAX_OUTPUT_TOKENS


def _command() -> CreateModelDeploymentDraft:
    return CreateModelDeploymentDraft(
        public_model_id="deepseek-isolated-contract",
        display_name="DeepSeek 隔离候选",
        connection_id=uuid4(),
        credential_version_id=uuid4(),
        expected_generation=0,
        wire_api="openai_chat_completions",
        max_output_tokens=32,
    )


def test_draft_is_deterministic_immutable_and_never_advertises_runtime_availability():
    command, identifier = _command(), uuid4()
    compiled = compile_model_deployment_draft(command, deployment_id=identifier)
    assert compiled == compile_model_deployment_draft(command, deployment_id=identifier)
    assert compiled.runtime_enabled is False and compiled.verification_status == "not_tested"
    assert compiled.public_model_id == command.public_model_id
    assert compiled.alias == "platform-model-" + identifier.hex
    assert compiled.generation == 1
    assert (
        compiled.configuration_sha256
        == sha256(compiled.canonical_configuration.encode("ascii")).hexdigest()
    )
    document = compiled.configuration_document()
    assert document["num_retries"] == document["max_retries"] == 0
    assert document["credential_version_id"] == str(command.credential_version_id)
    assert not {"api_key", "management_key", "credential_values"} & set(document)
    document["max_output_tokens"] = 1_000_000
    assert compiled.configuration_document()["max_output_tokens"] == 32


def test_generated_deployment_identity_does_not_break_request_idempotency():
    command = _command()
    first = compile_model_deployment_draft(command, deployment_id=uuid4())
    second = compile_model_deployment_draft(command, deployment_id=uuid4())
    assert first.request_hash == second.request_hash
    assert first.configuration_sha256 != second.configuration_sha256
    for change in (
        {"credential_version_id": uuid4()},
        {"max_output_tokens": 31},
        {"wire_api": "openai_responses"},
        {"expected_generation": 1},
    ):
        changed = compile_model_deployment_draft(
            replace(command, **change), deployment_id=first.deployment_id
        )
        assert changed.request_hash != first.request_hash
        assert changed.configuration_sha256 != first.configuration_sha256


@pytest.mark.parametrize(
    "change",
    (
        {"public_model_id": "untrusted/provider"},
        {"public_model_id": "deepseek-invalid/key"},
        {"display_name": " hidden "},
        {"display_name": "bad\nlabel"},
        {"connection_id": UUID(int=0)},
        {"credential_version_id": UUID(int=0)},
        {"expected_generation": True},
        {"expected_generation": -1},
        {"expected_generation": (1 << 31) - 1},
        {"wire_api": "custom"},
        {"max_output_tokens": True},
        {"max_output_tokens": 0},
        {"max_output_tokens": PLATFORM_MODEL_MAX_OUTPUT_TOKENS + 1},
    ),
)
def test_invalid_draft_never_echoes_the_payload(change):
    with pytest.raises(ModelDeploymentValidationError) as rejected:
        compile_model_deployment_draft(replace(_command(), **change), deployment_id=uuid4())
    assert str(rejected.value) == "platform_model_deployment_invalid"


def test_deployment_identifier_must_be_nonzero_uuid():
    with pytest.raises(ModelDeploymentValidationError):
        compile_model_deployment_draft(_command(), deployment_id=UUID(int=0))
