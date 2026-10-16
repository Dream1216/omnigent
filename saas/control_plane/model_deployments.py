"""Secret-free immutable draft compilation; a draft is never runtime admission."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from uuid import UUID

from saas.control_plane.model_provider import _MODEL_ID
from saas.runner_adapter.platform_models import PLATFORM_MODEL_MAX_OUTPUT_TOKENS

ModelWireApi = Literal["openai_chat_completions", "openai_responses"]


class ModelDeploymentValidationError(ValueError):
    """Stable validation code; never serialize caller input in an error."""


@dataclass(frozen=True, slots=True)
class CreateModelDeploymentDraft:
    public_model_id: str
    display_name: str
    connection_id: UUID
    credential_version_id: UUID
    expected_generation: int
    wire_api: ModelWireApi
    max_output_tokens: int


@dataclass(frozen=True, slots=True)
class CompiledModelDeploymentDraft:
    deployment_id: UUID
    alias: str
    public_model_id: str
    display_name: str
    connection_id: UUID
    credential_version_id: UUID
    generation: int
    wire_api: ModelWireApi
    max_output_tokens: int
    request_hash: str
    configuration_sha256: str
    canonical_configuration: str

    @property
    def runtime_enabled(self) -> Literal[False]:
        return False

    @property
    def verification_status(self) -> Literal["not_tested"]:
        return "not_tested"

    def configuration_document(self) -> dict[str, object]:
        """Return a disposable view without making the hashed draft mutable."""

        return json.loads(self.canonical_configuration)


def _canonical(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compile_model_deployment_draft(
    command: CreateModelDeploymentDraft, *, deployment_id: UUID
) -> CompiledModelDeploymentDraft:
    """Compile metadata only; authorization and persistence belong to admission."""

    if (
        not isinstance(command.public_model_id, str)
        or _MODEL_ID.fullmatch(command.public_model_id) is None
        or not isinstance(command.display_name, str)
        or not 1 <= len(command.display_name) <= 128
        or command.display_name != command.display_name.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in command.display_name)
        or any(
            not isinstance(value, UUID) or value.int == 0
            for value in (deployment_id, command.connection_id, command.credential_version_id)
        )
        or type(command.expected_generation) is not int
        or not 0 <= command.expected_generation < (1 << 31) - 1
        or not isinstance(command.wire_api, str)
        or command.wire_api not in {"openai_chat_completions", "openai_responses"}
        or type(command.max_output_tokens) is not int
        or not 1 <= command.max_output_tokens <= PLATFORM_MODEL_MAX_OUTPUT_TOKENS
    ):
        raise ModelDeploymentValidationError("platform_model_deployment_invalid")
    generation = command.expected_generation + 1
    # The public ID stays unchanged; the private alias identifies one immutable deployment.
    alias = "platform-model-" + deployment_id.hex
    request: dict[str, object] = {
        "action": "create_deployment",
        "schema_version": 1,
        "provider_id": "deepseek",
        "public_model_id": command.public_model_id,
        "display_name": command.display_name,
        "connection_id": str(command.connection_id),
        "credential_version_id": str(command.credential_version_id),
        "expected_generation": command.expected_generation,
        "wire_api": command.wire_api,
        "max_output_tokens": command.max_output_tokens,
    }
    configuration: dict[str, object] = {
        "schema_version": 1,
        "deployment_id": str(deployment_id),
        "alias": alias,
        "provider_id": "deepseek",
        "provider_base_url": "https://api.deepseek.com",
        "provider_model": command.public_model_id,
        "public_model_id": command.public_model_id,
        "display_name": command.display_name,
        "connection_id": str(command.connection_id),
        "credential_version_id": str(command.credential_version_id),
        "generation": generation,
        "wire_api": command.wire_api,
        "max_output_tokens": command.max_output_tokens,
        "num_retries": 0,
        "max_retries": 0,
    }
    canonical = _canonical(configuration)
    return CompiledModelDeploymentDraft(
        deployment_id,
        alias,
        command.public_model_id,
        command.display_name,
        command.connection_id,
        command.credential_version_id,
        generation,
        command.wire_api,
        command.max_output_tokens,
        sha256(_canonical(request).encode("ascii")).hexdigest(),
        sha256(canonical.encode("ascii")).hexdigest(),
        canonical,
    )
