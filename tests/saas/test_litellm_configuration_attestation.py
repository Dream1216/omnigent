from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import asdict, replace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from saas.production.litellm_configuration_attestation import (
    LiteLLMAttestationError,
    LiteLLMStoredConfiguration,
    attest_litellm_configuration,
)
from tests.saas.test_model_protocol_probe import _fixture

_KEY = "isolated-api-key-must-not-appear-in-evidence"
_SALT = "isolated-litellm-at-rest-salt-key-only"


def _seal(value, *, salt=_SALT):
    nonce = b"n" * 12
    return (
        "v2:gcm:"
        + base64.urlsafe_b64encode(
            nonce
            + AESGCM(hashlib.sha256(salt.encode()).digest()).encrypt(nonce, value.encode(), None)
        ).decode()
    )


def _snapshot():
    draft, _admission = _fixture()
    name = "platform-credential-" + draft.credential_version_id.hex
    snapshot = LiteLLMStoredConfiguration(
        [
            {
                "model_id": str(draft.deployment_id),
                "model_name": draft.alias,
                "blocked": False,
                "model_info": {
                    "id": str(draft.deployment_id),
                    "db_model": False,
                    "member_auto_router": False,
                    "mode": None,
                },
                "litellm_params": {
                    "model": _seal("deepseek/" + draft.public_model_id),
                    "api_base": _seal("https://api.deepseek.com"),
                    "litellm_credential_name": _seal(name),
                    "num_retries": 0,
                    "max_retries": 0,
                    "api_key": None,
                    "use_litellm_proxy": False,
                },
            }
        ],
        [
            {
                "credential_id": str(uuid4()),
                "credential_name": name,
                "credential_values": {"api_key": _seal(_KEY)},
                "credential_info": {"custom_llm_provider": "deepseek"},
            }
        ],
        [],
    )
    return snapshot, {
        "draft": draft,
        "credential_name": name,
        "expected_api_key": _KEY,
        "salt_key": _SALT,
    }


def test_attestation_binds_hidden_credential_and_only_exposes_nonsecret_evidence():
    snapshot, arguments = _snapshot()
    result = attest_litellm_configuration(snapshot, **arguments)
    evidence = json.dumps(asdict(result), default=str)
    assert result.configuration_sha256 == arguments["draft"].configuration_sha256
    assert len(result.stored_state_sha256) == 64
    assert _KEY not in evidence and _SALT not in evidence and "v2:gcm:" not in evidence
    assert _KEY not in repr(snapshot) and _SALT not in repr(snapshot)
    assert result.contract == "litellm-1.105.1-aes-gcm-v1"
    assert result.scope == "stored_model_credential_and_database_overlays"
    assert (
        attest_litellm_configuration(snapshot, **arguments).stored_state_sha256
        == result.stored_state_sha256
    )


@pytest.mark.parametrize(
    "change",
    (
        "wrong_key",
        "wrong_salt",
        "corrupt_cipher",
        "legacy_cipher",
        "plaintext_key",
        "hidden_key_override",
        "hidden_secret_override",
        "credential_endpoint_override",
        "wrong_name",
        "blocked",
        "duplicate_alias",
        "missing_model",
        "wrong_model_id",
        "unknown_parameter",
        "retry",
        "retry_boolean",
        "true_flag",
        "global_overlay",
        "unapproved_model_metadata",
        "stored_db_model_marker_changed",
        "member_auto_router_enabled",
        "provider_changed",
        "model_base_changed",
    ),
)
def test_unattested_or_overridden_configuration_is_redacted_and_rejected(change):
    original, arguments = _snapshot()
    snapshot = copy.deepcopy(original)
    model, credential = snapshot.models[0], snapshot.credentials[0]
    if change == "wrong_key":
        credential["credential_values"]["api_key"] = _seal("another-private-provider-key")
    elif change == "wrong_salt":
        arguments["salt_key"] = "another-private-litellm-salt-key-value"
    elif change == "corrupt_cipher":
        credential["credential_values"]["api_key"] = "v2:gcm:" + "?" * 100
    elif change == "legacy_cipher":
        credential["credential_values"]["api_key"] = "legacy-cipher-requires-explicit-migration"
    elif change == "plaintext_key":
        credential["credential_values"]["api_key"] = _KEY
    elif change in {"hidden_key_override", "hidden_secret_override"}:
        model["litellm_params"][
            "api_key" if change == "hidden_key_override" else "client_secret"
        ] = _seal(_KEY)
    elif change == "credential_endpoint_override":
        credential["credential_values"]["api_base"] = _seal("https://unapproved.example")
    elif change == "wrong_name":
        credential["credential_name"] = "not-the-approved-credential"
    elif change == "blocked":
        model["blocked"] = True
    elif change == "duplicate_alias":
        snapshot = replace(snapshot, models=[model, model])
    elif change == "missing_model":
        snapshot = replace(snapshot, models=[])
    elif change == "wrong_model_id":
        model["model_id"] = str(uuid4())
    elif change == "unknown_parameter":
        model["litellm_params"]["mock_response"] = "untrusted-response"
    elif change == "retry":
        model["litellm_params"]["num_retries"] = 1
    elif change == "retry_boolean":
        model["litellm_params"]["max_retries"] = False
    elif change == "true_flag":
        model["litellm_params"]["use_litellm_proxy"] = True
    elif change == "global_overlay":
        snapshot = replace(
            snapshot,
            settings=[{"param_name": "router_settings", "param_value": {"num_retries": 1}}],
        )
    elif change == "unapproved_model_metadata":
        model["model_info"]["callbacks"] = ["unapproved"]
    elif change == "stored_db_model_marker_changed":
        model["model_info"]["db_model"] = True
    elif change == "member_auto_router_enabled":
        model["model_info"]["member_auto_router"] = True
    elif change == "provider_changed":
        credential["credential_info"]["custom_llm_provider"] = "another-provider"
    elif change == "model_base_changed":
        model["litellm_params"]["api_base"] = _seal("https://unapproved.example")
    with pytest.raises(LiteLLMAttestationError) as error:
        attest_litellm_configuration(snapshot, **arguments)
    assert str(error.value) == "litellm_configuration_drift" or str(error.value).startswith(
        "litellm_attestation_"
    )
    assert _KEY not in str(error.value) and _SALT not in str(error.value)


def test_nonsecret_literal_parameters_are_supported_but_plaintext_credentials_are_not():
    snapshot, arguments = _snapshot()
    params = snapshot.models[0]["litellm_params"]
    params["model"] = "deepseek/" + arguments["draft"].public_model_id
    attest_litellm_configuration(snapshot, **arguments)
    snapshot.credentials[0]["credential_values"]["api_key"] = _KEY
    with pytest.raises(LiteLLMAttestationError, match="cipher_unsupported"):
        attest_litellm_configuration(snapshot, **arguments)


def test_only_the_unmodified_empty_upstream_license_baseline_is_allowed():
    snapshot, arguments = _snapshot()
    snapshot = replace(
        snapshot, settings=[{"param_name": "auto_router_tuning_baseline_v3", "param_value": {}}]
    )
    attest_litellm_configuration(snapshot, **arguments)
    snapshot.settings[0]["param_value"] = {"unapproved-router": "unapproved-tuning"}
    with pytest.raises(LiteLLMAttestationError):
        attest_litellm_configuration(snapshot, **arguments)


@pytest.mark.parametrize(
    "change", ("deployment", "credential", "configuration", "state", "scope", "contract", "time")
)
def test_storage_witness_binding_rejects_another_draft_or_proof_contract(change):
    snapshot, arguments = _snapshot()
    witness = attest_litellm_configuration(snapshot, **arguments)
    witness.require_binding(arguments["draft"])
    fields = {
        "deployment": {"deployment_id": uuid4()},
        "credential": {"credential_version_id": uuid4()},
        "configuration": {"configuration_sha256": "f" * 64},
        "state": {"stored_state_sha256": "invalid"},
        "scope": {"scope": "all_hidden_runtime_memory"},
        "contract": {"contract": "unapproved"},
        "time": {"observed_at": witness.observed_at.replace(tzinfo=None)},
    }
    with pytest.raises(LiteLLMAttestationError, match="binding_invalid"):
        replace(witness, **fields[change]).require_binding(arguments["draft"])
