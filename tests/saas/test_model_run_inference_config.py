from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from saas.production.model_run_inference import load_litellm_run_inference


def _source(tmp_path):
    key = tmp_path / "inference-key"
    key.write_text("isolated-inference-credential\n")
    key.chmod(0o400)
    return {
        "OMNIGENT_SAAS_MODEL_RUN_INFERENCE_ENABLED": "true",
        "OMNIGENT_SAAS_LITELLM_INFERENCE_BASE_URL": "http://omnigent-litellm",
        "OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE": str(key),
        "OMNIGENT_SAAS_LITELLM_RUN_ALIASES": "platform-model-" + "1" * 32,
    }


def test_run_inference_is_opt_in_and_secret_file_is_redacted(tmp_path):
    assert load_litellm_run_inference({}, sessionmaker()) is None
    configured = load_litellm_run_inference(_source(tmp_path), sessionmaker())
    assert configured.inference_key == "isolated-inference-credential"
    assert configured.inference_key not in repr(configured)


@pytest.mark.parametrize(
    "field,value",
    [
        ("OMNIGENT_SAAS_MODEL_RUN_INFERENCE_ENABLED", "TRUE"),
        ("OMNIGENT_SAAS_LITELLM_INFERENCE_KEY", "no-inline-credentials"),
        ("OMNIGENT_SAAS_LITELLM_INFERENCE_BASE_URL", "http://untrusted.test"),
        ("OMNIGENT_SAAS_LITELLM_INFERENCE_BASE_URL", "https://example.test/management"),
        ("OMNIGENT_SAAS_LITELLM_RUN_ALIASES", "arbitrary-model"),
        ("OMNIGENT_SAAS_LITELLM_RUN_ALIASES", ""),
        ("OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE", "relative-key"),
    ],
)
def test_run_inference_configuration_rejects_ambient_or_unbounded_transport(
    tmp_path, field, value
):
    source = _source(tmp_path)
    with pytest.raises(ValueError):
        load_litellm_run_inference({**source, field: value}, sessionmaker())


def test_run_inference_key_must_be_owner_read_only_and_not_a_symlink(tmp_path):
    source = _source(tmp_path)
    path = tmp_path / "inference-key"
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_litellm_run_inference(source, sessionmaker())
    path.chmod(0o400)
    link = tmp_path / "alias-key"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        load_litellm_run_inference(
            {**source, "OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE": str(link)}, sessionmaker()
        )
