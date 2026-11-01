from __future__ import annotations

import json
import sys

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from saas.production import identity_replay as replay_cli
from saas.production.identity_replay import load_identity_replay_config
from saas.production.identity_replay_grant import issue_grant
from saas.production.server_config import ProductionServerConfigError
from tests.saas.test_credential_worker_config import minimal_environment
from tests.saas.test_identity_replay import reviewed
from tests.saas.test_identity_sync import NOW
from tests.saas.test_identity_sync import source as source


def test_offline_review_signer_produces_bounded_owner_only_grant_without_secret_or_overwrite(
    source, tmp_path
):
    service, key, _document, inbox_id = reviewed(source)
    review = tmp_path / "review.json"
    review.write_text(json.dumps(service.review(inbox_id)))
    review.chmod(0o600)
    private = tmp_path / "offline.pem"
    private.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    private.chmod(0o600)
    output = issue_grant(
        review_file=str(review),
        signing_key_file=str(private),
        key_id="offline-review",
        review_reference="synthetic/OPS-123",
        reason_code="provider_restored",
        output_directory=str(tmp_path / "authorization"),
        now=NOW,
    )
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_mode & 0o777 == 0o700
    assert (
        service.replay((output / "grant.txt").read_text().strip(), now=NOW)["status"] == "pending"
    )
    with pytest.raises(FileExistsError):
        issue_grant(
            review_file=str(review),
            signing_key_file=str(private),
            key_id="offline-review",
            review_reference="synthetic/OPS-123",
            reason_code="provider_restored",
            output_directory=str(output),
            now=NOW,
        )


def test_replay_verification_keys_are_separate_from_runtime_authorities(tmp_path):
    source = minimal_environment(tmp_path)
    keys = tmp_path / "replay-keys.json"
    keys.write_text(json.dumps({"schema_version": 1, "keys": {"offline-review": "a" * 64}}))
    keys.chmod(0o600)
    source["OMNIGENT_SAAS_IDENTITY_REPLAY_KEYS_FILE"] = str(keys)
    release, verification = load_identity_replay_config(source)
    assert release.identity.organization == "customers" and list(verification.public_keys) == [
        "offline-review"
    ]
    for name in (
        "OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE",
        "OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE",
        "OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE",
        "OMNIGENT_SAAS_CREDENTIAL_RECOVERY_KEYRING_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
    ):
        with pytest.raises(ProductionServerConfigError, match="unrelated authority"):
            load_identity_replay_config(source | {name: "/never-read/private"})
    keys.chmod(0o644)
    with pytest.raises(ProductionServerConfigError):
        load_identity_replay_config(source)


def test_operations_failure_emits_no_private_driver_or_signature_material(monkeypatch, capsys):
    secret = "private-database-or-signed-grant-material"

    def fail(_source):
        raise RuntimeError(secret)

    monkeypatch.setattr(replay_cli, "load_identity_replay_config", fail)
    monkeypatch.setattr(sys, "argv", ["identity-replay", "list"])
    assert replay_cli.main() == 1
    out = capsys.readouterr()
    assert secret not in out.out + out.err
    assert json.loads(out.out)["error"] == "identity_replay_rejected"
