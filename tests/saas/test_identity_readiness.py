from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saas.production.admission import admission_signature_payload, validate_evidence_admission
from saas.production.business import canonical_business_record_sha256
from saas.production.identity_readiness import (
    EVIDENCE_DIRECTORY,
    _canonical,
    load_identity_evidence,
    validate_identity_readiness,
)
from saas.scripts.check_identity_readiness import main as identity_main
from tests.saas.test_business_readiness import _record
from tests.saas.test_evidence_admission import _fixture as _admission_fixture

_ROOT = Path(__file__).resolve().parents[2]
_NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
_REVISION = "a" * 40
_CASES = [
    "password_reset",
    "provider_disable",
    "provider_delete",
    "verified_contact_change",
    "missed_password_reset",
    "missed_provider_disable",
    "missed_provider_delete",
    "worker_restart",
]


def _hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def _time(value):
    return value.isoformat().replace("+00:00", "Z")


def _fixture(tmp_path):
    for relative in (
        "saas/production/identity-policy.json",
        "saas/production/baseline.json",
        "saas/production/casdoor/source-lock.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / relative, target)
    policy = json.loads((tmp_path / "saas/production/identity-policy.json").read_bytes())
    directory = tmp_path / EVIDENCE_DIRECTORY
    (directory / "observations").mkdir(parents=True)
    image = {
        "product_revision": _REVISION,
        "images": [{"name": "omnigent-saas-server", "manifest_digest": "sha256:" + "b" * 64}],
    }
    image_file = tmp_path / "saas/acceptance/p0-production-image-evidence.json"
    image_file.parent.mkdir(parents=True)
    image_file.write_bytes(_canonical(image))
    acceptance = _record("identity-policy.json")
    acceptance.update(started_at="2026-11-01T08:00:00Z", completed_at="2026-11-01T09:00:00Z")
    acceptance["customer_acceptances"][0]["accepted_at"] = "2026-11-01T08:45:00Z"
    for row in acceptance["attestations"]:
        row["attested_at"] = "2026-11-01T09:15:00Z"
    samples = []
    for index, case in enumerate(_CASES):
        for subject in range(2):
            trigger = datetime(2026, 11, 1, 8, 5, tzinfo=UTC) + timedelta(
                seconds=index * 10 + subject
            )
            periodic = case.startswith("missed_")
            samples.append(
                {
                    "case": case,
                    "subject_sha256": _hash(f"subject-{case}-{subject}"),
                    "global_user_before_sha256": _hash(f"global-{case}-{subject}"),
                    "global_user_after_sha256": _hash(f"global-{case}-{subject}"),
                    "session_sha256": _hash(f"session-{case}-{subject}"),
                    "oidc_verification_sha256": _hash(f"verified-token-{case}-{subject}"),
                    "provider_event_sha256": None
                    if periodic
                    else _hash(f"event-{case}-{subject}"),
                    "triggered_at": _time(trigger),
                    "inbox_committed_at": None
                    if periodic
                    else _time(trigger + timedelta(milliseconds=500)),
                    "readback_completed_at": _time(trigger + timedelta(seconds=1)),
                    "session_denied_at": _time(trigger + timedelta(seconds=2)),
                    "transport": "periodic_without_notification"
                    if periodic
                    else "direct_authenticated_https",
                    "security_version_before": 1,
                    "security_version_after": 2,
                    "session_valid_before": True,
                    "session_valid_after": False,
                    "credential_owner_before": "casdoor",
                    "credential_owner_after": "casdoor",
                    "tenant_grant_delta": 0,
                }
            )
    load = {
        "admitted_identity_population": 100,
        "baseline_verified_identity_count": 100,
        "worker_replica_count": 2,
        "load_seconds": 900,
    }
    observation = {
        "schema_version": 1,
        "environment": "production",
        "product_revision": _REVISION,
        "image_digest": "sha256:" + "b" * 64,
        "provider_source_lock_sha256": policy["identity_contract"]["provider_source_lock_sha256"],
        "pins": {
            "image_evidence_sha256": _hash_bytes(image_file.read_bytes()),
            **{
                name: _hash(name)
                for name in (
                    "identity_manifest_sha256",
                    "public_config_sha256",
                    "migration_receipt_sha256",
                    "service_role_graph_sha256",
                    "provider_configuration_sha256",
                )
            },
        },
        "provenance": {
            "live_provider": True,
            "installed_metadata_override": False,
            "private_ingress_direct_tls": True,
            "provider_ca_and_hostname_verified": True,
            "signed_oidc_sessions": True,
        },
        "load": load,
        "enabled_channels": list(policy["identity_contract"]["enabled_channels"]),
        "samples": samples,
    }
    acceptance["subject_hashes"] = [row["subject_sha256"] for row in samples]
    acceptance["metrics"].update(
        load
        | {"convergence_sample_count": len(samples)}
        | {"maximum_" + case + "_milliseconds": 2000 for case in _CASES}
    )
    wrapper = {
        "schema_version": 1,
        "acceptance": acceptance,
        "observations": {"path": EVIDENCE_DIRECTORY + "/observations/live.json", "sha256": ""},
    }
    _write(tmp_path, wrapper, observation)
    return policy, wrapper, observation


def _hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _write(repo, wrapper, observation):
    raw = _canonical(observation)
    wrapper["observations"]["sha256"] = _hash_bytes(raw)
    wrapper["acceptance"]["artifact"]["sha256"] = _hash_bytes(raw)
    wrapper["acceptance"]["record_sha256"] = canonical_business_record_sha256(
        wrapper["acceptance"]
    )
    (repo / wrapper["observations"]["path"]).write_bytes(raw)
    (repo / EVIDENCE_DIRECTORY / "acceptance.json").write_bytes(_canonical(wrapper))


def _validate(repo, policy):
    return validate_identity_readiness(
        repo,
        policy,
        load_identity_evidence(repo, policy),
        now=_NOW,
        expected_product_revision=_REVISION,
    )


def test_no_identity_evidence_is_structurally_valid_and_cannot_pass_release():
    policy = json.loads((_ROOT / "saas/production/identity-policy.json").read_bytes())
    report = validate_identity_readiness(
        _ROOT, policy, [], now=_NOW, expected_product_revision=_REVISION
    )
    assert report["status"] == "pass" and report["production_readiness"] == "blocked"
    assert report["metrics"]["qualified_record_count"] == 0


def test_complete_synthetic_unit_fixture_validates_domain_facts_but_is_not_live_evidence(tmp_path):
    policy, _wrapper, _observation = _fixture(tmp_path)
    report = _validate(tmp_path, policy)
    assert report["status"] == "pass" and report["production_readiness"] == "ready", report
    assert report["metrics"]["qualified_record_count"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment", "sandbox"),
        ("product_revision", "c" * 40),
        ("provider_source_lock_sha256", "c" * 64),
        ("enabled_channels", ["email_password", "github"]),
        ("enabled_channels", ["email_password"]),
        ("schema_version", True),
        ("image_digest", "sha256:" + "c" * 64),
    ],
)
def test_observation_cannot_replace_the_actual_release_or_channel_inventory(
    tmp_path, field, value
):
    policy, wrapper, observation = _fixture(tmp_path)
    observation[field] = value
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "blocked"


@pytest.mark.parametrize(
    "field,value",
    [
        ("live_provider", False),
        ("installed_metadata_override", True),
        ("private_ingress_direct_tls", False),
        ("provider_ca_and_hostname_verified", False),
        ("signed_oidc_sessions", False),
        ("live_provider", 1),
    ],
)
def test_fixture_metadata_or_insecure_transport_cannot_qualify(tmp_path, field, value):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["provenance"][field] = value
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "blocked"


@pytest.mark.parametrize(
    "field,value",
    [
        ("transport", "replayed_fixture"),
        ("provider_event_sha256", None),
        ("inbox_committed_at", None),
        ("global_user_after_sha256", "c" * 64),
        ("credential_owner_after", "legacy"),
        ("session_valid_before", False),
        ("session_valid_after", True),
        ("tenant_grant_delta", 1),
        ("security_version_before", True),
        ("security_version_after", 1),
        ("readback_completed_at", "2026-11-01T08:04:00Z"),
        ("session_denied_at", "2026-11-01T08:10:00.001Z"),
        ("oidc_verification_sha256", "0" * 64),
    ],
)
def test_samples_prove_the_measured_security_and_direct_delivery_path(tmp_path, field, value):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"][0][field] = value
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "blocked"


def test_periodic_recovery_and_all_required_cases_are_independently_covered(tmp_path):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"] = [
        row for row in observation["samples"] if row["case"] != "missed_provider_delete"
    ]
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "blocked"
    observation["samples"].append(copy.deepcopy(observation["samples"][0]))
    _write(tmp_path, wrapper, observation)
    report = _validate(tmp_path, policy)
    assert any("unique" in item or "independent" in item for item in report["violations"])


@pytest.mark.parametrize(
    "change",
    [
        {"baseline_verified_identity_count": 99},
        {"worker_replica_count": 1},
        {"load_seconds": 899},
        {"load_seconds": 3601},
        {"worker_replica_count": True},
    ],
)
def test_incomplete_baseline_or_unqualified_load_and_failover_are_not_admitted(tmp_path, change):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["load"].update(change)
    wrapper["acceptance"]["metrics"].update(change)
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "blocked"


def test_summary_metrics_cannot_hide_a_slower_observed_revocation(tmp_path):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"][0]["session_denied_at"] = "2026-11-01T08:09:59Z"
    _write(tmp_path, wrapper, observation)
    report = _validate(tmp_path, policy)
    assert any("metrics do not match" in item for item in report["violations"])


def test_observation_bytes_and_actual_image_are_transitively_bound(tmp_path):
    policy, wrapper, _observation = _fixture(tmp_path)
    path = tmp_path / wrapper["observations"]["path"]
    path.write_bytes(path.read_bytes().replace(b'"load_seconds":900', b'"load_seconds":901'))
    assert _validate(tmp_path, policy)["status"] == "fail"
    image = tmp_path / "saas/acceptance/p0-production-image-evidence.json"
    image.unlink()
    report = _validate(tmp_path, policy)
    assert any("immutable release image" in item for item in report["blockers"])


def test_observation_path_cannot_escape_through_parent_or_symlink(tmp_path):
    policy, wrapper, _observation = _fixture(tmp_path)
    wrapper["observations"]["path"] = EVIDENCE_DIRECTORY + "/observations/../acceptance.json"
    (tmp_path / EVIDENCE_DIRECTORY / "acceptance.json").write_bytes(_canonical(wrapper))
    assert _validate(tmp_path, policy)["status"] == "fail"
    wrapper["observations"]["path"] = EVIDENCE_DIRECTORY + "/observations/linked.json"
    (tmp_path / wrapper["observations"]["path"]).symlink_to(
        tmp_path / EVIDENCE_DIRECTORY / "observations/live.json"
    )
    (tmp_path / EVIDENCE_DIRECTORY / "acceptance.json").write_bytes(_canonical(wrapper))
    assert _validate(tmp_path, policy)["status"] == "fail"


def test_policy_cannot_waive_five_minutes_or_enable_a_channel_without_its_real_callback(tmp_path):
    policy, _wrapper, _observation = _fixture(tmp_path)
    policy["identity_contract"]["maximum_convergence_milliseconds"] = 600000
    assert _validate(tmp_path, policy)["status"] == "fail"
    policy["identity_contract"]["maximum_convergence_milliseconds"] = 300000
    policy["identity_contract"]["enabled_channels"].append("github")
    assert _validate(tmp_path, policy)["status"] == "fail"


def test_current_release_cannot_remove_sms_registration_from_its_policy(tmp_path):
    policy, _wrapper, _observation = _fixture(tmp_path)
    policy["identity_contract"]["enabled_channels"] = ["email_password"]
    policy["required_integrations"].pop("channel_sms_password")
    assert _validate(tmp_path, policy)["status"] == "fail"


@pytest.mark.parametrize(
    "check",
    [
        "actual_sms_delivery_and_signup",
        "missing_wrong_expired_and_replayed_code_rejected",
        "resend_attempt_and_spend_limits",
        "phone_verification_fact_not_inferred_from_number",
        "phone_change_and_number_reuse_do_not_take_over_accounts",
        "phone_only_workspace_first_run",
    ],
)
def test_sms_policy_cannot_replace_delivery_phone_proof_or_product_acceptance(tmp_path, check):
    policy, _wrapper, _observation = _fixture(tmp_path)
    policy["required_integrations"]["channel_sms_password"].remove(check)
    assert _validate(tmp_path, policy)["status"] == "fail"


def test_signed_wrapper_alone_does_not_admit_tampered_transitive_observations(tmp_path):
    policy, wrapper, _observation = _fixture(tmp_path)
    admission_policy, key = _admission_fixture(tmp_path)
    identity_source = next(
        row for row in admission_policy["evidence_sources"] if row["kind"] == "identity"
    )
    identity_source["directory"] = EVIDENCE_DIRECTORY
    key_file = tmp_path / admission_policy["trusted_key_registry"]
    registry = json.loads(key_file.read_bytes())
    registry["keys"][0].update(not_before="2026-10-01T00:00:00Z", not_after="2026-12-01T00:00:00Z")
    key_file.write_bytes(_canonical(registry))
    for path in (tmp_path / "admission/receipts").glob("*.json"):
        receipt = json.loads(path.read_bytes())
        receipt.update(issued_at="2026-11-01T10:00:00Z", expires_at="2026-11-02T10:00:00Z")
        if receipt["evidence_kind"] == "identity":
            receipt["evidence_path"] = EVIDENCE_DIRECTORY + "/acceptance.json"
            receipt["evidence_sha256"] = _hash_bytes(
                (tmp_path / receipt["evidence_path"]).read_bytes()
            )
        receipt["signature"] = base64.b64encode(
            key.sign(admission_signature_payload(receipt))
        ).decode()
        path.write_bytes(_canonical(receipt))
    report = validate_evidence_admission(
        tmp_path, admission_policy, expected_product_revision=_REVISION, now=_NOW
    )
    assert report["kinds"]["identity"]["production_readiness"] == "ready", report
    assert _validate(tmp_path, policy)["production_readiness"] == "ready"
    observation_file = tmp_path / wrapper["observations"]["path"]
    observation_file.write_bytes(
        observation_file.read_bytes().replace(b'"load_seconds":900', b'"load_seconds":901')
    )
    assert (
        validate_evidence_admission(
            tmp_path, admission_policy, expected_product_revision=_REVISION, now=_NOW
        )["kinds"]["identity"]["production_readiness"]
        == "ready"
    )
    assert _validate(tmp_path, policy)["status"] == "fail"


@pytest.mark.parametrize("value", [None, ["not-a-hash"], "not-a-list"])
def test_invalid_subject_inventory_is_rejected_without_a_validator_crash(tmp_path, value):
    policy, wrapper, observation = _fixture(tmp_path)
    wrapper["acceptance"]["subject_hashes"] = value
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["status"] == "fail"


def test_cli_requires_actual_ready_evidence_and_an_exact_candidate(capsys):
    assert identity_main(["--product-revision", _REVISION, "--require-ready"]) == 1
    assert json.loads(capsys.readouterr().out)["production_readiness"] == "blocked"
    assert identity_main(["--product-revision", "short"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "fail"


def test_five_minute_boundary_is_measured_and_one_millisecond_over_is_rejected(tmp_path):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"][0]["session_denied_at"] = "2026-11-01T08:10:00Z"
    wrapper["acceptance"]["metrics"]["maximum_password_reset_milliseconds"] = 300000
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["production_readiness"] == "ready"
    observation["samples"][0]["session_denied_at"] = "2026-11-01T08:10:00.001Z"
    wrapper["acceptance"]["metrics"]["maximum_password_reset_milliseconds"] = 300001
    _write(tmp_path, wrapper, observation)
    assert any("five-minute" in item for item in _validate(tmp_path, policy)["violations"])


def test_periodic_cases_cannot_sneak_in_a_replayed_notification(tmp_path):
    policy, wrapper, observation = _fixture(tmp_path)
    row = next(row for row in observation["samples"] if row["case"] == "missed_password_reset")
    row["provider_event_sha256"] = _hash("replayed-notification")
    _write(tmp_path, wrapper, observation)
    assert any(
        "without notification" in item for item in _validate(tmp_path, policy)["violations"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("triggered_at", "2026-11-01Z"),
        ("triggered_at", "2026-11-01T08:05:00"),
        ("password", "must-not-appear-in-an-observation"),
    ],
)
def test_samples_reject_ambiguous_times_and_unreviewed_secret_fields(tmp_path, field, value):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"][0][field] = value
    _write(tmp_path, wrapper, observation)
    assert _validate(tmp_path, policy)["status"] == "fail"


def test_independent_subject_and_session_coverage_cannot_be_inflated(tmp_path):
    policy, wrapper, observation = _fixture(tmp_path)
    observation["samples"][1]["subject_sha256"] = observation["samples"][0]["subject_sha256"]
    observation["samples"][2]["session_sha256"] = observation["samples"][0]["session_sha256"]
    _write(tmp_path, wrapper, observation)
    report = _validate(tmp_path, policy)
    assert any("independent subjects" in item for item in report["violations"])
    assert any("independent signed OIDC sessions" in item for item in report["violations"])


@pytest.mark.parametrize("variant", ["v1", "v2", "v99"])
def test_image_binding_preserves_reviewed_legacy_envelopes_without_admitting_their_stack(
    tmp_path, variant
):
    policy, wrapper, observation = _fixture(tmp_path)
    path = tmp_path / "saas/acceptance/p0-production-image-evidence.json"
    envelope = {
        "kind": "production_release_with_legacy_fallback/" + variant,
        "product_revision": _REVISION,
        "release_evidence": json.loads(path.read_bytes()),
        "legacy_fallback": {},
    }
    path.write_bytes(_canonical(envelope))
    observation["pins"]["image_evidence_sha256"] = _hash_bytes(path.read_bytes())
    _write(tmp_path, wrapper, observation)
    report = _validate(tmp_path, policy)
    # Stack provenance remains an independent requirement of the aggregate image gate.
    assert report["production_readiness"] == ("blocked" if variant == "v99" else "ready")
