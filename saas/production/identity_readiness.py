"""Validate release-bound identity acceptance and its measured live convergence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from saas.production.business import validate_business_readiness

EVIDENCE_DIRECTORY = "saas/production/identity-evidence"
_OBSERVATION_DIRECTORY = EVIDENCE_DIRECTORY + "/observations/"
_MAX_BYTES = 16 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")
_CASES = {
    "password_reset",
    "provider_disable",
    "provider_delete",
    "verified_contact_change",
    "missed_password_reset",
    "missed_provider_disable",
    "missed_provider_delete",
    "worker_restart",
}
_PERIODIC = {"missed_password_reset", "missed_provider_disable", "missed_provider_delete"}
_CHANNELS = {
    "email_password",
    "sms_password",
    "wechat",
    "dingtalk",
    "lark",
    "github",
    "google",
    "enterprise_oidc",
    "enterprise_saml",
}
_SMS_CHECKS = {
    "application_ownership_and_permissions",
    "actual_sms_delivery_and_signup",
    "missing_wrong_expired_and_replayed_code_rejected",
    "resend_attempt_and_spend_limits",
    "canonical_phone_country_and_duplicate_policy",
    "phone_verification_fact_not_inferred_from_number",
    "stable_issuer_subject_and_explicit_linking",
    "phone_change_and_number_reuse_do_not_take_over_accounts",
    "phone_only_workspace_first_run",
    "customer_claims_do_not_expand_product_authority",
}
_PINS = {
    "image_evidence_sha256",
    "identity_manifest_sha256",
    "public_config_sha256",
    "migration_receipt_sha256",
    "service_role_graph_sha256",
    "provider_configuration_sha256",
}
_SAMPLE_FIELDS = {
    "case",
    "subject_sha256",
    "global_user_before_sha256",
    "global_user_after_sha256",
    "session_sha256",
    "oidc_verification_sha256",
    "provider_event_sha256",
    "triggered_at",
    "inbox_committed_at",
    "readback_completed_at",
    "session_denied_at",
    "transport",
    "security_version_before",
    "security_version_after",
    "session_valid_before",
    "session_valid_after",
    "credential_owner_before",
    "credential_owner_after",
    "tenant_grant_delta",
}


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )


def _pairs(rows):
    result = {}
    for name, value in rows:
        if name in result:
            raise ValueError("identity evidence contains duplicate JSON keys")
        result[name] = value
    return result


def _read(repo: Path, relative: str, *, canonical: bool = True) -> tuple[bytes, dict]:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or str(path) != relative:
        raise ValueError("identity evidence path is unsafe")
    current = repo
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("identity evidence cannot traverse symbolic links")
    metadata = current.stat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_BYTES:
        raise ValueError("identity evidence file is not a bounded regular file")
    raw = current.read_bytes()
    if len(raw) > _MAX_BYTES:
        raise ValueError("identity evidence file exceeds its byte budget")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _value: None)
    if not isinstance(value, dict) or (canonical and raw != _canonical(value)):
        raise ValueError("identity evidence must contain canonical object JSON")
    return raw, value


def load_identity_evidence(repo: Path, policy: Mapping[str, Any]) -> list[dict]:
    if policy.get("evidence_directory") != EVIDENCE_DIRECTORY:
        raise ValueError("identity evidence directory must match the packaged contract")
    directory = repo / EVIDENCE_DIRECTORY
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("identity evidence directory is unavailable")
    return [
        _read(repo, path.relative_to(repo).as_posix())[1]
        for path in sorted(directory.glob("*.json"))
    ]


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None and value != "0" * 64


def _time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _contract(repo: Path, policy: Mapping[str, Any]) -> tuple[dict, list[str]]:
    contract = policy.get("identity_contract")
    fields = {
        "provider_source_lock_sha256",
        "maximum_convergence_milliseconds",
        "minimum_worker_replicas",
        "minimum_subjects_per_case",
        "minimum_load_seconds",
        "enabled_channels",
    }
    if not isinstance(contract, dict) or set(contract) != fields:
        return {}, ["identity policy contract fields are invalid"]
    violations = []
    if (
        type(policy.get("schema_version")) is not int
        or policy.get("schema_version") != 1
        or policy.get("policy_id") != "omnigent-casdoor-identity-readiness-v1"
        or policy.get("evidence_kind") != "production_casdoor_identity_acceptance"
        or policy.get("evidence_directory") != EVIDENCE_DIRECTORY
    ):
        violations.append("identity policy does not match its packaged acceptance profile")
    expected = hashlib.sha256(
        (repo / "saas/production/casdoor/source-lock.json").read_bytes()
    ).hexdigest()
    if contract["provider_source_lock_sha256"] != expected:
        violations.append("identity policy does not match the packaged provider source lock")
    for name, value in (
        ("maximum_convergence_milliseconds", 300000),
        ("minimum_worker_replicas", 2),
        ("minimum_subjects_per_case", 2),
        ("minimum_load_seconds", 900),
    ):
        if type(contract[name]) is not int or contract[name] != value:
            violations.append(
                "identity policy operation budgets differ from the reviewed contract"
            )
    channels = contract["enabled_channels"]
    if (
        not isinstance(channels, list)
        or any(not isinstance(value, str) for value in channels)
        or len(set(channels)) != len(channels)
        or not {"email_password", "sms_password"} <= set(channels)
        or not set(channels) <= _CHANNELS
    ):
        violations.append("identity policy channel inventory is invalid")
    else:
        integrations = policy.get("required_integrations", {})
        for name in channels:
            if name == "email_password":
                continue
            required = (
                _SMS_CHECKS
                if name == "sms_password"
                else {
                    "application_ownership_and_permissions",
                    "actual_two_layer_callback",
                    "stable_subject_and_verified_email_contract",
                    "explicit_binding_no_email_merge",
                    "customer_claims_do_not_expand_product_authority",
                }
            )
            if name.startswith("enterprise_"):
                required |= {
                    "explicit_source_to_tenant_mapping",
                    "approved_jit_or_invitation",
                    "single_directory_membership_authority",
                    "directory_exit_no_cross_tenant_grants",
                }
            checks = (
                integrations.get("channel_" + name) if isinstance(integrations, dict) else None
            )
            if (
                not isinstance(checks, list)
                or any(not isinstance(value, str) for value in checks)
                or not required <= set(checks)
            ):
                violations.append(
                    "each enabled identity channel requires its own live integration checks"
                )
    return contract, violations


def _samples(observation: dict, acceptance: dict, contract: dict) -> tuple[dict, list[str]]:
    samples = observation.get("samples")
    if not isinstance(samples, list) or not 1 <= len(samples) <= 100000:
        return {}, ["identity observations require bounded convergence samples"]
    started, completed = _time(acceptance.get("started_at")), _time(acceptance.get("completed_at"))
    if started is None or completed is None:
        return {}, ["identity acceptance measurement window is invalid"]
    maximums = dict.fromkeys(_CASES, 0)
    subjects = {case: set() for case in _CASES}
    seen = set()
    sessions = set()
    violations = []
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != _SAMPLE_FIELDS:
            violations.append("identity sample fields do not match the closed schema")
            continue
        case = sample["case"]
        if not isinstance(case, str) or case not in _CASES:
            violations.append("identity convergence case is not reviewed")
            continue
        if any(
            not _sha(sample[name])
            for name in (
                "subject_sha256",
                "global_user_before_sha256",
                "global_user_after_sha256",
                "session_sha256",
                "oidc_verification_sha256",
            )
        ):
            violations.append(
                "identity samples must use nonempty hashed stable identities and OIDC proofs"
            )
            continue
        key = (case, sample["subject_sha256"], sample["session_sha256"])
        if key in seen:
            violations.append("identity convergence samples must be unique")
        seen.add(key)
        if sample["session_sha256"] in sessions:
            violations.append("identity convergence requires independent signed OIDC sessions")
        sessions.add(sample["session_sha256"])
        inventory = acceptance.get("subject_hashes")
        if not isinstance(inventory, list) or sample["subject_sha256"] not in inventory:
            violations.append("identity convergence subject is not in the acceptance inventory")
        if (
            sample["global_user_before_sha256"] != sample["global_user_after_sha256"]
            or sample["session_valid_before"] is not True
            or sample["session_valid_after"] is not False
            or sample["credential_owner_before"] != "casdoor"
            or sample["credential_owner_after"] != "casdoor"
            or type(sample["tenant_grant_delta"]) is not int
            or sample["tenant_grant_delta"] != 0
            or not _positive(sample["security_version_before"])
            or not _positive(sample["security_version_after"])
            or sample["security_version_after"] <= sample["security_version_before"]
        ):
            violations.append(
                "identity sample changed product authority or did not invalidate its real session"
            )
        trigger, read, denied = (
            _time(sample[name])
            for name in ("triggered_at", "readback_completed_at", "session_denied_at")
        )
        if (
            trigger is None
            or read is None
            or denied is None
            or not started <= trigger <= read <= denied <= completed
        ):
            violations.append("identity convergence timestamps are invalid or out of order")
            continue
        if case in _PERIODIC:
            if (
                sample["transport"] != "periodic_without_notification"
                or sample["provider_event_sha256"] is not None
                or sample["inbox_committed_at"] is not None
            ):
                violations.append(
                    "missed-event samples must prove periodic recovery without notification"
                )
        else:
            inbox = _time(sample["inbox_committed_at"])
            if (
                sample["transport"] != "direct_authenticated_https"
                or not _sha(sample["provider_event_sha256"])
                or inbox is None
                or not trigger <= inbox <= read
            ):
                violations.append(
                    "direct samples require authenticated HTTPS delivery and durable Inbox commit"
                )
        elapsed = math.ceil((denied - trigger).total_seconds() * 1000)
        maximums[case] = max(maximums[case], elapsed)
        if not 0 < elapsed <= contract["maximum_convergence_milliseconds"]:
            violations.append("identity convergence exceeds the five-minute release bound")
        subjects[case].add(sample["subject_sha256"])
    if any(len(values) < contract["minimum_subjects_per_case"] for values in subjects.values()):
        violations.append(
            "identity convergence does not cover every required case with independent subjects"
        )
    return {
        **{"maximum_" + case + "_milliseconds": value for case, value in maximums.items()},
        "convergence_sample_count": len(samples),
    }, violations


def _observation(
    repo: Path, wrapper: dict, acceptance: dict, contract: dict
) -> tuple[list[str], list[str]]:
    violations, blockers = [], []
    ref = wrapper.get("observations")
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not _sha(ref.get("sha256")):
        return ["identity observation reference is invalid"], []
    if not isinstance(ref["path"], str) or not ref["path"].startswith(_OBSERVATION_DIRECTORY):
        return ["identity observation path must be inside the fixed observation directory"], []
    try:
        raw, observation = _read(repo, ref["path"])
    except (OSError, ValueError):
        return ["identity observation file is unavailable or invalid"], []
    artifact = acceptance.get("artifact", {})
    if (
        hashlib.sha256(raw).hexdigest() != ref["sha256"]
        or not isinstance(artifact, dict)
        or artifact.get("sha256") != ref["sha256"]
    ):
        violations.append("identity observation bytes do not match the signed acceptance artifact")
    fields = {
        "schema_version",
        "environment",
        "product_revision",
        "image_digest",
        "provider_source_lock_sha256",
        "pins",
        "provenance",
        "load",
        "enabled_channels",
        "samples",
    }
    if set(observation) != fields:
        return [*violations, "identity observation fields do not match the closed schema"], []
    if (
        type(observation["schema_version"]) is not int
        or observation["schema_version"] != 1
        or observation["environment"] != "production"
        or observation["product_revision"] != acceptance.get("product_revision")
        or observation["provider_source_lock_sha256"] != contract["provider_source_lock_sha256"]
        or observation["enabled_channels"] != contract["enabled_channels"]
    ):
        violations.append(
            "identity observations differ from the admitted release, source or channel inventory"
        )
    pins = observation["pins"]
    if (
        not isinstance(pins, dict)
        or set(pins) != _PINS
        or any(not _sha(value) for value in pins.values())
    ):
        violations.append("identity deployment, configuration and authority pins are incomplete")
    else:
        try:
            raw_image, image = _read(
                repo, "saas/acceptance/p0-production-image-evidence.json", canonical=False
            )
            if image.get("kind") is not None:
                if (
                    image.get("kind")
                    not in {
                        "production_release_with_legacy_fallback/v1",
                        "production_release_with_legacy_fallback/v2",
                    }
                    or image.get("product_revision") != observation["product_revision"]
                    or not isinstance(image.get("release_evidence"), dict)
                ):
                    raise ValueError("identity image envelope is not a reviewed release format")
                image = image["release_evidence"]
            rows = image.get("images", [])
            servers = [
                row
                for row in rows
                if isinstance(row, dict) and row.get("name") == "omnigent-saas-server"
            ]
            if (
                hashlib.sha256(raw_image).hexdigest() != pins["image_evidence_sha256"]
                or len(servers) != 1
                or servers[0].get("manifest_digest") != observation["image_digest"]
                or image.get("product_revision") != observation["product_revision"]
            ):
                violations.append("identity process image is not the exact release image evidence")
        except FileNotFoundError:
            blockers.append(
                "identity acceptance requires the exact immutable release image evidence"
            )
        except (OSError, ValueError, TypeError):
            violations.append("identity release image evidence cannot be verified")
    if (
        not isinstance(observation["image_digest"], str)
        or not observation["image_digest"].startswith("sha256:")
        or not _sha(observation["image_digest"][7:])
    ):
        violations.append("identity image digest is invalid")
    if observation["provenance"] != {
        "live_provider": True,
        "installed_metadata_override": False,
        "private_ingress_direct_tls": True,
        "provider_ca_and_hostname_verified": True,
        "signed_oidc_sessions": True,
    } or any(
        type(value) is not bool
        for value in (
            observation["provenance"].values()
            if isinstance(observation["provenance"], dict)
            else []
        )
    ):
        violations.append(
            "identity observations require live TLS and signed OIDC without fixture metadata"
        )
    load = observation["load"]
    load_fields = {
        "admitted_identity_population",
        "baseline_verified_identity_count",
        "worker_replica_count",
        "load_seconds",
    }
    if (
        not isinstance(load, dict)
        or set(load) != load_fields
        or any(not _positive(value) for value in load.values())
    ):
        violations.append("identity load observations are invalid")
    elif (
        load["baseline_verified_identity_count"] != load["admitted_identity_population"]
        or load["admitted_identity_population"] < contract["minimum_subjects_per_case"]
        or load["worker_replica_count"] < contract["minimum_worker_replicas"]
        or load["load_seconds"] < contract["minimum_load_seconds"]
    ):
        blockers.append(
            "identity baseline, replica coverage or admitted-load duration is insufficient"
        )
    started, completed = _time(acceptance.get("started_at")), _time(acceptance.get("completed_at"))
    if (
        isinstance(load, dict)
        and _positive(load.get("load_seconds"))
        and started
        and completed
        and load["load_seconds"] > (completed - started).total_seconds()
    ):
        violations.append("identity load duration exceeds its evidence window")
    measured, sample_violations = _samples(observation, acceptance, contract)
    violations.extend(sample_violations)
    metrics = acceptance.get("metrics")
    expected = measured | (load if isinstance(load, dict) else {})
    if not isinstance(metrics, dict) or any(
        type(metrics.get(name)) is not int or metrics[name] != value
        for name, value in expected.items()
    ):
        violations.append("identity acceptance metrics do not match their measured observations")
    return violations, blockers


def validate_identity_readiness(
    repo: Path,
    policy: Mapping[str, Any],
    records: list[dict],
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
    baseline: Mapping[str, Any] | None = None,
) -> dict:
    current = now or datetime.now(UTC)
    contract, violations = _contract(repo, policy)
    valid_contract = not violations
    if expected_product_revision is not None and (
        not isinstance(expected_product_revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_product_revision) is None
    ):
        violations.append("identity release candidate must be a full Git SHA")
    blockers, acceptances = [], []
    for wrapper in records:
        if (
            set(wrapper) != {"schema_version", "acceptance", "observations"}
            or type(wrapper["schema_version"]) is not int
            or wrapper["schema_version"] != 1
            or not isinstance(wrapper["acceptance"], dict)
        ):
            violations.append("identity evidence wrapper fields are invalid")
            continue
        acceptance = wrapper["acceptance"]
        acceptances.append(acceptance)
        if valid_contract:
            errors, pending = _observation(repo, wrapper, acceptance, contract)
            violations.extend(errors)
            blockers.extend(pending)
    report = validate_business_readiness(
        repo,
        policy,
        acceptances,
        now=current,
        expected_product_revision=expected_product_revision,
        baseline=baseline,
    )
    violations.extend(report["violations"])
    blockers.extend(report["blockers"])
    if expected_product_revision is None:
        blockers.append("identity acceptance requires an exact release candidate revision")
    report.update(
        status="fail" if violations else "pass",
        production_readiness="ready" if not violations and not blockers else "blocked",
        violations=sorted(set(violations)),
        blockers=sorted(set(blockers)),
    )
    report["metrics"]["qualified_record_count"] = (
        len(records) if not violations and not blockers else 0
    )
    return report
