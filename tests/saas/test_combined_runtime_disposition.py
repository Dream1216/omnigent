"""Unchanged raw-two-High composition with an explicitly trusted verifier seam."""

import copy
import hashlib
import json
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path

import pytest

from saas.scripts import combined_runtime_disposition as combined
from saas.scripts import sqlite_component_disposition as sqlite
from tests.saas.test_sqlite_component_disposition import NOW, candidate

LIBC = b"\x7fELFsynthetic-libc-fixture"


def combination(tmp_path, monkeypatch, *, extra=None, database_time=NOW):
    image, path, report = candidate(
        tmp_path,
        monkeypatch,
        extra={"usr/lib/libc.so.6": LIBC, **(extra or {})},
        config_os="linux",
        database_time=database_time,
    )
    monkeypatch.setattr(combined, "runtime_rule_enabled", lambda: True)
    monkeypatch.setitem(
        combined.RUNTIME_RULE,
        "libc_sha256",
        {"linux/amd64": hashlib.sha256(LIBC).hexdigest()},
    )
    glibc = copy.deepcopy(report["matches"][0])
    glibc["vulnerability"]["id"] = "CVE-2026-84243"
    glibc["artifact"].update(name="glibc-2.44", version="2.44-r8")
    report["matches"].append(glibc)
    path.write_text(json.dumps(report) + "\n")
    target = report["source"]["target"]
    subject = combined.RuntimeSubject(
        source_revision="a" * 40,
        platform="linux/amd64",
        manifest_digest=target["manifestDigest"],
        config_digest=target["imageID"],
        libc_sha256=hashlib.sha256(LIBC).hexdigest(),
        report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    # This fixture models a protected producer that has already verified the
    # condition, not candidate JSON or a production implementation of intake.
    approved = combined.VerifiedRuntimeCondition(
        subject=subject,
        role_contract_sha256="1" * 64,
        native_evidence_sha256="2" * 64,
        independent_review_sha256="3" * 64,
        authority_reference_sha256="4" * 64,
        runtime_graph_sha256="5" * 64,
        expires_at=NOW + timedelta(hours=2),
    )
    return image, path, report, approved


def inspect(image, path, approved, **overrides):
    def verified(subject, *, now):
        assert subject == approved.subject
        return approved

    return combined.inspect_combined_disposition(
        image,
        path,
        **{
            "platform": "linux/amd64",
            "now": NOW,
            "scanner_exit": 2,
            "verify_runtime": verified,
            **overrides,
        },
    )


def test_actual_oci_two_findings_and_original_bytes_are_composed_without_filtering(
    tmp_path, monkeypatch
):
    image, path, report, approved = combination(tmp_path, monkeypatch)
    original = path.read_bytes()
    assert sqlite.eligible_match(report, now=NOW) is False
    with pytest.raises(ValueError, match="do not qualify"):
        sqlite.inspect_disposition(image, path, platform="linux/amd64", now=NOW)
    proof = inspect(image, path, approved)
    assert proof["raw_high"] == 2 and proof["raw_critical"] == 0
    assert proof["scanner_exit"] == 2
    assert proof["report_sha256"] == approved.subject.report_sha256
    assert proof["runtime_condition"]["subject"] == asdict(approved.subject)
    assert len(proof["inventory"]) == 2
    assert path.read_bytes() == original
    assert (
        combined.validate_combined_disposition(
            image,
            path,
            proof,
            platform="linux/amd64",
            now=NOW,
            scanner_exit=2,
            verify_runtime=lambda subject, *, now: approved,
        )
        == proof
    )


@pytest.mark.parametrize(
    "fault",
    [
        "third-high",
        "critical",
        "duplicate",
        "version",
        "package",
        "matcher",
        "namespace",
        "ignored",
        "exclude",
        "vex",
        "filtered",
        "stale-db",
        "target",
        "libc",
    ],
)
def test_unknown_or_changed_raw_component_or_subject_never_reaches_native_acceptance(
    tmp_path, monkeypatch, fault
):
    image, path, report, approved = combination(tmp_path, monkeypatch)
    match = report["matches"][1]
    if fault == "third-high":
        report["matches"].append(copy.deepcopy(match))
    elif fault == "critical":
        match["vulnerability"]["severity"] = "Critical"
    elif fault == "duplicate":
        report["matches"][1] = copy.deepcopy(report["matches"][0])
    elif fault == "version":
        match["artifact"]["version"] = "2.44-r13"
    elif fault == "package":
        match["artifact"]["name"] = "glibc"
    elif fault == "matcher":
        match["matchDetails"][0]["matcher"] = "untrusted"
    elif fault == "namespace":
        match["vulnerability"]["namespace"] = "other"
    elif fault == "ignored":
        report["ignoredMatches"] = [copy.deepcopy(match)]
    elif fault in {"exclude", "vex", "filtered"}:
        field, value = {
            "exclude": ("exclude", ["**"]),
            "vex": ("vex-documents", ["fake.json"]),
            "filtered": ("only-fixed", True),
        }[fault]
        report["descriptor"]["configuration"][field] = value
    elif fault == "stale-db":
        report["descriptor"]["db"]["status"]["built"] = (NOW - timedelta(hours=25)).isoformat()
    elif fault == "target":
        report["source"]["target"]["manifestDigest"] = "sha256:" + "f" * 64
    elif fault == "libc":
        monkeypatch.setitem(combined.RUNTIME_RULE["libc_sha256"], "linux/amd64", "0" * 64)
    path.write_text(json.dumps(report) + "\n")

    def no_native_call(subject, *, now):
        pytest.fail("invalid raw/OCI must be rejected before trusting runtime conditions")

    with pytest.raises(ValueError):
        inspect(image, path, approved, verify_runtime=no_native_call)


@pytest.mark.parametrize("field", list(combined.RuntimeSubject.__dataclass_fields__))
def test_old_or_other_native_subject_cannot_be_transferred(tmp_path, monkeypatch, field):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    wrong = replace(approved, subject=replace(approved.subject, **{field: "different"}))
    with pytest.raises(ValueError, match="different exact subject"):
        inspect(image, path, approved, verify_runtime=lambda subject, *, now: wrong)


@pytest.mark.parametrize(
    "field",
    [
        "role_contract_sha256",
        "native_evidence_sha256",
        "independent_review_sha256",
        "authority_reference_sha256",
        "runtime_graph_sha256",
    ],
)
def test_unidentified_protected_input_is_rejected(tmp_path, monkeypatch, field):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    invalid = replace(approved, **{field: ""})
    with pytest.raises(ValueError, match="authenticated input identity"):
        inspect(image, path, approved, verify_runtime=lambda subject, *, now: invalid)


@pytest.mark.parametrize("expiry", [NOW, NOW.replace(tzinfo=None), NOW + timedelta(days=8)])
def test_expired_naive_or_overlong_conditions_are_rejected(tmp_path, monkeypatch, expiry):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    invalid = replace(approved, expires_at=expiry)
    with pytest.raises(ValueError, match="expired or extends"):
        inspect(image, path, approved, verify_runtime=lambda subject, *, now: invalid)


def test_no_native_verifier_or_approval_cannot_enable_the_path(tmp_path, monkeypatch):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="signed evidence admission"):
        inspect(image, path, approved, verify_runtime=None)
    monkeypatch.setattr(combined, "runtime_rule_enabled", lambda: False)
    with pytest.raises(ValueError, match="unavailable"):
        inspect(image, path, approved)


@pytest.mark.parametrize("scanner_exit", [0, 1, True])
def test_original_high_scanner_exit_cannot_be_inferred_or_rewritten(
    tmp_path, monkeypatch, scanner_exit
):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="unavailable"):
        inspect(image, path, approved, scanner_exit=scanner_exit)


def test_sqlite_shell_still_blocks_the_combination(tmp_path, monkeypatch):
    image, path, _, approved = combination(
        tmp_path, monkeypatch, extra={"usr/bin/sqlite3": b"\x7fELF.recover sqlite> "}
    )
    with pytest.raises(ValueError, match="shell or recovery"):
        inspect(image, path, approved)


def test_candidate_json_is_not_a_verified_runtime_condition(tmp_path, monkeypatch):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="different exact subject"):
        inspect(image, path, approved, verify_runtime=lambda subject, *, now: {"mitigated": True})


@pytest.mark.parametrize("fault", ["raw-critical-False", "inventory-False-as-zero"])
def test_noncanonical_boolean_integer_proof_cannot_compare_equal(tmp_path, monkeypatch, fault):
    image, path, _, approved = combination(tmp_path, monkeypatch)
    proof = inspect(image, path, approved)
    if fault == "raw-critical-False":
        proof["raw_critical"] = False
    else:
        assert proof["inventory"][0]["shell"] is False
        proof["inventory"][0]["shell"] = 0
    with pytest.raises(ValueError, match="finite combination"):
        combined.validate_combined_disposition(
            image,
            path,
            proof,
            platform="linux/amd64",
            now=NOW,
            scanner_exit=2,
            verify_runtime=lambda subject, *, now: approved,
        )


def test_actual_repository_policy_keeps_signed_full_role_approval_required():
    from saas.scripts.runtime_evidence_intake import REGISTRY, prepare_runtime_graph

    root = Path(__file__).resolve().parents[2]
    policy = json.loads((root / "saas/supply_chain/release-policy.json").read_text())
    assert combined.runtime_rule_enabled() is True
    assert policy["vulnerability_policy"]["runtime_mitigation"] == combined.RUNTIME_RULE
    assert policy["vulnerability_policy"]["critical_allowed"] == 0
    assert policy["vulnerability_policy"]["high_allowed"] == 0
    assert json.loads((root / REGISTRY).read_text())["approved_scopes"] == []
    with pytest.raises(ValueError, match="no approved full-role contract"):
        prepare_runtime_graph(root, product_revision="a" * 40)
