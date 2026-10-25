from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from saas.production import review_exception as review
from saas.production.readiness import _evidence_only_path, validate_candidate_revision

_NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args], text=True
    ).strip()


def _fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Any], dict[str, Any], str, list[str]]:
    origin = Path(__file__).resolve().parents[2]
    for relative in (review.POLICY_PATH, "saas/production/baseline.json"):
        output = tmp_path / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin / relative, output)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "fixture@example.test")
    _git(tmp_path, "config", "user.name", "Fixture")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "candidate")
    product = _git(tmp_path, "rev-parse", "HEAD")
    run = {
        "id": 731,
        "repository": {"full_name": "Dream1216/omnigent"},
        "head_repository": {"full_name": "Dream1216/omnigent"},
        "event": "workflow_dispatch",
        "head_branch": "main",
        "path": ".github/workflows/saas-production-admission.yml",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "head_sha": product,
        "updated_at": "2026-10-21T08:00:00Z",
    }
    approvals = [
        {
            "state": "approved",
            "user": {"login": "Dream1216", "id": 39821512, "type": "User"},
            "environments": [{"name": "production-evidence"}],
        }
    ]
    policy = json.loads((tmp_path / review.POLICY_PATH).read_text())
    commitment = hashlib.sha256(b"fixture-real-single-owner").hexdigest()
    manifest = {
        "schema_version": 1,
        "release_id": review.RELEASE_ID,
        "mode": review.MODE,
        "product_revision": product,
        "evidence_revision": product,
        "attestor_commitment": commitment,
        "expires_at": "2026-12-01T00:00:00Z",
        "revision_contract": policy["revision_contract"],
        "authorization_reference_sha256": policy["authorization_reference_sha256"],
        "workflow_identity": review.WORKFLOW_IDENTITY,
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "review-exception-authorization.json", review.canonical_review_record(manifest)
        )
    archive_bytes = stream.getvalue()
    artifact = {
        "id": 91,
        "name": "production-review-authorization-" + product,
        "expired": False,
        "workflow_run": {"id": 731, "head_sha": product},
        "size_in_bytes": len(archive_bytes),
        "digest": "sha256:" + hashlib.sha256(archive_bytes).hexdigest(),
    }
    fetched: list[str] = []

    def github(path: str) -> object:
        fetched.append(path)
        if path == "repos/Dream1216/omnigent":
            return {
                "owner": {"login": "Dream1216", "id": 39821512, "type": "User"},
                "default_branch": "main",
            }
        if path.endswith("/approvals"):
            return approvals
        if "/artifacts?" in path:
            return {"total_count": 1, "artifacts": [artifact]}
        return run

    monkeypatch.setattr(review, "_github_json", github)
    monkeypatch.setattr(review, "_github_artifact_zip", lambda artifact_id: archive_bytes)
    facts = review.native_review_facts(731)
    record = {
        "schema_version": 1,
        "release_id": review.RELEASE_ID,
        "mode": review.MODE,
        "governance_classification": "degraded",
        "product_revision": product,
        "evidence_revision": product,
        "revision_contract": policy["revision_contract"],
        "authorized_login": "Dream1216",
        "authorized_github_user_id": 39821512,
        "attestor_commitment": hashlib.sha256(b"fixture-real-single-owner").hexdigest(),
        "issued_at": "2026-10-21T09:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "authorization_reference_sha256": policy["authorization_reference_sha256"],
        "domains": sorted(policy["domain_roles"]),
        "native_approval": {key: value for key, value in facts.items() if key != "completed_at"},
    }
    relative = f"{review.RECORD_DIRECTORY}/{review.RELEASE_ID}-{product}.json"
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(review.canonical_review_record(record))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "append exception evidence")
    item = {
        "role": review.MODE,
        "actor_id_hash": record["attestor_commitment"],
        "attested_at": "2026-10-21T10:00:00Z",
        "product_revision": product,
        "review_exception": {
            "path": relative,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        },
    }
    fetched.clear()
    return item, record, product, fetched


@pytest.mark.parametrize(
    "domain",
    ["image", "deployment", "recovery", "slo_capacity", "deletion", "commercial", "enterprise"],
)
def test_exact_release_one_owner_is_explicit_without_fabricated_actors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, domain: str
) -> None:
    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    result = review.apply_review_exception(
        tmp_path,
        [item],
        domain=domain,
        required_roles=review._DOMAIN_ROLES[domain],
        product_revision=product,
        now=_NOW,
    )
    assert result.violations == ()
    assert result.required_roles == {review.MODE}
    assert result.attestations == [
        {key: value for key, value in item.items() if key != "review_exception"}
    ]
    assert len(result.attestations) == 1


def test_default_independent_review_path_never_reads_new_policy_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        review, "_load_policy", lambda repo: pytest.fail("default path must stay offline")
    )
    original = [{"role": "security", "actor_id_hash": "a" * 64}]
    result = review.apply_review_exception(
        None,
        original,
        domain="image",
        required_roles={"security", "site-reliability", "release-engineering"},
        product_revision="a" * 40,
        now=_NOW,
    )
    assert result.attestations is original
    assert len(result.required_roles) == 3


@pytest.mark.parametrize(
    "mutation",
    [
        "expired",
        "product",
        "commitment",
        "digest",
        "path",
        "extra_actor",
        "wrong_upstream",
        "uncommitted",
        "modified_history",
    ],
)
def test_candidate_scope_byte_history_and_actor_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    item, record, product, _ = _fixture(tmp_path, monkeypatch)
    items = [item]
    now = _NOW
    if mutation == "expired":
        now = datetime(2026, 12, 21, tzinfo=UTC)
    elif mutation == "product":
        product = "f" * 40
    elif mutation == "commitment":
        item["actor_id_hash"] = "f" * 64
    elif mutation == "digest":
        item["review_exception"]["sha256"] = "f" * 64
    elif mutation == "path":
        item["review_exception"]["path"] = (
            "saas/production/review-exception-evidence/../baseline.json"
        )
    elif mutation == "extra_actor":
        items.append(copy.deepcopy(item))
    elif mutation == "wrong_upstream":
        path = tmp_path / "saas/production/baseline.json"
        baseline = json.loads(path.read_text())
        baseline["revision_contract"]["upstream_revision"] = "f" * 40
        path.write_text(json.dumps(baseline))
    else:
        record["attestor_commitment"] = "e" * 64
        item["actor_id_hash"] = "e" * 64
        path = tmp_path / item["review_exception"]["path"]
        path.write_bytes(review.canonical_review_record(record))
        item["review_exception"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        if mutation == "modified_history":
            _git(tmp_path, "add", ".")
            _git(tmp_path, "commit", "-qm", "forbidden record amendment")
    result = review.apply_review_exception(
        tmp_path,
        items,
        domain="image",
        required_roles=review._DOMAIN_ROLES["image"],
        product_revision=product,
        now=now,
    )
    assert result.violations
    assert result.required_roles == review._DOMAIN_ROLES["image"]


def test_native_approval_is_live_not_caller_authorized_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(review, "_github_json", lambda path: {})
    result = review.apply_review_exception(
        tmp_path,
        [item],
        domain="image",
        required_roles=review._DOMAIN_ROLES["image"],
        product_revision=product,
        now=_NOW,
    )
    assert result.violations


def test_only_canonical_governed_record_is_evidence_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    relative = item["review_exception"]["path"]
    assert _evidence_only_path(relative, tmp_path)
    assert validate_candidate_revision(product, tmp_path)["production_readiness"] == "ready"
    path = tmp_path / relative
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2))
    assert not _evidence_only_path(relative, tmp_path)
    assert not _evidence_only_path(f"{review.RECORD_DIRECTORY}/policy.json", tmp_path)
    assert not _evidence_only_path(review.POLICY_PATH, tmp_path)


def test_native_facts_cached_only_within_one_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, fetched = _fixture(tmp_path, monkeypatch)

    @review.review_verification_scope
    def check() -> None:
        review.native_review_facts(731)
        review.native_review_facts(731)

    check()
    assert len(fetched) == 4
    check()
    assert len(fetched) == 8


@pytest.mark.parametrize(
    "field",
    ["product_revision", "attestor_commitment", "expires_at", "authorization_reference_sha256"],
)
def test_approval_for_another_manifest_cannot_authorize_this_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    actual = review.native_review_facts(731)
    actual[field] = (
        "2026-12-02T00:00:00Z"
        if field == "expires_at"
        else "e" * (40 if field == "product_revision" else 64)
    )
    monkeypatch.setattr(review, "native_review_facts", lambda run_id: actual)
    result = review.apply_review_exception(
        tmp_path,
        [item],
        domain="image",
        required_roles=review._DOMAIN_ROLES["image"],
        product_revision=product,
        now=_NOW,
    )
    assert result.violations


def test_downloaded_authorization_zip_digest_is_mandatory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(review, "_github_artifact_zip", lambda artifact_id: b"foreign payload")
    with pytest.raises(ValueError, match="digest or size"):
        review.native_review_facts(731)


@pytest.mark.parametrize("failure", [None, "short_window", "fairness"])
def test_single_owner_preserves_real_slo_window_and_capacity_thresholds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    import importlib.util

    from saas.production.slo_capacity import validate_slo_capacity_readiness

    spec = importlib.util.spec_from_file_location(
        "slo_fixture", Path(__file__).with_name("test_slo_capacity_readiness.py")
    )
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    delta = _NOW - fixture._NOW

    def shift(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: shift(child) for key, child in value.items()}
        if isinstance(value, list):
            return [shift(child) for child in value]
        if value == "a" * 40:
            return product
        if isinstance(value, str) and value.endswith("Z"):
            try:
                return (
                    (datetime.fromisoformat(value[:-1] + "+00:00") + delta)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            except ValueError:
                pass
        return value

    record = shift(fixture._record())
    record["attestations"] = [item]
    if failure == "short_window":
        record["window_started_at"] = "2026-10-20T08:30:00Z"
    elif failure == "fairness":
        record["capacity_test"]["service_outcomes"]["control-plane"]["scenarios"]["hot_tenant"][
            "tenant_fairness_ratio"
        ] = 0.8
    fixture._resign(record)
    policy = fixture._policy()
    (tmp_path / policy["evidence_directory"]).mkdir(parents=True)
    report = validate_slo_capacity_readiness(
        tmp_path,
        policy,
        [record],
        now=_NOW,
        expected_product_revision=product,
        baseline=fixture._active_baseline(),
    )
    assert report["status"] == "pass", report
    if failure is None:
        assert report["production_readiness"] == "ready", report
    else:
        assert report["production_readiness"] == "blocked", report
        expected = "window" if failure == "short_window" else "fairness"
        assert any(expected in reason for reason in report["blockers"]), report


@pytest.mark.parametrize(
    "failure", [None, "foreign_workflow", "extra_field", "expired", "unsafe_output"]
)
def test_native_authorization_producer_binds_inputs_without_existing_domain_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    import sys

    from saas.scripts import prepare_review_exception as prepare

    item, _, product, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        prepare, "__file__", str(tmp_path / "saas/scripts/prepare_review_exception.py")
    )
    request = {"attestor_commitment": item["actor_id_hash"], "expires_at": "2026-12-01T00:00:00Z"}
    identity = review.WORKFLOW_IDENTITY
    output = "artifacts/review-exception/review-exception-authorization.json"
    if failure == "foreign_workflow":
        identity = "foreign/workflow@main"
    elif failure == "extra_field":
        request["authorized"] = True
    elif failure == "expired":
        request["expires_at"] = "2026-10-20T00:00:00Z"
    elif failure == "unsafe_output":
        output = "../escape.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prepare_review_exception",
            "--authorization-request-json",
            json.dumps(request),
            "--product-revision",
            product,
            "--evidence-revision",
            product,
            "--workflow-identity",
            identity,
            "--output",
            output,
        ],
    )
    if failure is not None:
        with pytest.raises(SystemExit):
            prepare.main()
        assert not (tmp_path / "artifacts").exists()
        return
    assert prepare.main() == 0
    raw = (tmp_path / output).read_bytes()
    document = json.loads(raw)
    assert raw == review.canonical_review_record(document)
    assert document["product_revision"] == document["evidence_revision"] == product
    assert document["attestor_commitment"] == item["actor_id_hash"]
    assert not (tmp_path / "saas/production/evidence-admission-receipts").exists()
