from __future__ import annotations

import copy
import hashlib
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from saas.scripts.check_image_supply_chain import (
    canonical_release_evidence_sha256,
    load_release_evidence,
    validate_candidate_build_contract,
    validate_release,
)
from saas.scripts.compare_oci_rebuilds import compare_archives

_NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _policy() -> dict[str, object]:
    return json.loads(
        (_repo() / "saas/supply_chain/release-policy.json").read_text(encoding="utf-8")
    )


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _valid_evidence() -> dict[str, object]:
    policy = _policy()
    upstream = json.loads((_repo() / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    baseline = json.loads((_repo() / "saas/production/baseline.json").read_text(encoding="utf-8"))
    schema_revision = baseline["revision_contract"]["control_plane_schema_revision"]
    product_revision = "a" * 40
    labels = {
        "org.opencontainers.image.revision": product_revision,
        "ai.omnigent.upstream.revision": upstream["upstream_revision"],
        "ai.omnigent.saas.schema-revision": schema_revision,
        "ai.omnigent.saas.adapter-contract-version": upstream["adapter_contract_version"],
    }
    images = []
    for index, image_policy in enumerate(policy["images"]):  # type: ignore[index]
        character = str(index + 1)
        platform_chars = (("b", "c"), ("d", "e"))[index]
        config_chars = (("f", "a"), ("8", "9"))[index]
        manifest_digest = _digest(character)
        images.append(
            {
                "name": image_policy["name"],
                "target": image_policy["target"],
                "manifest_digest": manifest_digest,
                "platform_digests": {
                    "linux/amd64": _digest(platform_chars[0]),
                    "linux/arm64": _digest(platform_chars[1]),
                },
                "config_digests": {
                    "linux/amd64": _digest(config_chars[0]),
                    "linux/arm64": _digest(config_chars[1]),
                },
                "labels": labels,
                "sbom": {
                    "spdx_sha256": "1" * 64,
                    "cyclonedx_sha256": "2" * 64,
                    "subject_digest": manifest_digest,
                    "spdx_uri": (
                        f"oci://ghcr.io/dream1216/{image_policy['name']}@"
                        f"{manifest_digest}/sbom.spdx.json"
                    ),
                    "cyclonedx_uri": (
                        f"oci://ghcr.io/dream1216/{image_policy['name']}@"
                        f"{manifest_digest}/sbom.cyclonedx.json"
                    ),
                },
                "provenance": {
                    "verified": True,
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "subject_digest": manifest_digest,
                    "materials_digest_pinned": True,
                    "builder_id": "https://github.com/actions/runner",
                    "source_revision": product_revision,
                    "workflow_ref": (".github/workflows/saas-image-candidate.yml@refs/heads/main"),
                    "statement_sha256": "3" * 64,
                },
                "signature": {
                    "verified": True,
                    "issuer": "https://token.actions.githubusercontent.com",
                    "workflow_identity": (
                        "https://github.com/Dream1216/omnigent/.github/workflows/"
                        "saas-image-candidate.yml@refs/heads/main"
                    ),
                    "oidc_subject": ("repo:Dream1216/omnigent:environment:production-image"),
                    "subject_digest": manifest_digest,
                    "transparency_log_verified": True,
                    "transparency_log_entry_sha256": "4" * 64,
                    "bundle_sha256": "5" * 64,
                },
                "vulnerabilities": {
                    "scanner": "trivy-verified",
                    "scanner_database_updated_at": "2026-08-05T07:00:00Z",
                    "scan_completed_at": "2026-08-05T07:30:00Z",
                    "subject_digest": manifest_digest,
                    "report_sha256": "6" * 64,
                    "critical": 0,
                    "high": 0,
                    "exceptions": [],
                },
                "licenses": {
                    "scanner": "syft-license-verified",
                    "subject_digest": manifest_digest,
                    "policy_id": "omnigent-saas-license-admission-v1",
                    "report_sha256": "0" * 64,
                    "denied_license_count": 0,
                    "unknown_license_count": 0,
                    "exceptions": [],
                },
                "admission_completed_at": "2026-08-05T07:45:00Z",
                "smoke_passed": image_policy["required_smoke"],
            }
        )
    locks = {
        path: hashlib.sha256((_repo() / path).read_bytes()).hexdigest()
        for path in policy["reproducibility"]["dependency_locks"]  # type: ignore[index]
    }
    evidence: dict[str, object] = {
        "evidence_version": 2,
        "completed_at": "2026-08-05T10:30:00Z",
        "product_revision": product_revision,
        "upstream_revision": upstream["upstream_revision"],
        "adapter_contract_version": upstream["adapter_contract_version"],
        "control_plane_schema_revision": schema_revision,
        "workflow": {
            "repository": "Dream1216/omnigent",
            "workflow_ref": (".github/workflows/saas-image-candidate.yml@refs/heads/main"),
            "source_ref": "refs/heads/main",
            "source_ref_protected": True,
            "oidc_subject": "repo:Dream1216/omnigent:environment:production-image",
            "run_id": 1,
            "run_attempt": 1,
            "builder_id": "https://github.com/actions/runner",
            "environment": "production-image",
            "environment_protection_verified": True,
            "conclusion": "success",
        },
        "materials": {
            "base_images": {
                "python": f"python:3.12-slim@{_digest('a')}",
                "node": f"node:22-slim@{_digest('b')}",
            },
            "lockfiles": locks,
            "dockerfile_sha256": hashlib.sha256(
                (_repo() / policy["dockerfile"]).read_bytes()  # type: ignore[index]
            ).hexdigest(),
        },
        "images": images,
        "rebuild": {"attempts": 2, "matching_platform_manifest_and_config": True},
        "regression": {
            "official_suites": True,
            "saas_suite": True,
            "real_postgresql": True,
            "chromium": True,
            "migration_cycle": True,
            "patch_replay": True,
            "source_intrusion_budget": True,
        },
        "promotion": {
            "images": [
                {
                    "name": image["name"],
                    "registry_ref": (
                        f"ghcr.io/dream1216/{image['name']}@{image['manifest_digest']}"
                    ),
                    "registry_immutable": True,
                    "registry_immutability_receipt_sha256": "9" * 64,
                    "canary": {
                        "environment": "production-canary",
                        "deployed_digest": image["manifest_digest"],
                        "started_at": "2026-08-05T08:00:00Z",
                        "completed_at": "2026-08-05T09:00:00Z",
                        "observation_seconds": 3600,
                        "slo_gate_passed": True,
                        "security_gate_passed": True,
                        "result": "passed",
                        "evidence_sha256": "7" * 64,
                    },
                    "n_minus_one_rollback": {
                        "from_digest": image["manifest_digest"],
                        "to_digest": (target := _digest("f" if index == 0 else "e")),
                        "to_registry_ref": (f"ghcr.io/dream1216/{image['name']}@{target}"),
                        "previous_release_signature_verified": True,
                        "previous_release_provenance_verified": True,
                        "started_at": "2026-08-05T09:05:00Z",
                        "completed_at": "2026-08-05T09:10:00Z",
                        "recovery_seconds": 300,
                        "result": "passed",
                        "evidence_sha256": "8" * 64,
                    },
                }
                for index, image in enumerate(images)
            ]
        },
        "attestations": [
            {
                "role": role,
                "actor_id_hash": character * 64,
                "attested_at": "2026-08-05T10:00:00Z",
                "product_revision": product_revision,
            }
            for role, character in (
                ("release-engineering", "a"),
                ("security", "b"),
                ("site-reliability", "c"),
            )
        ],
    }
    evidence["evidence_sha256"] = canonical_release_evidence_sha256(evidence)
    return evidence


def _resign(evidence: dict[str, object]) -> None:
    evidence["evidence_sha256"] = canonical_release_evidence_sha256(evidence)


def _candidate_contract_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for relative in (
        ".github/workflows/saas-image-candidate.yml",
        ".github/workflows/saas-n1-compat-image.yml",
        "saas/actions/build-oci-candidate/action.yml",
    ):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((_repo() / relative).read_text(encoding="utf-8"), encoding="utf-8")
    return repo


def test_candidate_composite_build_contract_is_valid() -> None:
    assert validate_candidate_build_contract(_repo()) == []


def test_generic_docker_build_has_reproducible_epoch_fallback() -> None:
    dockerfile = (_repo() / "deploy/docker/Dockerfile").read_text(encoding="utf-8")

    assert "ARG SOURCE_DATE_EPOCH=1580601600" in dockerfile
    assert "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" in dockerfile


def test_candidate_composite_build_contract_rejects_action_drift(tmp_path: Path) -> None:
    repo = _candidate_contract_repo(tmp_path)
    action = repo / "saas/actions/build-oci-candidate/action.yml"
    action.write_text(
        action.read_text(encoding="utf-8").replace(
            "CONTROL_PLANE_SCHEMA_REVISION=${{ env.CONTROL_PLANE_SCHEMA_REVISION }}",
            "CONTROL_PLANE_SCHEMA_REVISION=${{ env.SOURCE_REVISION }}",
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert (
        "candidate composite build action must bind resolved CONTROL_PLANE_SCHEMA_REVISION"
    ) in violations


def test_candidate_composite_build_contract_rejects_shared_rebuild_cache(
    tmp_path: Path,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    action = repo / "saas/actions/build-oci-candidate/action.yml"
    action.write_text(
        action.read_text(encoding="utf-8").replace(
            (
                "cache-from: ${{ inputs.attempt == '1' && "
                "format('type=gha,scope=saas-{0}-candidate', inputs.artifact) || '' }}"
            ),
            "cache-from: type=gha,scope=saas-${{ inputs.artifact }}-candidate",
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "candidate attempt 2 must rebuild without shared cache" in violations


def test_n1_candidate_build_contract_rejects_shared_rebuild_cache(tmp_path: Path) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-n1-compat-image.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "          no-cache: true\n          build-args: |",
            (
                "          cache-from: type=gha,scope=saas-n1-compat-candidate\n"
                "          build-args: |"
            ),
            1,
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "N-1 candidate attempt 2 must rebuild without shared cache" in violations


def test_candidate_composite_build_contract_rejects_path_drift(tmp_path: Path) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "uses: ./saas/actions/build-oci-candidate",
            "uses: ./saas/actions/untrusted-build",
            1,
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "candidate workflow must invoke four repeated composite builds" in violations
    assert "candidate workflow build coordinates must cover server and host twice" in violations


def test_candidate_contract_rejects_unprotected_or_unsigned_release(tmp_path: Path) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8")
        .replace("environment: production-image", "environment: unprotected", 1)
        .replace(
            "uses: actions/attest@c32b4b8b198b65d0bd9d63490e847ff7b53989d4",
            "uses: actions/attest@main",
            1,
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "protected signed release workflow contract is incomplete" in violations
    assert "protected release must sign the wheel and both OCI images" in violations


def test_candidate_composite_build_contract_rejects_missing_and_symlink(
    tmp_path: Path,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    action = repo / "saas/actions/build-oci-candidate/action.yml"
    action.unlink()
    missing = validate_candidate_build_contract(repo)
    assert "candidate composite build action must be a repository file" in missing

    outside = tmp_path / "outside-action.yml"
    outside.write_text("runs:\n  using: composite\n", encoding="utf-8")
    action.symlink_to(outside)
    symlink = validate_candidate_build_contract(repo)
    assert "candidate composite build action path must not use symbolic links" in symlink


def test_image_policy_is_valid_but_missing_real_release_evidence() -> None:
    report = validate_release(_repo(), _policy(), None, now=_NOW)

    assert report == {
        "status": "pass",
        "production_readiness": "blocked",
        "violations": [],
        "blockers": ["no immutable signed production image evidence is recorded"],
        "metrics": {
            "policy_image_count": 2,
            "evidenced_image_count": 0,
            "promoted_image_count": 0,
            "readiness_blocker_count": 1,
        },
    }


def test_complete_image_evidence_satisfies_policy() -> None:
    report = validate_release(
        _repo(),
        _policy(),
        _valid_evidence(),
        now=_NOW,
        expected_product_revision="a" * 40,
    )

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["blockers"] == []


def test_image_evidence_rejects_floating_material_and_lock_drift() -> None:
    evidence = copy.deepcopy(_valid_evidence())
    evidence["materials"]["base_images"]["python"] = "python:3.12-slim"  # type: ignore[index]
    evidence["materials"]["lockfiles"]["uv.lock"] = "0" * 64  # type: ignore[index]

    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert report["production_readiness"] == "blocked"
    assert "every base image material must be digest-pinned" in report["blockers"]
    assert "image evidence lock hash drifted for uv.lock" in report["blockers"]


def test_untrusted_workflow_signature_subject_and_transparency_fail_closed() -> None:
    evidence = _valid_evidence()
    evidence["workflow"]["source_ref_protected"] = False  # type: ignore[index]
    signature = evidence["images"][0]["signature"]  # type: ignore[index]
    signature["subject_digest"] = _digest("0")
    signature["transparency_log_verified"] = False
    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert report["production_readiness"] == "blocked"
    assert "image evidence workflow.source_ref_protected is not trusted" in report["blockers"]
    assert "omnigent-saas-server signature subject_digest is invalid" in report["blockers"]
    assert (
        "omnigent-saas-server signature transparency_log_verified is invalid" in report["blockers"]
    )


def test_canary_rollback_and_registry_claims_are_mandatory() -> None:
    evidence = _valid_evidence()
    promotion = evidence["promotion"]["images"][0]  # type: ignore[index]
    promotion["registry_immutable"] = False
    promotion["registry_immutability_receipt_sha256"] = "invalid"
    canary = promotion["canary"]
    canary["completed_at"] = "2026-08-05T08:30:00Z"
    canary["observation_seconds"] = 1800
    canary["slo_gate_passed"] = False
    rollback = promotion["n_minus_one_rollback"]
    rollback["completed_at"] = "2026-08-05T09:20:01Z"
    rollback["recovery_seconds"] = 901
    rollback["to_registry_ref"] = "example.invalid/image:latest"
    rollback["previous_release_signature_verified"] = False
    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert any("registry immutability is not verified" in item for item in report["blockers"])
    assert any("registry immutability receipt is invalid" in item for item in report["blockers"])
    assert any("canary observation is shorter" in item for item in report["blockers"])
    assert any("canary slo_gate_passed is invalid" in item for item in report["blockers"])
    assert any("N-1 rollback exceeded policy" in item for item in report["blockers"])
    assert any("N-1 rollback registry target is invalid" in item for item in report["blockers"])
    assert any("N-1 target signature is not verified" in item for item in report["blockers"])


def test_admission_canary_and_rollback_must_run_in_order() -> None:
    evidence = _valid_evidence()
    image = evidence["images"][0]  # type: ignore[index]
    image["admission_completed_at"] = "2026-08-05T08:30:00Z"
    promotion = evidence["promotion"]["images"][0]  # type: ignore[index]
    rollback = promotion["n_minus_one_rollback"]
    rollback["started_at"] = "2026-08-05T08:55:00Z"
    rollback["completed_at"] = "2026-08-05T09:00:00Z"
    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert any("canary started before image admission" in item for item in report["blockers"])
    assert any("rollback started before canary" in item for item in report["blockers"])


def test_stale_scan_different_release_and_record_tampering_are_rejected() -> None:
    evidence = _valid_evidence()
    scan = evidence["images"][0]["vulnerabilities"]  # type: ignore[index]
    scan["scanner_database_updated_at"] = "2026-08-03T07:00:00Z"
    scan["scan_completed_at"] = "2026-08-03T07:30:00Z"
    _resign(evidence)

    report = validate_release(
        _repo(),
        _policy(),
        evidence,
        now=_NOW,
        expected_product_revision="b" * 40,
    )

    assert any("scan is older than release evidence" in item for item in report["blockers"])
    assert any("does not match the release candidate" in item for item in report["blockers"])

    evidence["completed_at"] = "2026-08-05T10:31:00Z"
    tampered = validate_release(_repo(), _policy(), evidence, now=_NOW)
    assert any("canonical record" in item for item in tampered["blockers"])


def test_license_admission_subject_policy_and_threshold_fail_closed() -> None:
    evidence = _valid_evidence()
    licenses = evidence["images"][0]["licenses"]  # type: ignore[index]
    licenses["subject_digest"] = _digest("0")
    licenses["policy_id"] = "unreviewed-policy"
    licenses["unknown_license_count"] = 1
    licenses["exceptions"] = [{"reason": "self-approved"}]
    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert any("license report subject" in item for item in report["blockers"])
    assert any("license report does not bind" in item for item in report["blockers"])
    assert any("license admission threshold" in item for item in report["blockers"])
    assert any("cannot carry license exceptions" in item for item in report["blockers"])


def test_boolean_integer_substitution_cannot_satisfy_strict_release_fields() -> None:
    evidence = _valid_evidence()
    image = evidence["images"][0]  # type: ignore[index]
    image["vulnerabilities"]["critical"] = False
    image["licenses"]["denied_license_count"] = False
    image["provenance"]["verified"] = 1
    promotion = evidence["promotion"]["images"][0]  # type: ignore[index]
    promotion["canary"]["slo_gate_passed"] = 1
    _resign(evidence)

    report = validate_release(_repo(), _policy(), evidence, now=_NOW)

    assert any("vulnerability threshold" in item for item in report["blockers"])
    assert any("license admission threshold" in item for item in report["blockers"])
    assert any("provenance verified is invalid" in item for item in report["blockers"])
    assert any("canary slo_gate_passed is invalid" in item for item in report["blockers"])


def test_release_evidence_loader_rejects_escape_symlink_and_non_object(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (repo / "link.json").symlink_to(outside)
    (repo / "array.json").write_text("[]", encoding="utf-8")

    for value in (str(outside), "../outside.json", "link.json"):
        try:
            load_release_evidence(repo, value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe release evidence path accepted: {value}")

    try:
        load_release_evidence(repo, "array.json")
    except ValueError as error:
        assert "must be an object" in str(error)
    else:
        raise AssertionError("non-object release evidence was accepted")

    assert load_release_evidence(repo, "missing.json", allow_missing=True) is None


def test_policy_drift_and_reused_release_attestor_fail_closed() -> None:
    policy = copy.deepcopy(_policy())
    policy["promotion"]["undeclared_bypass"] = True  # type: ignore[index]

    invalid_policy = validate_release(_repo(), policy, _valid_evidence(), now=_NOW)
    assert invalid_policy["status"] == "fail"
    assert "promotion policy fields do not match schema version 2" in invalid_policy["violations"]
    assert invalid_policy["blockers"] == [
        "release policy must be valid before evidence can qualify"
    ]

    evidence = _valid_evidence()
    attestations = evidence["attestations"]
    assert isinstance(attestations, list)
    assert isinstance(attestations[0], dict)
    assert isinstance(attestations[1], dict)
    attestations[1]["actor_id_hash"] = attestations[0]["actor_id_hash"]
    _resign(evidence)

    reused_actor = validate_release(_repo(), _policy(), evidence, now=_NOW)
    assert any("actors must be distinct" in item for item in reused_actor["blockers"])


def test_policy_weakening_and_malformed_nested_lists_fail_without_crashing() -> None:
    policy = copy.deepcopy(_policy())
    first_image = policy["images"][0]  # type: ignore[index]
    first_image["target"] = "host"
    first_image["platforms"] = 1
    first_image["required_smoke"] = [{"fake": True}]
    policy["required_labels"] = []
    policy["reproducibility"]["dependency_locks"] = [{}]  # type: ignore[index]
    policy["attestations"]["sbom_formats"] = 1  # type: ignore[index]
    policy["regression"]["official_suites"] = 1  # type: ignore[index]
    policy["promotion"]["required_approval_roles"] = [{}]  # type: ignore[index]

    report = validate_release(_repo(), policy, None, now=_NOW)

    assert report["status"] == "fail"
    assert any("approved Docker target" in item for item in report["violations"])
    assert any("approved smoke probes" in item for item in report["violations"])
    assert any("approved image labels" in item for item in report["violations"])
    assert any("approved set" in item for item in report["violations"])


def _write_oci(path: Path, *, revision: str, nested: bool = False) -> None:
    root = path.parent / f"{path.stem}-layout"
    (root / "blobs/sha256").mkdir(parents=True, exist_ok=True)
    descriptors = []
    for architecture in ("amd64", "arm64"):
        config = json.dumps(
            {"config": {"Labels": {"org.opencontainers.image.revision": revision}}},
            sort_keys=True,
        ).encode()
        config_hex = hashlib.sha256(config).hexdigest()
        (root / "blobs/sha256" / config_hex).write_bytes(config)
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "config": {"digest": f"sha256:{config_hex}"},
                "layers": [],
            },
            sort_keys=True,
        ).encode()
        manifest_hex = hashlib.sha256(manifest).hexdigest()
        (root / "blobs/sha256" / manifest_hex).write_bytes(manifest)
        descriptors.append(
            {
                "digest": f"sha256:{manifest_hex}",
                "platform": {"os": "linux", "architecture": architecture},
            }
        )
    descriptors.extend(
        [
            {"digest": _digest("e"), "platform": {"os": "unknown", "architecture": "unknown"}},
            {"digest": _digest("f"), "platform": {"os": "unknown", "architecture": "unknown"}},
        ]
    )
    if nested:
        nested_index = json.dumps(
            {"schemaVersion": 2, "manifests": descriptors}, sort_keys=True
        ).encode()
        nested_hex = hashlib.sha256(nested_index).hexdigest()
        (root / "blobs/sha256" / nested_hex).write_bytes(nested_index)
        descriptors = [
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": f"sha256:{nested_hex}",
            }
        ]
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": descriptors}), encoding="utf-8"
    )
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    with tarfile.open(path, "w") as archive:
        for member in sorted(root.rglob("*")):
            archive.add(member, arcname=member.relative_to(root))


def test_oci_rebuild_comparison_ignores_attestation_time_but_not_image_drift(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    _write_oci(first, revision="a" * 40)
    _write_oci(second, revision="a" * 40)

    assert compare_archives(first, second)["matching_platform_manifest_and_config"] is True

    _write_oci(second, revision="b" * 40)
    assert compare_archives(first, second)["matching_platform_manifest_and_config"] is False


def test_oci_rebuild_comparison_descends_buildkit_nested_index(tmp_path: Path) -> None:
    first = tmp_path / "first-nested.tar"
    second = tmp_path / "second-nested.tar"
    _write_oci(first, revision="a" * 40, nested=True)
    _write_oci(second, revision="a" * 40, nested=True)

    comparison = compare_archives(first, second)

    assert comparison["matching_platform_manifest_and_config"] is True
    assert comparison["first"]["attestation_descriptor_count"] == 2
