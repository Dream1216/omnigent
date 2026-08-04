from __future__ import annotations

import copy
import hashlib
import json
import tarfile
from pathlib import Path

from saas.scripts.check_image_supply_chain import validate_release
from saas.scripts.compare_oci_rebuilds import compare_archives


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
    product_revision = "a" * 40
    labels = {
        "org.opencontainers.image.revision": product_revision,
        "ai.omnigent.upstream.revision": upstream["upstream_revision"],
        "ai.omnigent.saas.schema-revision": "p4b000000001",
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
                "sbom": {"spdx_sha256": "1" * 64, "cyclonedx_sha256": "2" * 64},
                "provenance": {
                    "verified": True,
                    "predicate_type": "https://slsa.dev/provenance/v1",
                    "subject_digest": manifest_digest,
                    "materials_digest_pinned": True,
                },
                "signature": {
                    "verified": True,
                    "issuer": "https://token.actions.githubusercontent.com",
                    "workflow_identity": "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
                },
                "vulnerabilities": {"critical": 0, "high": 0, "exceptions": []},
                "smoke_passed": image_policy["required_smoke"],
            }
        )
    locks = {
        path: hashlib.sha256((_repo() / path).read_bytes()).hexdigest()
        for path in policy["reproducibility"]["dependency_locks"]  # type: ignore[index]
    }
    return {
        "evidence_version": 1,
        "product_revision": product_revision,
        "upstream_revision": upstream["upstream_revision"],
        "adapter_contract_version": upstream["adapter_contract_version"],
        "control_plane_schema_revision": "p4b000000001",
        "workflow": {
            "repository": "example/repo",
            "workflow_ref": ".github/workflows/release.yml@refs/heads/main",
            "run_id": 1,
            "run_attempt": 1,
            "builder_id": "https://github.com/actions/runner",
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
    }


def test_image_policy_is_valid_but_missing_real_release_evidence() -> None:
    report = validate_release(_repo(), _policy(), None)

    assert report == {
        "status": "pass",
        "production_readiness": "blocked",
        "violations": [],
        "blockers": ["no immutable signed production image evidence is recorded"],
        "metrics": {
            "policy_image_count": 2,
            "evidenced_image_count": 0,
            "readiness_blocker_count": 1,
        },
    }


def test_complete_image_evidence_satisfies_policy() -> None:
    report = validate_release(_repo(), _policy(), _valid_evidence())

    assert report["status"] == "pass"
    assert report["production_readiness"] == "ready"
    assert report["blockers"] == []


def test_image_evidence_rejects_floating_material_and_lock_drift() -> None:
    evidence = copy.deepcopy(_valid_evidence())
    evidence["materials"]["base_images"]["python"] = "python:3.12-slim"  # type: ignore[index]
    evidence["materials"]["lockfiles"]["uv.lock"] = "0" * 64  # type: ignore[index]

    report = validate_release(_repo(), _policy(), evidence)

    assert report["production_readiness"] == "blocked"
    assert "every base image material must be digest-pinned" in report["blockers"]
    assert "image evidence lock hash drifted for uv.lock" in report["blockers"]


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
