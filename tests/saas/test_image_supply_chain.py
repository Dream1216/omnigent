from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saas.scripts.check_image_supply_chain import (
    canonical_release_evidence_sha256,
    load_release_evidence,
    validate_candidate_build_contract,
    validate_image_material_lock,
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


def _material_lock_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for relative in (
        "deploy/docker/Dockerfile",
        "uv.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".github/ci-deps/package.json",
    ):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((_repo() / relative).read_bytes())
    return repo


def _host_pnpm_normalizer() -> str:
    dockerfile = (_repo() / "deploy/docker/Dockerfile").read_text(encoding="utf-8")
    marker = 'SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" python -B -c \''
    start = dockerfile.index(marker) + len(marker)
    end = dockerfile.index("' \\\n", start)
    return dockerfile[start:end]


def _run_host_pnpm_normalizer(
    root: Path,
    *,
    modules_source: str,
    state: object | None = None,
) -> subprocess.CompletedProcess[str]:
    node_modules = root / "node_modules"
    node_modules.mkdir(parents=True)
    (node_modules / ".modules.yaml").write_text(modules_source, encoding="utf-8")
    (node_modules / ".pnpm-workspace-state-v1.json").write_text(
        json.dumps({"lastValidatedTimestamp": 1788208533731} if state is None else state),
        encoding="utf-8",
    )
    return subprocess.run(
        [sys.executable, "-B", "-c", _host_pnpm_normalizer()],
        cwd=root,
        env={**os.environ, "SOURCE_DATE_EPOCH": "0"},
        text=True,
        capture_output=True,
        check=False,
    )


def test_candidate_composite_build_contract_is_valid() -> None:
    assert validate_candidate_build_contract(_repo()) == []


def test_generic_docker_build_has_reproducible_epoch_fallback() -> None:
    dockerfile = (_repo() / "deploy/docker/Dockerfile").read_text(encoding="utf-8")

    assert "ARG SOURCE_DATE_EPOCH=1580601600" in dockerfile
    assert "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" in dockerfile


def test_image_material_lock_contract_is_valid() -> None:
    assert validate_image_material_lock(_repo()) == []


def test_host_pnpm_normalizer_canonicalizes_json_wall_clock(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_result = _run_host_pnpm_normalizer(
        first,
        modules_source=json.dumps(
            {"z": {"value": 1}, "prunedAt": "Mon, 31 Aug 2026 20:35:21 GMT", "a": []},
            indent=2,
        ),
    )
    second_result = _run_host_pnpm_normalizer(
        second,
        modules_source=json.dumps(
            {"a": [], "prunedAt": "Mon, 31 Aug 2026 20:36:09 GMT", "z": {"value": 1}},
            indent=2,
        ),
    )

    assert first_result.returncode == 0, first_result.stderr
    assert second_result.returncode == 0, second_result.stderr
    expected = (
        json.dumps(
            {"a": [], "prunedAt": "Thu, 01 Jan 1970 00:00:00 GMT", "z": {"value": 1}},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    assert (first / "node_modules/.modules.yaml").read_text(encoding="utf-8") == expected
    assert (second / "node_modules/.modules.yaml").read_text(encoding="utf-8") == expected
    assert not (first / "node_modules/.pnpm-workspace-state-v1.json").exists()
    assert not (second / "node_modules/.pnpm-workspace-state-v1.json").exists()
    assert first_result.stdout.strip() == "pnpm prunedAt fields normalized: 1"


@pytest.mark.parametrize(
    "modules_source",
    [
        '{"other": true}',
        '{"prunedAt": "first", "prunedAt": "second"}',
        '{"prunedAt": true}',
    ],
)
def test_host_pnpm_normalizer_rejects_missing_duplicate_or_non_string_timestamp(
    tmp_path: Path,
    modules_source: str,
) -> None:
    result = _run_host_pnpm_normalizer(tmp_path, modules_source=modules_source)

    assert result.returncode != 0


@pytest.mark.parametrize("timestamp", [True, -1, "1788208533731", None])
def test_host_pnpm_normalizer_rejects_invalid_workspace_timestamp(
    tmp_path: Path,
    timestamp: object,
) -> None:
    result = _run_host_pnpm_normalizer(
        tmp_path,
        modules_source='{"prunedAt": "Mon, 31 Aug 2026 20:35:21 GMT"}',
        state={"lastValidatedTimestamp": timestamp},
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    ("target", "replacement", "expected"),
    [
        (
            "ARG UV_VERSION=0.12.1",
            "ARG UV_VERSION=0.12.2",
            "production Dockerfile must pin and install uv 0.12.1",
        ),
        (
            "uv sync --frozen --active --package omnigent --no-dev --no-editable --no-cache",
            "uv sync --active --package omnigent --no-dev --no-editable --no-cache",
            "production Dockerfile must frozen-sync the core runtime from uv.lock",
        ),
        (
            "sed -i '/^\\[tool\\.uv\\.workspace\\]$/,/^$/d' pyproject.toml",
            "true # workspace handling removed",
            "production Dockerfile must handle the excluded .github/triage_v2 workspace",
        ),
        (
            "ARG PSYCOPG_VERSION=3.3.4",
            "ARG PSYCOPG_VERSION=3.3.5",
            "server image must frozen-sync saas and assert psycopg 3.3.4",
        ),
        (
            "ARG PNPM_VERSION=11.15.1",
            "ARG PNPM_VERSION=11.15.2",
            "production Dockerfile must pin pnpm 11.15.1",
        ),
        (
            "ARG CLAUDE_CODE_VERSION=2.1.212",
            "ARG CLAUDE_CODE_VERSION=2.1.213",
            "host image must pin @anthropic-ai/claude-code to 2.1.212",
        ),
        (
            "pnpm install --frozen-lockfile --prod --filter e2e-ci-deps",
            "pnpm install --prod --filter e2e-ci-deps",
            "host CLI dependency graph must install from pnpm-lock.yaml",
        ),
        (
            'ENV PATH="/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin:${PATH}"',
            'ENV PATH="/usr/local/bin:${PATH}"',
            "host CLI wrappers must execute from their pnpm installation directory",
        ),
        (
            "UV_NO_INSTALLER_METADATA=1",
            "UV_NO_INSTALLER_METADATA=0",
            "production Python installs must disable nondeterministic uv installer metadata",
        ),
        (
            "> /tmp/venv-core-pyc.sha256",
            "> /tmp/venv-core-pyc-unchecked.sha256",
            "production venv must preserve seed bytecode and reject uv installer metadata",
        ),
        (
            "> /tmp/venv-server-pyc.sha256",
            "> /tmp/venv-server-pyc-unchecked.sha256",
            "server venv must preserve the deterministic seed bytecode manifest",
        ),
        (
            "rm -f /var/cache/ldconfig/aux-cache",
            "true # volatile apt state retained",
            (
                "builder, host and server apt layers must use a fixed snapshot and remove "
                "volatile state"
            ),
        ),
        (
            "unexpected additional apt sources",
            "extra apt sources ignored",
            (
                "builder, host and server apt layers must use a fixed snapshot and remove "
                "volatile state"
            ),
        ),
        (
            "expected two Debian snapshot sources",
            "rolling Debian mirrors are allowed",
            (
                "builder, host and server apt layers must use a fixed snapshot and remove "
                "volatile state"
            ),
        ),
        (
            "--store-dir /tmp/pnpm-store",
            "--store-dir /root/.local/share/pnpm/store",
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            "count == 1",
            "count in (0, 1)",
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            r'r"(?m)^\s*\"prunedAt\"\s*:"',
            r'r"(?m)^prunedAt:[^\r\n]*$"',
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            'type(data.get("prunedAt")) is str',
            'type(data.get("prunedAt")) in (str, type(None))',
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            'json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)+"\\n"',
            'json.dumps(data, ensure_ascii=False, indent=2)+"\\n"',
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            'type(state_data.get("lastValidatedTimestamp")) is int',
            'isinstance(state_data.get("lastValidatedTimestamp"), int)',
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            "--package-import-method=copy",
            "--package-import-method=auto",
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            "state.unlink()",
            'state_data["lastValidatedTimestamp"]=epoch*1000',
            "host CLI layer must normalize and remove volatile installer state",
        ),
        (
            "/root/.npm /root/.cache /root/.local/share/pnpm",
            "/root/.npm",
            "host CLI layer must normalize and remove volatile installer state",
        ),
    ],
)
def test_image_material_lock_rejects_dockerfile_drift(
    tmp_path: Path,
    target: str,
    replacement: str,
    expected: str,
) -> None:
    repo = _material_lock_repo(tmp_path)
    dockerfile = repo / "deploy/docker/Dockerfile"
    source = dockerfile.read_text(encoding="utf-8")
    assert target in source
    dockerfile.write_text(source.replace(target, replacement, 1), encoding="utf-8")

    assert expected in validate_image_material_lock(repo)


def test_image_material_lock_rejects_python_and_node_lock_drift(tmp_path: Path) -> None:
    repo = _material_lock_repo(tmp_path)
    uv_lock = repo / "uv.lock"
    uv_source = uv_lock.read_text(encoding="utf-8")
    uv_target = 'name = "psycopg"\nversion = "3.3.4"'
    assert uv_target in uv_source
    uv_lock.write_text(
        uv_source.replace(uv_target, 'name = "psycopg"\nversion = "3.3.5"', 1),
        encoding="utf-8",
    )

    pnpm_lock = repo / "pnpm-lock.yaml"
    pnpm_source = pnpm_lock.read_text(encoding="utf-8")
    pnpm_target = "'@openai/codex':\n        specifier: 0.139.0\n        version: 0.139.0"
    assert pnpm_target in pnpm_source
    pnpm_lock.write_text(
        pnpm_source.replace(
            pnpm_target,
            "'@openai/codex':\n        specifier: 0.140.0\n        version: 0.140.0",
            1,
        ),
        encoding="utf-8",
    )

    violations = validate_image_material_lock(repo)

    assert "uv.lock must resolve psycopg exactly to 3.3.4" in violations
    assert "pnpm-lock.yaml must bind @openai/codex to 0.139.0" in violations


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


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        (
            "CANDIDATE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}",
            "CANDIDATE_REVISION: ${{ github.sha }}",
        ),
        (
            "ref: ${{ env.CANDIDATE_REVISION }}",
            "ref: ${{ github.sha }}",
        ),
        (
            'source_revision="$CANDIDATE_REVISION"',
            "source_revision=$(git rev-parse HEAD)",
        ),
        (
            "name: saas-image-candidate-${{ env.CANDIDATE_REVISION }}",
            "name: saas-image-candidate-${{ github.sha }}",
        ),
    ],
)
def test_candidate_contract_rejects_merge_sha_binding(
    tmp_path: Path,
    target: str,
    replacement: str,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    source = workflow.read_text(encoding="utf-8")
    assert target in source
    workflow.write_text(source.replace(target, replacement, 1), encoding="utf-8")

    violations = validate_candidate_build_contract(repo)

    assert (
        "candidate workflow must bind builds and evidence to the exact pull-request head"
        in violations
    )


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


def test_candidate_composite_build_contract_rejects_timestamp_rewrite_drift(
    tmp_path: Path,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    action = repo / "saas/actions/build-oci-candidate/action.yml"
    action.write_text(
        action.read_text(encoding="utf-8").replace(",rewrite-timestamp=true", "", 1),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "candidate composite build action weakens the approved build contract" in violations


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

    assert "N-1 candidate attempt 2 must reproducibly rebuild without shared cache" in violations


def test_n1_candidate_build_contract_rejects_timestamp_rewrite_drift(
    tmp_path: Path,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-n1-compat-image.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(",rewrite-timestamp=true", "", 1),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "N-1 candidate attempt 1 must retain the approved reproducible GHA build" in violations


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


def test_candidate_contract_rejects_implicit_or_cross_profile_label_validation(
    tmp_path: Path,
) -> None:
    repo = _candidate_contract_repo(tmp_path)
    workflow = repo / ".github/workflows/saas-image-candidate.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "          --label-profile executable\n",
            "          --label-profile n1\n",
            1,
        ),
        encoding="utf-8",
    )
    n1_workflow = repo / ".github/workflows/saas-n1-compat-image.yml"
    n1_workflow.write_text(
        n1_workflow.read_text(encoding="utf-8").replace(
            "            --label-profile n1 \\\n",
            "",
            1,
        ),
        encoding="utf-8",
    )

    violations = validate_candidate_build_contract(repo)

    assert "candidate workflow must select the executable label profile" in violations
    assert (
        "N-1 candidate and publication comparisons must select the N-1 label profile" in violations
    )


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


def _write_oci(
    path: Path,
    *,
    revision: str,
    label_profile: str = "n1",
    missing_label: str | None = None,
    extra_label: str | None = None,
    nested: bool = False,
    history_command: str = "RUN stable",
    layer_payload: bytes = b"stable-layer",
    corrupt_layer: bool = False,
    rootfs_type: str = "layers",
    include_diff_id: bool = True,
    header_only_attestation: bool = False,
    buildkit_image_attestation_config: bool = False,
    statement_type: str = "https://in-toto.io/Statement/v0.1",
) -> None:
    root = path.parent / f"{path.stem}-layout"
    (root / "blobs/sha256").mkdir(parents=True, exist_ok=True)
    layer_hex = hashlib.sha256(layer_payload).hexdigest()
    (root / "blobs/sha256" / layer_hex).write_bytes(
        b"corrupt-layer" if corrupt_layer else layer_payload
    )
    labels = {
        "org.opencontainers.image.revision": revision,
        "ai.omnigent.upstream.revision": "u" * 40,
        "ai.omnigent.saas.schema-revision": "p0s000000003",
        "ai.omnigent.saas.adapter-contract-version": "adapter-v1",
    }
    if label_profile == "n1":
        labels.update(
            {
                "ai.omnigent.saas.n1.base-commit": "b" * 40,
                "ai.omnigent.saas.n1.patch-source-revision": revision,
                "ai.omnigent.saas.n1.patch-sha256": "c" * 64,
                "ai.omnigent.saas.n1.patched-tree-hash": "git-sha1:" + "d" * 40,
                "ai.omnigent.saas.n1.schema-revision": "p0s000000003",
                "ai.omnigent.saas.n1.contract-version": "contract-v1",
            }
        )
    elif label_profile != "executable":
        raise ValueError(f"unsupported test label profile: {label_profile}")
    if missing_label is not None:
        labels.pop(missing_label)
    if extra_label is not None:
        labels[extra_label] = "unexpected"
    descriptors = []
    for architecture in ("amd64", "arm64"):
        config = json.dumps(
            {
                "architecture": architecture,
                "created": "2026-08-31T10:52:21Z",
                "config": {"Labels": labels},
                "history": [
                    {
                        "created": "2026-08-31T10:52:21Z",
                        "created_by": history_command,
                    }
                ],
                "rootfs": {
                    "type": rootfs_type,
                    "diff_ids": [f"sha256:{layer_hex}"] if include_diff_id else [],
                },
            },
            sort_keys=True,
        ).encode()
        config_hex = hashlib.sha256(config).hexdigest()
        (root / "blobs/sha256" / config_hex).write_bytes(config)
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "config": {"digest": f"sha256:{config_hex}"},
                "layers": [
                    {
                        "digest": f"sha256:{layer_hex}",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "size": len(layer_payload),
                    }
                ],
            },
            sort_keys=True,
        ).encode()
        manifest_hex = hashlib.sha256(manifest).hexdigest()
        (root / "blobs/sha256" / manifest_hex).write_bytes(manifest)
        manifest_digest = f"sha256:{manifest_hex}"
        descriptors.append(
            {
                "digest": manifest_digest,
                "size": len(manifest),
                "platform": {"os": "linux", "architecture": architecture},
            }
        )
        attestation_layers = []
        for predicate in (
            "https://slsa.dev/provenance/v1",
            "https://spdx.dev/Document",
        ):
            predicate_body = (
                {}
                if header_only_attestation
                else (
                    {"buildDefinition": {}, "runDetails": {}}
                    if predicate == "https://slsa.dev/provenance/v1"
                    else {
                        "spdxVersion": "SPDX-2.3",
                        "SPDXID": "SPDXRef-DOCUMENT",
                        "dataLicense": "CC0-1.0",
                        "documentNamespace": "https://example.invalid/spdx/test",
                        "creationInfo": {},
                    }
                )
            )
            payload = json.dumps(
                {
                    "_type": statement_type,
                    "predicateType": predicate,
                    "subject": [],
                    "predicate": predicate_body,
                },
                sort_keys=True,
            ).encode()
            payload_hex = hashlib.sha256(payload).hexdigest()
            (root / "blobs/sha256" / payload_hex).write_bytes(payload)
            attestation_layers.append(
                {
                    "digest": f"sha256:{payload_hex}",
                    "size": len(payload),
                    "mediaType": "application/vnd.in-toto+json",
                    "annotations": {"in-toto.io/predicate-type": predicate},
                }
            )
        empty_config = json.dumps(
            (
                {
                    "architecture": "unknown",
                    "os": "unknown",
                    "config": {},
                    "rootfs": {
                        "type": "layers",
                        "diff_ids": [layer["digest"] for layer in attestation_layers],
                    },
                }
                if buildkit_image_attestation_config
                else {}
            ),
            sort_keys=True,
        ).encode()
        empty_config_hex = hashlib.sha256(empty_config).hexdigest()
        (root / "blobs/sha256" / empty_config_hex).write_bytes(empty_config)
        attestation = json.dumps(
            {
                "schemaVersion": 2,
                "config": {
                    "digest": f"sha256:{empty_config_hex}",
                    "size": len(empty_config),
                    "mediaType": (
                        "application/vnd.oci.image.config.v1+json"
                        if buildkit_image_attestation_config
                        else "application/vnd.oci.empty.v1+json"
                    ),
                },
                "layers": attestation_layers,
            },
            sort_keys=True,
        ).encode()
        attestation_hex = hashlib.sha256(attestation).hexdigest()
        (root / "blobs/sha256" / attestation_hex).write_bytes(attestation)
        descriptors.append(
            {
                "digest": f"sha256:{attestation_hex}",
                "size": len(attestation),
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": manifest_digest,
                },
                "platform": {"os": "unknown", "architecture": "unknown"},
            }
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

    assert (
        compare_archives(first, second, label_profile="n1")[
            "matching_platform_manifest_and_config"
        ]
        is True
    )

    _write_oci(second, revision="b" * 40)
    assert (
        compare_archives(first, second, label_profile="n1")[
            "matching_platform_manifest_and_config"
        ]
        is False
    )


@pytest.mark.parametrize("label_profile", ["executable", "n1"])
def test_oci_rebuild_accepts_only_the_exact_selected_label_profile(
    tmp_path: Path, label_profile: str
) -> None:
    first = tmp_path / f"first-{label_profile}.tar"
    second = tmp_path / f"second-{label_profile}.tar"
    _write_oci(first, revision="a" * 40, label_profile=label_profile)
    _write_oci(second, revision="a" * 40, label_profile=label_profile)

    comparison = compare_archives(first, second, label_profile=label_profile)

    assert comparison["label_profile"] == label_profile
    assert comparison["matching_platform_manifest_and_config"] is True


@pytest.mark.parametrize(
    ("label_profile", "missing_label"),
    [
        ("executable", "ai.omnigent.saas.adapter-contract-version"),
        ("n1", "ai.omnigent.saas.n1.contract-version"),
    ],
)
def test_oci_rebuild_rejects_a_missing_profile_label(
    tmp_path: Path, label_profile: str, missing_label: str
) -> None:
    first = tmp_path / f"first-missing-{label_profile}.tar"
    second = tmp_path / f"second-missing-{label_profile}.tar"
    _write_oci(first, revision="a" * 40, label_profile=label_profile)
    _write_oci(
        second,
        revision="a" * 40,
        label_profile=label_profile,
        missing_label=missing_label,
    )

    with pytest.raises(ValueError, match=f"approved {label_profile} image labels"):
        compare_archives(first, second, label_profile=label_profile)


@pytest.mark.parametrize("label_profile", ["executable", "n1"])
def test_oci_rebuild_rejects_an_extra_profile_label(tmp_path: Path, label_profile: str) -> None:
    first = tmp_path / f"first-extra-{label_profile}.tar"
    second = tmp_path / f"second-extra-{label_profile}.tar"
    _write_oci(first, revision="a" * 40, label_profile=label_profile)
    _write_oci(
        second,
        revision="a" * 40,
        label_profile=label_profile,
        extra_label="example.invalid/undeclared",
    )

    with pytest.raises(ValueError, match=f"approved {label_profile} image labels"):
        compare_archives(first, second, label_profile=label_profile)


@pytest.mark.parametrize(
    ("archive_profile", "selected_profile"),
    [("executable", "n1"), ("n1", "executable")],
)
def test_oci_rebuild_rejects_cross_profile_label_contracts(
    tmp_path: Path, archive_profile: str, selected_profile: str
) -> None:
    first = tmp_path / f"first-{archive_profile}-as-{selected_profile}.tar"
    second = tmp_path / f"second-{archive_profile}-as-{selected_profile}.tar"
    _write_oci(first, revision="a" * 40, label_profile=archive_profile)
    _write_oci(second, revision="a" * 40, label_profile=archive_profile)

    with pytest.raises(ValueError, match=f"approved {selected_profile} image labels"):
        compare_archives(first, second, label_profile=selected_profile)


def test_oci_rebuild_comparison_descends_buildkit_nested_index(tmp_path: Path) -> None:
    first = tmp_path / "first-nested.tar"
    second = tmp_path / "second-nested.tar"
    _write_oci(first, revision="a" * 40, nested=True)
    _write_oci(second, revision="a" * 40, nested=True)

    comparison = compare_archives(first, second, label_profile="n1")

    assert comparison["matching_platform_manifest_and_config"] is True
    assert comparison["first"]["attestation_descriptor_count"] == 2


def test_oci_rebuild_accepts_real_buildkit_image_attestation_config(tmp_path: Path) -> None:
    first = tmp_path / "first-real.tar"
    second = tmp_path / "second-real.tar"
    _write_oci(first, revision="a" * 40, buildkit_image_attestation_config=True)
    _write_oci(second, revision="a" * 40, buildkit_image_attestation_config=True)

    assert (
        compare_archives(first, second, label_profile="n1")[
            "matching_platform_manifest_and_config"
        ]
        is True
    )


def test_oci_rebuild_accepts_in_toto_statement_v1(tmp_path: Path) -> None:
    first = tmp_path / "first-v1.tar"
    second = tmp_path / "second-v1.tar"
    _write_oci(first, revision="a" * 40, statement_type="https://in-toto.io/Statement/v1")
    _write_oci(second, revision="a" * 40, statement_type="https://in-toto.io/Statement/v1")

    assert (
        compare_archives(first, second, label_profile="n1")[
            "matching_platform_manifest_and_config"
        ]
        is True
    )


def test_oci_rebuild_comparison_rejects_header_only_attestation(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    _write_oci(first, revision="a" * 40)
    _write_oci(second, revision="a" * 40, header_only_attestation=True)

    with pytest.raises(ValueError, match="predicate is incomplete"):
        compare_archives(first, second, label_profile="n1")


def test_oci_rebuild_diagnostics_expose_only_command_drift_ordinals(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first-safe.tar"
    second = tmp_path / "second-safe.tar"
    first_secret = "RUN --mount=type=secret secret-value-one"
    second_secret = "RUN --mount=type=secret secret-value-two"
    _write_oci(
        first,
        revision="a" * 40,
        history_command=first_secret,
        layer_payload=b"first-layer",
    )
    _write_oci(
        second,
        revision="a" * 40,
        history_command=second_secret,
        layer_payload=b"second-layer",
    )

    comparison = compare_archives(first, second, label_profile="n1")
    serialized = json.dumps(comparison, sort_keys=True)
    assert comparison["matching_platform_manifest_and_config"] is False
    assert comparison["history_created_by_equal"] is False
    assert comparison["history_created_by_drift_ordinals"]["linux/amd64"] == [0]
    assert "created_by_sha256" not in serialized
    assert "created_by_utf8_bytes" not in serialized
    assert first_secret not in serialized
    assert second_secret not in serialized
    assert (
        comparison["first"]["platforms"]["linux/amd64"]["rootfs_diff_ids"]
        != (comparison["second"]["platforms"]["linux/amd64"]["rootfs_diff_ids"])
    )
    assert (
        comparison["first"]["platforms"]["linux/amd64"]["layers"]
        != (comparison["second"]["platforms"]["linux/amd64"]["layers"])
    )


def test_oci_rebuild_comparison_rejects_tampered_layer_blob(tmp_path: Path) -> None:
    first = tmp_path / "first-valid.tar"
    second = tmp_path / "second-corrupt.tar"
    secret = "RUN --mount=type=secret raw-secret-must-not-leak"
    _write_oci(first, revision="a" * 40)
    _write_oci(
        second,
        revision="a" * 40,
        history_command=secret,
        corrupt_layer=True,
    )

    with pytest.raises(ValueError, match="OCI blob digest mismatch") as error:
        compare_archives(first, second, label_profile="n1")
    assert secret not in str(error.value)


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"rootfs_type": "not-layers"}, "OCI config rootfs is invalid"),
        (
            {"include_diff_id": False},
            "OCI layer and rootfs diff-id cardinality mismatch",
        ),
    ],
)
def test_oci_rebuild_comparison_rejects_invalid_rootfs_contract(
    tmp_path: Path,
    options: dict[str, object],
    expected: str,
) -> None:
    first = tmp_path / "first-rootfs.tar"
    second = tmp_path / "second-rootfs.tar"
    _write_oci(first, revision="a" * 40)
    _write_oci(second, revision="a" * 40, **options)

    with pytest.raises(ValueError, match=expected):
        compare_archives(first, second, label_profile="n1")
