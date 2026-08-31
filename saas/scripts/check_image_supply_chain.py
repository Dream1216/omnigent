"""Validate the production image policy and immutable release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import tomllib

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_APPROVED_PATHS = {
    "candidate_workflow": ".github/workflows/saas-image-candidate.yml",
    "release_runbook": "saas/production/runbooks/image-release.md",
    "dockerfile": "deploy/docker/Dockerfile",
    "upstream_manifest": "saas/upstream-baseline.json",
    "production_evidence": "saas/acceptance/p0-production-image-evidence.json",
}
_CANDIDATE_BUILD_ACTION = "saas/actions/build-oci-candidate/action.yml"
_CANDIDATE_BUILD_USES = "./saas/actions/build-oci-candidate"
_N1_CANDIDATE_WORKFLOW = ".github/workflows/saas-n1-compat-image.yml"
_BUILD_PUSH_ACTION = "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf"
_ATTEST_ACTION = "actions/attest@c32b4b8b198b65d0bd9d63490e847ff7b53989d4"
_APPROVED_UV_VERSION = "0.12.1"
_APPROVED_PNPM_VERSION = "11.15.1"
_APPROVED_PSYCOPG_VERSION = "3.3.4"
_APPROVED_HOST_CLI_VERSIONS = {
    "@anthropic-ai/claude-code": ("CLAUDE_CODE_VERSION", "2.1.212"),
    "@earendil-works/pi-coding-agent": ("PI_CODING_AGENT_VERSION", "0.84.2"),
    "@openai/codex": ("CODEX_CLI_VERSION", "0.139.0"),
}
_REQUIRED_BUILD_ARGS = {
    "PYTHON_IMAGE",
    "NODE_IMAGE",
    "SOURCE_DATE_EPOCH",
    "SOURCE_REVISION",
    "UPSTREAM_REVISION",
    "CONTROL_PLANE_SCHEMA_REVISION",
    "ADAPTER_CONTRACT_VERSION",
}
_REQUIRED_LABELS = {
    "org.opencontainers.image.revision",
    "ai.omnigent.upstream.revision",
    "ai.omnigent.saas.schema-revision",
    "ai.omnigent.saas.adapter-contract-version",
}
_REQUIRED_LOCKFILES = {"uv.lock", "pnpm-lock.yaml", "pnpm-workspace.yaml"}
_REQUIRED_IMAGES = {
    "omnigent-saas-server": {
        "target": "runtime",
        "smoke": {"cli-help", "health", "migration", "auth-context", "dual-rls"},
    },
    "omnigent-saas-host": {
        "target": "host",
        "smoke": {"cli-help", "git", "tmux", "bubblewrap", "runner-connect"},
    },
}
_REQUIRED_OFFICIAL_SUITES = {
    "tests/db/test_workspace_scope.py",
    "tests/cli/test_cli.py",
    "tests/runner/transports/ws_tunnel/test_serve.py",
    "tests/server/test_managed_hosts.py",
    "tests/server/integration/test_sessions_archive.py",
}
_POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "reviewed_at",
    "candidate_workflow",
    "release_runbook",
    "dockerfile",
    "upstream_manifest",
    "production_evidence",
    "images",
    "reproducibility",
    "required_labels",
    "attestations",
    "regression",
    "vulnerability_policy",
    "license_policy",
    "promotion",
}
_EVIDENCE_FIELDS = {
    "evidence_version",
    "completed_at",
    "product_revision",
    "upstream_revision",
    "adapter_contract_version",
    "control_plane_schema_revision",
    "workflow",
    "materials",
    "images",
    "rebuild",
    "regression",
    "promotion",
    "attestations",
    "evidence_sha256",
}
_WORKFLOW_FIELDS = {
    "repository",
    "workflow_ref",
    "source_ref",
    "source_ref_protected",
    "oidc_subject",
    "run_id",
    "run_attempt",
    "builder_id",
    "environment",
    "environment_protection_verified",
    "conclusion",
}
_SIGNATURE_FIELDS = {
    "verified",
    "issuer",
    "workflow_identity",
    "oidc_subject",
    "subject_digest",
    "transparency_log_verified",
    "transparency_log_entry_sha256",
    "bundle_sha256",
}
_PROVENANCE_FIELDS = {
    "verified",
    "predicate_type",
    "subject_digest",
    "materials_digest_pinned",
    "builder_id",
    "source_revision",
    "workflow_ref",
    "statement_sha256",
}
_IMAGE_FIELDS = {
    "name",
    "target",
    "manifest_digest",
    "platform_digests",
    "config_digests",
    "labels",
    "sbom",
    "provenance",
    "signature",
    "vulnerabilities",
    "licenses",
    "admission_completed_at",
    "smoke_passed",
}
_SBOM_FIELDS = {
    "spdx_sha256",
    "cyclonedx_sha256",
    "subject_digest",
    "spdx_uri",
    "cyclonedx_uri",
}
_VULNERABILITY_FIELDS = {
    "scanner",
    "scanner_database_updated_at",
    "scan_completed_at",
    "subject_digest",
    "report_sha256",
    "critical",
    "high",
    "exceptions",
}
_LICENSE_FIELDS = {
    "scanner",
    "subject_digest",
    "policy_id",
    "report_sha256",
    "denied_license_count",
    "unknown_license_count",
    "exceptions",
}
_PROMOTION_FIELDS = {"images"}
_IMAGE_PROMOTION_FIELDS = {
    "name",
    "registry_ref",
    "registry_immutable",
    "registry_immutability_receipt_sha256",
    "canary",
    "n_minus_one_rollback",
}
_CANARY_FIELDS = {
    "environment",
    "deployed_digest",
    "started_at",
    "completed_at",
    "observation_seconds",
    "slo_gate_passed",
    "security_gate_passed",
    "result",
    "evidence_sha256",
}
_ROLLBACK_FIELDS = {
    "from_digest",
    "to_digest",
    "to_registry_ref",
    "previous_release_signature_verified",
    "previous_release_provenance_verified",
    "started_at",
    "completed_at",
    "recovery_seconds",
    "result",
    "evidence_sha256",
}
_ATTESTATION_FIELDS = {"role", "actor_id_hash", "attested_at", "product_revision"}
_POLICY_IMAGE_FIELDS = {"name", "target", "platforms", "required_smoke"}
_REPRODUCIBILITY_POLICY_FIELDS = {
    "source_date_epoch",
    "base_images_must_be_digest_pinned",
    "clean_tree_required",
    "repeat_builds",
    "matching_platform_manifest_and_config_required",
    "dependency_locks",
    "required_build_args",
}
_ATTESTATION_POLICY_FIELDS = {
    "provenance_predicate",
    "provenance_mode",
    "sbom_formats",
    "keyless_signature_required",
    "signature_issuer",
    "signature_subject_digest_required",
    "transparency_log_required",
    "protected_workflow_identity_required",
    "trusted_repository",
    "trusted_workflow_ref",
    "trusted_workflow_identity",
    "trusted_oidc_subject",
    "trusted_builder_id",
    "trusted_environment",
}
_REGRESSION_POLICY_FIELDS = {
    "official_suites",
    "saas_suite",
    "real_postgresql_required",
    "chromium_required",
    "migration_upgrade_check_downgrade_required",
    "patch_replay_required",
    "source_intrusion_budget_required",
}
_VULNERABILITY_POLICY_FIELDS = {
    "critical_allowed",
    "high_allowed",
    "exceptions_require_owner_expiry_and_compensating_control",
    "maximum_scanner_database_age_hours",
}
_LICENSE_POLICY_FIELDS = {
    "policy_id",
    "denied_license_count_allowed",
    "unknown_license_count_allowed",
    "exceptions_require_legal_approval_and_expiry",
}
_PROMOTION_POLICY_FIELDS = {
    "digest_only_deployment",
    "n_minus_one_digest_required",
    "canary_required",
    "floating_tag_may_authorize_deployment",
    "allowed_registry_hosts",
    "canary_environment",
    "minimum_canary_observation_seconds",
    "maximum_n_minus_one_rollback_seconds",
    "required_approval_roles",
    "maximum_evidence_age_days",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_release_evidence_sha256(evidence: dict[str, Any]) -> str:
    """Hash the strict release record without its self-authenticating field."""

    payload = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hex_sha256(value: object) -> bool:
    return isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _positive_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _exact_integer(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _exact_scalar(value: object, expected: object) -> bool:
    return type(value) is type(expected) and value == expected


def _string_set(value: object) -> set[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    parsed = set(value)
    return parsed if len(parsed) == len(value) else None


def _secret_free_uri(value: object, schemes: set[str]) -> bool:
    parsed = urlsplit(value) if isinstance(value, str) else None
    return bool(
        parsed
        and parsed.scheme in schemes
        and parsed.netloc
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def load_release_evidence(
    repo: Path,
    relative_path: object,
    *,
    allow_missing: bool = False,
) -> dict[str, Any] | None:
    """Load evidence only from a regular, non-symlink repository file."""

    if not isinstance(relative_path, str) or not relative_path.strip():
        raise ValueError("release evidence path must be a non-empty string")
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("release evidence path must be repository-relative")
    root = repo.resolve()
    candidate = repo / relative
    if candidate.is_symlink():
        raise ValueError("release evidence path must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError("release evidence path escapes the repository") from error
    if not candidate.exists():
        if allow_missing:
            return None
        raise ValueError("release evidence file does not exist")
    if not candidate.is_file():
        raise ValueError("release evidence path must be a regular file")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("release evidence file must contain valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("release evidence JSON must be an object")
    return value


def _ids(items: object, field: str = "name") -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        value
        for item in items
        if isinstance(item, dict) and isinstance((value := item.get(field)), str)
    }


def _read_repository_contract(
    repo: Path,
    relative: str,
    *,
    label: str,
    violations: list[str],
) -> str | None:
    """Read a fixed repository contract without following symbolic links."""

    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        violations.append(f"{label} path must be repository-relative")
        return None
    candidate = repo / path
    current = repo
    for part in path.parts:
        current /= part
        if current.is_symlink():
            violations.append(f"{label} path must not use symbolic links")
            return None
    try:
        root = repo.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        violations.append(f"{label} must be a repository file")
        return None
    if not resolved.is_file():
        violations.append(f"{label} must be a repository file")
        return None
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        violations.append(f"{label} must be readable UTF-8 text")
        return None


def _named_workflow_step(source: str, name: str) -> str | None:
    marker = f"      - name: {name}\n"
    if source.count(marker) != 1:
        return None
    return source.split(marker, 1)[1].split("\n      - name:", 1)[0]


def validate_candidate_build_contract(repo: Path) -> list[str]:
    """Validate the workflow and its fixed local composite build action together."""

    violations: list[str] = []
    workflow = _read_repository_contract(
        repo,
        _APPROVED_PATHS["candidate_workflow"],
        label="candidate workflow",
        violations=violations,
    )
    if workflow is None:
        return violations

    candidate_checkout = _named_workflow_step(workflow, "Checkout immutable candidate")
    candidate_verification = _named_workflow_step(workflow, "Verify exact candidate revision")
    exact_head_verification = {
        '[[ "$CANDIDATE_REVISION" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$(git rev-parse HEAD)" == "$CANDIDATE_REVISION" ]]',
    }
    if (
        workflow.count(
            "CANDIDATE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}"
        )
        != 1
        or candidate_checkout is None
        or candidate_checkout.count("ref: ${{ env.CANDIDATE_REVISION }}") != 1
        or candidate_checkout.count("persist-credentials: false") != 1
        or candidate_verification is None
        or any(fragment not in candidate_verification for fragment in exact_head_verification)
        or workflow.count('source_epoch=$(git show -s --format=%ct "$CANDIDATE_REVISION")') != 1
        or workflow.count('source_revision="$CANDIDATE_REVISION"') != 1
        or workflow.count("name: saas-image-candidate-${{ env.CANDIDATE_REVISION }}") != 1
    ):
        violations.append(
            "candidate workflow must bind builds and evidence to the exact pull-request head"
        )

    material_sources = {
        "python_digest=$(crane digest python:3.12-slim)",
        "node_digest=$(crane digest node:22-slim)",
        'source_epoch=$(git show -s --format=%ct "$CANDIDATE_REVISION")',
        'source_revision="$CANDIDATE_REVISION"',
        "upstream_revision=$(jq -r .upstream_revision saas/upstream-baseline.json)",
        ("adapter_contract=$(jq -r .adapter_contract_version saas/upstream-baseline.json)"),
        (
            "schema_revision=$(jq -r .revision_contract.control_plane_schema_revision "
            "saas/production/baseline.json)"
        ),
    }
    if any(source not in workflow for source in material_sources):
        violations.append("candidate workflow build materials are not source-derived")

    material_exports = {
        'echo "PYTHON_IMAGE=python:3.12-slim@${python_digest}" >> "$GITHUB_ENV"',
        'echo "NODE_IMAGE=node:22-slim@${node_digest}" >> "$GITHUB_ENV"',
        'echo "SOURCE_DATE_EPOCH=${source_epoch}" >> "$GITHUB_ENV"',
        'echo "SOURCE_REVISION=${source_revision}" >> "$GITHUB_ENV"',
        'echo "UPSTREAM_REVISION=${upstream_revision}" >> "$GITHUB_ENV"',
        'echo "ADAPTER_CONTRACT_VERSION=${adapter_contract}" >> "$GITHUB_ENV"',
        ('echo "CONTROL_PLANE_SCHEMA_REVISION=${schema_revision}" >> "$GITHUB_ENV"'),
    }
    if any(workflow.count(export) != 1 for export in material_exports):
        violations.append("candidate workflow must export each resolved build material once")

    if workflow.count(f"uses: {_CANDIDATE_BUILD_USES}") != 4:
        violations.append("candidate workflow must invoke four repeated composite builds")
    if workflow.count("--label-profile executable") != 1:
        violations.append("candidate workflow must select the executable label profile")
    coordinates = {
        ("server", "runtime", "1"),
        ("server", "runtime", "2"),
        ("host", "host", "1"),
        ("host", "host", "2"),
    }
    for artifact, target, attempt in coordinates:
        invocation = (
            f"uses: {_CANDIDATE_BUILD_USES}\n"
            "        with:\n"
            f"          artifact: {artifact}\n"
            f"          target: {target}\n"
            f'          attempt: "{attempt}"'
        )
        if workflow.count(invocation) != 1:
            violations.append(
                "candidate workflow build coordinates must cover server and host twice"
            )
            break

    protected_release_fragments = {
        "environment: production-image",
        "inputs.publish_signed &&",
        "github.ref == 'refs/heads/main'",
        '[[ "$PRODUCT_REVISION" == "$TRUSTED_REVISION" ]]',
        "id-token: write",
        "attestations: write",
        "artifact-metadata: write",
        "packages: write",
        "subject-path: dist/*.whl",
        '--signer-workflow "$SIGNER_WORKFLOW"',
        "--source-ref refs/heads/main",
        '--source-digest "$PRODUCT_REVISION"',
        "production_deployment_receipt: null",
    }
    if any(fragment not in workflow for fragment in protected_release_fragments):
        violations.append("protected signed release workflow contract is incomplete")
    if workflow.count(f"uses: {_ATTEST_ACTION}") != 3:
        violations.append("protected release must sign the wheel and both OCI images")
    if workflow.count("push-to-registry: true") != 2 or workflow.count("push: true") != 2:
        violations.append("protected release must publish exactly two signed OCI images")

    action = _read_repository_contract(
        repo,
        _CANDIDATE_BUILD_ACTION,
        label="candidate composite build action",
        violations=violations,
    )
    if action is None:
        return violations
    required_action_fragments = {
        "using: composite",
        f"uses: {_BUILD_PUSH_ACTION}",
        "push: false",
        "platforms: linux/amd64,linux/arm64",
        "provenance: mode=max",
        "sbom: true",
        (
            "outputs: type=oci,dest=${{ runner.temp }}/"
            "${{ inputs.artifact }}-${{ inputs.attempt }}.tar,rewrite-timestamp=true"
        ),
        "server:runtime|host:host",
        "1|2)",
    }
    if any(fragment not in action for fragment in required_action_fragments):
        violations.append("candidate composite build action weakens the approved build contract")
    if action.count(f"uses: {_BUILD_PUSH_ACTION}") != 1:
        violations.append("candidate composite build action must use the pinned builder once")
    candidate_cache_contract = [
        "no-cache: ${{ inputs.attempt == '2' }}",
        (
            "cache-from: ${{ inputs.attempt == '1' && "
            "format('type=gha,scope=saas-{0}-candidate', inputs.artifact) || '' }}"
        ),
        (
            "cache-to: ${{ inputs.attempt == '1' && "
            "format('type=gha,scope=saas-{0}-candidate,mode=max', inputs.artifact) || '' }}"
        ),
    ]
    action_cache_lines = [
        line.strip()
        for line in action.splitlines()
        if line.strip().startswith(("no-cache:", "cache-from:", "cache-to:"))
    ]
    if action_cache_lines != candidate_cache_contract:
        violations.append("candidate attempt 2 must rebuild without shared cache")
    for build_arg in _REQUIRED_BUILD_ARGS:
        binding = f"{build_arg}=${{{{ env.{build_arg} }}}}"
        if action.count(binding) != 1:
            violations.append(f"candidate composite build action must bind resolved {build_arg}")

    n1_workflow = _read_repository_contract(
        repo,
        _N1_CANDIDATE_WORKFLOW,
        label="N-1 candidate workflow",
        violations=violations,
    )
    if n1_workflow is None:
        return violations
    if n1_workflow.count("--label-profile n1") != 2:
        violations.append(
            "N-1 candidate and publication comparisons must select the N-1 label profile"
        )
    n1_attempt_one = _named_workflow_step(
        n1_workflow,
        "Build dual-platform N-1 runtime candidate attempt 1",
    )
    n1_attempt_two = _named_workflow_step(
        n1_workflow,
        "Build dual-platform N-1 runtime candidate attempt 2",
    )
    attempt_one_cache = "type=gha,scope=saas-n1-compat-candidate"
    if (
        n1_attempt_one is None
        or n1_attempt_one.count(f"cache-from: {attempt_one_cache}") != 1
        or n1_attempt_one.count(f"cache-to: {attempt_one_cache},mode=max") != 1
        or n1_attempt_one.count(
            "outputs: type=oci,dest=${{ runner.temp }}/n1-runtime-1.tar,rewrite-timestamp=true"
        )
        != 1
        or "no-cache:" in n1_attempt_one
    ):
        violations.append(
            "N-1 candidate attempt 1 must retain the approved reproducible GHA build"
        )
    if (
        n1_attempt_two is None
        or n1_attempt_two.count("no-cache: true") != 1
        or n1_attempt_two.count(
            "outputs: type=oci,dest=${{ runner.temp }}/n1-runtime-2.tar,rewrite-timestamp=true"
        )
        != 1
        or "cache-from:" in n1_attempt_two
        or "cache-to:" in n1_attempt_two
    ):
        violations.append("N-1 candidate attempt 2 must reproducibly rebuild without shared cache")
    return violations


def validate_image_material_lock(repo: Path) -> list[str]:
    """Require image dependency installs to consume the evidenced lockfiles."""

    violations: list[str] = []
    dockerfile = _read_repository_contract(
        repo,
        _APPROVED_PATHS["dockerfile"],
        label="production Dockerfile",
        violations=violations,
    )
    uv_lock = _read_repository_contract(
        repo,
        "uv.lock",
        label="Python dependency lock",
        violations=violations,
    )
    pnpm_lock = _read_repository_contract(
        repo,
        "pnpm-lock.yaml",
        label="Node dependency lock",
        violations=violations,
    )
    cli_manifest = _read_repository_contract(
        repo,
        ".github/ci-deps/package.json",
        label="host CLI dependency manifest",
        violations=violations,
    )
    if None in (dockerfile, uv_lock, pnpm_lock, cli_manifest):
        return violations
    assert dockerfile is not None
    assert uv_lock is not None
    assert pnpm_lock is not None
    assert cli_manifest is not None

    if f"ARG UV_VERSION={_APPROVED_UV_VERSION}" not in dockerfile or not re.search(
        r'pip install[^\n]*"uv==\$\{UV_VERSION\}"', dockerfile
    ):
        violations.append("production Dockerfile must pin and install uv 0.12.1")
    if 'case "$(uv --version)" in "uv ${UV_VERSION}"|"uv ${UV_VERSION} "*' not in dockerfile:
        violations.append("production Dockerfile must verify the installed uv version")
    if "COPY pyproject.toml setup.py uv.lock ./" not in dockerfile:
        violations.append("production Dockerfile must copy the committed Python lock")
    if "sed -i '/^\\[tool\\.uv\\.workspace\\]$/,/^$/d' pyproject.toml" not in dockerfile:
        violations.append(
            "production Dockerfile must handle the excluded .github/triage_v2 workspace"
        )
    if (
        "uv sync --frozen --active --package omnigent --no-dev --no-editable --no-cache"
        not in dockerfile
    ):
        violations.append("production Dockerfile must frozen-sync the core runtime from uv.lock")
    if "uv pip install" in dockerfile:
        violations.append("production Dockerfile must not re-resolve Python dependencies")
    if "UV_NO_INSTALLER_METADATA=1" not in dockerfile:
        violations.append(
            "production Python installs must disable nondeterministic uv installer metadata"
        )
    core_bytecode_contract = {
        "> /tmp/venv-seed-pyc.sha256",
        "> /tmp/venv-core-pyc.sha256",
        "cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-core-pyc.sha256",
    }
    if (
        any(dockerfile.count(fragment) != 1 for fragment in core_bytecode_contract)
        or dockerfile.count('root.rglob("uv_cache.json")') != 2
        or dockerfile.count("python -B -I -c") < 3
    ):
        violations.append(
            "production venv must preserve seed bytecode and reject uv installer metadata"
        )
    server_bytecode_contract = {
        "> /tmp/venv-server-pyc.sha256",
        "cmp -s /tmp/venv-seed-pyc.sha256 /tmp/venv-server-pyc.sha256",
    }
    if any(dockerfile.count(fragment) != 1 for fragment in server_bytecode_contract):
        violations.append("server venv must preserve the deterministic seed bytecode manifest")

    try:
        lock_packages = tomllib.loads(uv_lock).get("package", [])
    except tomllib.TOMLDecodeError:
        violations.append("Python dependency lock must contain valid TOML")
        lock_packages = []
    psycopg_versions = {
        item.get("version")
        for item in lock_packages
        if isinstance(item, dict) and item.get("name") == "psycopg"
    }
    if psycopg_versions != {_APPROVED_PSYCOPG_VERSION}:
        violations.append("uv.lock must resolve psycopg exactly to 3.3.4")
    if (
        f"ARG PSYCOPG_VERSION={_APPROVED_PSYCOPG_VERSION}" not in dockerfile
        or "set -- --extra saas" not in dockerfile
        or "installed=\"$(python -c 'import importlib.metadata as m; "
        'print(m.version("psycopg"))\')"'
        not in dockerfile
    ):
        violations.append("server image must frozen-sync saas and assert psycopg 3.3.4")

    if f"ARG PNPM_VERSION={_APPROVED_PNPM_VERSION}" not in dockerfile or not re.search(
        r'npm install -g[^\n]*"pnpm@\$\{PNPM_VERSION\}"', dockerfile
    ):
        violations.append("production Dockerfile must pin pnpm 11.15.1")
    if "COPY pnpm-workspace.yaml pnpm-lock.yaml ./" not in dockerfile:
        violations.append("host image must copy the committed pnpm lock")
    if "pnpm install --frozen-lockfile --prod --filter e2e-ci-deps" not in dockerfile:
        violations.append("host CLI dependency graph must install from pnpm-lock.yaml")
    host_marker = "FROM ${PYTHON_IMAGE} AS host"
    runtime_marker = "FROM ${PYTHON_IMAGE} AS runtime"
    builder_marker = "FROM ${PYTHON_IMAGE} AS builder"
    server_builder_marker = "FROM builder AS server-builder"
    stage_markers = (builder_marker, server_builder_marker, host_marker, runtime_marker)
    if any(dockerfile.count(marker) != 1 for marker in stage_markers):
        violations.append("production Dockerfile must retain the approved executable stages")
        builder_stage = host_stage = runtime_stage = ""
    else:
        builder_stage = dockerfile.split(builder_marker, 1)[1].split(server_builder_marker, 1)[0]
        host_stage = dockerfile.split(host_marker, 1)[1].split(runtime_marker, 1)[0]
        runtime_stage = dockerfile.split(runtime_marker, 1)[1]
    apt_reproducibility_contract = {
        "ARG SOURCE_DATE_EPOCH",
        "case \"${SOURCE_DATE_EPOCH}\" in *[!0-9]*|'') exit 2 ;; esac;",
        "/etc/apt/sources.list.d/debian.sources",
        "snapshot[.]debian[.]org/archive/",
        "expected two Debian snapshot sources",
        "len(uris) == 2",
        "all(re.fullmatch",
        'sum("/archive/debian/" in uri for uri in uris) == 1',
        "VERSION_CODENAME",
        "Debian snapshot coordinates",
        "Acquire::Check-Valid-Until=false",
        "export DEBIAN_FRONTEND=noninteractive;",
        "apt-get clean",
        "rm -rf /var/lib/apt/lists/* /var/cache/apt/*",
        "rm -f /var/cache/ldconfig/aux-cache",
        "/var/log/alternatives.log",
        "/var/log/dpkg.log",
        "/var/log/apt/eipp.log.xz",
        "/var/log/apt/history.log",
        "/var/log/apt/term.log",
    }
    if any(
        fragment not in stage
        for stage in (builder_stage, host_stage, runtime_stage)
        for fragment in apt_reproducibility_contract
    ):
        violations.append(
            "builder, host and server apt layers must use a fixed snapshot "
            "and remove volatile state"
        )
    host_cli_reproducibility_contract = {
        "ARG SOURCE_DATE_EPOCH",
        "npm_config_cache=/tmp/npm-cache",
        "--store-dir /tmp/pnpm-store",
        "--package-import-method=copy",
        'modules=Path("node_modules/.modules.yaml")',
        "prunedAt:",
        'state=Path("node_modules/.pnpm-workspace-state-v1.json")',
        "state.unlink()",
        "HOME=/tmp/omnigent-cli-home XDG_CACHE_HOME=/tmp/omnigent-cli-cache",
        "rm -rf /tmp/npm-cache /tmp/pnpm-store",
        "/root/.npm /root/.cache /root/.local/share/pnpm",
        "test ! -e node_modules/.pnpm-workspace-state-v1.json",
    }
    if any(fragment not in host_stage for fragment in host_cli_reproducibility_contract):
        violations.append("host CLI layer must normalize and remove volatile installer state")
    cli_bin_path = "/opt/omnigent-host-cli/.github/ci-deps/node_modules/.bin"
    if f'ENV PATH="{cli_bin_path}:${{PATH}}"' not in dockerfile or re.search(
        rf"ln -s\s+{re.escape(cli_bin_path)}/(?:claude|codex|pi)\s+",
        dockerfile,
    ):
        violations.append("host CLI wrappers must execute from their pnpm installation directory")

    try:
        cli_dependencies = json.loads(cli_manifest).get("dependencies", {})
    except json.JSONDecodeError:
        violations.append("host CLI dependency manifest must contain valid JSON")
        cli_dependencies = {}
    expected_dependencies = {
        package: version for package, (_, version) in _APPROVED_HOST_CLI_VERSIONS.items()
    }
    if cli_dependencies != expected_dependencies:
        violations.append("host CLI dependency manifest does not match approved direct versions")
    for package, (argument, version) in _APPROVED_HOST_CLI_VERSIONS.items():
        if f"ARG {argument}={version}" not in dockerfile:
            violations.append(f"host image must pin {package} to {version}")
        importer = re.compile(
            rf"'{re.escape(package)}':\n\s+specifier: {re.escape(version)}\n"
            rf"\s+version: {re.escape(version)}(?:\n|\()"
        )
        if importer.search(pnpm_lock) is None:
            violations.append(f"pnpm-lock.yaml must bind {package} to {version}")
    if re.search(
        r"npm install -g[^\n]*(?:@anthropic-ai/claude-code|@openai/codex|"
        r"@earendil-works/pi-coding-agent)",
        dockerfile,
    ):
        violations.append("host CLIs must not bypass pnpm-lock.yaml via npm install")
    return violations


def _validate_policy(repo: Path, policy: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if set(policy) != _POLICY_FIELDS:
        violations.append("release policy fields do not match schema version 2")
    if not _exact_integer(policy.get("schema_version"), 2):
        violations.append("release policy schema_version must be 2")
    if policy.get("policy_id") != "omnigent-saas-production-image-v2":
        violations.append("release policy_id must match the approved v2 contract")
    if _parse_time(f"{policy.get('reviewed_at')}T00:00:00Z") is None:
        violations.append("release policy reviewed_at must be an ISO date")
    for field in ("candidate_workflow", "release_runbook", "dockerfile", "upstream_manifest"):
        value = policy.get(field)
        if value != _APPROVED_PATHS[field] or not (repo / str(value)).is_file():
            violations.append(f"release policy {field} must reference the approved file")
    violations.extend(validate_candidate_build_contract(repo))
    violations.extend(validate_image_material_lock(repo))
    production_evidence = policy.get("production_evidence")
    if production_evidence != _APPROVED_PATHS["production_evidence"]:
        violations.append("production_evidence must use the approved repository path")

    images = policy.get("images")
    if (
        not isinstance(images, list)
        or len(images) != 2
        or _ids(images) != {"omnigent-saas-server", "omnigent-saas-host"}
    ):
        violations.append("release policy must define server and host images")
    if isinstance(images, list):
        for image in images:
            if not isinstance(image, dict):
                violations.append("image policy entries must be objects")
                continue
            if set(image) != _POLICY_IMAGE_FIELDS:
                violations.append("image policy fields do not match schema version 2")
            name = image.get("name", "unknown")
            approved_image = _REQUIRED_IMAGES.get(str(name))
            if approved_image is None or image.get("target") != approved_image["target"]:
                violations.append(f"{name} does not use the approved Docker target")
            if _string_set(image.get("platforms")) != {"linux/amd64", "linux/arm64"}:
                violations.append(f"{name} must require amd64 and arm64")
            approved_smoke = approved_image["smoke"] if approved_image else set()
            if _string_set(image.get("required_smoke")) != approved_smoke:
                violations.append(f"{name} does not use the approved smoke probes")

    reproducibility = policy.get("reproducibility")
    required_args: set[str] = set()
    if not isinstance(reproducibility, dict):
        violations.append("release policy reproducibility must be an object")
    else:
        if set(reproducibility) != _REPRODUCIBILITY_POLICY_FIELDS:
            violations.append("reproducibility policy fields do not match schema version 2")
        if reproducibility.get("source_date_epoch") != "product-commit-timestamp":
            violations.append("SOURCE_DATE_EPOCH must come from the product commit")
        for field in (
            "base_images_must_be_digest_pinned",
            "clean_tree_required",
            "matching_platform_manifest_and_config_required",
        ):
            if reproducibility.get(field) is not True:
                violations.append(f"reproducibility.{field} must be true")
        if not _exact_integer(reproducibility.get("repeat_builds"), 2):
            violations.append("production images require two repeated builds")
        locks = reproducibility.get("dependency_locks")
        if _string_set(locks) != _REQUIRED_LOCKFILES or any(
            not (repo / path).is_file() for path in _REQUIRED_LOCKFILES
        ):
            violations.append("dependency locks do not match the approved set")
        args = reproducibility.get("required_build_args")
        parsed_args = _string_set(args)
        if parsed_args is not None:
            required_args = parsed_args
        if required_args != _REQUIRED_BUILD_ARGS:
            violations.append("required_build_args does not match the reproducible build contract")

    dockerfile_path = policy.get("dockerfile")
    if _string_set(policy.get("required_labels")) != _REQUIRED_LABELS:
        violations.append("required_labels does not match the approved image labels")
    if isinstance(dockerfile_path, str) and (repo / dockerfile_path).is_file():
        dockerfile = (repo / dockerfile_path).read_text(encoding="utf-8")
        for build_arg in required_args:
            if f"ARG {build_arg}" not in dockerfile:
                violations.append(f"Dockerfile does not declare {build_arg}")
        for label in _REQUIRED_LABELS:
            if label not in dockerfile:
                violations.append(f"Dockerfile does not emit label {label}")
        if "COPY saas/ ./saas/" not in dockerfile:
            violations.append("production Dockerfile does not package the SaaS boundary")
    setup = (repo / "setup.py").read_text(encoding="utf-8")
    if 'os.environ.get("SOURCE_DATE_EPOCH")' not in setup:
        violations.append("build metadata does not honor SOURCE_DATE_EPOCH")

    attestations = policy.get("attestations")
    if not isinstance(attestations, dict):
        violations.append("attestations policy must be an object")
    else:
        if set(attestations) != _ATTESTATION_POLICY_FIELDS:
            violations.append("attestation policy fields do not match schema version 2")
        if attestations.get("provenance_predicate") != "https://slsa.dev/provenance/v1":
            violations.append("SLSA provenance v1 is required")
        if attestations.get("provenance_mode") != "max":
            violations.append("maximum provenance mode is required")
        if _string_set(attestations.get("sbom_formats")) != {
            "spdx-json",
            "cyclonedx-json",
        }:
            violations.append("SPDX and CycloneDX SBOMs are required")
        for field in (
            "keyless_signature_required",
            "signature_subject_digest_required",
            "transparency_log_required",
            "protected_workflow_identity_required",
        ):
            if attestations.get(field) is not True:
                violations.append(f"attestations.{field} must be true")
        expected_trust = {
            "signature_issuer": "https://token.actions.githubusercontent.com",
            "trusted_repository": "Dream1216/omnigent",
            "trusted_workflow_ref": (".github/workflows/saas-image-candidate.yml@refs/heads/main"),
            "trusted_workflow_identity": (
                "https://github.com/Dream1216/omnigent/.github/workflows/"
                "saas-image-candidate.yml@refs/heads/main"
            ),
            "trusted_oidc_subject": ("repo:Dream1216/omnigent:environment:production-image"),
            "trusted_builder_id": "https://github.com/actions/runner",
            "trusted_environment": "production-image",
        }
        for field, expected in expected_trust.items():
            if attestations.get(field) != expected:
                violations.append(f"attestations.{field} does not match the trust root")

    regression = policy.get("regression")
    if not isinstance(regression, dict):
        violations.append("regression policy must be an object")
    else:
        if set(regression) != _REGRESSION_POLICY_FIELDS:
            violations.append("regression policy fields do not match schema version 2")
        suites = regression.get("official_suites")
        if _string_set(suites) != _REQUIRED_OFFICIAL_SUITES or any(
            not (repo / path).is_file() for path in _REQUIRED_OFFICIAL_SUITES
        ):
            violations.append("official OSS regression suites do not match the approved set")
        if regression.get("saas_suite") != "tests/saas" or not (repo / "tests/saas").is_dir():
            violations.append("the complete SaaS test suite is required")
        for field in (
            "real_postgresql_required",
            "chromium_required",
            "migration_upgrade_check_downgrade_required",
            "patch_replay_required",
            "source_intrusion_budget_required",
        ):
            if regression.get(field) is not True:
                violations.append(f"regression.{field} must be true")

    vulnerabilities = policy.get("vulnerability_policy")
    if not isinstance(vulnerabilities, dict):
        violations.append("vulnerability_policy must be an object")
    else:
        if set(vulnerabilities) != _VULNERABILITY_POLICY_FIELDS:
            violations.append("vulnerability policy fields do not match schema version 2")
        if not _exact_integer(vulnerabilities.get("critical_allowed"), 0) or not (
            _exact_integer(vulnerabilities.get("high_allowed"), 0)
        ):
            violations.append("critical and high vulnerability thresholds must both be zero")
        if (
            vulnerabilities.get("exceptions_require_owner_expiry_and_compensating_control")
            is not True
        ):
            violations.append("vulnerability exceptions require owner, expiry, and control")
        if not _exact_integer(vulnerabilities.get("maximum_scanner_database_age_hours"), 24):
            violations.append("scanner database age must be limited to 24 hours")

    licenses = policy.get("license_policy")
    if not isinstance(licenses, dict):
        violations.append("license_policy must be an object")
    else:
        if set(licenses) != _LICENSE_POLICY_FIELDS:
            violations.append("license policy fields do not match schema version 2")
        if licenses.get("policy_id") != "omnigent-saas-license-admission-v1":
            violations.append("license policy_id must match the approved contract")
        if not _exact_integer(
            licenses.get("denied_license_count_allowed"), 0
        ) or not _exact_integer(licenses.get("unknown_license_count_allowed"), 0):
            violations.append("denied and unknown license thresholds must both be zero")
        if licenses.get("exceptions_require_legal_approval_and_expiry") is not True:
            violations.append("license exceptions require legal approval and expiry")

    promotion = policy.get("promotion")
    if not isinstance(promotion, dict):
        violations.append("promotion policy must be an object")
    else:
        if set(promotion) != _PROMOTION_POLICY_FIELDS:
            violations.append("promotion policy fields do not match schema version 2")
        for field in ("digest_only_deployment", "n_minus_one_digest_required", "canary_required"):
            if promotion.get(field) is not True:
                violations.append(f"promotion.{field} must be true")
        if promotion.get("floating_tag_may_authorize_deployment") is not False:
            violations.append("floating tags must not authorize deployment")
        if promotion.get("allowed_registry_hosts") != ["ghcr.io"]:
            violations.append("production images must use the approved registry host")
        if promotion.get("canary_environment") != "production-canary":
            violations.append("production canary environment is invalid")
        if not _exact_integer(promotion.get("minimum_canary_observation_seconds"), 3600):
            violations.append("production canary observation must be at least one hour")
        if not _exact_integer(promotion.get("maximum_n_minus_one_rollback_seconds"), 900):
            violations.append("N-1 rollback must complete within 900 seconds")
        roles = promotion.get("required_approval_roles")
        role_set = _string_set(roles)
        if (
            not isinstance(roles, list)
            or len(roles) != 3
            or role_set
            != {
                "release-engineering",
                "security",
                "site-reliability",
            }
        ):
            violations.append("promotion requires three distinct approval roles")
        if not _exact_integer(promotion.get("maximum_evidence_age_days"), 30):
            violations.append("production image evidence age must be limited to 30 days")
    return violations


def _validate_workflow(policy: dict[str, Any], workflow: object) -> list[str]:
    if not isinstance(workflow, dict):
        return ["image evidence workflow must be an object"]
    violations: list[str] = []
    if set(workflow) != _WORKFLOW_FIELDS:
        violations.append("image evidence workflow fields do not match schema version 2")
    trust = policy["attestations"]
    expected = {
        "repository": trust["trusted_repository"],
        "workflow_ref": trust["trusted_workflow_ref"],
        "source_ref": "refs/heads/main",
        "source_ref_protected": True,
        "oidc_subject": trust["trusted_oidc_subject"],
        "builder_id": trust["trusted_builder_id"],
        "environment": trust["trusted_environment"],
        "environment_protection_verified": True,
        "conclusion": "success",
    }
    for field, value in expected.items():
        if not _exact_scalar(workflow.get(field), value):
            violations.append(f"image evidence workflow.{field} is not trusted")
    for field in ("run_id", "run_attempt"):
        if _positive_integer(workflow.get(field)) is None:
            violations.append(f"image evidence workflow.{field} must be positive")
    return violations


def _validate_image(
    policy: dict[str, Any],
    image: dict[str, Any],
    *,
    expected: dict[str, Any],
    product_revision: object,
    evidence: dict[str, Any],
    completed_at: datetime | None,
) -> tuple[list[str], datetime | None]:
    violations: list[str] = []
    name = str(image.get("name", "unknown"))
    if set(image) != _IMAGE_FIELDS:
        violations.append(f"{name} image fields do not match schema version 2")
    if image.get("target") != expected.get("target"):
        violations.append(f"{name} target does not match policy")
    manifest_digest = image.get("manifest_digest")
    if not isinstance(manifest_digest, str) or not _SHA256.fullmatch(manifest_digest):
        violations.append(f"{name} manifest digest is invalid")
    for field in ("platform_digests", "config_digests"):
        values = image.get(field)
        if not isinstance(values, dict) or set(values) != set(expected.get("platforms", [])):
            violations.append(f"{name} {field} does not cover every platform")
        elif any(
            not isinstance(value, str) or not _SHA256.fullmatch(value) for value in values.values()
        ):
            violations.append(f"{name} {field} contains an invalid digest")
    labels = image.get("labels")
    if not isinstance(labels, dict) or set(labels) != set(policy.get("required_labels", [])):
        violations.append(f"{name} labels do not match policy")
    else:
        expected_labels = {
            "org.opencontainers.image.revision": product_revision,
            "ai.omnigent.upstream.revision": evidence.get("upstream_revision"),
            "ai.omnigent.saas.schema-revision": evidence.get("control_plane_schema_revision"),
            "ai.omnigent.saas.adapter-contract-version": evidence.get("adapter_contract_version"),
        }
        if labels != expected_labels:
            violations.append(f"{name} labels do not bind the evidence revisions")

    sbom = image.get("sbom")
    if not isinstance(sbom, dict) or set(sbom) != _SBOM_FIELDS:
        violations.append(f"{name} SBOM evidence is incomplete")
    else:
        for field in ("spdx_sha256", "cyclonedx_sha256"):
            if not _hex_sha256(sbom.get(field)):
                violations.append(f"{name} SBOM {field} is invalid")
        if sbom.get("subject_digest") != manifest_digest:
            violations.append(f"{name} SBOM subject does not match the image")
        for field in ("spdx_uri", "cyclonedx_uri"):
            if not _secret_free_uri(sbom.get(field), {"oci"}):
                violations.append(f"{name} SBOM {field} is not an immutable OCI URI")
            elif isinstance(manifest_digest, str) and manifest_digest not in str(sbom.get(field)):
                violations.append(f"{name} SBOM {field} does not bind the image digest")

    trust = policy["attestations"]
    provenance = image.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != _PROVENANCE_FIELDS:
        violations.append(f"{name} provenance evidence is incomplete")
    else:
        expected_provenance = {
            "verified": True,
            "predicate_type": trust["provenance_predicate"],
            "subject_digest": manifest_digest,
            "materials_digest_pinned": True,
            "builder_id": trust["trusted_builder_id"],
            "source_revision": product_revision,
            "workflow_ref": trust["trusted_workflow_ref"],
        }
        for field, value in expected_provenance.items():
            if not _exact_scalar(provenance.get(field), value):
                violations.append(f"{name} provenance {field} is invalid")
        if not _hex_sha256(provenance.get("statement_sha256")):
            violations.append(f"{name} provenance statement_sha256 is invalid")

    signature = image.get("signature")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_FIELDS:
        violations.append(f"{name} signature evidence is incomplete")
    else:
        expected_signature = {
            "verified": True,
            "issuer": trust["signature_issuer"],
            "workflow_identity": trust["trusted_workflow_identity"],
            "oidc_subject": trust["trusted_oidc_subject"],
            "subject_digest": manifest_digest,
            "transparency_log_verified": True,
        }
        for field, value in expected_signature.items():
            if not _exact_scalar(signature.get(field), value):
                violations.append(f"{name} signature {field} is invalid")
        for field in ("transparency_log_entry_sha256", "bundle_sha256"):
            if not _hex_sha256(signature.get(field)):
                violations.append(f"{name} signature {field} is invalid")

    scan_at: datetime | None = None
    scan = image.get("vulnerabilities")
    if not isinstance(scan, dict) or set(scan) != _VULNERABILITY_FIELDS:
        violations.append(f"{name} vulnerability evidence is incomplete")
    else:
        if not isinstance(scan.get("scanner"), str) or not scan["scanner"].strip():
            violations.append(f"{name} vulnerability scanner identity is required")
        if scan.get("subject_digest") != manifest_digest:
            violations.append(f"{name} vulnerability scan subject does not match the image")
        if not _hex_sha256(scan.get("report_sha256")):
            violations.append(f"{name} vulnerability report SHA-256 is invalid")
        if not _exact_integer(scan.get("critical"), 0) or not _exact_integer(scan.get("high"), 0):
            violations.append(f"{name} exceeds the vulnerability threshold")
        if scan.get("exceptions") != []:
            violations.append(f"{name} release evidence cannot carry vulnerability exceptions")
        database_at = _parse_time(scan.get("scanner_database_updated_at"))
        scan_at = _parse_time(scan.get("scan_completed_at"))
        if (
            database_at is None
            or scan_at is None
            or database_at > scan_at
            or scan_at - database_at
            > timedelta(hours=policy["vulnerability_policy"]["maximum_scanner_database_age_hours"])
        ):
            violations.append(f"{name} vulnerability scanner database is stale")
        if completed_at is not None and (scan_at is None or scan_at > completed_at):
            violations.append(f"{name} vulnerability scan completion is invalid")
        elif (
            completed_at is not None
            and scan_at is not None
            and completed_at - scan_at > timedelta(hours=24)
        ):
            violations.append(f"{name} vulnerability scan is older than release evidence")

    licenses = image.get("licenses")
    if not isinstance(licenses, dict) or set(licenses) != _LICENSE_FIELDS:
        violations.append(f"{name} license evidence is incomplete")
    else:
        license_policy = policy["license_policy"]
        if not isinstance(licenses.get("scanner"), str) or not licenses["scanner"].strip():
            violations.append(f"{name} license scanner identity is required")
        if licenses.get("subject_digest") != manifest_digest:
            violations.append(f"{name} license report subject does not match the image")
        if licenses.get("policy_id") != license_policy["policy_id"]:
            violations.append(f"{name} license report does not bind the policy")
        if not _hex_sha256(licenses.get("report_sha256")):
            violations.append(f"{name} license report SHA-256 is invalid")
        if not _exact_integer(
            licenses.get("denied_license_count"),
            license_policy["denied_license_count_allowed"],
        ) or not _exact_integer(
            licenses.get("unknown_license_count"),
            license_policy["unknown_license_count_allowed"],
        ):
            violations.append(f"{name} exceeds the license admission threshold")
        if licenses.get("exceptions") != []:
            violations.append(f"{name} release evidence cannot carry license exceptions")

    admission_at = _parse_time(image.get("admission_completed_at"))
    if (
        admission_at is None
        or completed_at is None
        or admission_at > completed_at
        or (scan_at is not None and admission_at < scan_at)
    ):
        violations.append(f"{name} admission completion time is invalid")

    smoke = image.get("smoke_passed")
    if _string_set(smoke) != _string_set(expected.get("required_smoke")):
        violations.append(f"{name} smoke evidence does not match policy")
    return violations, admission_at


def _validate_promotion(
    policy: dict[str, Any],
    promotion: object,
    *,
    image_digests: dict[str, str],
    image_admission_times: dict[str, datetime],
    evidence_completed_at: datetime | None,
) -> tuple[list[str], datetime | None]:
    if not isinstance(promotion, dict) or set(promotion) != _PROMOTION_FIELDS:
        return ["image promotion evidence is incomplete"], None
    values = promotion.get("images")
    if (
        not isinstance(values, list)
        or _ids(values) != set(image_digests)
        or len(values) != len(image_digests)
    ):
        return ["image promotion evidence does not cover every policy image"], None
    violations: list[str] = []
    latest_completion: datetime | None = None
    contract = policy["promotion"]
    for raw in values:
        if not isinstance(raw, dict):
            violations.append("image promotion entries must be objects")
            continue
        name = str(raw.get("name", "unknown"))
        if set(raw) != _IMAGE_PROMOTION_FIELDS:
            violations.append(f"{name} promotion fields do not match schema version 2")
        digest = image_digests.get(name)
        registry_ref = raw.get("registry_ref")
        if not isinstance(registry_ref, str) or not _PINNED_IMAGE.fullmatch(registry_ref):
            violations.append(f"{name} registry_ref must be digest-pinned")
        else:
            registry_host = registry_ref.split("/", 1)[0]
            if registry_host not in set(contract["allowed_registry_hosts"]):
                violations.append(f"{name} registry host is not approved")
            if registry_ref.rsplit("@", 1)[-1] != digest:
                violations.append(f"{name} registry_ref does not bind the candidate digest")
        if raw.get("registry_immutable") is not True:
            violations.append(f"{name} registry immutability is not verified")
        if not _hex_sha256(raw.get("registry_immutability_receipt_sha256")):
            violations.append(f"{name} registry immutability receipt is invalid")

        canary = raw.get("canary")
        canary_completed: datetime | None = None
        if not isinstance(canary, dict) or set(canary) != _CANARY_FIELDS:
            violations.append(f"{name} canary evidence is incomplete")
        else:
            started = _parse_time(canary.get("started_at"))
            completed = _parse_time(canary.get("completed_at"))
            observation = _positive_integer(canary.get("observation_seconds"))
            if (
                started is None
                or completed is None
                or completed < started
                or observation is None
                or completed - started != timedelta(seconds=observation)
            ):
                violations.append(f"{name} canary observation window is invalid")
            elif observation < contract["minimum_canary_observation_seconds"]:
                violations.append(f"{name} canary observation is shorter than policy")
            if completed is not None and (
                evidence_completed_at is None or completed > evidence_completed_at
            ):
                violations.append(f"{name} canary completed after release evidence")
            admission_at = image_admission_times.get(name)
            if started is None or admission_at is None or started < admission_at:
                violations.append(f"{name} canary started before image admission completed")
            canary_completed = completed
            if latest_completion is None or (
                completed is not None and completed > latest_completion
            ):
                latest_completion = completed
            expected_canary = {
                "environment": contract["canary_environment"],
                "deployed_digest": digest,
                "slo_gate_passed": True,
                "security_gate_passed": True,
                "result": "passed",
            }
            for field, value in expected_canary.items():
                if not _exact_scalar(canary.get(field), value):
                    violations.append(f"{name} canary {field} is invalid")
            if not _hex_sha256(canary.get("evidence_sha256")):
                violations.append(f"{name} canary evidence SHA-256 is invalid")

        rollback = raw.get("n_minus_one_rollback")
        if not isinstance(rollback, dict) or set(rollback) != _ROLLBACK_FIELDS:
            violations.append(f"{name} N-1 rollback evidence is incomplete")
        else:
            started = _parse_time(rollback.get("started_at"))
            completed = _parse_time(rollback.get("completed_at"))
            recovery = _positive_integer(rollback.get("recovery_seconds"))
            if (
                started is None
                or completed is None
                or completed < started
                or recovery is None
                or completed - started != timedelta(seconds=recovery)
            ):
                violations.append(f"{name} N-1 rollback window is invalid")
            elif recovery > contract["maximum_n_minus_one_rollback_seconds"]:
                violations.append(f"{name} N-1 rollback exceeded policy")
            if completed is not None and (
                evidence_completed_at is None or completed > evidence_completed_at
            ):
                violations.append(f"{name} N-1 rollback completed after release evidence")
            if started is None or canary_completed is None or started < canary_completed:
                violations.append(f"{name} N-1 rollback started before canary completed")
            if latest_completion is None or (
                completed is not None and completed > latest_completion
            ):
                latest_completion = completed
            if rollback.get("from_digest") != digest:
                violations.append(f"{name} N-1 rollback source is not the candidate")
            target = rollback.get("to_digest")
            if not isinstance(target, str) or not _SHA256.fullmatch(target) or target == digest:
                violations.append(f"{name} N-1 rollback target is invalid")
            target_ref = rollback.get("to_registry_ref")
            if not isinstance(target_ref, str) or not _PINNED_IMAGE.fullmatch(target_ref):
                violations.append(f"{name} N-1 rollback registry target is invalid")
            else:
                registry_host = target_ref.split("/", 1)[0]
                if registry_host not in set(contract["allowed_registry_hosts"]):
                    violations.append(f"{name} N-1 rollback registry host is not approved")
                if target_ref.rsplit("@", 1)[-1] != target:
                    violations.append(f"{name} N-1 rollback registry target is not bound")
            if rollback.get("previous_release_signature_verified") is not True:
                violations.append(f"{name} N-1 target signature is not verified")
            if rollback.get("previous_release_provenance_verified") is not True:
                violations.append(f"{name} N-1 target provenance is not verified")
            if rollback.get("result") != "passed":
                violations.append(f"{name} N-1 rollback did not pass")
            if not _hex_sha256(rollback.get("evidence_sha256")):
                violations.append(f"{name} N-1 rollback evidence SHA-256 is invalid")
    return violations, latest_completion


def _validate_release_attestations(
    policy: dict[str, Any],
    value: object,
    *,
    product_revision: object,
    operations_completed_at: datetime | None,
    evidence_completed_at: datetime | None,
) -> list[str]:
    if not isinstance(value, list):
        return ["release attestations must be a list"]
    violations: list[str] = []
    roles: set[str] = set()
    actors: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict):
            violations.append("release attestation entries must be objects")
            continue
        if set(raw) != _ATTESTATION_FIELDS:
            violations.append("release attestation fields do not match schema version 2")
        role = raw.get("role")
        actor = raw.get("actor_id_hash")
        if not isinstance(role, str) or role in roles:
            violations.append("release attestation roles must be unique")
        else:
            roles.add(role)
        if not isinstance(actor, str) or not _hex_sha256(actor) or actor in actors:
            violations.append("release attestation actors must be distinct SHA-256 identities")
        else:
            actors.add(actor)
        attested_at = _parse_time(raw.get("attested_at"))
        if (
            attested_at is None
            or operations_completed_at is None
            or evidence_completed_at is None
            or attested_at < operations_completed_at
            or attested_at > evidence_completed_at
        ):
            violations.append("release attestation time is outside the approval window")
        if raw.get("product_revision") != product_revision:
            violations.append("release attestation revision does not match evidence")
    if roles != set(policy["promotion"]["required_approval_roles"]):
        violations.append("release attestations do not cover every approval role")
    return violations


def _validate_evidence(
    repo: Path,
    policy: dict[str, Any],
    evidence: dict[str, Any],
    *,
    now: datetime,
    expected_product_revision: str | None,
) -> list[str]:
    violations: list[str] = []
    if set(evidence) != _EVIDENCE_FIELDS:
        violations.append("image evidence fields do not match schema version 2")
    if not _exact_integer(evidence.get("evidence_version"), 2):
        violations.append("image evidence version must be 2")
    completed_at = _parse_time(evidence.get("completed_at"))
    maximum_age = policy["promotion"]["maximum_evidence_age_days"]
    if completed_at is None or completed_at > now:
        violations.append("image evidence completed_at is invalid")
    elif now - completed_at > timedelta(days=maximum_age):
        violations.append("image evidence is older than policy")

    product_revision = evidence.get("product_revision")
    if not isinstance(product_revision, str) or not _GIT_SHA.fullmatch(product_revision):
        violations.append("image evidence product_revision must be a full Git SHA")
    elif expected_product_revision is not None and product_revision != expected_product_revision:
        violations.append("image evidence product_revision does not match the release candidate")

    upstream = json.loads((repo / str(policy["upstream_manifest"])).read_text(encoding="utf-8"))
    for field in ("upstream_revision", "adapter_contract_version"):
        if evidence.get(field) != upstream.get(field):
            violations.append(f"image evidence {field} does not match the upstream manifest")
    baseline = json.loads((repo / "saas/production/baseline.json").read_text(encoding="utf-8"))
    schema_revision = baseline["revision_contract"]["control_plane_schema_revision"]
    if evidence.get("control_plane_schema_revision") != schema_revision:
        violations.append("image evidence schema revision does not match production baseline")

    violations.extend(_validate_workflow(policy, evidence.get("workflow")))

    materials = evidence.get("materials")
    if not isinstance(materials, dict) or set(materials) != {
        "base_images",
        "lockfiles",
        "dockerfile_sha256",
    }:
        violations.append("image evidence materials are incomplete")
    else:
        bases = materials.get("base_images")
        if not isinstance(bases, dict) or set(bases) != {"python", "node"}:
            violations.append("image evidence must record Python and Node base images")
        elif any(
            not isinstance(ref, str) or not _PINNED_IMAGE.fullmatch(ref) for ref in bases.values()
        ):
            violations.append("every base image material must be digest-pinned")
        locks = materials.get("lockfiles")
        expected_locks = set(policy["reproducibility"]["dependency_locks"])
        if not isinstance(locks, dict) or set(locks) != expected_locks:
            violations.append("image evidence lockfile set is incomplete")
        elif any(not _hex_sha256(digest) for digest in locks.values()):
            violations.append("image evidence lockfile hashes must be SHA-256")
        else:
            for path, digest in locks.items():
                if _sha256(repo / path) != digest:
                    violations.append(f"image evidence lock hash drifted for {path}")
        if materials.get("dockerfile_sha256") != _sha256(repo / str(policy["dockerfile"])):
            violations.append("image evidence Dockerfile hash drifted")

    images = evidence.get("images")
    policy_images = {
        image["name"]: image for image in policy.get("images", []) if isinstance(image, dict)
    }
    image_digests: dict[str, str] = {}
    image_admission_times: dict[str, datetime] = {}
    if (
        not isinstance(images, list)
        or len(images) != len(policy_images)
        or _ids(images) != set(policy_images)
    ):
        violations.append("image evidence does not cover every policy image exactly once")
    else:
        for image in images:
            if not isinstance(image, dict):
                violations.append("image evidence entries must be objects")
                continue
            name = str(image.get("name", "unknown"))
            manifest_digest = image.get("manifest_digest")
            if isinstance(manifest_digest, str):
                image_digests[name] = manifest_digest
            image_violations, admission_at = _validate_image(
                policy,
                image,
                expected=policy_images.get(name, {}),
                product_revision=product_revision,
                evidence=evidence,
                completed_at=completed_at,
            )
            violations.extend(image_violations)
            if admission_at is not None:
                image_admission_times[name] = admission_at

    rebuild = evidence.get("rebuild")
    if not isinstance(rebuild, dict) or set(rebuild) != {
        "attempts",
        "matching_platform_manifest_and_config",
    }:
        violations.append("image evidence rebuild is incomplete")
    else:
        if not _exact_integer(rebuild.get("attempts"), policy["reproducibility"]["repeat_builds"]):
            violations.append("image evidence repeat-build count is invalid")
        if rebuild.get("matching_platform_manifest_and_config") is not True:
            violations.append("repeat builds did not reproduce platform manifests and configs")

    regression = evidence.get("regression")
    required_regression = {
        "official_suites",
        "saas_suite",
        "real_postgresql",
        "chromium",
        "migration_cycle",
        "patch_replay",
        "source_intrusion_budget",
    }
    if not isinstance(regression, dict) or set(regression) != required_regression:
        violations.append("image evidence regression matrix is incomplete")
    elif any(value is not True for value in regression.values()):
        violations.append("an image regression gate did not pass")

    promotion_violations, operations_completed_at = _validate_promotion(
        policy,
        evidence.get("promotion"),
        image_digests=image_digests,
        image_admission_times=image_admission_times,
        evidence_completed_at=completed_at,
    )
    violations.extend(promotion_violations)
    violations.extend(
        _validate_release_attestations(
            policy,
            evidence.get("attestations"),
            product_revision=product_revision,
            operations_completed_at=operations_completed_at,
            evidence_completed_at=completed_at,
        )
    )
    if not _hex_sha256(evidence.get("evidence_sha256")) or evidence.get(
        "evidence_sha256"
    ) != canonical_release_evidence_sha256(evidence):
        violations.append("image evidence SHA-256 does not authenticate the canonical record")
    return violations


def validate_release(
    repo: Path,
    policy: dict[str, Any],
    evidence: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    expected_product_revision: str | None = None,
) -> dict[str, Any]:
    """Return policy validity separately from production promotion readiness."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    violations = _validate_policy(repo, policy)
    blockers: list[str] = []
    evidence_violations: list[str] = []
    if evidence is None:
        blockers.append("no immutable signed production image evidence is recorded")
    elif violations:
        blockers.append("release policy must be valid before evidence can qualify")
    else:
        evidence_violations = _validate_evidence(
            repo,
            policy,
            evidence,
            now=current,
            expected_product_revision=expected_product_revision,
        )
        blockers.extend(evidence_violations)
    return {
        "status": "pass" if not violations else "fail",
        "production_readiness": (
            "ready"
            if not violations and evidence is not None and not evidence_violations
            else "blocked"
        ),
        "violations": sorted(set(violations)),
        "blockers": sorted(set(blockers)),
        "metrics": {
            "policy_image_count": len(_ids(policy.get("images"))),
            "evidenced_image_count": len(_ids(evidence.get("images") if evidence else [])),
            "promoted_image_count": len(
                _ids(
                    evidence.get("promotion", {}).get("images", [])
                    if evidence and isinstance(evidence.get("promotion"), dict)
                    else []
                )
            ),
            "readiness_blocker_count": len(set(blockers)),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="saas/supply_chain/release-policy.json")
    parser.add_argument("--evidence")
    parser.add_argument("--product-revision")
    parser.add_argument("--output")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    policy = json.loads((repo / args.policy).read_text(encoding="utf-8"))
    evidence_path = args.evidence or policy.get("production_evidence")
    try:
        evidence = load_release_evidence(
            repo,
            evidence_path,
            allow_missing=args.evidence is None,
        )
    except ValueError as error:
        parser.error(str(error))
    report = validate_release(
        repo,
        policy,
        evidence,
        expected_product_revision=args.product_revision,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["status"] != "pass":
        return 1
    return 1 if args.require_ready and report["production_readiness"] != "ready" else 0


if __name__ == "__main__":
    raise SystemExit(main())
