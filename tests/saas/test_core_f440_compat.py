"""Bound the restart backport to the existing f440 schema and revoked Runner grant."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
import yaml

from saas.production.postgresql_migration import (
    PostgreSqlMigrationError,
    _canonical_runner_management_catalog,
)
from saas.scripts import core_f440_compat_release as release
from saas.scripts import prepare_core_f440_compat as recipe

ROOT = Path(__file__).resolve().parents[2]


def test_exact_f440_patch_preserves_both_runner_lifecycle_states() -> None:
    manifest = recipe.load_manifest(ROOT)
    patch = (ROOT / "saas/core_f440_compat/postgresql_migration.patch").read_text()
    hunks = patch.split("@@")
    # The first zero-context hunk contains only the source-pinned helper.
    helper = "".join(
        line[1:] for line in hunks[2].splitlines(keepends=True) if line.startswith("+")
    )
    tree = ast.parse(helper)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_canonical_runner_management_catalog"
    )
    current = ast.parse(inspect.getsource(_canonical_runner_management_catalog)).body[0]
    assert ast.dump(function, include_attributes=False) == ast.dump(
        current, include_attributes=False
    )
    assert manifest["patched_module_sha256"] == (
        "b83cfde2b98ff9e48a872a4eb833b931edc5f7ab067af8c9d71e0a115c44141e"
    )
    scope = {
        "Mapping": Mapping,
        "cast": cast,
        "PostgreSqlMigrationError": PostgreSqlMigrationError,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "backport", "exec"), scope)
    canonical = scope["_canonical_runner_management_catalog"]
    management = ["saas_runner_agent", "operator", "bootstrap", True, False, False]
    absent = {"control_plane_security": {"memberships": []}}
    present = {"control_plane_security": {"memberships": [management]}}
    assert canonical(absent, principal_operator="operator", bootstrap_name="bootstrap") == present
    assert canonical(present, principal_operator="operator", bootstrap_name="bootstrap") == present
    assert absent["control_plane_security"]["memberships"] == []
    wrong = {"control_plane_security": {"memberships": [[*management[:3], True, True, False]]}}
    with pytest.raises(PostgreSqlMigrationError):
        canonical(wrong, principal_operator="operator", bootstrap_name="bootstrap")
    assert patch.count("catalog = _canonical_runner_management_catalog(") == 2
    assert manifest["database_mutation"] is manifest["runner_permissions_changed"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_product_revision", "a" * 40),
        ("module_path", "other.py"),
        ("runtime_base_image", "ghcr.io/dream1216/omnigent-saas-server:latest"),
        ("required_schema_revision", "lm2s00000001"),
        ("runner_permissions_changed", True),
    ],
)
def test_recipe_rejects_source_image_schema_or_permission_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    destination = tmp_path / "saas/core_f440_compat"
    shutil.copytree(ROOT / "saas/core_f440_compat", destination)
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="materials differ"):
        recipe.load_manifest(tmp_path)


def test_core_scan_requires_raw_exact_platform_and_zero_findings(tmp_path: Path) -> None:
    built = datetime.now(UTC).isoformat()
    platforms = {}
    rows = []
    for arch in ("amd64", "arm64"):
        platform = "linux/" + arch
        facts = {
            "manifest_digest": "sha256:" + ("a" if arch == "amd64" else "b") * 64,
            "config_digest": "sha256:" + ("c" if arch == "amd64" else "d") * 64,
        }
        platforms[platform] = facts
        report = {
            "matches": [],
            "ignoredMatches": [],
            "descriptor": {
                "name": "grype",
                "version": "0.120.1",
                "db": {"status": {"built": built, "valid": True, "schemaVersion": "v6.0.0"}},
                "configuration": {"only-fixed": False, "only-notfixed": False},
            },
            "source": {
                "target": {
                    "manifestDigest": facts["manifest_digest"],
                    "imageID": facts["config_digest"],
                    "labels": {},
                    "os": "linux",
                    "architecture": arch,
                }
            },
        }
        path = tmp_path / ("server-" + arch + "-grype.json")
        path.write_text(json.dumps(report))
        rows.append(
            {
                "image": "server",
                "platform": platform,
                "archive_sha256": "1" * 64,
                "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "critical": 0,
                "high": 0,
                "findings": [],
            }
        )
    summary = {
        "scanner": "grype 0.120.1",
        "exceptions": [],
        "images": rows,
        "database_built_at": built,
    }
    (tmp_path / "server-preflight-scan-summary.json").write_text(json.dumps(summary))
    manifest = {"facts": {"platforms": platforms}, "labels": {}}
    assert len(release.validate_scans(tmp_path, manifest, "1" * 64)["reports"]) == 2
    report = json.loads((tmp_path / "server-amd64-grype.json").read_text())
    report["matches"] = [
        {
            "vulnerability": {"severity": "High", "id": "test-cve"},
            "artifact": {"name": "bad", "version": "1"},
        }
    ]
    (tmp_path / "server-amd64-grype.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="Critical or High"):
        release.validate_scans(tmp_path, manifest, "1" * 64)


def test_publication_requires_exact_main_protected_approval_and_both_architectures() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/saas-core-f440-compat.yml").read_text())
    job = workflow["jobs"]["publish-core"]
    assert job["environment"] == "production-image"
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert "inputs.product_revision == github.sha" in job["if"]
    builds = [step for step in job["steps"] if "docker/build-push-action@" in step.get("uses", "")]
    assert len(builds) == 2 and builds[1]["with"]["no-cache"] is True
    assert all(step["with"]["platforms"] == "linux/amd64,linux/arm64" for step in builds)
    assert workflow["jobs"]["independent-readback"]["needs"] == "publish-core"
