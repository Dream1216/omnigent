from __future__ import annotations

import hashlib
import json
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

import saas.scripts.render_kubernetes_namespace as namespace_renderer
from saas.scripts.render_kubernetes_namespace import (
    EVIDENCE_FILE_NAME,
    MANIFEST_NAMES,
    SOURCE_EXTERNAL_DATABASE_NAMESPACE,
    SOURCE_NAMESPACE,
    TARGET_EXTERNAL_DATABASE_NAMESPACE,
    TARGET_NAMESPACE,
    NamespaceRenderError,
    main,
    render_namespace_manifests,
)

_ROOT = Path(__file__).resolve().parents[2]
_DEPLOYMENT = _ROOT / "saas" / "deployment" / "server"


def _copy_sources(tmp_path: Path) -> Path:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    for name in MANIFEST_NAMES:
        shutil.copy2(_DEPLOYMENT / name, source_dir / name)
    return source_dir


def _items(path: Path) -> list[dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert document["apiVersion"] == "v1"
    assert document["kind"] == "List"
    return document["items"]


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _named_scalars(value: Any, name: str) -> list[str]:
    scalars: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == name and isinstance(child, str):
                scalars.append(child)
            scalars.extend(_named_scalars(child, name))
    elif isinstance(value, list):
        for child in value:
            scalars.extend(_named_scalars(child, name))
    return scalars


def test_renderer_changes_only_namespace_and_service_dns_and_emits_hashes(
    tmp_path: Path,
) -> None:
    source_dir = _copy_sources(tmp_path)
    source_hashes = {name: _sha256(source_dir / name) for name in MANIFEST_NAMES}
    output_dir = tmp_path / "rendered"

    result = render_namespace_manifests(source_dir, output_dir)

    assert result["status"] == "pass"
    assert result["manifest_count"] == 4
    assert {path.name for path in output_dir.iterdir()} == {
        *MANIFEST_NAMES,
        EVIDENCE_FILE_NAME,
    }
    for name in MANIFEST_NAMES:
        source_document = yaml.safe_load((source_dir / name).read_text(encoding="utf-8"))
        rendered_document = yaml.safe_load((output_dir / name).read_text(encoding="utf-8"))
        items = _items(output_dir / name)
        assert items
        assert all(item["metadata"]["namespace"] == TARGET_NAMESPACE for item in items)
        assert all(item["kind"] != "Secret" for item in items)
        assert _sha256(source_dir / name) == source_hashes[name]
        assert stat.S_IMODE((output_dir / name).stat().st_mode) == 0o600
        assert _named_scalars(rendered_document, "secretName") == _named_scalars(
            source_document, "secretName"
        )

    production = (output_dir / "kubernetes.production.yaml").read_text(encoding="utf-8")
    assert "omnigent-saas-runner-control.omnigent-next-beta.svc" in production
    assert "omnigent-next-beta.svc.cluster.local" in production
    assert ".omnigent.svc" not in production
    assert "s3://replace-with-production-bucket/omnigent" in production
    assert "replace-with-preview-owner-incarnation" in production

    network = (output_dir / "kubernetes.network-policy.yaml").read_text(encoding="utf-8")
    assert f"kubernetes.io/metadata.name: {TARGET_EXTERNAL_DATABASE_NAMESPACE}" in network
    assert SOURCE_EXTERNAL_DATABASE_NAMESPACE not in network
    assert "cidr: replace-with-artifact-endpoint-cidr" in network
    assert "cidr: replace-with-repository-endpoint-cidr" in network

    evidence_path = output_dir / EVIDENCE_FILE_NAME
    evidence = json.loads(evidence_path.read_text(encoding="ascii"))
    assert evidence["status"] == "pass"
    assert evidence["source_namespace"] == SOURCE_NAMESPACE
    assert evidence["target_namespace"] == TARGET_NAMESPACE
    assert evidence["schema_version"] == 2
    assert evidence["external_database_namespace"] == {
        "replacement_count": 6,
        "source": SOURCE_EXTERNAL_DATABASE_NAMESPACE,
        "target": TARGET_EXTERNAL_DATABASE_NAMESPACE,
    }
    assert evidence["manifest_count"] == 4
    assert {row["name"] for row in evidence["files"]} == set(MANIFEST_NAMES)
    assert all(row["source_sha256"] == source_hashes[row["name"]] for row in evidence["files"])
    assert all(row["metadata_namespace_replacements"] > 0 for row in evidence["files"])
    evidence_by_name = {row["name"]: row for row in evidence["files"]}
    assert (
        evidence_by_name["kubernetes.network-policy.yaml"][
            "external_database_namespace_replacements"
        ]
        == 6
    )
    assert (
        evidence_by_name["kubernetes.network-policy.yaml"][
            "external_database_namespace_text_replacements"
        ]
        == 1
    )
    assert all(
        row["external_database_namespace_replacements"] == 0
        and row["external_database_namespace_text_replacements"] == 0
        for name, row in evidence_by_name.items()
        if name != "kubernetes.network-policy.yaml"
    )
    assert result["evidence_sha256"] == _sha256(evidence_path)
    assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600


def test_console_main_outputs_only_secret_free_hash_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source_dir = _copy_sources(tmp_path)
    output_dir = tmp_path / "rendered"

    assert (
        main(
            [
                "--source-dir",
                str(source_dir),
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert captured.err == ""
    summary = json.loads(captured.out)
    assert set(summary) == {
        "evidence_file",
        "evidence_sha256",
        "manifest_count",
        "rendered_set_sha256",
        "status",
    }
    assert summary["status"] == "pass"
    assert summary["evidence_sha256"].startswith("sha256:")
    assert "value" not in captured.out.lower()
    assert "token" not in captured.out.lower()
    assert "credential" not in captured.out.lower()


def test_renderer_rejects_secret_resources(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    (source_dir / "kubernetes.migration.yaml").write_text(
        """apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: forbidden
      namespace: omnigent
""",
        encoding="utf-8",
    )

    with pytest.raises(NamespaceRenderError, match="Secret resources are forbidden"):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_non_dns_source_namespace_reference(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    production_path = source_dir / "kubernetes.production.yaml"
    production_path.write_text(
        production_path.read_text(encoding="utf-8").replace(
            "OMNIGENT_SAAS_HOST: 0.0.0.0",
            "OMNIGENT_SAAS_HOST: omnigent",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(NamespaceRenderError, match="residual source namespace"):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_zero_external_database_namespace_references(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            f"kubernetes.io/metadata.name: {SOURCE_EXTERNAL_DATABASE_NAMESPACE}",
            "kubernetes.io/metadata.name: isolated-data",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database namespace reference count is invalid",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_five_external_database_namespace_references(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            "        - to: *postgres_cluster",
            "        - to: []",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database namespace reference count is invalid",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_seven_external_database_namespace_references(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    rule = "        - to: *postgres_cluster\n          ports: *postgres_port\n"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(rule, rule + rule, 1),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database namespace reference count is invalid",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_external_database_namespace_substrings(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            SOURCE_EXTERNAL_DATABASE_NAMESPACE,
            f"{SOURCE_EXTERNAL_DATABASE_NAMESPACE}.attacker.invalid",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database namespace must be one exact scalar",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_external_database_namespace_mapping_keys(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            "kubernetes.io/metadata.name:",
            f"{SOURCE_EXTERNAL_DATABASE_NAMESPACE}:",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database namespace in a mapping key is forbidden",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_pre_rendered_external_database_namespace(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            SOURCE_EXTERNAL_DATABASE_NAMESPACE,
            TARGET_EXTERNAL_DATABASE_NAMESPACE,
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="pre-rendered external database namespace is forbidden",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_six_references_on_an_unreviewed_database_consumer(
    tmp_path: Path,
) -> None:
    source_dir = _copy_sources(tmp_path)
    network_path = source_dir / "kubernetes.network-policy.yaml"
    network_path.write_text(
        network_path.read_text(encoding="utf-8").replace(
            "name: omnigent-saas-migration",
            "name: omnigent-saas-unreviewed-database-client",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        NamespaceRenderError,
        match="external database consumer projection is invalid",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_residual_source_external_database_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = _copy_sources(tmp_path)

    def leave_source_namespace(value: str) -> tuple[str, int]:
        count = int(f"kubernetes.io/metadata.name: {SOURCE_EXTERNAL_DATABASE_NAMESPACE}" in value)
        return value, count

    monkeypatch.setattr(
        namespace_renderer,
        "_replace_external_database_namespace",
        leave_source_namespace,
    )
    with pytest.raises(
        NamespaceRenderError,
        match="source external database namespace line remains",
    ):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_malformed_source_service_dns(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    production_path = source_dir / "kubernetes.production.yaml"
    production_path.write_text(
        production_path.read_text(encoding="utf-8").replace(
            ".omnigent.svc",
            ".omnigent.svc.attacker.invalid",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(NamespaceRenderError, match="residual source service DNS"):
        render_namespace_manifests(source_dir, tmp_path / "rendered")


def test_renderer_rejects_pre_rendered_or_incomplete_source_set(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    migration_path = source_dir / "kubernetes.migration.yaml"
    migration_path.write_text(
        migration_path.read_text(encoding="utf-8").replace(
            "namespace: omnigent",
            "namespace: omnigent-next-beta",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(NamespaceRenderError, match=r"every metadata\.namespace"):
        render_namespace_manifests(source_dir, tmp_path / "rendered")

    shutil.copy2(
        _DEPLOYMENT / "kubernetes.production.yaml",
        source_dir / "unexpected-secret.yaml",
    )
    with pytest.raises(NamespaceRenderError, match="exactly four YAML manifests"):
        render_namespace_manifests(source_dir, tmp_path / "rendered-again")


def test_renderer_never_overwrites_an_existing_output_directory(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    output_dir = tmp_path / "rendered"
    output_dir.mkdir(mode=0o700)
    sentinel = output_dir / "keep"
    sentinel.write_text("operator-owned\n", encoding="utf-8")

    with pytest.raises(NamespaceRenderError, match="output directory must be empty"):
        render_namespace_manifests(source_dir, output_dir)

    assert sentinel.read_text(encoding="utf-8") == "operator-owned\n"


def test_renderer_rejects_group_accessible_output_directory(tmp_path: Path) -> None:
    source_dir = _copy_sources(tmp_path)
    output_dir = tmp_path / "rendered"
    output_dir.mkdir()
    output_dir.chmod(0o750)

    with pytest.raises(NamespaceRenderError, match="group/world accessible"):
        render_namespace_manifests(source_dir, output_dir)
