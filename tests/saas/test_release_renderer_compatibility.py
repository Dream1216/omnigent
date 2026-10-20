"""Bind a P0 application's R schema handoff to a verify-only Kubernetes Job."""

import pytest

from saas.production import postgresql_migration as migration
from saas.scripts import render_kubernetes_release as renderer
from tests.saas.test_render_kubernetes_release import (
    _canonical_json,
    _copy_sources,
    _document,
    _resource,
    _spec_document,
)


@pytest.mark.parametrize("mode", ["stage", "final"])
@pytest.mark.parametrize("head", ["p0s000000015", "lm2r00000001"])
def test_release_binds_the_actual_database_head_and_exact_migration_mode(tmp_path, mode, head):
    document = _spec_document(mode=mode)
    document["control_plane_schema_revision"] = head
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    output = tmp_path / "rendered"
    renderer.render_kubernetes_release(spec, _copy_sources(tmp_path), output)
    manifest = _document(output / "kubernetes.migration.yaml")
    job = _resource(manifest, kind="Job", name="omnigent-saas-postgresql-migration")
    migrate = next(
        row for row in job["spec"]["template"]["spec"]["containers"] if row["name"] == "migrate"
    )
    assert migrate["command"] == ["python", "-m", "saas.scripts.run_postgresql_migration"]
    expected = ["--product-revision", "$(OMNIGENT_SAAS_SOURCE_SHA)"]
    if head == "lm2r00000001":
        expected.extend(["--verify-only", "--verification-saas-head", head])
    assert migrate["args"] == expected
    evidence = _document(output / renderer.EVIDENCE_FILE_NAME)
    assert evidence["release_contract"]["control_plane_schema_revision"] == head
    production = _document(output / "kubernetes.production.yaml")
    release = _resource(production, kind="ConfigMap", data_key="OMNIGENT_SAAS_IMAGE_DIGEST")
    assert release["data"]["OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION"] == head
    assert release["data"]["OMNIGENT_SAAS_PRODUCT_REVISION"] == document["product_revision"]


@pytest.mark.parametrize("head", ["lm2q00000001", "future", "p0s000000009"])
def test_renderer_rejects_unreviewed_database_heads(tmp_path, head):
    document = _spec_document()
    document["control_plane_schema_revision"] = head
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    with pytest.raises(renderer.ReleaseRenderError, match="not supported"):
        renderer.render_kubernetes_release(spec, _copy_sources(tmp_path), tmp_path / "rendered")
    assert not (tmp_path / "rendered").exists()


def test_r_packaged_image_uses_its_own_migrations_without_a_cross_head_override(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(migration, "_expected_head", lambda _kind: "lm2r00000001")
    monkeypatch.setattr(renderer, "_expected_head", lambda _kind: "lm2r00000001")
    document = _spec_document()
    document["control_plane_schema_revision"] = "lm2r00000001"
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    parsed = renderer.load_public_release_spec(spec)
    assert renderer._migration_args(parsed) == [
        "--product-revision",
        "$(OMNIGENT_SAAS_SOURCE_SHA)",
    ]


def test_renderer_never_authorizes_a_mutating_argument_added_to_a_rollback(tmp_path, monkeypatch):
    document = _spec_document()
    document["control_plane_schema_revision"] = "lm2r00000001"
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    original = renderer._render_release_documents

    def changed(sources, release_spec):
        documents, suffixes = original(sources, release_spec)
        job = _resource(
            documents["kubernetes.migration.yaml"],
            kind="Job",
            name="omnigent-saas-postgresql-migration",
        )
        job["spec"]["template"]["spec"]["containers"][0]["args"].remove("--verify-only")
        return documents, suffixes

    monkeypatch.setattr(renderer, "_render_release_documents", changed)
    with pytest.raises(renderer.ReleaseRenderError, match="unauthorized"):
        renderer.render_kubernetes_release(spec, _copy_sources(tmp_path), tmp_path / "rendered")
    assert not (tmp_path / "rendered").exists()
