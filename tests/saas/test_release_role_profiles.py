"""Bind full release role profiles to immutable manifests, staged files and receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saas.production import service_bindings as bindings
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_migration_receipt,
)
from saas.production.worker import ProductionWorkerConfigError, load_production_worker_config
from saas.scripts import render_kubernetes_release as renderer
from tests.saas.test_production_server_config import _bindings, _receipt
from tests.saas.test_production_worker import _environment as _worker_environment
from tests.saas.test_render_kubernetes_release import (
    _canonical_json,
    _copy_sources,
    _document,
    _resource,
    _spec_document,
)

_PROFILES = (
    (
        "OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS",
        "platform-model-service-role-bindings.json",
    ),
    (
        "OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS",
        "platform-admin-service-role-bindings.json",
    ),
    (
        "OMNIGENT_SAAS_MODEL_PROJECTION_SERVICE_ROLE_BINDINGS",
        "model-projection-service-role-bindings.json",
    ),
)


def _spec(tmp_path, *, count=19, head="lm2r00000001", mode="stage", login_suffix=""):
    document = _spec_document(mode=mode)
    document["control_plane_schema_revision"] = head
    roles = dict(bindings.EXPECTED_PRODUCTION_SERVICE_ROLES)
    if count >= 18:
        roles.update(bindings.EXPECTED_PLATFORM_MODEL_SERVICE_ROLES)
        roles.update(bindings.EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES)
    if count == 19:
        roles.update(bindings.EXPECTED_MODEL_PROJECTION_SERVICE_ROLES)
    for service in roles:
        if service not in document["service_logins"]:
            document["service_logins"][service] = f"release_{service}_login{login_suffix}"
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    return spec


def _render(tmp_path, **kwargs):
    output = tmp_path / "rendered"
    renderer.render_kubernetes_release(_spec(tmp_path, **kwargs), _copy_sources(tmp_path), output)
    migration = _document(output / "kubernetes.migration.yaml")
    production = _document(output / "kubernetes.production.yaml")
    evidence = _document(output / renderer.EVIDENCE_FILE_NAME)
    return migration, production, evidence


@pytest.mark.parametrize(
    "count,head",
    [
        (15, "p0s000000015"),
        (18, "p0s000000015"),
        (18, "lm2r00000001"),
        (19, "lm2r00000001"),
        (15, "lm2s00000001"),
        (18, "lm2s00000001"),
        (19, "lm2s00000001"),
    ],
)
@pytest.mark.parametrize("mode", ["stage", "final"])
def test_complete_role_profiles_are_exactly_projected_and_receipt_bound(
    tmp_path, count, head, mode
):
    migration, production, evidence = _render(tmp_path, count=count, head=head, mode=mode)
    migration_bindings = _resource(
        migration, kind="ConfigMap", data_key="service-role-bindings.json"
    )
    production_bindings = _resource(
        production, kind="ConfigMap", data_key="service-role-bindings.json"
    )
    assert migration_bindings == production_bindings
    count_profiles = 0 if count == 15 else 2 if count == 18 else 3
    active = _PROFILES[:count_profiles]
    assert set(migration_bindings["data"]) == {
        "service-role-bindings.json",
        *(filename for _, filename in active),
    }
    environment = {}
    local = tmp_path / "profiles"
    local.mkdir()
    for prefix, filename in (
        ("OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS", "service-role-bindings.json"),
        *active,
    ):
        raw = migration_bindings["data"][filename].encode("ascii")
        path = local / filename
        path.write_bytes(raw)
        path.chmod(0o400)
        environment[prefix + "_FILE"] = str(path)
        environment[prefix + "_SHA256"] = hashlib.sha256(raw).hexdigest()
    graph = bindings.load_production_service_role_graph(environment)
    assert len(graph.bindings) == count
    assert production_bindings["metadata"]["name"].endswith(graph.sha256[:12])
    assert (
        evidence["service_role_bindings_sha256"]
        == environment["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_SHA256"]
    )
    if active:
        assert evidence["service_role_graph_sha256"] == graph.sha256
    for document, directory in ((migration, "/authority"), (production, "/runtime")):
        release = _resource(document, kind="ConfigMap", data_key="OMNIGENT_SAAS_PRODUCT_REVISION")
        for prefix, filename in active:
            assert release["data"][prefix + "_FILE"] == f"{directory}/{filename}"
            assert release["data"][prefix + "_SHA256"] == environment[prefix + "_SHA256"]
        staged = 0
        for resource in document["items"]:
            pod = resource.get("spec", {}).get("template", {}).get("spec", {})
            for init in pod.get("initContainers", []):
                script = "\n".join(init.get("args", []))
                core_install = (
                    "install -m 0400 /source/bindings/service-role-bindings.json "
                    f"{directory}/service-role-bindings.json"
                )
                if core_install not in script:
                    continue
                staged += 1
                for _, filename in active:
                    assert (
                        script.count(
                            f"install -m 0400 /source/bindings/{filename} {directory}/{filename}"
                        )
                        == 1
                    )
        assert staged == (1 if directory == "/authority" else 5)
    receipt_path = local / "receipt.json"
    _receipt(
        receipt_path,
        service_role_bindings_sha256=environment["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_SHA256"],
        service_role_graph_sha256=graph.sha256,
    )
    environment["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"] = str(receipt_path)
    facts = {
        "product_revision": "1" * 40,
        "official_head": "e5d9bc8ac650",
        "saas_head": "p0s000000007",
        "service_role_bindings_sha256": environment["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_SHA256"],
    }
    assert (
        load_production_migration_receipt(environment, **facts).service_role_graph_sha256
        == graph.sha256
    )
    if active:
        stripped = {
            key: value
            for key, value in environment.items()
            if key.startswith("OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS")
            or key == "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"
        }
        with pytest.raises(ProductionServerConfigError, match="verification facts"):
            load_production_migration_receipt(stripped, **facts)


def test_extension_login_change_rekeys_the_immutable_bindings_without_changing_core_bytes(
    tmp_path,
):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    a, _, _ = _render(first)
    b, _, _ = _render(second, login_suffix="_new")
    acm = _resource(a, kind="ConfigMap", data_key="service-role-bindings.json")
    bcm = _resource(b, kind="ConfigMap", data_key="service-role-bindings.json")
    assert acm["data"]["service-role-bindings.json"] == bcm["data"]["service-role-bindings.json"]
    assert acm["metadata"]["name"] != bcm["metadata"]["name"]


def test_projection_profile_is_not_admitted_on_the_p0_schema(tmp_path):
    with pytest.raises(renderer.ReleaseRenderError, match=r"projection.*R|projection.*lm2r"):
        renderer.load_public_release_spec(_spec(tmp_path, count=19, head="p0s000000015"))


def test_partial_extension_role_set_is_not_silently_reduced_to_core(tmp_path):
    spec = _spec(tmp_path)
    document = json.loads(spec.read_text())
    document["service_logins"].pop("platform_authenticator")
    spec.chmod(0o600)
    spec.write_bytes(_canonical_json(document))
    with pytest.raises(renderer.ReleaseRenderError, match="service_logins"):
        renderer.load_public_release_spec(spec)


@pytest.mark.parametrize("change", ["profile", "digest", "install"])
def test_profile_additions_and_staging_are_not_a_general_mutation_exception(
    tmp_path, monkeypatch, change
):
    original = renderer._render_release_documents

    def altered(sources, spec):
        documents, suffixes = original(sources, spec)
        manifest = documents["kubernetes.production.yaml"]
        if change == "profile":
            cm = _resource(manifest, kind="ConfigMap", data_key="service-role-bindings.json")
            cm["data"]["unapproved-role-bindings.json"] = "{}"
        elif change == "digest":
            cm = _resource(manifest, kind="ConfigMap", data_key="OMNIGENT_SAAS_PRODUCT_REVISION")
            cm["data"][_PROFILES[0][0] + "_SHA256"] = "0" * 64
        else:
            deployment = _resource(manifest, kind="Deployment", name="omnigent-saas-worker")
            init = deployment["spec"]["template"]["spec"]["initContainers"][0]
            init["args"][0] = (
                "\n".join(
                    line for line in init["args"][0].splitlines() if _PROFILES[0][1] not in line
                )
                + "\n"
            )
        return documents, suffixes

    monkeypatch.setattr(renderer, "_render_release_documents", altered)
    with pytest.raises(renderer.ReleaseRenderError, match="unauthorized"):
        _render(tmp_path)
    assert not (tmp_path / "rendered").exists()


@pytest.mark.parametrize("change", ["core_digest", "partial_profile"])
def test_role_loader_rejects_declared_hash_drift_and_partial_profile_facts(tmp_path, change):
    path = tmp_path / "core.json"
    _bindings(path)
    source = {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": str(path)}
    if change == "core_digest":
        source["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_SHA256"] = "0" * 64
        message = "declared SHA-256"
    else:
        source[_PROFILES[0][0] + "_SHA256"] = "0" * 64
        message = "FILE is required"
    with pytest.raises(bindings.ProductionServiceRoleBindingsError, match=message):
        bindings.load_production_service_role_graph(source)


@pytest.mark.parametrize("count", [18, 19])
def test_worker_configuration_consumes_the_complete_declared_receipt_graph(tmp_path, count):
    source = _worker_environment(tmp_path)
    known = dict(bindings.load_production_service_role_bindings(source).by_service)
    profiles = bindings.OPTIONAL_SERVICE_ROLE_PROFILES[: 2 if count == 18 else 3]
    for prefix, filename, roles in profiles:
        rows = tuple(
            known.get(service)
            or bindings.ProductionServiceRoleBinding(service, f"release_{service}_login", role)
            for service, role in roles.items()
        )
        known.update((row.service, row) for row in rows)
        raw = bindings.render_production_service_role_bindings(rows)
        path = tmp_path / filename
        path.write_text(raw)
        path.chmod(0o400)
        source[prefix + "_FILE"] = str(path)
        source[prefix + "_SHA256"] = hashlib.sha256(raw.encode("ascii")).hexdigest()
    graph = bindings.load_production_service_role_graph(source)
    receipt_path = Path(source["OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE"])
    document = json.loads(receipt_path.read_text())
    document["service_role_graph_sha256"] = graph.sha256
    document["saas_head"] = "lm2r00000001"
    source["OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION"] = "lm2r00000001"
    receipt_path.chmod(0o600)
    receipt_path.write_text(json.dumps(document))
    receipt_path.chmod(0o400)
    config = load_production_worker_config(source)
    assert config.migration_receipt.service_role_graph_sha256 == graph.sha256
    stripped = {
        key: value
        for key, value in source.items()
        if not any(key.startswith(prefix) for prefix, _filename, _roles in profiles)
    }
    with pytest.raises(ProductionWorkerConfigError, match="verification facts"):
        load_production_worker_config(stripped)
