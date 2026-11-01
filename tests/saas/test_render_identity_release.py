from __future__ import annotations

import copy
import json
import stat
from pathlib import Path

import pytest
import yaml

from saas.production.identity_process_config import (
    load_identity_read_broker_config,
    load_identity_worker_config,
)
from saas.production.service_bindings import (
    OPTIONAL_SERVICE_ROLE_PROFILES,
    load_production_service_role_bindings,
    load_production_service_role_graph,
)
from saas.scripts.render_identity_release import EVIDENCE, MANIFEST, render_identity_release
from saas.scripts.render_kubernetes_release import (
    ReleaseRenderError,
    _canonical_json,
    render_kubernetes_release,
)
from tests.saas.test_identity_process_config import certificate
from tests.saas.test_production_server_config import _receipt
from tests.saas.test_render_kubernetes_release import (
    _copy_sources,
    _resource,
    _spec_document,
)


def _identity():
    return {
        "schema_version": 1,
        "casdoor": {
            "issuer": "https://auth.identity.example.com",
            "organization": "customers",
            "application": "customer-web",
            "client_id": "customer-client",
            "provider_application": "private-state-reader",
            "provider_client_id": "private-machine-client",
            "endpoint_cidr": "203.0.113.12/32",
        },
        "reader_key_id": "current",
        "concurrency": 4,
        "reconcile_seconds": 60,
        "poll_seconds": 1,
        "private_ingress": {"namespace": "identity-private", "workload": "casdoor-webhook-relay"},
        "monitoring": {"namespace": "monitoring", "workload": "prometheus"},
        "secrets": {
            name: "identity-" + name.replace("_", "-") + "-" + str(index) * 12
            for index, name in enumerate(
                (
                    "provider",
                    "reader_keys",
                    "reader_secret",
                    "webhook_keys",
                    "broker_tls",
                    "worker_tls",
                    "provider_ca",
                    "reader_ca",
                ),
                1,
            )
        },
    }


def _write(path: Path, document):
    path.write_bytes(_canonical_json(document))
    path.chmod(0o600)
    return path


def _render(tmp_path, *, identity=None, release=None):
    source = _copy_sources(tmp_path)
    release_file = _write(tmp_path / "release.json", release or _spec_document())
    identity_file = _write(tmp_path / "identity.json", identity or _identity())
    output = tmp_path / "rendered"
    result = render_identity_release(release_file, identity_file, source, output)
    return result, output, release_file, source


def test_identity_stage_preserves_parent_bytes_and_keeps_every_process_disabled(tmp_path):
    result, output, release_file, source = _render(tmp_path)
    parent = tmp_path / "parent"
    render_kubernetes_release(release_file, source, parent)
    for path in parent.iterdir():
        assert (output / path.name).read_bytes() == path.read_bytes()
    receipt = json.loads((output / EVIDENCE).read_bytes())
    assert result["admission_state"] == receipt["admission_state"] == "pending"
    assert receipt["production_qualification"] is False
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    document = yaml.safe_load((output / MANIFEST).read_bytes())
    assert all(item["metadata"]["namespace"] == "omnigent-next-beta" for item in document["items"])
    assert not {"Ingress", "Role", "RoleBinding", "Secret"} & {
        item["kind"] for item in document["items"]
    }
    assert all(
        item["spec"]["replicas"] == 0 for item in document["items"] if item["kind"] == "Deployment"
    )
    assert all(
        item["spec"]["type"] == "ClusterIP"
        for item in document["items"]
        if item["kind"] == "Service"
    )


def test_secret_files_exist_only_in_the_correct_init_and_runtime_snapshot(tmp_path):
    _result, output, _release, _source = _render(tmp_path)
    document = yaml.safe_load((output / MANIFEST).read_bytes())
    for name, required, forbidden in (
        (
            "omnigent-identity-reader",
            {"provider", "reader-keys", "provider-ca", "tls"},
            {"authenticator", "receipt", "reader", "webhook", "postgresql-ca"},
        ),
        (
            "omnigent-identity-sync",
            {"authenticator", "receipt", "reader", "webhook", "reader-ca", "tls", "postgresql-ca"},
            {"provider", "reader-keys", "provider-ca"},
        ),
    ):
        deployment = _resource(document, kind="Deployment", name=name)
        pod = deployment["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        sa = _resource(document, kind="ServiceAccount", name=name)
        assert sa["automountServiceAccountToken"] is False
        mounts = {row["name"] for row in pod["initContainers"][0]["volumeMounts"]}
        assert required <= mounts and not forbidden & mounts
        container = pod["containers"][0]
        assert {row["name"] for row in container["volumeMounts"]} == {"runtime", "temp"}
        assert container["volumeMounts"][0]["readOnly"] is True
        assert all(
            row["securityContext"]["capabilities"]["drop"] == ["ALL"]
            and row["securityContext"]["readOnlyRootFilesystem"] is True
            and row["securityContext"]["runAsNonRoot"] is True
            for row in [*pod["initContainers"], *pod["containers"]]
        )
        assert all(
            row["image"].endswith("@sha256:" + "3" * 64)
            for row in [*pod["initContainers"], *pod["containers"]]
        )
        script = pod["initContainers"][0]["command"][2]
        sandbox = tmp_path / name
        for volume in pod["volumes"]:
            if "secret" in volume:
                directory = sandbox / "source" / volume["name"]
                directory.mkdir(parents=True)
                for item in volume["secret"]["items"]:
                    (directory / item["path"]).write_text("owned-synthetic-input")
        public = _resource(document, kind="ConfigMap", data_key="casdoor.json")
        public_dir = sandbox / "source/public"
        public_dir.mkdir(parents=True)
        for key, content in public["data"].items():
            (public_dir / key).write_text(content)
        runtime = sandbox / "runtime"
        runtime.mkdir()
        exec(
            script.replace("/source/", str(sandbox / "source") + "/").replace(
                "/runtime/", str(runtime) + "/"
            ),
            {},
        )
        assert all(
            path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o400
            for path in runtime.iterdir()
        )
        assert (runtime / "identity-tls.key").read_text() == "owned-synthetic-input"
        if name.endswith("reader"):
            assert not (runtime / "authenticator-database-url").exists()
        else:
            assert not (runtime / "provider-secret").exists()


def test_network_paths_are_private_and_provider_and_database_authority_are_separate(tmp_path):
    _result, output, _release, _source = _render(tmp_path)
    document = yaml.safe_load((output / MANIFEST).read_bytes())
    reader = _resource(document, kind="NetworkPolicy", name="omnigent-identity-reader")["spec"]
    worker = _resource(document, kind="NetworkPolicy", name="omnigent-identity-sync")["spec"]
    for policy in (reader, worker):
        assert policy["policyTypes"] == ["Ingress", "Egress"]
        assert all(
            row["ports"] == [{"protocol": "TCP", "port": 8443}] for row in policy["ingress"]
        )
        assert all(row.get("to") and row.get("ports") for row in policy["egress"])
    assert reader["egress"][1] == {
        "to": [{"ipBlock": {"cidr": "203.0.113.12/32"}}],
        "ports": [{"protocol": "TCP", "port": 443}],
    }
    assert [row["ports"] for row in worker["egress"]][1:] == [
        [{"protocol": "TCP", "port": 8443}],
        [{"protocol": "TCP", "port": 5432}],
    ]
    assert "omnigent-next-beta-data" in json.dumps(worker)
    assert "5432" not in json.dumps(reader) and "ipBlock" not in json.dumps(worker)


def test_full_role_profiles_are_copied_from_the_exact_parent_release(tmp_path):
    release = _spec_document()
    for _prefix, _filename, roles in OPTIONAL_SERVICE_ROLE_PROFILES:
        release["service_logins"].update({service: "identity_" + service for service in roles})
    _result, output, _release, _source = _render(tmp_path, release=release)
    document = yaml.safe_load((output / MANIFEST).read_bytes())
    public = _resource(document, kind="ConfigMap", data_key="casdoor.json")["data"]
    worker = _resource(document, kind="Deployment", name="omnigent-identity-sync")
    env = {
        row["name"]: row["value"]
        for row in worker["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    for prefix, filename, _roles in OPTIONAL_SERVICE_ROLE_PROFILES:
        assert filename in public
        assert env[prefix + "_FILE"] == "/runtime/" + filename
    receipt = json.loads((output / EVIDENCE).read_bytes())
    parent = json.loads((output / "release-render-evidence.json").read_bytes())
    assert receipt["service_role_graph_sha256"] == parent["service_role_graph_sha256"]


def test_rendered_process_environments_load_with_the_real_closed_configuration_loaders(tmp_path):
    release = _spec_document()
    for _prefix, _filename, roles in OPTIONAL_SERVICE_ROLE_PROFILES:
        release["service_logins"].update({service: "identity_" + service for service in roles})
    _result, output, _release, _source = _render(tmp_path, release=release)
    document = yaml.safe_load((output / MANIFEST).read_bytes())
    public = _resource(document, kind="ConfigMap", data_key="casdoor.json")["data"]
    tls = tmp_path / "tls"
    tls.mkdir()
    cert, key = certificate(tls)
    loaded = []
    for name, loader in (
        ("omnigent-identity-reader", load_identity_read_broker_config),
        ("omnigent-identity-sync", load_identity_worker_config),
    ):
        runtime = tmp_path / (name + "-runtime")
        runtime.mkdir()
        for filename, content in public.items():
            path = runtime / filename
            path.write_text(content.replace("/runtime/", str(runtime) + "/"))
            path.chmod(0o400)
        for filename, data in {
            "identity-tls.crt": Path(cert).read_bytes(),
            "identity-tls.key": Path(key).read_bytes(),
            "provider-ca.crt": Path(cert).read_bytes(),
            "reader-ca.crt": Path(cert).read_bytes(),
            "provider-secret": b"provider-secret-only-" + b"p" * 32,
            "reader-secret": b"r" * 40,
            "reader-keys.json": _canonical_json(
                {"schema_version": 1, "keys": {"current": "r" * 40}}
            ),
            "webhook-keys.json": _canonical_json(
                {"schema_version": 1, "keys": {"current": "w" * 40}}
            ),
        }.items():
            path = runtime / filename
            path.write_bytes(data)
            path.chmod(0o400)
        deployment = _resource(document, kind="Deployment", name=name)
        env = {
            row["name"]: row["value"].replace("/runtime/", str(runtime) + "/")
            for row in deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        if name.endswith("sync"):
            graph = load_production_service_role_graph(env)
            login = graph.login_for("authenticator")
            url = runtime / "authenticator-database-url"
            url.write_text(
                f"postgresql+psycopg://{login}:synthetic-password@db.example.test/fixture"
                "?sslmode=verify-full&sslrootcert=%2Fruntime%2Fpostgresql-ca.crt"
            )
            url.chmod(0o400)
            receipt_path = Path(
                _receipt(
                    runtime / "postgresql-migration-receipt",
                    service_role_bindings_sha256=load_production_service_role_bindings(env).sha256,
                    service_role_graph_sha256=graph.sha256,
                )
            )
            receipt = json.loads(receipt_path.read_bytes())
            receipt.update(
                official_head=release["official_schema_revision"],
                saas_head=release["control_plane_schema_revision"],
            )
            receipt_path.chmod(0o600)
            receipt_path.write_bytes(_canonical_json(receipt))
            receipt_path.chmod(0o400)
        loaded.append(loader(env))
    assert loaded[0].provider_application == "private-state-reader"
    assert "model_projection" in loaded[1].release.service_role_graph.by_service


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"provider_secret": "must-never-be-accepted"},
        {"concurrency": True},
        {"concurrency": 17},
        {"reconcile_seconds": 61},
        {"poll_seconds": 0},
        {"reader_key_id": "bad/header"},
        {"private_ingress": {"namespace": "identity-private", "workload": "*"}},
        {"secrets": {}},
    ],
)
def test_invalid_or_secret_bearing_identity_spec_has_no_output(tmp_path, change):
    identity = _identity() | change
    with pytest.raises(ReleaseRenderError):
        _render(tmp_path, identity=identity)
    assert not (tmp_path / "rendered").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "http://auth.identity.example.com"),
        ("issuer", "https://auth.identity.example.com/path"),
        ("issuer", 123),
        ("issuer", "https://secret@auth.identity.example.com"),
        ("endpoint_cidr", "0.0.0.0/0"),
        ("endpoint_cidr", "203.0.113.0/24"),
        ("provider_application", "customer-web"),
        ("provider_application", "app-built-in"),
        ("provider_client_id", "customer-client"),
        ("organization", "built-in"),
    ],
)
def test_provider_scope_does_not_admit_unsafe_origins_or_networks(tmp_path, field, value):
    identity = _identity()
    identity["casdoor"][field] = value
    with pytest.raises(ReleaseRenderError):
        _render(tmp_path, identity=identity)


def test_final_release_and_reused_secret_names_are_rejected(tmp_path):
    with pytest.raises(ReleaseRenderError, match="final admission is pending"):
        _render(tmp_path, release=_spec_document(mode="final"))
    other = tmp_path / "other"
    other.mkdir()
    identity = _identity()
    identity["secrets"]["reader_secret"] = identity["secrets"]["provider"]
    with pytest.raises(ReleaseRenderError, match="distinct revisioned"):
        _render(other, identity=identity)


def test_source_security_drift_and_output_overwrite_are_rejected(tmp_path):
    _result, output, release, source = _render(tmp_path)
    identity_file = tmp_path / "identity.json"
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(ReleaseRenderError):
        render_identity_release(release, identity_file, source, output)
    assert before == {path.name: path.read_bytes() for path in output.iterdir()}
    production = source / "kubernetes.production.yaml"
    production.write_text(
        production.read_text().replace(
            "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", 1
        )
    )
    with pytest.raises(ReleaseRenderError):
        render_identity_release(release, identity_file, source, tmp_path / "drift")


def test_identity_spec_requires_canonical_owner_only_regular_file(tmp_path):
    _result, _output, release, source = _render(tmp_path)
    identity_file = tmp_path / "identity.json"
    identity_file.chmod(0o644)
    with pytest.raises(ReleaseRenderError, match="owner-only"):
        render_identity_release(release, identity_file, source, tmp_path / "bad-permissions")
    identity_file.chmod(0o600)
    linked = tmp_path / "linked.json"
    linked.symlink_to(identity_file)
    with pytest.raises(ReleaseRenderError):
        render_identity_release(release, linked, source, tmp_path / "bad-link")
    noncanonical = copy.deepcopy(_identity())
    identity_file.write_text(json.dumps(noncanonical, indent=2))
    with pytest.raises(ReleaseRenderError, match="canonical JSON"):
        render_identity_release(release, identity_file, source, tmp_path / "bad-json")
