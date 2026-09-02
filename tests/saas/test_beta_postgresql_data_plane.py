from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from saas.production import beta_postgresql_data_plane as data_plane
from saas.production.beta_postgresql_data_plane import (
    BARMAN_MANIFEST_SHA256,
    BARMAN_MANIFEST_URL,
    BARMAN_OPERATOR_IMAGE,
    BARMAN_SIDECAR_IMAGE,
    CERT_MANAGER_CAINJECTOR_IMAGE,
    CERT_MANAGER_CONTROLLER_IMAGE,
    CERT_MANAGER_MANIFEST_SHA256,
    CERT_MANAGER_MANIFEST_URL,
    CERT_MANAGER_WEBHOOK_IMAGE,
    CNPG_OPERATOR_IMAGE,
    OPERATOR_MANIFEST_SHA256,
    OPERATOR_MANIFEST_URL,
    POSTGRESQL_IMAGE,
    SOURCE_URLS,
    BetaPostgresqlDataPlaneError,
    admit_restore_drill_evidence,
    load_beta_postgresql_data_plane_spec,
    render_beta_postgresql_data_plane,
    restore_drill_evidence_schema,
)


def _spec() -> dict[str, object]:
    return {
        "availability": {
            "high_availability": False,
            "instances": 1,
            "kubernetes_node_count": 3,
            "physical_host_count": 1,
        },
        "barman": {
            "access_key_secret": {"key": "ACCESS_KEY_ID", "name": "beta-object-store"},
            "backup_name": "beta-postgresql-backup",
            "destination_path": "s3://beta-backups/postgresql/",
            "endpoint_url": "https://object-store.internal",
            "manifest_sha256": BARMAN_MANIFEST_SHA256,
            "manifest_url": BARMAN_MANIFEST_URL,
            "object_store_name": "beta-postgresql-store",
            "operator_image": BARMAN_OPERATOR_IMAGE,
            "region_secret": {"key": "AWS_REGION", "name": "beta-object-store"},
            "retention_policy": "30d",
            "schedule": "0 0 2 * * *",
            "secret_key_secret": {
                "key": "ACCESS_SECRET_KEY",
                "name": "beta-object-store",
            },
            "sidecar_image": BARMAN_SIDECAR_IMAGE,
            "version": "0.14.0",
        },
        "cert_manager": {
            "cainjector_image": CERT_MANAGER_CAINJECTOR_IMAGE,
            "controller_image": CERT_MANAGER_CONTROLLER_IMAGE,
            "manifest_sha256": CERT_MANAGER_MANIFEST_SHA256,
            "manifest_url": CERT_MANAGER_MANIFEST_URL,
            "version": "1.21.1",
            "webhook_image": CERT_MANAGER_WEBHOOK_IMAGE,
        },
        "cluster_name": "beta-postgresql",
        "deployment_id": "6193ab6b-655d-490d-8bd3-8a707b29267d",
        "kubernetes": {"distribution": "k3s", "version": "1.36"},
        "namespace": "beta-data",
        "network": {
            "application_namespace": "beta-application",
            "application_pod_selector": {"app.kubernetes.io/name": "omnigent-server"},
            "dns_namespace": "kube-system",
            "dns_pod_selector": {"k8s-app": "kube-dns"},
            "kubernetes_api_cidrs": ["10.43.0.1/32"],
            "kubernetes_node_cidrs": ["10.0.0.0/24"],
            "object_store_cidrs": ["198.51.100.10/32"],
            "operator_namespace": "cnpg-system",
            "operator_pod_selector": {"app.kubernetes.io/name": "cloudnative-pg"},
            "plugin_namespace": "cnpg-system",
            "plugin_pod_selector": {"app": "barman-cloud"},
        },
        "operator": {
            "image": CNPG_OPERATOR_IMAGE,
            "manifest_sha256": OPERATOR_MANIFEST_SHA256,
            "manifest_url": OPERATOR_MANIFEST_URL,
            "version": "1.30.0",
        },
        "postgres": {
            "database": "omnigent_beta",
            "image": POSTGRESQL_IMAGE,
            "owner": "omnigent_owner",
            "owner_secret": {"name": "beta-postgresql-owner"},
            "server_ca_secret_name": "beta-postgresql-server-ca",
            "server_tls_secret_name": "beta-postgresql-server-tls",
            "version": "18.4",
        },
        "restore_drill": {
            "cluster_name": "beta-postgresql-restore-drill",
            "namespace": "beta-data-restore-drill",
            "source_server_name": "beta-postgresql",
            "target_time": "2026-08-31T18:00:00Z",
        },
        "schema_version": 1,
        "source_urls": list(SOURCE_URLS),
        "storage": {
            "class_name": "beta-postgresql-retain",
            "data_size": "40Gi",
            "parameters": {},
            "provisioner": "rancher.io/local-path",
            "volume_binding_mode": "WaitForFirstConsumer",
            "wal_size": "10Gi",
        },
        "target_platform": "linux/amd64",
    }


def _write_spec(path: Path, document: object, *, canonical: bool = True) -> Path:
    if canonical:
        raw = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    else:
        raw = json.dumps(document, indent=2) + "\n"
    path.write_text(raw, encoding="ascii")
    path.chmod(0o600)
    return path


def _evidence(*, status: str = "pass") -> dict[str, object]:
    document: dict[str, object] = {
        "bundle_sha256": "2" * 64,
        "checks": {
            "data_validation_sha256": "3" * 64,
            "database_owner_verified": True,
            "pitr_target_reached": True,
            "source_store_read_only": True,
            "wal_replay_verified": True,
        },
        "completed_at": "2026-08-31T20:00:00Z",
        "deployment_id": "6193ab6b-655d-490d-8bd3-8a707b29267d",
        "execution_status": status,
        "recovery_target_time": "2026-08-31T18:00:00Z",
        "restored_cluster_uid": "7cd48b17-0342-4ff4-b98d-c50336a25990",
        "schema_version": 1,
        "source_backup_uid": "e411c1d6-37a5-4707-9393-8f21923fe728",
        "spec_sha256": "1" * 64,
        "started_at": "2026-08-31T19:00:00Z",
    }
    if status == "fail":
        cast(dict[str, object], document["checks"])["wal_replay_verified"] = False
        document["failure_code"] = "wal_replay_failed"
        document["failure_detail_sha256"] = "4" * 64
    return document


def _write_evidence(path: Path, document: object) -> Path:
    path.write_text(
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


def _cert_manager_documents() -> list[dict[str, object]]:
    deployments = (
        (
            "cert-manager",
            "cert-manager-controller",
            "quay.io/jetstack/cert-manager-controller:v1.21.1",
        ),
        (
            "cert-manager-cainjector",
            "cert-manager-cainjector",
            "quay.io/jetstack/cert-manager-cainjector:v1.21.1",
        ),
        (
            "cert-manager-webhook",
            "cert-manager-webhook",
            "quay.io/jetstack/cert-manager-webhook:v1.21.1",
        ),
    )
    documents: list[dict[str, object]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "cert-manager"},
        }
    ]
    for deployment_name, container_name, image in deployments:
        labels = {"app.kubernetes.io/name": deployment_name}
        documents.append(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": deployment_name, "namespace": "cert-manager"},
                "spec": {
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "containers": [
                                {
                                    "name": container_name,
                                    "image": image,
                                    "imagePullPolicy": "IfNotPresent",
                                }
                            ]
                        },
                    },
                },
            }
        )
    return documents


def _operator_documents() -> list[dict[str, object]]:
    return [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "cnpg-system"},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "cnpg-controller-manager", "namespace": "cnpg-system"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "manager",
                                "image": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0",
                                "imagePullPolicy": "Always",
                                "env": [
                                    {
                                        "name": "OPERATOR_IMAGE_NAME",
                                        "value": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0",
                                    }
                                ],
                            }
                        ]
                    }
                }
            },
        },
    ]


def _plugin_documents() -> list[dict[str, object]]:
    secret_name = "plugin-barman-cloud-source-image"
    return [
        {
            "apiVersion": "v1",
            "data": {"SIDECAR_IMAGE": "bm90LWEtY3JlZGVudGlhbA=="},
            "kind": "Secret",
            "metadata": {"name": secret_name, "namespace": "cnpg-system"},
            "type": "Opaque",
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "barman-cloud", "namespace": "cnpg-system"},
            "spec": {"ports": [{"port": 9090, "protocol": "TCP", "targetPort": 9090}]},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "barman-cloud", "namespace": "cnpg-system"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "barman-cloud",
                                "image": ("ghcr.io/cloudnative-pg/plugin-barman-cloud:v0.14.0"),
                                "env": [
                                    {
                                        "name": "SIDECAR_IMAGE",
                                        "valueFrom": {
                                            "secretKeyRef": {
                                                "key": "SIDECAR_IMAGE",
                                                "name": secret_name,
                                            }
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                }
            },
        },
    ]


def _loader(_path: Path, _digest: str, field: str) -> list[dict[str, object]]:
    if field == "cert-manager manifest":
        return deepcopy(_cert_manager_documents())
    if field == "operator manifest":
        return deepcopy(_operator_documents())
    return deepcopy(_plugin_documents())


def _documents(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.yaml")):
        value = yaml.safe_load(path.read_text(encoding="ascii"))
        assert isinstance(value, dict)
        result.append(value)
    return result


def _resource(
    documents: list[dict[str, object]], kind: str, name: str, namespace: str | None = None
) -> dict[str, object]:
    matches = []
    for document in documents:
        metadata = cast(dict[str, object], document["metadata"])
        if (
            document["kind"] == kind
            and metadata["name"] == name
            and (namespace is None or metadata.get("namespace") == namespace)
        ):
            matches.append(document)
    assert len(matches) == 1
    return matches[0]


def test_rendered_bundle_is_pinned_secret_free_and_recoverable(tmp_path: Path) -> None:
    spec_file = _write_spec(tmp_path / "spec.json", _spec())
    output = tmp_path / "rendered"

    receipt = render_beta_postgresql_data_plane(
        spec_file,
        cert_manager_manifest=tmp_path / "cert-manager.yaml",
        operator_manifest=tmp_path / "operator.yaml",
        plugin_manifest=tmp_path / "plugin.yaml",
        output_directory=output,
        _manifest_loader=_loader,
    )

    assert len(receipt.spec_sha256) == 64
    assert len(receipt.bundle_sha256) == 64
    assert len(receipt.receipt_sha256) == 64
    assert all(path.stat().st_size <= 1024 * 1024 for path in output.rglob("*") if path.is_file())
    documents = _documents(output)
    assert not any(document["kind"] == "Secret" for document in documents)

    lock = json.loads((output / "00-source-lock.json").read_text(encoding="ascii"))
    assert lock["compatibility"] == {
        "barman_cloud_plugin": "0.14.0",
        "cert_manager": "1.21.1",
        "cloudnativepg": "1.30.0",
        "distribution": "k3s",
        "kubernetes": "1.36",
        "postgresql": "18.4",
    }
    assert lock["operator"]["manifest_sha256"] == OPERATOR_MANIFEST_SHA256
    assert lock["cert_manager"]["manifest_sha256"] == CERT_MANAGER_MANIFEST_SHA256
    assert lock["target_platform"] == "linux/amd64"
    assert lock["image_authority"] == {
        "digest_scope": "platform-child-manifest",
        "remote_registry_verified_during_render": False,
    }
    assert lock["availability"]["high_availability"] is False

    storage = _resource(documents, "StorageClass", "beta-postgresql-retain")
    assert storage["reclaimPolicy"] == "Retain"
    assert storage["volumeBindingMode"] == "WaitForFirstConsumer"
    storage_metadata = cast(dict[str, object], storage["metadata"])
    assert (
        cast(dict[str, str], storage_metadata["annotations"])["argocd.argoproj.io/sync-options"]
        == "Prune=false"
    )

    cluster = _resource(documents, "Cluster", "beta-postgresql", "beta-data")
    cluster_spec = cast(dict[str, object], cluster["spec"])
    assert cluster_spec["instances"] == 1
    assert cluster_spec["imageName"] == cast(dict[str, object], _spec()["postgres"])["image"]
    assert cluster_spec["storage"] == {
        "storageClass": "beta-postgresql-retain",
        "size": "40Gi",
    }
    assert cluster_spec["walStorage"] == {
        "storageClass": "beta-postgresql-retain",
        "size": "10Gi",
    }
    bootstrap = cast(dict[str, object], cluster_spec["bootstrap"])
    assert cast(dict[str, object], bootstrap["initdb"])["dataChecksums"] is True
    parameters = cast(
        dict[str, object],
        cast(dict[str, object], cluster_spec["postgresql"])["parameters"],
    )
    assert parameters["max_notify_queue_pages"] == "64"
    assert parameters["max_prepared_transactions"] == "0"
    assert cluster_spec["certificates"] == {
        "serverCASecret": "beta-postgresql-server-ca",
        "serverTLSSecret": "beta-postgresql-server-tls",
    }
    plugins = cast(list[dict[str, object]], cluster_spec["plugins"])
    assert plugins[0]["isWALArchiver"] is True
    assert plugins[0]["name"] == "barman-cloud.cloudnative-pg.io"

    scheduled = _resource(documents, "ScheduledBackup", "beta-postgresql-backup", "beta-data")
    scheduled_spec = cast(dict[str, object], scheduled["spec"])
    assert scheduled_spec["method"] == "plugin"
    assert scheduled_spec["backupOwnerReference"] == "none"
    assert scheduled_spec["schedule"] == "0 0 2 * * *"

    store = _resource(documents, "ObjectStore", "beta-postgresql-store", "beta-data")
    store_spec = cast(dict[str, object], store["spec"])
    assert store_spec["retentionPolicy"] == "30d"
    configuration = cast(dict[str, object], store_spec["configuration"])
    assert "serverName" not in configuration
    credentials = cast(dict[str, object], configuration["s3Credentials"])
    assert credentials["accessKeyId"] == {
        "key": "ACCESS_KEY_ID",
        "name": "beta-object-store",
    }

    restore = _resource(
        documents,
        "Cluster",
        "beta-postgresql-restore-drill",
        "beta-data-restore-drill",
    )
    restore_spec = cast(dict[str, object], restore["spec"])
    assert "plugins" not in restore_spec
    recovery = cast(
        dict[str, object], cast(dict[str, object], restore_spec["bootstrap"])["recovery"]
    )
    assert cast(dict[str, object], recovery["recoveryTarget"])["targetTime"] == (
        "2026-08-31T18:00:00Z"
    )
    external = cast(list[dict[str, object]], restore_spec["externalClusters"])[0]
    plugin = cast(dict[str, object], external["plugin"])
    assert cast(dict[str, object], plugin["parameters"])["serverName"] == "beta-postgresql"

    rendered_receipt = json.loads((output / "99-render-receipt.json").read_text(encoding="ascii"))
    assert rendered_receipt["render_status"] == "rendered_not_applied"
    assert rendered_receipt["restore_drill_execution"] == "not_executed"
    assert rendered_receipt["restore_drill_requires_explicit_authorization"] is True
    assert rendered_receipt["secret_resources"] == 0


def test_primary_apply_package_cannot_create_restore_drill(tmp_path: Path) -> None:
    output = tmp_path / "rendered"
    render_beta_postgresql_data_plane(
        _write_spec(tmp_path / "spec.json", _spec()),
        cert_manager_manifest=tmp_path / "cert-manager.yaml",
        operator_manifest=tmp_path / "operator.yaml",
        plugin_manifest=tmp_path / "plugin.yaml",
        output_directory=output,
        _manifest_loader=_loader,
    )

    primary = _documents(output / "primary")
    restore = _documents(output / "restore-drill")
    primary_clusters = [item for item in primary if item["kind"] == "Cluster"]
    restore_clusters = [item for item in restore if item["kind"] == "Cluster"]
    assert [cast(dict[str, object], item["metadata"])["name"] for item in primary_clusters] == [
        "beta-postgresql"
    ]
    assert [cast(dict[str, object], item["metadata"])["name"] for item in restore_clusters] == [
        "beta-postgresql-restore-drill"
    ]
    assert not any(
        cast(dict[str, object], item["metadata"]).get("namespace") == "beta-data-restore-drill"
        for item in primary
    )
    assert not any(
        item["kind"] == "Namespace"
        and cast(dict[str, object], item["metadata"])["name"] == "beta-data-restore-drill"
        for item in primary
    )
    lock = json.loads((output / "00-source-lock.json").read_text(encoding="ascii"))
    assert lock["packages"]["primary"]["apply_by_default"] is True
    assert lock["packages"]["restore_drill"] == {
        "apply_by_default": False,
        "path": "restore-drill",
        "requires_explicit_authorization": True,
    }


def test_rendered_upstreams_replace_all_runtime_images_without_secret(tmp_path: Path) -> None:
    document = _spec()
    output = tmp_path / "rendered"
    render_beta_postgresql_data_plane(
        _write_spec(tmp_path / "spec.json", document),
        cert_manager_manifest=tmp_path / "cert-manager.yaml",
        operator_manifest=tmp_path / "operator.yaml",
        plugin_manifest=tmp_path / "plugin.yaml",
        output_directory=output,
        _manifest_loader=_loader,
    )
    documents = _documents(output)
    operator = _resource(documents, "Deployment", "cnpg-controller-manager", "cnpg-system")
    plugin = _resource(documents, "Deployment", "barman-cloud", "cnpg-system")
    operator_container = cast(
        list[dict[str, object]],
        cast(
            dict[str, object],
            cast(dict[str, object], cast(dict[str, object], operator["spec"])["template"])["spec"],
        )["containers"],
    )[0]
    plugin_container = cast(
        list[dict[str, object]],
        cast(
            dict[str, object],
            cast(dict[str, object], cast(dict[str, object], plugin["spec"])["template"])["spec"],
        )["containers"],
    )[0]
    assert operator_container["image"] == cast(dict[str, object], document["operator"])["image"]
    assert (
        plugin_container["image"] == cast(dict[str, object], document["barman"])["operator_image"]
    )
    sidecar = cast(list[dict[str, object]], plugin_container["env"])[0]
    assert "valueFrom" not in sidecar
    assert sidecar["value"] == cast(dict[str, object], document["barman"])["sidecar_image"]
    cert_manager = cast(dict[str, object], document["cert_manager"])
    for deployment_name, image_key in (
        ("cert-manager", "controller_image"),
        ("cert-manager-cainjector", "cainjector_image"),
        ("cert-manager-webhook", "webhook_image"),
    ):
        deployment = _resource(documents, "Deployment", deployment_name, "cert-manager")
        container = cast(
            list[dict[str, object]],
            cast(
                dict[str, object],
                cast(
                    dict[str, object],
                    cast(dict[str, object], deployment["spec"])["template"],
                )["spec"],
            )["containers"],
        )[0]
        assert container["image"] == cert_manager[image_key]
    assert (output / "upstream" / "cert-manager").is_dir()


def test_cert_manager_source_rejects_secret_and_unexpected_image_workload() -> None:
    images = {
        "controller_image": CERT_MANAGER_CONTROLLER_IMAGE,
        "cainjector_image": CERT_MANAGER_CAINJECTOR_IMAGE,
        "webhook_image": CERT_MANAGER_WEBHOOK_IMAGE,
    }
    secret_documents = _cert_manager_documents()
    secret_documents.append(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "forbidden", "namespace": "cert-manager"},
        }
    )
    with pytest.raises(BetaPostgresqlDataPlaneError, match="cannot contain Secret"):
        data_plane._pin_cert_manager_manifest(secret_documents, **images)

    workload_documents = _cert_manager_documents()
    workload_documents.append(
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": "unexpected", "namespace": "cert-manager"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "unexpected", "image": "example.invalid/image:v1"}]
                    }
                }
            },
        }
    )
    with pytest.raises(BetaPostgresqlDataPlaneError, match="workload inventory drifted"):
        data_plane._pin_cert_manager_manifest(workload_documents, **images)


def test_network_contract_is_default_deny_and_only_reviewed_paths(tmp_path: Path) -> None:
    output = tmp_path / "rendered"
    render_beta_postgresql_data_plane(
        _write_spec(tmp_path / "spec.json", _spec()),
        cert_manager_manifest=tmp_path / "cert-manager.yaml",
        operator_manifest=tmp_path / "operator.yaml",
        plugin_manifest=tmp_path / "plugin.yaml",
        output_directory=output,
        _manifest_loader=_loader,
    )
    documents = _documents(output)
    defaults = [
        item
        for item in documents
        if item["kind"] == "NetworkPolicy"
        and cast(dict[str, object], item["metadata"])["name"] == "default-deny-ingress-egress"
    ]
    assert {cast(dict[str, object], item["metadata"])["namespace"] for item in defaults} == {
        "beta-data",
        "beta-data-restore-drill",
        "cnpg-system",
    }
    for policy in defaults:
        assert cast(dict[str, object], policy["spec"])["ingress"] == []
        assert cast(dict[str, object], policy["spec"])["egress"] == []

    rendered = "\n".join(path.read_text(encoding="ascii") for path in output.rglob("*.yaml"))
    assert "0.0.0.0/0" not in rendered
    assert "::/0" not in rendered
    ports = {
        port["port"]
        for policy in documents
        if policy["kind"] == "NetworkPolicy"
        for direction in ("ingress", "egress")
        for rule in cast(
            list[dict[str, object]],
            cast(dict[str, object], policy["spec"])[direction],
        )
        for port in cast(list[dict[str, object]], rule.get("ports", []))
    }
    assert ports == {53, 443, 5432, 8000, 9090, 9443}
    webhook = _resource(
        documents,
        "NetworkPolicy",
        "allow-cnpg-webhook-and-reconciliation",
        "cnpg-system",
    )
    assert "9443" in yaml.safe_dump(webhook)
    assert "8000" in yaml.safe_dump(webhook)
    assert "5432" in yaml.safe_dump(webhook)

    def peer(namespace: str, labels: dict[str, str]) -> dict[str, object]:
        return {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": labels},
        }

    operator_peer = peer("cnpg-system", {"app.kubernetes.io/name": "cloudnative-pg"})
    plugin_peer = peer("cnpg-system", {"app": "barman-cloud"})
    primary_peer = peer("beta-data", {"cnpg.io/cluster": "beta-postgresql"})
    restore_peer = peer(
        "beta-data-restore-drill",
        {"cnpg.io/cluster": "beta-postgresql-restore-drill"},
    )
    port_9090 = [{"port": 9090, "protocol": "TCP"}]
    primary_documents = _documents(output / "primary")
    restore_documents = _documents(output / "restore-drill")
    operator_policy = _resource(
        primary_documents,
        "NetworkPolicy",
        "allow-cnpg-webhook-and-reconciliation",
        "cnpg-system",
    )
    plugin_policy = _resource(
        primary_documents,
        "NetworkPolicy",
        "allow-barman-plugin-api",
        "cnpg-system",
    )
    operator_spec = cast(dict[str, object], operator_policy["spec"])
    plugin_spec = cast(dict[str, object], plugin_policy["spec"])
    assert {"to": [plugin_peer], "ports": port_9090} in cast(
        list[dict[str, object]], operator_spec["egress"]
    )
    assert {"from": [operator_peer], "ports": port_9090} in cast(
        list[dict[str, object]], plugin_spec["ingress"]
    )

    restore_operator_policy = _resource(
        restore_documents,
        "NetworkPolicy",
        "allow-cnpg-restore-reconciliation",
        "cnpg-system",
    )
    restore_plugin_policy = _resource(
        restore_documents,
        "NetworkPolicy",
        "allow-barman-restore-api",
        "cnpg-system",
    )
    operator_union = cast(list[dict[str, object]], operator_spec["egress"]) + cast(
        list[dict[str, object]],
        cast(dict[str, object], restore_operator_policy["spec"])["egress"],
    )
    plugin_union = cast(list[dict[str, object]], plugin_spec["ingress"]) + cast(
        list[dict[str, object]],
        cast(dict[str, object], restore_plugin_policy["spec"])["ingress"],
    )
    assert {
        "to": [primary_peer],
        "ports": [
            {"port": 5432, "protocol": "TCP"},
            {"port": 8000, "protocol": "TCP"},
        ],
    } in operator_union
    assert {
        "to": [restore_peer],
        "ports": [
            {"port": 5432, "protocol": "TCP"},
            {"port": 8000, "protocol": "TCP"},
        ],
    } in operator_union
    assert {"to": [plugin_peer], "ports": port_9090} in operator_union
    assert {"from": [operator_peer], "ports": port_9090} in plugin_union
    assert {"from": [primary_peer], "ports": port_9090} in plugin_union
    assert {"from": [restore_peer], "ports": port_9090} in plugin_union


@pytest.mark.parametrize(
    ("section", "key", "unsafe_value", "message"),
    [
        ("operator", "version", "1.29.3", "v1.30.0"),
        ("postgres", "version", "18.3", "18.4"),
        ("barman", "version", "0.13.0", "v0.14.0"),
        ("kubernetes", "version", "1.35", "k3s 1.36"),
        ("availability", "high_availability", True, "non-HA"),
        ("storage", "volume_binding_mode", "Immediate", "WaitForFirstConsumer"),
        ("barman", "retention_policy", "6d", "7d..365d"),
        ("barman", "retention_policy", "366d", "7d..365d"),
        ("barman", "schedule", "0 2 * * *", "six-field"),
        ("barman", "schedule", "0 * * * * *", "daily six-field"),
        (
            "barman",
            "endpoint_url",
            "https://owner:credential@object-store.internal",
            "credential-free HTTPS",
        ),
        ("network", "object_store_cidrs", ["0.0.0.0/0"], "default route"),
        ("network", "kubernetes_api_cidrs", ["::/0"], "default route"),
        (None, "target_platform", "linux/arm64", "linux/amd64"),
        ("barman", "manifest_sha256", "5" * 64, "manifest lock"),
        ("cert_manager", "manifest_sha256", "6" * 64, "exactly v1.21.1"),
        (
            "operator",
            "image",
            "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0@sha256:" + "1" * 64,
            "reviewed linux/amd64 child manifest",
        ),
        (
            "operator",
            "image",
            "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0@sha256:" + "0" * 64,
            "version and digest",
        ),
        (
            "operator",
            "image",
            "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0-unsigned@sha256:" + "1" * 64,
            "version and digest",
        ),
        (
            "postgres",
            "image",
            "ghcr.io/cloudnative-pg/postgresql:latest@sha256:" + "2" * 64,
            "version and digest",
        ),
        (None, "namespace", "placeholder", "sentinel"),
        (None, "unexpected", True, "invalid shape"),
    ],
)
def test_spec_rejects_drift_and_unsafe_defaults(
    tmp_path: Path,
    section: str | None,
    key: str,
    unsafe_value: object,
    message: str,
) -> None:
    document = _spec()
    target = document if section is None else cast(dict[str, object], document[section])
    target[key] = unsafe_value
    with pytest.raises(BetaPostgresqlDataPlaneError, match=message):
        load_beta_postgresql_data_plane_spec(_write_spec(tmp_path / "spec.json", document))


def test_spec_rejects_noncanonical_oversized_and_non_owner_file(tmp_path: Path) -> None:
    document = _spec()
    with pytest.raises(BetaPostgresqlDataPlaneError, match="canonical"):
        load_beta_postgresql_data_plane_spec(
            _write_spec(tmp_path / "noncanonical.json", document, canonical=False)
        )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (128 * 1024) + b"}")
    oversized.chmod(0o600)
    with pytest.raises(BetaPostgresqlDataPlaneError, match="unsafe ownership or metadata"):
        load_beta_postgresql_data_plane_spec(oversized)

    public = _write_spec(tmp_path / "public.json", document)
    public.chmod(0o644)
    with pytest.raises(BetaPostgresqlDataPlaneError, match="unsafe ownership or metadata"):
        load_beta_postgresql_data_plane_spec(public)


def test_spec_rejects_symlink(tmp_path: Path) -> None:
    real = _write_spec(tmp_path / "real.json", _spec())
    linked = tmp_path / "linked.json"
    linked.symlink_to(real)
    with pytest.raises(BetaPostgresqlDataPlaneError, match="opened safely"):
        load_beta_postgresql_data_plane_spec(linked)


def test_source_manifest_hash_and_metadata_are_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source.yaml"
    raw = b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: cnpg-system\n"
    source.write_bytes(raw)
    source.chmod(0o644)
    digest = hashlib.sha256(raw).hexdigest()
    assert data_plane._load_manifest(source, digest, "source") == [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnpg-system"}}
    ]
    with pytest.raises(BetaPostgresqlDataPlaneError, match="SHA-256"):
        data_plane._load_manifest(source, "f" * 64, "source")
    source.chmod(0o666)
    with pytest.raises(BetaPostgresqlDataPlaneError, match="unsafe ownership or metadata"):
        data_plane._load_manifest(source, digest, "source")


def test_renderer_rejects_unexpected_secret_and_existing_output(tmp_path: Path) -> None:
    spec_file = _write_spec(tmp_path / "spec.json", _spec())

    def unexpected_secret(_path: Path, _digest: str, field: str) -> list[dict[str, object]]:
        if field == "cert-manager manifest":
            return _cert_manager_documents()
        documents = _operator_documents() if field == "operator manifest" else _plugin_documents()
        if field == "operator manifest":
            documents.append(
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "forbidden", "namespace": "cnpg-system"},
                }
            )
        return documents

    with pytest.raises(BetaPostgresqlDataPlaneError, match="source identity drifted"):
        render_beta_postgresql_data_plane(
            spec_file,
            cert_manager_manifest=tmp_path / "cert-manager.yaml",
            operator_manifest=tmp_path / "operator.yaml",
            plugin_manifest=tmp_path / "plugin.yaml",
            output_directory=tmp_path / "first",
            _manifest_loader=unexpected_secret,
        )

    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(BetaPostgresqlDataPlaneError, match="must not already exist"):
        render_beta_postgresql_data_plane(
            spec_file,
            cert_manager_manifest=tmp_path / "cert-manager.yaml",
            operator_manifest=tmp_path / "operator.yaml",
            plugin_manifest=tmp_path / "plugin.yaml",
            output_directory=output,
            _manifest_loader=_loader,
        )


def test_restore_evidence_schema_snapshot_is_strict_and_not_an_execution_claim() -> None:
    schema_path = (
        Path(__file__).parents[2]
        / "saas"
        / "deployment"
        / "data"
        / "restore-drill-evidence.schema.json"
    )
    checked_in = json.loads(schema_path.read_text(encoding="utf-8"))
    assert checked_in == restore_drill_evidence_schema()
    assert checked_in["additionalProperties"] is False
    assert checked_in["properties"]["execution_status"]["enum"] == ["pass", "fail"]
    assert "not_executed" not in json.dumps(checked_in)
    validator = Draft202012Validator(checked_in, format_checker=FormatChecker())

    passed = _evidence()
    assert list(validator.iter_errors(passed)) == []
    false_pass = deepcopy(passed)
    cast(dict[str, object], false_pass["checks"])["pitr_target_reached"] = False
    assert list(validator.iter_errors(false_pass))
    pass_with_failure = deepcopy(passed)
    pass_with_failure["failure_code"] = "unexpected"
    pass_with_failure["failure_detail_sha256"] = "4" * 64
    assert list(validator.iter_errors(pass_with_failure))

    failed = _evidence(status="fail")
    assert list(validator.iter_errors(failed)) == []
    false_fail = deepcopy(failed)
    for key in (
        "database_owner_verified",
        "pitr_target_reached",
        "source_store_read_only",
        "wal_replay_verified",
    ):
        cast(dict[str, object], false_fail["checks"])[key] = True
    assert list(validator.iter_errors(false_fail))
    zero_digest = deepcopy(passed)
    zero_digest["bundle_sha256"] = "0" * 64
    assert list(validator.iter_errors(zero_digest))
    nil_uid = deepcopy(passed)
    nil_uid["restored_cluster_uid"] = "00000000-0000-0000-0000-000000000000"
    assert list(validator.iter_errors(nil_uid))


def test_restore_evidence_admission_binds_pass_and_true_fail(tmp_path: Path) -> None:
    expected = {
        "expected_deployment_id": "6193ab6b-655d-490d-8bd3-8a707b29267d",
        "expected_spec_sha256": "1" * 64,
        "expected_bundle_sha256": "2" * 64,
        "expected_recovery_target_time": "2026-08-31T18:00:00Z",
    }
    passed = admit_restore_drill_evidence(
        _write_evidence(tmp_path / "pass.json", _evidence()), **expected
    )
    assert passed.execution_status == "pass"
    assert passed.pitr_target_reached is True
    assert passed.failure_code is None

    failed = admit_restore_drill_evidence(
        _write_evidence(tmp_path / "fail.json", _evidence(status="fail")), **expected
    )
    assert failed.execution_status == "fail"
    assert failed.wal_replay_verified is False
    assert failed.failure_code == "wal_replay_failed"


def test_restore_evidence_admission_rejects_false_pass_time_and_binding_drift(
    tmp_path: Path,
) -> None:
    expected = {
        "expected_deployment_id": "6193ab6b-655d-490d-8bd3-8a707b29267d",
        "expected_spec_sha256": "1" * 64,
        "expected_bundle_sha256": "2" * 64,
        "expected_recovery_target_time": "2026-08-31T18:00:00Z",
    }
    false_pass = _evidence()
    cast(dict[str, object], false_pass["checks"])["source_store_read_only"] = False
    with pytest.raises(BetaPostgresqlDataPlaneError, match="every execution check"):
        admit_restore_drill_evidence(
            _write_evidence(tmp_path / "false-pass.json", false_pass), **expected
        )

    time_drift = _evidence()
    time_drift["started_at"] = "2026-08-31T17:59:59Z"
    with pytest.raises(BetaPostgresqlDataPlaneError, match="time binding drifted"):
        admit_restore_drill_evidence(
            _write_evidence(tmp_path / "time-drift.json", time_drift), **expected
        )

    binding_drift = _evidence()
    binding_drift["bundle_sha256"] = "5" * 64
    with pytest.raises(BetaPostgresqlDataPlaneError, match="release binding drifted"):
        admit_restore_drill_evidence(
            _write_evidence(tmp_path / "binding-drift.json", binding_drift), **expected
        )
    with pytest.raises(BetaPostgresqlDataPlaneError, match="time binding drifted"):
        admit_restore_drill_evidence(
            _write_evidence(tmp_path / "target-drift.json", _evidence()),
            **{
                **expected,
                "expected_recovery_target_time": "2026-08-31T18:00:01Z",
            },
        )


def test_no_gitops_contract_file_exceeds_one_megabyte() -> None:
    root = Path(__file__).parents[2] / "saas" / "deployment" / "data"
    assert all(path.stat().st_size <= 1024 * 1024 for path in root.rglob("*") if path.is_file())
