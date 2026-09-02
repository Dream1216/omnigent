from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    render_production_service_role_bindings,
)
from saas.scripts.render_kubernetes_namespace import (
    MANIFEST_NAMES,
    SOURCE_EXTERNAL_DATABASE_NAMESPACE,
    TARGET_EXTERNAL_DATABASE_NAMESPACE,
    render_namespace_manifests,
)

_ROOT = Path(__file__).resolve().parents[2]
_DEPLOYMENT = _ROOT / "saas" / "deployment" / "server"


def _items(name: str) -> list[dict[str, Any]]:
    document = yaml.safe_load((_DEPLOYMENT / name).read_text(encoding="utf-8"))
    assert document["kind"] == "List"
    return document["items"]


def _release(items: list[dict[str, Any]]) -> dict[str, str]:
    return next(
        item["data"]
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )


def _deployment(items: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(
        item for item in items if item["kind"] == "Deployment" and item["metadata"]["name"] == name
    )


def test_release_enables_only_closed_p0s10_preview_profile() -> None:
    items = _items("kubernetes.production.yaml")
    release = _release(items)

    assert release["OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION"] == "p0s000000010"
    assert release["OMNIGENT_SAAS_CAPABILITIES"] == "tenant,run,runner,preview"
    assert release["OMNIGENT_SAAS_PREVIEW_ADAPTER_FACTORY"] == (
        "saas.production.preview_readiness:build_remote_tls_preview_readiness"
    )


def test_migration_and_runtime_share_one_immutable_exact_ten_role_authority() -> None:
    manifests = []
    names = []
    for filename in ("kubernetes.migration.yaml", "kubernetes.production.yaml"):
        config = next(
            item
            for item in _items(filename)
            if item["kind"] == "ConfigMap" and "service-role-bindings.json" in item.get("data", {})
        )
        assert config["immutable"] is True
        assert "replace-bindings12" in config["metadata"]["name"]
        names.append(config["metadata"]["name"])
        manifests.append(config["data"]["service-role-bindings.json"])

    assert names[0] == names[1]
    assert manifests[0] == manifests[1]
    document = json.loads(manifests[0])
    bindings = tuple(
        ProductionServiceRoleBinding(
            service=row["service"], login=row["login"], base_role=row["base_role"]
        )
        for row in document["bindings"]
    )
    assert len(bindings) == 10
    assert {binding.service for binding in bindings} == set(EXPECTED_PRODUCTION_SERVICE_ROLES)
    assert manifests[0] == render_production_service_role_bindings(bindings)


def test_shared_release_has_no_ambient_provider_configuration() -> None:
    items = _items("kubernetes.production.yaml")
    release = _release(items)
    assert not any(name.startswith(("AWS_", "BOTO")) for name in release)

    server = _deployment(items, "omnigent-saas-server")
    server_env = {
        row["name"]: row["value"]
        for row in server["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert server_env["AWS_EC2_METADATA_DISABLED"] == "true"

    for item in items:
        if item["kind"] != "Deployment" or not item["metadata"]["name"].startswith(
            "omnigent-saas-runner-agent-"
        ):
            continue
        runner = item["spec"]["template"]["spec"]["containers"][0]
        explicit = {row["name"] for row in runner.get("env", [])}
        assert not any(name.startswith(("AWS_", "BOTO")) for name in explicit)


def test_beta_topology_has_redundant_services_and_two_distinct_runner_incarnations() -> None:
    items = _items("kubernetes.production.yaml")
    for name in (
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-preview-edge",
    ):
        deployment = _deployment(items, name)
        assert deployment["spec"]["replicas"] == 2
        constraints = deployment["spec"]["template"]["spec"]["topologySpreadConstraints"]
        assert any(
            row["topologyKey"] == "kubernetes.io/hostname"
            and row["whenUnsatisfiable"] == "DoNotSchedule"
            for row in constraints
        )

    runners = [
        item
        for item in items
        if item["kind"] == "Deployment"
        and item["metadata"]["name"].startswith("omnigent-saas-runner-agent-")
    ]
    assert {item["metadata"]["name"] for item in runners} == {
        "omnigent-saas-runner-agent-a",
        "omnigent-saas-runner-agent-b",
    }
    identities: set[tuple[str, str, str, str]] = set()
    runner_database_secrets: set[str] = set()
    runner_fleet_secrets: set[str] = set()
    for runner in runners:
        assert runner["spec"]["replicas"] == 0
        assert runner["spec"]["strategy"] == {"type": "Recreate"}
        assert runner["metadata"]["annotations"]["omnigent.io/runner-fleet-phase"] == ("admission")
        assert runner["metadata"]["annotations"]["omnigent.io/production-blocker"] == (
            "runner-fleet-admission-pending"
        )
        pod = runner["spec"]["template"]
        env = {row["name"]: row["value"] for row in pod["spec"]["containers"][0]["env"]}
        identities.add(
            (
                env["OMNIGENT_SAAS_RUNNER_ID"],
                env["OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION"],
                env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI"],
                env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE"],
            )
        )
        assert pod["metadata"]["labels"]["app.kubernetes.io/component"] == ("runner-agent")
        volumes = {row["name"]: row for row in pod["spec"]["volumes"]}
        database_secret = volumes["runner-database-source"]["secret"]["secretName"]
        runner_database_secrets.add(database_secret)
        runner_fleet_secrets.add(volumes["runner-fleet-source"]["secret"]["secretName"])
        assert database_secret != "omnigent-saas-executor-database"
        assert env["OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE"] == (
            "/runtime/runner-agent-database-url"
        )
        assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE" not in env
        assert "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE" not in env
        assert "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE" not in env
        assert pod["spec"]["containers"][0]["resources"] == {
            "requests": {"cpu": "500m", "memory": "512Mi"},
            "limits": {"cpu": "1", "memory": "512Mi"},
        }
        anti_affinity = pod["spec"]["affinity"]["podAntiAffinity"]
        assert anti_affinity["requiredDuringSchedulingIgnoredDuringExecution"]
    assert len(identities) == 2
    assert runner_database_secrets == {
        "omnigent-saas-runner-agent-a-database-g1",
        "omnigent-saas-runner-agent-b-database-g1",
    }
    assert runner_fleet_secrets == {"omnigent-saas-runner-database-fleet-replace-fleetpins12"}


def test_network_policy_is_default_deny_and_has_no_blanket_public_egress() -> None:
    items = _items("kubernetes.network-policy.yaml")
    policies = {
        item["metadata"]["name"]: item for item in items if item["kind"] == "NetworkPolicy"
    }
    assert "omnigent-saas-default-deny" in policies
    assert policies["omnigent-saas-default-deny"]["spec"] == {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"],
    }
    assert {
        "omnigent-saas-dns",
        "omnigent-saas-migration",
        "omnigent-saas-artifact-admission",
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-runner-agent",
        "omnigent-saas-preview-edge",
        "omnigent-saas-preview-owner",
    } <= set(policies)

    postgres_peer = {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "omnigent-data"}},
        "podSelector": {"matchLabels": {"cnpg.io/cluster": "omnigent-postgres"}},
    }
    database_consumers = {
        "omnigent-saas-migration",
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-runner-agent",
        "omnigent-saas-preview-edge",
        "omnigent-saas-preview-owner",
    }
    for name in database_consumers:
        assert any(
            rule.get("to") == [postgres_peer]
            and rule.get("ports") == [{"protocol": "TCP", "port": 5432}]
            for rule in policies[name]["spec"]["egress"]
        )

    dns = policies["omnigent-saas-dns"]["spec"]["egress"]
    assert dns == [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                    },
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }
            ],
            "ports": [
                {"protocol": "UDP", "port": 53},
                {"protocol": "TCP", "port": 53},
            ],
        }
    ]

    def egress_ports(
        policy_name: str, *, label: tuple[str, str] | None = None, cidr: str | None = None
    ) -> set[int]:
        ports: set[int] = set()
        for rule in policies[policy_name]["spec"].get("egress", []):
            for target in rule.get("to", []):
                matches_label = label is not None and target.get("podSelector") == {
                    "matchLabels": {label[0]: label[1]}
                }
                matches_cidr = cidr is not None and target.get("ipBlock") == {"cidr": cidr}
                if matches_label or matches_cidr:
                    ports.update(port["port"] for port in rule.get("ports", []))
        return ports

    assert egress_ports(
        "omnigent-saas-server",
        label=("app.kubernetes.io/name", "omnigent-saas-worker"),
    ) == {9445}
    assert egress_ports(
        "omnigent-saas-server",
        label=("app.kubernetes.io/name", "omnigent-saas-preview-edge"),
    ) == {8443}
    assert egress_ports(
        "omnigent-saas-worker",
        label=("app.kubernetes.io/name", "omnigent-saas-preview-edge"),
    ) == {8443}
    assert egress_ports(
        "omnigent-saas-runner-agent",
        label=("app.kubernetes.io/name", "omnigent-saas-worker"),
    ) == {9444}
    assert egress_ports(
        "omnigent-saas-runner-agent",
        label=("app.kubernetes.io/name", "omnigent-saas-preview-owner"),
    ) == {9442}
    assert egress_ports(
        "omnigent-saas-preview-edge",
        label=("app.kubernetes.io/name", "omnigent-saas-preview-owner"),
    ) == {9443}
    assert egress_ports(
        "omnigent-saas-preview-owner",
        label=("app.kubernetes.io/name", "omnigent-saas-preview-owner"),
    ) == {9443}
    edge_ingress = policies["omnigent-saas-preview-edge"]["spec"]["ingress"]
    assert {
        "from": [
            {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "omnigent-saas-server"}}},
            {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "omnigent-saas-worker"}}},
        ],
        "ports": [{"protocol": "TCP", "port": 8443}],
    } in edge_ingress
    assert egress_ports("omnigent-saas-server", cidr="replace-with-artifact-endpoint-cidr") == {
        443
    }
    assert egress_ports(
        "omnigent-saas-artifact-admission",
        cidr="replace-with-artifact-endpoint-cidr",
    ) == {443}
    assert policies["omnigent-saas-artifact-admission"]["spec"]["egress"] == [
        {
            "to": [{"ipBlock": {"cidr": "replace-with-artifact-endpoint-cidr"}}],
            "ports": [{"protocol": "TCP", "port": 443}],
        }
    ]
    assert egress_ports("omnigent-saas-worker", cidr="replace-with-artifact-endpoint-cidr") == {
        443
    }
    assert egress_ports(
        "omnigent-saas-runner-agent", cidr="replace-with-artifact-endpoint-cidr"
    ) == {443}
    assert egress_ports(
        "omnigent-saas-runner-agent", cidr="replace-with-repository-endpoint-cidr"
    ) == {443}

    rendered = (_DEPLOYMENT / "kubernetes.network-policy.yaml").read_text(encoding="utf-8")
    assert "cidr: replace-with-artifact-endpoint-cidr" in rendered
    assert "cidr: replace-with-repository-endpoint-cidr" in rendered
    assert "0.0.0.0/0" not in rendered
    assert "::/0" not in rendered
    for policy in policies.values():
        for rule in policy["spec"].get("egress", []):
            for target in rule.get("to", []):
                cidr = target.get("ipBlock", {}).get("cidr")
                assert cidr not in {"0.0.0.0/0", "::/0"}


def test_beta_rendered_network_policy_targets_only_the_dedicated_cnpg_namespace(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    for name in MANIFEST_NAMES:
        shutil.copy2(_DEPLOYMENT / name, source_dir / name)
    output_dir = tmp_path / "rendered"

    render_namespace_manifests(source_dir, output_dir)

    document = yaml.safe_load(
        (output_dir / "kubernetes.network-policy.yaml").read_text(encoding="utf-8")
    )
    policies = {
        item["metadata"]["name"]: item
        for item in document["items"]
        if item["kind"] == "NetworkPolicy"
    }
    postgres_peer = {
        "namespaceSelector": {
            "matchLabels": {
                "kubernetes.io/metadata.name": TARGET_EXTERNAL_DATABASE_NAMESPACE,
            }
        },
        "podSelector": {"matchLabels": {"cnpg.io/cluster": "omnigent-postgres"}},
    }
    database_consumers = {
        "omnigent-saas-migration",
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-runner-agent",
        "omnigent-saas-preview-edge",
        "omnigent-saas-preview-owner",
    }
    assert all(
        sum(
            rule.get("to") == [postgres_peer]
            and rule.get("ports") == [{"protocol": "TCP", "port": 5432}]
            for rule in policies[name]["spec"]["egress"]
        )
        == 1
        for name in database_consumers
    )
    rendered = (output_dir / "kubernetes.network-policy.yaml").read_text(encoding="utf-8")
    assert SOURCE_EXTERNAL_DATABASE_NAMESPACE not in rendered


def test_preview_owner_is_isolated_singleton_and_explicit_beta_blocker() -> None:
    items = _items("kubernetes.production.yaml")
    owner = _deployment(items, "omnigent-saas-preview-owner")
    assert owner["spec"]["replicas"] == 1
    assert owner["spec"]["strategy"] == {"type": "Recreate"}
    assert owner["metadata"]["annotations"]["omnigent.io/production-eligible"] == ("false")
    assert owner["metadata"]["annotations"]["omnigent.io/production-blocker"] == (
        "preview-owner-singleton"
    )
    assert owner["spec"]["template"]["metadata"]["annotations"][
        "omnigent.io/production-blocker"
    ] == ("preview-owner-singleton")
    pod = owner["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {row["name"]: row["value"] for row in container["env"]}
    secrets = {volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume}
    assert container["command"] == ["omnigent-saas-preview-owner"]
    assert pod["serviceAccountName"] == "omnigent-saas-preview-owner"
    assert pod["automountServiceAccountToken"] is False
    owner_service_account = next(
        item
        for item in items
        if item["kind"] == "ServiceAccount"
        and item["metadata"]["name"] == "omnigent-saas-preview-owner"
    )
    assert owner_service_account["automountServiceAccountToken"] is False
    assert not any(item["kind"] in {"Role", "RoleBinding"} for item in items)
    assert env["OMNIGENT_SAAS_PREVIEW_OWNER_DATABASE_URL_FILE"] == (
        "/runtime/preview-owner-database-url"
    )
    assert env["OMNIGENT_SAAS_PREVIEW_GATEWAY_REGISTRATION_TOKEN_FILE"] == (
        "/runtime/preview-gateway-registration-token"
    )
    assert env["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS"] == "9442,9443"
    assert env["OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_PORT"] == "9442"
    assert env["OMNIGENT_SAAS_PREVIEW_RUNNER_TUNNEL_HEARTBEAT_SECONDS"] == "15"
    assert {
        "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_KEY_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_SERVER_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_SERVER_KEY_FILE",
    } <= set(env)
    assert {
        "omnigent-saas-preview-owner-database",
        "omnigent-saas-preview-owner-registration-replace-owner12",
        "omnigent-saas-preview-owner-relay-client-tls-replace-owner12",
        "omnigent-saas-preview-owner-relay-server-tls-replace-owner12",
    } <= secrets
    stage_script = "\n".join(pod["initContainers"][0]["args"])
    assert (
        "install -m 0400 /source/registration/registration-token "
        "/runtime/preview-gateway-registration-token"
    ) in stage_script

    service = next(
        item
        for item in items
        if item["kind"] == "Service" and item["metadata"]["name"] == "omnigent-saas-preview-owner"
    )
    assert {(port["port"], port["targetPort"]) for port in service["spec"]["ports"]} == {
        (9442, "runner-wss"),
        (9443, "relay-mtls"),
    }
    assert service["spec"]["clusterIP"] == "None"
    for probe_name, path in (
        ("startupProbe", "/readyz"),
        ("readinessProbe", "/readyz"),
        ("livenessProbe", "/livez"),
    ):
        assert container[probe_name]["httpGet"] == {
            "path": path,
            "port": "runner-wss",
            "scheme": "HTTPS",
        }
    for deployment in (
        item for item in items if item["kind"] == "Deployment" and item is not owner
    ):
        assert "OMNIGENT_SAAS_PREVIEW_OWNER_DATABASE_URL_FILE" not in yaml.safe_dump(deployment)


def test_redundant_services_have_pdbs_but_singletons_do_not_claim_redundancy() -> None:
    items = _items("kubernetes.production.yaml")
    pdbs = {
        item["metadata"]["name"]: item for item in items if item["kind"] == "PodDisruptionBudget"
    }
    assert set(pdbs) == {
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-preview-edge",
    }
    assert all(item["spec"]["minAvailable"] == 1 for item in pdbs.values())
