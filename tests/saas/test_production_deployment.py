from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from saas.production.service_bindings import (
    ProductionServiceRoleBinding,
    render_production_service_role_bindings,
)

_ROOT = Path(__file__).resolve().parents[2]
_DEPLOYMENT = _ROOT / "saas" / "deployment" / "server"


def _items(name: str) -> list[dict[str, Any]]:
    document = yaml.safe_load((_DEPLOYMENT / name).read_text(encoding="utf-8"))
    assert document["kind"] == "List"
    return document["items"]


def _pod_specs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for item in items:
        if item["kind"] in {"Deployment", "Job"}:
            specs.append(item["spec"]["template"]["spec"])
    return specs


def test_k3s_images_are_digest_only_and_never_expose_host_port_8000() -> None:
    items = (
        _items("kubernetes.migration.yaml")
        + _items("kubernetes.artifact-admission.yaml")
        + _items("kubernetes.production.yaml")
    )
    pod_specs = _pod_specs(items)

    for pod in pod_specs:
        for container in [*pod.get("initContainers", []), *pod["containers"]]:
            image = container["image"]
            assert "@sha256:" in image
            assert len(image.rsplit("@sha256:", 1)[1]) == 64
            assert "hostPort" not in container
    services = [item for item in items if item["kind"] == "Service"]
    assert {service["metadata"]["name"] for service in services} == {
        "omnigent-saas-preview-edge",
        "omnigent-saas-preview-owner",
        "omnigent-saas-runner-control",
        "omnigent-saas-server",
    }
    assert all(service["spec"]["type"] == "ClusterIP" for service in services)
    assert all("nodePort" not in port for service in services for port in service["spec"]["ports"])
    release = next(
        item
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )
    image_digests = {
        container["image"].rsplit("@", 1)[1]
        for pod in pod_specs
        for container in [*pod.get("initContainers", []), *pod["containers"]]
    }
    assert image_digests == {release["data"]["OMNIGENT_SAAS_IMAGE_DIGEST"]}


def test_all_pods_stage_owner_only_files_without_root_or_plaintext_secret_envs() -> None:
    items = (
        _items("kubernetes.migration.yaml")
        + _items("kubernetes.artifact-admission.yaml")
        + _items("kubernetes.production.yaml")
    )

    for pod in _pod_specs(items):
        pod_security = pod["securityContext"]
        assert pod_security["runAsNonRoot"] is True
        assert pod_security["runAsUser"] == 10001
        assert pod_security["runAsGroup"] == 10001
        assert pod_security["fsGroup"] == 10001
        for container in [*pod.get("initContainers", []), *pod["containers"]]:
            security = container["securityContext"]
            assert security["runAsNonRoot"] is True
            assert security["runAsUser"] == 10001
            assert security["capabilities"]["drop"] == ["ALL"]
            for entry in container.get("env", []):
                assert "secretKeyRef" not in entry
                assert "valueFrom" not in entry
                if entry["name"] not in {
                    "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI",
                    "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_ENDPOINT_URL",
                }:
                    assert "://" not in str(entry.get("value", ""))
        for init in pod.get("initContainers", []):
            command = "\n".join(init.get("args", []))
            assert "install -m 0400" in command
            assert " -o " not in command
            assert " -g " not in command


def test_migration_job_has_four_file_only_authorities_and_no_service_login_secret() -> None:
    items = _items("kubernetes.migration.yaml")
    release = next(
        item
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_SOURCE_SHA" in item.get("data", {})
    )
    job = next(item for item in items if item["kind"] == "Job")
    pod = job["spec"]["template"]["spec"]
    migration = pod["containers"][0]
    env_names = {entry["name"] for entry in migration["env"]}

    authority_names = {
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL_FILE",
    }
    assert env_names == authority_names | {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE"}
    authority_secret_names = {
        volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume
    }
    assert authority_secret_names == {
        "omnigent-saas-principal-operator",
        "omnigent-saas-database-owner",
        "omnigent-saas-official-owner",
        "omnigent-saas-control-plane-owner",
        "omnigent-saas-postgresql-ca",
    }
    assert all("secretKeyRef" not in entry for entry in migration["env"])
    assert release["data"] == {
        "OMNIGENT_SAAS_PRODUCT_REVISION": "0" * 40,
        "OMNIGENT_SAAS_SOURCE_SHA": "0" * 40,
    }
    assert release["immutable"] is True
    assert "replace-release12" in release["metadata"]["name"]
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 900
    assert job["spec"]["ttlSecondsAfterFinished"] == 600


def test_artifact_admission_job_is_narrow_revision_bound_and_runs_before_server() -> None:
    items = _items("kubernetes.artifact-admission.yaml")
    release_item = next(item for item in items if item["kind"] == "ConfigMap")
    release = release_item["data"]
    job = next(item for item in items if item["kind"] == "Job")
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    secrets = {volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume}

    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 300
    assert pod["automountServiceAccountToken"] is False
    assert container["command"] == ["python", "-m", "saas.production.artifact_admission"]
    assert container["env"] == [
        {
            "name": "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_FILE",
            "value": "/runtime/artifact-credentials",
        }
    ]
    assert secrets == {"omnigent-artifact-creds-replace-credential12"}
    assert release_item["immutable"] is True
    assert "replace-release12" in release_item["metadata"]["name"]
    assert "replace-release12" in job["metadata"]["name"]
    assert set(release) == {
        "AWS_EC2_METADATA_DISABLED",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION",
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL",
        "OMNIGENT_SAAS_ARTIFACT_REGION",
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI",
        "OMNIGENT_SAAS_IMAGE_DIGEST",
        "OMNIGENT_SAAS_PRODUCT_REVISION",
        "OMNIGENT_SAAS_RELEASE_INCARNATION",
        "OMNIGENT_SAAS_SOURCE_SHA",
        "PYTHONDONTWRITEBYTECODE",
    }
    assert (
        release["OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION"]
        == job["spec"]["template"]["metadata"]["annotations"][
            "omnigent.io/artifact-credential-revision"
        ]
    )
    assert (
        release["OMNIGENT_SAAS_RELEASE_INCARNATION"]
        == job["spec"]["template"]["metadata"]["annotations"]["omnigent.io/release-incarnation"]
    )
    assert release["OMNIGENT_SAAS_SOURCE_SHA"] == release["OMNIGENT_SAAS_PRODUCT_REVISION"]


def test_server_consumes_exact_artifact_admission_authority_and_rollout_bindings() -> None:
    admission_items = _items("kubernetes.artifact-admission.yaml")
    production_items = _items("kubernetes.production.yaml")
    admission_release = next(item for item in admission_items if item["kind"] == "ConfigMap")[
        "data"
    ]
    production_release_item = next(
        item
        for item in production_items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )
    production_release = production_release_item["data"]
    server = next(
        item
        for item in production_items
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "omnigent-saas-server"
    )
    template = server["spec"]["template"]
    pod = template["spec"]
    container = next(item for item in pod["containers"] if item["name"] == "server")
    env = {item["name"]: item["value"] for item in container["env"]}
    volumes = {item["name"]: item for item in pod["volumes"]}

    for name in (
        "OMNIGENT_SAAS_PRODUCT_REVISION",
        "OMNIGENT_SAAS_SOURCE_SHA",
        "OMNIGENT_SAAS_IMAGE_DIGEST",
        "OMNIGENT_SAAS_RELEASE_INCARNATION",
        "OMNIGENT_SAAS_ARTIFACT_STORE_URI",
        "OMNIGENT_SAAS_ARTIFACT_ENDPOINT_URL",
        "OMNIGENT_SAAS_ARTIFACT_REGION",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE",
        "OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION",
    ):
        assert admission_release[name] == production_release[name]
    assert production_release_item["immutable"] is True
    assert "replace-release12" in production_release_item["metadata"]["name"]
    assert container["envFrom"] == [
        {"configMapRef": {"name": production_release_item["metadata"]["name"]}}
    ]
    assert env["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_FILE"] == (
        "/runtime/artifact-admission-receipt"
    )
    assert volumes["artifact-receipt-source"]["secret"]["secretName"] == (
        "omnigent-artifact-receipt-replace-release12"
    )
    annotations = template["metadata"]["annotations"]
    assert (
        annotations["omnigent.io/artifact-credential-revision"]
        == production_release["OMNIGENT_SAAS_ARTIFACT_CREDENTIAL_REVISION"]
    )
    assert (
        annotations["omnigent.io/artifact-admission-receipt-revision"]
        == (production_release["OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION"])
    )
    assert (
        annotations["omnigent.io/release-incarnation"]
        == production_release["OMNIGENT_SAAS_RELEASE_INCARNATION"]
    )


def test_migration_and_runtime_share_one_canonical_thirteen_binding_profile() -> None:
    migration_items = _items("kubernetes.migration.yaml")
    production_items = _items("kubernetes.production.yaml")
    manifests = []
    for items in (migration_items, production_items):
        config = next(
            item
            for item in items
            if item["kind"] == "ConfigMap" and "service-role-bindings.json" in item.get("data", {})
        )
        assert config["immutable"] is True
        assert "replace-bindings12" in config["metadata"]["name"]
        manifests.append(config["data"]["service-role-bindings.json"])
    assert manifests[0] == manifests[1]
    document = yaml.safe_load(manifests[0])
    bindings = tuple(
        ProductionServiceRoleBinding(
            service=row["service"],
            login=row["login"],
            base_role=row["base_role"],
        )
        for row in document["bindings"]
    )
    assert len(bindings) == 13
    assert manifests[0] == render_production_service_role_bindings(bindings)


def test_runtime_worker_receives_only_dispatcher_executor_and_receipt_files() -> None:
    items = _items("kubernetes.production.yaml")
    worker = next(
        item
        for item in items
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "omnigent-saas-worker"
    )
    pod = worker["spec"]["template"]["spec"]
    secret_names = {
        volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume
    }

    assert secret_names == {
        "omnigent-saas-migration-receipt",
        "omnigent-saas-dispatcher-database",
        "omnigent-saas-executor-database",
        "omnigent-saas-postgresql-ca",
        "omnigent-saas-preview-readiness-ca",
        "omnigent-saas-runner-control-tls",
    }
    rendered = yaml.safe_dump(worker)
    assert "owner" not in rendered
    assert "OMNIGENT_SAAS_DISPATCHER_DATABASE_URL_FILE" in rendered
    assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE" in rendered

    worker_container = next(
        container for container in pod["containers"] if container["name"] == "worker"
    )
    control_container = next(
        container for container in pod["containers"] if container["name"] == "runner-control"
    )
    worker_env = {entry["name"]: entry["value"] for entry in worker_container["env"]}
    control_env = {entry["name"]: entry["value"] for entry in control_container["env"]}
    assert worker_env["OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE"] == (
        "/runtime/executor-database-url"
    )
    assert control_env["OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE"] == (
        "/runtime/executor-database-url"
    )
    assert (
        next(
            volume["secret"]["secretName"]
            for volume in pod["volumes"]
            if volume["name"] == "executor-source"
        )
        == "omnigent-saas-executor-database"
    )
    assert (
        next(
            mount["name"]
            for mount in worker_container["volumeMounts"]
            if mount["mountPath"] == "/runtime"
        )
        == "worker-runtime-secrets"
    )
    assert (
        next(
            mount["name"]
            for mount in control_container["volumeMounts"]
            if mount["mountPath"] == "/runtime"
        )
        == "runner-control-runtime-secrets"
    )
    worker_stage, control_stage = pod["initContainers"]
    worker_script = "\n".join(worker_stage["args"])
    control_script = "\n".join(control_stage["args"])
    assert "runner-control-server.key" not in worker_script
    assert "runner-control-tls-source" not in {
        mount["name"] for mount in worker_stage["volumeMounts"]
    }
    assert "dispatcher-database-url" not in control_script
    assert "dispatcher-source" not in {mount["name"] for mount in control_stage["volumeMounts"]}


def test_runner_control_is_mtls_only_and_reuses_the_narrow_executor_authority() -> None:
    items = _items("kubernetes.production.yaml")
    worker = next(
        item
        for item in items
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "omnigent-saas-worker"
    )
    pod = worker["spec"]["template"]["spec"]
    control = next(
        container for container in pod["containers"] if container["name"] == "runner-control"
    )
    env = {entry["name"]: entry["value"] for entry in control["env"]}
    service = next(
        item
        for item in items
        if item["kind"] == "Service" and item["metadata"]["name"] == "omnigent-saas-runner-control"
    )

    assert control["command"] == ["python", "-m", "saas.production.runner_control"]
    assert set(env) == {
        "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_KEY_FILE",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE",
    }
    assert not any("DISPATCHER" in name or "OWNER" in name for name in env)
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"] == [
        {"name": "mtls", "port": 9444, "protocol": "TCP", "targetPort": "runner-control"},
        {
            "name": "tls-readiness",
            "port": 9445,
            "protocol": "TCP",
            "targetPort": "runner-ready",
        },
    ]


def test_runner_agents_have_file_only_double_bound_independent_identities() -> None:
    items = _items("kubernetes.production.yaml")
    deployments = [
        item
        for item in items
        if item["kind"] == "Deployment"
        and item["metadata"]["name"].startswith("omnigent-saas-runner-agent-")
    ]
    assert {item["metadata"]["name"] for item in deployments} == {
        "omnigent-saas-runner-agent-a",
        "omnigent-saas-runner-agent-b",
    }
    identities: set[str] = set()
    identity_secrets: set[str] = set()
    database_secrets: set[str] = set()
    recovery_secrets: set[str] = set()
    repository_spec_secrets: set[str] = set()
    repository_credential_secrets: set[str] = set()
    fleet_secrets: set[str] = set()
    fleet_items = [
        {"key": name, "path": name}
        for name in (
            "runner-database-fleet.json",
            "evidence-context.json",
            "trust-pins.json",
            "environment-attestation.json",
            "environment-attestation.signature",
            "environment-attestation-public.pem",
            "admission-receipt.json",
            "admission-receipt.signature",
            "admission-receipt-public.pem",
        )
    ]
    for deployment in deployments:
        pod = deployment["spec"]["template"]["spec"]
        runner = pod["containers"][0]
        env = {entry["name"]: entry["value"] for entry in runner["env"]}
        volumes = {volume["name"]: volume for volume in pod["volumes"]}

        assert deployment["spec"]["replicas"] == 0
        assert deployment["spec"]["strategy"] == {"type": "Recreate"}
        assert deployment["metadata"]["annotations"] == {
            "omnigent.io/runner-fleet-phase": "admission",
            "omnigent.io/production-blocker": "runner-fleet-admission-pending",
        }
        assert runner["command"] == ["python", "-m", "saas.production.runner_agent"]
        identities.add(env["OMNIGENT_SAAS_RUNNER_ID"])
        identity_secrets.add(volumes["runner-identity-source"]["secret"]["secretName"])
        database_secrets.add(volumes["runner-database-source"]["secret"]["secretName"])
        recovery_secrets.add(volumes["artifact-credentials-source"]["secret"]["secretName"])
        repository_spec_secrets.add(
            volumes["runner-repository-spec-source"]["secret"]["secretName"]
        )
        repository_credential_secrets.add(
            volumes["runner-repository-credentials-source"]["secret"]["secretName"]
        )
        fleet_secrets.add(volumes["runner-fleet-source"]["secret"]["secretName"])
        assert volumes["runner-fleet-source"]["secret"]["defaultMode"] == 0o400
        assert volumes["runner-fleet-source"]["secret"]["items"] == fleet_items
        assert env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_FILE"] == (
            "/runtime/runner-recovery-artifact-credentials"
        )
        assert env["OMNIGENT_SAAS_PREVIEW_RUNNER_CA_CERTIFICATE_FILE"] == (
            "/runtime/preview-runner-ca.crt"
        )
        assert env["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS"] == "9442"
        assert env["OMNIGENT_SAAS_PREVIEW_RUNNER_SOCKET_ROOT"] == "/preview/socket"
        assert env["OMNIGENT_SAAS_PREVIEW_RUNNER_LOG_ROOT"] == "/preview/log"
        assert env["OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE"] == (
            "/runtime/runner-agent-database-url"
        )
        assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL_FILE" not in env
        assert "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE" not in env
        assert "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE" not in env
        assert "executor-source" not in volumes
        assert "receipt-source" not in volumes
        assert "bindings-source" not in volumes
        assert runner["resources"] == {
            "requests": {"cpu": "500m", "memory": "512Mi"},
            "limits": {"cpu": "1", "memory": "512Mi"},
        }
        assert env["OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_NAMESPACE"] == (
            "replace-with-runner-fleet-namespace"
        )
        assert env["OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_SHA256"] == "0" * 64
        assert env["OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_EVIDENCE_CONTEXT_SHA256"] == ("0" * 64)
        assert env["OMNIGENT_SAAS_RUNNER_DATABASE_FLEET_TRUST_PINS_SHA256"] == "0" * 64
        assert env["OMNIGENT_SAAS_RUNNER_REPOSITORY_BINDINGS_FILE"] == (
            "/repository/state/repository-bindings.json"
        )
        assert env["OMNIGENT_SAAS_RUNNER_REPOSITORY_RECEIPT_FILE"] == (
            "/repository/state/repository-mirror-receipt.json"
        )
        assert env["OMNIGENT_SAAS_RUNNER_REPOSITORY_MIRROR_ROOT"].startswith(
            "/repository/state/mirrors/"
        )
        assert env["OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT"] in {"a", "b"}
        annotations = deployment["spec"]["template"]["metadata"]["annotations"]
        assert annotations["omnigent.io/runner-repository-expected-binding-keys"] == ("primary")
        for name in (
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256",
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256",
            "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256",
        ):
            assert env[name] == "0" * 64
        assert not any("PRIVATE_KEY" in name or "ADMIN_DATABASE" in name for name in env)
        assert (
            volumes["runner-database-source"]["secret"]["secretName"]
            != "omnigent-saas-executor-database"
        )
        stage = pod["initContainers"][0]
        stage_script = "\n".join(stage["args"])
        assert "/source/runner-database/value" in stage_script
        assert "/runtime/runner-agent-database-url" in stage_script
        assert "executor-database-url" not in stage_script
        assert "postgresql-migration-receipt" not in stage_script
        assert "service-role-bindings.json" not in stage_script
        assert "/source/repositories/repository-bindings.json" not in stage_script
        assert (
            "install -m 0400 /source/repository-spec/repository-provisioning.json "
            "/provisioning-private/spec/repository-provisioning.json"
        ) in stage_script
        assert (
            "install -m 0400 /source/repository-credentials/primary.credential "
            "/provisioning-private/credentials/primary.credential"
        ) in stage_script
        assert stage_script.count("/source/repository-credentials/") == 1
        assert volumes["runner-repository-credentials-source"]["secret"]["items"] == [
            {"key": "primary.credential", "path": "primary.credential"}
        ]
        assert (
            "omnigent-saas-provision-runner-repositories --spec "
            "/provisioning-private/spec/repository-provisioning.json "
            "--expected-binding-key primary"
        ) in stage_script
        for source_name in (
            "runner-database-fleet.json",
            "evidence-context.json",
            "trust-pins.json",
            "environment-attestation.json",
            "environment-attestation.signature",
            "environment-attestation-public.pem",
            "admission-receipt.json",
            "admission-receipt.signature",
            "admission-receipt-public.pem",
        ):
            assert f"/source/fleet/{source_name}" in stage_script
        assert "admission-receipt-private" not in stage_script.lower()
        assert "receipt-private-key" not in stage_script.lower()
        assert "admin-database" not in stage_script.lower()
        assert "private.pem" not in stage_script.lower()
        assert volumes["preview-runner-ca-source"]["secret"]["secretName"] == (
            "omnigent-saas-preview-runner-tunnel-ca"
        )
        assert not any(name.startswith(("AWS_", "BOTO")) for name in env)
        assert not any("DISPATCHER" in name or "OWNER_DATABASE" in name for name in env)
        main_mounts = {mount["name"]: mount for mount in runner["volumeMounts"]}
        assert "runner-repository-spec-source" not in main_mounts
        assert "runner-repository-credentials-source" not in main_mounts
        assert "runner-repository-private" not in main_mounts
        assert "runner-fleet-source" not in main_mounts
        assert main_mounts["repository-state"] == {
            "name": "repository-state",
            "mountPath": "/repository",
        }
        assert main_mounts["work"] == {"name": "work", "mountPath": "/work"}
        assert (
            env["OMNIGENT_SAAS_RUNNER_REPOSITORY_MIRROR_ROOT"].split("/", 2)[1]
            != (env["OMNIGENT_SAAS_RUNNER_WORK_ROOT"].split("/", 2)[1])
        )

    assert len(identities) == 2
    assert len(identity_secrets) == 2
    assert database_secrets == {
        "omnigent-saas-runner-agent-a-database-g1",
        "omnigent-saas-runner-agent-b-database-g1",
    }
    assert len(recovery_secrets) == 2
    assert repository_spec_secrets == {
        "omnigent-saas-runner-a-repository-provisioning-replace-repospec12",
        "omnigent-saas-runner-b-repository-provisioning-replace-repospec12",
    }
    assert repository_credential_secrets == {
        "omnigent-saas-runner-a-repository-credentials-replace-repocreds12",
        "omnigent-saas-runner-b-repository-credentials-replace-repocreds12",
    }
    assert fleet_secrets == {"omnigent-saas-runner-database-fleet-replace-fleetpins12"}

    readme = (_DEPLOYMENT / "README.md").read_text(encoding="utf-8")
    assert "runner_<runner_uuid_without_hyphens>_g<connection_generation>" in readme
    assert "outside the canonical exact-thirteen service-role binding manifest" in " ".join(
        readme.split()
    )
    collapsed_readme = " ".join(readme.split())
    assert 'expected_binding_keys=["primary"]' in collapsed_readme
    assert "single-repository Beta stager" in collapsed_readme
    assert "Production multi-binding or multi-tenant repository fan-out remains blocked" in (
        collapsed_readme
    )
    assert "owner-rendered exact `items` and copy projection" in collapsed_readme
    assert "`/repository` read-write" in collapsed_readme
    assert "official sandbox's cwd/read/write grants must never include `/repository`" in (
        collapsed_readme
    )


def test_worker_and_runner_control_probes_use_their_dedicated_health_contracts() -> None:
    items = _items("kubernetes.production.yaml")
    worker_deployment = next(
        item
        for item in items
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "omnigent-saas-worker"
    )
    pod = worker_deployment["spec"]["template"]["spec"]
    containers = {container["name"]: container for container in pod["containers"]}
    init = next(
        container
        for container in pod["initContainers"]
        if container["name"] == "stage-worker-secrets"
    )
    init_script = "\n".join(init["args"])
    init_mounts = {mount["name"]: mount for mount in init["volumeMounts"]}
    volumes = {volume["name"]: volume for volume in pod["volumes"]}

    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["runAsGroup"] == 10001
    assert "install -d -m 0700 /health/state" in init_script
    assert init_mounts["worker-health-state"]["mountPath"] == "/health"
    assert volumes["worker-health-state"] == {
        "name": "worker-health-state",
        "emptyDir": {"medium": "Memory", "sizeLimit": "64Ki"},
    }

    worker = containers["worker"]
    worker_env = {row["name"]: row["value"] for row in worker["env"]}
    assert worker_env["OMNIGENT_SAAS_WORKER_HEALTH_STATE_FILE"] == (
        "/health/state/worker-health.json"
    )
    assert {mount["name"]: mount["mountPath"] for mount in worker["volumeMounts"]}[
        "worker-health-state"
    ] == "/health"
    for probe_name, mode in (
        ("startupProbe", "startup"),
        ("readinessProbe", "readiness"),
        ("livenessProbe", "liveness"),
    ):
        assert worker[probe_name]["exec"]["command"] == [
            "omnigent-saas-worker-health",
            "--mode",
            mode,
        ]

    runner_control = containers["runner-control"]
    assert runner_control["startupProbe"]["exec"]["command"] == [
        "omnigent-saas-runner-control-readiness"
    ]
    assert runner_control["readinessProbe"]["exec"]["command"] == [
        "omnigent-saas-runner-control-readiness"
    ]
    assert runner_control["livenessProbe"]["tcpSocket"] == {"port": "runner-control"}
    assert {port["name"]: port["containerPort"] for port in runner_control["ports"]} == {
        "runner-control": 9444,
        "runner-ready": 9445,
    }


def test_runner_fleet_public_trust_projection_is_complete_and_private_key_free() -> None:
    items = _items("kubernetes.production.yaml")
    runners = [
        item
        for item in items
        if item["kind"] == "Deployment"
        and item["metadata"]["name"].startswith("omnigent-saas-runner-agent-")
    ]
    sha_annotations = {
        "omnigent.io/runner-database-fleet-sha256",
        "omnigent.io/runner-database-fleet-context-sha256",
        "omnigent.io/runner-database-fleet-trust-pins-sha256",
        "omnigent.io/runner-database-fleet-attestation-public-key-sha256",
        "omnigent.io/runner-database-fleet-attestation-sha256",
        "omnigent.io/runner-database-fleet-attestation-signature-sha256",
        "omnigent.io/runner-database-fleet-receipt-public-key-sha256",
        "omnigent.io/runner-database-fleet-receipt-sha256",
        "omnigent.io/runner-database-fleet-receipt-signature-sha256",
        "omnigent.io/runner-repository-credential-revision",
        "omnigent.io/runner-repository-spec-sha256",
        "omnigent.io/runner-repository-bindings-sha256",
        "omnigent.io/runner-repository-receipt-sha256",
    }
    identity_annotations = {
        "omnigent.io/runner-database-fleet-namespace",
        "omnigent.io/runner-database-fleet-admission-epoch",
        "omnigent.io/runner-database-fleet-attestation-issuer",
        "omnigent.io/runner-database-fleet-attestation-key-id",
        "omnigent.io/runner-database-fleet-receipt-issuer",
        "omnigent.io/runner-database-fleet-receipt-key-id",
        "omnigent.io/runner-repository-slot",
        "omnigent.io/runner-repository-expected-binding-keys",
    }
    for deployment in runners:
        annotations = deployment["spec"]["template"]["metadata"]["annotations"]
        assert sha_annotations | identity_annotations <= set(annotations)
        assert all(annotations[name] == f"sha256:{'0' * 64}" for name in sha_annotations)
        assert annotations["omnigent.io/runner-database-fleet-admission-epoch"] == "0"
        assert all(
            "replace-with-" in annotations[name]
            for name in identity_annotations
            - {
                "omnigent.io/runner-database-fleet-admission-epoch",
                "omnigent.io/runner-repository-slot",
                "omnigent.io/runner-repository-expected-binding-keys",
            }
        )
        assert annotations["omnigent.io/runner-repository-slot"] in {"a", "b"}
        assert annotations["omnigent.io/runner-repository-expected-binding-keys"] == ("primary")
        serialized = yaml.safe_dump(deployment)
        assert "ADMISSION_RECEIPT_PRIVATE_KEY" not in serialized
        assert "FLEET_ADMIN_DATABASE_URL" not in serialized


def test_runner_production_factories_are_concrete_and_not_deployment_placeholders() -> None:
    items = _items("kubernetes.production.yaml")
    release = next(
        item
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )["data"]

    assert release["OMNIGENT_SAAS_RUNNER_EXECUTOR_FACTORY"] == (
        "saas.production.runner_executor:build_production_host_isolation_executor"
    )
    assert release["OMNIGENT_SAAS_RUNNER_ADAPTER_FACTORY"] == (
        "saas.production.runner_readiness:build_remote_tls_runner_control_readiness"
    )
    assert release["OMNIGENT_SAAS_WORKER_RUNNER_READINESS_FACTORY"] == (
        "saas.production.runner_readiness:build_postgresql_runner_control_readiness"
    )
    assert release["OMNIGENT_SAAS_WORKER_PREVIEW_READINESS_FACTORY"] == (
        "saas.production.preview_readiness:build_remote_tls_preview_readiness"
    )
    assert release["OMNIGENT_SAAS_RUNNER_CONTROL_CERTIFICATE_AUTHORIZER_FACTORY"] == (
        "saas.production.runner_control:build_durable_runner_control_certificate_authorizer"
    )
    assert "OMNIGENT_SAAS_RUNNER_ID" not in release
    assert "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION" not in release
    assert "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI" not in release
    assert "OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE" not in release
    assert not any("replace.runner" in value for value in release.values())


def test_server_and_runner_artifact_authorities_are_three_way_isolated() -> None:
    items = _items("kubernetes.production.yaml")
    release = next(
        item["data"]
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )
    deployments = {
        item["metadata"]["name"]: item for item in items if item["kind"] == "Deployment"
    }

    def artifact_binding(name: str) -> tuple[str, str, dict[str, str]]:
        pod = deployments[name]["spec"]["template"]["spec"]
        secret = next(
            volume["secret"]["secretName"]
            for volume in pod["volumes"]
            if volume["name"] == "artifact-credentials-source"
        )
        container = pod["containers"][0]
        credentials_file = next(
            entry["value"]
            for entry in container["env"]
            if entry["name"].endswith("ARTIFACT_CREDENTIALS_FILE")
        )
        env = {entry["name"]: entry["value"] for entry in container["env"]}
        return secret, credentials_file, env

    server_secret, server_file, _server_env = artifact_binding("omnigent-saas-server")
    assert (server_secret, server_file) == (
        "omnigent-artifact-creds-replace-credential12",
        "/runtime/artifact-credentials",
    )
    runner_bindings = []
    for suffix in ("a", "b"):
        name = f"omnigent-saas-runner-agent-{suffix}"
        secret, credentials_file, env = artifact_binding(name)
        runner_bindings.append((secret, env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI"]))
        assert credentials_file == "/runtime/runner-recovery-artifact-credentials"
        assert env["OMNIGENT_SAAS_RUNNER_ID"] in env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI"]
        assert (
            env["OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION"]
            in env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_URI"]
        )
        assert (
            env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE"]
            != (release["OMNIGENT_SAAS_ARTIFACT_CREDENTIALS_PROFILE"])
        )
        assert env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIALS_PROFILE"] == (
            f"runner-{env['OMNIGENT_SAAS_RUNNER_ID']}-"
            f"g{env['OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION']}"
        )
        assert env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION"].startswith(
            "sha256:"
        )
        annotations = deployments[name]["spec"]["template"]["metadata"]["annotations"]
        assert (
            annotations["omnigent.io/runner-recovery-artifact-credential-revision"]
            == env["OMNIGENT_SAAS_RUNNER_RECOVERY_ARTIFACT_CREDENTIAL_REVISION"]
        )
        assert deployments[name]["spec"]["strategy"] == {"type": "Recreate"}
        assert deployments[name]["spec"]["replicas"] == 0

    assert len({binding[0] for binding in runner_bindings}) == 2
    assert len({binding[1] for binding in runner_bindings}) == 2
    assert all(release["OMNIGENT_SAAS_ARTIFACT_STORE_URI"] != uri for _, uri in runner_bindings)


def test_preview_edge_is_narrow_cookie_isolated_and_has_no_application_ingress() -> None:
    items = _items("kubernetes.production.yaml")
    release = next(
        item
        for item in items
        if item["kind"] == "ConfigMap" and "OMNIGENT_SAAS_IMAGE_DIGEST" in item.get("data", {})
    )["data"]
    deployment = next(
        item
        for item in items
        if item["kind"] == "Deployment"
        and item["metadata"]["name"] == "omnigent-saas-preview-edge"
    )
    pod = deployment["spec"]["template"]["spec"]
    edge = pod["containers"][0]
    env = {entry["name"]: entry["value"] for entry in edge["env"]}
    secrets = {volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume}

    assert edge["command"] == ["python", "-m", "saas.production.preview_edge"]
    assert set(env) == {
        "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE",
        "OMNIGENT_SAAS_PREVIEW_EDGE_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS",
        "OMNIGENT_SAAS_PREVIEW_RELAY_CA_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_PREVIEW_RELAY_CLIENT_KEY_FILE",
        "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_CERTIFICATE_FILE",
        "OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_KEY_FILE",
        "OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE",
    }
    assert secrets == {
        "omnigent-saas-migration-receipt",
        "omnigent-saas-postgresql-ca",
        "omnigent-saas-preview-edge-database",
        "omnigent-saas-preview-readiness-tls",
        "omnigent-saas-preview-relay-client-tls",
    }
    assert release["OMNIGENT_SAAS_PREVIEW_TUNNEL_FACTORY"] == (
        "saas.production.preview_relay:build_production_preview_tunnel"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES"] == (
        "omnigent.svc.cluster.local"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"] == (
        "replace-with-cluster-pod-cidr"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS"] == "9443"
    assert env["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS"] == "9443"
    assert release["OMNIGENT_SAAS_PREVIEW_READINESS_SERVER_NAME"] == (
        "omnigent-saas-preview-edge.omnigent.svc.cluster.local"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_DNS_SUFFIXES"] == (
        "omnigent.svc.cluster.local"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS"] == (
        "replace-with-cluster-service-cidr"
    )
    assert release["OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_PORTS"] == "8443"
    assert "OMNIGENT_SAAS_OUTBOX_FALLBACK_PUBLISHER_FACTORY" not in release
    assert not any(item["kind"] == "Ingress" for item in items)


def test_every_database_process_pins_the_staged_cnpg_ca_public_key() -> None:
    migration = _items("kubernetes.migration.yaml")
    production = _items("kubernetes.production.yaml")
    database_pods = {
        "omnigent-saas-postgresql-migration": "/authority/postgresql-ca.crt",
        "omnigent-saas-server": "/runtime/postgresql-ca.crt",
        "omnigent-saas-worker": "/runtime/postgresql-ca.crt",
        "omnigent-saas-runner-agent-a": "/runtime/postgresql-ca.crt",
        "omnigent-saas-runner-agent-b": "/runtime/postgresql-ca.crt",
        "omnigent-saas-preview-edge": "/runtime/postgresql-ca.crt",
        "omnigent-saas-preview-owner": "/runtime/postgresql-ca.crt",
    }
    items = migration + production
    for name, target in database_pods.items():
        workload = next(
            item
            for item in items
            if item["kind"] in {"Deployment", "Job"} and item["metadata"]["name"] == name
        )
        pod = workload["spec"]["template"]["spec"]
        command = "\n".join(pod["initContainers"][0]["args"])
        secret_names = {
            volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume
        }
        ca_volume = next(
            volume for volume in pod["volumes"] if volume["name"] == "postgresql-ca-source"
        )
        assert f"install -m 0400 /source/postgresql-ca/ca.crt {target}" in command
        assert "omnigent-saas-postgresql-ca" in secret_names
        assert ca_volume["secret"] == {
            "secretName": "omnigent-saas-postgresql-ca",
            "defaultMode": 0o400,
            "items": [{"key": "ca.crt", "path": "ca.crt"}],
        }

    public_ca_volumes = {
        "omnigent-saas-server": {
            "runner-control-ca-source": "omnigent-saas-runner-control-ca",
            "preview-readiness-ca-source": "omnigent-saas-preview-readiness-ca",
        },
        "omnigent-saas-worker": {
            "preview-readiness-ca-source": "omnigent-saas-preview-readiness-ca"
        },
        "omnigent-saas-runner-agent-a": {
            "preview-runner-ca-source": "omnigent-saas-preview-runner-tunnel-ca"
        },
        "omnigent-saas-runner-agent-b": {
            "preview-runner-ca-source": "omnigent-saas-preview-runner-tunnel-ca"
        },
    }
    for workload_name, expected_volumes in public_ca_volumes.items():
        workload = next(
            item
            for item in production
            if item["kind"] == "Deployment" and item["metadata"]["name"] == workload_name
        )
        volumes = {
            volume["name"]: volume for volume in workload["spec"]["template"]["spec"]["volumes"]
        }
        for volume_name, secret_name in expected_volumes.items():
            assert volumes[volume_name]["secret"] == {
                "secretName": secret_name,
                "defaultMode": 0o400,
                "items": [{"key": "ca.crt", "path": "ca.crt"}],
            }

    readme = (_DEPLOYMENT / "README.md").read_text(encoding="utf-8")
    assert "omnigent-postgres-ca" in readme
    assert "omnigent-saas-postgresql-ca" in readme
    assert "omnigent-next-beta-data/omnigent-postgres-ca" in readme
    assert "omnigent-postgres-rw.omnigent-next-beta-data.svc.cluster.local" in readme
    assert "omnigent_next_beta" in readme
    assert "Never modify the live `omnigent-data` database ACLs" in readme
    assert "leaves the CNPG Cluster and" in readme
    assert "`omnigent-local-retain` PVCs intact" in readme
    assert "exact PostgreSQL `CONNECTION LIMIT 8`" in readme
    assert "Runner rejects `-1`, `0`, or any other observed value" in readme
    assert "sslrootcert=/runtime/postgresql-ca.crt" in readme
    assert "Private CA key is never projected into any Pod" in " ".join(readme.split())


def test_beta_database_contract_requires_external_cnpg_postgresql18_admission() -> None:
    readme = (_DEPLOYMENT / "README.md").read_text(encoding="utf-8")
    collapsed_readme = " ".join(readme.split())

    assert "dedicated CNPG PostgreSQL 18" in readme
    assert "CNPG 16.14" not in readme
    assert "fresh PG16/PG18" not in readme
    assert "`max_notify_queue_pages=64`" in readme
    assert "`max_prepared_transactions=0`" in readme
    assert "`context=postmaster`" in readme
    assert "`source=configuration file`" in readme
    assert "`pending_restart=false`" in readme
    assert "SELECT count(*) FROM pg_prepared_xacts" in readme
    assert "`prepared_xacts=0`" in readme
    assert "PostgreSQL 16 is N-1 compatibility-only" in readme
    assert "`max_notify_queue_pages` being absent" in readme
    assert "direct Runner connection being expected-deny" in readme
    assert "not a deployable Beta database" in readme
    assert "separately reviewed external GitOps application must own the Cluster" in (
        collapsed_readme
    )
    assert "These exact four application manifests do not create a CNPG `Cluster`" in (
        collapsed_readme
    )

    required_order = readme.split("## Required order", maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
    ordered_contract = (
        "`postgresql_principals.sql`",
        "`postgresql_database.sql`",
        "`p0s000000011`",
        "`postgresql_roles.sql`",
        "`saas/control_plane/postgresql_runner_agent_cluster.psql`",
        "**Freeze the coupled evidence.**",
    )
    positions = [required_order.index(value) for value in ordered_contract]
    assert positions == sorted(positions)
    assert "short-lived, audited managed-cluster superuser channel" in required_order
    assert "superuser DSN or credential must never enter" in required_order
    assert "candidate receipt SHA256 and the managed-superuser evidence SHA256" in (
        " ".join(required_order.split())
    )

    manifest_names = (
        "kubernetes.migration.yaml",
        "kubernetes.artifact-admission.yaml",
        "kubernetes.network-policy.yaml",
        "kubernetes.production.yaml",
    )
    for name in manifest_names:
        manifest_text = (_DEPLOYMENT / name).read_text(encoding="utf-8")
        assert "postgresql_runner_agent_cluster" not in manifest_text
        assert "superuser" not in manifest_text.lower()
        for item in _items(name):
            assert item["kind"] != "Cluster"
            assert not item["apiVersion"].startswith("postgresql.cnpg.io/")


def test_beta_release_documentation_is_receipt_gated_and_keeps_production_no_go() -> None:
    readme = (_DEPLOYMENT / "README.md").read_text(encoding="utf-8")
    collapsed = " ".join(readme.split())

    assert "Beta-deployable only after" in collapsed
    assert "source Runner A/B Deployments deliberately have `replicas: 0`" in collapsed
    assert "omnigent-saas-runner-database-fleet-stage" in readme
    assert "omnigent-saas-runner-database-fleet-admit" in readme
    assert "omnigent-saas-runner-database-fleet-promote" in readme
    assert "no transient `online` window" in collapsed
    assert "database `clock_timestamp()`" in collapsed
    assert "five-minute expiry is a promotion deadline only" in collapsed
    assert "Startup and every claim revalidate" in collapsed
    assert "direct raw-DML transition surface" in collapsed
    assert "p0s10 RPC/ACL closure" in collapsed
    assert "enforcing proxy and central GC remains an explicit Enterprise Production NO-GO" in (
        collapsed
    )
    assert "omnigent-saas-render-kubernetes-release" in readme
    assert "release-render-evidence.json" in readme
    assert "`activeDeadlineSeconds: 900`" in readme
    assert "`ttlSecondsAfterFinished: 600`" in readme
    assert "`pids.max=128`" in readme
    assert "`memory.swap.max=0`" in readme
    assert "`memory.oom.group=1`" in readme
    assert "No YAML annotation may substitute for that receipt" in collapsed
    assert "`runner_egress_proxy_only`" in readme
    assert "not a production secret provider" in readme


def test_server_advertises_only_concrete_runner_and_holds_only_its_public_ca() -> None:
    items = _items("kubernetes.production.yaml")
    release = next(item for item in items if item["kind"] == "ConfigMap")
    server = next(
        item
        for item in items
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "omnigent-saas-server"
    )
    pod = server["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {entry["name"]: entry["value"] for entry in container["env"]}
    secret_names = {
        volume["secret"]["secretName"] for volume in pod["volumes"] if "secret" in volume
    }
    readme = (_DEPLOYMENT / "README.md").read_text(encoding="utf-8")

    assert release["data"]["OMNIGENT_SAAS_CAPABILITIES"] == ("tenant,run,runner,preview")
    assert release["data"]["OMNIGENT_SAAS_RUNNER_ADAPTER_FACTORY"] == (
        "saas.production.runner_readiness:build_remote_tls_runner_control_readiness"
    )
    assert release["data"]["OMNIGENT_SAAS_PREVIEW_ADAPTER_FACTORY"] == (
        "saas.production.preview_readiness:build_remote_tls_preview_readiness"
    )
    assert env["OMNIGENT_SAAS_RUNNER_READINESS_CA_CERTIFICATE_FILE"] == (
        "/runtime/runner-control-ca.crt"
    )
    assert env["OMNIGENT_SAAS_PREVIEW_READINESS_CA_CERTIFICATE_FILE"] == (
        "/runtime/preview-readiness-ca.crt"
    )
    assert "omnigent-saas-runner-control-ca" in secret_names
    assert "omnigent-saas-preview-readiness-ca" in secret_names
    assert "omnigent-saas-runner-control-tls" not in secret_names
    assert "omnigent-saas-preview-readiness-tls" not in secret_names
    rendered = yaml.safe_dump(server)
    assert "OMNIGENT_SAAS_EXECUTOR_DATABASE_URL" not in rendered
    assert "RUNNER_CONTROL_CLIENT" not in rendered
    assert "runner-control-server.key" not in rendered
    assert "external\nCA/HSM" in readme or "external CA/HSM" in readme
    assert "cross-host" in readme
    assert "must not be used as production evidence" in readme


def test_preview_readiness_ca_is_staged_exactly_once_per_consumer() -> None:
    items = _items("kubernetes.production.yaml")
    for deployment_name, init_name in (
        ("omnigent-saas-server", "stage-server-secrets"),
        ("omnigent-saas-worker", "stage-worker-secrets"),
    ):
        deployment = next(
            item
            for item in items
            if item["kind"] == "Deployment" and item["metadata"]["name"] == deployment_name
        )
        init = next(
            container
            for container in deployment["spec"]["template"]["spec"]["initContainers"]
            if container["name"] == init_name
        )
        script = "\n".join(init["args"])
        assert (
            script.count(
                "install -m 0400 /source/preview-readiness-ca/ca.crt "
                "/runtime/preview-readiness-ca.crt"
            )
            == 1
        )


def test_preview_exchange_authority_is_a_distinct_server_only_file() -> None:
    items = _items("kubernetes.production.yaml")
    deployments = [item for item in items if item["kind"] == "Deployment"]
    server = next(
        item for item in deployments if item["metadata"]["name"] == "omnigent-saas-server"
    )
    pod = server["spec"]["template"]["spec"]
    init = next(
        container
        for container in pod["initContainers"]
        if container["name"] == "stage-server-secrets"
    )
    script = "\n".join(init["args"])
    assert (
        script.count(
            "install -m 0400 /source/keys/preview-exchange-hmac-key "
            "/runtime/preview-exchange-hmac-key"
        )
        == 1
    )
    server_env = {entry["name"]: entry["value"] for entry in pod["containers"][0]["env"]}
    assert server_env["OMNIGENT_SAAS_PREVIEW_EXCHANGE_HMAC_KEY_FILE"] == (
        "/runtime/preview-exchange-hmac-key"
    )
    assert (
        len(
            {
                server_env["OMNIGENT_SAAS_CURSOR_HMAC_KEY_FILE"],
                server_env["OMNIGENT_SAAS_IDEMPOTENCY_HMAC_KEY_FILE"],
                server_env["OMNIGENT_SAAS_CONTEXT_SNAPSHOT_KEY_FILE"],
                server_env["OMNIGENT_SAAS_PREVIEW_EXCHANGE_HMAC_KEY_FILE"],
            }
        )
        == 4
    )
    for deployment in deployments:
        if deployment is server:
            continue
        assert "preview-exchange-hmac-key" not in yaml.safe_dump(deployment)


def test_no_mutable_compose_deployment_is_shipped() -> None:
    assert not (_DEPLOYMENT / "docker-compose.production.yaml").exists()
