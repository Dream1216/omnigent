"""Run disposable LiteLLM/PostgreSQL contracts; live credentials are explicit."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import secrets
import subprocess
import tarfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import sqlalchemy as sa

from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
    LiteLLMManagementError,
)
from saas.control_plane.model_deployments import (
    CompiledModelDeploymentDraft,
    CreateModelDeploymentDraft,
    compile_model_deployment_draft,
)
from saas.production.litellm_configuration_attestation import (
    LiteLLMAttestationError,
    LiteLLMConfigurationAttestor,
)
from saas.production.litellm_replica_readiness import (
    READINESS_SCOPE,
    LiteLLMReplicaEndpoint,
    LiteLLMReplicaReadinessAuthority,
    LiteLLMReplicaReadinessError,
)
from saas.production.model_protocol_probe import (
    ModelProbeAdmission,
    ModelProtocolProbe,
    ModelProtocolProbeConfiguration,
    ModelProtocolProbeError,
)

_REPO = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO / "tests/saas/fixtures/litellm"
_PROBE_MODEL = json.loads((_FIXTURES / "contract.json").read_text())["model"]
_RELEASE = json.loads((_REPO / "saas/production/litellm_release.json").read_text())
_POSTGRES = "postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
_PYTHON = "python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"


def _platform_usage(body: bytes, *, responses: bool) -> dict[str, int | None]:
    from saas.production.platform_model_gateway import _UsageParser

    parser = _UsageParser(responses=responses)
    parser.feed(body)
    parser.finish()
    usage = parser.final_usage
    return {
        "total_tokens": usage.total_tokens if usage is not None else None,
        "cache_hit_tokens": usage.input_cache_hit_tokens if usage is not None else None,
        "cache_miss_tokens": usage.input_cache_miss_tokens if usage is not None else None,
        "completion_tokens": usage.output_tokens if usage is not None else None,
    }


class ProbeFailure(RuntimeError):
    pass


class Probe:
    def __init__(
        self,
        context: str,
        image: str,
        source_archive: Path,
        architecture: str,
        upstream_image: str,
        real_provider_command: tuple[str, ...] = (),
        mode: str = "protocol_restore",
        dns_servers: tuple[str, ...] = (),
    ) -> None:
        self.context = context
        self.image = image
        self.source_archive = source_archive
        self.architecture = architecture
        self.upstream_image = upstream_image
        self.real_provider_command = real_provider_command
        self.mode = mode
        if len(dns_servers) > 3:
            raise ValueError("Probe DNS configuration is invalid")
        for value in dns_servers:
            address = ipaddress.ip_address(value)
            if address.is_loopback or address.is_multicast or address.is_unspecified:
                raise ValueError("Probe DNS configuration is invalid")
        self.dns_servers = dns_servers
        if mode == "live_protocol" and not real_provider_command:
            raise ValueError("Live protocol mode requires an approved credential source")
        self.source_config = _RELEASE["platform_configs"][f"linux/{architecture}"].removeprefix(
            "sha256:"
        )
        self.run_id = "omnigent-litellm-p0-" + uuid4().hex[:10]
        self.names: list[str] = []
        self.attestor: LiteLLMConfigurationAttestor | None = None
        self.attestation_database: str | None = None
        self.attested_bindings: list[tuple[CompiledModelDeploymentDraft, str, str, str]] = []
        self.environment = {
            **os.environ,
            "POSTGRES_PASSWORD": secrets.token_hex(24),
            "PROBE_DATABASE_PASSWORD": secrets.token_hex(24),
            "LITELLM_MASTER_KEY": "sk-" + secrets.token_hex(32),
            "LITELLM_SALT_KEY": secrets.token_hex(32),
            "PROBE_PROVIDER_KEY": "sk-" + secrets.token_hex(32),
        }
        self.report: dict[str, object] = {
            "schema_version": 1,
            "scope": "disposable_" + mode + "_not_production_acceptance",
            "run_id": self.run_id,
            "image_id": image,
            "architecture": architecture,
            "upstream_release": _RELEASE["release"],
            "upstream_image": _RELEASE["image"],
            "checks": {},
            "production_traffic_changed": False,
            "real_provider_tested": False,
            "agent_runtime_tested": False,
            "network_scope": "dedicated_bridge_loopback_ports",
            "explicit_dns_resolver_count": len(dns_servers),
            "provider_credential_source": "operator_command"
            if real_provider_command
            else "synthetic_fixture",
        }

    def docker(self, *args: str, input_bytes: bytes | None = None, timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                ["docker", "--context", self.context, *args],
                input=input_bytes,
                capture_output=True,
                env=self.environment,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise ProbeFailure("docker_operation_timed_out") from None
        if result.returncode:
            raise ProbeFailure("docker_operation_failed")
        output = result.stdout + result.stderr if args[0] == "logs" else result.stdout
        return output.decode("utf-8", errors="replace").strip()

    def check(self, name: str, passed: bool) -> None:
        checks = self.report["checks"]
        assert isinstance(checks, dict)
        checks[name] = passed
        print(json.dumps({"phase": name, "passed": passed}), flush=True)
        if not passed:
            raise ProbeFailure(name)

    def start(
        self,
        suffix: str,
        image: str,
        *args: str,
        extra_env: tuple[str, ...] = (),
        command: tuple[str, ...] = (),
    ) -> str:
        name = self.run_id + "-" + suffix
        self.names.append(name)
        env_args = [value for key in extra_env for value in ("-e", key)]
        dns_args = [value for server in self.dns_servers for value in ("--dns", server)]
        self.docker(
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"omnigent.litellm.probe={self.run_id}",
            "--network",
            self.run_id,
            *dns_args,
            *env_args,
            *args,
            image,
            *command,
        )
        return name

    def port(self, name: str, port: int) -> str:
        value = json.loads(self.docker("inspect", name))
        bindings = value[0]["NetworkSettings"]["Ports"].get(f"{port}/tcp")
        if not bindings:
            raise ProbeFailure("published_port_unavailable")
        host_port = bindings[0]["HostPort"]
        return f"http://127.0.0.1:{host_port}"

    def diagnostics(self) -> None:
        results = []
        for name in self.names:
            with contextlib.suppress(ProbeFailure):
                inspected = json.loads(self.docker("inspect", name))[0]
                if (
                    inspected["Config"].get("Labels", {}).get("omnigent.litellm.probe")
                    != self.run_id
                ):
                    continue
                logs = self.docker("logs", "--tail=30", name)
                for key in (
                    "DATABASE_URL",
                    "POSTGRES_PASSWORD",
                    "PROBE_DATABASE_PASSWORD",
                    "PGPASSWORD",
                    "LITELLM_MASTER_KEY",
                    "LITELLM_SALT_KEY",
                    "PROBE_PROVIDER_KEY",
                    "PROBE_INFERENCE_KEY",
                    "PROBE_LIVE_PROVIDER_KEY",
                    "PROBE_LIVE_INFERENCE_KEY",
                    "PROBE_BOUNDED_INFERENCE_KEY",
                    "PROBE_ATTESTOR_PASSWORD",
                ):
                    value = self.environment.get(key)
                    if value:
                        logs = logs.replace(value, "[REDACTED]")
                results.append(
                    {
                        "container": name,
                        "status": inspected["State"]["Status"],
                        "exit_code": inspected["State"]["ExitCode"],
                        "logs": logs[-3000:],
                    }
                )
        self.report["diagnostics"] = results

    def wait_http(self, url: str, headers: dict[str, str] | None = None) -> None:
        deadline = time.monotonic() + (600 if self.architecture == "arm64" else 180)
        with httpx.Client(timeout=3, trust_env=False) as client:
            while time.monotonic() < deadline:
                try:
                    if client.get(url, headers=headers).status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(1)
        raise ProbeFailure("http_readiness_timeout")

    def cleanup(self) -> None:
        if self.attestor is not None:
            self.attestor.engine.dispose()
        remaining = []
        for name in reversed(self.names):
            try:
                present = self.docker(
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"name=^/{name}$",
                    "--format",
                    "{{.ID}}",
                )
                if not present:
                    continue
                inspected = json.loads(self.docker("inspect", name))[0]
                if (
                    inspected["Config"].get("Labels", {}).get("omnigent.litellm.probe")
                    != self.run_id
                ):
                    raise ProbeFailure("cleanup_ownership_mismatch")
                self.docker("rm", "--force", name)
            except (ProbeFailure, ValueError, LookupError):
                remaining.append(name)
        try:
            networks = self.docker(
                "network", "ls", "--filter", "name=^" + self.run_id + "$", "--format", "{{.ID}}"
            )
            if networks:
                network = json.loads(self.docker("network", "inspect", self.run_id))[0]
                if network.get("Labels", {}).get("omnigent.litellm.probe") != self.run_id:
                    raise ProbeFailure("cleanup_ownership_mismatch")
                self.docker("network", "rm", self.run_id)
        except (ProbeFailure, ValueError, LookupError):
            remaining.append(self.run_id)
        self.report["cleanup_completed"] = not remaining
        if remaining:
            self.report["resources_remaining"] = remaining
            self.report["passed"] = False
            self.report.setdefault("error_code", "cleanup_incomplete")

    def verify_image_content(self) -> None:
        host_architecture = self.docker("info", "--format", "{{.Architecture}}")
        native_names = {"amd64": {"amd64", "x86_64"}, "arm64": {"arm64", "aarch64"}}
        self.report["execution_mode"] = (
            "native" if host_architecture in native_names[self.architecture] else "emulated"
        )
        with tarfile.open(self.source_archive) as archive:
            config = archive.extractfile(self.source_config + ".json")
            if config is None:
                raise ProbeFailure("source_config_missing")
            raw = config.read()
        self.check("source_config_digest", hashlib.sha256(raw).hexdigest() == self.source_config)
        source = json.loads(raw)
        image = json.loads(self.docker("image", "inspect", self.upstream_image))[0]
        self.check(
            "image_architecture",
            source["architecture"] == image["Architecture"] == self.architecture,
        )
        self.check("image_rootfs", source["rootfs"]["diff_ids"] == image["RootFS"]["Layers"])
        keys = (
            "Env",
            "Entrypoint",
            "Cmd",
            "WorkingDir",
            "User",
            "Labels",
            "ExposedPorts",
            "Volumes",
            "StopSignal",
        )
        self.check(
            "image_runtime_configuration",
            all(source["config"].get(key) == image["Config"].get(key) for key in keys),
        )
        self.report["source_config_sha256"] = self.source_config
        candidate = json.loads(self.docker("image", "inspect", self.image))[0]
        self.check(
            "oss_runtime_flattened",
            candidate["Architecture"] == self.architecture
            and len(candidate["RootFS"]["Layers"]) == 3,
        )
        self.check(
            "patched_image_preserves_runtime_configuration",
            all(
                source["config"].get(key) == candidate["Config"].get(key)
                for key in keys
                if key != "Labels"
            ),
        )
        labels = candidate["Config"].get("Labels", {})
        self.check(
            "patched_image_material_labels",
            labels.get("io.omnigent.litellm.upstream.digest") == _RELEASE["image"].split("@", 1)[1]
            and labels.get("io.omnigent.litellm.openssl.version")
            == _RELEASE["runtime_patch"]["openssl_version"]
            and labels.get("io.omnigent.litellm.profile")
            == _RELEASE["license"]["runtime_profile"],
        )
        evidence = json.loads(
            self.docker(
                "run",
                "--rm",
                "--network=none",
                "--platform=linux/" + self.architecture,
                "--entrypoint=python",
                self.image,
                "-B",
                "-I",
                "-c",
                "import ctypes,importlib.util,json; from pathlib import Path; "
                "library=ctypes.CDLL('/usr/lib/libcrypto.so.3'); "
                "library.OpenSSL_version.restype=ctypes.c_char_p; "
                "print(json.dumps({'openssl':library.OpenSSL_version(0).decode(), "
                "'enterprise_module_absent':"
                "importlib.util.find_spec('litellm_enterprise') is None, "
                "'enterprise_source_absent':not Path('/app/enterprise').exists()}))",
            )
        )
        self.check("patched_openssl_version", evidence["openssl"].startswith("OpenSSL 3.6.5 "))
        self.check(
            "enterprise_components_absent",
            evidence["enterprise_module_absent"] is True
            and evidence["enterprise_source_absent"] is True,
        )
        self.report["runtime_profile"] = _RELEASE["license"]["runtime_profile"]
        self.report["runtime_patch_dockerfile_sha256"] = hashlib.sha256(
            (_REPO / "saas/deployment/litellm/Dockerfile").read_bytes()
        ).hexdigest()

    def run(self) -> None:
        self.verify_image_content()
        self.docker(
            "network", "create", "--label", f"omnigent.litellm.probe={self.run_id}", self.run_id
        )
        db = self.start(
            "postgres",
            _POSTGRES,
            "--memory=1536m",
            "--cpus=1",
            "--tmpfs",
            "/var/lib/postgresql:rw,size=1073741824",
            "--publish",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_USER=probe",
            "-e",
            "POSTGRES_DB=probe",
            extra_env=("POSTGRES_PASSWORD",),
        )
        self.environment["DATABASE_URL"] = (
            "postgresql://probe_litellm_owner:"
            f"{self.environment['PROBE_DATABASE_PASSWORD']}@{db}:5432/probe"
        )
        upstream = self.start(
            "upstream",
            _PYTHON,
            "--memory=128m",
            "--cpus=0.5",
            "--publish",
            "127.0.0.1::8080",
            "--mount",
            f"type=bind,source={_FIXTURES},target=/probe,readonly",
            "--entrypoint=python",
            extra_env=("PROBE_PROVIDER_KEY",),
            command=("/probe/upstream.py",),
        )
        provider_base = f"http://{upstream}:8080/v1"
        upstream_url = self.port(upstream, 8080)
        self.wait_http(upstream_url + "/health")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                version = self.docker(
                    "exec",
                    db,
                    "psql",
                    "-U",
                    "probe",
                    "-d",
                    "probe",
                    "-Atc",
                    "SHOW server_version",
                )
                break
            except ProbeFailure:
                time.sleep(1)
        else:
            raise ProbeFailure("postgres_readiness_timeout")
        self.report["postgres_version"] = version
        self.check("postgres_18_ready", version.startswith("18."))
        password = self.environment["PROBE_DATABASE_PASSWORD"]
        self.docker(
            "exec",
            "-i",
            db,
            "psql",
            "-U",
            "probe",
            "-d",
            "probe",
            "-v",
            "ON_ERROR_STOP=1",
            input_bytes=(
                "CREATE ROLE probe_litellm_owner LOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOBYPASSRLS "
                f"PASSWORD '{password}';\n"
                "ALTER DATABASE probe OWNER TO probe_litellm_owner;\n"
                "CREATE DATABASE probe_boundary OWNER probe;\n"
                "REVOKE CONNECT ON DATABASE probe_boundary FROM PUBLIC;\n"
            ).encode(),
        )
        self.environment["PGPASSWORD"] = password
        role = self.docker(
            "exec",
            "-e",
            "PGPASSWORD",
            db,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            "probe_litellm_owner",
            "-d",
            "probe",
            "-Atc",
            "SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls) "
            "FROM pg_roles WHERE rolname = current_user",
        )
        self.check("database_owner_is_not_cluster_administrator", role == "t")
        try:
            self.docker(
                "exec",
                "-e",
                "PGPASSWORD",
                db,
                "psql",
                "-h",
                "127.0.0.1",
                "-U",
                "probe_litellm_owner",
                "-d",
                "probe_boundary",
                "-Atc",
                "SELECT 1",
            )
        except ProbeFailure:
            self.check("separate_database_connection_denied", True)
        else:
            self.check("separate_database_connection_denied", False)
        self.environment.update(
            {
                "STORE_MODEL_IN_DB": "True",
                "DISABLE_ADMIN_UI": "True",
                "LITELLM_MODE": "PRODUCTION",
                "LITELLM_LOCAL_MODEL_COST_MAP": "True",
            }
        )
        proxy = self.start(
            "proxy",
            self.image,
            "--platform=linux/" + self.architecture,
            "--memory=4g",
            "--cpus=2",
            "--publish",
            "127.0.0.1::4000",
            "--mount",
            f"type=bind,source={_FIXTURES / 'proxy.yaml'},target=/probe.yaml,readonly",
            extra_env=(
                "DATABASE_URL",
                "LITELLM_MASTER_KEY",
                "LITELLM_SALT_KEY",
                "STORE_MODEL_IN_DB",
                "DISABLE_ADMIN_UI",
                "LITELLM_MODE",
                "LITELLM_LOCAL_MODEL_COST_MAP",
            ),
            command=("--config", "/probe.yaml", "--port", "4000"),
        )
        proxy_url = self.port(proxy, 4000)
        self.wait_http(proxy_url + "/health/readiness")
        self.check("litellm_database_ready", True)
        if self.mode == "live_protocol":
            asyncio.run(self.live_contract(proxy_url))
            self.report["passed"] = True
            return
        self.configure_storage_attestor(db, "probe")
        asyncio.run(self.contract(proxy_url, provider_base, upstream_url))
        asyncio.run(self.check_replica_readiness(proxy_url, upstream_url))
        if self.real_provider_command:
            asyncio.run(self.live_contract(proxy_url))
        stored = self.docker(
            "exec",
            db,
            "psql",
            "-U",
            "probe",
            "-d",
            "probe",
            "-Atc",
            'SELECT credential_values::text FROM "LiteLLM_CredentialsTable" '
            "ORDER BY credential_name",
        )
        self.check(
            "provider_credential_not_stored_plaintext",
            bool(stored)
            and all(
                secret not in stored
                for secret in (
                    self.environment["PROBE_PROVIDER_KEY"],
                    self.environment.get(
                        "PROBE_LIVE_PROVIDER_KEY", self.environment["PROBE_PROVIDER_KEY"]
                    ),
                )
            ),
        )
        self.docker(
            "exec", db, "createdb", "-U", "probe", "-O", "probe_litellm_owner", "probe_restored"
        )
        dump = subprocess.run(
            [
                "docker",
                "--context",
                self.context,
                "exec",
                db,
                "pg_dump",
                "-U",
                "probe",
                "-d",
                "probe",
                "--format=custom",
            ],
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
        subprocess.run(
            [
                "docker",
                "--context",
                self.context,
                "exec",
                "-i",
                db,
                "pg_restore",
                "-U",
                "probe",
                "-d",
                "probe_restored",
                "--exit-on-error",
            ],
            input=dump,
            capture_output=True,
            check=True,
            timeout=60,
        )
        restored = self.docker(
            "exec",
            db,
            "psql",
            "-U",
            "probe",
            "-d",
            "probe_restored",
            "-Atc",
            'SELECT credential_values::text FROM "LiteLLM_CredentialsTable" '
            "ORDER BY credential_name",
        )
        self.check("database_logical_restore_credential_matches", stored == restored)
        self.docker("restart", proxy, timeout=60)
        proxy_url = self.port(proxy, 4000)
        self.wait_http(proxy_url + "/health/readiness")
        asyncio.run(self.check_model_persistence(proxy_url))
        self.docker("stop", "--time=30", proxy)
        self.environment["DATABASE_URL"] = (
            self.environment["DATABASE_URL"].rsplit("/", 1)[0] + "/probe_restored"
        )
        recovered = self.start(
            "restored",
            self.image,
            "--platform=linux/" + self.architecture,
            "--memory=4g",
            "--cpus=2",
            "--publish",
            "127.0.0.1::4000",
            "--mount",
            f"type=bind,source={_FIXTURES / 'proxy.yaml'},target=/probe.yaml,readonly",
            extra_env=(
                "DATABASE_URL",
                "LITELLM_MASTER_KEY",
                "LITELLM_SALT_KEY",
                "STORE_MODEL_IN_DB",
                "DISABLE_ADMIN_UI",
                "LITELLM_MODE",
                "LITELLM_LOCAL_MODEL_COST_MAP",
            ),
            command=("--config", "/probe.yaml", "--port", "4000"),
        )
        recovered_url = self.port(recovered, 4000)
        self.wait_http(recovered_url + "/health/readiness")
        asyncio.run(self.check_model_persistence(recovered_url, restored=True))
        self.configure_storage_attestor(db, "probe_restored")
        assert self.attestor is not None
        self.check(
            "stored_configuration_attestation_survives_restore",
            all(
                self.attestor.attest(
                    draft=draft,
                    credential_name=credential,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=base,
                ).stored_state_sha256
                == expected
                for draft, credential, base, expected in self.attested_bindings
            )
            and bool(self.attested_bindings),
        )
        self.report["passed"] = True

    async def check_replica_readiness(self, primary_url: str, upstream_url: str) -> None:
        assert self.attestor is not None and len(self.attested_bindings) == 2
        # The fixture deliberately freezes periodic reload so the stale-route negative is stable.
        replica = self.start(
            "second-replica",
            self.image,
            "--platform=linux/" + self.architecture,
            "--memory=4g",
            "--cpus=2",
            "--publish",
            "127.0.0.1::4000",
            "--mount",
            f"type=bind,source={_FIXTURES / 'proxy.yaml'},target=/probe.yaml,readonly",
            extra_env=(
                "DATABASE_URL",
                "LITELLM_MASTER_KEY",
                "LITELLM_SALT_KEY",
                "STORE_MODEL_IN_DB",
                "DISABLE_ADMIN_UI",
                "LITELLM_MODE",
                "LITELLM_LOCAL_MODEL_COST_MAP",
            ),
            command=("--config", "/probe.yaml", "--port", "4000"),
        )
        replica_url = self.port(replica, 4000)
        self.wait_http(replica_url + "/health/readiness")
        storage = self.attestor
        source, credential, provider_base, _ = self.attested_bindings[0]

        def endpoint(identifier: str, url: str) -> LiteLLMReplicaEndpoint:
            return LiteLLMReplicaEndpoint(
                identifier,
                LiteLLMManagementConfiguration(
                    base_url=url,
                    management_key=self.environment["LITELLM_MASTER_KEY"],
                    allowed_http_hosts=("127.0.0.1",),
                    allowed_provider_base_urls=(provider_base,),
                    timeout_seconds=10,
                ),
            )

        def authority(url: str) -> LiteLLMReplicaReadinessAuthority:
            return LiteLLMReplicaReadinessAuthority(
                (endpoint("primary", primary_url), endpoint("second", url)), storage=storage
            )

        known_replicas = authority(replica_url)
        evidence = []
        async with httpx.AsyncClient(timeout=10, trust_env=False) as observer:
            before = (await observer.get(upstream_url + "/evidence")).json()["requests"]
            for draft, name, base, _ in self.attested_bindings:
                proof = await known_replicas.attest(
                    draft=draft,
                    credential_name=name,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=base,
                )
                evidence.append(proof.evidence())
                self.check("replica_routes_and_storage_agree_" + draft.wire_api, True)
            late = compile_model_deployment_draft(
                CreateModelDeploymentDraft(
                    source.public_model_id,
                    "isolated not-yet-loaded replica route",
                    source.connection_id,
                    source.credential_version_id,
                    0,
                    source.wire_api,
                    32,
                ),
                deployment_id=uuid4(),
            )
            management = LiteLLMManagementClient(endpoint("primary", primary_url).management)
            await management.create_deepseek_deployment(
                deployment_id=late.deployment_id,
                alias=late.alias,
                model=late.public_model_id,
                credential_name=credential,
                provider_base_url=provider_base,
            )
            try:
                await known_replicas.attest(
                    draft=late,
                    credential_name=credential,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=provider_base,
                )
            except LiteLLMReplicaReadinessError:
                self.check("missing_replica_route_rejects_release_readiness", True)
            else:
                self.check("missing_replica_route_rejects_release_readiness", False)
            self.docker("restart", replica, timeout=60)
            replica_url = self.port(replica, 4000)
            self.wait_http(replica_url + "/health/readiness")
            proof = await authority(replica_url).attest(
                draft=late,
                credential_name=credential,
                expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                provider_base_url=provider_base,
            )
            evidence.append(proof.evidence())
            self.check("reloaded_replica_route_ready", True)
            after = (await observer.get(upstream_url + "/evidence")).json()["requests"]
            self.check("replica_readiness_never_calls_provider", before == after)
        self.docker("stop", "--time=30", replica)
        self.report["replica_route_readiness_checked"] = True
        self.report["replica_route_readiness_scope"] = READINESS_SCOPE
        self.report["replica_route_readiness"] = evidence

    def configure_storage_attestor(self, db: str, database: str) -> None:
        if self.attestor is not None:
            self.attestor.engine.dispose()
        self.attestation_database = db
        self.environment.setdefault("PROBE_ATTESTOR_PASSWORD", secrets.token_hex(24))
        self.docker(
            "exec",
            "-i",
            db,
            "psql",
            "-U",
            "probe",
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "--single-transaction",
            input_bytes=(
                _REPO / "saas/deployment/litellm/postgresql_attestation_principals.sql"
            ).read_bytes()
            + (
                "\nALTER ROLE omnigent_litellm_attestor PASSWORD '"
                + self.environment["PROBE_ATTESTOR_PASSWORD"]
                + "';\n"
            ).encode(),
        )
        self.docker(
            "exec",
            "-i",
            "-e",
            "PGPASSWORD",
            db,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            "probe_litellm_owner",
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            "litellm_database=" + database,
            "--single-transaction",
            input_bytes=(
                _REPO / "saas/deployment/litellm/postgresql_attestation_grants.sql"
            ).read_bytes(),
        )
        address = httpx.URL(self.port(db, 5432))
        url = sa.URL.create(
            "postgresql+psycopg",
            username="omnigent_litellm_attestor",
            password=self.environment["PROBE_ATTESTOR_PASSWORD"],
            host=address.host,
            port=address.port,
            database=database,
        )
        self.attestor = LiteLLMConfigurationAttestor(
            sa.create_engine(url, hide_parameters=True, poolclass=sa.pool.NullPool),
            salt_key=self.environment["LITELLM_SALT_KEY"],
            expected_database=database,
        )
        self.attestor.validate_authority()
        self.check("configuration_attestor_exact_read_only_identity", True)
        for label, statement in (
            ("ungranted_columns", 'SELECT * FROM public."LiteLLM_CredentialsTable"'),
            ("inference_keys", 'SELECT token FROM public."LiteLLM_VerificationToken"'),
            ("writes", 'UPDATE public."LiteLLM_CredentialsTable" SET credential_values = NULL'),
            ("set_role", "SET ROLE omnigent_litellm_attestation_read"),
        ):
            try:
                with self.attestor.engine.begin() as connection:
                    connection.exec_driver_sql(statement)
            except sa.exc.DBAPIError as error:
                self.check(
                    "configuration_attestor_denies_" + label,
                    getattr(error.orig, "sqlstate", None) in {"42501", "25006"},
                )
            else:
                self.check("configuration_attestor_denies_" + label, False)

    async def check_model_persistence(self, proxy_url: str, *, restored: bool = False) -> None:
        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url=proxy_url,
                management_key=self.environment["LITELLM_MASTER_KEY"],
                allowed_http_hosts=("127.0.0.1",),
                timeout_seconds=60,
            )
        )
        rows = await management.list_deployments()
        self.check(
            "restored_database_model_available" if restored else "model_persists_after_restart",
            any(row.id == self.report["model_id"] for row in rows),
        )
        async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
            response = await client.post(
                proxy_url + "/v1/chat/completions",
                headers={"Authorization": "Bearer " + self.environment["PROBE_INFERENCE_KEY"]},
                json={
                    "model": self.alias,
                    "stream": True,
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "P0_TEXT"}],
                },
            )
            self.check(
                "restored_database_credential_usable"
                if restored
                else "restarted_credential_usable",
                response.status_code == 200 and "OK" in response.text,
            )

    async def live_contract(self, proxy_url: str) -> None:
        # This is an operator-only local harness. A trusted command returns the
        # approved credential in memory; it is never written to the report.
        source = subprocess.run(
            self.real_provider_command, capture_output=True, check=True, timeout=30
        ).stdout
        if len(source) > 8192:
            raise ProbeFailure("provider_credential_source_invalid")
        credential = json.loads(source)
        if not isinstance(credential, dict):
            raise ProbeFailure("provider_credential_source_invalid")
        api_key = credential.get("api_key")
        model = credential.get("model")
        if (
            credential.get("provider_id") != "deepseek"
            or not isinstance(api_key, str)
            or not 16 <= len(api_key) <= 4096
            or not isinstance(model, str)
            or not model.startswith("deepseek-")
        ):
            raise ProbeFailure("provider_credential_source_invalid")
        self.environment["PROBE_LIVE_PROVIDER_KEY"] = api_key
        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url=proxy_url,
                management_key=self.environment["LITELLM_MASTER_KEY"],
                allowed_http_hosts=("127.0.0.1",),
                timeout_seconds=60,
            )
        )
        name = self.run_id + "-live-credential"
        alias = "deepseek-p0-live-" + uuid4().hex[:12]
        await management.create_deepseek_credential(name=name, api_key=api_key)
        await management.create_deepseek_deployment(
            deployment_id=uuid4(),
            alias=alias,
            model=model,
            credential_name=name,
        )
        key = await management.create_inference_key(
            aliases=(alias,),
            key_alias=self.run_id + "-live",
            duration_seconds=300,
        )
        self.environment["PROBE_LIVE_INFERENCE_KEY"] = key.value
        from saas.scripts.litellm_agent_probe import probe_agent

        results = await probe_agent(base_url=proxy_url + "/v1", api_key=key.value, model=alias)
        self.report["real_provider_agent_probe"] = results
        self.report["real_provider_model"] = model
        self.report["real_provider_configuration_version"] = credential.get(
            "configuration_version"
        )
        self.report["live_probe_request_scope"] = (
            "two_protocols_one_agent_turn_each_max_output_32_no_tools"
        )
        self.check("real_provider_agent_protocols", all(row["passed"] for row in results.values()))
        self.report["real_provider_tested"] = True

    async def bounded_protocol_contract(
        self,
        management: LiteLLMManagementClient,
        *,
        proxy_url: str,
        provider_base: str,
        upstream_url: str,
        credential_name: str,
    ) -> None:
        # The synthetic provider exercises transport, not Staff or money admission.
        results = []
        async with httpx.AsyncClient(timeout=30, trust_env=False) as observer:
            before = (await observer.get(upstream_url + "/evidence")).json()["requests"]
            for responses in (False, True):
                draft = compile_model_deployment_draft(
                    CreateModelDeploymentDraft(
                        _PROBE_MODEL,
                        "isolated bounded protocol",
                        uuid4(),
                        uuid4(),
                        0,
                        "openai_responses" if responses else "openai_chat_completions",
                        32,
                    ),
                    deployment_id=uuid4(),
                )
                await management.create_deepseek_deployment(
                    deployment_id=draft.deployment_id,
                    alias=draft.alias,
                    model=draft.public_model_id,
                    credential_name=credential_name,
                    provider_base_url=provider_base,
                )
                await management.reconcile_deepseek_deployment(
                    deployment_id=draft.deployment_id,
                    alias=draft.alias,
                    model=draft.public_model_id,
                    credential_name=credential_name,
                    provider_base_url=provider_base,
                )
                suffix = "responses" if responses else "chat"
                self.check("bounded_model_readback_" + suffix, True)
                assert self.attestor is not None
                witness = self.attestor.attest(
                    draft=draft,
                    credential_name=credential_name,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=provider_base,
                )
                self.check(
                    "stored_model_and_credential_attested_" + suffix,
                    witness.configuration_sha256 == draft.configuration_sha256,
                )
                self.attested_bindings.append(
                    (draft, credential_name, provider_base, witness.stored_state_sha256)
                )
                try:
                    self.attestor.attest(
                        draft=draft,
                        credential_name=credential_name,
                        expected_api_key="not-the-approved-private-provider-key",
                        provider_base_url=provider_base,
                    )
                except LiteLLMAttestationError as rejected:
                    self.check(
                        "stored_credential_mismatch_denied_" + suffix,
                        rejected.code == "litellm_configuration_drift",
                    )
                else:
                    self.check("stored_credential_mismatch_denied_" + suffix, False)
                try:
                    await management.reconcile_deepseek_deployment(
                        deployment_id=draft.deployment_id,
                        alias=draft.alias,
                        model=draft.public_model_id,
                        credential_name="not-the-approved-credential",
                        provider_base_url=provider_base,
                    )
                except LiteLLMManagementError as rejected:
                    self.check(
                        "bounded_model_readback_drift_rejected_" + suffix,
                        rejected.code == "litellm_deployment_drift",
                    )
                else:
                    self.check("bounded_model_readback_drift_rejected_" + suffix, False)
                key = await management.create_inference_key(
                    aliases=(draft.alias,),
                    key_alias=self.run_id
                    + ("-bounded-responses" if responses else "-bounded-chat"),
                    duration_seconds=300,
                )
                self.environment["PROBE_BOUNDED_INFERENCE_KEY"] = key.value
                result = await ModelProtocolProbe(
                    ModelProtocolProbeConfiguration(
                        base_url=proxy_url,
                        allowed_http_hosts=("127.0.0.1",),
                    )
                ).run_admitted_probe(
                    admission=ModelProbeAdmission(
                        uuid4(),
                        uuid4(),
                        draft.deployment_id,
                        draft.configuration_sha256,
                        datetime.now(timezone.utc) + timedelta(minutes=4),
                    ),
                    draft=draft,
                    inference_key=key,
                )
                results.append(
                    {
                        "wire_api": result.wire_api,
                        "configuration_sha256": result.configuration_sha256,
                        "request_attempts": result.request_attempts,
                        "output_token_limit": result.output_token_limit,
                        "input_tokens": result.usage.input_tokens,
                        "output_tokens": result.usage.output_tokens,
                        "total_tokens": result.usage.total_tokens,
                        "response_id_length": result.response_id_length,
                    }
                )
                self.check(
                    "bounded_model_probe_responses" if responses else "bounded_model_probe_chat",
                    result.request_attempts == 1 and result.usage.total_tokens == 22,
                )
            after = (await observer.get(upstream_url + "/evidence")).json()["requests"]
            self.check("bounded_model_probe_attempts_observed", len(after) - len(before) == 2)
            await self.storage_drift_contract(management, draft, credential_name, provider_base)
            self.report["masked_credentials_attested"] = True
            self.report["configuration_attestation_scope"] = (
                "stored_model_credential_and_database_overlays_not_replica_memory"
            )
        self.report["bounded_model_protocol_probe"] = {
            "scope": "synthetic_provider_transport_not_staff_or_budget_acceptance",
            "results": results,
        }

    def mutate_fixture_configuration(self, statement: str) -> None:
        assert self.attestation_database is not None
        self.docker(
            "exec",
            "-i",
            self.attestation_database,
            "psql",
            "-U",
            "probe",
            "-d",
            "probe",
            "-v",
            "ON_ERROR_STOP=1",
            "--single-transaction",
            input_bytes=statement.encode(),
        )

    async def storage_drift_contract(
        self,
        management: LiteLLMManagementClient,
        source: CompiledModelDeploymentDraft,
        credential_name: str,
        provider_base: str,
    ) -> None:
        assert self.attestor is not None
        draft = compile_model_deployment_draft(
            CreateModelDeploymentDraft(
                source.public_model_id,
                "isolated hidden override",
                source.connection_id,
                source.credential_version_id,
                0,
                source.wire_api,
                32,
            ),
            deployment_id=uuid4(),
        )
        await management.create_deepseek_deployment(
            deployment_id=draft.deployment_id,
            alias=draft.alias,
            model=draft.public_model_id,
            credential_name=credential_name,
            provider_base_url=provider_base,
        )
        try:
            self.mutate_fixture_configuration(
                'UPDATE "LiteLLM_ProxyModelTable" SET litellm_params = '
                "jsonb_set(litellm_params::jsonb, '{api_key}', "
                "to_jsonb('isolated-unapproved-override'::text)) "
                "WHERE model_id='" + str(draft.deployment_id) + "';"
            )
            await management.reconcile_deepseek_deployment(
                deployment_id=draft.deployment_id,
                alias=draft.alias,
                model=draft.public_model_id,
                credential_name=credential_name,
                provider_base_url=provider_base,
            )
            self.check("hidden_override_remains_hidden_from_management_readback", True)
            try:
                self.attestor.attest(
                    draft=draft,
                    credential_name=credential_name,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=provider_base,
                )
            except LiteLLMAttestationError as error:
                self.check(
                    "hidden_override_storage_attestation_denied",
                    error.code == "litellm_attestation_model_override",
                )
            else:
                self.check("hidden_override_storage_attestation_denied", False)
        finally:
            await management.delete_deployment(deployment_id=draft.deployment_id)
        self.mutate_fixture_configuration(
            'INSERT INTO "LiteLLM_Config" (param_name, param_value) '
            "VALUES ('router_settings', '{\"num_retries\":1}');"
        )
        try:
            try:
                self.attestor.attest(
                    draft=source,
                    credential_name=credential_name,
                    expected_api_key=self.environment["PROBE_PROVIDER_KEY"],
                    provider_base_url=provider_base,
                )
            except LiteLLMAttestationError as error:
                self.check(
                    "unapproved_database_router_overlay_denied",
                    error.code == "litellm_attestation_overlay_drift",
                )
            else:
                self.check("unapproved_database_router_overlay_denied", False)
        finally:
            self.mutate_fixture_configuration(
                "DELETE FROM \"LiteLLM_Config\" WHERE param_name='router_settings';"
            )

    async def contract(self, proxy_url: str, provider_base: str, upstream_url: str) -> None:
        management = LiteLLMManagementClient(
            LiteLLMManagementConfiguration(
                base_url=proxy_url,
                management_key=self.environment["LITELLM_MASTER_KEY"],
                allowed_http_hosts=("127.0.0.1",),
                allowed_provider_base_urls=(provider_base,),
                timeout_seconds=60,
            )
        )
        credential, alias = self.run_id + "-credential", "deepseek-p0-" + uuid4().hex[:12]
        self.alias = alias
        deployment_id = uuid4()
        await management.create_deepseek_credential(
            name=credential, api_key=self.environment["PROBE_PROVIDER_KEY"]
        )
        self.check("credential_projection", True)
        try:
            await management.create_deepseek_credential(
                name=credential, api_key=self.environment["PROBE_PROVIDER_KEY"]
            )
        except LiteLLMManagementError as error:
            self.check("duplicate_credential_conflict", error.status_code == 409)
        else:
            self.check("duplicate_credential_conflict", False)
        await management.create_deepseek_deployment(
            deployment_id=deployment_id,
            alias=alias,
            model=_PROBE_MODEL,
            credential_name=credential,
            provider_base_url=provider_base,
        )
        rows = await management.list_deployments()
        self.check(
            "model_management_round_trip", any(row.id == str(deployment_id) for row in rows)
        )
        disposable_id = uuid4()
        await management.create_deepseek_deployment(
            deployment_id=disposable_id,
            alias="deepseek-p0-delete-" + uuid4().hex[:12],
            model=_PROBE_MODEL,
            credential_name=credential,
            provider_base_url=provider_base,
        )
        await management.delete_deployment(deployment_id=disposable_id)
        self.check(
            "model_delete_round_trip",
            not any(row.id == str(disposable_id) for row in await management.list_deployments()),
        )
        self.report["model_id"] = str(deployment_id)
        key = await management.create_inference_key(
            aliases=(alias,), key_alias=self.run_id, duration_seconds=3600
        )
        self.environment["PROBE_INFERENCE_KEY"] = key.value
        headers = {"Authorization": f"Bearer {key.value}", "x-litellm-num-retries": "0"}
        async with httpx.AsyncClient(timeout=90, trust_env=False) as client:
            denied = await client.get(proxy_url + "/model/info")
            self.check("anonymous_management_denied", denied.status_code in {401, 403})
            denied = await client.post(proxy_url + "/credentials", headers=headers, json={})
            self.check("inference_key_management_denied", denied.status_code in {401, 403})
            for name, (method, path) in _RELEASE["management_contract"].items():
                denied = await client.request(
                    method,
                    proxy_url + path,
                    headers=headers,
                    json={} if method == "POST" else None,
                )
                self.check("inference_key_denied_" + name, denied.status_code in {401, 403})
            for wire in ("chat/completions", "responses"):
                document: dict[str, object] = {"model": alias, "stream": True}
                if wire == "responses":
                    document.update(input="P0_TEXT", max_output_tokens=32)
                else:
                    document.update(
                        messages=[{"role": "user", "content": "P0_TEXT"}],
                        max_tokens=32,
                        stream_options={"include_usage": True},
                    )
                response = await client.post(
                    proxy_url + "/v1/" + wire, headers=headers, json=document
                )
                self.check(
                    wire.replace("/", "_") + "_stream",
                    response.status_code == 200 and "OK" in response.text,
                )
                usage_found = False
                for line in response.text.splitlines():
                    if line.startswith("data:") and line[5:].strip() != "[DONE]":
                        event = json.loads(line[5:])
                        usage = event.get("usage") or event.get("response", {}).get("usage")
                        if usage and (usage.get("total_tokens") == 22):
                            usage_found = True
                self.check(wire.replace("/", "_") + "_usage", usage_found)
                observed = _platform_usage(response.content, responses=wire == "responses")
                self.report[wire.replace("/", "_") + "_platform_usage"] = observed
                self.check(
                    wire.replace("/", "_") + "_platform_usage_compatible",
                    observed
                    == {
                        "total_tokens": 22,
                        "cache_hit_tokens": 9,
                        "cache_miss_tokens": 8,
                        "completion_tokens": 5,
                    },
                )
            response = await client.post(
                proxy_url + "/v1/chat/completions",
                headers=headers,
                json={
                    "model": alias,
                    "stream": True,
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "P0_TOOL"}],
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": "p0_add",
                                "parameters": {
                                    "type": "object",
                                    "properties": {
                                        "a": {"type": "integer"},
                                        "b": {"type": "integer"},
                                    },
                                },
                            },
                        }
                    ],
                },
            )
            self.check(
                "chat_tool_stream", response.status_code == 200 and "call_p0_add" in response.text
            )
            before = (await client.get(upstream_url + "/evidence")).json()["requests"]
            response = await client.post(
                proxy_url + "/v1/chat/completions",
                headers=headers,
                json={
                    "model": alias,
                    "stream": True,
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "P0_RATE_LIMIT"}],
                },
            )
            after = (await client.get(upstream_url + "/evidence")).json()["requests"]
            failures = [row for row in after[len(before) :] if row["mode"] == "rate-limit"]
            self.check(
                "rate_limit_no_hidden_retry", response.status_code == 429 and len(failures) == 1
            )
            self.report["upstream_requests"] = after
            schema = await client.get(proxy_url + "/openapi.json")
            self.check("runtime_openapi_available", schema.status_code == 200)
            self.report["openapi_sha256"] = hashlib.sha256(schema.content).hexdigest()
            paths = schema.json()["paths"]
            self.check(
                "runtime_management_contract",
                all(
                    method.lower() in paths.get(path, {})
                    for method, path in _RELEASE["management_contract"].values()
                ),
            )
            from saas.scripts.litellm_agent_probe import probe_agent

            before_agent = (await client.get(upstream_url + "/evidence")).json()["requests"]
            agent_results = await probe_agent(
                base_url=proxy_url + "/v1", api_key=key.value, model=alias
            )
            self.report["mock_upstream_agent_probe"] = agent_results
            self.check(
                "omnigent_executor_mock_upstream",
                all(row["passed"] for row in agent_results.values()),
            )
            after_agent = (await client.get(upstream_url + "/evidence")).json()["requests"]
            self.check(
                "omnigent_executor_attempts_bounded", len(after_agent) - len(before_agent) == 2
            )
            self.report["agent_runtime_tested"] = True
            self.report["upstream_requests"] = after_agent
        await self.bounded_protocol_contract(
            management,
            proxy_url=proxy_url,
            provider_base=provider_base,
            upstream_url=upstream_url,
            credential_name=credential,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--upstream-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dns-server", action="append", default=[])
    parser.add_argument(
        "--mode", choices=("protocol_restore", "live_protocol"), default="protocol_restore"
    )
    parser.add_argument("--real-provider-command", nargs=argparse.REMAINDER, default=())
    args = parser.parse_args()
    probe = Probe(
        args.docker_context,
        args.image,
        args.source_archive,
        args.architecture,
        args.upstream_image,
        tuple(args.real_provider_command),
        args.mode,
        tuple(args.dns_server),
    )
    try:
        probe.run()
    except (
        ProbeFailure,
        LiteLLMManagementError,
        ModelProtocolProbeError,
        LiteLLMAttestationError,
        httpx.HTTPError,
        subprocess.SubprocessError,
        OSError,
        ValueError,
        TypeError,
        LookupError,
    ) as error:
        probe.report["passed"] = False
        probe.report["error_code"] = (
            error.code
            if isinstance(
                error, (LiteLLMManagementError, ModelProtocolProbeError, LiteLLMAttestationError)
            )
            else str(error)
            if isinstance(error, ProbeFailure)
            else type(error).__name__
        )
    finally:
        if not probe.report.get("passed"):
            probe.diagnostics()
        probe.cleanup()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(probe.report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": probe.report.get("passed", False), "report": str(args.output)}))
    return 0 if probe.report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
