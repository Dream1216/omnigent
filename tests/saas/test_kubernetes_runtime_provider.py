from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest

from saas.control_plane.runtime_provider import (
    RuntimeProviderCredential,
    RuntimeProviderError,
    RuntimeProviderFailureDisposition,
    RuntimeProviderOperation,
    RuntimeProviderOperationKind,
    RuntimeProviderOutcome,
    canonical_json,
    canonical_sha256,
)
from saas.production.kubernetes_runtime_provider import (
    KubernetesApiResponse,
    KubernetesRuntimeProviderClient,
    KubernetesRuntimeProviderConfig,
    KubernetesRuntimeProviderConfigError,
    OpenBaoTransitReceiptAuthority,
    ProjectedServiceAccountCredentialAuthority,
    _KubernetesCredentialMaterial,
    _verify_installed_lineage,
    load_kubernetes_runtime_provider_config,
)


def _document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "provider_type": "kubernetes",
        "placement_id": "a61eb576-2823-427f-ac49-96353ceeb39b",
        "binding_revision": "next-beta-20260906-v1",
        "endpoint": "https://kubernetes.default.svc",
        "endpoint_ref": "service://kubernetes.default.svc",
        "credential_ref": ("workload-identity://omnigent-next-beta/onboarding-runtime-provider"),
        "account_ref_hash": sha256(b"onboarding-runtime-provider").hexdigest(),
        "region": "cn-east-1",
        "runtime_namespace": "omnigent-next-runtime",
        "runtime_version": "0.13.0.dev0",
        "source_revision": "3" * 40,
        "adapter_contract_version": "0.2.0",
        "placement_generation": 1,
        "journal_login": "next_beta_runtime_provider_writer",
        "openbao_address": "https://openbao.omnigent-next-security.svc:8200",
        "transit_mount": "transit",
        "receipt_key_name": "omnigent-runtime-receipts",
        "receipt_key_version": 1,
        "request_timeout_seconds": 10,
    }


def _write(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o400)
    return path


def _config(tmp_path: Path) -> KubernetesRuntimeProviderConfig:
    document = _document()
    path = _write(
        tmp_path / "runtime-provider.json",
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
    )
    return load_kubernetes_runtime_provider_config(
        {"OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE": str(path)}
    )


def test_loads_exact_canonical_owner_only_binding(tmp_path: Path) -> None:
    config = _config(tmp_path)
    assert config.binding.provider_type == "kubernetes"
    assert config.binding.binding_revision == "next-beta-20260906-v1"
    assert config.runtime_namespace == "omnigent-next-runtime"
    assert config.journal_login == "next_beta_runtime_provider_writer"


def test_config_rejects_noncanonical_unsafe_and_direct_secrets(tmp_path: Path) -> None:
    path = _write(tmp_path / "runtime-provider.json", json.dumps(_document()) + "\n")
    with pytest.raises(KubernetesRuntimeProviderConfigError, match="canonical"):
        load_kubernetes_runtime_provider_config(
            {"OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE": str(path)}
        )

    path.chmod(0o600)
    path.write_text(
        json.dumps(_document(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(KubernetesRuntimeProviderConfigError, match="owner-only"):
        load_kubernetes_runtime_provider_config(
            {"OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE": str(path)}
        )

    path.chmod(0o400)
    with pytest.raises(KubernetesRuntimeProviderConfigError, match="direct secret"):
        load_kubernetes_runtime_provider_config(
            {
                "OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE": str(path),
                "OMNIGENT_SAAS_RUNTIME_PROVIDER_OPENBAO_TOKEN": "forbidden",
            }
        )


def test_config_rejects_mismatched_endpoint_reference(tmp_path: Path) -> None:
    document = _document()
    document["endpoint_ref"] = "service://another-control-plane.example"
    path = _write(
        tmp_path / "runtime-provider.json",
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
    )
    with pytest.raises(KubernetesRuntimeProviderConfigError, match="binding"):
        load_kubernetes_runtime_provider_config(
            {"OMNIGENT_SAAS_RUNTIME_PROVIDER_CONFIG_FILE": str(path)}
        )


def test_installed_build_lineage_must_match_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import omnigent

    config = _config(tmp_path)
    build_info = SimpleNamespace(COMMIT_SHA=config.source_revision)
    monkeypatch.setattr(omnigent, "_build_info", build_info, raising=False)
    _verify_installed_lineage(config)
    build_info.COMMIT_SHA = "f" * 40
    with pytest.raises(KubernetesRuntimeProviderConfigError, match="installed build"):
        _verify_installed_lineage(config)


@dataclass(slots=True)
class _Signer:
    production_capable: bool = True
    test_only: bool = False
    signature_key_id: str = "receipt-key-v1"

    def sign(self, payload: bytes) -> str:
        return sha256(b"signer" + payload).hexdigest()

    def verify_signature(self, payload: bytes, signature_hex: str) -> bool:
        return signature_hex == self.sign(payload)


@dataclass(slots=True)
class _Transport:
    resources: dict[str, dict[str, object]] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def request(
        self,
        *,
        method: str,
        path: str,
        bearer_token: str,
        body: Mapping[str, object] | None = None,
    ) -> KubernetesApiResponse:
        assert bearer_token == "projected-token"
        self.calls.append((method, path))
        if method == "GET":
            document = self.resources.get(path)
            return KubernetesApiResponse(
                status_code=404 if document is None else 200,
                document={} if document is None else document,
                request_id="audit-get",
            )
        if method == "POST":
            assert body is not None
            metadata = cast(Mapping[str, object], body["metadata"])
            name = str(metadata["name"])
            resource_path = f"{path}/{name}"
            if resource_path in self.resources:
                return KubernetesApiResponse(409, {}, "audit-conflict")
            stored = dict(body)
            self.resources[resource_path] = stored
            return KubernetesApiResponse(201, stored, "audit-create")
        if method == "DELETE":
            existed = self.resources.pop(path, None)
            return KubernetesApiResponse(
                status_code=404 if existed is None else 200,
                document={},
                request_id="audit-delete",
            )
        raise AssertionError(method)


def _operation(
    config: KubernetesRuntimeProviderConfig,
    kind: RuntimeProviderOperationKind,
) -> RuntimeProviderOperation:
    partition = {
        "schema_version": 1,
        "onboarding_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "space_id": str(uuid4()),
        "user_id": str(uuid4()),
        "runtime_partition_id": str(uuid4()),
        "placement_id": str(config.placement_id),
        "runtime_type": "shared",
        "data_region": "cn-east-1",
        "failure_domain": "beta-single-host",
        "official_schema_revision": "p0s000000012",
        "capacity_class": "trial",
        "provider_binding": {
            "provider_type": "kubernetes",
            "binding_revision": config.binding_revision,
            "binding_hash": config.binding.binding_hash,
        },
    }
    target: dict[str, object]
    if kind in {
        RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT,
        RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
    }:
        target = {
            "schema_version": 1,
            "partition": partition,
            "project_id": str(uuid4()),
            "project_name": "First project",
        }
    else:
        target = cast(dict[str, object], partition)
    target_json = canonical_json(target)
    return RuntimeProviderOperation(
        kind=kind,
        provider_type="kubernetes",
        placement_id=config.placement_id,
        binding_revision=config.binding_revision,
        binding_hash=config.binding.binding_hash,
        target_hash=canonical_sha256(target),
        idempotency_hash=sha256(b"idem").hexdigest(),
        request_hash=sha256(f"request:{kind.value}".encode()).hexdigest(),
        target_json=target_json,
        idempotency_key="onboarding-stage-1",
    )


def _credential(config: KubernetesRuntimeProviderConfig) -> RuntimeProviderCredential:
    return RuntimeProviderCredential(
        credential_ref_hash=config.binding.credential_ref_hash,
        version="projected-token-v1",
        material=_KubernetesCredentialMaterial("projected-token"),
    )


def test_partition_create_replay_and_conflict_are_deterministic(tmp_path: Path) -> None:
    config = _config(tmp_path)
    transport = _Transport()
    signer = _Signer()
    client = KubernetesRuntimeProviderClient(config=config, transport=transport, signer=signer)
    operation = _operation(config, RuntimeProviderOperationKind.ALLOCATE_PARTITION)
    credential = _credential(config)

    created = client.execute(operation, credential)
    assert created.receipt.outcome is RuntimeProviderOutcome.APPLIED
    assert created.attributes["source_revision"] == "3" * 40
    assert signer.verify_signature(
        created.receipt.unsigned_payload(), created.receipt.signature_hex
    )

    replayed = client.reconcile(operation, credential)
    assert replayed.receipt.outcome is RuntimeProviderOutcome.REPLAYED
    assert [method for method, _path in transport.calls] == ["GET", "POST", "GET"]

    document = next(iter(transport.resources.values()))
    metadata = dict(cast(Mapping[str, object], document["metadata"]))
    annotations = dict(cast(Mapping[str, object], metadata["annotations"]))
    annotations["ai.omnigent.runtime/request-hash"] = "f" * 64
    metadata["annotations"] = annotations
    document["metadata"] = metadata
    with pytest.raises(RuntimeProviderError) as error:
        client.reconcile(operation, credential)
    assert error.value.disposition is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT


def test_project_compensation_is_idempotent(tmp_path: Path) -> None:
    config = _config(tmp_path)
    transport = _Transport()
    client = KubernetesRuntimeProviderClient(config=config, transport=transport, signer=_Signer())
    provision = _operation(config, RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT)
    credential = _credential(config)
    created = client.execute(provision, credential)
    assert str(created.attributes["runtime_resource_id"]).startswith("k8s://")

    compensate = RuntimeProviderOperation(
        kind=RuntimeProviderOperationKind.COMPENSATE_DEFAULT_PROJECT,
        provider_type=provision.provider_type,
        placement_id=provision.placement_id,
        binding_revision=provision.binding_revision,
        binding_hash=provision.binding_hash,
        target_hash=provision.target_hash,
        idempotency_hash=sha256(b"compensate").hexdigest(),
        request_hash=sha256(b"compensate-request").hexdigest(),
        target_json=provision.target_json,
        idempotency_key="onboarding-compensate-project",
    )
    removed = client.execute(compensate, credential)
    absent = client.reconcile(compensate, credential)
    assert removed.receipt.outcome is RuntimeProviderOutcome.APPLIED
    assert absent.receipt.outcome is RuntimeProviderOutcome.ALREADY_ABSENT
    assert absent.receipt.provider_resource_id is None


def test_projected_token_is_reread_and_never_ambient(tmp_path: Path) -> None:
    config = _config(tmp_path)
    token = _write(tmp_path / "token", "projected-token\n")
    authority = ProjectedServiceAccountCredentialAuthority(token_file=token)
    with authority.acquire(
        binding=config.binding,
        operation=RuntimeProviderOperationKind.ALLOCATE_PARTITION,
    ) as credential:
        assert credential.credential_ref_hash == config.binding.credential_ref_hash
        assert credential.version == sha256(b"projected-token").hexdigest()
        assert "projected-token" not in repr(credential)
    assert authority.production_capable is True
    assert authority.uses_ambient_credentials is False


class _Transit:
    def __init__(self) -> None:
        self.last_signature = ""

    def sign_data(self, **kwargs: object) -> dict[str, object]:
        payload = str(kwargs["hash_input"]).encode()
        signature = base64.b64encode(sha256(payload).digest()).decode()
        self.last_signature = f"vault:v1:{signature}"
        return {"data": {"signature": self.last_signature}}

    def verify_signed_data(self, **kwargs: object) -> dict[str, object]:
        payload = str(kwargs["hash_input"]).encode()
        signature = base64.b64encode(sha256(payload).digest()).decode()
        return {
            "data": {
                "valid": kwargs["signature"] == f"vault:v1:{signature}",
            }
        }


class _Secrets:
    def __init__(self, transit: _Transit) -> None:
        self.transit = transit


class _OpenBaoClient:
    def __init__(self, transit: _Transit) -> None:
        self.secrets = _Secrets(transit)


def test_openbao_signature_roundtrip_is_hex_and_version_pinned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = _write(tmp_path / "openbao-token", "token\n")
    ca = _write(tmp_path / "openbao-ca", "test-ca")
    authority = OpenBaoTransitReceiptAuthority(
        address="https://openbao.example.test",
        ca_file=ca,
        token_file=token,
        mount_point="transit",
        key_name="omnigent-runtime-receipts",
        key_version=1,
    )
    transit = _Transit()
    monkeypatch.setattr(authority, "_client", lambda: _OpenBaoClient(transit))
    payload = b"canonical receipt"
    signature = authority.sign(payload)
    assert bytes.fromhex(signature)
    assert authority.verify_signature(payload, signature) is True
    assert authority.verify_signature(payload + b"!", signature) is False
