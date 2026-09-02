from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

import saas.scripts.render_kubernetes_release as release_renderer_module
from saas.production.service_bindings import EXPECTED_PRODUCTION_SERVICE_ROLES
from saas.scripts.render_kubernetes_namespace import MANIFEST_NAMES, TARGET_NAMESPACE
from saas.scripts.render_kubernetes_release import (
    EVIDENCE_FILE_NAME,
    ReleaseRenderError,
    load_public_release_spec,
    main,
    render_kubernetes_release,
)

_ROOT = Path(__file__).resolve().parents[2]
_DEPLOYMENT = _ROOT / "saas" / "deployment" / "server"
_ZERO_DIGEST = "sha256:" + ("0" * 64)
_RECEIPT_DIGEST = "sha256:" + ("7" * 64)
_FLEET_RECEIPT_DIGEST = "sha256:" + ("b" * 64)
_FLEET_RECEIPT_SIGNATURE_DIGEST = "sha256:" + ("c" * 64)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _copy_sources(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    for name in MANIFEST_NAMES:
        shutil.copy2(_DEPLOYMENT / name, source / name)
    return source


def _spec_document(*, mode: str = "stage") -> dict[str, Any]:
    store_uri = "s3://omnigent-release/runtime"
    runners = {
        "a": {
            "connection_generation": 1,
            "recovery_artifact_uri": (
                f"{store_uri}/runtime-recovery/runner/"
                "11111111-1111-4111-8111-111111111111/generation/1"
            ),
            "recovery_credential_revision": "sha256:" + ("8" * 64),
            "recovery_credential_secret_name": "omnigent-runner-a-recovery-g1-888888888888",
            "recovery_credentials_profile": ("runner-11111111-1111-4111-8111-111111111111-g1"),
            "repository_bindings_sha256": "sha256:" + ("a3" * 32),
            "repository_credential_revision": "sha256:" + ("a1" * 32),
            "repository_receipt_sha256": "sha256:" + ("a4" * 32),
            "repository_spec_sha256": "sha256:" + ("a2" * 32),
            "runner_id": "11111111-1111-4111-8111-111111111111",
        },
        "b": {
            "connection_generation": 2,
            "recovery_artifact_uri": (
                f"{store_uri}/runtime-recovery/runner/"
                "22222222-2222-4222-8222-222222222222/generation/2"
            ),
            "recovery_credential_revision": "sha256:" + ("9" * 64),
            "recovery_credential_secret_name": "omnigent-runner-b-recovery-g2-999999999999",
            "recovery_credentials_profile": ("runner-22222222-2222-4222-8222-222222222222-g2"),
            "repository_bindings_sha256": "sha256:" + ("b3" * 32),
            "repository_credential_revision": "sha256:" + ("b1" * 32),
            "repository_receipt_sha256": "sha256:" + ("b4" * 32),
            "repository_spec_sha256": "sha256:" + ("b2" * 32),
            "runner_id": "22222222-2222-4222-8222-222222222222",
        },
    }
    fleet_hash = "a" * 64
    context_hash = "d" * 64
    attestation_public_hash = "e" * 64
    attestation_hash = "f" * 64
    attestation_signature_hash = "4" * 64
    receipt_public_hash = "5" * 64
    pins_document = {
        "admission_epoch": 7,
        "attestation_issuer": "omnigent-owner-attestation",
        "attestation_key_id": "attestation-key-v1",
        "attestation_public_key_sha256": attestation_public_hash,
        "attestation_sha256": attestation_hash,
        "attestation_signature_sha256": attestation_signature_hash,
        "evidence_context_sha256": context_hash,
        "fleet_sha256": fleet_hash,
        "product_revision": "1" * 40,
        "receipt_issuer": "omnigent-owner-admission",
        "receipt_key_id": "receipt-key-v1",
        "receipt_public_key_sha256": receipt_public_hash,
        "receipt_sha256": (
            None if mode == "stage" else _FLEET_RECEIPT_DIGEST.removeprefix("sha256:")
        ),
        "receipt_signature_sha256": (
            None if mode == "stage" else _FLEET_RECEIPT_SIGNATURE_DIGEST.removeprefix("sha256:")
        ),
        "schema_revision": "p0s000000010",
        "schema_version": 1,
        "stage": "admission" if mode == "stage" else "runtime",
    }
    trust_pins_digest = "sha256:" + hashlib.sha256(_canonical_json(pins_document)).hexdigest()
    runner_fleet = {
        "admission_epoch": 7,
        "attestation": {
            "document_sha256": "sha256:" + attestation_hash,
            "issuer": "omnigent-owner-attestation",
            "key_id": "attestation-key-v1",
            "public_key_sha256": "sha256:" + attestation_public_hash,
            "signature_sha256": "sha256:" + attestation_signature_hash,
        },
        "evidence_context_sha256": "sha256:" + context_hash,
        "fleet_sha256": "sha256:" + fleet_hash,
        "namespace": TARGET_NAMESPACE,
        "receipt": {
            "document_sha256": "pending" if mode == "stage" else _FLEET_RECEIPT_DIGEST,
            "issuer": "omnigent-owner-admission",
            "key_id": "receipt-key-v1",
            "public_key_sha256": "sha256:" + receipt_public_hash,
            "signature_sha256": (
                "pending" if mode == "stage" else _FLEET_RECEIPT_SIGNATURE_DIGEST
            ),
        },
        "secret_name": (
            "omnigent-saas-runner-database-fleet-" + trust_pins_digest.removeprefix("sha256:")[:12]
        ),
        "trust_pins_sha256": trust_pins_digest,
    }
    return {
        "adapter_contract_version": "adapter-v1",
        "artifact": {
            "credential_revision": "sha256:" + ("5" * 64),
            "credentials_profile": "omnigent-saas-artifacts",
            "endpoint_cidr": "198.51.100.10/32",
            "endpoint_url": "https://s3.release.example.com",
            "readiness_key": "readiness/omnigent-saas-release-v1",
            "readiness_sha256": "6" * 64,
            "receipt_revision": "pending" if mode == "stage" else _RECEIPT_DIGEST,
            "region": "cn-east-1",
            "store_uri": store_uri,
        },
        "control_plane_schema_revision": "p0s000000010",
        "image_digest": "sha256:" + ("3" * 64),
        "ingress": {"namespace": "kube-system", "workload": "traefik"},
        "mode": mode,
        "official_schema_revision": "official-head-v1",
        "preview": {
            "gateway_instance_id": "next-beta-gateway-1",
            "owner_incarnation": "a" * 32,
            "pod_cidr": "10.42.0.0/16",
            "relay_trust_bundle_versions": ["preview-relay-v1", "preview-relay-v2"],
            "root_domain": "preview.next.jxhh.com",
            "service_cidr": "10.43.0.0/16",
        },
        "product_revision": "1" * 40,
        "public_origin": "https://next.jxhh.com",
        "release_incarnation": "4" * 32,
        "repository_endpoint_cidr": "203.0.113.20/32",
        "runner_fleet": runner_fleet,
        "runners": runners,
        "runtime_version": "runtime-v1",
        "schema_version": 1,
        "service_logins": {
            service: f"login_{index:02d}"
            for index, service in enumerate(EXPECTED_PRODUCTION_SERVICE_ROLES, start=1)
        },
        "source_revision": "1" * 40,
        "upstream_revision": "2" * 40,
    }


def _write_spec(tmp_path: Path, *, mode: str = "stage") -> Path:
    path = tmp_path / f"release-{mode}.json"
    path.write_bytes(_canonical_json(_spec_document(mode=mode)))
    path.chmod(0o600)
    return path


def _document(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="ascii"))
    assert isinstance(value, dict)
    return value


def _resource(
    document: dict[str, Any], *, kind: str, name: str | None = None, data_key: str | None = None
) -> dict[str, Any]:
    matches = []
    for item in document["items"]:
        if item["kind"] != kind:
            continue
        if name is not None and item["metadata"]["name"] != name:
            continue
        if data_key is not None and data_key not in item.get("data", {}):
            continue
        matches.append(item)
    assert len(matches) == 1
    return matches[0]


def test_stage_renderer_binds_four_manifests_and_only_six_pending_receipts(
    tmp_path: Path,
) -> None:
    source = _copy_sources(tmp_path)
    spec_file = _write_spec(tmp_path)
    output = tmp_path / "rendered"

    result = render_kubernetes_release(spec_file, source, output)

    assert result["status"] == "pass"
    assert result["mode"] == "stage"
    assert result["receipt_state"] == "pending"
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {*MANIFEST_NAMES, EVIDENCE_FILE_NAME}
    assert all(stat.S_IMODE((output / name).stat().st_mode) == 0o600 for name in MANIFEST_NAMES)

    production_path = output / "kubernetes.production.yaml"
    assert production_path.read_text(encoding="ascii").count(_ZERO_DIGEST) == 6
    production = _document(production_path)
    assert all(item["metadata"]["namespace"] == TARGET_NAMESPACE for item in production["items"])
    release = _resource(
        production,
        kind="ConfigMap",
        name="omnigent-saas-release-444444444444",
    )
    assert release["data"]["OMNIGENT_SAAS_SOURCE_SHA"] == "1" * 40
    assert release["data"]["OMNIGENT_SAAS_IMAGE_DIGEST"] == "sha256:" + ("3" * 64)
    assert release["data"]["OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS"] == "10.42.0.0/16"
    assert release["data"]["OMNIGENT_SAAS_PREVIEW_READINESS_ALLOWED_CIDRS"] == ("10.43.0.0/16")

    runner_b = _resource(production, kind="Deployment", name="omnigent-saas-runner-agent-b")
    assert all(
        item["spec"]["replicas"] == 0
        for item in production["items"]
        if item["kind"] == "Deployment"
    )
    runner_b_env = {
        row["name"]: row.get("value")
        for row in runner_b["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert runner_b_env["OMNIGENT_SAAS_RUNNER_ID"] == ("22222222-2222-4222-8222-222222222222")
    assert runner_b_env["OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION"] == "2"
    assert runner_b_env["OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT"] == "b"
    assert runner_b_env["OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256"] == ("b2" * 32)
    runner_b_annotations = runner_b["spec"]["template"]["metadata"]["annotations"]
    assert runner_b_annotations["omnigent.io/runner-repository-spec-sha256"] == (
        "sha256:" + ("b2" * 32)
    )
    pod_spec = runner_b["spec"]["template"]["spec"]
    init_mounts = {row["name"] for row in pod_spec["initContainers"][0]["volumeMounts"]}
    main_mounts = {row["name"] for row in pod_spec["containers"][0]["volumeMounts"]}
    repository_secret_volumes = {
        "runner-repository-spec-source",
        "runner-repository-credentials-source",
    }
    assert repository_secret_volumes.issubset(init_mounts)
    assert not repository_secret_volumes.intersection(main_mounts)

    network_text = (output / "kubernetes.network-policy.yaml").read_text(encoding="ascii")
    assert "cidr: 198.51.100.10/32" in network_text
    assert "cidr: 203.0.113.20/32" in network_text
    assert "replace" not in network_text.lower()
    assert "0.0.0.0/0" not in network_text

    evidence_path = output / EVIDENCE_FILE_NAME
    evidence_raw = evidence_path.read_bytes()
    evidence = json.loads(evidence_raw)
    assert evidence_raw == _canonical_json(evidence)
    assert evidence["artifact"]["receipt_state"] == "pending"
    assert evidence["artifact"]["receipt_revision"] is None
    assert evidence["runner_fleet"]["receipt"]["document_sha256"] == "pending"
    assert evidence["runner_fleet"]["receipt"]["signature_sha256"] == "pending"
    repository_evidence = evidence["runners"]["b"]["repository_pre_provisioning_expectations"]
    assert repository_evidence["source"] == "owner-sealed-pre-provisioning-rehearsal"
    assert repository_evidence["final_init_requirement"] == ("must-reproduce-exact-digests")
    assert evidence["namespace_render"]["target_namespace"] == TARGET_NAMESPACE
    assert evidence["spec_sha256"].startswith("sha256:")


def test_final_renderer_binds_exact_receipt_and_has_no_sentinel(tmp_path: Path) -> None:
    output = tmp_path / "rendered"

    result = render_kubernetes_release(
        _write_spec(tmp_path, mode="final"), _copy_sources(tmp_path), output
    )

    assert result["receipt_state"] == "bound"
    all_text = "".join((output / name).read_text(encoding="ascii") for name in MANIFEST_NAMES)
    assert all_text.count(_RECEIPT_DIGEST) == 2
    assert _ZERO_DIGEST not in all_text
    assert "replace" not in all_text.lower()
    evidence = json.loads((output / EVIDENCE_FILE_NAME).read_bytes())
    assert evidence["artifact"]["receipt_state"] == "bound"
    assert evidence["artifact"]["receipt_revision"] == _RECEIPT_DIGEST
    assert evidence["runner_fleet"]["receipt"]["document_sha256"] == (_FLEET_RECEIPT_DIGEST)
    production = _document(output / "kubernetes.production.yaml")
    expected_replicas = {
        "omnigent-saas-server": 2,
        "omnigent-saas-worker": 2,
        "omnigent-saas-runner-agent-a": 1,
        "omnigent-saas-runner-agent-b": 1,
        "omnigent-saas-preview-edge": 2,
        "omnigent-saas-preview-owner": 1,
    }
    for name, replicas in expected_replicas.items():
        deployment = _resource(production, kind="Deployment", name=name)
        assert deployment["spec"]["replicas"] == replicas
    for slot in ("a", "b"):
        runner = _resource(
            production, kind="Deployment", name=f"omnigent-saas-runner-agent-{slot}"
        )
        assert "omnigent.io/production-blocker" not in runner["metadata"]["annotations"]


def test_repository_projections_are_unique_and_secrets_are_init_only(
    tmp_path: Path,
) -> None:
    output = tmp_path / "rendered"
    render_kubernetes_release(_write_spec(tmp_path), _copy_sources(tmp_path), output)
    production_path = output / "kubernetes.production.yaml"
    production_text = production_path.read_text(encoding="ascii")
    production = _document(production_path)
    spec_document = _spec_document()

    annotation_fields = (
        "omnigent.io/runner-repository-expected-binding-keys",
        "omnigent.io/runner-repository-slot",
        "omnigent.io/runner-repository-credential-revision",
        "omnigent.io/runner-repository-spec-sha256",
        "omnigent.io/runner-repository-bindings-sha256",
        "omnigent.io/runner-repository-receipt-sha256",
    )
    env_fields = (
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RUNNER_SLOT",
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_SPEC_SHA256",
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_BINDINGS_SHA256",
        "OMNIGENT_SAAS_RUNNER_REPOSITORY_EXPECTED_RECEIPT_SHA256",
    )
    for field in annotation_fields:
        assert production_text.count(f"{field}:") == 2
    for slot in ("a", "b"):
        runner = _resource(
            production, kind="Deployment", name=f"omnigent-saas-runner-agent-{slot}"
        )
        pod_spec = runner["spec"]["template"]["spec"]
        main = next(row for row in pod_spec["containers"] if row["name"] == "runner-agent")
        init = next(
            row for row in pod_spec["initContainers"] if row["name"] == "stage-runner-identity"
        )
        env_names = [row["name"] for row in main["env"]]
        assert all(env_names.count(field) == 1 for field in env_fields)
        volume_names = [row["name"] for row in pod_spec["volumes"]]
        assert volume_names.count("runner-repository-spec-source") == 1
        assert volume_names.count("runner-repository-credentials-source") == 1
        init_mounts = {row["name"]: row for row in init["volumeMounts"]}
        main_mounts = {row["name"]: row for row in main["volumeMounts"]}
        assert init_mounts["runner-repository-spec-source"]["readOnly"] is True
        assert init_mounts["runner-repository-credentials-source"]["readOnly"] is True
        assert "runner-repository-spec-source" not in main_mounts
        assert "runner-repository-credentials-source" not in main_mounts
        assert init_mounts["repository-state"]["mountPath"] == "/repository"
        assert main_mounts["repository-state"]["mountPath"] == "/repository"
        assert main_mounts["work"]["mountPath"] == "/work"
        annotations = runner["spec"]["template"]["metadata"]["annotations"]
        assert annotations["omnigent.io/runner-repository-expected-binding-keys"] == ("primary")
        assert "--expected-binding-key primary" in "\n".join(init["args"])

        runner_spec = spec_document["runners"][slot]
        binding_sha256 = hashlib.sha256(
            _canonical_json(
                {
                    "release_incarnation": spec_document["release_incarnation"],
                    "runner_slot": slot,
                    "spec_sha256": runner_spec["repository_spec_sha256"],
                }
            )
        ).hexdigest()
        volumes = {row["name"]: row for row in pod_spec["volumes"]}
        assert volumes["runner-fleet-source"]["secret"]["defaultMode"] == 0o400
        assert volumes["runner-fleet-source"]["secret"]["items"] == [
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
        assert volumes["runner-repository-credentials-source"]["secret"]["items"] == [
            {"key": "primary.credential", "path": "primary.credential"}
        ]
        assert volumes["runner-repository-spec-source"]["secret"]["secretName"] == (
            f"omnigent-saas-runner-{slot}-repository-provisioning-{binding_sha256[:12]}"
        )
        credential_suffix = runner_spec["repository_credential_revision"].removeprefix("sha256:")[
            :12
        ]
        assert (
            volumes["runner-repository-credentials-source"]["secret"]["secretName"]
            == f"omnigent-saas-runner-{slot}-repository-credentials-{credential_suffix}"
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong-path"])
def test_renderer_rejects_runner_fleet_secret_projection_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = _copy_sources(tmp_path)
    production_path = source / "kubernetes.production.yaml"
    document = _document(production_path)
    runner = _resource(document, kind="Deployment", name="omnigent-saas-runner-agent-a")
    volumes = {row["name"]: row for row in runner["spec"]["template"]["spec"]["volumes"]}
    items = volumes["runner-fleet-source"]["secret"]["items"]
    if mutation == "missing":
        items.pop()
    elif mutation == "extra":
        items.append({"key": "admin-database-url", "path": "admin-database-url"})
    else:
        items[0]["path"] = "renamed.json"
    production_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    with pytest.raises(ReleaseRenderError, match="fleet Secret projection"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")


@pytest.mark.parametrize(
    ("manifest_name", "kind", "resource_name", "volume_name", "mutation"),
    [
        (
            "kubernetes.migration.yaml",
            "Job",
            "omnigent-saas-postgresql-migration",
            "postgresql-ca-source",
            "missing",
        ),
        (
            "kubernetes.production.yaml",
            "Deployment",
            "omnigent-saas-server",
            "runner-control-ca-source",
            "extra",
        ),
        (
            "kubernetes.production.yaml",
            "Deployment",
            "omnigent-saas-runner-agent-a",
            "preview-runner-ca-source",
            "wrong-path",
        ),
    ],
)
def test_renderer_rejects_public_ca_secret_projection_drift(
    tmp_path: Path,
    manifest_name: str,
    kind: str,
    resource_name: str,
    volume_name: str,
    mutation: str,
) -> None:
    source = _copy_sources(tmp_path)
    manifest_path = source / manifest_name
    document = _document(manifest_path)
    resource = _resource(document, kind=kind, name=resource_name)
    volumes = {row["name"]: row for row in resource["spec"]["template"]["spec"]["volumes"]}
    secret = volumes[volume_name]["secret"]
    if mutation == "missing":
        secret.pop("items")
    elif mutation == "extra":
        secret["items"].append({"key": "ca.key", "path": "ca.key"})
    else:
        secret["items"][0]["path"] = "renamed-ca.crt"
    manifest_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    with pytest.raises(ReleaseRenderError, match="public CA Secret projection"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-flag",
        "comment-decoy",
        "extra-flag",
        "spec-wrong-path",
        "credential-extra",
        "private-main",
    ],
)
def test_renderer_rejects_beta_repository_projection_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = _copy_sources(tmp_path)
    production_path = source / "kubernetes.production.yaml"
    document = _document(production_path)
    runner = _resource(document, kind="Deployment", name="omnigent-saas-runner-agent-a")
    pod_spec = runner["spec"]["template"]["spec"]
    init = next(
        row for row in pod_spec["initContainers"] if row["name"] == "stage-runner-identity"
    )
    volumes = {row["name"]: row for row in pod_spec["volumes"]}
    main = next(row for row in pod_spec["containers"] if row["name"] == "runner-agent")
    if mutation == "missing-flag":
        init["args"][0] = init["args"][0].replace(" --expected-binding-key primary", "")
    elif mutation == "comment-decoy":
        init["args"][0] = init["args"][0].replace(
            " --expected-binding-key primary",
            "\n# --expected-binding-key primary",
        )
    elif mutation == "extra-flag":
        init["args"][0] = init["args"][0].replace(
            "--expected-binding-key primary",
            "--expected-binding-key primary --expected-binding-key secondary",
        )
    elif mutation == "spec-wrong-path":
        volumes["runner-repository-spec-source"]["secret"]["items"][0]["path"] = "renamed.json"
    elif mutation == "credential-extra":
        volumes["runner-repository-credentials-source"]["secret"]["items"].append(
            {"key": "secondary.credential", "path": "secondary.credential"}
        )
    else:
        main["volumeMounts"].append(
            {"name": "runner-repository-private", "mountPath": "/provisioning-private"}
        )
    production_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    with pytest.raises(
        ReleaseRenderError,
        match=r"repository (?:exact-primary|spec|credential)|main volume mount",
    ):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")


def test_semantic_locator_does_not_depend_on_list_item_order(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    production_path = source / "kubernetes.production.yaml"
    document = _document(production_path)
    document["items"] = list(reversed(document["items"]))
    production_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    result = render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")

    assert result["status"] == "pass"


def test_renderer_rejects_unknown_future_template_sentinel(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    production_path = source / "kubernetes.production.yaml"
    document = _document(production_path)
    release = _resource(document, kind="ConfigMap", data_key="OMNIGENT_SAAS_UPSTREAM_REVISION")
    release["data"]["OMNIGENT_SAAS_FUTURE_FIELD"] = "replace-with-future-authority"
    production_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    with pytest.raises(ReleaseRenderError, match="unknown template sentinel"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")


def test_renderer_rejects_duplicate_projection_token_location(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    production_path = source / "kubernetes.production.yaml"
    document = _document(production_path)
    release = _resource(document, kind="ConfigMap", data_key="OMNIGENT_SAAS_UPSTREAM_REVISION")
    release["data"]["UNAUTHORIZED_RELEASE_REFERENCE"] = "omnigent-saas-release-replace-release12"
    production_path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=4096), encoding="utf-8"
    )

    with pytest.raises(ReleaseRenderError, match=r"exactly .* authorized"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered")


def test_renderer_rejects_noncanonical_or_non_owner_only_spec(tmp_path: Path) -> None:
    document = _spec_document()
    path = tmp_path / "release.json"
    path.write_text(json.dumps(document, indent=2), encoding="ascii")
    path.chmod(0o600)
    with pytest.raises(ReleaseRenderError, match="canonical JSON"):
        load_public_release_spec(path)

    path.write_bytes(_canonical_json(document))
    path.chmod(0o640)
    with pytest.raises(ReleaseRenderError, match=r"unavailable|owner-only regular file"):
        load_public_release_spec(path)


def test_renderer_rejects_spec_symlink_and_unknown_key(tmp_path: Path) -> None:
    target = _write_spec(tmp_path)
    symlink = tmp_path / "release-link.json"
    symlink.symlink_to(target)
    with pytest.raises(ReleaseRenderError, match=r"unavailable|owner-only regular file"):
        load_public_release_spec(symlink)

    document = _spec_document()
    document["unexpected"] = True
    target.write_bytes(_canonical_json(document))
    with pytest.raises(ReleaseRenderError, match="fields do not match"):
        load_public_release_spec(target)


@pytest.mark.parametrize(
    ("mode", "mutate", "message"),
    [
        (
            "stage",
            lambda spec: spec["runner_fleet"].__setitem__(
                "trust_pins_sha256", "sha256:" + ("1" * 64)
            ),
            "does not bind the canonical public pins",
        ),
        (
            "stage",
            lambda spec: spec["runner_fleet"].__setitem__(
                "secret_name", "omnigent-saas-runner-database-fleet-wrong00000000"
            ),
            "must be derived from the canonical trust pins",
        ),
        (
            "stage",
            lambda spec: spec["runner_fleet"]["receipt"].update(
                {
                    "document_sha256": _FLEET_RECEIPT_DIGEST,
                    "signature_sha256": _FLEET_RECEIPT_SIGNATURE_DIGEST,
                }
            ),
            "stage runner_fleet receipt hashes must equal pending",
        ),
        (
            "final",
            lambda spec: spec["runner_fleet"]["receipt"].update(
                {"document_sha256": "pending", "signature_sha256": "pending"}
            ),
            "invalid or all-zero",
        ),
        (
            "stage",
            lambda spec: spec.__setitem__("control_plane_schema_revision", "p0s000000009"),
            "must equal the packaged p0s10 Alembic head",
        ),
        (
            "stage",
            lambda spec: spec["runners"]["a"].__setitem__(
                "recovery_credentials_profile", "runner-arbitrary-g1"
            ),
            "must bind the exact runner generation",
        ),
        (
            "stage",
            lambda spec: spec["runners"]["a"].__setitem__(
                "recovery_credential_secret_name", "runner-a-secret"
            ),
            "must be the derived immutable name",
        ),
        (
            "stage",
            lambda spec: spec["runners"]["a"].__setitem__(
                "repository_receipt_sha256", _ZERO_DIGEST
            ),
            "repository_receipt_sha256 is invalid or all-zero",
        ),
        (
            "stage",
            lambda spec: spec["runners"]["b"].__setitem__(
                "repository_spec_sha256",
                spec["runners"]["a"]["repository_spec_sha256"],
            ),
            "must be distinct",
        ),
    ],
)
def test_renderer_rejects_invalid_fleet_and_recovery_contract(
    tmp_path: Path,
    mode: str,
    mutate: Any,
    message: str,
) -> None:
    document = _spec_document(mode=mode)
    mutate(document)
    path = tmp_path / "release.json"
    path.write_bytes(_canonical_json(document))
    path.chmod(0o600)

    with pytest.raises(ReleaseRenderError, match=message):
        load_public_release_spec(path)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda spec: spec.__setitem__("image_digest", _ZERO_DIGEST),
            "image_digest is invalid or all-zero",
        ),
        (
            lambda spec: spec["preview"].__setitem__("pod_cidr", "0.0.0.0/0"),
            "bounded canonical CIDR",
        ),
        (
            lambda spec: spec["preview"].__setitem__("root_domain", "replace-preview.example.net"),
            "canonical routable DNS name",
        ),
        (
            lambda spec: spec["runners"]["b"].__setitem__(
                "runner_id", spec["runners"]["a"]["runner_id"]
            ),
            "exact runner generation|must be distinct",
        ),
        (
            lambda spec: spec["runners"]["b"].__setitem__(
                "recovery_credential_revision",
                spec["runners"]["a"]["recovery_credential_revision"],
            ),
            "derived immutable name|must be distinct",
        ),
    ],
)
def test_renderer_rejects_invalid_release_authority(
    tmp_path: Path,
    mutate: Any,
    message: str,
) -> None:
    document = _spec_document()
    mutate(document)
    path = tmp_path / "release.json"
    path.write_bytes(_canonical_json(document))
    path.chmod(0o600)

    with pytest.raises(ReleaseRenderError, match=message):
        load_public_release_spec(path)


def test_renderer_rejects_extra_yaml_and_nonempty_or_insecure_output(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    (source / "extra.yaml").write_text("apiVersion: v1\nkind: List\nitems: []\n")
    with pytest.raises(ReleaseRenderError, match="exact four YAML"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "rendered-extra")

    (source / "extra.yaml").unlink()
    output = tmp_path / "rendered"
    output.mkdir(mode=0o700)
    (output / "unexpected").write_text("x")
    with pytest.raises(ReleaseRenderError, match="must be empty"):
        render_kubernetes_release(_write_spec(tmp_path), source, output)

    (output / "unexpected").unlink()
    output.chmod(0o750)
    with pytest.raises(ReleaseRenderError, match="mode-0700"):
        render_kubernetes_release(_write_spec(tmp_path), source, output)


def test_renderer_rejects_any_extra_source_file_or_manifest_symlink(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    (source / "README.txt").write_text("unexpected\n", encoding="ascii")
    with pytest.raises(ReleaseRenderError, match="only the exact four YAML"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "extra-output")

    (source / "README.txt").unlink()
    production = source / "kubernetes.production.yaml"
    real_production = tmp_path / "real-production.yaml"
    production.replace(real_production)
    production.symlink_to(real_production)
    with pytest.raises(ReleaseRenderError, match="must be a regular file"):
        render_kubernetes_release(_write_spec(tmp_path), source, tmp_path / "link-output")


def test_authorized_change_audit_rejects_unapproved_scalar_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = release_renderer_module._render_release_documents

    def tampered_render(
        sources: Any, spec: Any
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        documents, suffixes = original(sources, spec)
        server = _resource(
            documents["kubernetes.production.yaml"],
            kind="Deployment",
            name="omnigent-saas-server",
        )
        server["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
        return documents, suffixes

    monkeypatch.setattr(release_renderer_module, "_render_release_documents", tampered_render)
    with pytest.raises(ReleaseRenderError, match="unauthorized scalar"):
        render_kubernetes_release(
            _write_spec(tmp_path), _copy_sources(tmp_path), tmp_path / "rendered"
        )


def test_authorized_change_audit_rejects_wrong_value_on_allowed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = release_renderer_module._render_release_documents

    def tampered_render(
        sources: Any, spec: Any
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        documents, suffixes = original(sources, spec)
        release = _resource(
            documents["kubernetes.production.yaml"],
            kind="ConfigMap",
            data_key="OMNIGENT_SAAS_UPSTREAM_REVISION",
        )
        release["data"]["OMNIGENT_SAAS_IMAGE_DIGEST"] = "sha256:" + ("e" * 64)
        return documents, suffixes

    monkeypatch.setattr(release_renderer_module, "_render_release_documents", tampered_render)
    with pytest.raises(ReleaseRenderError, match="unauthorized scalar"):
        render_kubernetes_release(
            _write_spec(tmp_path), _copy_sources(tmp_path), tmp_path / "rendered"
        )


def test_console_outputs_only_secret_free_hash_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = main(
        [
            "--spec-file",
            str(_write_spec(tmp_path)),
            "--source-dir",
            str(_copy_sources(tmp_path)),
            "--output-dir",
            str(tmp_path / "rendered"),
        ]
    )

    assert result == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    summary = json.loads(captured.out)
    assert set(summary) == {
        "evidence_file",
        "evidence_sha256",
        "manifest_count",
        "mode",
        "receipt_state",
        "rendered_set_sha256",
        "status",
    }
    assert summary["status"] == "pass"
    assert "https://" not in captured.out
    assert "s3://" not in captured.out


def test_failed_render_does_not_modify_source_templates(tmp_path: Path) -> None:
    source = _copy_sources(tmp_path)
    before = {name: (source / name).read_bytes() for name in MANIFEST_NAMES}
    document = copy.deepcopy(_spec_document())
    document["artifact"]["receipt_revision"] = _RECEIPT_DIGEST
    spec_file = tmp_path / "invalid-stage.json"
    spec_file.write_bytes(_canonical_json(document))
    spec_file.chmod(0o600)

    with pytest.raises(ReleaseRenderError, match="must equal pending"):
        render_kubernetes_release(spec_file, source, tmp_path / "rendered")

    assert {name: (source / name).read_bytes() for name in MANIFEST_NAMES} == before
