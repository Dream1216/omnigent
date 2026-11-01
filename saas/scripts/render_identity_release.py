"""Extend a staged release with isolated, disabled identity process resources."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from saas.scripts.render_kubernetes_namespace import (
    MANIFEST_NAMES,
    TARGET_EXTERNAL_DATABASE_NAMESPACE,
    TARGET_NAMESPACE,
)
from saas.scripts.render_kubernetes_release import (
    EVIDENCE_FILE_NAME as PARENT_EVIDENCE,
)
from saas.scripts.render_kubernetes_release import (
    ReleaseRenderError,
    _canonical_json,
    _default_source_dir,
    _load_source_manifests,
    _mapping,
    _prepare_output_directory,
    _read_owner_only_spec,
    _write_exclusive,
    load_public_release_spec,
    render_kubernetes_release,
)

MANIFEST = "kubernetes.identity.yaml"
EVIDENCE = "identity-release-render-evidence.json"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PROVIDER_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SECRET_FIELDS = {
    "provider",
    "reader_keys",
    "reader_secret",
    "webhook_keys",
    "broker_tls",
    "worker_tls",
    "provider_ca",
    "reader_ca",
}
_BROKER = "omnigent-identity-reader"
_WORKER = "omnigent-identity-sync"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _label(value: object) -> str:
    if not isinstance(value, str) or _LABEL.fullmatch(value) is None:
        raise ReleaseRenderError("identity peer or Secret name is invalid")
    return value


def _peer(value: object) -> dict:
    row = _mapping(value, name="identity peer", fields={"namespace", "workload"})
    return {
        "namespaceSelector": {
            "matchLabels": {"kubernetes.io/metadata.name": _label(row["namespace"])}
        },
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": _label(row["workload"])}},
    }


def _load_identity_spec(path: Path) -> tuple[bytes, dict]:
    raw, doc = _read_owner_only_spec(path)
    _mapping(
        doc,
        name="identity spec",
        fields={
            "schema_version",
            "casdoor",
            "reader_key_id",
            "concurrency",
            "reconcile_seconds",
            "poll_seconds",
            "private_ingress",
            "monitoring",
            "secrets",
        },
    )
    provider = _mapping(
        doc["casdoor"],
        name="identity casdoor",
        fields={
            "issuer",
            "organization",
            "application",
            "client_id",
            "provider_application",
            "provider_client_id",
            "endpoint_cidr",
        },
    )
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise ReleaseRenderError("identity schema_version must equal 1")
    for name in (
        "organization",
        "application",
        "client_id",
        "provider_application",
        "provider_client_id",
    ):
        if not isinstance(provider[name], str) or not _PROVIDER_LABEL.fullmatch(provider[name]):
            raise ReleaseRenderError("identity application pins are invalid")
    if (
        provider["organization"] == "built-in"
        or "app-built-in" in (provider["application"], provider["provider_application"])
        or provider["application"] == provider["provider_application"]
        or provider["client_id"] == provider["provider_client_id"]
    ):
        raise ReleaseRenderError("identity provider application must be separate")
    if not isinstance(provider["issuer"], str) or not isinstance(provider["endpoint_cidr"], str):
        raise ReleaseRenderError("identity provider endpoint pins are invalid")
    try:
        origin = urlsplit(provider["issuer"])
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username
            or origin.password
            or origin.path
            or origin.query
            or origin.fragment
            or origin.port not in (None, 443)
            or provider["issuer"] != "https://" + origin.netloc
        ):
            raise ValueError
        endpoint = ipaddress.ip_network(provider["endpoint_cidr"], strict=True)
        if endpoint.prefixlen != endpoint.max_prefixlen or endpoint.network_address.is_unspecified:
            raise ValueError
        if str(endpoint) != provider["endpoint_cidr"]:
            raise ValueError
    except (TypeError, ValueError):
        raise ReleaseRenderError(
            "identity provider requires an HTTPS origin and one endpoint IP"
        ) from None
    for name, maximum in (("concurrency", 16), ("reconcile_seconds", 60), ("poll_seconds", 5)):
        if type(doc[name]) is not int or not 1 <= doc[name] <= maximum:
            raise ReleaseRenderError("identity operation budget is invalid")
    if not isinstance(doc["reader_key_id"], str) or not _KEY_ID.fullmatch(doc["reader_key_id"]):
        raise ReleaseRenderError("identity reader key ID is invalid")
    _peer(doc["private_ingress"])
    _peer(doc["monitoring"])
    secrets = _mapping(doc["secrets"], name="identity Secret references", fields=_SECRET_FIELDS)
    names = [_label(value) for value in secrets.values()]
    if len(set(names)) != len(names) or any(
        re.search(r"-[0-9a-f]{12}$", name) is None for name in names
    ):
        raise ReleaseRenderError("identity Secret references must be distinct revisioned names")
    return raw, doc


def _resource(kind: str, name: str, **fields) -> dict:
    api = {
        "Deployment": "apps/v1",
        "PodDisruptionBudget": "policy/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
    }.get(kind, "v1")
    return {
        "apiVersion": api,
        "kind": kind,
        "metadata": {"name": name, "namespace": TARGET_NAMESPACE},
        **fields,
    }


def _security() -> dict:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "capabilities": {"drop": ["ALL"]},
    }


def _deployment(
    name: str,
    *,
    release,
    public_name: str,
    public_files: dict,
    secrets: dict,
    common_env: dict,
    role_env: dict,
    annotations: dict,
) -> dict:
    broker = name == _BROKER
    inputs = [
        (
            "tls",
            secrets["broker_tls" if broker else "worker_tls"],
            {"tls.crt": "identity-tls.crt", "tls.key": "identity-tls.key"},
        ),
    ]
    if broker:
        inputs += [
            ("provider", secrets["provider"], {"value": "provider-secret"}),
            ("reader-keys", secrets["reader_keys"], {"value": "reader-keys.json"}),
            ("provider-ca", secrets["provider_ca"], {"ca.crt": "provider-ca.crt"}),
        ]
    else:
        inputs += [
            ("reader", secrets["reader_secret"], {"value": "reader-secret"}),
            ("webhook", secrets["webhook_keys"], {"value": "webhook-keys.json"}),
            ("reader-ca", secrets["reader_ca"], {"ca.crt": "reader-ca.crt"}),
            (
                "authenticator",
                "omnigent-saas-authenticator-database",
                {"value": "authenticator-database-url"},
            ),
            (
                "receipt",
                "omnigent-saas-migration-receipt",
                {"value": "postgresql-migration-receipt"},
            ),
            ("postgresql-ca", "omnigent-saas-postgresql-ca", {"ca.crt": "postgresql-ca.crt"}),
        ]
    copies = {f"/source/public/{key}": key for key in public_files}
    volumes: list[dict] = [
        {"name": "public", "configMap": {"name": public_name, "defaultMode": 0o444}},
        {"name": "runtime", "emptyDir": {"medium": "Memory", "sizeLimit": "256Ki"}},
        {"name": "temp", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
    ]
    init_mounts = [
        {"name": "runtime", "mountPath": "/runtime"},
        {"name": "public", "mountPath": "/source/public", "readOnly": True},
    ]
    for volume, secret, files in inputs:
        volumes.append(
            {
                "name": volume,
                "secret": {
                    "secretName": secret,
                    "defaultMode": 0o440,
                    "items": [{"key": key, "path": key} for key in files],
                },
            }
        )
        init_mounts.append({"name": volume, "mountPath": "/source/" + volume, "readOnly": True})
        copies.update({f"/source/{volume}/{key}": target for key, target in files.items()})
    script = (
        "import os,pathlib; os.umask(0o077)\n"
        f"for source,target in {copies!r}.items():\n"
        " with open(source,'rb') as stream: data=stream.read(131073)\n"
        " if len(data)>131072: raise ValueError('identity input exceeds budget')\n"
        " descriptor=os.open('/runtime/'+target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)\n"
        " with os.fdopen(descriptor,'wb') as stream: stream.write(data)\n"
    )
    env = {
        **common_env,
        "OMNIGENT_SAAS_CASDOOR_CONFIG_FILE": "/runtime/casdoor.json",
        "OMNIGENT_SAAS_IDENTITY_SYNC_CONFIG_FILE": "/runtime/sync.json",
        "OMNIGENT_SAAS_IDENTITY_TLS_CERT_FILE": "/runtime/identity-tls.crt",
        "OMNIGENT_SAAS_IDENTITY_TLS_KEY_FILE": "/runtime/identity-tls.key",
    }
    if broker:
        env.update(
            {
                "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_CONFIG_FILE": "/runtime/provider.json",
                "OMNIGENT_SAAS_IDENTITY_BROKER_PROVIDER_SECRET_FILE": "/runtime/provider-secret",
                "OMNIGENT_SAAS_IDENTITY_READER_KEYS_FILE": "/runtime/reader-keys.json",
            }
        )
    else:
        env.update(role_env)
        env.update(
            {
                "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE": (
                    "/runtime/authenticator-database-url"
                ),
                "OMNIGENT_SAAS_MIGRATION_RECEIPT_FILE": "/runtime/postgresql-migration-receipt",
                "OMNIGENT_SAAS_IDENTITY_READER_SECRET_FILE": "/runtime/reader-secret",
                "OMNIGENT_SAAS_CASDOOR_WEBHOOK_SECRET_FILE": "/runtime/webhook-keys.json",
                "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": release.official_schema_revision,
                "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": (
                    release.control_plane_schema_revision
                ),
            }
        )
    image = "ghcr.io/omnigent-ai/omnigent-server@" + release.image_digest
    pod = {
        "serviceAccountName": name,
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 60,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "fsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "initContainers": [
            {
                "name": "stage-identity-files",
                "image": image,
                "command": ["python", "-c", script],
                "securityContext": _security(),
                "resources": {
                    "requests": {"cpu": "50m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                },
                "volumeMounts": init_mounts,
            }
        ],
        "containers": [
            {
                "name": "identity",
                "image": image,
                "command": [
                    "python",
                    "-m",
                    "saas.production."
                    + ("identity_read_broker_main" if broker else "identity_sync_main"),
                ],
                "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
                "ports": [{"name": "https", "containerPort": 8443}],
                "securityContext": _security(),
                "resources": {
                    "requests": {"cpu": "100m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "512Mi"},
                },
                "volumeMounts": [
                    {"name": "runtime", "mountPath": "/runtime", "readOnly": True},
                    {"name": "temp", "mountPath": "/tmp"},
                ],
                **{
                    kind: {
                        "httpGet": {"scheme": "HTTPS", "path": path, "port": 8443},
                        "timeoutSeconds": timeout,
                        "periodSeconds": 10,
                        "failureThreshold": failures,
                    }
                    for kind, path, timeout, failures in (
                        ("startupProbe", "/healthz", 3, 30),
                        ("livenessProbe", "/healthz", 3, 6),
                        ("readinessProbe", "/healthz" if broker else "/readyz", 15, 3),
                    )
                },
            }
        ],
        "volumes": volumes,
        "affinity": {
            "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [
                    {
                        "weight": 100,
                        "podAffinityTerm": {
                            "topologyKey": "kubernetes.io/hostname",
                            "labelSelector": {"matchLabels": {"app.kubernetes.io/name": name}},
                        },
                    }
                ]
            }
        },
    }
    result = _resource(
        "Deployment",
        name,
        spec={
            "replicas": 0,
            "revisionHistoryLimit": 3,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
            },
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {
                "metadata": {
                    "labels": {"app.kubernetes.io/name": name},
                    "annotations": annotations,
                },
                "spec": pod,
            },
        },
    )
    result["metadata"]["annotations"] = {
        "omnigent.io/production-blocker": "identity-admission-pending"
    }
    return result


def _network(name: str, *, provider: dict, ingress: dict, monitoring: dict) -> dict:
    def local(app):
        return {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}}

    dns = {
        "to": [
            {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                },
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }
        ],
        "ports": [{"protocol": protocol, "port": 53} for protocol in ("TCP", "UDP")],
    }
    if name == _BROKER:
        incoming = [local(_WORKER), monitoring]
        outgoing = [
            {
                "to": [{"ipBlock": {"cidr": provider["endpoint_cidr"]}}],
                "ports": [{"protocol": "TCP", "port": 443}],
            }
        ]
    else:
        incoming = [ingress, monitoring]
        outgoing = [
            {"to": [local(_BROKER)], "ports": [{"protocol": "TCP", "port": 8443}]},
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": TARGET_EXTERNAL_DATABASE_NAMESPACE
                            }
                        },
                        "podSelector": {"matchLabels": {"cnpg.io/cluster": "omnigent-postgres"}},
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 5432}],
            },
        ]
    return _resource(
        "NetworkPolicy",
        name,
        spec={
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": incoming, "ports": [{"protocol": "TCP", "port": 8443}]}],
            "egress": [dns, *outgoing],
        },
    )


def render_identity_release(
    release_spec: Path, identity_spec: Path, source_dir: Path, output_dir: Path
) -> dict:
    release_raw, _document = _read_owner_only_spec(release_spec)
    raw, identity = _load_identity_spec(identity_spec)
    sources = _load_source_manifests(source_dir)
    bundled = _load_source_manifests(_default_source_dir())
    if any(sources[name].raw != bundled[name].raw for name in MANIFEST_NAMES):
        raise ReleaseRenderError("identity rendering requires the bundled reviewed parent sources")
    with tempfile.TemporaryDirectory(prefix="omnigent-identity-render-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        frozen_release = root / "release.json"
        _write_exclusive(frozen_release, release_raw)
        release = load_public_release_spec(frozen_release)
        if release.mode != "stage" or release.control_plane_schema_revision != "cd4a00000001":
            raise ReleaseRenderError(
                "identity rendering requires a staged cd4a release; final admission is pending"
            )
        frozen_sources = root / "source"
        frozen_sources.mkdir(mode=0o700)
        for name in MANIFEST_NAMES:
            _write_exclusive(frozen_sources / name, sources[name].raw)
        parent = root / "parent"
        render_kubernetes_release(frozen_release, frozen_sources, parent)
        parent_files = {
            name: (parent / name).read_bytes() for name in (*MANIFEST_NAMES, PARENT_EVIDENCE)
        }
    evidence = json.loads(parent_files[PARENT_EVIDENCE])
    production = yaml.safe_load(parent_files["kubernetes.production.yaml"])
    bindings = next(
        item
        for item in production["items"]
        if item["kind"] == "ConfigMap" and "service-role-bindings.json" in item["data"]
    )
    public = copy.deepcopy(bindings["data"])
    provider = identity["casdoor"]
    reader_origin = f"https://{_BROKER}.{TARGET_NAMESPACE}.svc.cluster.local:8443"
    public.update(
        {
            "casdoor.json": _canonical_json(
                {
                    key: provider[key]
                    for key in ("issuer", "organization", "application", "client_id")
                }
                | {"token_endpoint_auth_method": "client_secret_basic"}
            ).decode(),
            "sync.json": _canonical_json(
                {
                    "schema_version": 1,
                    "reader_origin": reader_origin,
                    "reader_key_id": identity["reader_key_id"],
                    "reader_ca_file": "/runtime/reader-ca.crt",
                    "provider_source_lock_sha256": _digest(
                        (
                            Path(__file__).resolve().parents[1]
                            / "production/casdoor/source-lock.json"
                        ).read_bytes()
                    ),
                    **{
                        key: identity[key]
                        for key in ("concurrency", "reconcile_seconds", "poll_seconds")
                    },
                }
            ).decode(),
            "provider.json": _canonical_json(
                {
                    "schema_version": 1,
                    "provider_application": provider["provider_application"],
                    "provider_client_id": provider["provider_client_id"],
                    "provider_ca_file": "/runtime/provider-ca.crt",
                }
            ).decode(),
        }
    )
    config_hash = _digest(_canonical_json(public))
    public_name = "omnigent-identity-public-" + config_hash[:12]
    common = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": release.product_revision,
        "OMNIGENT_SAAS_SOURCE_SHA": release.source_revision,
        "OMNIGENT_SAAS_UPSTREAM_REVISION": release.upstream_revision,
        "OMNIGENT_SAAS_IMAGE_DIGEST": release.image_digest,
    }
    role_env = {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": "/runtime/service-role-bindings.json"}
    for prefix, filename in (
        ("PLATFORM_MODEL", "platform-model-service-role-bindings.json"),
        ("PLATFORM_ADMIN", "platform-admin-service-role-bindings.json"),
        ("MODEL_PROJECTION", "model-projection-service-role-bindings.json"),
    ):
        if filename in public:
            role_env[f"OMNIGENT_SAAS_{prefix}_SERVICE_ROLE_BINDINGS_FILE"] = "/runtime/" + filename
    annotations = {
        "omnigent.io/product-revision": release.product_revision,
        "omnigent.io/parent-release-evidence-sha256": _digest(parent_files[PARENT_EVIDENCE]),
        "omnigent.io/identity-spec-sha256": _digest(raw),
        "omnigent.io/public-config-sha256": config_hash,
    }
    items = [_resource("ConfigMap", public_name, immutable=True, data=public)]
    for name in (_BROKER, _WORKER):
        items += [
            _resource("ServiceAccount", name, automountServiceAccountToken=False),
            _deployment(
                name,
                release=release,
                public_name=public_name,
                public_files=public,
                secrets=identity["secrets"],
                common_env=common,
                role_env=role_env,
                annotations=annotations,
            ),
            _resource(
                "Service",
                name,
                spec={
                    "type": "ClusterIP",
                    "selector": {"app.kubernetes.io/name": name},
                    "ports": [{"name": "https", "port": 8443, "targetPort": "https"}],
                },
            ),
            _resource(
                "PodDisruptionBudget",
                name,
                spec={
                    "minAvailable": 1,
                    "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                },
            ),
            _network(
                name,
                provider=provider,
                ingress=_peer(identity["private_ingress"]),
                monitoring=_peer(identity["monitoring"]),
            ),
        ]
    manifest = yaml.safe_dump(
        {"apiVersion": "v1", "kind": "List", "items": items}, sort_keys=False, allow_unicode=False
    ).encode("ascii")
    receipt = {
        "schema_version": 1,
        "status": "pass",
        "mode": "stage",
        "admission_state": "pending",
        "production_qualification": False,
        "product_revision": release.product_revision,
        "image_digest": release.image_digest,
        "parent_evidence_sha256": _digest(parent_files[PARENT_EVIDENCE]),
        "parent_rendered_set_sha256": evidence["rendered_set_sha256"],
        "service_role_bindings_sha256": evidence["service_role_bindings_sha256"],
        "identity_spec_sha256": _digest(raw),
        "public_config_sha256": config_hash,
        "identity_manifest_sha256": _digest(manifest),
        "replicas": {_BROKER: 0, _WORKER: 0},
        "requirements": [
            "installed-image admission",
            "private TLS/network/secret isolation",
            "direct webhook and signed OIDC session convergence under admitted load",
            "alerts and audited dead-letter replay",
            "paired restore and HA qualification",
        ],
    }
    if "service_role_graph_sha256" in evidence:
        receipt["service_role_graph_sha256"] = evidence["service_role_graph_sha256"]
    files = {**parent_files, MANIFEST: manifest, EVIDENCE: _canonical_json(receipt)}
    _prepare_output_directory(source_dir, output_dir)
    created = []
    try:
        for name, content in files.items():
            _write_exclusive(output_dir / name, content)
            created.append(output_dir / name)
    except ReleaseRenderError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {
        "status": "pass",
        "mode": "stage",
        "admission_state": "pending",
        "evidence_file": EVIDENCE,
        "identity_manifest_sha256": _digest(manifest),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-spec", type=Path, required=True)
    parser.add_argument("--identity-spec", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, default=_default_source_dir())
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = render_identity_release(
            args.release_spec, args.identity_spec, args.source_dir, args.output_dir
        )
    except (ReleaseRenderError, OSError):
        print("identity release render rejected")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
