"""Read actual managed object identities without treating existence as termination."""

from __future__ import annotations

import base64
import hmac
import json
from hashlib import sha256

from omnigent.host.identity import HOST_ID_ENV_VAR, HOST_TOKEN_ENV_VAR
from omnigent.onboarding.sandboxes.agent_sandbox import API_GROUP, API_VERSION, SANDBOX_PLURAL
from omnigent.onboarding.sandboxes.kubernetes import _token_secret_name
from omnigent.stores.host_store import hash_host_launch_token
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import (
    ManagedCreationIntent,
    ManagedPreparationBinding,
    ManagedResourceBinding,
)

_REQUEST_TIMEOUT_SECONDS = 10
CREATION_ANNOTATION = "saas.omnigent.ai/creation-nonce"
INPUT_TEMPLATE_ANNOTATION = "saas.omnigent.ai/input-template-sha256"
TERMINATION_FINALIZER = "saas.omnigent.ai/observe-termination"


def _creation_metadata(document, creation, *, template=False):
    annotations = document["metadata"]["annotations"]
    if annotations.get(CREATION_ANNOTATION) != creation.nonce or (
        template and annotations.get(INPUT_TEMPLATE_ANNOTATION) != creation.input_template_sha256
    ):
        raise _unavailable()


def _metadata(document, *, namespace, name, kind, allow_deleting=False):
    metadata = document["metadata"]
    labels = metadata["labels"]
    if (
        document["kind"] != kind
        or document["apiVersion"]
        != {"Job": "batch/v1", "Sandbox": API_GROUP + "/" + API_VERSION, "Secret": "v1"}[kind]
        or metadata["name"] != name
        or metadata["namespace"] != namespace
        or (not allow_deleting and metadata.get("deletionTimestamp") is not None)
        or labels.get("app.kubernetes.io/managed-by") != "omnigent"
        or labels.get("omnigent.ai/role") != "sandbox-host"
    ):
        raise _unavailable()
    return metadata["uid"]


def _template(workload, preparation):
    template = workload["spec"][
        "template" if preparation.provider == "kubernetes" else "podTemplate"
    ]
    spec = template["spec"]
    hosts = [item for item in spec["containers"] if item["name"] == "host"]
    if len(hosts) != 1 or spec.get("automountServiceAccountToken") is not False:
        raise _unavailable()
    host = hosts[0]
    env = {item["name"]: item for item in host["env"]}
    reference = env[HOST_TOKEN_ENV_VAR]["valueFrom"]["secretKeyRef"]
    if (
        len(env) != len(host["env"])
        or host.get("envFrom")
        or env[HOST_ID_ENV_VAR].get("value") != preparation.host_id
        or env[HOST_ID_ENV_VAR].get("valueFrom") is not None
        or env[HOST_TOKEN_ENV_VAR].get("value") not in (None, "")
        or reference["name"] != _token_secret_name(preparation.resource_name)
        or reference["key"] != HOST_TOKEN_ENV_VAR
        or reference.get("optional") is True
        or sha256(host["image"].encode()).hexdigest() != preparation.image_reference_sha256
    ):
        raise _unavailable()
    return template


def _secret_uid(secret, preparation, host_token_sha256, *, allow_deleting=False):
    uid = _metadata(
        secret,
        namespace=preparation.namespace,
        name=_token_secret_name(preparation.resource_name),
        kind="Secret",
        allow_deleting=allow_deleting,
    )
    if secret["type"] != "Opaque" or set(secret["data"]) != {HOST_TOKEN_ENV_VAR}:
        raise _unavailable()
    encoded = secret["data"][HOST_TOKEN_ENV_VAR]
    if not isinstance(encoded, str) or not 0 < len(encoded) <= 1024:
        raise _unavailable()
    digest = hash_host_launch_token(base64.b64decode(encoded, validate=True).decode())
    if not hmac.compare_digest(digest, host_token_sha256):
        raise _unavailable()
    return uid


def _template_sha256(template):
    raw = json.dumps(template, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 65536:
        raise _unavailable()
    return sha256(raw).hexdigest()


def read_managed_resources(
    launcher,
    preparation: ManagedPreparationBinding,
    *,
    host_token_sha256: str,
    creation: ManagedCreationIntent | None = None,
    validate_host_token=None,
) -> ManagedResourceBinding:
    """Read one exact workload and Secret; missing/foreign objects are unavailable, not stopped."""
    try:
        namespace, name = preparation.namespace, preparation.resource_name
        if preparation.provider == "kubernetes":
            raw = launcher._load_batch().read_namespaced_job(
                name, namespace, _request_timeout=_REQUEST_TIMEOUT_SECONDS
            )
            workload = launcher._api_client.sanitize_for_serialization(raw)
            kind = "Job"
        elif preparation.provider == "agent_sandbox":
            workload = launcher._load_custom().get_namespaced_custom_object(
                API_GROUP,
                API_VERSION,
                namespace,
                SANDBOX_PLURAL,
                name,
                _request_timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            kind = "Sandbox"
        else:
            raise _unavailable()
        uid = _metadata(workload, namespace=namespace, name=name, kind=kind)
        template = _template(workload, preparation)
        secret_name = _token_secret_name(name)
        secret = launcher._api_client.sanitize_for_serialization(
            launcher._load_core().read_namespaced_secret(
                secret_name, namespace, _request_timeout=_REQUEST_TIMEOUT_SECONDS
            )
        )
        secret_uid = _secret_uid(secret, preparation, host_token_sha256)
        if validate_host_token is not None and not validate_host_token(
            base64.b64decode(secret["data"][HOST_TOKEN_ENV_VAR], validate=True).decode()
        ):
            raise _unavailable()
        if creation is not None:
            if (
                not creation.workload_submitted
                or creation.secret_uid != secret_uid
                or creation.host_token_sha256 != host_token_sha256
            ):
                raise _unavailable()
            _creation_metadata(workload, creation)
            _creation_metadata(template, creation, template=True)
            _creation_metadata(secret, creation)
        return ManagedResourceBinding(
            uid, secret_uid, _template_sha256(template), host_token_sha256
        )
    except Exception:  # noqa: BLE001 - SDK bodies and token contents are private.
        raise _unavailable() from None
