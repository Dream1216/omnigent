"""Secret-free Host projection for the Platform-managed DeepSeek Provider."""

from __future__ import annotations

import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from saas.control_plane.model_provider import PlatformManagedModelRuntimeConfiguration

PLATFORM_MODEL_PROVIDER_NAME = "platform-deepseek"
PLATFORM_MODEL_CREDENTIAL_ENV = "OMNIGENT_PLATFORM_DEEPSEEK_KEY"
PLATFORM_MODEL_CREDENTIAL_REFERENCE = f"${PLATFORM_MODEL_CREDENTIAL_ENV}"
PLATFORM_MODEL_VAULT_PROVIDER = "filesystem"
PLATFORM_MODEL_VAULT_REF = "platform-deepseek"
_MAX_PROJECTION_BYTES = 64 * 1024
PLATFORM_MODEL_GATEWAY_BASE_URL = "http://omnigent-platform-model-gateway:8090/v1"


@dataclass(frozen=True, slots=True)
class PlatformManagedModelSecretBinding:
    """Metadata-only input for ``IsolationControlPlane.bind_secret``."""

    name: str
    vault_provider: str
    vault_ref: str
    version_ref: str
    credential_scheme: str
    host: str
    inject_env: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlatformManagedModelRuntimeProjection:
    """Version-bound Host config plus its Server-owned Secret binding metadata."""

    provider_config: dict[str, object]
    secret_binding: PlatformManagedModelSecretBinding
    configuration_version: int
    projection_sha256: str


@dataclass(frozen=True, slots=True)
class PlatformManagedModelRuntimeFiles:
    """Secret-free public authority plus the private versioned key path."""

    config_home: Path
    config_file: Path
    projection_file: Path
    projection_sha256_file: Path
    secret_file: Path = field(repr=False)
    configuration_version: int
    projection_sha256: str


def project_platform_managed_model(
    configuration: PlatformManagedModelRuntimeConfiguration,
) -> PlatformManagedModelRuntimeProjection:
    """Compile a verified Provider without copying its API key into config."""

    if (
        configuration.provider_id != "deepseek"
        or configuration.api_type != "openai_chat_completions"
        or configuration.configuration_version <= 0
        or not configuration.allowed_models
        or configuration.default_model not in configuration.allowed_models
    ):
        raise ValueError("managed model runtime configuration is invalid")
    parsed = urlsplit(configuration.base_url)
    if (
        configuration.base_url.rstrip("/") != "https://api.deepseek.com"
        or parsed.scheme != "https"
        or parsed.hostname != "api.deepseek.com"
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("managed model runtime endpoint is not admitted")

    # Pi accepts an environment-variable *name* in models.json. The matching
    # Credential Proxy binding injects a per-launch synthetic value under this
    # name and replaces it with the real Provider key only for api.deepseek.com.
    models = {
        "default": configuration.default_model,
        **{
            f"allowed-{index + 1}": model
            for index, model in enumerate(configuration.allowed_models)
        },
    }
    provider: dict[str, object] = {
        "providers": {
            PLATFORM_MODEL_PROVIDER_NAME: {
                "kind": "gateway",
                "default": "pi",
                "openai": {
                    "base_url": "https://api.deepseek.com",
                    "api_key": PLATFORM_MODEL_CREDENTIAL_REFERENCE,
                    "wire_api": "chat",
                    "models": models,
                },
            }
        }
    }
    binding = PlatformManagedModelSecretBinding(
        name=f"platform-model-provider-v{configuration.configuration_version}",
        vault_provider=PLATFORM_MODEL_VAULT_PROVIDER,
        vault_ref=PLATFORM_MODEL_VAULT_REF,
        version_ref=f"v{configuration.configuration_version}",
        credential_scheme="bearer",
        host="api.deepseek.com",
        inject_env=(PLATFORM_MODEL_CREDENTIAL_ENV,),
    )
    payload = _projection_payload(
        provider_config=provider,
        secret_binding=binding,
        configuration_version=configuration.configuration_version,
    )
    return PlatformManagedModelRuntimeProjection(
        provider_config=provider,
        secret_binding=binding,
        configuration_version=configuration.configuration_version,
        projection_sha256=_payload_sha256(payload),
    )


def render_platform_managed_model_projection(
    projection: PlatformManagedModelRuntimeProjection,
) -> str:
    """Render canonical, secret-free Runtime input for an immutable deployment."""

    payload = _projection_payload(
        provider_config=projection.provider_config,
        secret_binding=projection.secret_binding,
        configuration_version=projection.configuration_version,
    )
    digest = _payload_sha256(payload)
    if not hmac.compare_digest(digest, projection.projection_sha256):
        raise ValueError("managed model projection digest is invalid")
    return (
        json.dumps(
            {**payload, "projection_sha256": digest},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    )


def render_platform_managed_model_config(
    projection: PlatformManagedModelRuntimeProjection,
) -> str:
    """Render the canonical JSON-as-YAML config consumed by official Omnigent."""

    # Reuse the full projection validator so a malformed nested Provider can
    # never be written as an apparently valid config.yaml.
    render_platform_managed_model_projection(projection)
    return (
        json.dumps(
            projection.provider_config,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    )


def render_platform_model_gateway_config(
    *,
    allowed_models: tuple[str, ...],
    default_model: str,
) -> str:
    """Render the fixed in-cluster gateway config consumed by the official Host.

    This deployment projection contains only the environment-variable name for
    a per-session synthetic bearer. The real Provider credential is never
    materialized in the Host or Runner pod.
    """

    models = tuple(dict.fromkeys(allowed_models))
    if (
        not models
        or default_model not in models
        or any(not model or len(model) > 128 for model in models)
    ):
        raise ValueError("Platform model gateway catalog is invalid")
    provider_config = {
        "providers": {
            PLATFORM_MODEL_PROVIDER_NAME: {
                "kind": "gateway",
                "default": "pi",
                "openai": {
                    "base_url": PLATFORM_MODEL_GATEWAY_BASE_URL,
                    "api_key": PLATFORM_MODEL_CREDENTIAL_REFERENCE,
                    "wire_api": "chat",
                    "models": {
                        "default": default_model,
                        **{f"allowed-{index + 1}": model for index, model in enumerate(models)},
                    },
                },
            }
        }
    }
    return (
        json.dumps(provider_config, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )


def load_platform_managed_model_projection(
    path: Path,
    *,
    expected_sha256: str,
) -> PlatformManagedModelRuntimeProjection:
    """Load one digest-pinned, secret-free projection from a read-only mount."""

    if (
        not path.is_absolute()
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError("managed model projection authority is invalid")
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError:
        raise ValueError("managed model projection is unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 0 < len(raw) <= _MAX_PROJECTION_BYTES
        or len(raw) != metadata.st_size
        or not hmac.compare_digest(sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ValueError("managed model projection authority is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("managed model projection is invalid") from None
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "configuration_version",
        "provider_config",
        "secret_binding",
        "projection_sha256",
    }:
        raise ValueError("managed model projection is invalid")
    binding_document = document["secret_binding"]
    if not isinstance(binding_document, dict) or set(binding_document) != {
        "name",
        "vault_provider",
        "vault_ref",
        "version_ref",
        "credential_scheme",
        "host",
        "inject_env",
    }:
        raise ValueError("managed model projection is invalid")
    inject_env = binding_document["inject_env"]
    if (
        document["schema_version"] != 1
        or isinstance(document["configuration_version"], bool)
        or not isinstance(document["configuration_version"], int)
        or not isinstance(document["provider_config"], dict)
        or not isinstance(document["projection_sha256"], str)
        or not all(
            isinstance(binding_document[name], str)
            for name in set(binding_document) - {"inject_env"}
        )
        or not isinstance(inject_env, list)
        or not all(isinstance(value, str) for value in inject_env)
    ):
        raise ValueError("managed model projection is invalid")
    binding = PlatformManagedModelSecretBinding(
        name=binding_document["name"],
        vault_provider=binding_document["vault_provider"],
        vault_ref=binding_document["vault_ref"],
        version_ref=binding_document["version_ref"],
        credential_scheme=binding_document["credential_scheme"],
        host=binding_document["host"],
        inject_env=tuple(inject_env),
    )
    projection = PlatformManagedModelRuntimeProjection(
        provider_config=document["provider_config"],
        secret_binding=binding,
        configuration_version=document["configuration_version"],
        projection_sha256=document["projection_sha256"],
    )
    # Re-rendering validates the complete nested Provider and binding contract,
    # its content digest, and the canonical byte representation in one place.
    rendered = render_platform_managed_model_projection(projection).encode()
    if not hmac.compare_digest(rendered, raw):
        raise ValueError("managed model projection is not canonical")
    return projection


def _projection_payload(
    *,
    provider_config: dict[str, object],
    secret_binding: PlatformManagedModelSecretBinding,
    configuration_version: int,
) -> dict[str, object]:
    if configuration_version <= 0:
        raise ValueError("managed model projection version is invalid")
    expected_binding = PlatformManagedModelSecretBinding(
        name=f"platform-model-provider-v{configuration_version}",
        vault_provider=PLATFORM_MODEL_VAULT_PROVIDER,
        vault_ref=PLATFORM_MODEL_VAULT_REF,
        version_ref=f"v{configuration_version}",
        credential_scheme="bearer",
        host="api.deepseek.com",
        inject_env=(PLATFORM_MODEL_CREDENTIAL_ENV,),
    )
    if secret_binding != expected_binding:
        raise ValueError("managed model projection binding is invalid")
    providers = provider_config.get("providers")
    provider = providers.get(PLATFORM_MODEL_PROVIDER_NAME) if isinstance(providers, dict) else None
    openai = provider.get("openai") if isinstance(provider, dict) else None
    models = openai.get("models") if isinstance(openai, dict) else None
    if (
        set(provider_config) != {"providers"}
        or not isinstance(providers, dict)
        or set(providers) != {PLATFORM_MODEL_PROVIDER_NAME}
        or not isinstance(provider, dict)
        or set(provider) != {"kind", "default", "openai"}
        or provider.get("kind") != "gateway"
        or provider.get("default") != "pi"
        or not isinstance(openai, dict)
        or set(openai) != {"base_url", "api_key", "wire_api", "models"}
        or openai.get("base_url") != "https://api.deepseek.com"
        or openai.get("api_key") != PLATFORM_MODEL_CREDENTIAL_REFERENCE
        or openai.get("wire_api") != "chat"
        or not isinstance(models, dict)
        or not models
        or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in models.items()
        )
        or "default" not in models
    ):
        raise ValueError("managed model projection Provider config is invalid")
    return {
        "schema_version": 1,
        "configuration_version": configuration_version,
        "provider_config": provider_config,
        "secret_binding": {
            "name": secret_binding.name,
            "vault_provider": secret_binding.vault_provider,
            "vault_ref": secret_binding.vault_ref,
            "version_ref": secret_binding.version_ref,
            "credential_scheme": secret_binding.credential_scheme,
            "host": secret_binding.host,
            "inject_env": list(secret_binding.inject_env),
        },
    }


def _payload_sha256(payload: dict[str, object]) -> str:
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()


def activate_platform_managed_model_secret(
    configuration: PlatformManagedModelRuntimeConfiguration,
    *,
    secret_root: Path,
) -> Path:
    """Atomically stage one versioned key below an owner-only Runtime tmpfs.

    The returned path matches the projection's ``vault_ref/version_ref`` and
    is consumed only by the trusted Runner parent. Existing equal content is
    idempotent; a same-version mismatch fails closed instead of overwriting an
    in-use key.
    """

    projection = project_platform_managed_model(configuration)
    root = _private_directory(secret_root, create=True)
    provider_root = _private_directory(root / projection.secret_binding.vault_ref, create=True)
    target = provider_root / projection.secret_binding.version_ref
    encoded = configuration.api_key.encode()
    if not 16 <= len(encoded) <= 65_536 or b"\x00" in encoded:
        raise ValueError("managed model runtime secret is invalid")
    if target.exists():
        existing = _read_private_file(target)
        if not hmac.compare_digest(existing, encoded):
            raise RuntimeError("managed model runtime secret version conflicts")
        return target

    temporary = provider_root / f".{target.name}.{uuid4().hex}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, target, follow_symlinks=False)
            _fsync_directory(provider_root)
        except FileExistsError:
            if not hmac.compare_digest(_read_private_file(target), encoded):
                raise RuntimeError("managed model runtime secret version conflicts") from None
    except BaseException:
        temporary.unlink(missing_ok=True)
        _fsync_directory(provider_root)
        raise
    temporary.unlink(missing_ok=True)
    _fsync_directory(provider_root)
    return target


def activate_platform_managed_model_runtime(
    configuration: PlatformManagedModelRuntimeConfiguration,
    *,
    secret_root: Path,
    config_home: Path,
) -> PlatformManagedModelRuntimeFiles:
    """Publish one coherent config/projection/digest set and its private key.

    Public files are replaced one at a time with the digest last. Readers
    therefore either observe a complete generation or reject a transient
    mismatch. The Provider key is written only below ``secret_root``.
    """

    projection = project_platform_managed_model(configuration)
    secret_file = activate_platform_managed_model_secret(configuration, secret_root=secret_root)
    public_root = _public_runtime_directory(config_home, create=True)
    config_file = public_root / "config.yaml"
    projection_file = public_root / "platform-model-projection.json"
    digest_file = public_root / "platform-model-projection.sha256"
    config_bytes = render_platform_managed_model_config(projection).encode("ascii")
    projection_bytes = render_platform_managed_model_projection(projection).encode("ascii")
    digest = sha256(projection_bytes).hexdigest()
    _replace_public_file(config_file, config_bytes)
    _replace_public_file(projection_file, projection_bytes)
    _replace_public_file(digest_file, f"{digest}\n".encode("ascii"))
    return PlatformManagedModelRuntimeFiles(
        config_home=public_root,
        config_file=config_file,
        projection_file=projection_file,
        projection_sha256_file=digest_file,
        secret_file=secret_file,
        configuration_version=configuration.configuration_version,
        projection_sha256=digest,
    )


def validate_platform_managed_model_config_home(
    projection: PlatformManagedModelRuntimeProjection,
    config_home: Path,
) -> Path:
    """Verify that ``config.yaml`` is the exact secret-free projection config."""

    root = _public_runtime_directory(config_home, create=False)
    path = root / "config.yaml"
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError:
        raise ValueError("managed model config is unavailable") from None
    expected = render_platform_managed_model_config(projection).encode("ascii")
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or len(raw) != metadata.st_size
        or not hmac.compare_digest(raw, expected)
    ):
        raise ValueError("managed model config authority is invalid")
    return root


def _private_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute():
        raise ValueError("managed model secret root must be absolute")
    for component in (path, *path.parents):
        if component.exists() and component.is_symlink():
            raise ValueError("managed model secret root contains a symbolic link")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.geteuid()
    ):
        raise ValueError("managed model secret root is not private")
    return resolved


def _public_runtime_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute():
        raise ValueError("managed model config home must be absolute")
    for component in (path, *path.parents):
        if component.exists() and component.is_symlink():
            raise ValueError("managed model config home contains a symbolic link")
    if create:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        raise ValueError("managed model config home is unsafe")
    return resolved


def _replace_public_file(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o444,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        os.chmod(path, 0o444, follow_symlinks=False)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _read_private_file(path: Path) -> bytes:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or not 16 <= metadata.st_size <= 65_536
    ):
        raise ValueError("managed model runtime secret file is unsafe")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("managed model runtime secret identity changed")
        value = os.read(descriptor, 65_537)
    finally:
        os.close(descriptor)
    if len(value) != metadata.st_size:
        raise ValueError("managed model runtime secret changed while reading")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "PLATFORM_MODEL_CREDENTIAL_ENV",
    "PLATFORM_MODEL_CREDENTIAL_REFERENCE",
    "PLATFORM_MODEL_GATEWAY_BASE_URL",
    "PLATFORM_MODEL_PROVIDER_NAME",
    "PLATFORM_MODEL_VAULT_PROVIDER",
    "PLATFORM_MODEL_VAULT_REF",
    "PlatformManagedModelRuntimeFiles",
    "PlatformManagedModelRuntimeProjection",
    "PlatformManagedModelSecretBinding",
    "activate_platform_managed_model_runtime",
    "activate_platform_managed_model_secret",
    "load_platform_managed_model_projection",
    "project_platform_managed_model",
    "render_platform_managed_model_config",
    "render_platform_managed_model_projection",
    "render_platform_model_gateway_config",
    "validate_platform_managed_model_config_home",
]
