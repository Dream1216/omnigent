"""Fail-closed Runtime materializer for the governed Platform model Provider.

The init process reads only the ``saas_secret_broker`` PostgreSQL projection,
decrypts through the configured OpenBao Transit cipher, writes the Provider key
to the Runner tmpfs, and publishes only secret-free official configuration.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from omnigent.stores.credential_store.secret_cipher import SecretCipher
from saas.control_plane.model_provider import ModelProviderConfigurationReader
from saas.production.onboarding import build_production_secret_cipher
from saas.production.postgresql_migration import (
    PostgreSqlMigrationError,
    _inspect_service_login,
)
from saas.production.server_config import (
    ProductionServerConfigError,
    load_production_database_url_file,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)
from saas.runner_adapter.platform_models import (
    PLATFORM_MODEL_CREDENTIAL_ENV,
    PlatformManagedModelRuntimeFiles,
    activate_platform_managed_model_runtime,
)

_PROJECTION_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_FILE"
_PROJECTION_DIGEST_FILE_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256_FILE"
_PROJECTION_DIGEST_ENV = "OMNIGENT_SAAS_PLATFORM_MODEL_PROJECTION_SHA256"
_CONFIG_HOME_ENV = "OMNIGENT_CONFIG_HOME"
_SECRET_ROOT_ENV = "OMNIGENT_SAAS_RUNNER_SECRET_PROVIDER_ROOT"


class PlatformModelRuntimeError(RuntimeError):
    """Stable, secret-free rejection for model Runtime activation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Platform model Runtime rejected: {code}")


def reconcile_platform_model_runtime(
    *,
    environ: Mapping[str, str],
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url, pool_pre_ping=True
    ),
    cipher_loader: Callable[[Mapping[str, str]], SecretCipher | None] = (
        build_production_secret_cipher
    ),
    login_inspector: Callable[..., object] = _inspect_service_login,
) -> dict[str, object]:
    """Materialize one verified database generation into the Runtime tmpfs."""

    config_home = _absolute_path(environ, _CONFIG_HOME_ENV)
    secret_root = _absolute_path(environ, _SECRET_ROOT_ENV)
    projection_file = _absolute_path(environ, _PROJECTION_FILE_ENV)
    digest_file = _absolute_path(environ, _PROJECTION_DIGEST_FILE_ENV)
    if (
        projection_file != config_home / "platform-model-projection.json"
        or digest_file != config_home / "platform-model-projection.sha256"
        or environ.get(_PROJECTION_DIGEST_ENV)
        or environ.get(PLATFORM_MODEL_CREDENTIAL_ENV)
    ):
        raise PlatformModelRuntimeError("runtime_authority_invalid")
    try:
        database_url, parsed, _path = load_production_database_url_file(
            environ,
            "secret_broker",
        )
        bindings = load_production_service_role_bindings(environ)
        binding = bindings.by_service["secret_broker"]
    except (
        KeyError,
        ProductionServerConfigError,
        ProductionServiceRoleBindingsError,
    ):
        raise PlatformModelRuntimeError("database_authority_invalid") from None
    if parsed.username != binding.login or binding.base_role != "saas_secret_broker":
        raise PlatformModelRuntimeError("database_authority_invalid")

    engine: Engine | None = None
    try:
        engine = engine_factory(database_url)
        try:
            login_inspector(
                engine,
                expected_login=binding.login,
                expected_role=binding.base_role,
            )
        except PostgreSqlMigrationError:
            raise PlatformModelRuntimeError("database_authority_invalid") from None
        cipher = cipher_loader(environ)
        if cipher is None:
            raise PlatformModelRuntimeError("secret_cipher_unavailable")
        sessions = sessionmaker(engine, expire_on_commit=False, class_=Session)
        configuration = ModelProviderConfigurationReader(
            sessions,
            secret_cipher=cipher,
        ).load()
        if configuration is None:
            raise PlatformModelRuntimeError("verified_configuration_unavailable")
        files = activate_platform_managed_model_runtime(
            configuration,
            secret_root=secret_root,
            config_home=config_home,
        )
        _require_expected_files(files, projection_file=projection_file, digest_file=digest_file)
        return {
            "schema_version": 1,
            "status": "pass",
            "production_authority": False,
            "provider": configuration.provider_id,
            "configuration_version": files.configuration_version,
            "projection_sha256": files.projection_sha256,
            "config_file": str(files.config_file),
            "projection_file": str(files.projection_file),
            "projection_sha256_file": str(files.projection_sha256_file),
            "secret_exported": False,
            "credential_proxy_required": True,
        }
    except PlatformModelRuntimeError:
        raise
    except Exception:  # noqa: BLE001 - redact database, Vault, and filesystem details.
        raise PlatformModelRuntimeError("runtime_materialization_failed") from None
    finally:
        if engine is not None:
            engine.dispose()


def _absolute_path(source: Mapping[str, str], name: str) -> Path:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise PlatformModelRuntimeError("runtime_authority_invalid")
    path = Path(value)
    if not path.is_absolute() or "\x00" in value:
        raise PlatformModelRuntimeError("runtime_authority_invalid")
    return path


def _require_expected_files(
    files: PlatformManagedModelRuntimeFiles,
    *,
    projection_file: Path,
    digest_file: Path,
) -> None:
    if files.projection_file != projection_file or files.projection_sha256_file != digest_file:
        raise PlatformModelRuntimeError("runtime_authority_invalid")


def main() -> int:
    try:
        result = reconcile_platform_model_runtime(environ=os.environ)
    except Exception:  # noqa: BLE001 - stdout must stay secret-free.
        print(json.dumps({"schema_version": 1, "status": "fail"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PlatformModelRuntimeError",
    "main",
    "reconcile_platform_model_runtime",
]
