"""Concrete production readiness for the managed Runner control plane."""

from __future__ import annotations

import os
import re
import socket
import ssl
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from saas.onboarding_composition import verify_onboarding_database_authority

_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_READINESS_REQUEST = b"OMNIGENT_RUNNER_CONTROL_READY_V1\n"
_READINESS_RESPONSE = b"READY\n"


class RunnerReadinessError(RuntimeError):
    """Runner control or its durable fleet has no production-ready endpoint."""


class RunnerReadinessConfig(Protocol):
    """Structural subset supplied by the production worker factory loader."""

    @property
    def product_revision(self) -> str: ...

    @property
    def official_schema_revision(self) -> str: ...

    @property
    def adapter_contract_version(self) -> str: ...

    @property
    def executor_database_url(self) -> str: ...


@dataclass(slots=True)
class PostgreSQLRunnerControlReadiness:
    """Require both a listening sidecar and one current compatible Runner."""

    engine: Engine
    product_revision: str
    official_schema_revision: str
    adapter_contract_version: str
    port: int
    connect_probe: Callable[[str, int, float], None]

    def assert_production_ready(self) -> None:
        try:
            self.connect_probe("127.0.0.1", self.port, 2.0)
        except OSError as exc:
            raise RunnerReadinessError("Runner control readiness is unavailable") from exc
        assert_postgresql_runner_fleet_ready(
            self.engine,
            product_revision=self.product_revision,
            official_schema_revision=self.official_schema_revision,
            adapter_contract_version=self.adapter_contract_version,
        )


@dataclass(frozen=True, slots=True)
class RemoteTlsRunnerControlReadiness:
    """Server-side readiness through TLS server auth and a content-blind probe."""

    connect_host: str
    port: int
    server_name: str
    ca_certificate_path: Path
    timeout_seconds: float = 2.0

    def assert_production_ready(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            context.load_verify_locations(
                cadata=_load_public_ca_certificate(self.ca_certificate_path)
            )
        except ssl.SSLError as exc:
            raise RunnerReadinessError("Runner control TLS readiness CA is invalid") from exc
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            with (
                socket.create_connection(
                    (self.connect_host, self.port), timeout=self.timeout_seconds
                ) as raw,
                context.wrap_socket(raw, server_hostname=self.server_name) as connection,
            ):
                connection.settimeout(self.timeout_seconds)
                connection.sendall(_READINESS_REQUEST)
                response = bytearray()
                while len(response) < len(_READINESS_RESPONSE):
                    chunk = connection.recv(len(_READINESS_RESPONSE) - len(response))
                    if not chunk:
                        break
                    response.extend(chunk)
        except (OSError, ssl.SSLError) as exc:
            raise RunnerReadinessError("Runner control TLS readiness is unavailable") from exc
        if bytes(response) != _READINESS_RESPONSE:
            raise RunnerReadinessError("Runner control TLS readiness response is invalid")


def _connect(host: str, port: int, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        pass


def assert_postgresql_runner_fleet_ready(
    engine: Engine,
    *,
    product_revision: str,
    official_schema_revision: str,
    adapter_contract_version: str,
) -> None:
    """Require one current compatible Runner without exposing fleet details."""

    if engine.dialect.name != "postgresql":
        raise RunnerReadinessError("Runner readiness requires PostgreSQL")
    try:
        with engine.connect() as connection:
            ready = connection.execute(
                sa.text(
                    "SELECT 1 FROM saas_runner_registrations runner "
                    "JOIN saas_runner_pools pool ON pool.id = runner.pool_id "
                    "WHERE runner.status = 'online' "
                    "AND runner.connection_generation > 0 "
                    "AND runner.last_heartbeat_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds' "
                    "AND runner.active_leases < runner.max_concurrency "
                    "AND runner.source_revision = :product_revision "
                    "AND runner.schema_revision = :schema_revision "
                    "AND runner.adapter_contract_version = :adapter_contract_version "
                    "AND pool.status = 'active' "
                    "AND pool.source_revision = :product_revision "
                    "AND pool.schema_revision = :schema_revision "
                    "AND pool.adapter_contract_version = :adapter_contract_version "
                    "LIMIT 1"
                ),
                {
                    "product_revision": product_revision,
                    "schema_revision": official_schema_revision,
                    "adapter_contract_version": adapter_contract_version,
                },
            ).first()
    except sa.exc.SQLAlchemyError as exc:
        raise RunnerReadinessError("Runner control readiness is unavailable") from exc
    if ready is None:
        raise RunnerReadinessError("No current compatible Runner is online")


def build_postgresql_runner_control_readiness(
    *, config: RunnerReadinessConfig
) -> PostgreSQLRunnerControlReadiness:
    """Build the deployable Runner readiness adapter from the executor DSN."""

    raw_port = os.environ.get("OMNIGENT_SAAS_RUNNER_CONTROL_BIND_PORT", "9444")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise RunnerReadinessError("Runner control readiness port is invalid") from exc
    if not 1 <= port <= 65_535:
        raise RunnerReadinessError("Runner control readiness port is invalid")
    engine = sa.create_engine(config.executor_database_url, pool_pre_ping=True)
    try:
        verify_onboarding_database_authority(engine, authority="execution")
        return PostgreSQLRunnerControlReadiness(
            engine=engine,
            product_revision=config.product_revision,
            official_schema_revision=config.official_schema_revision,
            adapter_contract_version=config.adapter_contract_version,
            port=port,
            connect_probe=_connect,
        )
    except Exception:
        engine.dispose()
        raise


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value != value.strip() or not value or "\x00" in value:
        raise RunnerReadinessError(f"{name} is invalid")
    return value


def _public_ca_path(name: str) -> Path:
    path = Path(_required_environment(name))
    if not path.is_absolute():
        raise RunnerReadinessError(f"{name} is invalid")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerReadinessError(f"{name} is invalid") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise RunnerReadinessError(f"{name} is invalid")
    return path


def _load_public_ca_certificate(path: Path) -> str:
    """Read one stable public CA from a single no-follow descriptor."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise RunnerReadinessError("Runner readiness public CA is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= 1_048_576
        ):
            raise RunnerReadinessError("Runner readiness public CA is invalid")
        chunks: list[bytes] = []
        remaining = 1_048_577
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(payload) != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise RunnerReadinessError("Runner readiness public CA changed while reading")
        try:
            return payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RunnerReadinessError("Runner readiness public CA is invalid") from exc
    finally:
        os.close(descriptor)


def build_remote_tls_runner_control_readiness(
    *, config: object
) -> RemoteTlsRunnerControlReadiness:
    """Build the Server adapter without any database DSN or client credential."""

    del config
    host = _required_environment("OMNIGENT_SAAS_RUNNER_READINESS_HOST").lower()
    server_name = _required_environment("OMNIGENT_SAAS_RUNNER_READINESS_SERVER_NAME").lower()
    if (
        _INTERNAL_HOST.fullmatch(host) is None
        or _INTERNAL_HOST.fullmatch(server_name) is None
        or host != server_name
        or not host.endswith((".svc", ".svc.cluster.local"))
    ):
        raise RunnerReadinessError("Runner readiness endpoint is invalid")
    try:
        port = int(_required_environment("OMNIGENT_SAAS_RUNNER_READINESS_PORT"))
    except ValueError as exc:
        raise RunnerReadinessError("Runner readiness endpoint is invalid") from exc
    if not 1 <= port <= 65_535:
        raise RunnerReadinessError("Runner readiness endpoint is invalid")
    return RemoteTlsRunnerControlReadiness(
        connect_host=host,
        port=port,
        server_name=server_name,
        ca_certificate_path=_public_ca_path("OMNIGENT_SAAS_RUNNER_READINESS_CA_CERTIFICATE_FILE"),
    )


__all__ = [
    "PostgreSQLRunnerControlReadiness",
    "RemoteTlsRunnerControlReadiness",
    "RunnerReadinessError",
    "assert_postgresql_runner_fleet_ready",
    "build_postgresql_runner_control_readiness",
    "build_remote_tls_runner_control_readiness",
]
