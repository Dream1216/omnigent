"""Explicit purpose-bound SLO process composition; no ambient S3 credentials."""

from __future__ import annotations

import atexit
import json
import os
import ssl
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from saas.observability import SloMetrics, SloRuntime
from saas.production.slo_witness import (
    RunEventWitness,
    S3WitnessStore,
    WitnessDeadlineExceeded,
    WitnessUnavailable,
)

_RUNTIME: SloRuntime | None = None
_LOCK = threading.RLock()


def _private(path: str, maximum: int) -> bytes:
    location = Path(path)
    if not location.is_absolute():
        raise WitnessUnavailable("SLO input paths must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(location, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > maximum
        ):
            raise WitnessUnavailable("SLO input must be a bounded owner-only regular file")
        result = os.read(descriptor, maximum + 1)
        if len(result) > maximum:
            raise WitnessUnavailable("SLO input exceeded its bound")
        return result
    finally:
        os.close(descriptor)


def _validated_ca(path: object) -> str:
    if not isinstance(path, str) or not path or not Path(path).is_absolute():
        raise WitnessUnavailable("SLO TLS trust requires an explicit absolute CA bundle")
    pem = _private(path, 1024 * 1024)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=pem.decode("ascii"))
        if context.cert_store_stats()["x509_ca"] < 1:
            raise ValueError("no CA certificate")
    except (UnicodeError, ValueError, ssl.SSLError):
        raise WitnessUnavailable("SLO CA bundle does not contain valid trust anchors") from None
    return path


def configured_runtime() -> SloRuntime | None:
    """Called by actual source service constructors, after original lineage checks.

    An absent configuration emits no fictitious observations and cannot qualify the
    planned SLO dashboards. A supplied invalid dependency fails process composition.
    """
    global _RUNTIME
    name = os.environ.get("OMNIGENT_SAAS_SLO_CONFIG_FILE")
    if not name:
        return None
    with _LOCK:
        if _RUNTIME is not None:
            return _RUNTIME
        client = None
        try:
            import boto3
            from botocore.config import Config

            from omnigent import _build_info
            from saas.observability import activate_runtime

            value = json.loads(_private(name, 65536))
            if set(value) != {
                "schema_version",
                "purpose",
                "product_revision",
                "service",
                "metrics_port",
                "endpoint",
                "bucket",
                "ca_file",
                "credentials_file",
                "hmac_key_file",
                "key_version",
            }:
                raise WitnessUnavailable("SLO configuration fields are invalid")
            if (
                value["schema_version"] != 1
                or value["purpose"] != "saas-slo-observation"
                or value["product_revision"] != _build_info.COMMIT_SHA
                or value["service"]
                not in {"server", "scheduler", "runner-control", "outbox", "witness-recovery"}
                or type(value["metrics_port"]) is not int
                or not 1024 <= value["metrics_port"] <= 65535
            ):
                raise WitnessUnavailable("SLO process/product binding is invalid")
            endpoint = urlsplit(value["endpoint"])
            if (
                endpoint.scheme != "https"
                or not endpoint.hostname
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.path not in {"", "/"}
                or endpoint.query
                or endpoint.fragment
            ):
                raise WitnessUnavailable("SLO endpoint requires a fixed TLS authority")
            ca_file = _validated_ca(value["ca_file"])
            credentials = json.loads(_private(value["credentials_file"], 16384))
            if set(credentials) not in (
                {"access_key", "secret_key"},
                {"access_key", "secret_key", "session_token"},
            ) or any(not isinstance(v, str) or not v for v in credentials.values()):
                raise WitnessUnavailable("SLO credentials are not an explicit profile")
            client = boto3.client(
                "s3",
                aws_access_key_id=credentials["access_key"],
                aws_secret_access_key=credentials["secret_key"],
                aws_session_token=credentials.get("session_token"),
                endpoint_url=value["endpoint"],
                verify=ca_file,
                region_name="us-east-1",
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=2,
                    read_timeout=3,
                    retries={"total_max_attempts": 1},
                    proxies={},
                    s3={"addressing_style": "path"},
                ),
            )
            store = S3WitnessStore(client, bucket=value["bucket"], prefix="saas-slo-witness")
            store.preflight()
            runtime = SloRuntime(
                SloMetrics(),
                RunEventWitness(
                    store,
                    product_revision=value["product_revision"],
                    key_version=value["key_version"],
                    hmac_key=_private(value["hmac_key_file"], 64),
                ),
            )
            runtime.witness.bind_epoch()
            product, service, key_version = (
                value["product_revision"],
                value["service"],
                value["key_version"],
            )

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    if self.path != "/metrics":
                        self.send_error(404)
                        return
                    payload = (
                        f'saas_slo_build_info{{product_revision="{product}",service="{service}",'
                        f'witness_key_version="{key_version}"}} 1\n'
                    ).encode() + runtime.metrics.render()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, format: str, *_args: object) -> None:
                    pass

            # Deployment must apply its existing metrics-only NetworkPolicy; no
            # product router or credential-bearing public endpoint is introduced.
            server = ThreadingHTTPServer(("0.0.0.0", value["metrics_port"]), Handler)
            server.daemon_threads = True
            thread = threading.Thread(
                target=server.serve_forever, daemon=True, name="saas-slo-metrics"
            )
            thread.start()

            def close() -> None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                client.close()

            atexit.register(close)
            activate_runtime(runtime)
            _RUNTIME = runtime
            return runtime
        except Exception:  # noqa: BLE001 -- never expose profiles/SDK signed requests
            if client is not None:
                client.close()
            raise WitnessUnavailable("configured SLO process dependency is unavailable") from None


def recover_run_prefix(factory, runtime, scope, context, *, segments=1, deadline_seconds=60):
    """Maintenance-only cooperative I/O budget; supervisor owns absolute timeout."""
    import time

    if not 1 <= segments <= 1000 or not 1 <= deadline_seconds <= 300:
        raise WitnessUnavailable("witness recovery budget is invalid")
    deadline = time.monotonic() + deadline_seconds
    observed = (0, 0)
    completed = 0
    exhausted = False
    for _ in range(segments):
        if time.monotonic() >= deadline:
            exhausted = True
            break
        try:
            with runtime.witness.budget(deadline):
                observed = runtime.require_runs(factory, {scope}, context, recovery=True)[scope]
        except WitnessDeadlineExceeded:
            exhausted = True
            break
        completed += 1
        if observed[0] == observed[1]:
            break
    return {
        "segments": completed,
        "witness_cursor": observed[0],
        "source_cursor": observed[1],
        "caught_up": not exhausted and completed > 0 and observed[0] == observed[1],
        "deadline_exhausted": exhausted,
    }


def recovery_main() -> int:
    """One explicitly scoped deployment/maintenance drive using original executor role."""
    import argparse
    from uuid import UUID

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker

    from saas.control_plane.rls import RlsContext
    from saas.onboarding_composition import verify_onboarding_database_authority

    parser = argparse.ArgumentParser(description="Bounded independent Run Event witness recovery")
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--executor-url-file", required=True)
    parser.add_argument("--segments", type=int, default=1)
    parser.add_argument("--deadline-seconds", type=int, default=60)
    arguments = parser.parse_args()
    runtime = configured_runtime()
    if runtime is None:
        raise WitnessUnavailable("explicit SLO witness configuration is required for recovery")
    scope = json.loads(_private(arguments.scope_file, 4096))
    if set(scope) != {"tenant_id", "space_id", "project_id", "run_id"}:
        raise WitnessUnavailable("recovery must name exactly one existing scoped Run")
    values = tuple(UUID(scope[k]) for k in ("tenant_id", "space_id", "project_id", "run_id"))
    engine = sa.create_engine(_private(arguments.executor_url_file, 16384).decode())
    try:
        verify_onboarding_database_authority(engine, authority="execution")
        factory = sessionmaker(engine, expire_on_commit=False)
        result = recover_run_prefix(
            factory,
            runtime,
            values,
            RlsContext(),
            segments=arguments.segments,
            deadline_seconds=arguments.deadline_seconds,
        )
        # Source identifiers remain only in the owner-only input, never in metrics/logs.
        print(json.dumps(result))
        return 0 if result["caught_up"] else 2
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(recovery_main())
