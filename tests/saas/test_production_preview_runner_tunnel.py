from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from omnigent.host.frames import CAP_MCP_REGISTRY
from omnigent.runner.identity import token_bound_runner_id
from omnigent.runner.transports.ws_tunnel.frames import (
    HelloFrame,
    PingFrame,
    PongFrame,
    decode_frame,
    encode_frame,
)
from saas.preview_relay_transport import PreviewRelayEndpoint, PreviewRelayEndpointPolicy
from saas.production import preview_runner_tunnel as tunnel_module
from saas.production.preview_runner_tunnel import (
    ProductionPreviewRunnerTunnel,
    ProductionPreviewRunnerTunnelConfig,
    ProductionPreviewRunnerTunnelError,
    load_production_preview_runner_tunnel_config,
)
from saas.production.runner_control import RunnerPreviewTunnelRegistration


def _ca(root: Path) -> Path:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Preview Runner CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = root / "preview-ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def _config(tmp_path: Path) -> ProductionPreviewRunnerTunnelConfig:
    socket_root = tmp_path / "sockets"
    log_root = tmp_path / "logs"
    socket_root.mkdir(mode=0o700)
    log_root.mkdir(mode=0o700)
    return ProductionPreviewRunnerTunnelConfig(
        source_revision="a" * 40,
        product_revision="a" * 40,
        runner_id=uuid4(),
        connection_generation=7,
        ca_certificate_path=_ca(tmp_path),
        endpoint_policy=PreviewRelayEndpointPolicy.from_strings(
            allowed_dns_suffixes=("preview.svc.cluster.local",),
            allowed_cidrs=("10.42.0.0/16",),
            allowed_ports=(9442,),
        ),
        socket_root=socket_root,
        log_root=log_root,
        open_timeout_seconds=5,
        reconnect_min_seconds=0.1,
        reconnect_max_seconds=1,
    )


def _registration(
    config: ProductionPreviewRunnerTunnelConfig,
    *,
    token: str = "r" * 48,
    host: str = "owner.preview.svc.cluster.local",
) -> RunnerPreviewTunnelRegistration:
    return RunnerPreviewTunnelRegistration(
        registration_id=uuid4(),
        runner_id=config.runner_id,
        connection_generation=config.connection_generation,
        official_runner_id=token_bound_runner_id(token),
        endpoint_host=host,
        endpoint_port=9442,
        server_name="owner.preview.svc.cluster.local",
        audience="owner.preview.svc.cluster.local",
        registration_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
    )


class _RegistrationClient:
    def __init__(self, registration: RunnerPreviewTunnelRegistration) -> None:
        self.registration = registration
        self.calls = 0

    async def mint_preview_tunnel(self) -> RunnerPreviewTunnelRegistration:
        self.calls += 1
        return self.registration


def test_runner_rejects_private_function_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(tunnel_module, "_send_hello", tunnel_module._cancel_dispatch_tasks)
    with pytest.raises(ProductionPreviewRunnerTunnelError, match="contract changed"):
        ProductionPreviewRunnerTunnel(config, _RegistrationClient(_registration(config)))


@pytest.mark.asyncio
async def test_preview_only_handshake_excludes_managed_mcp_and_handles_ping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    registration = _registration(config)
    tunnel = ProductionPreviewRunnerTunnel(config, _RegistrationClient(registration))
    stop = asyncio.Event()
    sent = []
    connection = {}

    class Socket:
        async def send(self, data: str) -> None:
            frame = decode_frame(data)
            sent.append(frame)
            if isinstance(frame, PongFrame):
                stop.set()

        async def recv(self) -> str:
            return encode_frame(PingFrame(ts=123))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    def connect(uri, **kwargs):
        connection.update(uri=uri, **kwargs)
        return Socket()

    monkeypatch.setattr(tunnel_module.websockets, "connect", connect)
    try:
        await tunnel._serve_once(
            registration, PreviewRelayEndpoint("10.42.1.17", 9442, registration.server_name), stop
        )
        assert isinstance(sent[0], HelloFrame)
        assert CAP_MCP_REGISTRY not in sent[0].capabilities
        assert sent[0].runner_version == config.product_revision
        assert any(isinstance(frame, PongFrame) and frame.ts == 123 for frame in sent)
        assert connection["uri"].startswith("wss://10.42.1.17:9442/")
        assert connection["server_hostname"] == registration.server_name
        tunnel.assert_production_ready()
    finally:
        await tunnel.aclose()


def test_runner_tunnel_pins_server_selected_dns_to_cluster_cidr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    client = ProductionPreviewRunnerTunnel(config, _RegistrationClient(_registration(config)))
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.42.1.17", 9442),
            )
        ],
    )

    endpoint = client._endpoint(_registration(config))

    assert endpoint.connect_host == "10.42.1.17"
    assert endpoint.server_name == "owner.preview.svc.cluster.local"
    client.assert_production_ready()


@pytest.mark.parametrize(
    ("host", "address"),
    [
        ("metadata.preview.svc.cluster.local", "169.254.169.254"),
        ("loopback.preview.svc.cluster.local", "127.0.0.1"),
        ("private.preview.svc.cluster.local", "10.0.0.5"),
        ("owner.attacker.invalid", "10.42.1.17"),
    ],
)
def test_runner_tunnel_rejects_disallowed_or_rebound_endpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    address: str,
) -> None:
    config = _config(tmp_path)
    registration = _registration(config, host=host)
    client = ProductionPreviewRunnerTunnel(config, _RegistrationClient(registration))
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, 9442),
            )
        ],
    )

    with pytest.raises(ProductionPreviewRunnerTunnelError):
        client._endpoint(registration)


@pytest.mark.asyncio
async def test_runner_mints_a_new_one_use_registration_after_disconnect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    registration_client = _RegistrationClient(_registration(config))
    tunnel = ProductionPreviewRunnerTunnel(config, registration_client)
    stop = asyncio.Event()
    attempts = 0

    monkeypatch.setattr(
        tunnel,
        "_endpoint",
        lambda _registration: object(),
    )

    async def fail_then_stop(_registration, _endpoint, _stop) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            stop.set()
        raise OSError("connection unavailable")

    monkeypatch.setattr(tunnel, "_serve_once", fail_then_stop)

    await tunnel.run(stop)

    assert registration_client.calls == 2
    await tunnel.aclose()


def test_runner_loader_rejects_release_drift_and_non_private_roots(tmp_path: Path) -> None:
    ca_path = _ca(tmp_path)
    socket_root = tmp_path / "socket"
    log_root = tmp_path / "log"
    socket_root.mkdir(mode=0o700)
    log_root.mkdir(mode=0o700)
    source = {
        "OMNIGENT_SAAS_SOURCE_SHA": "a" * 40,
        "OMNIGENT_SAAS_PRODUCT_REVISION": "b" * 40,
        "OMNIGENT_SAAS_PREVIEW_RUNNER_CA_CERTIFICATE_FILE": str(ca_path),
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_DNS_SUFFIXES": ("preview.svc.cluster.local"),
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_CIDRS": "10.42.0.0/16",
        "OMNIGENT_SAAS_PREVIEW_RELAY_ALLOWED_PORTS": "9442",
        "OMNIGENT_SAAS_PREVIEW_RUNNER_SOCKET_ROOT": str(socket_root),
        "OMNIGENT_SAAS_PREVIEW_RUNNER_LOG_ROOT": str(log_root),
    }

    with pytest.raises(ProductionPreviewRunnerTunnelError):
        load_production_preview_runner_tunnel_config(
            runner_id=uuid4(), connection_generation=7, environ=source
        )

    source["OMNIGENT_SAAS_PRODUCT_REVISION"] = "a" * 40
    log_root.chmod(0o755)
    with pytest.raises(ProductionPreviewRunnerTunnelError):
        load_production_preview_runner_tunnel_config(
            runner_id=uuid4(), connection_generation=7, environ=source
        )
