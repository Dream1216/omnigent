from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saas.control_plane import (
    PreviewRouteGrant,
    RunnerTunnelPlacement,
    RunnerTunnelPlacementError,
)
from saas.preview_gateway import PreviewTunnelRequest, PreviewTunnelResponse
from saas.preview_relay_transport import (
    MutualTlsPreviewRelayClient,
    MutualTlsPreviewRelayServer,
    PreviewRelayEndpoint,
    PreviewRelayTransportError,
)
from saas.preview_tunnel import (
    OfficialRunnerPreviewTunnel,
    PlacementRoutedPreviewTunnel,
    PreviewTunnelAdapterError,
)


@dataclass(frozen=True, slots=True)
class _CertificateFiles:
    ca: Path
    certificate: Path
    private_key: Path


class _ClosableBody(Protocol):
    async def aclose(self) -> None: ...


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _certificate_fixture(
    root: Path,
    *,
    server_gateway_id: str = "gateway-b",
    client_gateway_uris: tuple[str, ...] = ("gateway-a",),
) -> dict[str, _CertificateFiles]:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Preview Relay Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))

    def issue(
        name: str,
        *,
        san: x509.SubjectAlternativeName,
        usage: x509.ObjectIdentifier,
    ) -> _CertificateFiles:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san, critical=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        certificate_path = root / f"{name}.pem"
        private_key_path = root / f"{name}-key.pem"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        _write_private_key(private_key_path, key)
        return _CertificateFiles(ca_path, certificate_path, private_key_path)

    server = issue(
        "gateway-server",
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.UniformResourceIdentifier(
                    f"spiffe://omnigent/preview-gateway/{server_gateway_id}"
                ),
            ]
        ),
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    client_uris = [
        x509.UniformResourceIdentifier(f"spiffe://omnigent/preview-gateway/{gateway_id}")
        for gateway_id in client_gateway_uris
    ]
    client = issue(
        "gateway-client",
        san=x509.SubjectAlternativeName(client_uris),
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    return {"server": server, "client": client}


def _server_context(files: _CertificateFiles) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(files.ca))
    context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


def _client_context(
    files: _CertificateFiles,
    *,
    with_certificate: bool = True,
) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    if with_certificate:
        context.load_cert_chain(str(files.certificate), str(files.private_key))
    return context


class _CertificateAuthorizer:
    def __init__(self, allowed: tuple[str, ...]) -> None:
        self.allowed = set(allowed)
        self.calls: list[tuple[str, str, int]] = []

    def is_preview_gateway_certificate_authorized(
        self,
        *,
        gateway_instance_id: str,
        certificate_der: bytes,
        purpose: str,
    ) -> bool:
        self.calls.append((gateway_instance_id, purpose, len(certificate_der)))
        return gateway_instance_id in self.allowed


class _EndpointResolver:
    def __init__(self, endpoint: PreviewRelayEndpoint) -> None:
        self.endpoint = endpoint
        self.calls: list[RunnerTunnelPlacement] = []

    def resolve(self, placement: RunnerTunnelPlacement) -> PreviewRelayEndpoint:
        self.calls.append(placement)
        return self.endpoint


class _PlacementAuthority:
    def __init__(self, placement: RunnerTunnelPlacement) -> None:
        self.current = placement
        self.calls: list[tuple[RunnerTunnelPlacement, UUID, int, str]] = []

    def resolve_preview_route(
        self,
        *,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        del now
        if (
            self.current.runner_id != runner_id
            or self.current.runner_connection_generation != runner_connection_generation
            or preview_token_hash != "a" * 64
        ):
            raise RunnerTunnelPlacementError("runner_tunnel_route_unavailable", "stale")
        return self.current

    def require_route_owner(
        self,
        *,
        placement: RunnerTunnelPlacement,
        runner_id: UUID,
        runner_connection_generation: int,
        preview_token_hash: str,
        now: datetime | None = None,
    ) -> RunnerTunnelPlacement:
        del now
        self.calls.append((placement, runner_id, runner_connection_generation, preview_token_hash))
        supplied = (
            placement.placement_id,
            placement.runner_id,
            placement.runner_connection_generation,
            placement.routing_generation,
            placement.gateway_instance_id,
            placement.relay_subject,
        )
        current = (
            self.current.placement_id,
            self.current.runner_id,
            self.current.runner_connection_generation,
            self.current.routing_generation,
            self.current.gateway_instance_id,
            self.current.relay_subject,
        )
        if (
            supplied != current
            or runner_id != self.current.runner_id
            or runner_connection_generation != self.current.runner_connection_generation
            or preview_token_hash != "a" * 64
        ):
            raise RunnerTunnelPlacementError("runner_tunnel_route_owner_changed", "stale")
        return self.current


class _LocalTunnel:
    def __init__(self) -> None:
        self.calls: list[PreviewTunnelRequest] = []
        self.failure: PreviewTunnelAdapterError | None = None

    async def forward(self, request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure

        async def chunks() -> AsyncIterator[bytes]:
            yield b"chunk-one"
            await asyncio.sleep(0)
            yield b"chunk-two"

        return PreviewTunnelResponse(
            status_code=201,
            headers={"content-type": "text/plain", "set-cookie": "must-not-cross=1"},
            body=chunks(),
        )


def _placement() -> RunnerTunnelPlacement:
    placement_id = uuid4()
    return RunnerTunnelPlacement(
        placement_id=placement_id,
        runner_id=uuid4(),
        runner_connection_generation=4,
        routing_generation=7,
        gateway_instance_id="gateway-b",
        relay_subject=f"rtp_{placement_id.hex}",
        status="active",
        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
    )


def _route(placement: RunnerTunnelPlacement) -> PreviewRouteGrant:
    headers = {"accept": "text/plain", "user-agent": "relay-test"}
    return PreviewRouteGrant(
        preview_id=uuid4(),
        tenant_id=uuid4(),
        space_id=uuid4(),
        project_id=uuid4(),
        runner_id=placement.runner_id,
        runner_connection_generation=placement.runner_connection_generation,
        run_id=uuid4(),
        run_fence_token=9,
        worktree_id=uuid4(),
        worktree_lease_generation=6,
        opaque_preview_key="pvr_relay_contract",
        preview_token_hash="a" * 64,
        upstream_request_headers=headers,
        response_headers={"Content-Security-Policy": "sandbox"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
    )


def _request(placement: RunnerTunnelPlacement) -> PreviewTunnelRequest:
    route = _route(placement)
    return PreviewTunnelRequest(
        route=route,
        method="POST",
        path="/api/nested",
        query="mode=test",
        headers=route.upstream_request_headers,
        body=b'{"ok":true}',
    )


async def _relay_pair(
    tmp_path: Path,
    *,
    certificates: dict[str, _CertificateFiles] | None = None,
    server_authorized: tuple[str, ...] = ("gateway-a",),
    client_authorized: tuple[str, ...] = ("gateway-b",),
    server_response_head_timeout_seconds: float = 30.0,
) -> tuple[
    MutualTlsPreviewRelayServer,
    MutualTlsPreviewRelayClient,
    _PlacementAuthority,
    _LocalTunnel,
    _CertificateAuthorizer,
    _CertificateAuthorizer,
    _EndpointResolver,
    RunnerTunnelPlacement,
]:
    certificates = certificates or _certificate_fixture(tmp_path)
    placement = _placement()
    placements = _PlacementAuthority(placement)
    local = _LocalTunnel()
    router = PlacementRoutedPreviewTunnel(
        gateway_instance_id="gateway-b",
        placements=placements,
        local_tunnel=cast(OfficialRunnerPreviewTunnel, local),
        relay=None,
    )
    server_authorizer = _CertificateAuthorizer(server_authorized)
    server = MutualTlsPreviewRelayServer(
        gateway_instance_id="gateway-b",
        router=router,
        tls_context=_server_context(certificates["server"]),
        certificate_authorizer=server_authorizer,
        response_head_timeout_seconds=server_response_head_timeout_seconds,
    )
    await server.start()
    resolver = _EndpointResolver(PreviewRelayEndpoint("127.0.0.1", server.port, "localhost"))
    client_authorizer = _CertificateAuthorizer(client_authorized)
    client = MutualTlsPreviewRelayClient(
        gateway_instance_id="gateway-a",
        endpoint_resolver=resolver,
        tls_context=_client_context(certificates["client"]),
        certificate_authorizer=client_authorizer,
    )
    return (
        server,
        client,
        placements,
        local,
        server_authorizer,
        client_authorizer,
        resolver,
        placement,
    )


@pytest.mark.asyncio
async def test_mtls_preview_relay_streams_to_exact_placement_owner(tmp_path: Path) -> None:
    (
        server,
        client,
        placements,
        local,
        server_authorizer,
        client_authorizer,
        resolver,
        placement,
    ) = await _relay_pair(tmp_path)
    request = _request(placement)
    try:
        response = await client.forward(placement, request)
        assert not isinstance(response.body, bytes)
        chunks = [chunk async for chunk in response.body]
    finally:
        await server.aclose()

    assert response.status_code == 201
    assert response.headers == {"content-type": "text/plain"}
    assert chunks == [b"chunk-one", b"chunk-two"]
    assert len(local.calls) == 1
    relayed = local.calls[0]
    assert relayed.method == request.method
    assert relayed.path == request.path
    assert relayed.query == request.query
    assert relayed.body == request.body
    assert relayed.route.preview_id == request.route.preview_id
    assert relayed.route.tenant_id == request.route.tenant_id
    assert relayed.route.project_id == request.route.project_id
    assert relayed.route.run_id == request.route.run_id
    assert relayed.route.worktree_id == request.route.worktree_id
    assert placements.calls[0][0].relay_subject == placement.relay_subject
    assert server_authorizer.calls[0][:2] == ("gateway-a", "preview_relay_client")
    assert client_authorizer.calls[0][:2] == ("gateway-b", "preview_relay_server")
    assert resolver.calls == [placement]


@pytest.mark.asyncio
async def test_mtls_preview_relay_rechecks_stale_placement_without_replay(tmp_path: Path) -> None:
    server, client, placements, local, *_rest, placement = await _relay_pair(tmp_path)
    placements.current = replace(
        placement,
        placement_id=uuid4(),
        routing_generation=placement.routing_generation + 1,
        relay_subject=f"rtp_{uuid4().hex}",
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as stale:
            await client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert stale.value.code == "preview_runner_placement_stale"
    assert local.calls == []
    assert len(placements.calls) == 1


@pytest.mark.asyncio
async def test_mtls_preview_relay_never_replays_side_effecting_request(tmp_path: Path) -> None:
    server, client, _placements, local, *_rest, placement = await _relay_pair(tmp_path)
    local.failure = PreviewTunnelAdapterError(
        "preview_response_timeout", "response state is unknown"
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as failed:
            await client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert failed.value.code == "preview_response_timeout"
    assert len(local.calls) == 1


@pytest.mark.asyncio
async def test_mtls_preview_relay_bounds_owner_response_head_and_cancels(
    tmp_path: Path,
) -> None:
    server, client, _placements, local, *_rest, placement = await _relay_pair(
        tmp_path, server_response_head_timeout_seconds=0.05
    )
    cancelled = asyncio.Event()

    async def hanging_forward(request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        local.calls.append(request)
        try:
            await asyncio.Future()
        finally:
            cancelled.set()
        raise AssertionError("unreachable")

    local.forward = hanging_forward  # type: ignore[method-assign]
    try:
        with pytest.raises(PreviewRelayTransportError) as timeout:
            await client.forward(placement, _request(placement))
        await asyncio.wait_for(cancelled.wait(), timeout=1)
    finally:
        await server.aclose()
    assert timeout.value.code == "preview_relay_owner_timeout"
    assert len(local.calls) == 1


@pytest.mark.asyncio
async def test_mtls_preview_relay_binds_server_identity_to_placement(tmp_path: Path) -> None:
    certificates = _certificate_fixture(tmp_path, server_gateway_id="gateway-c")
    server, client, _placements, local, *_rest, placement = await _relay_pair(
        tmp_path,
        certificates=certificates,
        client_authorized=("gateway-c",),
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as mismatch:
            await client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert mismatch.value.code == "preview_relay_destination_identity_mismatch"
    assert local.calls == []


@pytest.mark.asyncio
async def test_mtls_preview_relay_rejects_revoked_or_ambiguous_client_identity(
    tmp_path: Path,
) -> None:
    server, client, _placements, local, *_rest, placement = await _relay_pair(
        tmp_path, server_authorized=()
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as revoked:
            await client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert revoked.value.code == "preview_relay_gateway_certificate_denied"
    assert local.calls == []

    ambiguous_root = tmp_path / "ambiguous"
    ambiguous_root.mkdir()
    ambiguous_certificates = _certificate_fixture(
        ambiguous_root, client_gateway_uris=("gateway-a", "gateway-shadow")
    )
    server, client, _placements, local, *_rest, placement = await _relay_pair(
        ambiguous_root,
        certificates=ambiguous_certificates,
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as ambiguous:
            await client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert ambiguous.value.code == "preview_relay_gateway_identity_invalid"
    assert local.calls == []


@pytest.mark.asyncio
async def test_mtls_preview_relay_requires_client_certificate(tmp_path: Path) -> None:
    certificates = _certificate_fixture(tmp_path)
    (
        server,
        _client,
        placements,
        local,
        server_authorizer,
        _,
        resolver,
        placement,
    ) = await _relay_pair(tmp_path, certificates=certificates)
    no_certificate_client = MutualTlsPreviewRelayClient(
        gateway_instance_id="gateway-a",
        endpoint_resolver=resolver,
        tls_context=_client_context(certificates["client"], with_certificate=False),
        certificate_authorizer=_CertificateAuthorizer(("gateway-b",)),
    )
    try:
        with pytest.raises(PreviewRelayTransportError) as missing:
            await no_certificate_client.forward(placement, _request(placement))
    finally:
        await server.aclose()
    assert missing.value.code == "preview_relay_unavailable"
    assert local.calls == []
    assert placements.calls == []
    assert server_authorizer.calls == []


@pytest.mark.asyncio
async def test_mtls_preview_relay_rejects_duplicate_or_oversized_frames(tmp_path: Path) -> None:
    certificates = _certificate_fixture(tmp_path)
    server, _client, _placements, local, *_rest = await _relay_pair(
        tmp_path, certificates=certificates
    )

    async def raw_error(frame: bytes) -> str:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            server.port,
            ssl=_client_context(certificates["client"]),
            server_hostname="localhost",
        )
        try:
            writer.write(frame)
            await writer.drain()
            magic, length = struct.unpack("!8sI", await reader.readexactly(12))
            assert magic == b"OMNIPVR1"
            document = json.loads(await reader.readexactly(length))
            return cast(str, document["code"])
        finally:
            writer.close()
            await writer.wait_closed()

    duplicate = b'{"version":1,"version":1}'
    try:
        assert (
            await raw_error(struct.pack("!8sIQ", b"OMNIPVR1", len(duplicate), 0) + duplicate)
            == "preview_relay_request_invalid"
        )
        assert (
            await raw_error(struct.pack("!8sIQ", b"OMNIPVR1", 65_537, 0))
            == "preview_relay_request_invalid"
        )
    finally:
        await server.aclose()
    assert local.calls == []


@pytest.mark.asyncio
async def test_mtls_preview_relay_client_close_cancels_owner_stream(tmp_path: Path) -> None:
    server, client, _placements, local, *_rest, placement = await _relay_pair(tmp_path)
    closed = asyncio.Event()

    async def hanging_body() -> AsyncIterator[bytes]:
        try:
            yield b"first"
            await asyncio.Future()
        finally:
            closed.set()

    async def hanging_forward(request: PreviewTunnelRequest) -> PreviewTunnelResponse:
        local.calls.append(request)
        return PreviewTunnelResponse(200, {"content-type": "text/plain"}, hanging_body())

    local.forward = hanging_forward  # type: ignore[method-assign]
    try:
        response = await client.forward(placement, _request(placement))
        assert not isinstance(response.body, bytes)
        iterator = response.body.__aiter__()
        assert await anext(iterator) == b"first"
        await cast(_ClosableBody, response.body).aclose()
        await asyncio.wait_for(closed.wait(), timeout=2)
    finally:
        await server.aclose()
    assert len(local.calls) == 1


def test_mtls_preview_relay_rejects_weak_tls_and_untrusted_endpoint(tmp_path: Path) -> None:
    certificates = _certificate_fixture(tmp_path)
    placement = _placement()
    placements = _PlacementAuthority(placement)
    local = _LocalTunnel()
    router = PlacementRoutedPreviewTunnel(
        gateway_instance_id="gateway-b",
        placements=placements,
        local_tunnel=cast(OfficialRunnerPreviewTunnel, local),
        relay=None,
    )
    weak_server = _server_context(certificates["server"])
    weak_server.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match=r"only TLS 1\.3"):
        MutualTlsPreviewRelayServer(
            gateway_instance_id="gateway-b",
            router=router,
            tls_context=weak_server,
            certificate_authorizer=_CertificateAuthorizer(("gateway-a",)),
        )

    weak_client = _client_context(certificates["client"])
    weak_client.check_hostname = False
    with pytest.raises(ValueError, match="hostname"):
        MutualTlsPreviewRelayClient(
            gateway_instance_id="gateway-a",
            endpoint_resolver=_EndpointResolver(
                PreviewRelayEndpoint("127.0.0.1", 8443, "localhost")
            ),
            tls_context=weak_client,
            certificate_authorizer=_CertificateAuthorizer(("gateway-b",)),
        )

    with pytest.raises(ValueError, match="endpoint"):
        PreviewRelayEndpoint("https://attacker.invalid/path", 443, "localhost")


@pytest.mark.asyncio
async def test_mtls_preview_relay_hides_service_discovery_failures(tmp_path: Path) -> None:
    certificates = _certificate_fixture(tmp_path)
    placement = _placement()

    class _UnavailableDirectory:
        def resolve(self, _placement: RunnerTunnelPlacement) -> PreviewRelayEndpoint:
            raise RuntimeError("internal topology must not escape")

    client = MutualTlsPreviewRelayClient(
        gateway_instance_id="gateway-a",
        endpoint_resolver=_UnavailableDirectory(),
        tls_context=_client_context(certificates["client"]),
        certificate_authorizer=_CertificateAuthorizer(("gateway-b",)),
    )
    with pytest.raises(PreviewRelayTransportError) as denied:
        await client.forward(placement, _request(placement))
    assert denied.value.code == "preview_relay_endpoint_unavailable"
