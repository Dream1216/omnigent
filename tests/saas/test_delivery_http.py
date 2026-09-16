"""Cookie/RBAC/JWT and actual DCP repositories; deterministic provider fixtures.

OMNIGENT_DCP_SOURCE must select the matching candidate checkout. These tests
are authenticated integration proof, not live Snapshot/Tekton/GitOps proof.
"""

# ruff: noqa: E402
from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from saas.control_plane import (
    ProjectAdministrationService,
    ProjectAuthorizer,
    RuntimeCompatibilityPolicy,
    SqlAlchemyContextResolver,
)
from saas.control_plane.db_models import GlobalUser
from saas.delivery.authorization import AuthorizationBody, DeliveryAuthorization
from saas.delivery.client import DeliveryClient, DeliveryConfig, DeliveryProject
from saas.delivery.http import create_delivery_router
from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login

_source = os.environ.get("OMNIGENT_DCP_SOURCE")
if not _source:
    pytest.skip("matching DCP source checkout required", allow_module_level=True)
_dcp = Path(_source).resolve()
sys.path.insert(0, str(_dcp / "src"))
from omnigent_dcp.api.app import create_app
from omnigent_dcp.auth.jwks import JwksActorResolver, JwksConfig
from omnigent_dcp.persistence.builds import BuildRepository
from omnigent_dcp.persistence.delivery import DeliveryRepository
from omnigent_dcp.persistence.domains import DomainBindingRepository
from omnigent_dcp.persistence.models import Base, DeliveryRow, SourceSnapshotRow
from omnigent_dcp.persistence.previews import ReleasePreviewRepository
from omnigent_dcp.persistence.repository import ReleaseRepository
from omnigent_dcp.services.admission import StaticCapacityProbe
from omnigent_dcp.services.builds import BuildService
from omnigent_dcp.services.delivery import DeliveryService
from omnigent_dcp.services.domains import DomainService
from omnigent_dcp.services.entitlements import EntitlementKey, StaticEntitlementAdmission
from omnigent_dcp.services.previews import ReleasePreviewService
from omnigent_dcp.services.releases import ReleaseService
from omnigent_dcp.snapshot.repository import SnapshotRepository


def fixture_module(path):
    name = "delivery_fixture_" + Path(path).stem
    spec = importlib.util.spec_from_file_location(name, _dcp / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_harness(
    origin="http://testserver", app_database=None, dcp_database=None, checkpoint_service=None
):
    app, scope = _build_fastapi_app(origin, app_database)
    client = TestClient(app)
    csrf = _login(client)
    sessions = app.state.saas_test_sessions
    resolver = SqlAlchemyContextResolver(
        sessions,
        RuntimeCompatibilityPolicy(
            runtime_type="omnigent",
            allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
            allowed_source_revisions=frozenset({"15dd7becff2bda8ee2b9afd5d16abc4feafb9552"}),
            allowed_schema_revisions=frozenset({"c4d5e6f7a8b9"}),
            adapter_contract_version="0.2.0",
        ),
    )
    context = resolver.resolve_request_context(
        actor_id=UUID(scope["user_id"]),
        tenant_id=UUID(scope["tenant_id"]),
        space_id=UUID(scope["space_id"]),
        trace_id="delivery-test",
    )
    project = ProjectAdministrationService(sessions, ProjectAuthorizer(sessions)).create_project(
        context, name="交付验收项目", visibility="private", idempotency_key="delivery-project"
    )
    binding = DeliveryProject(
        context.tenant_id,
        context.space_id,
        project.project_id,
        "交付验收项目",
        "preview",
        "production",
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    config = DeliveryConfig(
        endpoint="https://dcp.test",
        issuer="https://app.test/saas/delivery",
        key_id="acceptance-key",
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        projects=(binding,),
    )
    transport = DeliveryClient(config)
    authority = DeliveryAuthorization(config, resolver, sessions)

    class Revalidator:
        def authorize(self, *, identity, action, spec):
            return authority.decide(
                AuthorizationBody(
                    action=action,
                    actor_id=identity.actor_id,
                    tenant_id=identity.tenant_id,
                    project_id=identity.project_id,
                    membership_version=identity.membership_version,
                    token_id=identity.token_id,
                    request_nonce=uuid4().hex,
                    resource={
                        "environment_id": spec.environment_id,
                        "environment_type": spec.environment_type.value,
                        "artifact_ref": spec.artifact_ref,
                    },
                )
            )["allowed"]

    fixtures = fixture_module("tests/unit/test_snapshot_gateway.py")
    engine, _, upload, _, runner, snapshots = fixtures._service()
    if dcp_database is not None:
        engine.dispose()
        engine = create_engine(
            dcp_database, connect_args={"check_same_thread": False, "timeout": 20}
        )
        Base.metadata.create_all(engine)
        snapshots.repository = SnapshotRepository(engine)

    async def seed():
        actor = fixtures._identity("snapshot:create", "snapshot:read", "snapshot:reconcile")
        created = await snapshots.create(
            identity=actor,
            request=fixtures._request(),
            idempotency_key="source",
            correlation_id="test",
        )
        runner.succeed(object_ref=upload.target.object_ref)
        return await snapshots.reconcile(identity=actor, snapshot_id=created.snapshot.id)

    snapshot = asyncio.run(seed())
    # Install the verified fixture under this test's fresh SaaS project scope.
    with Session(engine) as session, session.begin():
        row = session.get(SourceSnapshotRow, snapshot.id)
        row.tenant_id, row.project_id = str(context.tenant_id), str(project.project_id)
        row.space_id, row.actor_id = str(context.space_id), str(context.actor_id)
        row.oci_status, row.oci_attempt_count = "ready", 1
        row.oci_artifact_ref = "registry.example.test/source@sha256:" + "a" * 64
        row.oci_manifest_digest = "sha256:" + "a" * 64
        row.oci_layer_digest = "sha256:" + "b" * 64
        row.oci_promoted_at = datetime.now(timezone.utc)
    entitlements = StaticEntitlementAdmission(dict.fromkeys(EntitlementKey, True))
    builds = BuildService(BuildRepository(engine), entitlement_admission=entitlements)
    releases = ReleaseService(
        ReleaseRepository(engine),
        entitlement_admission=entitlements,
        capacity_probe=StaticCapacityProbe(True),
        high_risk_revalidator=Revalidator(),
    )
    previews = ReleasePreviewService(
        ReleasePreviewRepository(engine), entitlement_admission=entitlements
    )
    delivery = DeliveryService(
        DeliveryRepository(engine),
        snapshots=snapshots,
        snapshot_oci=None,
        builds=builds,
        releases=releases,
        previews=previews,
    )
    jwks_app = FastAPI()
    jwks_app.get("/jwks")(transport.jwks)
    actor_resolver = JwksActorResolver(
        JwksConfig(issuer=config.issuer, jwks_url="https://app.test/jwks"),
        transport=httpx.ASGITransport(app=jwks_app),
    )
    dcp_app = create_app(
        release_service=releases,
        build_service=builds,
        snapshot_service=snapshots,
        preview_service=previews,
        delivery_service=delivery,
        domain_service=DomainService(DomainBindingRepository(engine)),
        actor_resolver=actor_resolver,
        checkpoint_service=checkpoint_service,
    )
    transport.transport = httpx.ASGITransport(app=dcp_app)
    app.include_router(
        create_delivery_router(
            auth=app.state.saas_test_auth, resolver=resolver, sessions=sessions, client=transport
        ),
        prefix="/saas",
    )
    return SimpleNamespace(
        app=app,
        client=client,
        scope=scope,
        project=binding,
        transport=transport,
        dcp_app=dcp_app,
        delivery=delivery,
        context=context,
        snapshot_id=snapshot.id,
        engine=engine,
        csrf=csrf,
        authority=authority,
        base=f"/saas/delivery/projects/{project.project_id}",
    )


def post(h, path, body, key=None):
    return h.client.post(
        path,
        json=body,
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": h.csrf,
            "Idempotency-Key": key or uuid4().hex,
        },
    )


def tick(h):
    build = fixture_module("tests/contract/test_build_dispatcher.py")
    release = fixture_module("tests/contract/test_release_dispatcher.py")

    class DifferentArtifactProvider(build.ImmediateSuccessProvider):
        async def submit(self, **kwargs):
            result = await super().submit(**kwargs)
            digest = "b" if kwargs["spec"].mode == "static" else "f"
            return result.model_copy(
                update={"artifact_ref": "registry.example.test/app@sha256:" + digest * 64}
            )

    with Session(h.engine) as session, session.begin():
        session.execute(
            update(DeliveryRow).values(
                next_attempt_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
                lease_expires_at=None,
                lease_token=None,
            )
        )
    asyncio.run(h.delivery.run_once())
    asyncio.run(build._dispatcher(h.engine, DifferentArtifactProvider()).run_once())
    asyncio.run(
        release._dispatcher(
            h.engine,
            release.ImmediateSuccessProvider(),
            release.MutableClock(datetime.now(timezone.utc)),
        ).run_once()
    )


@pytest.fixture
def harness(tmp_path):
    h = build_harness(dcp_database=f"sqlite+pysqlite:///{tmp_path / 'dcp.sqlite3'}")
    yield h
    h.client.close()
    h.engine.dispose()
    h.app.state.saas_test_engine.dispose()


def test_cookie_jwt_build_preview_promote_and_explicit_rollback(harness):
    h = harness
    assert h.client.get("/saas/delivery/projects").json()["projects"][0]["actions"]["publish"]
    body = {"snapshot_id": h.snapshot_id, "mode": "static"}
    created = post(h, h.base + "/build", body, "browser-command-idempotency")
    assert created.status_code == 202, created.text
    assert (
        post(h, h.base + "/build", body, "browser-command-idempotency").json()["id"]
        == created.json()["id"]
    )
    for _ in range(3):
        tick(h)
    overview = h.client.get(h.base).json()
    assert overview["deliveries"][0]["status"] == "ready", overview
    preview = overview["deliveries"][0]["release_id"]
    first = post(h, h.base + f"/releases/{preview}/promote", {"expected_target_generation": 0})
    assert first.status_code == 202, first.text
    tick(h)
    a = first.json()["release"]
    assert (
        post(h, h.base + "/build", {"snapshot_id": h.snapshot_id, "mode": "auto"}).status_code
        == 202
    )
    for _ in range(3):
        tick(h)
    preview = h.client.get(h.base).json()["deliveries"][0]["release_id"]
    second = post(h, h.base + f"/releases/{preview}/promote", {"expected_target_generation": 1})
    assert second.status_code == 202, second.text
    tick(h)
    b = second.json()["release"]
    assert a["artifact_ref"] != b["artifact_ref"]
    path = h.base + f"/releases/{b['id']}/rollback"
    body = {"target_release_id": a["id"], "expected_target_generation": 2}
    rollback = post(h, path, body, "browser-rollback-idempotency")
    assert rollback.status_code == 202, rollback.text
    assert rollback.json()["release"]["artifact_ref"] == a["artifact_ref"]
    replay = post(h, path, body, "browser-rollback-idempotency")
    assert replay.json()["release"]["id"] == rollback.json()["release"]["id"]
    tick(h)
    assert h.client.get(h.base).json()["releases"][0]["status"] == "ready"
    asyncio.run(h.transport.check_contract())


def test_delivery_rejects_csrf_scope_injection_and_revoked_session(harness):
    h = harness
    body = {"snapshot_id": h.snapshot_id}
    assert h.client.post(h.base + "/build", json=body).status_code == 403
    assert (
        h.client.post(
            h.base + "/build",
            json=body,
            headers={
                "Origin": "https://evil.test",
                "X-CSRF-Token": h.csrf,
                "Idempotency-Key": uuid4().hex,
            },
        ).status_code
        == 403
    )
    assert post(h, h.base + "/build", {**body, "tenant_id": str(uuid4())}).status_code == 422
    assert post(h, h.base + "/build", {"snapshot_id": str(uuid4())}).status_code == 404
    assert h.client.get(f"/saas/delivery/projects/{uuid4()}").status_code == 404
    other = TestClient(h.app)
    assert other.get(h.base).status_code == 401
    assert (
        other.post(
            "/saas/auth/login",
            json={"email": "viewer@example.com", "password": "initial-viewer-password"},
        ).status_code
        == 200
    )
    assert other.get(h.base).status_code == 404
    with h.app.state.saas_test_sessions.begin() as session:
        session.get(GlobalUser, UUID(h.scope["user_id"])).security_version += 1
    assert h.client.get(h.base).status_code == 401


def test_preview_link_requires_current_domain_generation_and_unexpired_lease(harness):
    from dataclasses import replace
    from datetime import timedelta

    from omnigent_dcp.domain.models import ActorContext, DomainBindingSpec
    from omnigent_dcp.persistence.models import DomainBindingRow, ReleasePreviewRow

    h = harness
    assert post(h, h.base + "/build", {"snapshot_id": h.snapshot_id}).status_code == 202
    for _ in range(3):
        tick(h)
    delivery = h.client.get(h.base).json()["deliveries"][0]
    path = h.base + f"/previews/{delivery['preview_id']}/open"
    assert h.client.get(path).status_code == 409
    actor = ActorContext(
        tenant_id=str(h.context.tenant_id),
        project_id=str(h.project.project_id),
        actor_id=str(h.context.actor_id),
        membership_version=h.context.tenant_membership_version,
        token_id="domain-fixture",
        permissions=frozenset({"domain:create"}),
    )
    with Session(h.engine) as session:
        preview = session.get(ReleasePreviewRow, delivery["preview_id"])
        spec = DomainBindingSpec(
            environment_id=preview.environment_id,
            hostname="delivery-preview.example.test",
            target_generation=preview.target_generation,
            git_revision=preview.git_revision,
            desired_fingerprint="a" * 64,
            dns_target="edge.example.test",
        )
    domain = (
        DomainService(DomainBindingRepository(h.engine))
        .create(identity=actor, spec=spec, idempotency_key="domain-fixture", correlation_id="test")
        .domain
    )
    binding = replace(h.project, preview_domain_binding_id=domain.id)
    h.transport.config = replace(h.transport.config, projects=(binding,))
    now = datetime.now(timezone.utc)
    with Session(h.engine) as session, session.begin():
        row = session.get(DomainBindingRow, domain.id)
        row.status = "ready"
        row.ownership_evidence_sha256 = "a" * 64
        row.ownership_resolver_ids = ["resolver-a", "resolver-b"]
        row.ownership_verified_at = now
        row.ready_evidence_sha256 = "b" * 64
        row.public_addresses = ["1.1.1.1"]
        row.certificate_not_after = now + timedelta(days=1)
        row.ready_at = now
    opened = h.client.get(path)
    assert opened.status_code == 200, opened.text
    assert opened.json()["url"] == "https://delivery-preview.example.test"
    assert opened.headers["Cache-Control"] == "no-store"
    h.transport.config = replace(h.transport.config, projects=(h.project,))
    assert h.client.get(path).json()["url"] == opened.json()["url"]
    h.transport.config = replace(h.transport.config, projects=(binding,))
    with Session(h.engine) as session, session.begin():
        session.get(DomainBindingRow, domain.id).target_generation += 1
    assert h.client.get(path).json()["detail"]["code"] == "preview_endpoint_stale"
    with Session(h.engine) as session, session.begin():
        session.get(DomainBindingRow, domain.id).target_generation = spec.target_generation
        session.get(ReleasePreviewRow, delivery["preview_id"]).created_at = now - timedelta(
            hours=1
        )
        session.get(ReleasePreviewRow, delivery["preview_id"]).expires_at = now - timedelta(
            seconds=1
        )
    assert h.client.get(path).json()["detail"]["code"] == "preview_expired"
    assert h.client.get(h.base + "/runs").status_code == 200


def test_expired_cookie_can_load_delivery_login_without_exposing_project_data(harness):
    h = harness
    cookie_name = next(iter(h.client.cookies))
    h.client.cookies.clear()
    h.client.cookies.set(cookie_name, "expired-test-session")
    assert h.client.get("/saas/delivery").status_code == 200
    assert h.client.get("/saas/delivery/assets/delivery.js").status_code == 200
    assert h.client.get("/saas/delivery/.well-known/jwks.json").status_code == 200
    assert h.client.get("/saas/delivery/projects").status_code == 401
    assert h.client.get(h.base).status_code == 401
    h.csrf = _login(h.client)
    assert h.client.get(h.base).status_code == 200
