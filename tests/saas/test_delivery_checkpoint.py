"""Completed Run -> thin Git recovery bundle -> authenticated DCP snapshot."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import socket
import ssl
import subprocess
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from saas.control_plane import RuntimeCompatibilityPolicy, SqlAlchemyContextResolver
from saas.control_plane.db_models import GlobalUser
from saas.control_plane.execution_models import ExecutionSessionRecord, RunRecord
from saas.control_plane.resolver import ControlPlaneResolutionError
from saas.control_plane.worktree_models import ChangeSetRecord, WorktreeInstanceRecord
from saas.control_plane.worktrees import ChangeSetSpec
from saas.delivery.authorization import DeliveryAuthorization, create_authorization_app
from saas.delivery.checkpoints import CheckpointExportBody, CheckpointExporter
from saas.delivery.client import DeliveryConfig, DeliveryProject
from saas.runner_adapter.worktrees import CheckpointArtifact, FilesystemRecoveryArtifactStore
from tests.saas import test_delivery_http as _pinned_dcp  # noqa: F401
from tests.saas.test_billing_metering_transport import _certificate_fixture
from tests.saas.test_worktree_control_plane import (
    _allocate,
    _configure_worktree_quota,
    _lease_run,
    _ready,
    worktree_fixture,  # noqa: F401
)


@pytest.fixture
def checkpoint(worktree_fixture, tmp_path):  # noqa: F811
    f = worktree_fixture
    source = tmp_path / "source"
    source.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(source), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-b", "main")
    git("config", "user.name", "Acceptance")
    git("config", "user.email", "acceptance@example.test")
    (source / "index.html").write_text("<h1>base</h1>")
    git("add", ".")
    git("commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    mirror = tmp_path / "mirror.git"
    git("clone", "--bare", str(source), str(mirror))
    (source / "index.html").write_text("<h1>completed run</h1>")
    git("add", ".")
    git("commit", "-m", "checkpoint")
    head = git("rev-parse", "HEAD")
    bundle = tmp_path / "source.bundle"
    git("bundle", "create", str(bundle), f"{base}..HEAD")
    binding = "repo_checkpoint_" + uuid4().hex
    repository = f.worktrees.register_repository(
        f.request,
        project_id=f.project_id,
        provider="github-app",
        source_binding_key=binding,
        display_name="Checkpoint",
        default_branch="main",
    )
    change = f.worktrees.create_change_set_group(
        f.request,
        project_id=f.project_id,
        title="Delivery",
        specs=(
            ChangeSetSpec(
                repository_id=repository,
                base_revision=base,
                branch_ref="refs/heads/codex/checkpoint",
            ),
        ),
    ).change_set_ids[0]
    now = datetime.now(timezone.utc)
    _configure_worktree_quota(f)
    run = _lease_run(f, change_set_id=change, key="checkpoint-run", now=now)
    lease = _allocate(f, run, change, now=now + timedelta(seconds=2))
    _ready(f, lease, now=now + timedelta(seconds=3))
    store = FilesystemRecoveryArtifactStore(tmp_path / "objects")
    reference = store.put(
        CheckpointArtifact(
            repository_binding_digest=hashlib.sha256(binding.encode()).hexdigest(),
            base_revision=base,
            head_revision=head,
            bundle=bundle.read_bytes(),
        )
    )
    session_id = uuid4()
    with f.factory.begin() as db:
        db.add(
            ExecutionSessionRecord(
                id=session_id,
                tenant_id=f.request.tenant_id,
                space_id=f.request.space_id,
                project_id=f.project_id,
                created_by=f.request.actor_id,
            )
        )
        db.flush()
        record = db.get(RunRecord, run.run_id)
        record.status, record.terminal_at, record.session_id = "succeeded", now, session_id
        row = db.get(WorktreeInstanceRecord, lease.worktree_id)
        row.recovery_artifact_ref, row.dirty = reference, False
        # A later ChangeSet checkpoint must never change this completed Run's source.
        db.get(ChangeSetRecord, change).recovery_artifact_ref = "wta_sha256_" + "f" * 64
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    config = DeliveryConfig(
        "https://dcp.test",
        "https://app.test/saas/delivery",
        "checkpoint-key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        (
            DeliveryProject(
                f.request.tenant_id,
                f.request.space_id,
                f.project_id,
                "Checkpoint",
                "preview",
                "production",
            ),
        ),
        repository_mirrors={binding: mirror},
    )
    policy = RuntimeCompatibilityPolicy(
        runtime_type="omnigent",
        allowed_runtime_versions=frozenset({"0.9.0.dev0"}),
        allowed_source_revisions=frozenset({"a" * 40}),
        allowed_schema_revisions=frozenset({"test"}),
        adapter_contract_version="0.2.0",
    )
    authority = DeliveryAuthorization(
        config, SqlAlchemyContextResolver(f.factory, policy), f.factory
    )
    exporter = CheckpointExporter(authority, store, config.repository_mirrors)
    body = CheckpointExportBody(
        actor_id=f.request.actor_id,
        tenant_id=f.request.tenant_id,
        project_id=f.project_id,
        membership_version=1,
        run_id=run.run_id,
        request_nonce="checkpoint-acceptance",
    )
    return f, exporter, body, head


def test_export_uses_pinned_thin_bundle_and_denies_scope_or_changed_membership(checkpoint):
    f, exporter, body, head = checkpoint
    result = exporter.export(body)
    metadata = json.loads(result.headers["X-Omnigent-Checkpoint"])
    assert metadata["source_revision"] == head
    with tarfile.open(fileobj=io.BytesIO(result.body)) as archive:
        assert archive.extractfile("index.html").read() == b"<h1>completed run</h1>"
    with pytest.raises(HTTPException):
        exporter.export(body.model_copy(update={"project_id": uuid4()}))
    with pytest.raises(HTTPException):
        exporter.export(body.model_copy(update={"membership_version": 2}))
    with f.factory.begin() as db:
        db.get(GlobalUser, body.actor_id).status = "suspended"
    with pytest.raises(ControlPlaneResolutionError):
        exporter.export(body)


def test_real_mtls_checkpoint_import_object_verification_and_replay(checkpoint, tmp_path):
    from omnigent_dcp.auth.revalidation import OnlineAuthorizationConfig
    from omnigent_dcp.domain.errors import DcpError
    from omnigent_dcp.domain.models import ActorContext
    from omnigent_dcp.persistence.models import Base, SourceSnapshotRow
    from omnigent_dcp.services.checkpoints import CheckpointImportRequest, CheckpointImportService
    from omnigent_dcp.services.entitlements import EntitlementKey, StaticEntitlementAdmission
    from omnigent_dcp.snapshot.gateway import SnapshotObjectMetadata, SnapshotUploadTarget
    from omnigent_dcp.snapshot.repository import SnapshotRepository
    from pydantic import SecretStr

    f, exporter, body, _head = checkpoint
    certs = _certificate_fixture(tmp_path, (uuid4(),))
    server_files, client_files = certs["server"], certs["runner-0"]
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(
        uvicorn.Config(
            create_authorization_app(exporter.authority, checkpoint_exporter=exporter),
            ssl_certfile=str(server_files.certificate),
            ssl_keyfile=str(server_files.private_key),
            ssl_ca_certs=str(server_files.ca),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            access_log=False,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'checkpoint-dcp.db'}")
    Base.metadata.create_all(engine)
    repository = SnapshotRepository(engine)
    stored = {}

    class Upload:
        async def allocate(self, *, identity, request):
            self.identity, self.request = identity, request
            return SnapshotUploadTarget(
                object_ref="oss://test/checkpoint.tar.zst",
                put_url=SecretStr("https://upload.test/source"),
                headers=(),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                max_bytes=1024 * 1024,
            )

        async def head(self, *, object_ref):
            data = stored["bytes"]
            return SnapshotObjectMetadata(
                object_ref=object_ref,
                size=len(data),
                archive_digest="sha256:" + hashlib.sha256(data).hexdigest(),
                tenant_id=self.identity.tenant_id,
                project_id=self.identity.project_id,
                build_id=self.request.build_id,
                encrypted=True,
            )

        async def revoke(self, *, object_ref):
            pass

    async def upload(request):
        stored["bytes"] = await request.aread()
        return httpx.Response(200)

    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        endpoint = f"https://127.0.0.1:{listener.getsockname()[1]}/authorize"
        service = CheckpointImportService(
            repository,
            Upload(),
            OnlineAuthorizationConfig(
                endpoint, client_files.ca, client_files.certificate, client_files.private_key
            ),
            tmp_path,
            StaticEntitlementAdmission(dict.fromkeys(EntitlementKey, True)),
            upload_transport=httpx.MockTransport(upload),
        )
        actor = ActorContext(
            tenant_id=str(body.tenant_id),
            project_id=str(body.project_id),
            actor_id=str(body.actor_id),
            membership_version=1,
            token_id="checkpoint-mtls",
            permissions=frozenset({"snapshot:create"}),
        )
        request = CheckpointImportRequest(run_id=body.run_id, environment_id="preview")

        async def run():
            first = await service.create(
                identity=actor,
                request=request,
                idempotency_key="checkpoint-v1",
                correlation_id="test",
            )
            second = await service.create(
                identity=actor,
                request=request,
                idempotency_key="checkpoint-v1",
                correlation_id="test",
            )
            assert first.id == second.id and first.status.value == "ready"
            assert (
                first.receipt is None
            )  # A checkpoint authority never forges a Runner export receipt.
            return first

        result = asyncio.run(run())
        with Session(engine) as db:
            assert db.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 1
        assert result.archive_digest == "sha256:" + hashlib.sha256(stored["bytes"]).hexdigest()
        with httpx.Client(
            verify=ssl.create_default_context(cafile=str(server_files.ca)),
            trust_env=False,
            timeout=2,
        ) as client:
            with pytest.raises(httpx.HTTPError):
                client.post(
                    endpoint.rsplit("/", 1)[0] + "/checkpoints/export",
                    json=body.model_dump(mode="json"),
                )
        with f.factory.begin() as db:
            db.get(GlobalUser, body.actor_id).status = "suspended"
        with pytest.raises(DcpError):
            asyncio.run(
                service.create(
                    identity=actor,
                    request=request,
                    idempotency_key="revoked",
                    correlation_id="test",
                )
            )
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        engine.dispose()
