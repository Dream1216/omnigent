from __future__ import annotations

import copy
import os
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from saas.production.preview_execution import (
    PREVIEW_EXECUTION_KIND,
    STATIC_WEB_PREVIEW_PROFILE,
    STATIC_WEB_RUNTIME_MODULE,
    PreviewExecutionContractError,
    preview_request_identity,
    server_owned_preview_run_input,
    static_web_preview_execution,
)
from saas.runner_adapter import static_web_preview
from saas.runner_adapter.static_web_preview import create_static_web_preview_app

PREVIEW_EXECUTION_ID = UUID("10000000-0000-4000-8000-000000000001")
CHANGE_SET_ID = UUID("20000000-0000-4000-8000-000000000002")
RUN_ID = UUID("30000000-0000-4000-8000-000000000003")
CHECKPOINT = "a" * 40


def _input() -> dict[str, object]:
    return server_owned_preview_run_input(
        preview_execution_id=PREVIEW_EXECUTION_ID,
        change_set_id=CHANGE_SET_ID,
        checkpoint_revision=CHECKPOINT,
    )


def test_static_web_child_run_contract_derives_only_fixed_process_surface(
    tmp_path: Path,
) -> None:
    publish = tmp_path / "dist"
    publish.mkdir(mode=0o700)
    execution = static_web_preview_execution(_input())

    spec = execution.process_spec(tmp_path.resolve())

    assert execution.preview_execution_id == PREVIEW_EXECUTION_ID
    assert execution.change_set_id == CHANGE_SET_ID
    assert execution.checkpoint_revision == CHECKPOINT
    assert execution.profile == STATIC_WEB_PREVIEW_PROFILE
    assert len(execution.spec_hash) == 64
    assert spec.argv[1:] == ("-P", "-m", STATIC_WEB_RUNTIME_MODULE)
    assert spec.working_directory == publish.resolve()
    assert spec.environment == ()
    # The checkout owner may still have OS write permission. Production safety
    # comes from the durable readonly Worktree/checkpoint grant plus this trusted
    # static-only reader; it never executes Worktree code or accepts argv/path.
    assert os.access(publish, os.W_OK)


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("kind", "shell"),
        ("profile", "npm_dev_server"),
        ("argv", ["sh", "-c", "id"]),
        ("path", "/tmp/public"),
        ("environment", {"TOKEN": "secret"}),
    ),
)
def test_static_web_child_run_contract_rejects_caller_process_surface(
    mutation: str,
    value: object,
) -> None:
    payload = copy.deepcopy(_input())
    execution = payload["execution"]
    assert isinstance(execution, dict)
    execution[mutation] = value

    with pytest.raises(PreviewExecutionContractError):
        static_web_preview_execution(payload)


def test_static_web_child_run_contract_rejects_noncanonical_checkpoint() -> None:
    payload = _input()
    execution = payload["execution"]
    assert isinstance(execution, dict)
    execution["checkpoint_revision"] = "refs/heads/main"

    with pytest.raises(PreviewExecutionContractError, match="checkpoint"):
        static_web_preview_execution(payload)


def test_static_web_process_spec_rejects_symlinked_publish_directory(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "dist").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PreviewExecutionContractError, match="exact readonly child"):
        static_web_preview_execution(_input()).process_spec(worktree.resolve())


def test_preview_request_identity_binds_idempotency_key_to_canonical_body() -> None:
    first = preview_request_identity(
        run_id=RUN_ID,
        preview_kind=STATIC_WEB_PREVIEW_PROFILE,
        idempotency_key="preview-request-0001",
    )
    replay = preview_request_identity(
        run_id=RUN_ID,
        preview_kind=STATIC_WEB_PREVIEW_PROFILE,
        idempotency_key="preview-request-0001",
    )
    different_run = preview_request_identity(
        run_id=UUID("40000000-0000-4000-8000-000000000004"),
        preview_kind=STATIC_WEB_PREVIEW_PROFILE,
        idempotency_key="preview-request-0001",
    )

    assert first == replay
    assert first.key_hash == different_run.key_hash
    assert first.request_hash != different_run.request_hash


def test_server_owned_preview_input_is_closed_and_non_secret() -> None:
    payload = _input()
    execution = payload["execution"]
    assert isinstance(execution, dict)
    assert execution == {
        "checkpoint_revision": CHECKPOINT,
        "kind": PREVIEW_EXECUTION_KIND,
        "preview_execution_id": str(PREVIEW_EXECUTION_ID),
        "profile": STATIC_WEB_PREVIEW_PROFILE,
    }
    encoded = repr(payload).lower()
    assert all(
        fragment not in encoded
        for fragment in ("argv", "path", "token", "secret", "password", "lease")
    )


@pytest.mark.asyncio
async def test_static_web_runtime_serves_health_files_and_no_directory_listing(
    tmp_path: Path,
) -> None:
    (tmp_path / "index.html").write_text("<h1>preview</h1>", encoding="utf-8")
    (tmp_path / "asset.txt").write_text("asset", encoding="utf-8")
    (tmp_path / "bundle.js").write_text("export default 1", encoding="utf-8")
    (tmp_path / "opaque.custom").write_bytes(b"opaque")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "index.html").write_text("nested-index", encoding="utf-8")
    (tmp_path / "empty").mkdir()
    app = create_static_web_preview_app(
        root=tmp_path,
        health_path="/__omnigent_preview_health",
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://preview.invalid",
        follow_redirects=False,
    ) as client:
        health = await client.get("/__omnigent_preview_health")
        index = await client.get("/")
        nested_index = await client.get("/nested/")
        asset = await client.get("/asset.txt")
        asset_repeat = await client.get("/asset.txt")
        javascript = await client.get("/bundle.js")
        unknown = await client.get("/opaque.custom")
        listing = await client.get("/empty/")
        mutation = await client.post("/asset.txt", content=b"replace")
        ranged = await client.get("/asset.txt", headers={"Range": "bytes=0-1"})
        head = await client.head("/asset.txt")
    app.close()

    assert health.status_code == 200
    assert health.headers["cache-control"] == "no-store"
    assert index.text == "<h1>preview</h1>"
    assert nested_index.text == "nested-index"
    assert asset.text == "asset"
    assert javascript.headers["content-type"] == "application/javascript; charset=utf-8"
    assert unknown.headers["content-type"] == "application/octet-stream"
    assert asset.headers["content-security-policy"].startswith(
        "sandbox allow-scripts allow-forms allow-modals allow-same-origin; "
    )
    assert "connect-src 'none'" in asset.headers["content-security-policy"]
    assert asset.headers["accept-ranges"] == "none"
    assert dict(asset.headers) == dict(asset_repeat.headers)
    assert listing.status_code == 404
    assert mutation.status_code == 405
    assert ranged.status_code == 416
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == str(len(b"asset"))


@pytest.mark.asyncio
async def test_static_web_runtime_rejects_symlinks_dotfiles_and_oversized_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dist"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("not public", encoding="utf-8")
    (root / "escape.txt").symlink_to(outside)
    (root / ".secret").write_text("not public", encoding="utf-8")
    oversized = root / "oversized.bin"
    descriptor = os.open(oversized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(descriptor, 10 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    app = create_static_web_preview_app(root=root, health_path="/_health")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://preview.invalid") as client:
        symlink = await client.get("/escape.txt")
        dotfile = await client.get("/.secret")
        too_large = await client.get("/oversized.bin")
    app.close()

    assert symlink.status_code == 404
    assert dotfile.status_code == 404
    assert too_large.status_code == 404


@pytest.mark.asyncio
async def test_static_web_runtime_rejects_same_inode_mutation_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "changing.bin"
    target.write_bytes(b"a" * (2 * 64 * 1024))
    real_read = os.read
    mutated = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            with target.open("r+b") as stream:
                stream.seek(64 * 1024)
                stream.write(b"b" * (64 * 1024))
                stream.flush()
                os.fsync(stream.fileno())
        return chunk

    monkeypatch.setattr(static_web_preview.os, "read", racing_read)
    app = create_static_web_preview_app(root=tmp_path, health_path="/_health")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://preview.invalid") as client:
        response = await client.get("/changing.bin")
    app.close()

    assert mutated is True
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_static_web_runtime_rejects_path_and_component_bound_overflow(
    tmp_path: Path,
) -> None:
    (tmp_path / "index.html").write_text("index", encoding="utf-8")
    app = create_static_web_preview_app(root=tmp_path, health_path="/_health")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://preview.invalid") as client:
        long_path = await client.get("/" + "a" * 1025)
        long_component = await client.get("/" + "b" * 256)
        too_many_components = await client.get("/".join(["", *("c" for _ in range(33))]))
    app.close()

    assert long_path.status_code == 404
    assert long_component.status_code == 404
    assert too_many_components.status_code == 404
