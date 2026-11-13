"""The unchanged seeded corpus must reference actual readable agent artifacts."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import httpx
import pytest

from dev.benchmarks.omnigent.environment import BenchEnvironment
from dev.benchmarks.omnigent.seed import _AGENT_BUNDLE, seed
from omnigent.runtime.agent_cache import AgentCache
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore


@pytest.mark.parametrize("with_runner", [False, True])
def test_every_seeded_agent_loads_its_real_bundle_and_missing_bundles_still_fail(
    tmp_path: Path, with_runner: bool
) -> None:
    location = f"sqlite:///{tmp_path / 'corpus.db'}"
    assert seed(location, sessions=4, items_per_session=3, projects=2) == 4
    environment = BenchEnvironment(with_runner=with_runner, database_uri=location)
    environment.mock_url = "http://127.0.0.1:1"  # Parse only; no provider request.
    artifacts = tmp_path / "artifacts"
    environment._seed_agent_artifact(artifacts)
    store = LocalArtifactStore(str(artifacts))
    cache = AgentCache(artifact_store=store, cache_dir=tmp_path / "cache")
    conversations = SqlAlchemyConversationStore(location).list_conversations(limit=4)
    assert len(conversations.data) == 4
    agents = SqlAlchemyAgentStore(location).get_many(
        [conversation.agent_id for conversation in conversations.data]
    )
    assert len(agents) == 4
    for agent in agents.values():
        assert agent.bundle_location == _AGENT_BUNDLE
        loaded = cache.load(agent.id, agent.bundle_location)
        assert loaded.spec.executor.config["harness"] == environment.harness
        assert cache.load(agent.id, agent.bundle_location).spec is loaded.spec
    with pytest.raises(KeyError):
        cache.load("missing-agent", "missing/bundle")


async def test_fork_diagnostic_is_opt_in_fixed_target_and_consumed_once(monkeypatch) -> None:
    from fastapi import APIRouter, FastAPI

    from saas.scripts import benchmark_fork_diagnostics as debug_router

    monkeypatch.delenv("OMNIGENT_BENCH_FORK_DIAGNOSTICS", raising=False)
    assert debug_router._diagnostic_binding() is None
    router = APIRouter()
    calls = []

    async def profile(_request, source_id):
        calls.append(source_id)
        return {"status": "complete"}

    monkeypatch.setattr(debug_router, "_profile_original_fork", profile)
    debug_router.install_fork_diagnostic(router, {"source_id": "original", "token": "1" * 32})
    app = FastAPI()
    app.include_router(router, prefix="/debug")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bench"
    ) as client:
        assert (await client.post("/debug/server-metrics")).status_code == 403
        response = await client.post(
            "/debug/server-metrics", headers={"X-Omnigent-Bench-Diagnostic": "1" * 32}
        )
        assert response.json()["status"] == "complete"
        assert (
            await client.post(
                "/debug/server-metrics", headers={"X-Omnigent-Bench-Diagnostic": "1" * 32}
            )
        ).status_code == 409
    assert calls == ["original"]


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout"])
async def test_fork_profile_scopes_sql_executor_and_restores_loop(outcome, monkeypatch) -> None:
    from fastapi import FastAPI, HTTPException
    from sqlalchemy import create_engine, text
    from starlette.requests import Request

    from omnigent.db.query_context import query_name_scope
    from saas.scripts.benchmark_fork_diagnostics import _profile_original_fork

    app = FastAPI()
    deleted = []

    finished = threading.Event()
    if outcome == "timeout":
        original_timeout = asyncio.timeout
        monkeypatch.setattr(
            asyncio,
            "timeout",
            lambda seconds: original_timeout(0.005 if seconds == 15 else seconds),
        )

    def query():
        if outcome == "timeout":
            time.sleep(0.02)
        with query_name_scope("benchmark.fixed_fork"):
            engine = create_engine("sqlite://")
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
            finally:
                engine.dispose()
                finished.set()

    @app.post("/v1/sessions/{source_id}/fork")
    async def fork(source_id: str):
        assert source_id == "original"
        await asyncio.to_thread(query)
        if outcome == "failure":
            raise HTTPException(503)
        return {"id": "diagnostic-child"}

    @app.delete("/v1/sessions/{session_id}")
    async def delete(session_id: str):
        deleted.append(session_id)
        return {}

    loop = asyncio.get_running_loop()
    original = loop.run_in_executor
    request = Request({"type": "http", "app": app, "headers": []})
    result = await _profile_original_fork(request, "original")
    assert loop.run_in_executor == original
    assert result["status"] == ("complete" if outcome == "success" else "incomplete")
    assert finished.is_set()
    assert {row["kind"] for row in result["records"]} == {"sql", "thread_pool"}
    assert any(row.get("query_name") == "benchmark.fixed_fork" for row in result["records"])
    assert "SELECT 1" not in str(result["records"])
    assert result["workers_remaining"] == 0
    assert deleted == (["diagnostic-child"] if outcome == "success" else [])


async def test_fork_snapshot_hashes_complete_original_pages() -> None:
    import hashlib
    import json

    from saas.scripts.benchmark_fork_diagnostics import _fork_source_snapshot

    requests = []

    def respond(request):
        requests.append(str(request.url))
        assert "/sessions/original/" in request.url.path
        second = request.url.params.get("after") == "first"
        return httpx.Response(
            200,
            json={
                "data": [{"id": "second" if second else "first", "data": {"text": "fixture"}}],
                "has_more": not second,
                "last_id": "second" if second else "first",
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(respond), base_url="http://bench"
    ) as client:
        result = await _fork_source_snapshot(client, "original")
    assert len(requests) == 4
    for kind in ("items", "files"):
        assert result[kind]["count"] == 2
        canonical = json.dumps(
            result[kind]["data"], sort_keys=True, separators=(",", ":")
        ).encode()
        assert result[kind]["sha256"] == hashlib.sha256(canonical).hexdigest()


def test_fork_diagnostics_follow_both_formal_sides_and_original_comparator() -> None:
    import yaml

    workflow = yaml.safe_load(
        (
            Path(__file__).resolve().parents[2] / ".github/workflows/saas-upgrade-benchmark.yml"
        ).read_text()
    )
    steps = workflow["jobs"]["compare"]["steps"]
    names = [step["name"] for step in steps]
    assert (
        names.index("Measure pinned components with one isolated harness")
        < names.index("Require measured journeys and enforce upstream thresholds")
        < names.index(
            "Diagnose retained fork targets after both formal measurements and comparison"
        )
    )
    comparator = steps[names.index("Require measured journeys and enforce upstream thresholds")][
        "run"
    ]
    assert "--threshold 0.30 --threshold-p95 0.50 --require" in comparator
    assert (
        "continue-on-error"
        not in steps[names.index("Require measured journeys and enforce upstream thresholds")]
    )
    assert len(workflow["jobs"]["compare"]["env"]["JOURNEYS"].split(",")) == 10


@pytest.mark.parametrize(
    ("side", "fault"),
    [("baseline", None), ("candidate", None), ("baseline", "side"), ("candidate", "revision")],
)
def test_fork_component_binding_uses_actual_editable_install_receipt(side, fault) -> None:
    from saas.scripts.benchmark_fork_diagnostics import _require_component_binding

    revisions = {
        "baseline": "adf6f0f1ef62199d171ffd32d7feec4b848a084a",
        "candidate": "b5e284b8215d9cbc1bdab12cd700d832e74b75a8",
    }
    module = f"/home/runner/work/omnigent/omnigent/{side}/omnigent/__init__.py"
    installed = {"revision": revisions[side], "module": module}
    profile = {"component_revision": revisions[side], "component_module": module}
    other = "candidate" if side == "baseline" else "baseline"
    if side == "candidate" and fault is None:
        profile["component_module"] = module.replace(
            "/omnigent/__init__.py", "/omnigent/../omnigent/__init__.py"
        )
    if fault == "side":
        profile["component_module"] = module.replace(f"/{side}/", f"/{other}/")
    elif fault == "revision":
        profile["component_revision"] = revisions[other]
    if fault:
        with pytest.raises(ValueError, match="pinned install"):
            _require_component_binding(profile, installed)
    else:
        _require_component_binding(profile, installed)
