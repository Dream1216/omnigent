from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from omnigent.runtime.agent_cache import AgentCache
from omnigent.server.routes.builtin_agents import create_builtin_agents_router
from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
from omnigent.stores.artifact_store.local import LocalArtifactStore
from saas.production.agent_store import disable_standalone_agent_installs


def test_production_install_capability_blocks_new_routes_before_artifact_writes(
    db_uri: str, tmp_path: Path
) -> None:
    underlying = SqlAlchemyAgentStore(db_uri)
    artifacts = LocalArtifactStore(str(tmp_path / "artifacts"))
    cache = AgentCache(artifact_store=artifacts, cache_dir=tmp_path / "cache")
    guarded = disable_standalone_agent_installs(underlying)
    router = create_builtin_agents_router(guarded, cache, artifact_store=artifacts)
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    client = TestClient(app)

    assert underlying.supports_user_agents is True
    assert guarded.supports_user_agents is False
    server_agents = client.get("/v1/agents")
    assert server_agents.status_code == 200
    assert server_agents.json()["data"] == []
    for method, path in [
        ("POST", "/v1/agents"),
        ("DELETE", "/v1/agents/ag_unadmitted"),
        ("GET", "/v1/agents?scope=user"),
    ]:
        response = client.request(method, path)
        assert response.status_code == 404
    assert list((tmp_path / "artifacts").rglob("*")) == []
