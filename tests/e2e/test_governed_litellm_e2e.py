from tests.saas.conftest import isolated_postgres_url as isolated_postgres_url
from tests.saas.test_interactive_controller_factory_process import (
    test_actual_controller_factory_host_litellm_and_pg18_billing as run_path,
)


def test_governed_litellm_turn(request, tmp_path, db_uri, monkeypatch):
    run_path(tmp_path, db_uri, monkeypatch, request)
