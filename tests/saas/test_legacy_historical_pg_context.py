"""Historical PG parsing must use the explicit read-only context throughout."""

import pytest

from tests.saas.test_legacy_control_results import consumer
from tests.saas.test_legacy_control_results import pg_native as pg_native
from tests.saas.test_legacy_pg_contract import scenario as scenario


@pytest.mark.parametrize(
    "scenario", [{"pg_inputs": True, "control_workflow": True}], indirect=True
)
def test_historical_pg_source_uses_readonly_context_without_producer_environment(
    scenario, pg_native, tmp_path, monkeypatch
):
    for name in ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_EVENT_NAME", "GITHUB_SHA"):
        monkeypatch.delenv(name, raising=False)
    pg_native["run"].update(status="completed", conclusion="success")
    checks = []

    def context(root, revision):
        assert root == scenario["control"] and revision == scenario["control_sha"]
        checks.append((root, revision))

    result = consumer._collect_pg_receipts(
        scenario["control"],
        scenario["product"],
        "Core",
        scenario["control_sha"],
        run_id=6001,
        attempt=1,
        actor="reviewed-actor",
        destination=tmp_path / "readonly-pg",
        context_verifier=context,
    )
    assert result["native_PG_receipts_pass"] is True
    assert len(checks) >= 3
    with pytest.raises(ValueError, match="protected native main context"):
        consumer.collect_pg_receipts(
            scenario["control"],
            scenario["product"],
            "Core",
            scenario["control_sha"],
            run_id=6001,
            attempt=1,
            actor="reviewed-actor",
            destination=tmp_path / "normal-pg",
        )
