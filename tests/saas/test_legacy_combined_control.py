"""The read-only context callback retains the complete native domain join.

Native responses use the existing owned fixtures. This exercises the shared
parser callback; the historical producer's authentication has separate tests.
"""

from __future__ import annotations

import pytest

from tests.saas.test_legacy_domain_integration import add_run, current_refusal, qualifier
from tests.saas.test_legacy_domain_integration import discovery_case as discovery_case
from tests.saas.test_legacy_domain_integration import native_domain as native_domain
from tests.saas.test_legacy_domain_integration import scenario as scenario


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("fault", [None, "unknown-source", "unregistered-default"])
def test_readonly_context_callback_keeps_typed_native_domain_requirements(
    scenario, discovery_case, tmp_path, monkeypatch, fault
):
    data = discovery_case
    current_refusal(scenario, data, "default", "workflow_run")
    if fault == "unknown-source":
        data["log"] = data["log"].replace(
            "WORKFLOW_HEAD_SHA: " + scenario["profile"]["product_revision"],
            "WORKFLOW_HEAD_SHA: 0",
        )
        data["refresh_rule"]()
    elif fault == "unregistered-default":
        add_run(scenario, data, "default")
    monkeypatch.delenv("GITHUB_REF")
    with pytest.raises(ValueError, match="protected native main context"):
        qualifier.qualify_source_ci(
            scenario["control"],
            scenario["product"],
            "Core",
            scenario["control_sha"],
            tmp_path / "normal-source",
        )
    calls = []

    def readonly_context(root, revision):
        assert root == scenario["control"] and revision == scenario["control_sha"]
        calls.append((root, revision))

    destination = tmp_path / "readonly-source"
    destination.mkdir()
    with qualifier.preserve_native_evidence(
        destination / "native-api", evidence_root=destination
    ) as evidence:
        if fault:
            with pytest.raises(ValueError):
                qualifier._qualify_source_ci(
                    scenario["control"],
                    scenario["product"],
                    "Core",
                    scenario["control_sha"],
                    destination,
                    evidence,
                    context_verifier=readonly_context,
                )
            assert not (destination / "source-qualification.json").exists()
        else:
            result = qualifier._qualify_source_ci(
                scenario["control"],
                scenario["product"],
                "Core",
                scenario["control_sha"],
                destination,
                evidence,
                context_verifier=readonly_context,
            )
            assert result["status"] == "pass" and result["source_ci_pass"] is True
            assert result["complete_domain_discovery"] is True
            assert result["domain_qualification_kind"] == (
                "legacy_authenticated_domain_eligibility/v2"
            )
            assert result["production_admission"] is False
    assert calls == [(scenario["control"], scenario["control_sha"])]
