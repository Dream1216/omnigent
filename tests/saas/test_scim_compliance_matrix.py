from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from saas.scim_schema_catalog import IDP_PROVIDER_TYPES

_ROOT = Path(__file__).resolve().parents[2]
_MATRIX = _ROOT / "saas" / "production" / "scim-compliance-matrix.json"
_ENTERPRISE_POLICY = _ROOT / "saas" / "production" / "enterprise-policy.json"
_ADMISSION_WORKFLOW = _ROOT / ".github" / "workflows" / "saas-enterprise-idp-admission.yml"


def _matrix() -> dict[str, object]:
    return cast(dict[str, object], json.loads(_MATRIX.read_text(encoding="utf-8")))


def test_scim_compliance_matrix_is_closed_and_honest() -> None:
    matrix = _matrix()
    statuses = set(cast(list[str], matrix["status_values"]))
    capabilities = cast(list[dict[str, object]], matrix["capabilities"])
    capability_ids = {str(item["id"]) for item in capabilities}

    assert {"RFC7643", "RFC7644"} == {
        str(item["id"]) for item in cast(list[dict[str, object]], matrix["standards"])
    }
    assert len(capability_ids) == len(capabilities)
    assert {
        "discovery.service_provider_config",
        "discovery.resource_types",
        "discovery.schemas",
        "schema.enterprise_user",
        "schema.optional_complex_attributes",
        "idp.configuration_product",
        "security.exact_directory_postgresql_rls",
    } <= capability_ids
    assert all(str(item["status"]) in statuses for item in capabilities)
    assert all(
        item.get("evidence")
        for item in capabilities
        if item["status"] == "implemented_tested_locally"
    )
    assert {
        str(item["status"])
        for item in capabilities
        if item["id"]
        in {
            "protocol.filter_user_multivalue_value_path",
            "protocol.attribute_projection",
        }
    } == {"implemented_tested_locally"}
    assert matrix["release_admission"] == "NO_GO_UNTIL_EXTERNAL_AND_PRODUCTION_EVIDENCE"


def test_scim_compliance_matrix_covers_every_idp_profile_without_false_e2e_claims() -> None:
    profiles = cast(list[dict[str, object]], _matrix()["idp_profiles"])
    by_provider = {str(profile["provider"]): profile for profile in profiles}

    assert {str(profile["provider"]) for profile in profiles} == set(IDP_PROVIDER_TYPES)
    assert all(
        profile["configuration_status"] == "implemented_tested_locally"
        for profile in profiles
    )
    assert by_provider["microsoft_entra"]["external_conformance_status"] == (
        "pending_external_evidence"
    )
    assert by_provider["okta"]["external_conformance_status"] == "pending_external_evidence"
    assert by_provider["google_workspace"]["external_conformance_status"] == (
        "blocked_external_prerequisite"
    )
    assert "does not expose generic outbound SCIM" in str(
        by_provider["google_workspace"]["provider_constraint"]
    )


def test_enterprise_policy_requires_independent_real_provider_evidence() -> None:
    policy = cast(
        dict[str, object],
        json.loads(_ENTERPRISE_POLICY.read_text(encoding="utf-8")),
    )
    integrations = cast(dict[str, object], policy["required_integrations"])
    positive_metrics = set(cast(list[str], policy["required_positive_metrics"]))

    assert {
        "scim_microsoft_entra",
        "scim_okta",
        "scim_google_workspace",
    } <= set(integrations)
    assert {
        "scim_microsoft_entra_operation_count",
        "scim_okta_operation_count",
        "scim_google_workspace_operation_count",
    } <= positive_metrics


def test_external_idp_admission_is_main_only_protected_and_fail_closed() -> None:
    workflow = _ADMISSION_WORKFLOW.read_text(encoding="utf-8")

    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "environment: production-evidence" in workflow
    assert "persist-credentials: false" in workflow
    assert "tests/saas/test_enterprise_identity_postgresql.py" in workflow
    assert "python -m saas.scripts.check_enterprise_readiness" in workflow
    assert "--require-ready" in workflow
