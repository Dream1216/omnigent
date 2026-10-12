"""Delivery defaults must be admissible to the deployed DCP contract."""

from html.parser import HTMLParser
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from saas.delivery.http import BuildBody, BuildOptions, RunBuildBody
from saas.delivery.legacy import LegacyBuild, LegacyRelease

IDENTIFIER = UUID("00000000-0000-0000-0000-000000000001")
MODELS = (
    (BuildOptions, {}),
    (BuildBody, {"snapshot_id": IDENTIFIER}),
    (RunBuildBody, {"run_id": IDENTIFIER}),
    (LegacyBuild, {"project_id": str(IDENTIFIER), "session_id": "contract-fixture"}),
    (
        LegacyRelease,
        {
            "project_id": str(IDENTIFIER),
            "environment": "production",
            "source_revision": "a" * 40,
            "artifact_ref": "registry.example.test/app@sha256:" + "a" * 64,
        },
    ),
)


@pytest.mark.parametrize(("model", "body"), MODELS)
def test_delivery_models_default_to_business_health_endpoint(model, body):
    assert model(**body).model_dump(mode="json")["health_path"] == "/health"


@pytest.mark.parametrize(("model", "body"), MODELS)
@pytest.mark.parametrize("path", ["/health", "/readyz", "/.well-known/app-health"])
def test_explicit_business_health_endpoints_remain_configurable(model, body, path):
    assert model(**body, health_path=path).health_path == path


@pytest.mark.parametrize(("model", "body"), MODELS)
@pytest.mark.parametrize("path", ["/", "/../private", "/health/../private", "relative"])
def test_root_or_non_normalized_health_endpoint_is_rejected(model, body, path):
    with pytest.raises(ValidationError):
        model(**body, health_path=path)


def test_delivery_workbench_default_matches_api_health_contract():
    class Inputs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.health = []

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            if tag == "input" and attributes.get("id") == "health":
                self.health.append(attributes.get("value"))

    parser = Inputs()
    parser.feed((Path(__file__).parents[2] / "saas/admin_ui/delivery.html").read_text())
    assert parser.health == ["/health"]
