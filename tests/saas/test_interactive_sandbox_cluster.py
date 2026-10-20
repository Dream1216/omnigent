"""Own real K3s sandbox journeys; synthetic Fleet/PKI/supplier are not production admission."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from saas.production.interactive_model_channel import model_channel_origin
from tests.saas import test_interactive_controller_factory_process as physical


def _assert_cluster_authority(profile):
    from kubernetes import client, config

    namespace = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read_text().strip()
    runners = profile["sandbox"]["kubernetes"]["namespace"]
    configuration = client.Configuration()
    config.load_incluster_config(client_configuration=configuration)
    checks = {}
    with client.ApiClient(configuration) as api:
        identity = client.AuthenticationV1Api(api).create_self_subject_review(
            {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview", "spec": {}},
            _request_timeout=10,
        )
        assert (
            identity.status.user_info.username == f"system:serviceaccount:{namespace}:controller"
        )
        authorization = client.AuthorizationV1Api(api)
        recovery_enabled = (
            profile.get("scenario") == "create_ack_recovered"
            or profile.get("managed_retirement") is True
        )
        for group, resource, subresource, verb, target, expected in (
            ("batch", "jobs", None, "create", runners, True),
            ("agents.x-k8s.io", "sandboxes", None, "create", runners, True),
            ("", "pods", None, "list", runners, True),
            ("", "secrets", None, "create", runners, True),
            ("", "secrets", None, "get", runners, True),
            ("", "secrets", None, "list", runners, False),
            ("", "secrets", None, "watch", runners, False),
            ("", "secrets", None, "get", namespace, False),
            ("", "pods", "exec", "create", runners, False),
            ("batch", "jobs", None, "create", namespace, False),
            ("batch", "jobs", None, "patch", runners, recovery_enabled),
            ("", "pods", None, "patch", runners, recovery_enabled),
            ("batch", "jobs", None, "patch", namespace, False),
            ("", "pods", None, "patch", namespace, False),
        ):
            attributes = {"group": group, "resource": resource, "verb": verb, "namespace": target}
            if subresource:
                attributes["subresource"] = subresource
            review = authorization.create_self_subject_access_review(
                {
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": {"resourceAttributes": attributes},
                },
                _request_timeout=10,
            )
            assert review.status.allowed is expected, attributes
            checks[f"{target}:{verb}:{group}/{resource}/{subresource or ''}"] = (
                review.status.allowed
            )
    Path("/exchange/cluster-authority.json").write_text(
        json.dumps(
            {"passed": True, "subject": identity.status.user_info.username, "checks": checks}
        )
    )


def test_fixture_operator_can_replace_owner_only_pins_without_root(tmp_path):
    from tests.saas.test_production_runner_database_fleet_postgresql import _write_0400

    path = tmp_path / "public-pins.json"
    _write_0400(path, "first-public-pins")
    _write_0400(path, "replacement-public-pins")
    assert path.read_text() == "replacement-public-pins"
    assert stat.S_IMODE(path.stat().st_mode) == 0o400


def test_managed_sandbox_controller_litellm_and_pg18_billing(
    tmp_path, db_uri, monkeypatch, isolated_postgres_url
):
    path = os.environ.get("OMNIGENT_SAAS_TEST_CLUSTER_SANDBOX_FILE")
    if path is None:
        pytest.skip("requires task-owned real K3s sandbox environment")
    profile = json.loads(Path(path).read_text())
    assert profile["provider"] in {"kubernetes", "agent_sandbox"}
    _assert_cluster_authority(profile)
    origin = model_channel_origin(profile["sandbox"]["server_url"])
    monkeypatch.setattr(physical, "ORIGIN", origin)

    def probe(case):
        case.scenario = profile.get("scenario", "single")
        monkeypatch.setenv(
            "OMNIGENT_SAAS_TEST_GC_INTERVAL_SECONDS", str(profile.get("gc_interval_seconds", 30))
        )
        assert case.scenario != "controller_crash_recovery"
        if profile.get("official_postgresql", False):
            from tests.saas.interactive_official_postgresql import official_runtime_database

            with official_runtime_database(case.engine, monkeypatch) as runtime_url:
                physical._physical_controller(
                    case, runtime_url, tmp_path, monkeypatch, cluster=profile
                )
                assert (
                    json.loads(Path("/exchange/result.json").read_text())["official_store_backend"]
                    == "postgresql"
                )
        else:
            physical._physical_controller(case, db_uri, tmp_path, monkeypatch, cluster=profile)

    physical._signed_fleet(
        isolated_postgres_url,
        tmp_path,
        runtime_probe=probe,
    )
