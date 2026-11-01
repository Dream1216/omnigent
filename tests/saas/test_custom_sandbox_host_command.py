"""Private custom Host argv retains the upstream Kubernetes PID-1 reaper."""

from __future__ import annotations

import pytest

import omnigent.onboarding.sandboxes.kubernetes as k8s
from omnigent.onboarding import harness_install
from omnigent.onboarding.sandboxes.kubernetes import build_job_manifest

_MANIFEST_KW = {
    "job_name": "omnigent-managed-abc-1a2b3c",
    "namespace": "omnigent-sandboxes",
    "image": "ghcr.io/omnigent-ai/omnigent-host:latest",
    "service_account": "omnigent-runner",
    "host_id": "host_abcdef",
    "host_name": "managed-abcdef",
    "server_url": "http://srv.example.com",
    "token_secret_name": "omnigent-managed-abc-1a2b3c-token",
    "harness_secret": "omnigent-creds",
    "env_literals": {},
    "node_selector": None,
    "workspace": "/home/omnigent/workspace",
}


@pytest.fixture(autouse=True)
def _clear_probe_caches() -> None:
    """Isolate the module-level CLI probe caches between tests.

    ``harness_cli_logged_in`` / ``_harness_cli_version_string`` cache
    verdicts process-wide; a positive cached by one test's fake probe
    would leak into the next test's counting assertions.
    """
    harness_install._LOGIN_PROBE_CACHE.clear()
    harness_install._VERSION_PROBE_CACHE.clear()


def _pod_spec(manifest: dict) -> dict:
    """Extract the Pod spec from a Job manifest."""
    return manifest["spec"]["template"]["spec"]


def test_build_job_manifest_runs_reviewed_custom_host_command_under_same_reaper() -> None:
    """A downstream Host argv replaces only the reaper's child process."""
    manifest = build_job_manifest(
        **_MANIFEST_KW,
        host_command=["python3", "-m", "saas.production.platform_model_sandbox_host"],
    )
    host = _pod_spec(manifest)["containers"][0]
    script = host["command"][2]
    assert "exec python3 -c" in script
    assert "python3 -m saas.production.platform_model_sandbox_host" in script
    assert "omnigent host --server" not in script
    assert {
        "name": k8s.MANAGED_SERVER_URL_ENV_VAR,
        "value": "http://srv.example.com",
    } in host["env"]
