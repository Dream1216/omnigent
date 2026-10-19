"""Fence legacy name-only writers while the Controller owns managed resources."""

from __future__ import annotations

from dataclasses import replace

from omnigent.onboarding.sandboxes.agent_sandbox import (
    API_GROUP,
    API_VERSION,
    SANDBOX_PLURAL,
    _shutdown_time,
    resolve_shutdown_window_s,
)
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_resources import (
    _creation_metadata,
    _metadata,
    _template,
    _template_sha256,
    read_managed_resources,
)


class ControlledManagedLauncher:
    def __init__(self, delegate, journal):
        self.delegate, self.journal = delegate, journal

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def start_host(self, *_args, **_kwargs):
        raise _unavailable()

    def terminate(self, *_args, **_kwargs):
        raise _unavailable()

    def resume(self, *_args, **_kwargs):
        raise _unavailable()

    def suspend(self, *_args, **_kwargs):
        raise _unavailable()

    def keep_alive(self, sandbox_id):
        from saas.production.interactive_managed_recovery import _tests
        from saas.production.interactive_preparation import _binding

        delegate = self.delegate
        try:
            rows = [
                row
                for row in self.journal.records()
                if row.managed_preparation is not None
                and row.managed_preparation.provider == delegate.provider
                and row.managed_preparation.resource_name == sandbox_id
            ]
            if not rows or any(row.managed_termination is not None for row in rows):
                raise _unavailable()
            records = [
                row
                for row in rows
                if row.managed_resources is not None and row.managed_creation is not None
            ]
            if not records or len({row.managed_resources.workload_uid for row in records}) != 1:
                raise _unavailable()
            record = records[0]
            preparation = record.managed_preparation
            if _binding(delegate, sandbox_id, preparation.host_id) != preparation:
                raise _unavailable()
            if (
                read_managed_resources(
                    delegate,
                    preparation,
                    host_token_sha256=record.managed_resources.host_token_sha256,
                    creation=record.managed_creation,
                )
                != record.managed_resources
            ):
                raise _unavailable()
            if delegate.provider == "kubernetes":
                return True
            parent = delegate._load_custom().get_namespaced_custom_object(
                API_GROUP,
                API_VERSION,
                preparation.namespace,
                SANDBOX_PLURAL,
                sandbox_id,
                _request_timeout=10,
            )
            if (
                parent["metadata"]["uid"] != record.managed_resources.workload_uid
                or parent["metadata"].get("deletionTimestamp")
                or parent["spec"].get("operatingMode") != "Running"
            ):
                raise _unavailable()
            _metadata(parent, namespace=preparation.namespace, name=sandbox_id, kind="Sandbox")
            template = _template(parent, preparation)
            _creation_metadata(parent, record.managed_creation)
            _creation_metadata(template, record.managed_creation, template=True)
            if _template_sha256(template) != record.managed_resources.pod_template_sha256:
                raise _unavailable()
            if any(self.journal.read(row.run_id) != row for row in rows):
                raise _unavailable()
            delegate._api_client.call_api(
                f"/apis/{API_GROUP}/{API_VERSION}/namespaces/{preparation.namespace}/{SANDBOX_PLURAL}/{sandbox_id}",
                "PATCH",
                header_params={
                    "Content-Type": "application/json-patch+json",
                    "Accept": "application/json",
                },
                body=[
                    *_tests(parent),
                    {
                        "op": "add",
                        "path": "/spec/shutdownTime",
                        "value": _shutdown_time(resolve_shutdown_window_s()),
                    },
                ],
                response_types_map={200: "object", 201: "object", 202: "object"},
                auth_settings=["BearerToken"],
                _return_http_data_only=True,
                _request_timeout=10,
            )
            return True
        except Exception:  # noqa: BLE001 - keepalive failure cannot expose cluster/credential data.
            return False
        finally:
            delegate._close_clients()


def protect_managed_deployment(deployment, journal):
    """Update the same parsed deployment captured by the original lifespan and reaper."""
    if deployment is None:
        return
    deployment.configs = tuple(
        replace(
            entry,
            launcher_factory=lambda factory=entry.launcher_factory: ControlledManagedLauncher(
                factory(), journal
            ),
        )
        for entry in deployment.configs
    )
