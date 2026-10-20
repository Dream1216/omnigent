"""A fresh generation may follow complete retirement, never a name-only resume."""

from __future__ import annotations

from dataclasses import dataclass, replace

from omnigent.stores.host_store import Host, HostStore
from saas.production.interactive_recovery import (
    InteractiveRecoveryRecord,
    managed_retirement_proof_sha256,
)


@dataclass(frozen=True, slots=True)
class ManagedGenerationAdmission:
    origin: InteractiveRecoveryRecord
    host: Host


def inspect_retired_generation(driver, authorized, origins, conversation):
    from omnigent.onboarding.sandboxes.agent_sandbox import (
        API_GROUP,
        API_VERSION,
        SANDBOX_PLURAL,
        AgentSandboxLauncher,
    )
    from omnigent.onboarding.sandboxes.kubernetes import _token_secret_name
    from saas.production.interactive_controller import _unavailable
    from saas.production.interactive_preparation import _binding, _direct_launcher

    try:
        from kubernetes.client.rest import ApiException
    except ImportError:
        raise _unavailable() from None

    matching = [
        row
        for row in origins
        if isinstance(row, InteractiveRecoveryRecord)
        and row.managed_preparation is not None
        and row.managed_preparation.host_id == conversation.host_id
        and row.managed_preparation.provider == authorized.launch["sandbox_provider"]
    ]
    predecessors = {row.managed_predecessor_run_id for row in matching}
    leaves = [row for row in matching if row.run_id not in predecessors]
    if len(leaves) != 1:
        raise _unavailable()
    origin = leaves[0]
    for row in matching:
        managed_retirement_proof_sha256(row)
    preparation = origin.managed_preparation
    if preparation is None:
        raise _unavailable()
    with driver._adapter.bind(authorized.runtime):
        host = driver._official.host_store.get_host(conversation.host_id)
    if (
        host is None
        or host.sandbox_id is not None
        or host.terminating_sandbox_id is not None
        or host.deleted_at is not None
        or host.sandbox_provider != preparation.provider
        or host.user_id != authorized.runtime.runtime_user_key
        or host.user_id != (origin.host_owner or origin.runtime.runtime_user_key)
        or (
            origin.host_owner is not None
            and host.account_generation != origin.host_account_generation
        )
    ):
        raise _unavailable()
    deployment = driver._app.state.sandbox_config
    delegate = _direct_launcher(
        deployment.for_provider(preparation.provider), preparation.provider
    )
    try:
        actual = _binding(delegate, preparation.resource_name, preparation.host_id)
        if (
            replace(actual, image_reference_sha256=preparation.image_reference_sha256)
            != preparation
        ):
            raise _unavailable()
        if preparation.provider == "kubernetes":
            readers = [
                lambda: delegate._load_batch().read_namespaced_job(
                    preparation.resource_name, preparation.namespace, _request_timeout=10
                )
            ]
        elif isinstance(delegate, AgentSandboxLauncher):
            readers = [
                lambda: delegate._load_custom().get_namespaced_custom_object(
                    API_GROUP,
                    API_VERSION,
                    preparation.namespace,
                    SANDBOX_PLURAL,
                    preparation.resource_name,
                    _request_timeout=10,
                )
            ]
        else:
            raise _unavailable()
        readers.append(
            lambda: delegate._load_core().read_namespaced_secret(
                _token_secret_name(preparation.resource_name),
                preparation.namespace,
                _request_timeout=10,
            )
        )
        for read in readers:
            try:
                read()
            except ApiException as error:
                if error.status != 404:
                    raise _unavailable() from None
            else:
                raise _unavailable()
        return ManagedGenerationAdmission(origin, host)
    except Exception:  # noqa: BLE001 - SDK errors can contain credentials and response bodies.
        raise _unavailable() from None
    finally:
        delegate._close_clients()


class RetiredGenerationHostStore:
    """Reuse the original lifecycle transaction with a retired-snapshot predicate."""

    def __init__(self, delegate: HostStore, expected: Host):
        self._delegate, self._expected = delegate, expected

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    def replace_managed_host_sandbox(self, **kwargs):
        return self._delegate.replace_managed_host_sandbox(
            **kwargs, expected_retired_host=self._expected
        )
