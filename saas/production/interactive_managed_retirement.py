"""Retire only journal-owned generations, retaining the official offline-age policy."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from omnigent.server.managed_sandbox_reaper import ManagedSandboxReaper
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_recovery import InteractiveRecoveryRecord

_LOGGER = logging.getLogger(__name__)


def _owned_host(driver, record):
    preparation = record.managed_preparation
    if preparation is None:
        raise _unavailable()
    host = driver._official.host_store.get_host(preparation.host_id, include_deleted=True)
    if host is not None and (
        host.host_id != preparation.host_id
        or host.sandbox_provider != preparation.provider
        or host.user_id != (record.host_owner or record.runtime.runtime_user_key)
        or (
            record.host_owner is not None
            and host.account_generation != record.host_account_generation
        )
    ):
        raise _unavailable()
    return host


def read_retirement_host(driver, record, *, cutoff, now, force, retaining=False):
    with driver._adapter.bind(record.runtime):
        host = _owned_host(driver, record)
        if host is None:
            return None
        name = record.managed_preparation.resource_name
        retained = record.managed_suspension is not None and record.managed_suspension.complete
        if name not in (host.sandbox_id, host.terminating_sandbox_id) and not (
            retained and host.sandbox_id is host.terminating_sandbox_id is None
        ):
            return None
        if host.sandbox_id == host.terminating_sandbox_id == name:
            raise _unavailable()
        if retaining:
            from saas.production.interactive_suspension import suspension_due

            if retained and host.sandbox_id is host.terminating_sandbox_id is None:
                return None
            return (
                host if suspension_due(driver._app.state.sandbox_config, record, now=now) else None
            )
        if (
            record.managed_suspension is not None
            and record.managed_termination is None
            and not force
        ):
            if not ManagedSandboxReaper._is_reap_candidate(
                replace(host, sandbox_id=name, terminating_sandbox_id=None), cutoff=cutoff, now=now
            ):
                return None
        if (
            force
            or record.managed_termination is not None
            or host.terminating_sandbox_id == name
            or ManagedSandboxReaper._is_reap_candidate(host, cutoff=cutoff, now=now)
            or (
                retained
                and ManagedSandboxReaper._is_reap_candidate(
                    replace(host, sandbox_id=name, terminating_sandbox_id=None),
                    cutoff=cutoff,
                    now=now,
                )
            )
        ):
            if record.managed_termination is None:
                if retained:
                    from saas.production.interactive_preparation import _direct_launcher
                    from saas.production.interactive_suspension import read_suspended_resources

                    launcher = _direct_launcher(
                        driver._app.state.sandbox_config.for_provider(
                            record.managed_preparation.provider
                        ),
                        record.managed_preparation.provider,
                    )
                    try:
                        read_suspended_resources(launcher, record)
                    finally:
                        launcher._close_clients()
                else:
                    from saas.production.interactive_preparation import inspect_managed_resources

                    inspect_managed_resources(driver._app.state.sandbox_config, record)
            return host
        return None


def detach_retirement_host(driver, record, expected):
    with driver._adapter.bind(record.runtime):
        current = _owned_host(driver, record)
        if current is None or current != expected:
            return False
        if (
            record.managed_suspension is not None
            and record.managed_suspension.complete
            and current.sandbox_id is current.terminating_sandbox_id is None
        ):
            return True
        name = record.managed_preparation.resource_name
        if current.deleted_at is not None or current.terminating_sandbox_id == name:
            return True
        return driver._official.host_store.detach_stale_managed_sandbox(
            current.host_id,
            sandbox_id=name,
            expected_updated_at=current.updated_at,
            expected_token_hash=record.managed_creation.host_token_sha256,
        )


def finish_retirement_host(driver, record):
    if not (
        (record.managed_termination is not None and record.managed_termination.complete)
        or (record.managed_suspension is not None and record.managed_suspension.complete)
    ):
        raise _unavailable()
    with driver._adapter.bind(record.runtime):
        current = _owned_host(driver, record)
        name = record.managed_preparation.resource_name
        if current is None or name not in (current.sandbox_id, current.terminating_sandbox_id):
            return True
        return driver._official.host_store.mark_sandbox_terminated(
            current.host_id, sandbox_id=name
        )


def _retain_offline_generation(driver, record, *, cutoff, now):
    preparation, creation = record.managed_preparation, record.managed_creation
    if (
        preparation is None
        or creation is None
        or preparation.provider != "agent_sandbox"
        or creation.pod_uid is None
        or record.managed_termination is not None
    ):
        return False
    with driver._adapter.bind(record.runtime):
        host = _owned_host(driver, record)
    return (
        host is not None
        and host.deleted_at is None
        and not ManagedSandboxReaper._is_reap_candidate(
            replace(host, sandbox_id=preparation.resource_name, terminating_sandbox_id=None),
            cutoff=cutoff,
            now=now,
        )
    )


class ControllerManagedSandboxReaper(ManagedSandboxReaper):
    """Use exact private RuntimeContexts, not a context-free cross-workspace scan."""

    def __init__(self, *, executor, driver, host_store, sandbox_config, **kwargs):
        if (
            host_store is not driver._official.host_store
            or sandbox_config is not driver._app.state.sandbox_config
        ):
            raise _unavailable()
        super().__init__(host_store=host_store, sandbox_config=sandbox_config, **kwargs)
        self._executor = executor
        self._driver = driver

    async def sweep_once(self, *, now: int | None = None) -> int:
        reference_time = self._clock() if now is None else now
        cutoff = reference_time - self._sandbox_config.reaper.terminate_after_offline_days * 86400
        records = sorted(
            (
                row
                for row in self._executor._journal.records()
                if isinstance(row, InteractiveRecoveryRecord)
                and row.managed_origin_run_id is None
                and row.managed_preparation is not None
                and row.managed_creation is not None
                and row.managed_resources is not None
            ),
            key=lambda row: str(row.run_id),
        )
        completed = 0
        for record in records:
            try:
                if any(row.managed_predecessor_run_id == record.run_id for row in records):
                    continue
                retaining = await asyncio.to_thread(
                    _retain_offline_generation,
                    self._driver,
                    record,
                    cutoff=cutoff,
                    now=reference_time,
                )
                completed += bool(
                    await self._executor.retire_managed_origin(
                        record.run_id,
                        cutoff=cutoff,
                        now=reference_time,
                        **({"retaining": True} if retaining else {}),
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - no provider/credential diagnostics.
                _LOGGER.warning("Managed retirement remains pending (%s)", type(error).__name__)
        return completed
