"""Retire only journal-owned generations, retaining the official offline-age policy."""

from __future__ import annotations

import asyncio
import logging

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


def read_retirement_host(driver, record, *, cutoff, now, force):
    with driver._adapter.bind(record.runtime):
        host = _owned_host(driver, record)
        if host is None:
            return None
        name = record.managed_preparation.resource_name
        if name not in (host.sandbox_id, host.terminating_sandbox_id):
            return None
        if host.sandbox_id == host.terminating_sandbox_id == name:
            raise _unavailable()
        if (
            force
            or record.managed_termination is not None
            or host.terminating_sandbox_id == name
            or ManagedSandboxReaper._is_reap_candidate(host, cutoff=cutoff, now=now)
        ):
            if record.managed_termination is None:
                from saas.production.interactive_preparation import inspect_managed_resources

                inspect_managed_resources(driver._app.state.sandbox_config, record)
            return host
        return None


def detach_retirement_host(driver, record, expected):
    with driver._adapter.bind(record.runtime):
        current = _owned_host(driver, record)
        if current is None or current != expected:
            return False
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
    if record.managed_termination is None or not record.managed_termination.complete:
        raise _unavailable()
    with driver._adapter.bind(record.runtime):
        current = _owned_host(driver, record)
        name = record.managed_preparation.resource_name
        if current is None or name not in (current.sandbox_id, current.terminating_sandbox_id):
            return True
        return driver._official.host_store.mark_sandbox_terminated(
            current.host_id, sandbox_id=name
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
                completed += bool(
                    await self._executor.retire_managed_origin(
                        record.run_id, cutoff=cutoff, now=reference_time
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - no provider/credential diagnostics.
                _LOGGER.warning("Managed retirement remains pending (%s)", type(error).__name__)
        return completed
