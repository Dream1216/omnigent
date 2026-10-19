"""Private write-ahead/receipt contracts, not a real Kubernetes termination drive."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from uuid import UUID

import pytest

from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    ManagedCreationIntent,
    ManagedPodTermination,
    ManagedTerminationReceipt,
    physical_recovery_proof_sha256,
)
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_preparation import _reference
from tests.saas.test_interactive_managed_resources import _resources


def _intent(**changes):
    return replace(ManagedCreationIntent("a" * 32, "b" * 64), **changes)


async def _record(c):
    active, _ = await c.executor._prepare_active(c.lease, cancellation=asyncio.Event())
    c.executor._put(active, phase="preparing")
    c.executor._put(active, managed_preparation=_reference())
    return active


@pytest.mark.asyncio
async def test_creation_intent_is_write_ahead_monotonic_and_v5(controller_case):
    c = controller_case
    active = await _record(c)
    c.executor._put(active, managed_creation=_intent())
    path = c.journal.root / f"{c.lease.run_id}.json"
    assert json.loads(path.read_bytes())["schema_version"] == 5
    reserved = active.record
    for invalid in (
        _intent(
            secret_submitted=True,
            secret_uid=str(UUID(int=2)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
        _intent(nonce="c" * 32),
    ):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(reserved, managed_creation=invalid))
    c.executor._put(active, managed_creation=_intent(secret_submitted=True))
    c.executor._put(
        active, managed_creation=_intent(secret_submitted=True, secret_uid=str(UUID(int=2)))
    )
    c.executor._put(
        active,
        managed_creation=_intent(
            secret_submitted=True,
            secret_uid=str(UUID(int=2)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
    )
    c.executor._put(active, managed_resources=_resources())
    assert c.journal.read(c.lease.run_id) == active.record
    for old in (None, _intent(), _intent(secret_submitted=True)):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(active.record, managed_creation=old))
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(active.record)


@pytest.mark.asyncio
async def test_pod_receipts_cannot_forget_a_uid_or_change_a_terminal_digest(controller_case):
    c = controller_case
    active = await _record(c)
    for intent in (
        _intent(),
        _intent(secret_submitted=True),
        _intent(secret_submitted=True, secret_uid=str(UUID(int=2))),
        _intent(
            secret_submitted=True,
            secret_uid=str(UUID(int=2)),
            workload_submitted=True,
            input_template_sha256="a" * 64,
        ),
    ):
        c.executor._put(active, managed_creation=intent)
    c.executor._put(active, managed_resources=_resources())
    c.executor._put(active, phase="draining", outcome="orphaned")
    pod = ManagedPodTermination(str(UUID(int=3)), "owned-pod")
    receipt = ManagedTerminationReceipt((pod,), str(UUID(int=2)))
    c.executor._put(active, managed_termination=receipt)
    observed = replace(pod, containers_sha256="c" * 64)
    receipt = replace(receipt, pods=(observed,), secret_gone=True)
    c.executor._put(active, managed_termination=receipt)
    for invalid in (
        None,
        replace(receipt, pods=()),
        replace(receipt, pods=(pod,)),
        replace(receipt, pods=(replace(observed, containers_sha256="d" * 64),)),
    ):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(active.record, managed_termination=invalid))
    c.executor._put(active, managed_termination=replace(receipt, complete=True))
    with pytest.raises(InteractiveRecoveryError):
        physical_recovery_proof_sha256(active.record)
    c.executor._put(active, process_stopped=True, stop_kind="managed_container")
    assert len(physical_recovery_proof_sha256(c.journal.read(c.lease.run_id))) == 64
    with pytest.raises(InteractiveRecoveryError):
        c.journal.put(replace(active.record, managed_termination=receipt))


@pytest.mark.asyncio
async def test_v5_cannot_be_smuggled_into_an_older_private_format(controller_case):
    c = controller_case
    active = await _record(c)
    c.executor._put(active, managed_creation=_intent())
    path = c.journal.root / f"{c.lease.run_id}.json"
    raw = path.read_bytes()
    try:
        for version in (1, 2, 3, 4, True):
            data = json.loads(raw)
            data["schema_version"] = version
            if version == 1:
                data.pop("record_type")
            path.write_text(json.dumps(data))
            with pytest.raises(InteractiveRecoveryError):
                c.journal.read(c.lease.run_id)
    finally:
        path.write_bytes(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"secret_submitted": 1},
        {"workload_submitted": True},
        {"secret_uid": "invalid"},
        {"host_token_sha256": "invalid"},
        {"nonce": "invalid"},
        {"input_template_sha256": "a" * 64},
    ],
)
def test_invalid_creation_intent_is_unavailable(changes):
    with pytest.raises(InteractiveRecoveryError):
        _intent(**changes)
